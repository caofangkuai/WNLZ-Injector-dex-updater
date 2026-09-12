package com.wunelezi.injector;

import android.app.Application;
import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import dalvik.system.DexClassLoader;

public final class Inject {

    private static final String TAG = "WNLZ-Inject";

    private static final String PLUGIN_LIST_FILE = "plugins.txt";
    private static final String DEX_DIR_NAME      = "wnlz_dex";
    private static final String INFO_ENTRY_NAME   = "info.json";
    private static final String INFO_KEY_INIT     = "init";
    private static final String INFO_KEY_MERGE_DEX = "mergeDex";
    private static final String DEX_SUFFIX        = ".dex";

    private static final int BUFFER_SIZE = 4096;

    /** info.json 读取上限(字符);<=0 表示完整读取。 */
    private static final int MAX_INFO_JSON_CHARS = -1;

    /** 是否清理 wnlz_dex 目录下的旧 dex(仅在本进程首次注入时执行)。 */
    private static final boolean CLEAN_DEX_DIR_BEFORE_INJECT = true;

    /** 本进程是否已执行过目录清理,保证多次注入只清一次。 */
    private static final AtomicBoolean sCleanedOnce = new AtomicBoolean(false);

    /** 防止同一插件被重复注入。 */
    private static final Set<String> sInjectedPlugins = new HashSet<>();

    /** 已解压的 dex 绝对路径(本次进程内)。 */
    private static final Set<String> sExtractedDexPaths = new HashSet<>();

    /** 方案 B:已合并进宿主的 dex 绝对路径,防止重复注册。 */
    private static final Set<String> sRegisteredDexPaths = new HashSet<>();

    /** 全局唯一序号,保证同一进程内每次解压文件名不重复。 */
    private static final AtomicInteger sDexSeq = new AtomicInteger(0);

    private Inject() {}

    // =====================================================================
    // 插件配置
    // =====================================================================

    private static final class PluginInfo {
        final String initClassName;
        final boolean mergeDex;

        PluginInfo(String initClassName, boolean mergeDex) {
            this.initClassName = initClassName;
            this.mergeDex = mergeDex;
        }
    }

    // =====================================================================
    // 入口
    // =====================================================================

    public static void inject(Application application) {
        if (application == null) {
            log("inject: application is null");
            return;
        }

        File externalFilesDir = application.getExternalFilesDir(null);
        if (externalFilesDir == null) {
            log("inject: externalFilesDir is null");
            return;
        }

        // 只在本进程首次注入时清理一次
        if (CLEAN_DEX_DIR_BEFORE_INJECT && sCleanedOnce.compareAndSet(false, true)) {
            cleanDexDir(application);
        }

        File pluginListFile = new File(externalFilesDir, PLUGIN_LIST_FILE);
        if (!pluginListFile.exists()) {
            log("plugins.txt not found at " + pluginListFile.getAbsolutePath());
            return;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(pluginListFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                File pluginZip = new File(externalFilesDir, trimmed);
                try {
                    processPlugin(pluginZip, application);
                } catch (Throwable th) {
                    log("Failed to process plugin: " + trimmed);
                    logThrowable(th);
                }
            }
        } catch (Throwable th) {
            log("inject failed");
            logThrowable(th);
        }
    }

    /** 清理 wnlz_dex 目录,避免旧 dex 无限堆积。 */
    private static void cleanDexDir(Application application) {
        File dexDir = application.getDir(DEX_DIR_NAME, 0);
        if (!dexDir.exists() || !dexDir.isDirectory()) {
            return;
        }
        File[] files = dexDir.listFiles();
        if (files == null) {
            return;
        }
        int deleted = 0;
        for (File f : files) {
            if (f.isFile() && f.getName().endsWith(DEX_SUFFIX)) {
                if (f.delete()) {
                    deleted++;
                }
            }
        }
        log("First inject in this process, cleaned " + deleted
                + " old dex file(s) in " + dexDir.getAbsolutePath());
    }

    // =====================================================================
    // 单个插件处理
    // =====================================================================

    private static void processPlugin(File pluginZip, Application application) {
        if (!pluginZip.exists()) {
            log("Plugin zip not found: " + pluginZip.getAbsolutePath());
            return;
        }

        String pluginKey = pluginZip.getAbsolutePath();
        synchronized (sInjectedPlugins) {
            if (sInjectedPlugins.contains(pluginKey)) {
                log("Plugin already injected, skip: " + pluginKey);
                return;
            }
            sInjectedPlugins.add(pluginKey);
        }

        PluginInfo info = readPluginInfoFromZip(pluginZip);
        if (info == null || info.initClassName == null || info.initClassName.isEmpty()) {
            log("No init class found in " + INFO_ENTRY_NAME + " for: " + pluginKey);
            return;
        }
        log("Init class: " + info.initClassName + ", mergeDex=" + info.mergeDex);

        ClassLoader classLoaderForPlugin;
        if (info.mergeDex) {
            boolean merged = mergePluginDexToHost(pluginZip, application);
            if (!merged) {
                log("mergeDex=true but merge failed, fallback to Plan A for: " + pluginKey);
                classLoaderForPlugin = buildPluginClassLoader(pluginZip, application);
            } else {
                classLoaderForPlugin = Inject.class.getClassLoader();
            }
        } else {
            classLoaderForPlugin = buildPluginClassLoader(pluginZip, application);
        }

        if (classLoaderForPlugin == null) {
            log("Failed to build ClassLoader for: " + pluginKey);
            return;
        }

        Object result = invokeOnInit(info.initClassName, pluginZip, application,
                classLoaderForPlugin);
        if (result == null) {
            log("onInject returned null for " + info.initClassName);
            return;
        }

        if (result instanceof Application.ActivityLifecycleCallbacks) {
            application.registerActivityLifecycleCallbacks(
                    (Application.ActivityLifecycleCallbacks) result);
            log("Registered ActivityLifecycleCallbacks from " + info.initClassName);
        } else {
            log("onInject returned non-lifecycle object for " + info.initClassName
                    + ": " + result.getClass().getName());
        }
    }

    // =====================================================================
    // 方案 A:构建插件自己的 DexClassLoader(不合并)
    // =====================================================================

    private static DexClassLoader buildPluginClassLoader(File pluginZip,
                                                        Application application) {
        List<File> dexFiles = extractAllDex(pluginZip, application, "a");
        if (dexFiles.isEmpty()) {
            log("Plan A: no " + DEX_SUFFIX + " entries in " + pluginZip.getAbsolutePath());
            return null;
        }

        File dexDir = application.getDir(DEX_DIR_NAME, 0);
        ClassLoader hostLoader = Inject.class.getClassLoader();

        StringBuilder dexPath = new StringBuilder();
        for (File f : dexFiles) {
            if (dexPath.length() > 0) {
                dexPath.append(File.pathSeparator);
            }
            dexPath.append(f.getAbsolutePath());
        }

        DexClassLoader pluginLoader = new DexClassLoader(
                dexPath.toString(),
                dexDir.getAbsolutePath(),
                null,
                hostLoader);

        log("Plan A: built DexClassLoader with " + dexFiles.size()
                + " dex file(s), parent=" + hostLoader);
        return pluginLoader;
    }

    // =====================================================================
    // 方案 B:合并 dex 到宿主 ClassLoader
    // =====================================================================

    private static boolean mergePluginDexToHost(File pluginZip, Application application) {
        List<File> dexFiles = extractAllDex(pluginZip, application, "b");
        if (dexFiles.isEmpty()) {
            log("Plan B: no " + DEX_SUFFIX + " entries in " + pluginZip.getAbsolutePath());
            return false;
        }

        List<File> toMerge = new ArrayList<>();
        synchronized (sRegisteredDexPaths) {
            for (File f : dexFiles) {
                if (sRegisteredDexPaths.contains(f.getAbsolutePath())) {
                    log("Plan B: dex already registered, skip: " + f.getAbsolutePath());
                    continue;
                }
                toMerge.add(f);
            }
        }
        if (toMerge.isEmpty()) {
            log("Plan B: all dex already registered, nothing to merge");
            return true;
        }

        File dexDir = application.getDir(DEX_DIR_NAME, 0);
        ClassLoader hostLoader = Inject.class.getClassLoader();

        StringBuilder dexPath = new StringBuilder();
        for (File f : toMerge) {
            if (dexPath.length() > 0) {
                dexPath.append(File.pathSeparator);
            }
            dexPath.append(f.getAbsolutePath());
        }

        try {
            DexClassLoader pluginLoader = new DexClassLoader(
                    dexPath.toString(),
                    dexDir.getAbsolutePath(),
                    null,
                    hostLoader);

            boolean ok = combineDexElementsAndDetach(pluginLoader, hostLoader);
            if (ok) {
                synchronized (sRegisteredDexPaths) {
                    for (File f : toMerge) {
                        sRegisteredDexPaths.add(f.getAbsolutePath());
                    }
                }
                log("Plan B: merged " + toMerge.size() + " dex file(s) into host");
            }
            return ok;
        } catch (Throwable th) {
            log("Plan B: failed to merge dex");
            logThrowable(th);
            return false;
        }
    }

    private static boolean combineDexElementsAndDetach(ClassLoader sourceLoader,
                                                       ClassLoader targetLoader) {
        try {
            Field pathListField = Class.forName("dalvik.system.BaseDexClassLoader")
                    .getDeclaredField("pathList");
            pathListField.setAccessible(true);

            Object sourcePathList = pathListField.get(sourceLoader);
            Object targetPathList = pathListField.get(targetLoader);
            if (sourcePathList == null || targetPathList == null) {
                log("Plan B: pathList is null, cannot combine");
                return false;
            }

            Field dexElementsField = Class.forName("dalvik.system.DexPathList")
                    .getDeclaredField("dexElements");
            dexElementsField.setAccessible(true);

            Object[] sourceElements = (Object[]) dexElementsField.get(sourcePathList);
            Object[] targetElements = (Object[]) dexElementsField.get(targetPathList);

            if (sourceElements.length == 0) {
                log("Plan B: no dex elements to combine");
                return false;
            }

            Object[] combined = (Object[]) Array.newInstance(
                    targetElements.getClass().getComponentType(),
                    targetElements.length + sourceElements.length);
            System.arraycopy(targetElements, 0, combined, 0, targetElements.length);
            System.arraycopy(sourceElements, 0, combined, targetElements.length,
                    sourceElements.length);

            dexElementsField.set(targetPathList, combined);
            log("Plan B: combined " + sourceElements.length
                    + " plugin element(s) after " + targetElements.length
                    + " host element(s)");

            Object[] emptyElements = (Object[]) Array.newInstance(
                    sourceElements.getClass().getComponentType(), 0);
            dexElementsField.set(sourcePathList, emptyElements);
            log("Plan B: detached source loader dex elements");
            return true;

        } catch (Throwable th) {
            log("Plan B: failed to combine dex elements");
            logThrowable(th);
            return false;
        }
    }

    // =====================================================================
    // dex 解压(方案 A/B 共用)
    // =====================================================================

    private static List<File> extractAllDex(File pluginZip,
                                            Application application,
                                            String planTag) {
        List<File> result = new ArrayList<>();
        File dexDir = application.getDir(DEX_DIR_NAME, 0);

        try (ZipFile zipFile = new ZipFile(pluginZip)) {
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String entryName = entry.getName();
                if (entryName == null || entry.isDirectory()) {
                    continue;
                }
                if (!entryName.toLowerCase().endsWith(DEX_SUFFIX)) {
                    continue;
                }

                int seq = sDexSeq.incrementAndGet();
                long ts = System.currentTimeMillis();
                String baseName = new File(entryName).getName();
                String uniqueName = "plugin_"
                        + planTag + "_"
                        + Math.abs(pluginZip.getAbsolutePath().hashCode()) + "_"
                        + seq + "_"
                        + ts + "_"
                        + baseName;
                File outputFile = new File(dexDir, uniqueName);

                synchronized (sExtractedDexPaths) {
                    if (sExtractedDexPaths.contains(outputFile.getAbsolutePath())) {
                        log("Dex already extracted, reuse: " + outputFile.getAbsolutePath());
                        result.add(outputFile);
                        continue;
                    }
                }

                if (extractEntry(zipFile, entry, outputFile)) {
                    result.add(outputFile);
                    synchronized (sExtractedDexPaths) {
                        sExtractedDexPaths.add(outputFile.getAbsolutePath());
                    }
                    log("Extracted dex entry [" + planTag + "]: " + entryName
                            + " -> " + outputFile.getAbsolutePath());
                }
            }
        } catch (Throwable th) {
            log("Failed to extract dex from: " + pluginZip.getAbsolutePath());
            logThrowable(th);
        }
        return result;
    }

    private static boolean extractEntry(ZipFile zipFile, ZipEntry entry, File outputFile) {
        File parent = outputFile.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            log("Failed to create dir: " + parent.getAbsolutePath());
            return false;
        }
        try (InputStream in = zipFile.getInputStream(entry);
             FileOutputStream out = new FileOutputStream(outputFile)) {
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) > 0) {
                out.write(buffer, 0, bytesRead);
            }
            return true;
        } catch (Throwable th) {
            log("Failed to extract entry: " + entry.getName());
            logThrowable(th);
            return false;
        }
    }

    // =====================================================================
    // info.json 读取
    // =====================================================================

    private static PluginInfo readPluginInfoFromZip(File pluginZip) {
        try (ZipFile zipFile = new ZipFile(pluginZip)) {
            ZipEntry infoEntry = zipFile.getEntry(INFO_ENTRY_NAME);
            if (infoEntry == null) {
                log(INFO_ENTRY_NAME + " not found in zip: " + pluginZip.getAbsolutePath());
                return null;
            }
            try (Reader reader = new InputStreamReader(
                    zipFile.getInputStream(infoEntry), StandardCharsets.UTF_8)) {
                String content = readFully(reader, MAX_INFO_JSON_CHARS);
                if (content == null) {
                    log("Failed to read " + INFO_ENTRY_NAME + " fully: "
                            + pluginZip.getAbsolutePath());
                    return null;
                }
                return parsePluginInfo(content);
            }
        } catch (Throwable th) {
            log("Failed to read " + INFO_ENTRY_NAME + " from: " + pluginZip.getAbsolutePath());
            logThrowable(th);
            return null;
        }
    }

    private static String readFully(Reader reader, int maxChars) throws IOException {
        StringBuilder sb = new StringBuilder(1024);
        char[] buf = new char[BUFFER_SIZE];
        int n;
        while ((n = reader.read(buf)) != -1) {
            if (maxChars > 0 && sb.length() + n > maxChars) {
                int extra = reader.read();
                if (extra != -1) {
                    return null;
                }
                sb.append(buf, 0, n);
                break;
            }
            sb.append(buf, 0, n);
        }
        return sb.toString();
    }

    private static PluginInfo parsePluginInfo(String json) {
        try {
            JSONObject obj = new JSONObject(json);
            String init = obj.optString(INFO_KEY_INIT, null);
            boolean mergeDex = obj.optBoolean(INFO_KEY_MERGE_DEX, false);
            return new PluginInfo(init, mergeDex);
        } catch (Throwable th) {
            log("Failed to parse " + INFO_ENTRY_NAME);
            logThrowable(th);
            return null;
        }
    }

    // =====================================================================
    // 反射调用 onInject
    // =====================================================================

    private static Object invokeOnInit(String className, File pluginZip,
                                       Application application,
                                       ClassLoader pluginLoader) {
        try {
            Class<?> initClass = Class.forName(className, true, pluginLoader);
            log("Loaded init class: " + initClass.getName()
                    + " via " + pluginLoader);

            Method m = findOnInject(initClass,
                    new Class<?>[]{File.class, Application.class});
            if (m != null) {
                return invoke(m, initClass, pluginZip, application);
            }

            m = findOnInject(initClass, new Class<?>[]{Application.class});
            if (m != null) {
                return invoke(m, initClass, application);
            }

            log("No matching onInject method found in " + className);
            return null;
        } catch (Throwable th) {
            log("Failed to invoke onInject on " + className);
            logThrowable(th);
            return null;
        }
    }

    private static Method findOnInject(Class<?> clazz, Class<?>[] paramTypes) {
        try {
            Method m = clazz.getDeclaredMethod("onInject", paramTypes);
            m.setAccessible(true);
            return m;
        } catch (NoSuchMethodException e) {
            return null;
        }
    }

    private static Object invoke(Method method, Class<?> clazz, Object... args) {
        try {
            Object target = null;
            if (!Modifier.isStatic(method.getModifiers())) {
                target = clazz.getDeclaredConstructor().newInstance();
            }
            log("Invoking " + (target == null ? "static " : "instance ")
                    + method.getName() + " with " + args.length + " arg(s)");
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            log("onInject threw an exception");
            logThrowable(cause);
            return null;
        } catch (Throwable th) {
            log("Failed to invoke " + method.getName());
            logThrowable(th);
            return null;
        }
    }

    // =====================================================================
    // 日志
    // =====================================================================

    private static void log(String message) {
        Log.d(TAG, message);
    }

    private static void logThrowable(Throwable th) {
        Log.e(TAG, "exception", th);
    }
}
