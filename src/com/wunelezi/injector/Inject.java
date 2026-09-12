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
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import dalvik.system.DexClassLoader;

public final class Inject {

    private static final String TAG = "WNLZ-Inject";

    private static final String PLUGIN_LIST_FILE = "plugins.txt";
    private static final String DEX_DIR_NAME      = "wnlz_dex";
    private static final String INFO_ENTRY_NAME   = "info.json";
    private static final String INFO_KEY_INIT     = "init";
    private static final String DEX_SUFFIX        = ".dex";

    private static final int BUFFER_SIZE = 4096;

    /** info.json 读取上限(字符);<=0 表示完整读取。 */
    private static final int MAX_INFO_JSON_CHARS = -1;

    /** 防止同一插件被重复注入。 */
    private static final Set<String> sInjectedPlugins = new HashSet<>();

    /** 缓存每个插件的 DexClassLoader,避免重复创建。 */
    private static final Set<String> sCreatedDexPaths = new HashSet<>();

    private Inject() {}

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

        // 1. 读取 info.json 里的 init 类名
        String initClassName = readInitClassFromZip(pluginZip);
        if (initClassName == null || initClassName.isEmpty()) {
            log("No init class found in " + INFO_ENTRY_NAME + " for: " + pluginKey);
            return;
        }
        log("Init class: " + initClassName);

        // 2. 为这个插件构建一个 DexClassLoader(不合并到宿主)
        DexClassLoader pluginLoader = buildPluginClassLoader(pluginZip, application);
        if (pluginLoader == null) {
            log("Failed to build DexClassLoader for: " + pluginKey);
            return;
        }

        // 3. 用插件自己的 DexClassLoader 加载 init 类
        Object result = invokeOnInit(initClassName, pluginZip, application, pluginLoader);
        if (result == null) {
            log("onInject returned null for " + initClassName);
            return;
        }

        // 4. 注册 ActivityLifecycleCallbacks
        if (result instanceof Application.ActivityLifecycleCallbacks) {
            application.registerActivityLifecycleCallbacks(
                    (Application.ActivityLifecycleCallbacks) result);
            log("Registered ActivityLifecycleCallbacks from " + initClassName);
        } else {
            log("onInject returned non-lifecycle object for " + initClassName
                    + ": " + result.getClass().getName());
        }
    }

    // =====================================================================
    // 构建插件 ClassLoader(方案 A 核心)
    // =====================================================================

    /**
     * 解压 zip 里所有 .dex 到私有目录,构建一个 DexClassLoader。
     * parent 使用 Inject 所在的 ClassLoader(即宿主 ClassLoader)。
     *
     * 不做任何 dexElements 合并,插件类只由这个 pluginLoader 加载;
     * 插件需要引用宿主类时,双亲委派会把请求交给 hostLoader。
     */
    private static DexClassLoader buildPluginClassLoader(File pluginZip,
                                                        Application application) {
        File dexDir = application.getDir(DEX_DIR_NAME, 0);
        ClassLoader hostLoader = Inject.class.getClassLoader();

        try (ZipFile zipFile = new ZipFile(pluginZip)) {
            List<File> extractedDexFiles = new ArrayList<>();
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

                File outputFile = new File(dexDir,
                        "plugin_" + Math.abs(pluginZip.getAbsolutePath().hashCode())
                                + "_" + new File(entryName).getName());

                synchronized (sCreatedDexPaths) {
                    if (sCreatedDexPaths.contains(outputFile.getAbsolutePath())) {
                        log("Dex already extracted, reuse: " + outputFile.getAbsolutePath());
                        extractedDexFiles.add(outputFile);
                        continue;
                    }
                }

                if (extractEntry(zipFile, entry, outputFile)) {
                    extractedDexFiles.add(outputFile);
                    synchronized (sCreatedDexPaths) {
                        sCreatedDexPaths.add(outputFile.getAbsolutePath());
                    }
                    log("Extracted dex entry: " + entryName
                            + " -> " + outputFile.getAbsolutePath());
                }
            }

            if (extractedDexFiles.isEmpty()) {
                log("No " + DEX_SUFFIX + " entries found in: " + pluginZip.getAbsolutePath());
                return null;
            }

            // 拼所有 dex 路径
            StringBuilder dexPath = new StringBuilder();
            for (File f : extractedDexFiles) {
                if (dexPath.length() > 0) {
                    dexPath.append(File.pathSeparator);
                }
                dexPath.append(f.getAbsolutePath());
            }

            // 关键:parent = hostLoader,插件类需要宿主类时走双亲委派
            DexClassLoader pluginLoader = new DexClassLoader(
                    dexPath.toString(),
                    dexDir.getAbsolutePath(),
                    null,          // librarySearchPath,插件无 so 可传 null
                    hostLoader);

            log("Built DexClassLoader with " + extractedDexFiles.size()
                    + " dex file(s), parent=" + hostLoader);
            return pluginLoader;

        } catch (Throwable th) {
            log("Failed to build DexClassLoader from: " + pluginZip.getAbsolutePath());
            logThrowable(th);
            return null;
        }
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

    private static String readInitClassFromZip(File pluginZip) {
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
                return parseInitFromJson(content);
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

    private static String parseInitFromJson(String json) {
        try {
            return new JSONObject(json).optString(INFO_KEY_INIT, null);
        } catch (Throwable th) {
            log("Failed to parse " + INFO_KEY_INIT + " from " + INFO_ENTRY_NAME);
            logThrowable(th);
            return null;
        }
    }

    // =====================================================================
    // 反射调用 onInject
    // =====================================================================

    /**
     * 支持以下四种签名(按优先级):
     *   1) static  onInject(File, Application)
     *   2) instance onInject(File, Application)
     *   3) static  onInject(Application)
     *   4) instance onInject(Application)
     *
     * 方案 A:用传入的 pluginLoader 加载 init 类,而不是宿主 loader。
     */
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
