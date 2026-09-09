package com.wunelezi.injector;

import android.app.Application;
import dalvik.system.DexClassLoader;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import org.json.JSONObject;

public class Inject {
    private static final String PLUGIN_LIST_FILE = "plugins.txt";
    private static final int BUFFER_SIZE = 4096;

    public static void inject(Application application) {
        try {
            File externalFilesDir = application.getExternalFilesDir(null);
            File pluginListFile = new File(externalFilesDir, PLUGIN_LIST_FILE);
            if (!pluginListFile.exists()) {
                log("plugins.txt not found at " + pluginListFile.getAbsolutePath());
                return;
            }
            BufferedReader reader = new BufferedReader(new FileReader(pluginListFile));
            while (true) {
                String line = reader.readLine();
                if (line != null) {
                    String trimmed = line.trim();
                    if (!trimmed.isEmpty()) {
                        log("Processing plugin: " + trimmed);
                        try {
                            processPlugin(new File(externalFilesDir, trimmed), application);
                        } catch (Throwable th) {
                            log("Failed to process plugin: " + trimmed);
                            th.printStackTrace();
                        }
                    }
                } else {
                    reader.close();
                    return;
                }
            }
        } catch (Throwable th) {
            log("inject failed");
            th.printStackTrace();
        }
    }

    private static void processPlugin(File pluginZip, Application application) {
        if (!pluginZip.exists()) {
            log("Plugin zip not found: " + pluginZip.getAbsolutePath());
            return;
        }
        List<File> loadedDexFiles = loadAllDexFromZip(pluginZip, application);
        if (loadedDexFiles.isEmpty()) {
            log("No .dex entries found in: " + pluginZip.getAbsolutePath());
        } else {
            log("Loaded " + loadedDexFiles.size() + " dex file(s) from: " + pluginZip.getAbsolutePath());
        }
        String initClassName = readInitClassFromZip(pluginZip);
        if (initClassName == null || initClassName.isEmpty()) {
            log("No init class found in info.json for: " + pluginZip.getAbsolutePath());
            return;
        }
        log("Init class: " + initClassName);
        Object result = invokeOnInit(initClassName, pluginZip, application);
        if (result != null) {
            try {
                if (result instanceof Application.ActivityLifecycleCallbacks) {
                    application.registerActivityLifecycleCallbacks((Application.ActivityLifecycleCallbacks) result);
                    log("Registered ActivityLifecycleCallbacks from " + initClassName);
                    return;
                }
                Application.class.getMethod("registerActivityLifecycleCallbacks", Application.ActivityLifecycleCallbacks.class).invoke(application, result);
                log("Registered ActivityLifecycleCallbacks (reflection) from " + initClassName);
                return;
            } catch (Throwable th) {
                log("Failed to register ActivityLifecycleCallbacks");
                th.printStackTrace();
                return;
            }
        }
        log("onInject returned null for " + initClassName);
    }

    private static List<File> loadAllDexFromZip(File pluginZip, Application application) {
        ArrayList<File> result = new ArrayList<>();
        File dexDir = application.getDir("wnlz_dex", 0);
        ClassLoader parentClassLoader = Inject.class.getClassLoader();
        ZipFile zipFile = null;
        try {
            zipFile = new ZipFile(pluginZip);
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String entryName = entry.getName();
                if (entryName != null && !entry.isDirectory() && entryName.toLowerCase().endsWith(".dex")) {
                    File outputFile = new File(dexDir, "plugin_" + System.nanoTime() + "_" + new File(entryName).getName());
                    InputStream inputStream = zipFile.getInputStream(entry);
                    try {
                        FileOutputStream outputStream = new FileOutputStream(outputFile);
                        try {
                            byte[] buffer = new byte[BUFFER_SIZE];
                            int bytesRead;
                            while ((bytesRead = inputStream.read(buffer)) > 0) {
                                outputStream.write(buffer, 0, bytesRead);
                            }
                        } finally {
                            outputStream.close();
                        }
                    } finally {
                        inputStream.close();
                    }
                    try {
                        DexClassLoader pluginLoader = new DexClassLoader(outputFile.getAbsolutePath(), dexDir.getAbsolutePath(), null, parentClassLoader);
                        combineDexElements(pluginLoader, parentClassLoader);
                        result.add(outputFile);
                        log("Loaded dex entry: " + entryName + " -> " + outputFile.getAbsolutePath());
                    } catch (Throwable th) {
                        log("Failed to load dex entry: " + entryName);
                        th.printStackTrace();
                    }
                }
            }
        } catch (Throwable th) {
            log("Failed to enumerate dex from: " + pluginZip.getAbsolutePath());
            th.printStackTrace();
        } finally {
            if (zipFile != null) {
                try {
                    zipFile.close();
                } catch (Exception ignored) {
                }
            }
        }
        return result;
    }

    private static void combineDexElements(ClassLoader sourceLoader, ClassLoader targetLoader) {
        try {
            Field pathListField = Class.forName("dalvik.system.BaseDexClassLoader").getDeclaredField("pathList");
            pathListField.setAccessible(true);
            Object sourcePathList = pathListField.get(sourceLoader);
            Object targetPathList = pathListField.get(targetLoader);
            if (sourcePathList != null && targetPathList != null) {
                Field dexElementsField = Class.forName("dalvik.system.DexPathList").getDeclaredField("dexElements");
                dexElementsField.setAccessible(true);
                Object[] sourceElements = (Object[]) dexElementsField.get(sourcePathList);
                Object[] targetElements = (Object[]) dexElementsField.get(targetPathList);
                Object[] combined = (Object[]) Array.newInstance(sourceElements.getClass().getComponentType(), sourceElements.length + targetElements.length);
                System.arraycopy(sourceElements, 0, combined, 0, sourceElements.length);
                System.arraycopy(targetElements, 0, combined, sourceElements.length, targetElements.length);
                dexElementsField.set(targetPathList, combined);
                log("Combined " + sourceElements.length + " dex elements into classloader");
            } else {
                log("pathList is null, cannot combine dex elements");
            }
        } catch (Throwable th) {
            log("Failed to combine dex elements");
            th.printStackTrace();
        }
    }

    private static String readInitClassFromZip(File pluginZip) {
        ZipFile zipFile = null;
        try {
            zipFile = new ZipFile(pluginZip);
            ZipEntry infoEntry = zipFile.getEntry("info.json");
            if (infoEntry == null) {
                log("info.json not found in zip: " + pluginZip.getAbsolutePath());
                return null;
            }
            BufferedReader reader = new BufferedReader(new java.io.InputStreamReader(zipFile.getInputStream(infoEntry)));
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line);
            }
            reader.close();
            return parseInitFromJson(content.toString());
        } catch (Throwable th) {
            log("Failed to read info.json from: " + pluginZip.getAbsolutePath());
            th.printStackTrace();
            return null;
        } finally {
            if (zipFile != null) {
                try {
                    zipFile.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    private static String parseInitFromJson(String json) {
        try {
            return new JSONObject(json).getString("init");
        } catch (Throwable th) {
            log("Failed to parse init from info.json");
            th.printStackTrace();
            return null;
        }
    }

    private static Object invokeOnInit(String className, File pluginZip, Application application) {
        try {
            Class<?> initClass = Class.forName(className, true, application.getClassLoader());
            log("Loaded init class: " + initClass.getName());
            try {
                Method onInjectStatic = initClass.getDeclaredMethod("onInject", File.class, Application.class);
                onInjectStatic.setAccessible(true);
                log("Invoking static onInject(File, Application)");
                return onInjectStatic.invoke(null, pluginZip, application);
            } catch (NoSuchMethodException e) {
                try {
                    Method onInjectInstance = initClass.getDeclaredMethod("onInject", File.class, Application.class);
                    onInjectInstance.setAccessible(true);
                    log("Invoking instance onInject(File, Application)");
                    return onInjectInstance.invoke(initClass.newInstance(), pluginZip, application);
                } catch (NoSuchMethodException e2) {
                    try {
                        Method onInjectLegacy = initClass.getDeclaredMethod("onInject", Application.class);
                        onInjectLegacy.setAccessible(true);
                        log("Invoking static onInject(Application) [legacy]");
                        return onInjectLegacy.invoke(null, application);
                    } catch (NoSuchMethodException e3) {
                        Object instance = initClass.newInstance();
                        Method onInjectInstanceLegacy = initClass.getDeclaredMethod("onInject", Application.class);
                        onInjectInstanceLegacy.setAccessible(true);
                        log("Invoking instance onInject(Application) [legacy]");
                        return onInjectInstanceLegacy.invoke(instance, application);
                    }
                }
            }
        } catch (Throwable th) {
            log("Failed to invoke onInject on " + className);
            th.printStackTrace();
            return null;
        }
    }

    private static void log(String message) {
        System.out.println("[WNLZ-Inject] " + message);
    }
}
