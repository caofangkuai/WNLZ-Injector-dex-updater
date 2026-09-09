# WNLZ Injector DEX 自动更新器

自动化工作流：从网易我的世界 APK 中解密 DEX 文件，注入 WNZ LZ Injector 插件加载器，重新加密后发布到目标仓库。

## 工作流程

1. **下载**最新版 APK（或指定 URL）
2. **从 APK 中提取**加密的 DEX 文件
3. **解密** DEX 文件（网易易盾 XOR 加密）
4. **反编译** DEX 为 smali
5. **修改** smali：在 `handleOnApplicationOnCreate` 中插入 `Inject.inject()` 调用
6. **编译** `src/` 中的 Java 源码为 `core.dex`（或解密现有的 core.dex）
7. **重新编译** smali 为 DEX
8. **加密** DEX 文件并打包为 `dex.zip`
9. **发布**到目标 GitHub 仓库

## 触发方式

- **Push 触发**：`.py`、`core.dex`、`src/**`、`.github/workflows/**` 文件变更时
- **定时触发**：每 7 天执行一次
- **手动触发**：`workflow_dispatch`，可指定 APK URL 和版本号

## 密钥配置

| 密钥 | 说明 |
|------|------|
| `TARGET_REPO` | 发布到的目标仓库（格式: `owner/repo`） |
| `ACCESS_TOKEN` | GitHub 个人访问令牌，需要 `contents:write` 权限 |

## 目录结构

```
.
├── .github/workflows/dex-injector.yml   # 主工作流
├── dex_crypto_tool.py                   # DEX 加密/解密工具
├── smali_modifier.py                    # Smali 注入脚本
├── src/                                 # core.dex 的 Java 源码
│   └── com/wunelezi/injector/Inject.java
└── core.dex                             # 编译后的 DEX（不纳入版本控制）
```

## 依赖说明

- `src/` 目录需包含 `com.wunelezi.injector.Inject` 类
- baksmali/smali jar（自动下载并缓存）
- Android 构建工具：`d8` 和 `android.jar`（自动下载并缓存）
- androguard（用于解析 AndroidManifest.xml 获取版本号）

## 版本号格式

格式为 `版本名称_版本号`，例如 `3.9.15.297907_840297907`，从 APK 的 AndroidManifest.xml 中自动提取。

## 注意事项

- 如果目标仓库已存在包含 `dex.zip` 的 release，则跳过处理（core.dex 更新触发除外）
- `Inject` 类从外部存储的 `plugins.txt` 读取插件列表，通过 `DexClassLoader` 加载
