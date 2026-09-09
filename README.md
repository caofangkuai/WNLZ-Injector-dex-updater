# WNLZ Injector DEX Updater

Automated workflow that decrypts, modifies, and re-encrypts DEX files from NetEase Minecraft APK to inject the WNZ LZ Injector plugin loader.

## How It Works

1. **Download** the latest APK (or use a provided URL)
2. **Extract** encrypted DEX files from APK assets
3. **Decrypt** DEX files using NetEase Yidun decryption (XOR-based)
4. **Decompile** DEX to smali via baksmali
5. **Modify** smali to add `Inject.inject()` call in `handleOnApplicationOnCreate`
6. **Compile** Java source from `src/` to `core.dex` via d8 (or decompile existing core.dex)
7. **Recompile** smali back to DEX via smali
8. **Encrypt** DEX files and package as `dex.zip`
9. **Release** to a target GitHub repository

## Trigger Modes

- **Push**: Triggered by changes to `.py`, `core.dex`, `src/**`, or workflow files
- **Scheduled**: Every 7 days via cron
- **Manual**: `workflow_dispatch` with optional APK URL and version inputs

## Secrets

| Secret | Description |
|--------|-------------|
| `TARGET_REPO` | Target repository for releases (format: `owner/repo`) |
| `ACCESS_TOKEN` | GitHub personal access token with `contents:write` permission |

## File Structure

```
.
├── .github/workflows/dex-injector.yml   # Main workflow
├── dex_crypto_tool.py                   # DEX encrypt/decrypt tool
├── smali_modifier.py                    # Smali injection script
├── src/                                 # Java source for core.dex
│   └── com/wunelezi/injector/Inject.java
└── core.dex                             # Compiled DEX (gitignored)
```

## Requirements

- `src/` directory with Java source containing `com.wunelezi.injector.Inject` class
- baksmali/smali jars (auto-downloaded and cached)
- Android build tools: `d8` and `android.jar` (auto-downloaded and cached)

## Notes

- If a release with `dex.zip` already exists, the workflow skips (except when triggered by `core.dex` update)
- The `Inject` class loads plugin ZIPs from `plugins.txt` in external storage and injects them via `DexClassLoader`
