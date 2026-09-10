#!/usr/bin/env python3
"""Resolve APK URL and version from workflow inputs."""
import os
import re
import requests
import sys

apk_url_input = os.environ.get("INPUT_APK_URL", "")
version_input = os.environ.get("INPUT_VERSION", "")

# Get trigger event name
trigger_event = os.environ.get("GITHUB_EVENT_NAME", "")

# Determine if triggered by core.dex update
is_core_dex_trigger = False
if trigger_event == "push":
    import subprocess
    result = subprocess.run(
        ["git", "diff", "--name-only", "HEAD~1", "HEAD"],
        capture_output=True, text=True
    )
    changed_files = result.stdout.strip().split("\n")
    if "core.dex" in changed_files:
        is_core_dex_trigger = True

print(f"Trigger event: {trigger_event}")
print(f"Is core.dex trigger: {is_core_dex_trigger}")

apk_url = None

if apk_url_input:
    apk_url = apk_url_input
else:
    # Auto-detect from API
    print("Auto-detecting latest APK URL...")
    try:
        resp = requests.get("https://adl.netease.com/d/g/mc/c/gwnew?type=android", timeout=30)
        resp.raise_for_status()
        content = resp.text

        for line in content.split("\n"):
            line = line.strip()
            if 'var android_link = android_type ? "' in line:
                match = re.search(r'var android_link = android_type \? "([^"]+)"', line)
                if match:
                    apk_url = match.group(1)
                    break

        if not apk_url:
            for line in content.split("\n"):
                line = line.strip()
                if 'android_link' in line and 'http' in line:
                    urls = re.findall(r'https?://[^\s"\']+', line)
                    if urls:
                        apk_url = urls[0]
                        break

        if not apk_url:
            print("::error::Failed to find APK URL in API response")
            sys.exit(1)

        print(f"Found APK URL: {apk_url}")

    except Exception as e:
        print(f"::error::Failed to auto-detect APK URL: {e}")
        sys.exit(1)

# Output results
with open(os.environ["GITHUB_OUTPUT"], "a") as f:
    f.write(f"apk_url={apk_url}\n")
    f.write(f"version_input={version_input}\n")
    f.write(f"is_core_dex_trigger={str(is_core_dex_trigger).lower()}\n")

print(f"apk_url={apk_url}")
