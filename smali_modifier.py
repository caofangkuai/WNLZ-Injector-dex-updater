#!/usr/bin/env python3
"""
Smali Modifier - Adds com.wunelezi.injector.Inject.inject call to
ApplicationHandler.handleOnApplicationOnCreate(Landroid/content/Context;Landroid/app/Application;)V
"""

import os
import re
import sys


def find_smali_class(class_name, search_dirs):
    """Find smali file for a given class"""
    # Strip JNI type prefix (L) and suffix (;) if present
    clean_name = class_name
    if clean_name.startswith("L"):
        clean_name = clean_name[1:]
    if clean_name.endswith(";"):
        clean_name = clean_name[:-1]
    class_path = clean_name.replace(".", "/") + ".smali"
    for search_dir in search_dirs:
        if not os.path.exists(search_dir):
            continue
        full_path = os.path.join(search_dir, class_path)
        if os.path.exists(full_path):
            return full_path
        for root, dirs, files in os.walk(search_dir):
            for f in files:
                if f.endswith(".smali"):
                    filepath = os.path.join(root, f)
                    if filepath.endswith(class_path):
                        return filepath
    return None


def add_injector_call(smali_file):
    """
    Add com.wunelezi.injector.Inject.inject call to handleOnApplicationOnCreate method
    at the very beginning of the method body (after .registers/.locals).
    """
    with open(smali_file, 'r') as f:
        content = f.read()

    # Target: handleOnApplicationOnCreate(Landroid/content/Context;Landroid/app/Application;)V
    # Use negative lookahead to prevent matching across .method boundaries
    pattern = r'(\.method(?:(?!\.method)[\s\S])*?handleOnApplicationOnCreate\(Landroid/content/Context;\s*Landroid/app/Application;\)V[\s\S]*?\.end method)'
    match = re.search(pattern, content, re.DOTALL)

    if not match:
        return False

    method_body = match.group(1)

    # Check if injector call already exists
    if 'Lcom/wunelezi/injector/Inject;' in method_body:
        print(f"[SKIP] Injector call already exists in {smali_file}")
        return True

    lines = method_body.split('\n')

    # Insert after .registers or .locals line
    insert_idx = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('.registers') or stripped.startswith('.locals'):
            insert_idx = i + 1
            break

    injector_call = [
        "",
        "    invoke-static {p1}, Lcom/wunelezi/injector/Inject;->inject(Landroid/app/Application;)V",
        ""
    ]

    new_lines = lines[:insert_idx] + injector_call + lines[insert_idx:]
    new_method_body = '\n'.join(new_lines)
    content = content.replace(method_body, new_method_body)

    with open(smali_file, 'w') as f:
        f.write(content)

    print(f"[MODIFIED] {smali_file}: Added injector call")
    return True


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 smali_modifier.py <smali_output_dir>")
        sys.exit(1)

    smali_dir = sys.argv[1]

    # Build search list: all smali_classes* directories
    search_dirs = []
    if os.path.exists(smali_dir):
        for entry in sorted(os.listdir(smali_dir)):
            full = os.path.join(smali_dir, entry)
            if os.path.isdir(full) and entry.startswith("smali_classes"):
                search_dirs.append(full)
        # Also check root and legacy dirs
        search_dirs.append(smali_dir)
        legacy = os.path.join(smali_dir, "smali_main")
        if os.path.exists(legacy):
            search_dirs.append(legacy)

    if not search_dirs:
        print(f"::error::No smali directories found in {smali_dir}")
        sys.exit(1)

    target_class = "Lcom/netease/ntunisdk/base/ApplicationHandler"
    smali_file = find_smali_class(target_class, search_dirs)

    if smali_file:
        print(f"Found ApplicationHandler at: {smali_file}")
        add_injector_call(smali_file)
    else:
        print(f"::error::ApplicationHandler not found in {smali_dir}")
        sys.exit(1)


if __name__ == "__main__":
    main()
