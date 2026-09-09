#!/usr/bin/env python3
"""
Smali Modifier - Adds com.wunelezi.injector.Inject.inject call
to the ApplicationHandler.handleOnApplicationOnCreate method.
"""

import os
import re
import sys


def find_smali_class(class_name, search_dirs):
    """Find smali file for a given class"""
    for search_dir in search_dirs:
        if not os.path.exists(search_dir):
            continue
        class_path = class_name.replace(".", "/") + ".smali"
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
    Add com.wunelezi.injector.Inject.inject call to handleOnApplicationOnCreate method.
    The method signature is:
        handleOnApplicationOnCreate(Landroid/content/Context; Landroid/app/Application;)V
    We need to add: invoke-static {p1}, Lcom/wunelezi/injector/Inject;->inject(Landroid/app/Application;)V
    """
    with open(smali_file, 'r') as f:
        content = f.read()

    # Pattern to find handleOnApplicationOnCreate method with Application parameter
    # This is the method that has both Context and Application parameters
    pattern = r'(\.method[\s\S]*?handleOnApplicationOnCreate\(Landroid/content/Context;\s*Landroid/app/Application;\)V[\s\S]*?\.end method)'

    match = re.search(pattern, content, re.DOTALL)
    if not match:
        # Try a more general pattern
        pattern = r'(\.method[\s\S]*?public\s+static\s+handleOnApplicationOnCreate[\s\S]*?\.end method)'
        match = re.search(pattern, content, re.DOTALL)

    if match:
        method_body = match.group(1)
        lines = method_body.split('\n')

        # Find insertion point (after .locals/.registers line)
        insert_idx = 0
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('.locals') or stripped.startswith('.registers'):
                insert_idx = i + 1
                break
            elif stripped.startswith('.param'):
                insert_idx = i + 1
                continue
            elif stripped.startswith('.annotation'):
                insert_idx = i + 1
                continue
            elif stripped and not stripped.startswith('.') and not stripped.startswith('#'):
                insert_idx = i
                break

        # Check if injector call already exists
        if 'Lcom/wunelezi/injector/Inject;' in method_body:
            print(f"[SKIP] Injector call already exists in {smali_file}")
            return True

        # Create the injector call
        # p0 = Context (first parameter for static method)
        # p1 = Application (second parameter for static method)
        injector_call = [
            "",
            "    # WNLZ Injector call",
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

    return False


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 smali_modifier.py <smali_output_dir>")
        sys.exit(1)

    smali_dir = sys.argv[1]
    search_dirs = [
        os.path.join(smali_dir, "smali_main"),
        os.path.join(smali_dir, "smali_core"),
        smali_dir
    ]

    # Filter to existing directories
    search_dirs = [d for d in search_dirs if os.path.exists(d)]

    if not search_dirs:
        print(f"::error::No smali directories found in {smali_dir}")
        sys.exit(1)

    print(f"Searching for ApplicationHandler in: {search_dirs}")

    # Target class
    target_class = "Lcom/netease/ntunisdk/base/ApplicationHandler"
    smali_file = find_smali_class(target_class, search_dirs)

    modified = False
    if smali_file:
        print(f"Found ApplicationHandler at: {smali_file}")
        if add_injector_call(smali_file):
            modified = True
    else:
        print("ApplicationHandler not found, searching for any handler class...")
        for search_dir in search_dirs:
            for root, dirs, files in os.walk(search_dir):
                for f in files:
                    if f.endswith(".smali"):
                        filepath = os.path.join(root, f)
                        with open(filepath, 'r') as sf:
                            content = sf.read()
                        if 'handleOnApplicationOnCreate' in content:
                            print(f"Found handler in: {filepath}")
                            if add_injector_call(filepath):
                                modified = True
                                break

    if not modified:
        print("::warning::Could not find suitable method to modify")
        print("This might mean the dex file already has the injector call")
        print("or the method signature is different than expected")

    print("Smali modification complete")


if __name__ == "__main__":
    main()
