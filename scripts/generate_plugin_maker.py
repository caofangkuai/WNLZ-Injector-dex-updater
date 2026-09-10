#!/usr/bin/env python3
"""Generate plugin-maker.jar from core.dex smali.

Disassembles core.dex with baksmali, filters smali files by package,
strips private methods and implementation code, keeping only public
method signatures as stubs, then packages into a JAR.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile


def strip_smali_to_public_api(smali_path, output_path):
    """Strip smali file to only public method signatures.

    Removes:
    - Private methods entirely
    - All fields
    - Method implementation code (keeps only .method/.end method with nop)
    - Annotations
    """
    with open(smali_path, 'r') as f:
        lines = f.readlines()

    output = []
    in_method = False
    method_is_public = False

    for line in lines:
        stripped = line.strip()

        # Keep class declaration
        if stripped.startswith('.class'):
            output.append(line)
            continue

        # Keep .super
        if stripped.startswith('.super'):
            output.append(line)
            continue

        # Keep .source
        if stripped.startswith('.source'):
            output.append(line)
            continue

        # Skip all field declarations
        if stripped.startswith('.field'):
            continue

        # Skip annotations
        if stripped.startswith('.annotation') or stripped.startswith('.end annotation'):
            continue

        # Method handling
        if stripped.startswith('.method'):
            in_method = True
            method_is_public = 'public' in stripped
            # Skip constructors
            if '<init>' in stripped or '<clinit>' in stripped:
                method_is_public = False
            if method_is_public:
                output.append(line)
                # Add minimal stub body
                output.append('    .registers 0\n')
                output.append('\n')
                output.append('    return-void\n')
                output.append('.end method\n')
            continue

        if in_method:
            if stripped == '.end method':
                in_method = False
                method_is_public = False
            continue

        # Skip everything else (comments, blank lines between sections)
        if stripped.startswith('#') or stripped == '':
            continue

        # Keep any other directives we might have missed
        if stripped.startswith('.'):
            output.append(line)

    # Ensure output ends with newline
    if output and not output[-1].endswith('\n'):
        output[-1] += '\n'

    with open(output_path, 'w') as f:
        f.writelines(output)


def main():
    if len(sys.argv) < 3:
        print("Usage: python generate_plugin_maker.py <core.dex> <baksmali_jars> [output.jar] [package_filter]")
        sys.exit(1)

    dex_path = sys.argv[1]
    baksmali_jars = sys.argv[2]
    output_jar = sys.argv[3] if len(sys.argv) > 3 else 'plugin-maker.jar'
    package_filter = sys.argv[4] if len(sys.argv) > 4 else 'com/wunelezi'

    if not os.path.exists(dex_path):
        print(f"DEX file not found: {dex_path}")
        sys.exit(1)

    print(f"core.dex: {dex_path}")
    print(f"package filter: {package_filter}")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Step 1: Disassemble
        smali_dir = os.path.join(tmpdir, 'smali')
        os.makedirs(smali_dir)
        cmd = ['java', '-cp', baksmali_jars, 'org.jf.baksmali.Main', 'disassemble', dex_path, '-o', smali_dir]
        print("\n[1/4] Disassembling core.dex...")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"baksmali failed: {result.stderr}")
            sys.exit(1)
        print("  Done")

        # Step 2: Filter smali files by package
        print(f"\n[2/4] Filtering smali files ({package_filter})...")
        pkg_dir = os.path.join(smali_dir, package_filter)
        if not os.path.exists(pkg_dir):
            print(f"  Package directory not found: {pkg_dir}")
            sys.exit(1)

        # Step 3: Strip to public API only
        print("\n[3/4] Stripping to public API...")
        stripped_dir = os.path.join(tmpdir, 'stripped')
        os.makedirs(stripped_dir)

        smali_files = []
        for root, dirs, files in os.walk(pkg_dir):
            for f in files:
                if not f.endswith('.smali'):
                    continue
                src_path = os.path.join(root, f)
                # Maintain relative structure
                rel_path = os.path.relpath(src_path, pkg_dir)
                dst_path = os.path.join(stripped_dir, rel_path)
                os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                strip_smali_to_public_api(src_path, dst_path)
                smali_files.append(rel_path)
                print(f"  Stripped: {rel_path}")

        print(f"  Processed {len(smali_files)} file(s)")

        # Step 4: Create JAR
        print(f"\n[4/4] Creating JAR...")
        jar_path = os.path.join(tmpdir, output_jar)
        jar_cmd = ['jar', 'cf', jar_path, '-C', stripped_dir, '.']
        result = subprocess.run(jar_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"JAR creation failed:\n{result.stderr}")
            sys.exit(1)

        shutil.copy2(jar_path, output_jar)
        size = os.path.getsize(output_jar)
        print(f"  Created: {output_jar} ({size} bytes)")


if __name__ == '__main__':
    main()
