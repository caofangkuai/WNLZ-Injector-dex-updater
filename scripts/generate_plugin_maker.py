#!/usr/bin/env python3
"""Generate plugin-maker.jar from core.dex smali.

Disassembles core.dex with baksmali, filters smali files by package,
and packages them directly into a JAR for reference.
"""
import os
import shutil
import subprocess
import sys
import tempfile


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
        print("\n[1/3] Disassembling core.dex...")
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"baksmali failed: {result.stderr}")
            sys.exit(1)
        print("  Done")

        # Step 2: Filter smali files by package
        print(f"\n[2/3] Filtering smali files ({package_filter})...")
        pkg_dir = os.path.join(smali_dir, package_filter)
        if not os.path.exists(pkg_dir):
            print(f"  Package directory not found: {pkg_dir}")
            sys.exit(1)

        # Copy filtered smali to a clean directory
        filtered_dir = os.path.join(tmpdir, 'filtered')
        shutil.copytree(pkg_dir, filtered_dir)
        smali_files = []
        for root, dirs, files in os.walk(filtered_dir):
            for f in files:
                if f.endswith('.smali'):
                    smali_files.append(os.path.join(root, f))
        print(f"  Found {len(smali_files)} smali file(s)")

        # Step 3: Create JAR with smali files
        print(f"\n[3/3] Creating JAR...")
        jar_path = os.path.join(tmpdir, output_jar)
        # Use absolute paths with jar command
        jar_cmd = ['jar', 'cf', jar_path, '-C', filtered_dir, '.']
        result = subprocess.run(jar_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"JAR creation failed:\n{result.stderr}")
            sys.exit(1)

        shutil.copy2(jar_path, output_jar)
        size = os.path.getsize(output_jar)
        print(f"  Created: {output_jar} ({size} bytes)")
        print(f"  Contains {len(smali_files)} smali file(s)")


if __name__ == '__main__':
    main()
