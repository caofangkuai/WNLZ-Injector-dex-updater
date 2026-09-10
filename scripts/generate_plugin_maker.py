#!/usr/bin/env python3
"""Generate plugin-maker.jar by analyzing src/ public API.

Scans src/ for Java files, extracts public class/method/field signatures,
generates stub implementations, and packages into a JAR for plugin compilation.
"""
import os
import re
import subprocess
import sys
import tempfile


def find_java_files(src_dir):
    """Find all .java files in src directory."""
    java_files = []
    for root, dirs, files in os.walk(src_dir):
        for f in files:
            if f.endswith('.java'):
                java_files.append(os.path.join(root, f))
    return sorted(java_files)


def parse_java_file(filepath):
    """Parse a Java file and extract public API information."""
    with open(filepath, 'r') as f:
        content = f.read()

    result = {
        'package': '',
        'classes': []
    }

    # Extract package
    pkg_match = re.search(r'^\s*package\s+([\w.]+)\s*;', content, re.MULTILINE)
    if pkg_match:
        result['package'] = pkg_match.group(1)

    # Remove comments to avoid false matches
    content_no_comments = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
    content_no_comments = re.sub(r'/\*.*?\*/', '', content_no_comments, flags=re.DOTALL)

    # Find all class declarations with their bodies
    class_pattern = r'(?:public\s+)?(?:abstract\s+)?(?:final\s+)?class\s+(\w+)\s*(?:extends\s+[\w<>,\s]+)?\s*(?:implements\s+[\w<>,\s]+)?\s*\{'

    for match in re.finditer(class_pattern, content_no_comments):
        class_name = match.group(1)
        start = match.end()

        # Find matching closing brace
        depth = 1
        pos = start
        while pos < len(content_no_comments) and depth > 0:
            if content_no_comments[pos] == '{':
                depth += 1
            elif content_no_comments[pos] == '}':
                depth -= 1
            pos += 1

        class_body = content_no_comments[start:pos-1]

        # Check if class is public by looking at the full match
        full_match = match.group(0)
        is_public = 'public' in full_match

        # Extract public methods
        methods = []
        method_pattern = r'(?:^|;)[\s\n]*(public|private|protected)?\s*([\w<>\[\],\s]+?)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[\w,\s]+)?\s*\{'

        for meth_match in re.finditer(method_pattern, class_body):
            visibility = (meth_match.group(1) or '').strip()
            return_type = meth_match.group(2).strip()
            method_name = meth_match.group(3)
            params = meth_match.group(4).strip()

            # Skip control flow statements
            if method_name in ('if', 'while', 'for', 'switch', 'catch', 'synchronized', 'return', 'throw'):
                continue

            # Skip constructors
            if method_name == class_name:
                continue

            # Only public methods
            if visibility != 'public':
                continue

            # Parse parameters
            param_list = []
            if params:
                for param in params.split(','):
                    param = param.strip()
                    if param:
                        parts = param.split()
                        if len(parts) >= 2:
                            param_type = ' '.join(parts[:-1])
                            param_name = parts[-1].rstrip('[]')
                            param_list.append((param_type, param_name))

            methods.append({
                'return_type': return_type,
                'name': method_name,
                'params': param_list,
                'params_raw': params,
                'visibility': visibility
            })

        # Extract public fields
        fields = []
        field_pattern = r'(?:public|private|protected)?\s*(?:static\s+)?(?:final\s+)?([\w<>\[\],\s]+?)\s+(\w+)\s*(?:=\s*[^;]+)?\s*;'

        for field_match in re.finditer(field_pattern, class_body):
            modifiers = field_match.group(0).split(field_match.group(1))[0].strip() if field_match.group(0).split(field_match.group(1)) else ''
            field_type = field_match.group(1).strip()
            field_name = field_match.group(2).strip()

            if 'public' in modifiers and field_name != 'serialVersionUID':
                fields.append({
                    'type': field_type,
                    'name': field_name,
                    'is_static': 'static' in modifiers,
                    'is_final': 'final' in modifiers
                })

        result['classes'].append({
            'name': class_name,
            'is_public': is_public,
            'methods': methods,
            'fields': fields
        })

    return result


def generate_stub(parsed):
    """Generate stub Java source from parsed API."""
    package = parsed['package']
    classes = parsed['classes']

    lines = []
    if package:
        lines.append(f'package {package};')
        lines.append('')

    # Collect imports from public method signatures
    imports = set()
    type_map = {
        'Application': 'android.app.Application',
        'Activity': 'android.app.Activity',
        'Context': 'android.content.Context',
        'Intent': 'android.content.Intent',
        'Bundle': 'android.os.Bundle',
        'View': 'android.view.View',
        'ViewGroup': 'android.view.ViewGroup',
        'LayoutInflater': 'android.view.LayoutInflater',
        'SharedPreferences': 'android.content.SharedPreferences',
        'File': 'java.io.File',
        'List': 'java.util.List',
        'Map': 'java.util.Map',
        'ArrayList': 'java.util.ArrayList',
        'HashMap': 'java.util.HashMap',
        'JSONObject': 'org.json.JSONObject',
        'JSONArray': 'org.json.JSONArray',
        'DexClassLoader': 'dalvik.system.DexClassLoader',
    }

    for cls in classes:
        for meth in cls['methods']:
            ret = meth['return_type']
            for short, full in type_map.items():
                if short in ret:
                    imports.add(full)
            for ptype, pname in meth['params']:
                for short, full in type_map.items():
                    if short in ptype:
                        imports.add(full)
        for field in cls.get('fields', []):
            for short, full in type_map.items():
                if short in field['type']:
                    imports.add(full)

    for imp in sorted(imports):
        lines.append(f'import {imp};')
    if imports:
        lines.append('')

    for cls in classes:
        if not cls['is_public']:
            continue

        lines.append(f'public class {cls["name"]} {{')
        lines.append('')

        # Fields
        for field in cls['fields']:
            modifiers = 'public'
            if field['is_static']:
                modifiers += ' static'
            if field['is_final']:
                modifiers += ' final'
            lines.append(f'    {modifiers} {field["type"]} {field["name"]};')

        if cls['fields']:
            lines.append('')

        # Methods
        for meth in cls['methods']:
            params_str = meth['params_raw']
            lines.append(f'    public {meth["return_type"]} {meth["name"]}({params_str}) {{')

            # Return default value
            ret = meth['return_type']
            # Check if void (may have modifiers like 'static void')
            if 'void' in ret:
                pass
            elif ret in ('boolean',):
                lines.append('        return false;')
            elif ret in ('int', 'short', 'byte', 'long', 'float', 'double'):
                lines.append('        return 0;')
            elif ret in ('char',):
                lines.append("        return '\\0';")
            elif ret.endswith('[]') or 'List' in ret or 'Map' in ret or 'Array' in ret:
                lines.append('        return null;')
            else:
                lines.append('        return null;')

            lines.append('    }')
            lines.append('')

        lines.append('}')
        lines.append('')

    return '\n'.join(lines)


def main():
    src_dir = sys.argv[1] if len(sys.argv) > 1 else 'src'
    output_jar = sys.argv[2] if len(sys.argv) > 2 else 'plugin-maker.jar'
    android_jar = sys.argv[3] if len(sys.argv) > 3 else '/tmp/android.jar'

    if not os.path.exists(src_dir):
        print(f"Source directory not found: {src_dir}")
        sys.exit(1)

    java_files = find_java_files(src_dir)
    if not java_files:
        print(f"No Java files found in {src_dir}")
        sys.exit(1)

    print(f"Found {len(java_files)} Java file(s)")

    # Parse all Java files
    all_parsed = []
    for filepath in java_files:
        parsed = parse_java_file(filepath)
        if parsed['classes']:
            all_parsed.append(parsed)
            for cls in parsed['classes']:
                public_methods = len([m for m in cls['methods']])
                print(f"  {parsed['package']}.{cls['name']}: {public_methods} public method(s)")

    # Merge all classes by package
    packages = {}
    for parsed in all_parsed:
        pkg = parsed['package']
        if pkg not in packages:
            packages[pkg] = {'package': pkg, 'classes': []}
        packages[pkg]['classes'].extend(parsed['classes'])

    # Generate stubs
    with tempfile.TemporaryDirectory() as tmpdir:
        source_files = []
        for pkg, data in packages.items():
            stub_source = generate_stub(data)
            if not stub_source.strip():
                continue

            # Write source files
            if pkg:
                pkg_dir = os.path.join(tmpdir, 'src', pkg.replace('.', '/'))
            else:
                pkg_dir = os.path.join(tmpdir, 'src')
            os.makedirs(pkg_dir, exist_ok=True)

            # Use the first public class name as filename, or 'Stubs' if none
            public_classes = [c for c in data['classes'] if c['is_public']]
            if public_classes:
                filename = f"{public_classes[0]['name']}.java"
            else:
                filename = 'Stubs.java'

            filepath = os.path.join(pkg_dir, filename)
            with open(filepath, 'w') as f:
                f.write(stub_source)
            source_files.append(filepath)
            print(f"Generated: {filepath}")

        # Compile
        if not source_files:
            print("No source files generated")
            sys.exit(1)

        compile_cmd = ['javac', '--release', '8', '-classpath', android_jar] + source_files
        print(f"Compiling: {' '.join(compile_cmd)}")
        result = subprocess.run(compile_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Compilation failed:\n{result.stderr}")
            sys.exit(1)

        print("Compilation successful")

        # Create JAR
        class_files = []
        for root, dirs, files in os.walk(os.path.join(tmpdir, 'src')):
            for f in files:
                if f.endswith('.class'):
                    class_files.append(os.path.join(root, f))

        if not class_files:
            print("No class files generated")
            sys.exit(1)

        # Create JAR
        jar_dir = os.path.join(tmpdir, 'jar')
        os.makedirs(jar_dir, exist_ok=True)
        jar_path = os.path.join(jar_dir, os.path.basename(output_jar))

        os.chdir(os.path.join(tmpdir, 'src'))
        class_args = [os.path.relpath(f, os.path.join(tmpdir, 'src')) for f in class_files]
        jar_cmd = ['jar', 'cf', jar_path] + class_args
        print(f"Creating JAR: {' '.join(jar_cmd)}")
        result = subprocess.run(jar_cmd, capture_output=True, text=True, cwd=os.path.join(tmpdir, 'src'))
        if result.returncode != 0:
            print(f"JAR creation failed:\n{result.stderr}")
            sys.exit(1)

        # Copy to output
        import shutil
        shutil.copy2(jar_path, output_jar)
        print(f"Created: {output_jar} ({os.path.getsize(output_jar)} bytes)")


if __name__ == '__main__':
    main()
