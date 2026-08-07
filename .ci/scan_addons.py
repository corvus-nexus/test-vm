#!/usr/bin/env python3
"""Discover Odoo addons without executing repository code.

The generated manifest is embedded in the image and used by the server to
upgrade only custom modules that are already installed and whose source changed.
An empty addon set is valid.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any


MODULE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+(?:\.[0-9]+)*$")
EXTERNAL_DEPENDENCY_RE = re.compile(r"^[A-Za-z0-9_.+:-]+$")
IGNORED_PARTS = {".git", ".github", ".ci", "__pycache__", ".venv", "venv", "node_modules"}


class ScanError(RuntimeError):
    pass


def load_manifest(path: Path) -> dict[str, Any]:
    if path.stat().st_size > 1024 * 1024:
        raise ScanError(f"manifest is unexpectedly large: {path}")
    try:
        value = ast.literal_eval(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError, ValueError) as exc:
        raise ScanError(f"cannot parse {path} as a literal dictionary: {exc}") from exc
    if not isinstance(value, dict):
        raise ScanError(f"manifest is not a dictionary: {path}")
    return value


def validate_string_list(value: Any, field: str, path: Path) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ScanError(f"{path}: {field} must be a list of strings")
    if len(value) != len(set(value)):
        raise ScanError(f"{path}: {field} contains duplicates")
    if field == "depends" and any(MODULE_RE.fullmatch(item) is None for item in value):
        raise ScanError(f"{path}: depends contains an invalid technical module name")
    if field.startswith("external_dependencies.") and any(
        EXTERNAL_DEPENDENCY_RE.fullmatch(item) is None for item in value
    ):
        raise ScanError(f"{path}: {field} contains an invalid dependency name")
    return sorted(value)


def module_checksum(module_dir: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(module_dir.rglob("*"), key=lambda item: item.as_posix()):
        if any(part in IGNORED_PARTS for part in path.parts):
            continue
        if path.is_symlink():
            raise ScanError(f"symlinks are not allowed in addon directories: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(module_dir).as_posix().encode()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def discover(root: Path, odoo_version: str, compatibility: str) -> list[dict[str, Any]]:
    expected_major = odoo_version.split(".", 1)[0]
    modules: list[dict[str, Any]] = []
    seen: dict[str, Path] = {}
    warnings: list[str] = []
    for manifest_path in sorted(root.rglob("__manifest__.py")):
        relative_parts = manifest_path.relative_to(root).parts
        if any(part in IGNORED_PARTS for part in relative_parts):
            continue
        module_dir = manifest_path.parent
        name = module_dir.name
        if not MODULE_RE.fullmatch(name):
            raise ScanError(f"addon directory is not a valid technical name: {module_dir}")
        if name in seen:
            raise ScanError(f"duplicate addon technical name {name}: {seen[name]} and {module_dir}")
        seen[name] = module_dir
        manifest = load_manifest(manifest_path)
        version_value = manifest.get("version", "")
        if not isinstance(version_value, str):
            raise ScanError(f"{manifest_path}: version must be a string")
        version = version_value.strip()
        if version and VERSION_RE.fullmatch(version) is None:
            raise ScanError(f"{manifest_path}: version is malformed")
        declared_major = version.split(".", 1)[0] if version else ""
        if version and (not version.startswith(f"{odoo_version}.") and version != odoo_version):
            message = f"{manifest_path}: version {version} is incompatible with Odoo {odoo_version}"
            if compatibility == "strict":
                raise ScanError(message)
            warnings.append(message)
        depends = validate_string_list(manifest.get("depends", []), "depends", manifest_path)
        installable = manifest.get("installable", True)
        auto_install = manifest.get("auto_install", False)
        license_value = manifest.get("license", "")
        if not isinstance(installable, bool):
            raise ScanError(f"{manifest_path}: installable must be a boolean")
        if not isinstance(auto_install, bool):
            raise ScanError(f"{manifest_path}: auto_install must be a boolean")
        if not isinstance(license_value, str) or len(license_value) > 64:
            raise ScanError(f"{manifest_path}: license must be a short string")
        external = manifest.get("external_dependencies", {})
        if not isinstance(external, dict):
            raise ScanError(f"{manifest_path}: external_dependencies must be a dictionary")
        normalized_external: dict[str, list[str]] = {}
        for key, value in sorted(external.items()):
            if not isinstance(key, str):
                raise ScanError(f"{manifest_path}: external dependency keys must be strings")
            normalized_external[key] = validate_string_list(value, f"external_dependencies.{key}", manifest_path)
        modules.append(
            {
                "name": name,
                "path": module_dir.relative_to(root).as_posix(),
                "version": version,
                "installable": installable,
                "auto_install": auto_install,
                "depends": depends,
                "external_dependencies": normalized_external,
                "license": license_value,
                "checksum": module_checksum(module_dir),
            }
        )
    for warning in warnings:
        print(f"WARNING: {warning}", file=sys.stderr)
    return modules


def copy_modules(root: Path, destination: Path, modules: list[dict[str, Any]]) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for module in modules:
        source = root / module["path"]
        target = destination / module["name"]
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(
            source,
            target,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache", ".mypy_cache"),
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--odoo-version", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--copy-to", type=Path)
    parser.add_argument("--compatibility", choices=("strict", "warn"), default="strict")
    parser.add_argument("--git-sha", default=os.environ.get("GIT_SHA", "unknown"))
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        raise ScanError(f"repository root is not a directory: {root}")
    modules = discover(root, args.odoo_version, args.compatibility)
    if args.copy_to:
        copy_modules(root, args.copy_to, modules)
    result = {
        "schema": 1,
        "odoo_version": args.odoo_version,
        "git_sha": args.git_sha,
        "custom_modules": modules,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(args.output)
    print(f"discovered {len(modules)} custom addon(s)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ScanError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
