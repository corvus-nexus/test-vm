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


MODULE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+(?:\.[0-9]+)*$")
EXTERNAL_DEPENDENCY_RE = re.compile(r"^[A-Za-z0-9_.+:-]+$")
IGNORED_PARTS = {".git", ".github", ".ci", "__pycache__", ".venv", "venv", "node_modules"}
COPY_IGNORED_PARTS = IGNORED_PARTS | {".pytest_cache", ".mypy_cache"}
MAX_CUSTOM_MODULES = 512
SIDE_EFFECT_FORMAT = "odoo-addon-side-effects-v1"
SIDE_EFFECT_CATEGORIES = (
    "scheduled_jobs",
    "outbound_email",
    "inbound_email",
    "payments",
    "webhooks",
    "queues",
    "external_integrations",
    "none",
)
MAX_SIDE_EFFECT_DECLARATION_BYTES = 1024 * 1024


class ScanError(RuntimeError):
    pass


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ScanError(f"side-effect declaration contains duplicate key: {key}")
        result[key] = value
    return result


def load_side_effect_declaration(path: Path, module_names: list[str]) -> tuple[dict[str, list[str]], str]:
    if path.parent.is_symlink() or not path.parent.is_dir() or path.is_symlink() or not path.is_file():
        raise ScanError(f"side-effect declaration is missing or not a regular file: {path}")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ScanError(f"cannot inspect side-effect declaration {path}: {exc}") from exc
    if size <= 0 or size > MAX_SIDE_EFFECT_DECLARATION_BYTES:
        raise ScanError(f"side-effect declaration has an invalid size: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
    except ScanError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ScanError(f"cannot parse side-effect declaration {path}: {exc}") from exc
    if not isinstance(value, dict) or set(value) != {"format", "schema", "addons"}:
        raise ScanError("side-effect declaration must contain exactly format, schema, and addons")
    if value["format"] != SIDE_EFFECT_FORMAT or value["schema"] != 1:
        raise ScanError("side-effect declaration format or schema is unsupported")
    addons = value["addons"]
    if not isinstance(addons, dict):
        raise ScanError("side-effect declaration addons must be an object")
    expected = set(module_names)
    declared = set(addons)
    missing = sorted(expected - declared)
    unknown = sorted(declared - expected)
    if missing:
        raise ScanError(f"side-effect declaration is missing addon(s): {', '.join(missing)}")
    if unknown:
        raise ScanError(f"side-effect declaration contains unknown addon(s): {', '.join(unknown)}")

    category_order = {category: index for index, category in enumerate(SIDE_EFFECT_CATEGORIES)}
    normalized: dict[str, list[str]] = {}
    for module_name in sorted(module_names):
        entry = addons[module_name]
        if not isinstance(entry, dict) or set(entry) != {"categories"}:
            raise ScanError(f"side-effect declaration for {module_name} must contain exactly categories")
        categories = entry["categories"]
        if not isinstance(categories, list) or not categories or not all(isinstance(item, str) for item in categories):
            raise ScanError(f"side-effect categories for {module_name} must be a nonempty string array")
        if len(categories) != len(set(categories)):
            raise ScanError(f"side-effect categories for {module_name} contain duplicates")
        invalid = sorted(set(categories) - set(SIDE_EFFECT_CATEGORIES))
        if invalid:
            raise ScanError(f"side-effect categories for {module_name} are unknown: {', '.join(invalid)}")
        ordered = sorted(categories, key=category_order.__getitem__)
        if categories != ordered:
            raise ScanError(f"side-effect categories for {module_name} are not in canonical order")
        if "none" in categories and categories != ["none"]:
            raise ScanError(f"side-effect category none must be exclusive for {module_name}")
        normalized[module_name] = categories

    canonical = {
        "format": SIDE_EFFECT_FORMAT,
        "schema": 1,
        "addons": {name: {"categories": normalized[name]} for name in sorted(normalized)},
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return normalized, hashlib.sha256(encoded).hexdigest()


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
        if len(modules) > MAX_CUSTOM_MODULES:
            raise ScanError(f"repository contains more than {MAX_CUSTOM_MODULES} custom addons")
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
            # Keep export membership identical to checksum membership. In
            # particular, never let copytree dereference a symlink hidden
            # below a directory that module_checksum deliberately ignores.
            ignore=shutil.ignore_patterns(*sorted(COPY_IGNORED_PARTS), "*.pyc"),
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--odoo-version", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--copy-to", type=Path)
    parser.add_argument("--side-effects", type=Path)
    parser.add_argument("--compatibility", choices=("strict", "warn"), default="strict")
    parser.add_argument("--git-sha", default=os.environ.get("GIT_SHA", "unknown"))
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        raise ScanError(f"repository root is not a directory: {root}")
    modules = discover(root, args.odoo_version, args.compatibility)
    declaration_path = args.side_effects or root / ".odoo-deploy" / "side-effects.json"
    side_effects, declaration_sha256 = load_side_effect_declaration(
        declaration_path, [module["name"] for module in modules]
    )
    for module in modules:
        module["side_effect_categories"] = side_effects[module["name"]]
    if args.copy_to:
        copy_modules(root, args.copy_to, modules)
    result = {
        "schema": 2,
        "odoo_version": args.odoo_version,
        "git_sha": args.git_sha,
        "side_effect_contract": {
            "format": SIDE_EFFECT_FORMAT,
            "sha256": declaration_sha256,
        },
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
