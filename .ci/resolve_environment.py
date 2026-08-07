#!/usr/bin/env python3
"""Resolve one configured Git branch to a fixed deployment environment.

The accepted branch syntax is an intentionally conservative subset of Git's
ref-format rules that is safe to render into the generated GitHub workflow:
ASCII letters, digits, ``._/-``, at most 200 characters, and no empty, hidden,
``.lock``-suffixed, doubled-slash, doubled-dot, or trailing-dot components.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Mapping, Optional, Sequence


ENVIRONMENTS = ("development", "staging", "live")
SAFE_BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}")


class RouteError(ValueError):
    """The configured mapping or requested branch is unsafe or ambiguous."""


def validate_branch(name: str, label: str) -> None:
    if not name:
        raise RouteError(f"{label} branch is empty")
    if not SAFE_BRANCH.fullmatch(name):
        raise RouteError(f"{label} branch is malformed")
    if ".." in name or "//" in name or name.endswith("."):
        raise RouteError(f"{label} branch is malformed")
    components = name.split("/")
    if any(
        not component or component.startswith(".") or component.endswith(".lock")
        for component in components
    ):
        raise RouteError(f"{label} branch is malformed")
    if name == "HEAD" or name.startswith("refs/"):
        raise RouteError(f"{label} branch is malformed")


def resolve_environment(ref_name: str, branches: Mapping[str, str]) -> str:
    if set(branches) != set(ENVIRONMENTS):
        raise RouteError("branch mapping must define development, staging, and live exactly once")

    for environment in ENVIRONMENTS:
        validate_branch(branches[environment], environment)

    configured = list(branches.values())
    if len(set(configured)) != len(configured):
        raise RouteError("development, staging, and live branches must be distinct")

    validate_branch(ref_name, "requested")
    matches = [environment for environment in ENVIRONMENTS if ref_name == branches[environment]]
    if len(matches) != 1:
        raise RouteError("requested branch is not configured for deployment")
    return matches[0]


def validate_github_branch_ref(ref_name: str, ref_type: str, full_ref: str) -> None:
    """Reject tags and any ref whose complete identity is not this branch."""

    if ref_type != "branch" or full_ref != f"refs/heads/{ref_name}":
        raise RouteError("requested ref is not an exact branch ref")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", required=True, help="complete GitHub ref_name to resolve")
    parser.add_argument("--ref-type", required=True, help="GitHub ref_type; must be branch")
    parser.add_argument("--full-ref", required=True, help="complete GitHub ref; must be refs/heads/<ref>")
    for environment in ENVIRONMENTS:
        parser.add_argument(f"--{environment}", required=True, help=f"configured {environment} branch")
    parser.add_argument("--github-output", type=Path, help="append fixed outputs to this GitHub output file")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    branches = {environment: getattr(args, environment) for environment in ENVIRONMENTS}
    try:
        validate_github_branch_ref(args.ref, args.ref_type, args.full_ref)
        environment = resolve_environment(args.ref, branches)
    except RouteError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 64

    output = f"environment={environment}\nconvenience_tag={environment}\n"
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as handle:
            handle.write(output)
    else:
        sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
