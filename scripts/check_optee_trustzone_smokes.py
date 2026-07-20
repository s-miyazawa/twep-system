#!/usr/bin/env python3
# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
"""Check static naming consistency for OP-TEE TrustZone smoke targets."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = ROOT / "Makefile"
SMOKE_SCRIPT = ROOT / "optee/twep-wr-ta/run_trustzone_smokes.sh"
TESTING_DOC = ROOT / "docs/Testing.md"
TRUSTZONE_README = ROOT / "optee/twep-wr-ta/README.md"

TARGET_RE = re.compile(r"^(smoke-optee-trustzone[-a-z0-9]*):$", re.MULTILINE)
PHONY_RE = re.compile(r"^\.PHONY:\s*(.*)$", re.MULTILINE)
GUEST_COMMAND_RE = re.compile(r"run_trustzone_smokes\.sh\s+([a-z0-9-]+)")
USAGE_RE = re.compile(r"usage: \$0 \[([a-z0-9| -]+)\]")
CASE_RE = re.compile(r"^([a-z0-9-]+)\)\s*$", re.MULTILINE)
README_GUEST_RUNNER_RE = re.compile(
    r"^## Guest Runner\s*$\n(?P<body>.*?)(?=^## |\Z)",
    re.DOTALL | re.MULTILINE,
)

ALLOWED_DIRECT_SCRIPT_MODES = {"default", "diagnose", "provision"}


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def target_sort_key(target: str) -> tuple[int, str]:
    if target == "smoke-optee-trustzone":
        return (0, target)
    return (1, target)


def parse_make_targets(makefile: str) -> set[str]:
    return set(TARGET_RE.findall(makefile))


def parse_phony_targets(makefile: str) -> set[str]:
    phony_targets: set[str] = set()
    for match in PHONY_RE.finditer(makefile):
        phony_targets.update(match.group(1).split())
    return {target for target in phony_targets if target.startswith("smoke-optee-trustzone")}


def parse_target_scenarios(makefile: str, targets: set[str]) -> dict[str, str]:
    scenarios: dict[str, str] = {}
    sorted_targets = sorted(targets, key=lambda target: makefile.index(f"{target}:"))
    for index, target in enumerate(sorted_targets):
        start = makefile.index(f"{target}:")
        if index + 1 < len(sorted_targets):
            end = makefile.index(f"{sorted_targets[index + 1]}:")
        else:
            next_target = re.search(r"^[A-Za-z0-9_.-]+:", makefile[start + len(target) + 1 :], re.MULTILINE)
            end = start + len(target) + 1 + next_target.start() if next_target else len(makefile)
        block = makefile[start:end]
        matches = GUEST_COMMAND_RE.findall(block)
        if len(matches) != 1:
            fail(f"{target} must contain exactly one run_trustzone_smokes.sh scenario, found {len(matches)}")
        scenarios[target] = matches[0]
    return scenarios


def parse_usage_modes(script: str) -> set[str]:
    match = USAGE_RE.search(script)
    if not match:
        fail("run_trustzone_smokes.sh usage line not found")
    return set(match.group(1).split("|"))


def parse_case_modes(script: str) -> set[str]:
    modes = set(CASE_RE.findall(script))
    modes.discard("*")
    if not modes:
        fail("run_trustzone_smokes.sh case modes not found")
    return modes


def parse_readme_guest_runner_modes(readme: str) -> set[str]:
    match = README_GUEST_RUNNER_RE.search(readme)
    if not match:
        fail("README Guest Runner mode list not found")
    modes = set(GUEST_COMMAND_RE.findall(match.group("body")))
    if not modes:
        fail("README Guest Runner mode list is empty")
    return modes


def expected_target_for_mode(mode: str) -> str:
    if mode == "all":
        return "smoke-optee-trustzone"
    return f"smoke-optee-trustzone-{mode}"


def main() -> int:
    makefile = MAKEFILE.read_text()
    script = SMOKE_SCRIPT.read_text()
    testing_doc = TESTING_DOC.read_text()
    trustzone_readme = TRUSTZONE_README.read_text()

    targets = parse_make_targets(makefile)
    phony_targets = parse_phony_targets(makefile)
    target_scenarios = parse_target_scenarios(makefile, targets)
    usage_modes = parse_usage_modes(script)
    case_modes = parse_case_modes(script)
    readme_modes = parse_readme_guest_runner_modes(trustzone_readme)

    missing_phony = sorted(targets - phony_targets, key=target_sort_key)
    if missing_phony:
        fail(f"Makefile .PHONY is missing TrustZone targets: {', '.join(missing_phony)}")

    extra_phony = sorted(phony_targets - targets, key=target_sort_key)
    if extra_phony:
        fail(f"Makefile .PHONY lists undefined TrustZone targets: {', '.join(extra_phony)}")

    if usage_modes != case_modes:
        missing_usage = sorted(case_modes - usage_modes)
        missing_case = sorted(usage_modes - case_modes)
        if missing_usage:
            fail(f"run_trustzone_smokes.sh usage is missing modes: {', '.join(missing_usage)}")
        fail(f"run_trustzone_smokes.sh case is missing modes: {', '.join(missing_case)}")

    if readme_modes != case_modes:
        missing_readme = sorted(case_modes - readme_modes)
        extra_readme = sorted(readme_modes - case_modes)
        if missing_readme:
            fail(f"README Guest Runner list is missing modes: {', '.join(missing_readme)}")
        fail(f"README Guest Runner list references unknown modes: {', '.join(extra_readme)}")

    script_modes_for_make = case_modes - ALLOWED_DIRECT_SCRIPT_MODES
    missing_targets = sorted(
        expected_target_for_mode(mode) for mode in script_modes_for_make if expected_target_for_mode(mode) not in targets
    )
    if missing_targets:
        fail(f"script modes have no Makefile target: {', '.join(missing_targets)}")

    missing_script_modes = sorted(
        f"{target} -> {scenario}"
        for target, scenario in target_scenarios.items()
        if scenario not in case_modes
    )
    if missing_script_modes:
        fail(f"Makefile targets reference unknown script modes: {', '.join(missing_script_modes)}")

    missing_doc_targets = sorted(
        target for target in targets if f"make {target}" not in testing_doc
    )
    if missing_doc_targets:
        fail(f"docs/Testing.md does not mention TrustZone targets: {', '.join(missing_doc_targets)}")

    print(
        "OP-TEE TrustZone smoke mapping ok: "
        f"{len(targets)} Makefile targets, {len(case_modes)} script modes"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
