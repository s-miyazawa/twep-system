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
CMAKEFILE = ROOT / "lib/twep-wr/CMakeLists.txt"
RISCV_BUILD_SCRIPT = ROOT / "scripts/build_optee_riscv_v9.sh"
RISCV_PHASE_EXPECT = ROOT / "scripts/run_optee_riscv_v9_phase.exp"
RISCV_MODES_SCRIPT = ROOT / "scripts/run_optee_riscv_v9_modes.sh"
RISCV_MODES_EXPECT = ROOT / "scripts/run_optee_riscv_v9_modes.exp"
PLATFORM_DIR = ROOT / "lib/twep-wr/src/platform"

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
DUAL_PROFILE_TARGETS = {
    "smoke-optee-all-profiles": (
        "smoke-optee-trustzone",
        "smoke-optee-riscv-v9",
    ),
    "smoke-optee-all-profiles-offline-full": (
        "smoke-optee-arm-v8-offline-full",
        "smoke-optee-riscv-v9-offline-full",
    ),
}
LIVE_PROFILE_TARGET_PAIRS = {
    "attestam-live": (
        "smoke-optee-trustzone-attestam-live",
        "smoke-optee-riscv-v9-attestam-live",
    ),
    "attestam-verified-acceptance": (
        "smoke-optee-trustzone-attestam-verified-acceptance",
        "smoke-optee-riscv-v9-attestam-verified-acceptance",
    ),
    "attestam-verified-catalog": (
        "smoke-optee-trustzone-attestam-verified-catalog",
        "smoke-optee-riscv-v9-attestam-verified-catalog",
    ),
    "attestam-verified-app": (
        "smoke-optee-trustzone-attestam-verified-app",
        "smoke-optee-riscv-v9-attestam-verified-app",
    ),
}
LIVE_FIXTURE_TARGETS = {
    "attestam-live": ("register-attestam-helloworld-fixture",),
    "attestam-verified-acceptance": ("register-attestam-helloworld-fixture",),
    "attestam-verified-catalog": ("register-attestam-catalog-fixture",),
    "attestam-verified-app": (
        "register-attestam-app-catalog-fixture",
        "register-attestam-helloworld-fixture",
    ),
}


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
    for target in targets:
        block = parse_recipe(makefile, target)
        matches = GUEST_COMMAND_RE.findall(block)
        if len(matches) != 1:
            fail(f"{target} must contain exactly one run_trustzone_smokes.sh scenario, found {len(matches)}")
        scenarios[target] = matches[0]
    return scenarios


def parse_make_words(makefile: str, name: str) -> list[str]:
    lines = makefile.splitlines()
    prefix = f"{name} :="
    for index, line in enumerate(lines):
        if not line.startswith(prefix):
            continue
        words: list[str] = []
        fragment = line.split(":=", 1)[1]
        while True:
            continued = fragment.rstrip().endswith("\\")
            words.extend(fragment.rstrip().removesuffix("\\").split())
            if not continued:
                return words
            index += 1
            if index >= len(lines):
                fail(f"unterminated Makefile variable: {name}")
            fragment = lines[index]
    fail(f"Makefile variable not found: {name}")


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


def parse_recipe(makefile: str, target: str) -> str:
    match = re.search(
        rf"^{re.escape(target)}:[^\n]*\n(?P<body>(?:\t[^\n]*(?:\n|$))+)",
        makefile,
        re.MULTILINE,
    )
    if not match:
        fail(f"Makefile target has no recipe: {target}")
    return match.group("body")


def main() -> int:
    makefile = MAKEFILE.read_text()
    script = SMOKE_SCRIPT.read_text()
    testing_doc = TESTING_DOC.read_text()
    trustzone_readme = TRUSTZONE_README.read_text()
    cmakefile = CMAKEFILE.read_text()
    riscv_build_script = RISCV_BUILD_SCRIPT.read_text()
    riscv_phase_expect = RISCV_PHASE_EXPECT.read_text()
    riscv_modes_script = RISCV_MODES_SCRIPT.read_text()
    riscv_modes_expect = RISCV_MODES_EXPECT.read_text()

    for leaf in ("optee-common", "arm-optee", "riscv-optee"):
        if not (PLATFORM_DIR / leaf).is_dir():
            fail(f"missing OP-TEE platform directory: {leaf}")
    if (PLATFORM_DIR / "trustzone").exists():
        fail("ambiguous legacy platform/trustzone directory must be absent")
    legacy_common_terms = re.compile(
        r"TWEP_(?:WR_)?TZ|twep_(?:wr_)?tz|trustzone|TrustZone"
    )
    for source in (PLATFORM_DIR / "optee-common").glob("*"):
        if source.is_file() and legacy_common_terms.search(source.read_text()):
            fail(f"legacy TrustZone terminology remains in OP-TEE common code: {source.name}")
    for choice in ("arm-optee", "riscv-optee"):
        if f'TWEP_WR_PLATFORM_BACKEND STREQUAL "{choice}"' not in cmakefile:
            fail(f"CMake does not select {choice}")
    if 'TWEP_WR_PLATFORM_BACKEND STREQUAL "trustzone"' in cmakefile:
        fail("CMake must reject the ambiguous trustzone backend")
    if "src/platform/optee-common/optee_execute.c" not in cmakefile:
        fail("CMake OP-TEE choices do not include common sources")
    if "src/platform/arm-optee/platform_arm_optee.c" not in cmakefile:
        fail("CMake arm-optee choice does not include its leaf profile")
    if "src/platform/riscv-optee/platform_riscv_optee.c" not in cmakefile:
        fail("CMake riscv-optee choice does not include its leaf profile")
    if "arm-optee requires an arm or aarch64 target" not in cmakefile:
        fail("CMake does not reject arm-optee/CPU mismatches")
    if "riscv-optee requires a riscv64 target" not in cmakefile:
        fail("CMake does not reject riscv-optee/CPU mismatches")
    if "TWEP_OPTEE_PLATFORM_BACKEND=riscv-optee" not in riscv_build_script:
        fail("RISC-V build does not select the riscv-optee REE profile")
    if "TWEP_TA_PLATFORM_BACKEND=riscv-optee" not in riscv_build_script:
        fail("RISC-V build does not pass riscv-optee to the TA")
    if 'TWEP_TA_WAMR_LINK="${TWEP_TA_WAMR_LINK:-1}"' not in riscv_build_script:
        fail("RISC-V build does not provide an overridable WAMR link mode")
    if 'TWEP_TA_WAMR_LINK="$TWEP_TA_WAMR_LINK"' not in riscv_build_script:
        fail("RISC-V build does not pass its WAMR link mode to the TA")
    if '"$OVERLAY/opt/twep/ta/$source"' not in riscv_build_script:
        fail("RISC-V image does not stage TA sources required by the SHA-256 boundary smoke")

    phony_lines = " ".join(PHONY_RE.findall(makefile))
    all_phony_targets = set(phony_lines.split())
    for aggregate, members in DUAL_PROFILE_TARGETS.items():
        if aggregate not in all_phony_targets:
            fail(f"Makefile .PHONY is missing dual-profile target: {aggregate}")
        recipe = parse_recipe(makefile, aggregate)
        for member in members:
            if f"$(MAKE) {member}" not in recipe:
                fail(f"{aggregate} does not invoke required profile target: {member}")
        if f"make {aggregate}" not in testing_doc:
            fail(f"docs/Testing.md does not mention dual-profile target: {aggregate}")

    for target, marker in (
        ("smoke-optee-arm-v8-offline-full", "TWEP_ARM_OPTEE_V8_OFFLINE_FULL_PASS"),
        ("smoke-optee-riscv-v9-offline-full", "TWEP_RISCV_OPTEE_V9_OFFLINE_FULL_PASS"),
        ("smoke-optee-all-profiles-offline-full", "TWEP_OPTEE_ALL_PROFILES_OFFLINE_FULL_PASS"),
    ):
        if marker not in parse_recipe(makefile, target):
            fail(f"{target} is missing its final pass marker: {marker}")

    for mode, members in LIVE_PROFILE_TARGET_PAIRS.items():
        for member in members:
            if member not in all_phony_targets:
                fail(f"Makefile .PHONY is missing {mode} profile target: {member}")
            if not re.search(rf"^{re.escape(member)}:", makefile, re.MULTILINE):
                fail(f"Makefile does not define {mode} profile target: {member}")
            if f"make {member}" not in testing_doc:
                fail(f"docs/Testing.md does not mention {mode} profile target: {member}")
            recipe = parse_recipe(makefile, member)
            if "ATTESTAM_REGISTER_URL" not in recipe:
                fail(f"{member} does not require an AttesTAM registration URL")
            if "provision-veraison-generic-eat-fixture" not in recipe:
                fail(f"{member} does not provision the Veraison Generic EAT fixture")
            for fixture_target in LIVE_FIXTURE_TARGETS[mode]:
                if fixture_target not in recipe:
                    fail(f"{member} does not register required fixture: {fixture_target}")
        if mode not in riscv_phase_expect:
            fail(f"RISC-V live phase runner does not accept mode: {mode}")

    targets = parse_make_targets(makefile)
    phony_targets = parse_phony_targets(makefile)
    target_scenarios = parse_target_scenarios(makefile, targets)
    usage_modes = parse_usage_modes(script)
    case_modes = parse_case_modes(script)
    readme_modes = parse_readme_guest_runner_modes(trustzone_readme)

    live_modes = set(LIVE_PROFILE_TARGET_PAIRS)
    live_arm_targets = {members[0] for members in LIVE_PROFILE_TARGET_PAIRS.values()}
    expected_arm_offline_targets = targets - live_arm_targets
    arm_offline_targets = set(parse_make_words(makefile, "ARM_OPTEE_OFFLINE_TARGETS"))
    if arm_offline_targets != expected_arm_offline_targets:
        missing = sorted(expected_arm_offline_targets - arm_offline_targets)
        extra = sorted(arm_offline_targets - expected_arm_offline_targets)
        fail(f"ARM offline aggregate mismatch; missing={missing}, extra={extra}")

    riscv_mode_groups = {
        "normal": set(parse_make_words(makefile, "RISCV_OPTEE_OFFLINE_NORMAL_MODES")),
        "unlinked": set(parse_make_words(makefile, "RISCV_OPTEE_OFFLINE_UNLINKED_MODES")),
        "hooks": set(parse_make_words(makefile, "RISCV_OPTEE_OFFLINE_HOOK_MODES")),
    }
    group_names = list(riscv_mode_groups)
    for index, left_name in enumerate(group_names):
        for right_name in group_names[index + 1 :]:
            overlap = riscv_mode_groups[left_name] & riscv_mode_groups[right_name]
            if overlap:
                fail(f"RISC-V offline mode groups overlap ({left_name}/{right_name}): {sorted(overlap)}")
    expected_riscv_offline_modes = case_modes - ALLOWED_DIRECT_SCRIPT_MODES - live_modes
    configured_riscv_offline_modes = set().union(*riscv_mode_groups.values())
    if configured_riscv_offline_modes != expected_riscv_offline_modes:
        missing = sorted(expected_riscv_offline_modes - configured_riscv_offline_modes)
        extra = sorted(configured_riscv_offline_modes - expected_riscv_offline_modes)
        fail(f"RISC-V offline mode coverage mismatch; missing={missing}, extra={extra}")

    expected_riscv_groups = {"normal": set(), "unlinked": set(), "hooks": set()}
    for target, mode in target_scenarios.items():
        if mode in live_modes:
            continue
        recipe = parse_recipe(makefile, target)
        if "TWEP_TA_D043_TEST_HOOKS=1" in recipe:
            expected_riscv_groups["hooks"].add(mode)
        elif "TWEP_TA_WAMR_LINK=1" in recipe:
            expected_riscv_groups["normal"].add(mode)
        else:
            expected_riscv_groups["unlinked"].add(mode)
    for group_name, expected_modes in expected_riscv_groups.items():
        if riscv_mode_groups[group_name] != expected_modes:
            missing = sorted(expected_modes - riscv_mode_groups[group_name])
            extra = sorted(riscv_mode_groups[group_name] - expected_modes)
            fail(f"RISC-V {group_name} build-mode mapping mismatch; missing={missing}, extra={extra}")

    for target, variable in (
        ("smoke-optee-riscv-v9-offline-normal", "RISCV_OPTEE_OFFLINE_NORMAL_MODES"),
        ("smoke-optee-riscv-v9-offline-unlinked", "RISCV_OPTEE_OFFLINE_UNLINKED_MODES"),
        ("smoke-optee-riscv-v9-offline-hooks", "RISCV_OPTEE_OFFLINE_HOOK_MODES"),
    ):
        recipe = parse_recipe(makefile, target)
        if "run_optee_riscv_v9_modes.sh" not in recipe or f"$({variable})" not in recipe:
            fail(f"{target} does not run its configured RISC-V mode group")
    if "run_trustzone_smokes.sh" not in riscv_modes_expect:
        fail("RISC-V focused expect runner does not invoke the canonical guest runner")
    if "run_optee_riscv_v9_modes.exp" not in riscv_modes_script:
        fail("RISC-V focused shell runner does not invoke its expect driver")
    if ': >"$LOG"' not in riscv_modes_script:
        fail("RISC-V focused shell runner does not start with a fresh log")

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
        f"{len(targets)} ARM Makefile targets, {len(case_modes)} script modes, "
        f"{len(expected_riscv_offline_modes)} RISC-V offline modes in 3 build groups, "
        f"{len(DUAL_PROFILE_TARGETS)} dual-profile aggregate, "
        f"{len(LIVE_PROFILE_TARGET_PAIRS)} live profile pairs"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
