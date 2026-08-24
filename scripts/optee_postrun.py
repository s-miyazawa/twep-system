#!/usr/bin/env python3
# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
"""Run a TWEP guest scenario on the official OP-TEE QEMU v8 image."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import sys
import time
import uuid

try:
    import pexpect
except ImportError as exc:  # pragma: no cover - environment preflight
    raise SystemExit(
        "python3-pexpect is required; install it with "
        "'sudo apt-get install python3-pexpect'"
    ) from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="run a command in OP-TEE QEMU v8 and validate both consoles"
    )
    parser.add_argument("--project-path", required=True, type=Path)
    parser.add_argument("--guest-command", required=True)
    parser.add_argument("--expect-ree", action="append", default=[])
    parser.add_argument("--expect-tee", action="append", default=[])
    parser.add_argument(
        "--optee-root",
        type=Path,
        default=Path(os.environ.get("OPTEE_ROOT", "~/opt/optee")).expanduser(),
    )
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--log-dir", type=Path)
    return parser.parse_args()


def require_file(path: Path, description: str, executable: bool = False) -> None:
    if not path.is_file():
        raise SystemExit(f"missing {description}: {path}")
    if executable and not os.access(path, os.X_OK):
        raise SystemExit(f"{description} is not executable: {path}")


def report_missing(label: str, expected: list[str], text: str) -> bool:
    missing = [item for item in expected if item not in text]
    for item in missing:
        print(f"missing {label} expectation: {item!r}", file=sys.stderr)
    return bool(missing)


def main() -> int:
    args = parse_args()
    if args.timeout <= 0:
        raise SystemExit("--timeout must be positive")

    project = args.project_path.expanduser().resolve()
    optee_root = args.optee_root.expanduser().resolve()
    optee_build = optee_root / "build"
    runner_mk = Path(__file__).resolve().with_name("optee_qemu_v8_runner.mk")
    qemu_mk = optee_build / "qemu_v8.mk"
    qemu_bin = optee_root / "qemu" / "build" / "qemu-system-aarch64"
    if not qemu_bin.is_file():
        qemu_bin = (
            optee_root
            / "qemu"
            / "build"
            / "aarch64-softmmu"
            / "qemu-system-aarch64"
        )

    require_file(project / "deploy.sh", "TWEP guest deploy script", executable=True)
    require_file(project / "host" / "optee_example_twep_wr_ta", "TWEP host app")
    require_file(
        project / "ta" / "6b9f4d2a-2f3e-4c7b-9d21-5a6f0e3c8b10.ta",
        "TWEP trusted application",
    )
    require_file(qemu_mk, "OP-TEE qemu_v8.mk")
    require_file(runner_mk, "TWEP QEMU make overlay")
    require_file(qemu_bin, "OP-TEE QEMU binary", executable=True)
    require_file(optee_root / "out" / "bin" / "bl1.bin", "OP-TEE QEMU BL1")
    require_file(optee_root / "out-br" / "images" / "rootfs.cpio.gz", "rootfs")

    if shutil.which("make") is None:
        raise SystemExit("make is required")

    log_dir = (
        args.log_dir.expanduser().resolve()
        if args.log_dir
        else project / "build" / "postrun-logs"
    )
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    run_id = f"{stamp}-{os.getpid()}"
    ree_log = log_dir / f"ree-{run_id}.log"
    tee_log = log_dir / f"tee-{run_id}.log"

    command = "make"
    make_args = [
        "--no-print-directory",
        "-f",
        str(qemu_mk),
        "-f",
        str(runner_mk),
        "twep-qemu",
        "QEMU_VIRTFS_AUTOMOUNT=y",
        f"QEMU_VIRTFS_HOST_DIR={project}",
        f"TWEP_TEE_LOG={tee_log}",
    ]

    token = f"__TWEP_POSTRUN_RC_{uuid.uuid4().hex}__"
    guest_line = (
        "cd /mnt/host && ./deploy.sh && ( "
        + args.guest_command
        + " ); twep_postrun_rc=$?; "
        + f"printf '\\n{token}%d\\n' \"$twep_postrun_rc\"; "
        + "sync; poweroff -f"
    )

    child: pexpect.spawn | None = None
    guest_rc: int | None = None
    try:
        with ree_log.open("w", encoding="utf-8", errors="replace") as ree_stream:
            child = pexpect.spawn(
                command,
                make_args,
                cwd=str(optee_build),
                encoding="utf-8",
                codec_errors="replace",
                timeout=args.timeout,
            )
            child.logfile_read = ree_stream
            boot = child.expect(
                [r"(?m)^\r?(?:buildroot )?login:", r"Kernel panic"]
            )
            if boot == 1:
                raise RuntimeError("Normal World kernel panic during boot")
            # Use carriage returns explicitly because the QEMU serial console is
            # a terminal, not a pipe.  Anchor the prompt at the beginning of a
            # line so U-Boot messages such as "## Booting ..." cannot satisfy it.
            child.send("root\r")
            child.expect(r"(?m)^# ")
            child.send(guest_line + "\r")
            result = child.expect([re.escape(token) + r"([0-9]+)", r"Kernel panic"])
            if result == 1:
                raise RuntimeError("Normal World kernel panic during guest command")
            guest_rc = int(child.match.group(1))
            try:
                child.expect(pexpect.EOF, timeout=60)
            except pexpect.TIMEOUT:
                child.terminate(force=True)
    except (pexpect.TIMEOUT, pexpect.EOF, RuntimeError) as exc:
        print(f"OP-TEE QEMU run failed: {exc}", file=sys.stderr)
    finally:
        if child is not None and child.isalive():
            child.terminate(force=True)

    ree_text = ree_log.read_text(encoding="utf-8", errors="replace")
    tee_text = (
        tee_log.read_text(encoding="utf-8", errors="replace")
        if tee_log.exists()
        else ""
    )
    failed = guest_rc is None or guest_rc != 0
    if guest_rc not in (None, 0):
        print(f"guest command exited with status {guest_rc}", file=sys.stderr)
    failed |= report_missing("REE", args.expect_ree, ree_text)
    failed |= report_missing("TEE", args.expect_tee, tee_text)

    print(f"REE log: {ree_log}")
    print(f"TEE log: {tee_log}")
    if failed:
        return 1
    print("OP-TEE QEMU v8 post-run checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
