# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause

# This file is loaded after OP-TEE build/qemu_v8.mk.  It deliberately reuses
# the official image paths and QEMU arguments instead of maintaining a second
# board definition in TWEP.

TWEP_TEE_LOG ?= $(CURDIR)/serial1-twep.log

.PHONY: twep-qemu
twep-qemu:
	ln -sf $(ROOT)/out-br/images/rootfs.cpio.gz $(BINARIES_PATH)/
	cd $(BINARIES_PATH) && $(QEMU_BIN) \
		$(QEMU_BASE_ARGS) $(QEMU_SCMI_ARGS) $(QEMU_RUN_ARGS_COMMON) \
		-serial mon:stdio -serial file:$(TWEP_TEE_LOG)
