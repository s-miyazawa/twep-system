#!/bin/sh
# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
set -eu

APP=optee_example_twep_wr_ta
TA_UUID=6b9f4d2a-2f3e-4c7b-9d21-5a6f0e3c8b10

install -d /lib/optee_armtz /usr/bin /usr/lib
install -m 0444 "ta/${TA_UUID}.ta" "/lib/optee_armtz/${TA_UUID}.ta"
install -m 0755 "host/${APP}" "/usr/bin/${APP}"
if [ -f "guest/bin/twep_wr_public_abi_smoke" ]; then
	install -m 0755 "guest/bin/twep_wr_public_abi_smoke" "/usr/bin/twep_wr_public_abi_smoke"
fi
if [ -f "guest/bin/twepd" ]; then
	install -m 0755 "guest/bin/twepd" "/usr/bin/twepd"
fi
if [ -f "guest/bin/twep-cli" ]; then
	install -m 0755 "guest/bin/twep-cli" "/usr/bin/twep-cli"
fi
if [ -f "guest/build/libtwep_wr.so" ]; then
	install -m 0755 "guest/build/libtwep_wr.so" "/usr/lib/libtwep_wr.so"
fi

echo "deployed ${APP} and ${TA_UUID}.ta"
