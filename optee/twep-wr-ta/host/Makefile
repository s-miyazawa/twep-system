# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
CC ?= $(CROSS_COMPILE)gcc

OBJS = main.o
BINARY = optee_example_twep_wr_ta

CFLAGS += -Wall -Wextra -Werror -I../ta/include -I$(TEEC_EXPORT)/include
LDADD += -lteec -L$(TEEC_EXPORT)/lib

ifeq ($(TWEP_TA_D043_TEST_HOOKS),1)
CFLAGS += -DTWEP_TA_D043_TEST_HOOKS=1
endif

.PHONY: all
all: $(BINARY)

$(BINARY): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $< $(LDADD)

.PHONY: clean
clean:
	rm -f $(OBJS) $(BINARY)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
