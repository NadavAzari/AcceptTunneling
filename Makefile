# Cross-compilation examples:
#   make CROSS_COMPILE=arm-linux-gnueabihf-    # ARMv7 hard-float
#   make CROSS_COMPILE=arm-linux-gnueabi-      # ARMv7 soft-float (uclibc/musl)
#   make CROSS_COMPILE=aarch64-linux-gnu-      # AArch64
#   make CROSS_COMPILE=mipsel-linux-gnu-       # MIPS little-endian
CROSS_COMPILE ?=

CC          = $(CROSS_COMPILE)gcc
CFLAGS      = -Wall -Wextra -Iinclude $(EXTRA_CFLAGS)
LDFLAGS    ?=

# Override BUILDDIR and BIN for out-of-tree builds (used by the dist target).
BUILDDIR   ?= .
BIN        ?= portstealer

TEST_SERVER = test/server

SRCS = main.c             \
       proc/pid.c         \
       proc/exe.c         \
       proc/maps.c        \
       elf/load.c         \
       elf/got.c          \
       inject/ptrace.c    \
       inject/hook.c      \
       hook/accept_hook.c

OBJS = $(addprefix $(BUILDDIR)/,$(SRCS:.c=.o))

# hook/accept_hook.c contains naked functions — disable stack protector.
# On ARM targets, force ARM (not Thumb) mode so conditional data-processing
# instructions and register-shifted-register operands assemble correctly.
HOOK_ARCH_FLAGS := $(shell $(CC) -dumpmachine 2>/dev/null | grep -q arm && echo -marm)

# 'build' is the default goal for recursive dist invocations.
build: $(BIN)

$(BIN): $(OBJS)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) -o $@ $^

$(TEST_SERVER): test/server.c
	$(CC) $(CFLAGS) -o $@ $<

all: $(BIN) $(TEST_SERVER)

$(BUILDDIR)/hook/accept_hook.o: hook/accept_hook.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -fno-stack-protector $(HOOK_ARCH_FLAGS) -c -o $@ $<

$(BUILDDIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

# ── dist: build all static targets ───────────────────────────────────────────
# Output: dist/portstealer-arm   (ARMv7 hard-float, NVR302-32S kernel 3.18.x)
#         dist/portstealer-x64   (x86-64, statically linked)
#
# Note: x86-32 is omitted — hook/accept_hook.c has no __i386__ implementation.

dist:
	$(MAKE) build BIN=dist/portstealer-arm BUILDDIR=build/arm \
	        CROSS_COMPILE=arm-linux-gnueabihf- LDFLAGS=-static
	$(MAKE) build BIN=dist/portstealer-x64 BUILDDIR=build/x64 \
	        LDFLAGS=-static
	@echo ""
	@file dist/portstealer-arm dist/portstealer-x64

clean:
	rm -rf build dist
	rm -f $(OBJS) portstealer $(TEST_SERVER)

.PHONY: all build dist clean
