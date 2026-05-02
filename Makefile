# Cross-compilation examples:
#   make CROSS_COMPILE=arm-linux-gnueabihf-    # ARMv7 hard-float
#   make CROSS_COMPILE=arm-linux-gnueabi-      # ARMv7 soft-float (uclibc/musl)
#   make CROSS_COMPILE=aarch64-linux-gnu-      # AArch64
#   make CROSS_COMPILE=mipsel-linux-gnu-       # MIPS little-endian
CROSS_COMPILE ?=

CC     = $(CROSS_COMPILE)gcc
CFLAGS = -Wall -Wextra -Iinclude

TARGET      = portstealer
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

OBJS = $(SRCS:.c=.o)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(TEST_SERVER): test/server.c
	$(CC) $(CFLAGS) -o $@ $<

# hook/accept_hook.c contains naked functions — disable stack protector.
# On ARM targets, force ARM (not Thumb) mode so conditional data-processing
# instructions and register-shifted-register operands assemble correctly.
HOOK_ARCH_FLAGS := $(shell $(CC) -dumpmachine | grep -q arm && echo -marm)
hook/accept_hook.o: hook/accept_hook.c
	$(CC) $(CFLAGS) -fno-stack-protector $(HOOK_ARCH_FLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

all: $(TARGET) $(TEST_SERVER)

clean:
	rm -f $(OBJS) $(TARGET) $(TEST_SERVER)

.PHONY: all clean
