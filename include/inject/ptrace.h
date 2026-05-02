#ifndef INJECT_PTRACE_H
#define INJECT_PTRACE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#if defined(__x86_64__)
#  include <sys/user.h>
   typedef struct user_regs_struct ptrace_regs_t;
#elif defined(__arm__)
   typedef struct { unsigned long uregs[18]; } ptrace_regs_t;
#  define ARM_PC      uregs[15]
#  define ARM_CPSR    uregs[16]
#  define ARM_ORIG_R0 uregs[17]
#  define ARM_R0      uregs[0]
#  define ARM_R1      uregs[1]
#  define ARM_R2      uregs[2]
#  define ARM_R3      uregs[3]
#  define ARM_R4      uregs[4]
#  define ARM_R5      uregs[5]
#  define ARM_R7      uregs[7]
#  define ARM_THUMB_BIT (1 << 5)
#else
#  error "inject/ptrace: unsupported architecture"
#endif

/* Attach to pid and wait for it to stop. Returns 0 on success. */
int       ptrace_attach(pid_t pid);

/* Detach and let the process continue. */
void      ptrace_detach(pid_t pid);

/* Read/write arbitrary bytes in the target's address space.
 * Both handle word-alignment internally. Return 0 on success. */
int       ptrace_read_mem(pid_t pid, uintptr_t addr, void *buf, size_t len);
int       ptrace_write_mem(pid_t pid, uintptr_t addr, const void *buf, size_t len);

/* Read or write one pointer-sized value (GOT entry, function pointer…). */
uintptr_t ptrace_read_ptr(pid_t pid, uintptr_t addr);
void      ptrace_write_ptr(pid_t pid, uintptr_t addr, uintptr_t val);

/* Execute a syscall inside the target process and return its result.
 * The target is left paused at the same instruction it was at before. */
long      ptrace_inject_syscall(pid_t pid, long nr,
                                long a0, long a1, long a2,
                                long a3, long a4, long a5);

/* Allocate one RWX page inside the target via an injected mmap syscall.
 * Returns the page address in the target's VA space, or 0 on failure. */
uintptr_t ptrace_alloc_page(pid_t pid);

/* Overwrite a GOT entry.  Reads and returns the original value
 * (the real function address) so the caller can save it for the hook. */
uintptr_t ptrace_patch_got(pid_t pid, uintptr_t got_addr, uintptr_t hook_addr);

#endif
