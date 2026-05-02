#include "inject/ptrace.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/syscall.h>

/* ------------------------------------------------------------------ */
/* Attach / detach                                                      */
/* ------------------------------------------------------------------ */

int ptrace_attach(pid_t pid)
{
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("ptrace_attach: PTRACE_ATTACH");
        return -1;
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("ptrace_attach: waitpid");
        return -1;
    }
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "ptrace_attach: process did not stop\n");
        return -1;
    }
    return 0;
}

void ptrace_detach(pid_t pid)
{
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

/* ------------------------------------------------------------------ */
/* Memory read / write                                                  */
/* ------------------------------------------------------------------ */

/* PTRACE_PEEKDATA / POKEDATA operate in word-sized (sizeof long) chunks
 * and require natural alignment.  These two helpers hide that. */

static long read_word(pid_t pid, uintptr_t addr)
{
    errno = 0;
    long v = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
    if (v == -1 && errno) {
        perror("ptrace read_word");
        return -1;
    }
    return v;
}

static int write_word(pid_t pid, uintptr_t addr, long word)
{
    if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)word) < 0) {
        perror("ptrace write_word");
        return -1;
    }
    return 0;
}

int ptrace_read_mem(pid_t pid, uintptr_t addr, void *buf, size_t len)
{
    uint8_t  *dst  = buf;
    uintptr_t cur  = addr;
    size_t    left = len;

    while (left > 0) {
        uintptr_t aligned = cur & ~(sizeof(long) - 1);
        size_t    off     = cur - aligned;
        size_t    chunk   = sizeof(long) - off;
        if (chunk > left) chunk = left;

        long word = read_word(pid, aligned);
        if (word == -1 && errno) return -1;
        memcpy(dst, (uint8_t *)&word + off, chunk);

        dst  += chunk;
        cur  += chunk;
        left -= chunk;
    }
    return 0;
}

int ptrace_write_mem(pid_t pid, uintptr_t addr, const void *buf, size_t len)
{
    const uint8_t *src  = buf;
    uintptr_t      cur  = addr;
    size_t         left = len;

    while (left > 0) {
        uintptr_t aligned = cur & ~(sizeof(long) - 1);
        size_t    off     = cur - aligned;
        size_t    chunk   = sizeof(long) - off;
        if (chunk > left) chunk = left;

        long word = 0;
        if (off != 0 || chunk < sizeof(long)) {
            /* partial word: read first to preserve surrounding bytes */
            word = read_word(pid, aligned);
            if (word == -1 && errno) return -1;
        }
        memcpy((uint8_t *)&word + off, src, chunk);
        if (write_word(pid, aligned, word) < 0) return -1;

        src  += chunk;
        cur  += chunk;
        left -= chunk;
    }
    return 0;
}

uintptr_t ptrace_read_ptr(pid_t pid, uintptr_t addr)
{
    uintptr_t val = 0;
    ptrace_read_mem(pid, addr, &val, sizeof(val));
    return val;
}

void ptrace_write_ptr(pid_t pid, uintptr_t addr, uintptr_t val)
{
    ptrace_write_mem(pid, addr, &val, sizeof(val));
}

/* ------------------------------------------------------------------ */
/* Register save / restore                                              */
/* ------------------------------------------------------------------ */

static int save_regs(pid_t pid, ptrace_regs_t *regs)
{
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
        perror("save_regs: PTRACE_GETREGS");
        return -1;
    }
    return 0;
}

static int restore_regs(pid_t pid, const ptrace_regs_t *regs)
{
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
        perror("restore_regs: PTRACE_SETREGS");
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Syscall injection                                                    */
/* ------------------------------------------------------------------ */

/*
 * x86-64: overwrite 3 bytes at RIP with  syscall (0F 05) + int3 (CC),
 *         set rax/rdi/rsi/rdx/r10/r8/r9, PTRACE_CONT, wait for SIGTRAP.
 *
 * ARM: check CPSR T-bit for Thumb vs ARM mode, write the right
 *      encoding of  svc #0 + bkpt #0  at PC,
 *      set r7 (syscall nr) + r0-r5 (args), PTRACE_CONT, wait.
 *
 * In both cases the original instruction bytes and registers are
 * fully restored before returning.
 */

#if defined(__x86_64__)

static const uint8_t SYSCALL_INSTR[] = { 0x0f, 0x05, 0xcc }; /* syscall; int3 */

static void regs_setup_syscall(ptrace_regs_t *r,
                                long nr,
                                long a0, long a1, long a2,
                                long a3, long a4, long a5)
{
    r->rax = (unsigned long long)nr;
    r->rdi = (unsigned long long)a0;
    r->rsi = (unsigned long long)a1;
    r->rdx = (unsigned long long)a2;
    r->r10 = (unsigned long long)a3;
    r->r8  = (unsigned long long)a4;
    r->r9  = (unsigned long long)a5;
}

static uintptr_t regs_pc(const ptrace_regs_t *r) { return r->rip; }
static long      regs_result(const ptrace_regs_t *r) { return (long)r->rax; }

#elif defined(__arm__)

/* ARM mode: svc #0 (E7 00 90 EF ← wrong, correct below) + bkpt #0 */
/* ARM mode little-endian encoding:
 *   svc  #0  = 0xEF000000
 *   bkpt #0  = 0xE1200070
 * Thumb mode:
 *   svc  #0  = 0xDF00  (2 bytes)
 *   bkpt #0  = 0xBE00  (2 bytes)
 */
static const uint8_t SYSCALL_ARM_INSTR[]   = { 0x00, 0x00, 0x00, 0xef,   /* svc #0  */
                                                0x70, 0x00, 0x20, 0xe1 }; /* bkpt #0 */
static const uint8_t SYSCALL_THUMB_INSTR[] = { 0x00, 0xdf,               /* svc #0  */
                                                0x00, 0xbe };             /* bkpt #0 */

static void regs_setup_syscall(ptrace_regs_t *r,
                                long nr,
                                long a0, long a1, long a2,
                                long a3, long a4, long a5)
{
    r->ARM_R7 = (unsigned long)nr;
    r->ARM_R0 = (unsigned long)a0;
    r->ARM_R1 = (unsigned long)a1;
    r->ARM_R2 = (unsigned long)a2;
    r->ARM_R3 = (unsigned long)a3;
    r->ARM_R4 = (unsigned long)a4;
    r->ARM_R5 = (unsigned long)a5;
}

static uintptr_t regs_pc(const ptrace_regs_t *r) { return r->ARM_PC; }
static long      regs_result(const ptrace_regs_t *r) { return (long)r->ARM_R0; }
static int       regs_is_thumb(const ptrace_regs_t *r)
{
    return (r->ARM_CPSR & ARM_THUMB_BIT) != 0;
}

#endif

long ptrace_inject_syscall(pid_t pid, long nr,
                            long a0, long a1, long a2,
                            long a3, long a4, long a5)
{
    ptrace_regs_t saved, modified;
    if (save_regs(pid, &saved) < 0) return -1;

    uintptr_t pc = regs_pc(&saved);

    /* Save original bytes at PC and overwrite with syscall+breakpoint. */
#if defined(__x86_64__)
    uint8_t orig[sizeof(SYSCALL_INSTR)];
    ptrace_read_mem(pid, pc, orig, sizeof(orig));
    ptrace_write_mem(pid, pc, SYSCALL_INSTR, sizeof(SYSCALL_INSTR));
#elif defined(__arm__)
    int thumb = regs_is_thumb(&saved);
    const uint8_t *instr     = thumb ? SYSCALL_THUMB_INSTR : SYSCALL_ARM_INSTR;
    size_t         instr_len = thumb ? sizeof(SYSCALL_THUMB_INSTR)
                                     : sizeof(SYSCALL_ARM_INSTR);
    uint8_t orig[sizeof(SYSCALL_ARM_INSTR)];
    ptrace_read_mem(pid, pc, orig, instr_len);
    ptrace_write_mem(pid, pc, instr, instr_len);
#endif

    /* Set up registers for the syscall. */
    memcpy(&modified, &saved, sizeof(saved));
    regs_setup_syscall(&modified, nr, a0, a1, a2, a3, a4, a5);
    restore_regs(pid, &modified);

    /* Run until the breakpoint fires. */
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    int status;
    waitpid(pid, &status, 0);

    /* Read the syscall return value. */
    ptrace_regs_t after;
    save_regs(pid, &after);
    long result = regs_result(&after);

    /* Restore original bytes and registers. */
#if defined(__x86_64__)
    ptrace_write_mem(pid, pc, orig, sizeof(orig));
#elif defined(__arm__)
    ptrace_write_mem(pid, pc, orig, instr_len);
#endif
    restore_regs(pid, &saved);

    return result;
}

/* ------------------------------------------------------------------ */
/* Page allocation and GOT patching                                     */
/* ------------------------------------------------------------------ */

uintptr_t ptrace_alloc_page(pid_t pid)
{
#if defined(__x86_64__)
    long addr = ptrace_inject_syscall(pid, SYS_mmap,
        0,
        4096,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0);
#elif defined(__arm__)
    /* ARM EABI uses mmap2 (nr 192); offset argument is in pages. */
    long addr = ptrace_inject_syscall(pid, 192,
        0,
        4096,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0);
#endif

    if (addr <= 0) {
        fprintf(stderr, "ptrace_alloc_page: mmap failed (%ld)\n", addr);
        return 0;
    }
    return (uintptr_t)addr;
}

uintptr_t ptrace_patch_got(pid_t pid, uintptr_t got_addr, uintptr_t hook_addr)
{
    uintptr_t original = ptrace_read_ptr(pid, got_addr);
    ptrace_write_ptr(pid, got_addr, hook_addr);
    return original;
}
