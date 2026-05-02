#include "inject/ptrace.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/syscall.h>

/* ------------------------------------------------------------------ */
/* Thread-group tracking                                                */
/* ------------------------------------------------------------------ */

/*
 * When attaching to a multithreaded target, PTRACE_ATTACH only stops the
 * one thread you name.  The rest keep running and can interfere with the
 * injected svc+bkpt, or produce ptrace events that a bare waitpid() catches
 * instead of our SIGTRAP, leaving the injected thread still RUNNING when we
 * call PTRACE_GETREGS — which returns ESRCH and leaves `after` uninitialised.
 *
 * Fix: stop every thread in the group up-front, then detach from all.
 */

#define MAX_TIDS 256
static pid_t s_tids[MAX_TIDS];
static int   s_ntids;

static void attach_all_threads(pid_t pid)
{
    char task_dir[64];
    snprintf(task_dir, sizeof(task_dir), "/proc/%d/task", pid);

    DIR *d = opendir(task_dir);
    if (!d)
        return;   /* can't enumerate — single-threaded or no /proc */

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && s_ntids < MAX_TIDS) {
        char *end;
        long v = strtol(ent->d_name, &end, 10);
        if (*end != '\0' || v <= 0)
            continue;
        pid_t tid = (pid_t)v;
        if (tid == pid)
            continue;   /* already attached */

        if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) == 0) {
            int st;
            waitpid(tid, &st, __WALL);
            s_tids[s_ntids++] = tid;
        }
    }
    closedir(d);
}

/* ------------------------------------------------------------------ */
/* Attach / detach                                                      */
/* ------------------------------------------------------------------ */

int ptrace_attach(pid_t pid)
{
    s_ntids = 0;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("ptrace_attach: PTRACE_ATTACH");
        return -1;
    }

    int status;
    if (waitpid(pid, &status, __WALL) < 0) {
        perror("ptrace_attach: waitpid");
        return -1;
    }
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "ptrace_attach: process did not stop\n");
        return -1;
    }

    s_tids[s_ntids++] = pid;
    attach_all_threads(pid);
    return 0;
}

void ptrace_detach(pid_t pid)
{
    (void)pid;
    for (int i = 0; i < s_ntids; i++)
        ptrace(PTRACE_DETACH, s_tids[i], NULL, NULL);
    s_ntids = 0;
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

static uintptr_t regs_pc(const ptrace_regs_t *r)     { return r->rip; }
static long      regs_result(const ptrace_regs_t *r)  { return (long)r->rax; }

#elif defined(__arm__)

static const uint8_t SYSCALL_ARM_INSTR[]   = { 0x00, 0x00, 0x00, 0xef,   /* svc #0        */
                                                0xf0, 0x01, 0xf0, 0xe7 }; /* udf #0xe7f001f0 → SIGTRAP via arm_break_hook */
static const uint8_t SYSCALL_THUMB_INSTR[] = { 0x00, 0xdf,               /* svc #0        */
                                                0x01, 0xde };             /* udf #1 = 0xde01 → SIGTRAP via thumb_break_hook */

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
    /* If the thread was stopped mid-syscall (e.g. inside accept()), the kernel
     * stores the original r0 in ORIG_R0 and restores it on restart, clobbering
     * whatever we put in R0.  Writing ORIG_R0 = our a0 prevents that. */
    r->ARM_ORIG_R0 = (unsigned long)a0;
}

static uintptr_t regs_pc(const ptrace_regs_t *r)     { return r->ARM_PC; }
static long      regs_result(const ptrace_regs_t *r)  { return (long)r->ARM_R0; }
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

    /* Determine instruction sequence and save original bytes at PC. */
#if defined(__x86_64__)
    const uint8_t *instr    = SYSCALL_INSTR;
    size_t         instr_len = sizeof(SYSCALL_INSTR);
#elif defined(__arm__)
    int            thumb     = regs_is_thumb(&saved);
    const uint8_t *instr     = thumb ? SYSCALL_THUMB_INSTR : SYSCALL_ARM_INSTR;
    size_t         instr_len = thumb ? sizeof(SYSCALL_THUMB_INSTR)
                                     : sizeof(SYSCALL_ARM_INSTR);

    /*
     * When the tracee is blocked inside a syscall, PTRACE_GETREGS returns
     * the PC *after* the svc instruction (the return address). The kernel
     * restarts the syscall from PC-2 (Thumb) or PC-4 (ARM). We must write
     * our stub at the svc site, not at the return address, or the stub
     * will never execute.
     *
     * Detect via /proc/pid/syscall: if the first field is not -1 the
     * tracee was interrupted in a syscall and PC needs adjusting.
     */
    {
        char path[64]; FILE *f; long active_nr = -1;
        snprintf(path, sizeof(path), "/proc/%d/syscall", (int)pid);
        if ((f = fopen(path, "r")) != NULL) { fscanf(f, "%ld", &active_nr); fclose(f); }
        if (active_nr != -1)
            pc -= thumb ? 2 : 4;   /* back up to the svc instruction */
    }
#endif
    uint8_t orig[8];   /* large enough for any arch's sequence */
    ptrace_read_mem(pid, pc, orig, instr_len);
    ptrace_write_mem(pid, pc, instr, instr_len);
#if defined(__arm__)
    {
        uint8_t verify[4] = {0};
        ptrace_read_mem(pid, pc, verify, instr_len);
        fprintf(stderr, "[dbg] wrote at 0x%lx: %02x%02x%02x%02x  want: %02x%02x%02x%02x\n",
                (unsigned long)pc,
                verify[0], verify[1], verify[2], verify[3],
                instr[0], instr[1],
                instr_len > 2 ? instr[2] : 0,
                instr_len > 3 ? instr[3] : 0);
    }
#endif

    /* Set up registers for the syscall. */
    memcpy(&modified, &saved, sizeof(saved));
    regs_setup_syscall(&modified, nr, a0, a1, a2, a3, a4, a5);
#if defined(__arm__)
    /* Point PC at our injected stub (needed when pc was adjusted above). */
    modified.ARM_PC = (unsigned long)pc;
#endif
    restore_regs(pid, &modified);

    /*
     * Resume and wait for SIGTRAP from our breakpoint.
     *
     * Without a signal-forwarding loop, any non-SIGTRAP stop (SIGCHLD,
     * SIGSTOP from another thread, etc.) is silently swallowed and we
     * proceed as if the bkpt fired — but the thread is still RUNNING,
     * so the subsequent PTRACE_GETREGS returns ESRCH and `after` stays
     * uninitialised, producing a garbage mmap address.
     */
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    int status;
    for (;;) {
        if (waitpid(pid, &status, __WALL) < 0) {
            perror("ptrace_inject_syscall: waitpid");
            ptrace_write_mem(pid, pc, orig, instr_len);
            restore_regs(pid, &saved);
            return -1;
        }
        fprintf(stderr, "[dbg] waitpid status=0x%x WIFSTOPPED=%d WSTOPSIG=%d WIFEXITED=%d WIFSIGNALED=%d\n",
                status, WIFSTOPPED(status),
                WIFSTOPPED(status) ? WSTOPSIG(status) : -1,
                WIFEXITED(status), WIFSIGNALED(status));
        if (!WIFSTOPPED(status)) {
            fprintf(stderr, "ptrace_inject_syscall: tracee terminated (status 0x%x)\n",
                    status);
            return -1;
        }
        int sig = WSTOPSIG(status);
        if (sig == SIGTRAP)
            break;
        /* Forward the signal and keep waiting for our breakpoint. */
        ptrace(PTRACE_CONT, pid, NULL, (void *)(uintptr_t)sig);
    }

    /* Read the syscall return value. */
    ptrace_regs_t after;
    if (save_regs(pid, &after) < 0) {
        ptrace_write_mem(pid, pc, orig, instr_len);
        restore_regs(pid, &saved);
        return -1;
    }
    long result = regs_result(&after);
#if defined(__arm__)
    fprintf(stderr, "[dbg] after SIGTRAP: PC=0x%lx R0=0x%lx result=%ld\n",
            (unsigned long)after.ARM_PC, (unsigned long)after.ARM_R0, result);
#endif

    /* Restore original bytes and registers. */
    ptrace_write_mem(pid, pc, orig, instr_len);
    restore_regs(pid, &saved);

    return result;
}

/* ------------------------------------------------------------------ */
/* Page allocation and GOT patching                                     */
/* ------------------------------------------------------------------ */

/* Verify injection works by running getpid() and checking the result. */
static int injection_selftest(pid_t pid)
{
#if defined(__x86_64__)
    long nr_getpid = 39;
#elif defined(__arm__)
    long nr_getpid = 20;
#endif
    long got = ptrace_inject_syscall(pid, nr_getpid, 0, 0, 0, 0, 0, 0);
    if (got != (long)pid) {
        fprintf(stderr,
                "ptrace_alloc_page: injection self-test failed — "
                "getpid() returned %ld, expected %d\n"
                "  (svc likely not executing; thread may need to be in a non-syscall state)\n",
                got, pid);
        return -1;
    }
    return 0;
}

#if defined(__arm__)
/* Fallback when mmap2 is blocked: extend the heap with brk() then make the
 * new page executable with mprotect().
 *   ARM EABI: brk=45, mprotect=125 */
static uintptr_t alloc_via_brk(pid_t pid)
{
    long brk0 = ptrace_inject_syscall(pid, 45, 0, 0, 0, 0, 0, 0);
    if (brk0 <= 0 || (brk0 & 0xfff)) {
        fprintf(stderr, "ptrace_alloc_page: brk(0) returned 0x%lx\n", brk0);
        return 0;
    }
    long brk1 = ptrace_inject_syscall(pid, 45, brk0 + 4096, 0, 0, 0, 0, 0);
    if (brk1 != brk0 + 4096) {
        fprintf(stderr, "ptrace_alloc_page: brk extend failed (got 0x%lx)\n", brk1);
        return 0;
    }
    long mret = ptrace_inject_syscall(pid, 125,
        brk0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, 0, 0, 0);
    if (mret != 0) {
        fprintf(stderr, "ptrace_alloc_page: mprotect failed (%ld)\n", mret);
        return 0;
    }
    return (uintptr_t)brk0;
}
#endif

uintptr_t ptrace_alloc_page(pid_t pid)
{
    /* Prove the svc injection mechanism works before attempting mmap. */
    if (injection_selftest(pid) < 0)
        return 0;

#if defined(__x86_64__)
    long addr = ptrace_inject_syscall(pid, SYS_mmap,
        0,
        4096,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0);
#elif defined(__arm__)
    /* ARM EABI: mmap2 = 192, offset in pages. */
    long addr = ptrace_inject_syscall(pid, 192,
        0,
        4096,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0);
#endif

    /* mmap always returns a page-aligned address on success.
     * A non-aligned or implausibly small positive result is garbage from an
     * uninitialised ptrace_regs_t — writing it to the GOT crashes the target. */
    if (addr > 0 && !((uintptr_t)addr & 0xfff))
        return (uintptr_t)addr;

    fprintf(stderr,
            "ptrace_alloc_page: mmap2 failed (result 0x%lx), trying brk fallback\n",
            addr);

#if defined(__arm__)
    return alloc_via_brk(pid);
#else
    return 0;
#endif
}

uintptr_t ptrace_patch_got(pid_t pid, uintptr_t got_addr, uintptr_t hook_addr)
{
    uintptr_t original = ptrace_read_ptr(pid, got_addr);
    ptrace_write_ptr(pid, got_addr, hook_addr);
    return original;
}
