#include "hook/accept_log.h"

/*
 * Position-independent hook for accept().
 *
 * Compiled as a naked function so we control every byte.
 * Two magic immediates act as placeholders — the injector patches them
 * before writing the code into the target process.
 *
 * Page layout after injection:
 *   page + 0x000  hook code   (GOT entry points here)
 *   page + 0x800  "hey\n"     (MSG_ADDR_MAGIC is replaced with this address)
 *
 * real_accept is called first so the return value (fd) is preserved.
 * The write(2, ...) uses a raw syscall — no libc dependency.
 */

/* ------------------------------------------------------------------ */
/* x86-64                                                              */
/* ------------------------------------------------------------------ */
#if defined(__x86_64__)

__attribute__((naked, section(".text.hook")))
void hook_accept(void)
{
    __asm__ volatile(
        /* --- save callee-saved registers we'll use --- */
        "push %%rbp\n\t"
        "push %%rbx\n\t"
        "push %%r12\n\t"
        "push %%r13\n\t"
        "push %%r14\n\t"

        /* --- save accept() arguments --- */
        "mov %%rdi, %%rbx\n\t"      /* sockfd */
        "mov %%rsi, %%r12\n\t"      /* addr   */
        "mov %%rdx, %%r13\n\t"      /* addrlen */

        /* --- call real accept() via patched immediate --- */
        "movabs $0xDEADBEEFCAFEBABE, %%rax\n\t"
        "mov %%rbx, %%rdi\n\t"
        "mov %%r12, %%rsi\n\t"
        "mov %%r13, %%rdx\n\t"
        "call *%%rax\n\t"
        "mov %%rax, %%r14\n\t"      /* save fd */

        /* --- write(2, msg, 4) via raw syscall --- */
        "movabs $0xCAFEBABEDEADBEEF, %%rsi\n\t"
        "mov $1,  %%rax\n\t"        /* SYS_write */
        "mov $2,  %%rdi\n\t"        /* stderr    */
        "mov $4,  %%rdx\n\t"        /* length    */
        "syscall\n\t"

        /* --- return the fd from real accept() --- */
        "mov %%r14, %%rax\n\t"
        "pop %%r14\n\t"
        "pop %%r13\n\t"
        "pop %%r12\n\t"
        "pop %%rbx\n\t"
        "pop %%rbp\n\t"
        "ret\n\t"

        ".globl hook_accept_end\n\t"
        "hook_accept_end:\n\t"
        :::
    );
}

/* ------------------------------------------------------------------ */
/* ARM 32-bit (ARMv7 / NVR302-32S)                                     */
/* ------------------------------------------------------------------ */
#elif defined(__arm__)

__attribute__((naked, section(".text.hook")))
void hook_accept(void)
{
    __asm__ volatile(
        /* save all callee-saved regs + lr so we can use r4-r11 freely */
        "push {r4-r11, lr}\n\t"

        "mov r4, r0\n\t"            /* sockfd  */
        "mov r5, r1\n\t"            /* addr    */
        "mov r6, r2\n\t"            /* addrlen */

        /* call real accept via literal pool placeholder */
        "ldr r3, 1f\n\t"
        "mov r0, r4\n\t"
        "mov r1, r5\n\t"
        "mov r2, r6\n\t"
        "blx r3\n\t"
        "mov r9, r0\n\t"            /* save fd */

        /* write(2, msg, 4) — syscall nr 4 on ARM EABI */
        "ldr r1, 2f\n\t"            /* msg address   */
        "mov r0, #2\n\t"            /* stderr        */
        "mov r2, #4\n\t"            /* length        */
        "mov r7, #4\n\t"            /* __NR_write    */
        "svc #0\n\t"

        "mov r0, r9\n\t"            /* return fd */
        "pop {r4-r11, pc}\n\t"

        ".balign 4\n\t"
        "1: .word 0xDEADBEEF\n\t"   /* HOOK_REAL_ACCEPT_MAGIC */
        "2: .word 0xCAFEBABE\n\t"   /* HOOK_MSG_ADDR_MAGIC    */

        ".globl hook_accept_end\n\t"
        "hook_accept_end:\n\t"
        :::
    );
}

#else
#  error "hook/accept_log: unsupported architecture"
#endif
