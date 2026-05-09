#include "inject/hook.h"
#include "inject/ptrace.h"
#include "hook/accept_hook.h"
#include "elf/got.h"
#include "elf/sym.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <arpa/inet.h>

/* ------------------------------------------------------------------ */
/* Placeholder patching                                                 */
/* ------------------------------------------------------------------ */

#if defined(__x86_64__) || defined(__aarch64__)

static int patch_u64(uint8_t *buf, size_t len, uint64_t find, uint64_t replace)
{
    for (size_t i = 0; i + 8 <= len; i++) {
        uint64_t val;
        memcpy(&val, buf + i, 8);
        if (val == find) {
            memcpy(buf + i, &replace, 8);
            return 0;
        }
    }
    fprintf(stderr, "patch_u64: magic 0x%lx not found in hook blob\n", find);
    return -1;
}

static int patch_config_ptr(uint8_t *buf, size_t len, uintptr_t addr)
{
    return patch_u64(buf, len, HOOK_CONFIG_MAGIC, (uint64_t)addr);
}

#elif defined(__arm__) || defined(__i386__)

static int patch_u32(uint8_t *buf, size_t len, uint32_t find, uint32_t replace)
{
    for (size_t i = 0; i + 4 <= len; i++) {
        uint32_t val;
        memcpy(&val, buf + i, 4);
        if (val == find) {
            memcpy(buf + i, &replace, 4);
            return 0;
        }
    }
    fprintf(stderr, "patch_u32: magic 0x%x not found in hook blob\n", find);
    return -1;
}

static int patch_config_ptr(uint8_t *buf, size_t len, uintptr_t addr)
{
    return patch_u32(buf, len, (uint32_t)HOOK_CONFIG_MAGIC, (uint32_t)addr);
}

#endif

/* ------------------------------------------------------------------ */
/* Libc symbol resolution                                               */
/* ------------------------------------------------------------------ */

/* Find the first libc mapping in the target's maps.
 * Returns 0 on success, fills path_out (255 chars max) and base_out. */
static int find_libc(pid_t pid, char *path_out, uintptr_t *base_out)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *fp = fopen(maps_path, "r");
    if (!fp) return -1;

    char line[512];
    int  found = 0;
    while (fgets(line, sizeof(line), fp)) {
        uintptr_t start, end, offset;
        char      perms[8], path[256];
        path[0] = '\0';

        int r = sscanf(line,
                       "%"SCNxPTR"-%"SCNxPTR" %7s %"SCNxPTR" %*s %*s %255s",
                       &start, &end, perms, &offset, path);
        if (r < 5 || offset != 0) continue;
        if (!strstr(path, "libc") || !strstr(path, ".so")) continue;

        strncpy(path_out, path, 255);
        path_out[255] = '\0';
        *base_out = start;
        found = 1;
        break;
    }
    fclose(fp);
    return found ? 0 : -1;
}

static uintptr_t resolve_fn(const char *libc_path, uintptr_t libc_base,
                             const char *name)
{
    uint64_t off = elf_sym_offset(libc_path, name);
    if (!off) {
        fprintf(stderr, "[inject] warning: %s not found in %s\n", name, libc_path);
        return 0;
    }
    return libc_base + (uintptr_t)off;
}

/* ------------------------------------------------------------------ */
/* Multi-GOT patching                                                   */
/* ------------------------------------------------------------------ */

static void patch_so_gots(pid_t pid, uintptr_t hook_page)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *fp = fopen(maps_path, "r");
    if (!fp) return;

    char (*seen)[256] = malloc(64 * 256);
    if (!seen) { fclose(fp); return; }
    int  nseen = 0;
    char line[512];

    while (fgets(line, sizeof(line), fp)) {
        uintptr_t start, end, offset;
        char      perms[8], path[256];
        path[0] = '\0';

        int r = sscanf(line,
                       "%"SCNxPTR"-%"SCNxPTR" %7s %"SCNxPTR" %*s %*s %255s",
                       &start, &end, perms, &offset, path);
        if (r < 5 || offset != 0) continue;
        if (!strstr(path, ".so")) continue;

        int already = 0;
        for (int i = 0; i < nseen; i++)
            if (strcmp(seen[i], path) == 0) { already = 1; break; }
        if (already || nseen >= 64) continue;
        strncpy(seen[nseen++], path, 255);

        uint64_t got_va = elf_got_offset(path, "accept");
        if (!got_va) continue;

        uintptr_t runtime_addr = start + (uintptr_t)got_va;
        printf("[inject] patching GOT[accept] in %-40s @ 0x%"PRIxPTR"\n",
               path, runtime_addr);
        ptrace_write_ptr(pid, runtime_addr, hook_page);
    }
    fclose(fp);
    free(seen);
}

/* ------------------------------------------------------------------ */
/* Injection                                                            */
/* ------------------------------------------------------------------ */

int inject_accept_hook(pid_t pid, uintptr_t got_addr,
                       uint32_t remote_ip, uint16_t remote_port,
                       uint16_t scope_port, uint16_t listen_port)
{
    /* resolve libc symbols before attaching */
    char      libc_path[256];
    uintptr_t libc_base;
    if (find_libc(pid, libc_path, &libc_base) < 0) {
        fprintf(stderr, "[inject] libc not found in /proc/%d/maps\n", pid);
        return -1;
    }
    printf("[inject] libc     : %s  base 0x%"PRIxPTR"\n", libc_path, libc_base);

#define RESOLVE(fn) resolve_fn(libc_path, libc_base, fn)
    uintptr_t fn_fork        = RESOLVE("fork");
    uintptr_t fn_socket      = RESOLVE("socket");
    uintptr_t fn_connect     = RESOLVE("connect");
    uintptr_t fn_recvfrom    = RESOLVE("recvfrom");
    uintptr_t fn_sendto      = RESOLVE("sendto");
    uintptr_t fn_poll        = RESOLVE("poll");
    uintptr_t fn_close       = RESOLVE("close");
    uintptr_t fn_exit        = RESOLVE("_exit");
    uintptr_t fn_getsockname = RESOLVE("getsockname");
    uintptr_t fn_setsockopt  = RESOLVE("setsockopt");
#undef RESOLVE

    if (!fn_fork || !fn_socket || !fn_connect || !fn_recvfrom ||
        !fn_sendto || !fn_poll || !fn_close || !fn_exit) {
        fprintf(stderr, "[inject] failed to resolve required libc symbols\n");
        return -1;
    }

    if (ptrace_attach(pid) < 0)
        return -1;

    uintptr_t real_accept = ptrace_read_ptr(pid, got_addr);
    printf("[inject] real accept() @ 0x%"PRIxPTR"\n", real_accept);

    uintptr_t page = ptrace_alloc_page(pid);
    if (!page) {
        fprintf(stderr, "[inject] mmap in target failed\n");
        ptrace_detach(pid);
        return -1;
    }
    printf("[inject] hook page @ 0x%"PRIxPTR"\n", page);

    uintptr_t config_addr = page + HOOK_CONFIG_OFFSET;

    /* copy blob and patch the config-pointer placeholder */
    size_t   code_len = hook_accept_size();
    uint8_t *code     = malloc(code_len);
    if (!code) { ptrace_detach(pid); return -1; }

    memcpy(code, (void *)hook_accept, code_len);

    if (patch_config_ptr(code, code_len, config_addr) < 0) {
        free(code);
        ptrace_detach(pid);
        return -1;
    }

    ptrace_write_mem(pid, page, code, code_len);
    free(code);

    /* write config at page + 0x400 */
    struct hook_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.real_accept    = (uint64_t)real_accept;
    cfg.remote_ip      = remote_ip;
    cfg.remote_port    = remote_port;
    cfg.local_port     = scope_port;
    cfg.magic[0]       = 0xDE;
    cfg.magic[1]       = 0xAD;
    cfg.magic[2]       = 0xBE;
    cfg.magic[3]       = 0xEF;
    cfg.fn_fork        = (uint64_t)fn_fork;
    cfg.fn_socket      = (uint64_t)fn_socket;
    cfg.fn_connect     = (uint64_t)fn_connect;
    cfg.fn_recvfrom    = (uint64_t)fn_recvfrom;
    cfg.fn_sendto      = (uint64_t)fn_sendto;
    cfg.fn_poll        = (uint64_t)fn_poll;
    cfg.fn_close       = (uint64_t)fn_close;
    cfg.fn_exit        = (uint64_t)fn_exit;
    cfg.fn_getsockname = (uint64_t)fn_getsockname;
    cfg.fn_setsockopt  = (uint64_t)fn_setsockopt;

    ptrace_write_mem(pid, config_addr, &cfg, sizeof(cfg));
    printf("[inject] config   @ 0x%"PRIxPTR"  remote %s:%d  scope_port %d\n",
           config_addr, inet_ntoa(*(struct in_addr *)&remote_ip),
           ntohs(remote_port), ntohs(scope_port));

    ptrace_write_ptr(pid, got_addr, page);
    printf("[inject] GOT[accept] patched → 0x%"PRIxPTR"\n", page);

    patch_so_gots(pid, page);

    ptrace_detach(pid);

    /* Kickstart: the server was already blocked in accept() before we patched the
     * GOT, so that call bypasses the hook.  We connect once; the server handles
     * this dummy connection via the old path, then re-enters accept() through
     * the patched GOT.  All subsequent connections hit the hook. */
    if (listen_port) {
        int kfd = socket(AF_INET, SOCK_STREAM, 0);
        if (kfd >= 0) {
            struct sockaddr_in sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family      = AF_INET;
            sa.sin_port        = listen_port;        /* already network byte order */
            sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            connect(kfd, (struct sockaddr *)&sa, sizeof(sa)); /* ignore errors */
            usleep(100000);  /* let the server close and re-enter accept() */
            close(kfd);
        }
        printf("[inject] kickstart sent to port %d\n", ntohs(listen_port));
    }

    return 0;
}
