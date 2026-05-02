#include "inject/hook.h"
#include "inject/ptrace.h"
#include "hook/accept_hook.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
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
/* Injection                                                            */
/* ------------------------------------------------------------------ */

/*
 * Page layout written into the target process:
 *   page + 0x000  hook code  (GOT[accept] points here)
 *   page + 0x400  struct hook_config  (config pointer patched to here)
 */
int inject_accept_hook(pid_t pid, uintptr_t got_addr,
                       uint32_t remote_ip, uint16_t remote_port)
{
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

    /* copy hook code and patch the single config-pointer placeholder */
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

    /* write config struct at page + 0x400 */
    struct hook_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.real_accept  = (uint64_t)real_accept;
    cfg.remote_ip    = remote_ip;
    cfg.remote_port  = remote_port;
    cfg.magic[0]     = 0xDE;
    cfg.magic[1]     = 0xAD;
    cfg.magic[2]     = 0xBE;
    cfg.magic[3]     = 0xEF;

    ptrace_write_mem(pid, config_addr, &cfg, sizeof(cfg));
    printf("[inject] config @ 0x%"PRIxPTR"  remote %s:%d\n",
           config_addr, inet_ntoa(*(struct in_addr *)&remote_ip),
           ntohs(remote_port));

    /* redirect GOT[accept] to our hook */
    ptrace_write_ptr(pid, got_addr, page);
    printf("[inject] GOT[accept] patched → 0x%"PRIxPTR"\n", page);

    ptrace_detach(pid);
    return 0;
}
