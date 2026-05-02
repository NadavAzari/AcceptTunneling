#ifndef HOOK_ACCEPT_LOG_H
#define HOOK_ACCEPT_LOG_H

#include <stddef.h>
#include <stdint.h>

/*
 * Magic placeholder values burned into the hook machine code.
 * The injector scans the compiled bytes and replaces these with
 * the real addresses before writing the hook to the target page.
 */
#if defined(__x86_64__) || defined(__aarch64__)
#  define HOOK_REAL_ACCEPT_MAGIC  UINT64_C(0xDEADBEEFCAFEBABE)
#  define HOOK_MSG_ADDR_MAGIC     UINT64_C(0xCAFEBABEDEADBEEF)
#elif defined(__arm__) || defined(__i386__)
#  define HOOK_REAL_ACCEPT_MAGIC  UINT32_C(0xDEADBEEF)
#  define HOOK_MSG_ADDR_MAGIC     UINT32_C(0xCAFEBABE)
#endif

/* Hook entry point and end marker (used to compute code size). */
void hook_accept(void);
void hook_accept_end(void);

static inline size_t hook_accept_size(void)
{
    return (size_t)((uint8_t *)hook_accept_end - (uint8_t *)hook_accept);
}

#endif
