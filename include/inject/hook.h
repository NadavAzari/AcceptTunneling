#ifndef INJECT_HOOK_H
#define INJECT_HOOK_H

#include <stdint.h>
#include <sys/types.h>

/*
 * Inject the tunneling hook into pid.
 *   got_addr    - runtime address of GOT[accept] (from elf_got_runtime)
 *   remote_ip   - destination IP in network byte order (from inet_addr)
 *   remote_port - destination port in network byte order (from htons)
 * Returns 0 on success.
 */
int inject_accept_hook(pid_t pid, uintptr_t got_addr,
                       uint32_t remote_ip, uint16_t remote_port);

#endif
