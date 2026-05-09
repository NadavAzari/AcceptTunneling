#ifndef INJECT_HOOK_H
#define INJECT_HOOK_H

#include <stdint.h>
#include <sys/types.h>

/*
 * Inject the tunneling hook into pid.
 *   got_addr     - runtime address of GOT[accept] (from elf_got_runtime)
 *   remote_ip    - tunnel destination IP in network byte order
 *   remote_port  - tunnel destination port in network byte order
 *   scope_port   - only intercept connections on this port (network byte order)
 *                  pass 0 to intercept all ports
 *   listen_port  - the port the target is listening on (network byte order)
 *                  used for the kickstart connection that flushes the
 *                  server's currently-blocked accept() call
 * Returns 0 on success.
 */
int inject_accept_hook(pid_t pid, uintptr_t got_addr,
                       uint32_t remote_ip, uint16_t remote_port,
                       uint16_t scope_port, uint16_t listen_port);

#endif
