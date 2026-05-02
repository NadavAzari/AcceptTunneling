#include "proc/pid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#define TCP_LISTEN_STATE  0x0A

/* Scans one /proc/net/tcp* file for a LISTEN socket on port.
 * Returns the socket inode on match, 0 if not found. */
static ino_t tcp_scan_file(const char *path, uint16_t port)
{
    FILE *fp = fopen(path, "r");
    if (!fp)
        return 0;

    char line[512];
    fgets(line, sizeof(line), fp);  /* skip header row */

    while (fgets(line, sizeof(line), fp)) {
        unsigned int  local_port, state;
        unsigned long inode;

        int n = sscanf(line,
            " %*d: %*64[0-9A-Fa-f]:%X %*64[0-9A-Fa-f]:%*X %X"
            " %*X:%*X %*X:%*X %*X %*u %*u %lu",
            &local_port, &state, &inode);

        if (n == 3 && state == TCP_LISTEN_STATE && local_port == port) {
            fclose(fp);
            return (ino_t)inode;
        }
    }
    fclose(fp);
    return 0;
}

/* Tries /proc/net/tcp (IPv4) then /proc/net/tcp6 (IPv6).
 * Returns the inode, or 0 if nothing is listening on port. */
static ino_t tcp_inode_for_port(uint16_t port)
{
    ino_t inode;
    if ((inode = tcp_scan_file("/proc/net/tcp",  port))) return inode;
    if ((inode = tcp_scan_file("/proc/net/tcp6", port))) return inode;
    return 0;
}

/* Returns 1 if the fd symlink at fd_path is a socket with the given inode. */
static int fd_matches_inode(const char *fd_path, ino_t target)
{
    struct stat st;
    return stat(fd_path, &st) == 0
        && S_ISSOCK(st.st_mode)
        && st.st_ino == target;
}

/* Scans every open file descriptor of pid for a socket matching target.
 * Returns pid on match, -1 otherwise. */
static pid_t pid_scan_fds(long pid, ino_t target)
{
    char fd_dir[64];
    snprintf(fd_dir, sizeof(fd_dir), "/proc/%ld/fd", pid);

    DIR *fds = opendir(fd_dir);
    if (!fds)
        return -1;

    struct dirent *entry;
    pid_t found = -1;

    while ((entry = readdir(fds)) != NULL && found == -1) {
        char fd_path[128];
        snprintf(fd_path, sizeof(fd_path), "/proc/%ld/fd/%.64s", pid, entry->d_name);
        if (fd_matches_inode(fd_path, target))
            found = (pid_t)pid;
    }
    closedir(fds);
    return found;
}

/* Iterates all /proc/<pid> entries to find which process owns the socket inode. */
static pid_t pid_for_inode(ino_t target)
{
    DIR *proc = opendir("/proc");
    if (!proc)
        return -1;

    struct dirent *entry;
    pid_t found = -1;

    while ((entry = readdir(proc)) != NULL && found == -1) {
        char *end;
        long pid = strtol(entry->d_name, &end, 10);
        if (*end != '\0' || pid <= 0)
            continue;

        pid_t result = pid_scan_fds(pid, target);
        if (result != -1)
            found = result;
    }
    closedir(proc);
    return found;
}

pid_t proc_pid_for_port(uint16_t port)
{
    ino_t inode = tcp_inode_for_port(port);
    if (inode == 0)
        return -1;
    return pid_for_inode(inode);
}
