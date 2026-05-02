#include "proc/exe.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>

char *proc_exe_path(pid_t pid)
{
    char link[64];
    snprintf(link, sizeof(link), "/proc/%d/exe", pid);

    char *buf = malloc(PATH_MAX);
    if (!buf)
        return NULL;

    ssize_t n = readlink(link, buf, PATH_MAX - 1);
    if (n == -1) {
        free(buf);
        return NULL;
    }
    buf[n] = '\0';
    return buf;
}
