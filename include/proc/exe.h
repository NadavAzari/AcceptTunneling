#ifndef PROC_EXE_H
#define PROC_EXE_H

#include <sys/types.h>

/* Caller must free the returned string. Returns NULL on failure. */
char *proc_exe_path(pid_t pid);

#endif
