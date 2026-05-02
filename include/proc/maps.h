#ifndef PROC_MAPS_H
#define PROC_MAPS_H

#include <stdint.h>
#include <sys/types.h>

/* Returns the runtime load base of exe_path in pid's address space.
 * Returns 0 on failure or if the mapping is not found. */
uint64_t proc_load_base(pid_t pid, const char *exe_path);

#endif
