#ifndef ELF_GOT_H
#define ELF_GOT_H

#include <stdint.h>
#include <sys/types.h>

/* Static offset of symbol's GOT entry as stored on disk.
 * For PIE binaries this is relative to the load base, not an absolute address. */
uint64_t elf_got_offset(const char *elf_path, const char *symbol);

/* Runtime address of symbol's GOT entry inside the running process pid.
 * Reads /proc/pid/maps to add the ASLR slide for PIE binaries. */
uint64_t elf_got_runtime(pid_t pid, const char *symbol);

#endif
