#ifndef ELF_SYM_H
#define ELF_SYM_H

#include <stdint.h>

/* Returns the st_value (load offset within the ELF) for 'sym' in the ELF at
 * 'path', or 0 if not found.  For a PIC shared library add the runtime load
 * base to get the final address. */
uint64_t elf_sym_offset(const char *path, const char *sym);

#endif
