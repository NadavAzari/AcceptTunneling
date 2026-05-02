#ifndef ELF_LOAD_H
#define ELF_LOAD_H

#include <stddef.h>
#include <stdint.h>
#include "arch.h"

typedef struct {
    const uint8_t *data;
    size_t         size;
} ElfMap;

ElfMap             elf_open(const char *path);
void               elf_close(ElfMap m);

/* Returns 1 if the map holds a valid ELF for this architecture. */
int                elf_valid(const ElfMap *m);

/* Returns a pointer to the section header whose name matches, or NULL. */
const arch_shdr_t *elf_section_by_name(const arch_ehdr_t *eh, const char *name);

#endif
