#include "elf/load.h"

#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

ElfMap elf_open(const char *path)
{
    ElfMap m = { NULL, 0 };

    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return m;

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return m; }

    void *p = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED)
        return m;

    m.data = (const uint8_t *)p;
    m.size = (size_t)st.st_size;
    return m;
}

void elf_close(ElfMap m)
{
    if (m.data)
        munmap((void *)m.data, m.size);
}

int elf_valid(const ElfMap *m)
{
    return m->data != NULL
        && m->size  >= SELFMAG
        && memcmp(m->data, ELFMAG, SELFMAG) == 0
        && m->data[EI_CLASS] == ARCH_ELF_CLASS;
}

const arch_shdr_t *elf_section_by_name(const arch_ehdr_t *eh, const char *name)
{
    const uint8_t     *base  = (const uint8_t *)eh;
    const arch_shdr_t *shdrs = (const arch_shdr_t *)(base + eh->e_shoff);
    const char        *shstr = (const char *)(base + shdrs[eh->e_shstrndx].sh_offset);

    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        if (strcmp(shstr + shdrs[i].sh_name, name) == 0)
            return &shdrs[i];
    }
    return NULL;
}
