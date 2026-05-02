#include "elf/got.h"
#include "elf/load.h"
#include "proc/exe.h"
#include "proc/maps.h"
#include "arch.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Searches a RELA section for a GOT-slot relocation whose symbol name
 * matches sym.  Returns the r_offset (GOT entry address) or 0. */
static uint64_t scan_rela(const arch_rela_t *relas, size_t count,
                           const arch_sym_t  *syms,  size_t nsyms,
                           const char        *strtb,
                           const char        *sym)
{
    for (size_t i = 0; i < count; i++) {
        uint32_t sidx = ARCH_R_SYM(relas[i].r_info);
        uint32_t type = ARCH_R_TYPE(relas[i].r_info);
        if (!IS_GOT_RELOC(type) || sidx >= nsyms)
            continue;
        if (strcmp(strtb + syms[sidx].st_name, sym) == 0)
            return (uint64_t)relas[i].r_offset;
    }
    return 0;
}

/* Same as scan_rela but for REL sections (no explicit addend field).
 * ARM and i386 toolchains emit SHT_REL; AArch64 and x86-64 use SHT_RELA.
 * Both are scanned so the code works on all arches and mixed toolchains. */
static uint64_t scan_rel(const arch_rel_t *rels,  size_t count,
                          const arch_sym_t *syms,  size_t nsyms,
                          const char       *strtb,
                          const char       *sym)
{
    for (size_t i = 0; i < count; i++) {
        uint32_t sidx = ARCH_R_SYM(rels[i].r_info);
        uint32_t type = ARCH_R_TYPE(rels[i].r_info);
        if (!IS_GOT_RELOC(type) || sidx >= nsyms)
            continue;
        if (strcmp(strtb + syms[sidx].st_name, sym) == 0)
            return (uint64_t)rels[i].r_offset;
    }
    return 0;
}

/* Dispatches one section header to the right scanner based on its type. */
static uint64_t search_section(const arch_ehdr_t *eh,
                                const arch_shdr_t *sh,
                                const arch_sym_t  *syms, size_t nsyms,
                                const char        *strtb,
                                const char        *sym)
{
    const uint8_t *base = (const uint8_t *)eh;

    if (sh->sh_type == SHT_RELA) {
        const arch_rela_t *relas = (const arch_rela_t *)(base + sh->sh_offset);
        return scan_rela(relas, sh->sh_size / sizeof(arch_rela_t),
                         syms, nsyms, strtb, sym);
    }
    if (sh->sh_type == SHT_REL) {
        const arch_rel_t *rels = (const arch_rel_t *)(base + sh->sh_offset);
        return scan_rel(rels, sh->sh_size / sizeof(arch_rel_t),
                        syms, nsyms, strtb, sym);
    }
    return 0;
}

/* Walks all relocation sections in the ELF to find the GOT entry for sym. */
static uint64_t got_offset_in_elf(const arch_ehdr_t *eh, const char *sym)
{
    const arch_shdr_t *dynsym_sh = elf_section_by_name(eh, ".dynsym");
    const arch_shdr_t *dynstr_sh = elf_section_by_name(eh, ".dynstr");
    if (!dynsym_sh || !dynstr_sh)
        return 0;

    const uint8_t    *base  = (const uint8_t *)eh;
    const arch_sym_t *syms  = (const arch_sym_t *)(base + dynsym_sh->sh_offset);
    const char       *strtb = (const char *)(base + dynstr_sh->sh_offset);
    size_t            nsyms = dynsym_sh->sh_size / sizeof(arch_sym_t);

    const arch_shdr_t *shdrs = (const arch_shdr_t *)(base + eh->e_shoff);

    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        uint64_t hit = search_section(eh, &shdrs[i], syms, nsyms, strtb, sym);
        if (hit)
            return hit;
    }
    return 0;
}

static int elf_is_pie(const arch_ehdr_t *eh)
{
    return eh->e_type == ET_DYN;
}

uint64_t elf_got_offset(const char *elf_path, const char *symbol)
{
    ElfMap m = elf_open(elf_path);
    if (!elf_valid(&m)) { elf_close(m); return 0; }

    uint64_t offset = got_offset_in_elf((const arch_ehdr_t *)m.data, symbol);
    elf_close(m);
    return offset;
}

uint64_t elf_got_runtime(pid_t pid, const char *symbol)
{
    char *exe = proc_exe_path(pid);
    if (!exe)
        return 0;

    ElfMap m = elf_open(exe);
    if (!elf_valid(&m)) { elf_close(m); free(exe); return 0; }

    const arch_ehdr_t *eh     = (const arch_ehdr_t *)m.data;
    uint64_t           offset = got_offset_in_elf(eh, symbol);
    int                pie    = elf_is_pie(eh);
    elf_close(m);

    if (offset && pie) {
        uint64_t base = proc_load_base(pid, exe);
        if (base)
            offset += base;
    }
    free(exe);
    return offset;
}
