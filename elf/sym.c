#include "elf/sym.h"
#include "elf/load.h"
#include "arch.h"

#include <string.h>

/* Walk the section-header table for .dynsym / .dynstr and return
 * the matching symbol's st_value, or 0. */
static uint64_t sym_via_sections(const arch_ehdr_t *eh, const char *name)
{
    const arch_shdr_t *dynsym = elf_section_by_name(eh, ".dynsym");
    const arch_shdr_t *dynstr = elf_section_by_name(eh, ".dynstr");
    if (!dynsym || !dynstr)
        return 0;

    const uint8_t    *base  = (const uint8_t *)eh;
    const arch_sym_t *syms  = (const arch_sym_t *)(base + dynsym->sh_offset);
    const char       *strtb = (const char *)(base + dynstr->sh_offset);
    size_t            n     = dynsym->sh_size / sizeof(arch_sym_t);

    for (size_t i = 0; i < n; i++)
        if (syms[i].st_value && strcmp(strtb + syms[i].st_name, name) == 0)
            return (uint64_t)syms[i].st_value;
    return 0;
}

/* Fallback for stripped ELFs: locate .dynsym via PT_DYNAMIC. */
static uint64_t sym_via_dynamic(const arch_ehdr_t *eh, const char *name)
{
    const uint8_t     *base  = (const uint8_t *)eh;
    const arch_phdr_t *phdrs = (const arch_phdr_t *)(base + eh->e_phoff);

    /* find PT_DYNAMIC */
    const arch_dyn_t *dyns = NULL;
    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            dyns = (const arch_dyn_t *)(base + phdrs[i].p_offset);
            break;
        }
    }
    if (!dyns) return 0;

    uint64_t symtab_va = 0, strtab_va = 0;
    for (size_t i = 0; (int)dyns[i].d_tag != DT_NULL; i++) {
        if ((int)dyns[i].d_tag == DT_SYMTAB) symtab_va = (uint64_t)dyns[i].d_un.d_ptr;
        if ((int)dyns[i].d_tag == DT_STRTAB) strtab_va = (uint64_t)dyns[i].d_un.d_ptr;
    }
    if (!symtab_va || !strtab_va) return 0;

    /* va → file offset via PT_LOAD segments */
    size_t symtab_off = 0, strtab_off = 0;
    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        if (phdrs[i].p_type != PT_LOAD) continue;
        uint64_t s = (uint64_t)phdrs[i].p_vaddr;
        uint64_t e = s + (uint64_t)phdrs[i].p_filesz;
        if (!symtab_off && symtab_va >= s && symtab_va < e)
            symtab_off = (size_t)(phdrs[i].p_offset + (symtab_va - s));
        if (!strtab_off && strtab_va >= s && strtab_va < e)
            strtab_off = (size_t)(phdrs[i].p_offset + (strtab_va - s));
    }
    if (!symtab_off || !strtab_off) return 0;

    const arch_sym_t *syms  = (const arch_sym_t *)(base + symtab_off);
    const char       *strtb = (const char *)(base + strtab_off);
    /* estimate count: strtab follows symtab in virtually all real binaries */
    size_t n = (strtab_va > symtab_va)
             ? (size_t)((strtab_va - symtab_va) / sizeof(arch_sym_t))
             : 4096;

    for (size_t i = 0; i < n; i++)
        if (syms[i].st_value && strcmp(strtb + syms[i].st_name, name) == 0)
            return (uint64_t)syms[i].st_value;
    return 0;
}

uint64_t elf_sym_offset(const char *path, const char *sym)
{
    ElfMap m = elf_open(path);
    if (!elf_valid(&m)) { elf_close(m); return 0; }

    const arch_ehdr_t *eh = (const arch_ehdr_t *)m.data;
    uint64_t result = sym_via_sections(eh, sym);
    if (!result)
        result = sym_via_dynamic(eh, sym);

    elf_close(m);
    return result;
}
