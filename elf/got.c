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

/* Convert an ELF virtual address to a file offset using PT_LOAD segments.
 * Returns 0 if va falls outside all mapped segments. */
static size_t va_to_file_offset(const arch_ehdr_t *eh, uint64_t va)
{
    const uint8_t     *base  = (const uint8_t *)eh;
    const arch_phdr_t *phdrs = (const arch_phdr_t *)(base + eh->e_phoff);
    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        if (phdrs[i].p_type != PT_LOAD) continue;
        uint64_t seg_start = (uint64_t)phdrs[i].p_vaddr;
        uint64_t seg_end   = seg_start + (uint64_t)phdrs[i].p_filesz;
        if (va >= seg_start && va < seg_end)
            return (size_t)(phdrs[i].p_offset + (va - seg_start));
    }
    return 0;
}

/* Fallback ELF scanner that works on stripped binaries (no section header
 * table).  Locates .dynsym/.dynstr/.rel.plt via the PT_DYNAMIC segment,
 * which the dynamic linker — and therefore the kernel — always preserves. */
static uint64_t got_offset_from_dynamic(const arch_ehdr_t *eh, const char *sym)
{
    const uint8_t     *base  = (const uint8_t *)eh;
    const arch_phdr_t *phdrs = (const arch_phdr_t *)(base + eh->e_phoff);

    const arch_dyn_t *dyns = NULL;
    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            dyns = (const arch_dyn_t *)(base + phdrs[i].p_offset);
            break;
        }
    }
    if (!dyns) return 0;

    uint64_t symtab_va = 0, strtab_va  = 0;
    uint64_t jmprel_va = 0, pltrelsz   = 0, pltrel_type = 0;
    uint64_t rel_va    = 0, relsz      = 0;
    uint64_t rela_va   = 0, relasz     = 0;

    for (size_t i = 0; (int)dyns[i].d_tag != DT_NULL; i++) {
        switch ((int)dyns[i].d_tag) {
        case DT_SYMTAB:   symtab_va   = (uint64_t)dyns[i].d_un.d_ptr; break;
        case DT_STRTAB:   strtab_va   = (uint64_t)dyns[i].d_un.d_ptr; break;
        case DT_JMPREL:   jmprel_va   = (uint64_t)dyns[i].d_un.d_ptr; break;
        case DT_PLTRELSZ: pltrelsz    = (uint64_t)dyns[i].d_un.d_val; break;
        case DT_PLTREL:   pltrel_type = (uint64_t)dyns[i].d_un.d_val; break;
        case DT_REL:      rel_va      = (uint64_t)dyns[i].d_un.d_ptr; break;
        case DT_RELSZ:    relsz       = (uint64_t)dyns[i].d_un.d_val; break;
        case DT_RELA:     rela_va     = (uint64_t)dyns[i].d_un.d_ptr; break;
        case DT_RELASZ:   relasz      = (uint64_t)dyns[i].d_un.d_val; break;
        }
    }

    if (!symtab_va || !strtab_va) return 0;

    size_t symtab_off = va_to_file_offset(eh, symtab_va);
    size_t strtab_off = va_to_file_offset(eh, strtab_va);
    if (!symtab_off || !strtab_off) return 0;

    const arch_sym_t *syms  = (const arch_sym_t *)(base + symtab_off);
    const char       *strtb = (const char *)(base + strtab_off);
    /* nsyms estimated from layout; strtab always follows symtab in practice */
    size_t nsyms = (strtab_va > symtab_va)
                 ? (size_t)((strtab_va - symtab_va) / sizeof(arch_sym_t))
                 : 4096;

    /* PLT relocations — where accept's GOT slot lives */
    if (jmprel_va && pltrelsz) {
        size_t off = va_to_file_offset(eh, jmprel_va);
        if (off) {
            uint64_t hit = (pltrel_type == (uint64_t)DT_RELA)
                ? scan_rela((const arch_rela_t *)(base + off),
                            pltrelsz / sizeof(arch_rela_t), syms, nsyms, strtb, sym)
                : scan_rel ((const arch_rel_t  *)(base + off),
                            pltrelsz / sizeof(arch_rel_t),  syms, nsyms, strtb, sym);
            if (hit) return hit;
        }
    }
    /* DT_REL/DT_RELA for GLOB_DAT entries (less common for accept, but complete) */
    if (rel_va && relsz) {
        size_t off = va_to_file_offset(eh, rel_va);
        if (off) {
            uint64_t hit = scan_rel((const arch_rel_t *)(base + off),
                                    relsz / sizeof(arch_rel_t), syms, nsyms, strtb, sym);
            if (hit) return hit;
        }
    }
    if (rela_va && relasz) {
        size_t off = va_to_file_offset(eh, rela_va);
        if (off) {
            uint64_t hit = scan_rela((const arch_rela_t *)(base + off),
                                     relasz / sizeof(arch_rela_t), syms, nsyms, strtb, sym);
            if (hit) return hit;
        }
    }
    return 0;
}

/* Walks all relocation sections in the ELF to find the GOT entry for sym.
 * Tries the section-header table first (fast, non-stripped binaries), then
 * falls back to PT_DYNAMIC (always present, survives strip). */
static uint64_t got_offset_in_elf(const arch_ehdr_t *eh, const char *sym)
{
    /* Fast path: section headers intact */
    const arch_shdr_t *dynsym_sh = elf_section_by_name(eh, ".dynsym");
    const arch_shdr_t *dynstr_sh = elf_section_by_name(eh, ".dynstr");
    if (dynsym_sh && dynstr_sh) {
        const uint8_t    *base  = (const uint8_t *)eh;
        const arch_sym_t *syms  = (const arch_sym_t *)(base + dynsym_sh->sh_offset);
        const char       *strtb = (const char *)(base + dynstr_sh->sh_offset);
        size_t            nsyms = dynsym_sh->sh_size / sizeof(arch_sym_t);
        const arch_shdr_t *shdrs = (const arch_shdr_t *)(base + eh->e_shoff);
        for (uint16_t i = 0; i < eh->e_shnum; i++) {
            uint64_t hit = search_section(eh, &shdrs[i], syms, nsyms, strtb, sym);
            if (hit) return hit;
        }
    }
    /* Fallback: PT_DYNAMIC — works on stripped firmware */
    return got_offset_from_dynamic(eh, sym);
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
