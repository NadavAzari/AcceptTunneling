#ifndef ARCH_H
#define ARCH_H

#include <elf.h>
#include <stdint.h>

/*
 * Per-architecture ELF type aliases and GOT relocation filters.
 *
 * Add a new #elif block here when porting to a new target.
 * The three required macros per arch:
 *   ARCH_ELF_CLASS  - ELFCLASS32 or ELFCLASS64
 *   ARCH_R_SYM(i)   - extract symbol index from r_info
 *   ARCH_R_TYPE(i)  - extract relocation type from r_info
 *   IS_GOT_RELOC(t) - true if reloc type writes a GOT slot
 */

/* ------------------------------------------------------------------ */
/* x86-64                                                              */
/* ------------------------------------------------------------------ */
#if defined(__x86_64__)

typedef Elf64_Ehdr  arch_ehdr_t;
typedef Elf64_Shdr  arch_shdr_t;
typedef Elf64_Sym   arch_sym_t;
typedef Elf64_Rela  arch_rela_t;
typedef Elf64_Rel   arch_rel_t;
#define ARCH_ELF_CLASS      ELFCLASS64
#define ARCH_R_SYM(i)       ELF64_R_SYM(i)
#define ARCH_R_TYPE(i)      ELF64_R_TYPE(i)
#define IS_GOT_RELOC(t)     ((t) == R_X86_64_JUMP_SLOT || (t) == R_X86_64_GLOB_DAT)
#define ARCH_NAME           "x86_64"

/* ------------------------------------------------------------------ */
/* AArch64 (ARM 64-bit)                                                */
/* ------------------------------------------------------------------ */
#elif defined(__aarch64__)

typedef Elf64_Ehdr  arch_ehdr_t;
typedef Elf64_Shdr  arch_shdr_t;
typedef Elf64_Sym   arch_sym_t;
typedef Elf64_Rela  arch_rela_t;
typedef Elf64_Rel   arch_rel_t;
#define ARCH_ELF_CLASS      ELFCLASS64
#define ARCH_R_SYM(i)       ELF64_R_SYM(i)
#define ARCH_R_TYPE(i)      ELF64_R_TYPE(i)
#define IS_GOT_RELOC(t)     ((t) == R_AARCH64_JUMP_SLOT || (t) == R_AARCH64_GLOB_DAT)
#define ARCH_NAME           "aarch64"

/* ------------------------------------------------------------------ */
/* ARMv7 / ARMv5 (32-bit) — primary embedded target                   */
/* Kernel 3.18.x (NVR302-32S), may use uclibc / musl.                 */
/* ARM toolchains emit SHT_REL (.rel.plt) but some newer ones use     */
/* SHT_RELA; scan both in elf_got.c.                                  */
/* ------------------------------------------------------------------ */
#elif defined(__arm__)

typedef Elf32_Ehdr  arch_ehdr_t;
typedef Elf32_Shdr  arch_shdr_t;
typedef Elf32_Sym   arch_sym_t;
typedef Elf32_Rela  arch_rela_t;
typedef Elf32_Rel   arch_rel_t;
#define ARCH_ELF_CLASS      ELFCLASS32
#define ARCH_R_SYM(i)       ELF32_R_SYM(i)
#define ARCH_R_TYPE(i)      ELF32_R_TYPE(i)
#define IS_GOT_RELOC(t)     ((t) == R_ARM_JUMP_SLOT || (t) == R_ARM_GLOB_DAT)
#define ARCH_NAME           "arm"

/* ------------------------------------------------------------------ */
/* i386 / x86 32-bit                                                   */
/* ------------------------------------------------------------------ */
#elif defined(__i386__)

typedef Elf32_Ehdr  arch_ehdr_t;
typedef Elf32_Shdr  arch_shdr_t;
typedef Elf32_Sym   arch_sym_t;
typedef Elf32_Rela  arch_rela_t;
typedef Elf32_Rel   arch_rel_t;
#define ARCH_ELF_CLASS      ELFCLASS32
#define ARCH_R_SYM(i)       ELF32_R_SYM(i)
#define ARCH_R_TYPE(i)      ELF32_R_TYPE(i)
#define IS_GOT_RELOC(t)     ((t) == R_386_JUMP_SLOT || (t) == R_386_GLOB_DAT)
#define ARCH_NAME           "i386"

/* ------------------------------------------------------------------ */
/* MIPS 32-bit (big or little endian)                                  */
/* ------------------------------------------------------------------ */
#elif defined(__mips__) && !defined(__mips64)

typedef Elf32_Ehdr  arch_ehdr_t;
typedef Elf32_Shdr  arch_shdr_t;
typedef Elf32_Sym   arch_sym_t;
typedef Elf32_Rela  arch_rela_t;
typedef Elf32_Rel   arch_rel_t;
#define ARCH_ELF_CLASS      ELFCLASS32
#define ARCH_R_SYM(i)       ELF32_R_SYM(i)
#define ARCH_R_TYPE(i)      ELF32_R_TYPE(i)
#define IS_GOT_RELOC(t)     ((t) == R_MIPS_JUMP_SLOT || (t) == R_MIPS_GLOB_DAT)
#define ARCH_NAME           "mips"

/* ------------------------------------------------------------------ */
/* MIPS 64-bit                                                         */
/* ------------------------------------------------------------------ */
#elif defined(__mips64)

typedef Elf64_Ehdr  arch_ehdr_t;
typedef Elf64_Shdr  arch_shdr_t;
typedef Elf64_Sym   arch_sym_t;
typedef Elf64_Rela  arch_rela_t;
typedef Elf64_Rel   arch_rel_t;
#define ARCH_ELF_CLASS      ELFCLASS64
#define ARCH_R_SYM(i)       ELF64_R_SYM(i)
#define ARCH_R_TYPE(i)      ELF64_R_TYPE(i)
#define IS_GOT_RELOC(t)     ((t) == R_MIPS_JUMP_SLOT || (t) == R_MIPS_GLOB_DAT)
#define ARCH_NAME           "mips64"

/* ------------------------------------------------------------------ */
/* PowerPC 32-bit                                                      */
/* ------------------------------------------------------------------ */
#elif defined(__powerpc__) && !defined(__powerpc64__)

typedef Elf32_Ehdr  arch_ehdr_t;
typedef Elf32_Shdr  arch_shdr_t;
typedef Elf32_Sym   arch_sym_t;
typedef Elf32_Rela  arch_rela_t;
typedef Elf32_Rel   arch_rel_t;
#define ARCH_ELF_CLASS      ELFCLASS32
#define ARCH_R_SYM(i)       ELF32_R_SYM(i)
#define ARCH_R_TYPE(i)      ELF32_R_TYPE(i)
#define IS_GOT_RELOC(t)     ((t) == R_PPC_JMP_SLOT || (t) == R_PPC_GLOB_DAT)
#define ARCH_NAME           "ppc"

/* ------------------------------------------------------------------ */
/* PowerPC 64-bit                                                      */
/* ------------------------------------------------------------------ */
#elif defined(__powerpc64__)

typedef Elf64_Ehdr  arch_ehdr_t;
typedef Elf64_Shdr  arch_shdr_t;
typedef Elf64_Sym   arch_sym_t;
typedef Elf64_Rela  arch_rela_t;
typedef Elf64_Rel   arch_rel_t;
#define ARCH_ELF_CLASS      ELFCLASS64
#define ARCH_R_SYM(i)       ELF64_R_SYM(i)
#define ARCH_R_TYPE(i)      ELF64_R_TYPE(i)
#define IS_GOT_RELOC(t)     ((t) == R_PPC64_JMP_SLOT || (t) == R_PPC64_GLOB_DAT)
#define ARCH_NAME           "ppc64"

/* ------------------------------------------------------------------ */
/* RISC-V 32-bit                                                       */
/* ------------------------------------------------------------------ */
#elif defined(__riscv) && (__riscv_xlen == 32)

typedef Elf32_Ehdr  arch_ehdr_t;
typedef Elf32_Shdr  arch_shdr_t;
typedef Elf32_Sym   arch_sym_t;
typedef Elf32_Rela  arch_rela_t;
typedef Elf32_Rel   arch_rel_t;
#define ARCH_ELF_CLASS      ELFCLASS32
#define ARCH_R_SYM(i)       ELF32_R_SYM(i)
#define ARCH_R_TYPE(i)      ELF32_R_TYPE(i)
#define IS_GOT_RELOC(t)     ((t) == R_RISCV_JUMP_SLOT)
#define ARCH_NAME           "riscv32"

/* ------------------------------------------------------------------ */
/* RISC-V 64-bit                                                       */
/* ------------------------------------------------------------------ */
#elif defined(__riscv) && (__riscv_xlen == 64)

typedef Elf64_Ehdr  arch_ehdr_t;
typedef Elf64_Shdr  arch_shdr_t;
typedef Elf64_Sym   arch_sym_t;
typedef Elf64_Rela  arch_rela_t;
typedef Elf64_Rel   arch_rel_t;
#define ARCH_ELF_CLASS      ELFCLASS64
#define ARCH_R_SYM(i)       ELF64_R_SYM(i)
#define ARCH_R_TYPE(i)      ELF64_R_TYPE(i)
#define IS_GOT_RELOC(t)     ((t) == R_RISCV_JUMP_SLOT)
#define ARCH_NAME           "riscv64"

/* ------------------------------------------------------------------ */
#else
#error "Unsupported architecture — add an #elif block in include/arch.h"
#endif

/* Program header and dynamic entry types — derived from word size, not arch */
#if ARCH_ELF_CLASS == ELFCLASS32
typedef Elf32_Phdr  arch_phdr_t;
typedef Elf32_Dyn   arch_dyn_t;
#else
typedef Elf64_Phdr  arch_phdr_t;
typedef Elf64_Dyn   arch_dyn_t;
#endif

#endif /* ARCH_H */
