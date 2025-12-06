#ifndef ELF64_PHEADER_H
#define ELF64_PHEADER_H

#include <stddef.h>
#include <stdint.h>

#define ELF64_PHEADER_LEN 56    // NOLINT(cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)

typedef struct
{
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} elf64_pheader;


#ifdef __cplusplus
#define C_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#define C_ALIGNOF(T) alignof(T)
#else
#define C_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#define C_ALIGNOF(T) _Alignof(T)
#endif

C_STATIC_ASSERT(sizeof(elf64_pheader) == ELF64_PHEADER_LEN, "elf64_pheader size mismatch, expected 56");
C_STATIC_ASSERT(C_ALIGNOF(elf64_pheader) == 8, "elf64_pheader must be 8-byte aligned");
C_STATIC_ASSERT(offsetof(elf64_pheader, p_type) == 0, "p_type bad offset");
C_STATIC_ASSERT(offsetof(elf64_pheader, p_flags) == 4, "p_flags bad offset");
C_STATIC_ASSERT(offsetof(elf64_pheader, p_offset) == 8, "p_offset bad offset");
C_STATIC_ASSERT(offsetof(elf64_pheader, p_vaddr) == 16, "p_vaddr bad offset");
C_STATIC_ASSERT(offsetof(elf64_pheader, p_paddr) == 24, "p_paddr bad offset");
C_STATIC_ASSERT(offsetof(elf64_pheader, p_filesz) == 32, "p_filesz bad offset");
C_STATIC_ASSERT(offsetof(elf64_pheader, p_memsz) == 40, "p_memsz bad offset");
C_STATIC_ASSERT(offsetof(elf64_pheader, p_align) == 48, "p_allign bad offset");

#undef C_STATIC_ASSERT
#undef C_ALIGNOF

#endif    // ELF64_PHEADER_H
