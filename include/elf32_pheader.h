#ifndef ELF32_PHEADER_H
#define ELF32_PHEADER_H

#include <stddef.h>
#include <stdint.h>

#define ELF32_PHEADER_LEN 32    // NOLINT(cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)

typedef struct
{
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
} elf32_pheader;


#ifdef __cplusplus
    #define C_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
    #define C_ALIGNOF(T) alignof(T)
#else
    #define C_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
    #define C_ALIGNOF(T) _Alignof(T)
#endif

C_STATIC_ASSERT(sizeof(elf32_pheader) == ELF32_PHEADER_LEN, "elf32_pheader size mismatch, expected 32");
C_STATIC_ASSERT(C_ALIGNOF(elf32_pheader) == 4, "elf32_pheader must be 4-byte aligned");
C_STATIC_ASSERT(offsetof(elf32_pheader, p_type) == 0, "p_type bad offset");
C_STATIC_ASSERT(offsetof(elf32_pheader, p_offset) == 4, "p_offset bad offset");
C_STATIC_ASSERT(offsetof(elf32_pheader, p_vaddr) == 8, "p_vaddr bad offset");
C_STATIC_ASSERT(offsetof(elf32_pheader, p_paddr) == 12, "p_paddr bad offset");
C_STATIC_ASSERT(offsetof(elf32_pheader, p_filesz) == 16, "p_filesz bad offset");
C_STATIC_ASSERT(offsetof(elf32_pheader, p_memsz) == 20, "p_memsz bad offset");
C_STATIC_ASSERT(offsetof(elf32_pheader, p_flags) == 24, "p_flags bad offset");
C_STATIC_ASSERT(offsetof(elf32_pheader, p_align) == 28, "p_allign bad offset");

#undef C_STATIC_ASSERT
#undef C_ALIGNOF

#endif    // ELF32_PHEADER_H
