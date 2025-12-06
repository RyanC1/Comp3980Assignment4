#ifndef ELF64_SHEADER_H
#define ELF64_SHEADER_H


#include <stddef.h>
#include <stdint.h>

#define ELF64_SHEADER_LEN 64    // NOLINT(cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)

typedef struct
{
    uint32_t s_name;
    uint32_t s_type;
    uint64_t s_flags;
    uint64_t s_addr;
    uint64_t s_offset;
    uint64_t s_size;
    uint32_t s_link;
    uint32_t s_info;
    uint64_t s_addralign;
    uint64_t s_entsize;
} elf64_sheader;


#ifdef __cplusplus
#define C_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#define C_ALIGNOF(T) alignof(T)
#else
#define C_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#define C_ALIGNOF(T) _Alignof(T)
#endif

C_STATIC_ASSERT(sizeof(elf64_sheader) == ELF64_SHEADER_LEN, "elf64_sheader size mismatch, expected 64");
C_STATIC_ASSERT(C_ALIGNOF(elf64_sheader) == 8, "elf64_sheader must be 4-byte aligned");
C_STATIC_ASSERT(offsetof(elf64_sheader, s_name) == 0, "s_name bad offset");
C_STATIC_ASSERT(offsetof(elf64_sheader, s_type) == 4, "s_type bad offset");
C_STATIC_ASSERT(offsetof(elf64_sheader, s_flags) == 8, "s_flags bad offset");
C_STATIC_ASSERT(offsetof(elf64_sheader, s_addr) == 16, "s_addr bad offset");
C_STATIC_ASSERT(offsetof(elf64_sheader, s_offset) == 24, "s_offset bad offset");
C_STATIC_ASSERT(offsetof(elf64_sheader, s_size) == 32, "s_size bad offset");
C_STATIC_ASSERT(offsetof(elf64_sheader, s_link) == 40, "s_link bad offset");
C_STATIC_ASSERT(offsetof(elf64_sheader, s_info) == 44, "s_info bad offset");
C_STATIC_ASSERT(offsetof(elf64_sheader, s_addralign) == 48, "s_addralign bad offset");
C_STATIC_ASSERT(offsetof(elf64_sheader, s_entsize) == 56, "s_entsize bad offset");

#undef C_STATIC_ASSERT
#undef C_ALIGNOF

#endif    // ELF64_SHEADER_H
