#ifndef ELF32_SHEADER_H
#define ELF32_SHEADER_H


#include <stddef.h>
#include <stdint.h>

#define ELF32_SHEADER_LEN 40    // NOLINT(cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)

typedef struct
{
    uint32_t s_name;
    uint32_t s_type;
    uint32_t s_flags;
    uint32_t s_addr;
    uint32_t s_offset;
    uint32_t s_size;
    uint32_t s_link;
    uint32_t s_info;
    uint32_t s_addralign;
    uint32_t s_entsize;
} elf32_sheader;


#ifdef __cplusplus
#define C_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#define C_ALIGNOF(T) alignof(T)
#else
#define C_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#define C_ALIGNOF(T) _Alignof(T)
#endif

C_STATIC_ASSERT(sizeof(elf32_sheader) == ELF32_SHEADER_LEN, "elf32_sheader size mismatch, expected 40");
C_STATIC_ASSERT(C_ALIGNOF(elf32_sheader) == 4, "elf32_sheader must be 4-byte aligned");
C_STATIC_ASSERT(offsetof(elf32_sheader, s_name) == 0, "s_name bad offset");
C_STATIC_ASSERT(offsetof(elf32_sheader, s_type) == 4, "s_type bad offset");
C_STATIC_ASSERT(offsetof(elf32_sheader, s_flags) == 8, "s_flags bad offset");
C_STATIC_ASSERT(offsetof(elf32_sheader, s_addr) == 12, "s_addr bad offset");
C_STATIC_ASSERT(offsetof(elf32_sheader, s_offset) == 16, "s_offset bad offset");
C_STATIC_ASSERT(offsetof(elf32_sheader, s_size) == 20, "s_size bad offset");
C_STATIC_ASSERT(offsetof(elf32_sheader, s_link) == 24, "s_link bad offset");
C_STATIC_ASSERT(offsetof(elf32_sheader, s_info) == 28, "s_info bad offset");
C_STATIC_ASSERT(offsetof(elf32_sheader, s_addralign) == 32, "s_addralign bad offset");
C_STATIC_ASSERT(offsetof(elf32_sheader, s_entsize) == 36, "s_entsize bad offset");

#undef C_STATIC_ASSERT
#undef C_ALIGNOF

#endif    // ELF32_SHEADER_H
