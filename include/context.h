#ifndef CONTEXT_H
#define CONTEXT_H

#include "arguments.h"
#include "elf_util.h"
#include <stdint.h>

struct context
{
    struct arguments *arguments;

    int elf_fd;
    int64_t file_size;

    elf_header header;

    char *elf_error;

    int exit_code;
};

#endif    // CONTEXT_H
