#include "arguments.h"
#include "context.h"
#include "elf32_header.h"
#include "elf32_pheader.h"
#include "elf32_sheader.h"
#include "elf64_header.h"
#include "elf64_pheader.h"
#include "elf64_sheader.h"
#include "errors.h"
#include "util.h"
#include <ctype.h>
#include <fcntl.h>
#include <p101_c/p101_stdlib.h>
#include <p101_c/p101_string.h>
#include <p101_fsm/fsm.h>
#include <p101_posix/p101_string.h>
#include <p101_posix/p101_unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

enum states
{
    PARSE_ARGS = P101_FSM_USER_START,
    HANDLE_ARGS,
    USAGE,
    READ_ELF_HEADER,
    VERIFY_ELF_HEADER,
    PARSE_PROGRAM_HEADERS,
    PARSE_SECTION_HEADERS,
    CLEANUP,
};

struct verification_set
{
    int (*verifier)(uint64_t, char *);
    const uint64_t input;
    const char    *field_name;
};

static p101_fsm_state_t parse_arguments(const struct p101_env *env, struct p101_error *err, void *context);
static p101_fsm_state_t handle_arguments(const struct p101_env *env, struct p101_error *err, void *context);
static p101_fsm_state_t read_elf_header(const struct p101_env *env, struct p101_error *err, void *context);
static p101_fsm_state_t verify_elf_header(const struct p101_env *env, struct p101_error *err, void *context);
static int              run_header_verifiers(const struct p101_env *env, struct p101_error *err, const elf_header *header, char **err_msg);
static p101_fsm_state_t parse_program_headers(const struct p101_env *env, struct p101_error *err, void *context);
static p101_fsm_state_t parse_section_headers(const struct p101_env *env, struct p101_error *err, void *context);
void                    print_elf32_pheaders(elf32_pheader *program_headers, uint64_t count);
void                    print_elf64_pheaders(elf64_pheader *program_headers, uint64_t count);
void                    print_elf32_sheaders(elf32_sheader *section_headers, uint64_t count);
void                    print_elf64_sheaders(elf64_sheader *section_headers, uint64_t count);
static p101_fsm_state_t usage(const struct p101_env *env, struct p101_error *err, void *context);
static p101_fsm_state_t cleanup(const struct p101_env *env, struct p101_error *err, void *context);

#define MSG_LEN 256    // NOLINT(cppcoreguidelines-macro-to-enum, modernize-macro-to-enum)

int main(int argc, char *argv[])
{
    static struct p101_fsm_transition transitions[] = {
        {P101_FSM_INIT,         PARSE_ARGS,            parse_arguments      },
        {PARSE_ARGS,            HANDLE_ARGS,           handle_arguments     },
        {PARSE_ARGS,            USAGE,                 usage                },
        {PARSE_ARGS,            CLEANUP,               cleanup              },
        {HANDLE_ARGS,           READ_ELF_HEADER,       read_elf_header      },
        {HANDLE_ARGS,           CLEANUP,               cleanup              },
        {READ_ELF_HEADER,       VERIFY_ELF_HEADER,     verify_elf_header    },
        {READ_ELF_HEADER,       CLEANUP,               cleanup              },
        {VERIFY_ELF_HEADER,     PARSE_PROGRAM_HEADERS, parse_program_headers},
        {VERIFY_ELF_HEADER,     CLEANUP,               cleanup              },
        {PARSE_PROGRAM_HEADERS, PARSE_SECTION_HEADERS, parse_section_headers},
        {PARSE_PROGRAM_HEADERS, CLEANUP,               cleanup              },
        {PARSE_SECTION_HEADERS, CLEANUP,               cleanup              },
        {USAGE,                 CLEANUP,               cleanup              },
        {CLEANUP,               P101_FSM_EXIT,         NULL                 }
    };

    struct p101_error    *err;
    struct p101_env      *env;
    struct p101_fsm_info *fsm;
    p101_fsm_state_t      from_state;
    p101_fsm_state_t      to_state;
    struct p101_error    *fsm_err;
    struct p101_env      *fsm_env;
    struct arguments      args;
    struct context        ctx;

    err = p101_error_create(false);

    if(err == NULL)
    {
        ctx.exit_code = EXIT_FAILURE;
        goto done;
    }

    env = p101_env_create(err, true, NULL);

    if(p101_error_has_error(err))
    {
        ctx.exit_code = EXIT_FAILURE;
        goto free_error;
    }

    fsm_err = p101_error_create(false);

    if(fsm_err == NULL)
    {
        ctx.exit_code = EXIT_FAILURE;
        goto free_env;
    }

    fsm_env = p101_env_create(err, true, NULL);

    if(p101_error_has_error(err))
    {
        ctx.exit_code = EXIT_FAILURE;
        goto free_fsm_error;
    }

    p101_memset(env, &args, 0, sizeof(args));
    p101_memset(env, &ctx, 0, sizeof(ctx));
    ctx.arguments       = &args;
    ctx.arguments->argc = argc;
    ctx.arguments->argv = argv;
    ctx.exit_code       = EXIT_SUCCESS;

    fsm = p101_fsm_info_create(env, err, "elf-inspect-fsm", fsm_env, fsm_err, NULL);

    p101_fsm_run(fsm, &from_state, &to_state, &ctx, transitions, sizeof(transitions));
    p101_fsm_info_destroy(env, &fsm);

    free(fsm_env);
free_fsm_error:
    p101_error_reset(fsm_err);
    p101_free(env, fsm_err);
free_env:
    p101_free(env, env);
free_error:
    p101_error_reset(err);
    free(err);
done:
    return ctx.exit_code;
}

static p101_fsm_state_t parse_arguments(const struct p101_env *env, struct p101_error *err, void *context)
{
    struct context  *ctx;
    p101_fsm_state_t next_state;
    int              opt;

    P101_TRACE(env);
    ctx                          = (struct context *)context;
    ctx->arguments->program_name = ctx->arguments->argv[0];
    next_state                   = HANDLE_ARGS;
    opterr                       = 0;

    while((opt = p101_getopt(env, ctx->arguments->argc, ctx->arguments->argv, "h")) != -1 && p101_error_has_no_error(err))
    {
        switch(opt)
        {
            case 'h':
            {
                next_state = USAGE;
                break;
            }
            case '?':
            {
                char msg[MSG_LEN];

                if(isprint(optopt))
                {
                    snprintf(msg, sizeof msg, "Unknown option '-%c'.", optopt);
                }
                else
                {
                    snprintf(msg, sizeof msg, "Unknown option character 0x%02X.", (unsigned)(unsigned char)optopt);
                }

                P101_ERROR_RAISE_USER(err, msg, ERR_USAGE);
                break;
            }
            default:
            {
                char msg[MSG_LEN];

                snprintf(msg, sizeof msg, "Internal error: unhandled option '-%c' returned by getopt.", isprint(opt) ? opt : '?');
                P101_ERROR_RAISE_USER(err, msg, ERR_SYSTEM);
                break;
            }
        }
    }

    if(p101_error_has_no_error(err) && next_state != USAGE)
    {
        if(optind >= ctx->arguments->argc)
        {
            P101_ERROR_RAISE_USER(err, "Elf path must be specified", ERR_USAGE);
        }
        else if(optind < ctx->arguments->argc - 1)
        {
            P101_ERROR_RAISE_USER(err, "Too many unnamed arguments", ERR_USAGE);
        }
        else
        {
            ctx->arguments->elf_path = ctx->arguments->argv[optind];
        }
    }

    if(p101_error_is_error(err, P101_ERROR_USER, ERR_USAGE))
    {
        next_state = USAGE;
    }
    else if(p101_error_has_error(err))
    {
        next_state = CLEANUP;
    }

    return next_state;
}

static p101_fsm_state_t handle_arguments(const struct p101_env *env, struct p101_error *err, void *context)
{
    struct context  *ctx;
    p101_fsm_state_t next_state;
    struct stat      file_stats;

    P101_TRACE(env);
    ctx        = (struct context *)context;
    next_state = READ_ELF_HEADER;

    ctx->elf_fd = open(ctx->arguments->elf_path, O_RDONLY | O_CLOEXEC);

    if(ctx->elf_fd == -1)
    {
        P101_ERROR_RAISE_USER(err, "Failed to open given file", ERR_USAGE);
        goto done;
    }

    if(fstat(ctx->elf_fd, &file_stats) == -1)
    {
        P101_ERROR_RAISE_USER(err, "Failed to get fstat() of given file", ERR_USAGE);
        goto done;
    }

    if(!S_ISREG(file_stats.st_mode))
    {
        P101_ERROR_RAISE_USER(err, "Given file is not a regular file", ERR_USAGE);
    }

    ctx->file_size = file_stats.st_size;

done:
    if(p101_error_has_error(err))
    {
        next_state = CLEANUP;
    }

    return next_state;
}

static p101_fsm_state_t read_elf_header(const struct p101_env *env, struct p101_error *err, void *context)
{
    struct context  *ctx;
    p101_fsm_state_t next_state;
    elf_ident        ident;

    P101_TRACE(env);
    ctx        = (struct context *)context;
    next_state = VERIFY_ELF_HEADER;

    if(ctx->file_size < ELF32_HEADER_LEN)
    {
        ctx->elf_error = p101_strdup(env, err, "File size too small to contain elf 32 header");
        goto done;
    }

    if(lseek(ctx->elf_fd, 0, SEEK_SET) == -1)
    {
        P101_ERROR_RAISE_USER(err, "Failed to seek to start of file", ERR_SYSTEM);
        goto done;
    }

    if(safe_read(ctx->elf_fd, &ident, ELF_IDENT_LEN, true) == -1)
    {
        P101_ERROR_RAISE_USER(err, "Failed attempt to read elf ident", ERR_SYSTEM);
        goto done;
    }

    if(ident.ei_class == ELFCLASS32)
    {
        elf32_header header32;
        header32.e_ident = ident;

        if(safe_read(ctx->elf_fd, &header32.e_type, ELF32_HEADER_LEN - ELF_IDENT_LEN, true) == -1)
        {
            P101_ERROR_RAISE_USER(err, "Failed attempt to read elf header (as elf 32)", ERR_SYSTEM);
            goto done;
        }

        if(convert_elf32_header_to_generic(header32, &ctx->header) == -1)
        {
            P101_ERROR_RAISE_USER(err, "Failed attempt to convert elf 32 header to generic form", ERR_SYSTEM);
        }
    }
    else if(ident.ei_class == ELFCLASS64)
    {
        elf64_header header64;
        header64.e_ident = ident;

        if(ctx->file_size < ELF64_HEADER_LEN)
        {
            ctx->elf_error = p101_strdup(env, err, "e_ident is ELFCLASS64 but the file size too small to contain elf 64 header");
            goto done;
        }

        if(safe_read(ctx->elf_fd, &header64.e_type, ELF64_HEADER_LEN - ELF_IDENT_LEN, true) == -1)
        {
            P101_ERROR_RAISE_USER(err, "Failed attempt to read elf header (as elf 64)", ERR_SYSTEM);
            goto done;
        }

        if(convert_elf64_header_to_generic(header64, &ctx->header) == -1)
        {
            P101_ERROR_RAISE_USER(err, "Failed attempt to convert elf 64 header to generic form", ERR_SYSTEM);
        }
    }
    else
    {
        ctx->elf_error = p101_strdup(env, err, "Unknown elf class");
    }

done:
    if(p101_error_has_error(err))
    {
        next_state = CLEANUP;
    }
    else if(ctx->elf_error != NULL)
    {
        printf("Not a valid elf file due to: %s\n", ctx->elf_error);
        next_state = CLEANUP;
    }

    return next_state;
}

static p101_fsm_state_t verify_elf_header(const struct p101_env *env, struct p101_error *err, void *context)
{
    struct context  *ctx;
    p101_fsm_state_t next_state;

    P101_TRACE(env);
    ctx        = (struct context *)context;
    next_state = PARSE_PROGRAM_HEADERS;

    P101_TRACE(env);

    if(run_header_verifiers(env, err, &ctx->header, &ctx->elf_error) == -1 || ctx->elf_error != NULL)
    {
        goto done;
    }

    if(ctx->header.e_ident.ei_class == ELFCLASS32)
    {
        if(ctx->header.e_ehsize != ELF32_HEADER_LEN)
        {
            ctx->elf_error = p101_strdup(env, err, "INVALID ELFEHSIZE");
        }
        else if(ctx->header.e_phentsize != ELF32_PHEADER_LEN)
        {
            ctx->elf_error = p101_strdup(env, err, "INVALID ELFPHENTSIZE");
        }
        else if(ctx->header.e_shentsize != ELF32_SHEADER_LEN)
        {
            ctx->elf_error = p101_strdup(env, err, "INVALID ELFSHENTSIZE");
        }
    }
    else
    {
        if(ctx->header.e_ehsize != ELF64_HEADER_LEN)
        {
            ctx->elf_error = p101_strdup(env, err, "INVALID ELFEHSIZE");
        }
        else if(ctx->header.e_phentsize != ELF64_PHEADER_LEN)
        {
            ctx->elf_error = p101_strdup(env, err, "INVALID ELFPHENTSIZE");
        }
        else if(ctx->header.e_shentsize != ELF64_SHEADER_LEN)
        {
            ctx->elf_error = p101_strdup(env, err, "INVALID ELFSHENTSIZE");
        }
    }

done:
    if(p101_error_has_error(err))
    {
        next_state = CLEANUP;
    }
    else if(ctx->elf_error != NULL)
    {
        printf("Not a valid ELF file due to: %s\n", ctx->elf_error);
        next_state = CLEANUP;
    }

    return next_state;
}

static int run_header_verifiers(const struct p101_env *env, struct p101_error *err, const elf_header *header, char **err_msg)
{
    char                    msg[MAX_VALIDATION_MSG];
    struct verification_set sets[] = {
        {verify_class,   header->e_ident.ei_class,      "class:"      },
        {verify_data,    header->e_ident.ei_data,       "data:"       },
        {verify_version, header->e_ident.ei_version,    "version:"    },
        {verify_osabi,   header->e_ident.ei_osabi,      "OS ABI:"     },
        {NULL,           header->e_ident.ei_abiversion, "ABI Version:"},
        {verify_machine, header->e_machine,             "machine:"    },
        {verify_type,    header->e_type,                "type:"       },
        {verify_version, header->e_version,             "version:"    },
        {NULL,           header->e_entry,               "entry:"      },
        {NULL,           header->e_phoff,               "phoff:"      },
        {NULL,           header->e_shoff,               "shoff:"      },
        {NULL,           header->e_flags,               "flags:"      },
        {NULL,           header->e_ehsize,              "ehsize:"     },
        {NULL,           header->e_phentsize,           "phentsize:"  },
        {NULL,           header->e_phnum,               "phnum:"      },
        {NULL,           header->e_shentsize,           "shentsize:"  },
        {NULL,           header->e_shnum,               "shnum:"      },
        {NULL,           header->e_shstrndx,            "shstrndx:"   },
    };

    P101_TRACE(env);
    p101_memset(env, msg, 0, sizeof(msg));

    if(verify_magic(header->e_ident.ei_mag, msg) == -1)
    {
        *err_msg = p101_strdup(env, err, "INVALID ELFMAGIC");

        if(p101_error_has_error(err))
        {
            goto done;
        }
    }

    printf("%-13s%s\n", "magic:", msg);

    for(size_t i = 0; i < sizeof(sets) / sizeof(sets[0]); i++)
    {
        struct verification_set *set;

        set = &sets[i];

        printf("%-13s%lu ", set->field_name, set->input);
        if(set->verifier != NULL)
        {
            if(set->verifier(set->input, msg) == -1 && *err_msg == NULL)
            {
                *err_msg = p101_strdup(env, err, msg);
            }

            printf("(%s)", msg);
        }

        fputc('\n', stdout);
    }

done:
    if(p101_error_has_error(err))
    {
        return -1;
    }

    return 0;
}

static p101_fsm_state_t parse_program_headers(const struct p101_env *env, struct p101_error *err, void *context)
{
    struct context  *ctx;
    p101_fsm_state_t next_state;
    void            *program_headers;

    P101_TRACE(env);
    ctx             = (struct context *)context;
    next_state      = PARSE_SECTION_HEADERS;
    program_headers = NULL;

    if(ctx->header.e_phoff + ctx->header.e_phnum * ctx->header.e_phentsize > (uint64_t)ctx->file_size)
    {
        printf("Cannot parse program headers, they index out of bounds\n");
        goto done;
    }

    if(lseek(ctx->elf_fd, (int64_t)ctx->header.e_phoff, SEEK_SET) == -1)
    {
        P101_ERROR_RAISE_USER(err, "Failed to seek to phoff value", ERR_SYSTEM);
        goto done;
    }

    program_headers = p101_malloc(env, err, ctx->header.e_phnum * ctx->header.e_phentsize);

    if(program_headers == NULL)
    {
        P101_ERROR_RAISE_USER(err, "Failed to allocate memory for program headers", ERR_SYSTEM);
        goto done;
    }

    if(safe_read(ctx->elf_fd, program_headers, ctx->header.e_phentsize * ctx->header.e_phnum, true) == -1)
    {
        P101_ERROR_RAISE_USER(err, "Failed attempt to read elf program headers", ERR_SYSTEM);
        goto done;
    }

    printf("***** PROGRAM HEADERS *****\n");

    if(ctx->header.e_ident.ei_class == ELFCLASS32)
    {
        elf32_pheader *program_headers32;
        program_headers32 = (elf32_pheader *)program_headers;
        correct_elf32_pheader_endianness(ctx->header.e_ident.ei_data, program_headers32, ctx->header.e_phnum);

        print_elf32_pheaders(program_headers32, ctx->header.e_phnum);
    }
    else
    {
        elf64_pheader *program_headers64;
        program_headers64 = (elf64_pheader *)program_headers;
        correct_elf64_pheader_endianness(ctx->header.e_ident.ei_data, program_headers64, ctx->header.e_phnum);

        print_elf64_pheaders(program_headers64, ctx->header.e_phnum);
    }

done:
    if(p101_error_has_error(err))
    {
        next_state = CLEANUP;
    }

    if(program_headers != NULL)
    {
        p101_free(env, program_headers);
    }

    return next_state;
}

void print_elf32_pheaders(elf32_pheader *program_headers, uint64_t count)
{
    char p_type[MAX_VALIDATION_MSG];

    for(uint64_t i = 0; i < count; i++)
    {
        printf("\t%lu\n", i);

        verify_p_type(program_headers[i].p_type, p_type);
        printf("\t\tp_type=0x%08x (%s)\n", program_headers[i].p_type, p_type);
        printf("\t\tp_offset=0x%08x\n", program_headers[i].p_offset);
        printf("\t\tp_vaddr=0x%08x\n", program_headers[i].p_vaddr);
        printf("\t\tp_paddr=0x%08x\n", program_headers[i].p_paddr);
        printf("\t\tp_filesz=0x%08x\n", program_headers[i].p_filesz);
        printf("\t\tp_memsz=0x%08x\n", program_headers[i].p_memsz);
        printf("\t\tp_flags=0x%08x\n", program_headers[i].p_flags);
        printf("\t\tp_align=0x%08x\n", program_headers[i].p_align);
    }
}

void print_elf64_pheaders(elf64_pheader *program_headers, uint64_t count)
{
    char p_type[MAX_VALIDATION_MSG];

    for(uint64_t i = 0; i < count; i++)
    {
        printf("\t%lu\n", i);

        verify_p_type(program_headers[i].p_type, p_type);
        printf("\t\tp_type=0x%08x (%s)\n", program_headers[i].p_type, p_type);
        printf("\t\tp_offset=0x%016lx\n", program_headers[i].p_offset);
        printf("\t\tp_vaddr=0x%016lx\n", program_headers[i].p_vaddr);
        printf("\t\tp_paddr=0x%016lx\n", program_headers[i].p_paddr);
        printf("\t\tp_filesz=0x%016lx\n", program_headers[i].p_filesz);
        printf("\t\tp_memsz=0x%016lx\n", program_headers[i].p_memsz);
        printf("\t\tp_flags=0x%08x\n", program_headers[i].p_flags);
        printf("\t\tp_align=0x%016lx\n", program_headers[i].p_align);
    }
}

static p101_fsm_state_t parse_section_headers(const struct p101_env *env, struct p101_error *err, void *context)
{
    struct context *ctx;
    void           *section_headers;

    P101_TRACE(env);
    ctx             = (struct context *)context;
    section_headers = NULL;

    if(ctx->header.e_shoff + ctx->header.e_shnum * ctx->header.e_shentsize > (uint64_t)ctx->file_size)
    {
        printf("Cannot parse section headers, they index out of bounds\n");
        goto done;
    }

    if(lseek(ctx->elf_fd, (int64_t)ctx->header.e_shoff, SEEK_SET) == -1)
    {
        P101_ERROR_RAISE_USER(err, "Failed to seek to shoff value", ERR_SYSTEM);
        goto done;
    }

    section_headers = p101_malloc(env, err, ctx->header.e_shnum * ctx->header.e_shentsize);

    if(section_headers == NULL)
    {
        P101_ERROR_RAISE_USER(err, "Failed to allocate memory for section headers", ERR_SYSTEM);
        goto done;
    }

    if(safe_read(ctx->elf_fd, section_headers, ctx->header.e_shentsize * ctx->header.e_shnum, true) == -1)
    {
        P101_ERROR_RAISE_USER(err, "Failed attempt to read elf section headers", ERR_SYSTEM);
        goto done;
    }

    printf("***** SECTION HEADERS *****\n");

    if(ctx->header.e_ident.ei_class == ELFCLASS32)
    {
        elf32_sheader *section_headers32;
        section_headers32 = (elf32_sheader *)section_headers;
        correct_elf32_sheader_endianness(ctx->header.e_ident.ei_data, section_headers32, ctx->header.e_shnum);

        print_elf32_sheaders(section_headers32, ctx->header.e_shnum);
    }
    else
    {
        elf64_sheader *section_headers64;
        section_headers64 = (elf64_sheader *)section_headers;
        correct_elf64_sheader_endianness(ctx->header.e_ident.ei_data, section_headers64, ctx->header.e_shnum);

        print_elf64_sheaders(section_headers64, ctx->header.e_shnum);
    }

done:
    if(section_headers != NULL)
    {
        p101_free(env, section_headers);
    }

    return CLEANUP;
}

void print_elf32_sheaders(elf32_sheader *section_headers, uint64_t count)
{
    char s_type[MAX_VALIDATION_MSG];

    for(uint64_t i = 0; i < count; i++)
    {
        printf("\t%lu\n", i);
        printf("\t\tsh_name=0x%08x\n", section_headers[i].s_name);

        verify_s_type(section_headers[i].s_type, s_type);
        printf("\t\tsh_type=0x%08x (%s)\n", section_headers[i].s_type, s_type);
        printf("\t\tsh_flags=0x%08x\n", section_headers[i].s_flags);
        printf("\t\tsh_addr=0x%08x\n", section_headers[i].s_addr);
        printf("\t\tsh_offset=0x%08x\n", section_headers[i].s_offset);
        printf("\t\tsh_size=0x%08x\n", section_headers[i].s_size);
        printf("\t\tsh_link=%u\n", section_headers[i].s_link);
        printf("\t\tsh_info=%u\n", section_headers[i].s_info);
        printf("\t\tsh_addralign=%u\n", section_headers[i].s_addralign);
        printf("\t\tsh_entsize=%u\n", section_headers[i].s_entsize);
    }
}

void print_elf64_sheaders(elf64_sheader *section_headers, uint64_t count)
{
    char s_type[MAX_VALIDATION_MSG];

    for(uint64_t i = 0; i < count; i++)
    {
        printf("\t%lu\n", i);
        printf("\t\tsh_name=0x%08x\n", section_headers[i].s_name);

        verify_s_type(section_headers[i].s_type, s_type);
        printf("\t\tsh_type=0x%08x (%s)\n", section_headers[i].s_type, s_type);
        printf("\t\tsh_flags=0x%016lx\n", section_headers[i].s_flags);
        printf("\t\tsh_addr=0x%016lx\n", section_headers[i].s_addr);
        printf("\t\tsh_offset=0x%016lx\n", section_headers[i].s_offset);
        printf("\t\tsh_size=0x%016lx\n", section_headers[i].s_size);
        printf("\t\tsh_link=%u\n", section_headers[i].s_link);
        printf("\t\tsh_info=%u\n", section_headers[i].s_info);
        printf("\t\tsh_addralign=%lu\n", section_headers[i].s_addralign);
        printf("\t\tsh_entsize=%lu\n", section_headers[i].s_entsize);
    }
}

static p101_fsm_state_t usage(const struct p101_env *env, struct p101_error *err, void *context)
{
    struct context *ctx;

    P101_TRACE(env);
    ctx = (struct context *)context;

    if(p101_error_has_error(err))
    {
        const char *msg;
        msg = p101_error_get_message(err);

        if(msg != NULL)
        {
            fputs(msg, stderr);
            fputc('\n', stderr);
        }

        p101_error_reset(err);
        ctx->exit_code = EXIT_FAILURE;

        p101_error_reset(err);
        ctx->exit_code = EXIT_FAILURE;
    }

    fprintf(stderr, "Usage: %s [-h] <file-path>\n", ctx->arguments->program_name);
    fputs("Options:\n", stderr);
    fputs("  -h                Display this help message\n", stderr);
    fputs("  <file-path>     Path to the elf file (required)\n", stderr);

    return CLEANUP;
}

static p101_fsm_state_t cleanup(const struct p101_env *env, struct p101_error *err, void *context)
{
    struct context *ctx;

    P101_TRACE(env);
    ctx = (struct context *)context;

    if(p101_error_has_error(err))
    {
        p101_error_default_error_reporter(err);
        p101_error_reset(err);
        ctx->exit_code = EXIT_FAILURE;
    }

    p101_free(env, ctx->elf_error);
    ctx->elf_error = NULL;

    if(ctx->elf_fd > 0 && p101_close(env, err, ctx->elf_fd) != -1)
    {
        ctx->elf_fd = -1;
    }

    if(p101_error_has_error(err))
    {
        p101_error_default_error_reporter(err);
        p101_error_reset(err);
        ctx->exit_code = EXIT_FAILURE;
    }

    return P101_FSM_EXIT;
}
