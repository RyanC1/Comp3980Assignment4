set(PROJECT_NAME "Comp3980Assignment4")
set(PROJECT_VERSION "1.0.0")
set(PROJECT_DESCRIPTION "Comp3980Assignment4")
set(PROJECT_LANGUAGE "C")

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Common compiler flags
set(STANDARD_FLAGS
        -D_POSIX_C_SOURCE=200809L
        -D_XOPEN_SOURCE=700
        #-D_GNU_SOURCE
        #-D_DARWIN_C_SOURCE
        #-D__BSD_VISIBLE
        -Werror
)

# Define targets
set(EXECUTABLE_TARGETS elfinspect)
set(LIBRARY_TARGETS "")

set(elfinspect_SOURCES
        src/elfinspect.c
        src/elf_util.c
        src/util.c
)

set(elfinspect_HEADERS
        include/arguments.h
        include/context.h
        include/elf32_header.h
        include/elf32_pheader.h
        include/elf32_sheader.h
        include/elf64_header.h
        include/elf64_pheader.h
        include/elf64_sheader.h
        include/elf_ident.h
        include/errors.h
        include/verification_set.h
)

set(elfinspect_LINK_LIBRARIES
        p101_error
        p101_env
        p101_c
        p101_posix
        p101_unix
        p101_fsm
        p101_convert
        m
)
