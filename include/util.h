#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>
#include <unistd.h>

/**
 * Safely reads count bytes from the given file descriptor or until eof.
 * Returns the number of characters read or -1 if an error occurs.
 * Setting exact to true will prevent non-blocking io from returning
 * a value, instead returning -1.
 *
 * @param fd the file descriptor to read from
 * @param buf where to read too
 * @param count bytes to read
 * @param exact if non-blocking fds should return the number of bytes read or -1
 * @return number of bytes read or -1
 */
ssize_t safe_read(int fd, void *buf, size_t count, bool exact);

/**
 * Writes n bytes from buf to the given fd.
 * Will return n or -1 if not all the bytes were written.
 * @param fd the file to write to
 * @param buf the buffer to pull from
 * @param n the number of bytes to write
 * @return n or -1 if partial write
 */
ssize_t safe_write(int fd, const void *buf, size_t n);

/**
 * Creates a newly allocated string using by concatenating the
 * two given strings, or returns NULL if allocation fails.
 *
 * Assumes both given arguments are valid c strings (null terminated)
 *
 * @param str1 the first string
 * @param str2 the second string
 * @return a pointer to the new string or nullptr if allocation fails
 */
char * concat_string(const char * str1, const char * str2);


/**
 * Determines host endianess
 * @return 1 if small endian, 0 if big endian
 */
int determine_endianness(void);

/**
 * Reverses the bytes of the given buffer.
 * @param buf the buffer to reverse the bytes in
 * @param size the size of the buffer
 */
void byte_swap(void *buf, int size);


#endif    // UTIL_H
