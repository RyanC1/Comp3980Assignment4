#include "../include/util.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ssize_t safe_read(const int fd, void *buf, const size_t count, bool exact)
{
    uint8_t *p;
    size_t   total;
    ssize_t  n;

    p     = buf;
    total = 0;

    do
    {
        n = read(fd, p + total, count - total);
        if(n > 0)
        {
            total += (size_t)n;
        }
        else if(n == -1 && errno != EINTR)
        {
            if((errno == EAGAIN || !exact) && total > 0)
            {
                return (ssize_t)total;
            }
            return -1;
        }

    } while(total < count && n != 0);

    if(exact && count != total)
    {
        return -1;
    }

    return (ssize_t)total;
}

ssize_t safe_write(int fd, const void *buf, size_t n)
{
    const uint8_t *p;
    size_t         left;

    p    = (const uint8_t *)buf;
    left = n;
    while(left > 0)
    {
        ssize_t w;
        w = write(fd, p, left);
        if(w > 0)
        {
            p += (size_t)w;
            left -= (size_t)w;
            continue;
        }
        if(w < 0 && errno == EINTR)
        {
            continue;
        }

        return -1;
    }
    return (ssize_t)n;
}

int determine_endianness(void)
{
    const uint16_t v = 0x0102;
    const uint8_t *p = (const uint8_t *)&v;

    return p[0] == 0x02;
}

void byte_swap(void *buf, const int size)
{
    uint8_t  tmp[1];
    uint8_t *p;

    p = (uint8_t *)buf;

    for(int i = 0; i < size / 2; i++)
    {
        memcpy(tmp, p + i, 1);
        memcpy(p + i, p + size - 1 - i, 1);
        memcpy(p + size - 1 - i, tmp, 1);
    }
}
