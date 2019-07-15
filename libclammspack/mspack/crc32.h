#ifndef CRC32_H
#define CRC32_H

extern const unsigned int crc32_table[256];

/* Return a 32-bit CRC of the contents of the buffer. */

static inline unsigned int
crc32(unsigned int val, const void *ss, int len)
{
        const unsigned char *s = ss;
        while (--len >= 0)
                val = crc32_table[(val ^ *s++) & 0xff] ^ (val >> 8);
        return val;
}

#endif
