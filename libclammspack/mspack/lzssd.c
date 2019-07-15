/* This file is part of libmspack.
 * (C) 2003-2010 Stuart Caie.
 *
 * LZSS is a derivative of LZ77 and was created by James Storer and
 * Thomas Szymanski in 1982. Haruhiko Okumura wrote a very popular C
 * implementation.
 *
 * libmspack is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License (LGPL) version 2.1
 *
 * For further details, see the file COPYING.LIB distributed with libmspack
 */

#include <system.h>
#include <lzss.h>

#define ENSURE_BYTES do {                               \
    if (i_ptr >= i_end) {                               \
        read = system->read(input, &inbuf[0],           \
                            input_buffer_size);         \
        if (read <= 0) {                                \
            system->free(window);                       \
            return (read < 0) ? MSPACK_ERR_READ         \
                              : MSPACK_ERR_OK;          \
        }                                               \
        i_ptr = &inbuf[0]; i_end = &inbuf[read];        \
    }                                                   \
} while (0)

#define WRITE_BYTE do {                                 \
    if (system->write(output, &window[pos], 1) != 1) {  \
        system->free(window);                           \
        return MSPACK_ERR_WRITE;                        \
    }                                                   \
} while (0)

int lzss_decompress(struct mspack_system *system,
                    struct mspack_file *input,
                    struct mspack_file *output,
                    int input_buffer_size,
                    int mode)
{
    unsigned char *window, *inbuf, *i_ptr, *i_end;
    unsigned int pos, i, c, invert, mpos, len;
    int read;

    /* check parameters */
    if (!system || input_buffer_size < 1 || (mode != LZSS_MODE_EXPAND &&
        mode != LZSS_MODE_MSHELP && mode != LZSS_MODE_QBASIC))
    {
        return MSPACK_ERR_ARGS;
    }

    /* allocate memory */
    window = (unsigned char *) system->alloc(system, LZSS_WINDOW_SIZE + input_buffer_size);
    if (!window) return MSPACK_ERR_NOMEMORY;

    /* initialise decompression */
    inbuf = &window[LZSS_WINDOW_SIZE];
    memset(window, LZSS_WINDOW_FILL, (size_t) LZSS_WINDOW_SIZE);
    pos = LZSS_WINDOW_SIZE - ((mode == LZSS_MODE_QBASIC) ? 18 : 16);
    invert = (mode == LZSS_MODE_MSHELP) ? ~0 : 0;
    i_ptr = i_end = &inbuf[0];

    /* loop forever; exit condition is in ENSURE_BYTES macro */
    for (;;) {
        ENSURE_BYTES; c = *i_ptr++ ^ invert;
        for (i = 0x01; i & 0xFF; i <<= 1) {
            if (c & i) {
                /* literal */
                ENSURE_BYTES; window[pos] = *i_ptr++;
                WRITE_BYTE;
                pos++; pos &= LZSS_WINDOW_SIZE - 1;
            }
            else {
                /* match */
                ENSURE_BYTES; mpos = *i_ptr++;
                ENSURE_BYTES; mpos |= (*i_ptr & 0xF0) << 4;
                len = (*i_ptr++ & 0x0F) + 3;
                while (len--) {
                    window[pos] = window[mpos];
                    WRITE_BYTE;
                    pos++;  pos  &= LZSS_WINDOW_SIZE - 1;
                    mpos++; mpos &= LZSS_WINDOW_SIZE - 1;
                }
            }
        }
    }

    /* not reached */
    system->free(window);
    return MSPACK_ERR_OK;
}
