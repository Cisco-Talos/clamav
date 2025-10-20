/*
 *  Extract component parts of ARJ archives.
 *
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Trog
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#include "clamav.h"
#include "str.h"
#include "others.h"
#include "unarj.h"
#include "textnorm.h"

#define FIRST_HDR_SIZE 30
#define COMMENT_MAX 2048
#define FNAME_MAX 512
#define HEADERSIZE_MAX (FIRST_HDR_SIZE + 10 + FNAME_MAX + COMMENT_MAX)
#define MAXDICBIT 16
#define DDICSIZ 26624
#define THRESHOLD 3
#ifndef UCHAR_MAX
#define UCHAR_MAX (255)
#endif
#ifndef CHAR_BIT
#define CHAR_BIT (8)
#endif
#define MAXMATCH 256

#define CODE_BIT 16
#define NT (CODE_BIT + 3)
#define PBIT 5
#define TBIT 5
#define NC (UCHAR_MAX + MAXMATCH + 2 - THRESHOLD)
#define NP (MAXDICBIT + 1)
#define CBIT 9
#define CTABLESIZE 4096
#define PTABLESIZE 256
#define STRTP 9
#define STOPP 13

#define STRTL 0
#define STOPL 7

#if NT > NP
#define NPT NT
#else
#define NPT NP
#endif

#define GARBLE_FLAG 0x01

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif

#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

typedef struct arj_main_hdr_tag {
    uint8_t first_hdr_size; /* must be 30 bytes */
    uint8_t version;
    uint8_t min_version;
    uint8_t host_os;
    uint8_t flags;
    uint8_t security_version;
    uint8_t file_type;
    uint8_t pad;
    uint32_t time_created __attribute__((packed));
    uint32_t time_modified __attribute__((packed));
    uint32_t archive_size __attribute__((packed));
    uint32_t sec_env_file_position __attribute__((packed));
    uint16_t entryname_pos __attribute__((packed));
    uint16_t sec_trail_size __attribute__((packed));
    uint16_t host_data __attribute__((packed));
} arj_main_hdr_t;

typedef struct arj_file_hdr_tag {
    uint8_t first_hdr_size; /* must be 30 bytes */
    uint8_t version;
    uint8_t min_version;
    uint8_t host_os;
    uint8_t flags;
    uint8_t method;
    uint8_t file_type;
    uint8_t password_mod;
    uint32_t time_modified __attribute__((packed));
    uint32_t comp_size __attribute__((packed));
    uint32_t orig_size __attribute__((packed));
    uint32_t orig_crc __attribute__((packed));
    uint16_t entryname_pos __attribute__((packed));
    uint16_t file_mode __attribute__((packed));
    uint16_t host_data __attribute__((packed));
} arj_file_hdr_t;

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

typedef struct arj_decode_tag {
    unsigned char *text;
    fmap_t *map;
    size_t offset;
    const uint8_t *buf;
    const void *bufend;
    uint16_t blocksize;
    uint16_t bit_buf;
    int bit_count;
    uint32_t comp_size;
    int16_t getlen, getbuf;
    uint16_t left[2 * NC - 1];
    uint16_t right[2 * NC - 1];
    unsigned char c_len[NC];
    uint16_t c_table[CTABLESIZE];
    unsigned char pt_len[NPT];
    unsigned char sub_bit_buf;
    uint16_t pt_table[PTABLESIZE];
    int status;
} arj_decode_t;

static cl_error_t fill_buf(arj_decode_t *decode_data, int n)
{
    if (decode_data->status == CL_EFORMAT)
        return CL_EFORMAT;
    if (((uint64_t)decode_data->bit_buf) * (n > 0 ? 2 << (n - 1) : 0) > UINT32_MAX)
        return CL_EFORMAT;
    decode_data->bit_buf = (((uint64_t)decode_data->bit_buf) << n) & 0xFFFF;
    while (n > decode_data->bit_count) {
        decode_data->bit_buf |= decode_data->sub_bit_buf << (n -= decode_data->bit_count);
        if (decode_data->comp_size != 0) {
            decode_data->comp_size--;
            if (decode_data->buf == decode_data->bufend) {
                size_t len;
                decode_data->buf = fmap_need_off_once_len(decode_data->map, decode_data->offset, 8192, &len);
                if (!decode_data->buf || !len) {
                    /* the file is most likely corrupted, so
                     * we return CL_EFORMAT instead of CL_EREAD
                     */
                    decode_data->status = CL_EFORMAT;
                    return CL_EFORMAT;
                }
                decode_data->bufend = decode_data->buf + len;
            }
            decode_data->sub_bit_buf = *decode_data->buf++;
            decode_data->offset++;
        } else {
            decode_data->sub_bit_buf = 0;
        }
        decode_data->bit_count = CHAR_BIT;
    }
    decode_data->bit_buf |= decode_data->sub_bit_buf >> (decode_data->bit_count -= n);
    return CL_SUCCESS;
}

static cl_error_t init_getbits(arj_decode_t *decode_data)
{
    decode_data->bit_buf     = 0;
    decode_data->sub_bit_buf = 0;
    decode_data->bit_count   = 0;
    return fill_buf(decode_data, 2 * CHAR_BIT);
}

static unsigned short arj_getbits(arj_decode_t *decode_data, int n)
{
    unsigned short x;

    x = decode_data->bit_buf >> (2 * CHAR_BIT - n);
    fill_buf(decode_data, n);
    return x;
}

static cl_error_t decode_start(arj_decode_t *decode_data)
{
    decode_data->blocksize = 0;
    return init_getbits(decode_data);
}

static cl_error_t write_text(int ofd, unsigned char *data, size_t length)
{
    size_t count;

    count = cli_writen(ofd, data, length);
    if (count != length) {
        return CL_EWRITE;
    }
    return CL_SUCCESS;
}

static cl_error_t make_table(arj_decode_t *decode_data, int nchar, unsigned char *bitlen, int tablebits,
                             unsigned short *table, int tablesize)
{
    unsigned short count[17], weight[17], start[18], *p;
    unsigned int i, k, len, ch, jutbits, avail, nextcode, mask;

    for (i = 1; i <= 16; i++) {
        count[i] = 0;
    }
    for (i = 0; (int)i < nchar; i++) {
        if (bitlen[i] >= 17) {
            cli_dbgmsg("UNARJ: bounds exceeded\n");
            decode_data->status = CL_EUNPACK;
            return CL_EUNPACK;
        }
        count[bitlen[i]]++;
    }

    start[1] = 0;
    for (i = 1; i <= 16; i++) {
        start[i + 1] = start[i] + (count[i] << (16 - i));
    }
    if (start[17] != (unsigned short)(1 << 16)) {
        decode_data->status = CL_EUNPACK;
        return CL_EUNPACK;
    }

    jutbits = 16 - tablebits;
    if (tablebits >= 17) {
        cli_dbgmsg("UNARJ: bounds exceeded\n");
        decode_data->status = CL_EUNPACK;
        return CL_EUNPACK;
    }
    for (i = 1; (int)i <= tablebits; i++) {
        start[i] >>= jutbits;
        weight[i] = 1 << (tablebits - i);
    }
    while (i <= 16) {
        weight[i] = 1 << (16 - i);
        i++;
    }

    i = start[tablebits + 1] >> jutbits;
    if (i != (unsigned short)(1 << 16)) {
        k = 1 << tablebits;
        while (i != k) {
            if (i >= (unsigned int)tablesize) {
                cli_dbgmsg("UNARJ: bounds exceeded\n");
                decode_data->status = CL_EUNPACK;
                return CL_EUNPACK;
            }
            table[i++] = 0;
        }
    }

    avail = nchar;
    mask  = 1 << (15 - tablebits);
    for (ch = 0; (int)ch < nchar; ch++) {
        if ((len = bitlen[ch]) == 0) {
            continue;
        }
        if (len >= 17) {
            cli_dbgmsg("UNARJ: bounds exceeded\n");
            decode_data->status = CL_EUNPACK;
            return CL_EUNPACK;
        }
        k        = start[len];
        nextcode = k + weight[len];
        if ((int)len <= tablebits) {
            if (nextcode > (unsigned int)tablesize) {
                decode_data->status = CL_EUNPACK;
                return CL_EUNPACK;
            }
            for (i = start[len]; i < nextcode; i++) {
                table[i] = ch;
            }
        } else {
            p = &table[k >> jutbits];
            i = len - tablebits;
            while (i != 0) {
                if (*p == 0) {
                    if (avail >= (2 * NC - 1)) {
                        cli_dbgmsg("UNARJ: bounds exceeded\n");
                        decode_data->status = CL_EUNPACK;
                        return CL_EUNPACK;
                    }
                    decode_data->right[avail] = decode_data->left[avail] = 0;
                    *p                                                   = avail++;
                }
                if (*p >= (2 * NC - 1)) {
                    cli_dbgmsg("UNARJ: bounds exceeded\n");
                    decode_data->status = CL_EUNPACK;
                    return CL_EUNPACK;
                }
                if (k & mask) {
                    p = &decode_data->right[*p];
                } else {
                    p = &decode_data->left[*p];
                }
                k <<= 1;
                i--;
            }
            *p = ch;
        }
        start[len] = nextcode;
    }
    return CL_SUCCESS;
}

static cl_error_t read_pt_len(arj_decode_t *decode_data, int nn, int nbit, int i_special)
{
    int i, n;
    short c;
    unsigned short mask;

    n = arj_getbits(decode_data, nbit);
    if (n == 0) {
        if (nn > NPT) {
            cli_dbgmsg("UNARJ: bounds exceeded\n");
            decode_data->status = CL_EUNPACK;
            return CL_EUNPACK;
        }
        c = arj_getbits(decode_data, nbit);
        for (i = 0; i < nn; i++) {
            decode_data->pt_len[i] = 0;
        }
        for (i = 0; i < 256; i++) {
            decode_data->pt_table[i] = c;
        }
    } else {
        i = 0;
        while ((i < n) && (i < NPT)) {
            c = decode_data->bit_buf >> 13;
            if (c == 7) {
                mask = 1 << 12;
                while (mask & decode_data->bit_buf) {
                    mask >>= 1;
                    c++;
                }
            }
            fill_buf(decode_data, (c < 7) ? 3 : (int)(c - 3));
            if (decode_data->status != CL_SUCCESS) {
                return decode_data->status;
            }
            decode_data->pt_len[i++] = (unsigned char)c;
            if (i == i_special) {
                c = arj_getbits(decode_data, 2);
                if (decode_data->status != CL_SUCCESS) {
                    return decode_data->status;
                }
                while ((--c >= 0) && (i < NPT)) {
                    decode_data->pt_len[i++] = 0;
                }
            }
        }
        while ((i < nn) && (i < NPT)) {
            decode_data->pt_len[i++] = 0;
        }
        if (make_table(decode_data, nn, decode_data->pt_len, 8, decode_data->pt_table, PTABLESIZE) != CL_SUCCESS) {
            return CL_EUNPACK;
        }
    }
    return CL_SUCCESS;
}

static cl_error_t read_c_len(arj_decode_t *decode_data)
{
    short i, c, n;
    unsigned short mask;

    n = arj_getbits(decode_data, CBIT);
    if (decode_data->status != CL_SUCCESS) {
        return decode_data->status;
    }
    if (n == 0) {
        c = arj_getbits(decode_data, CBIT);
        if (decode_data->status != CL_SUCCESS) {
            return decode_data->status;
        }
        for (i = 0; i < NC; i++) {
            decode_data->c_len[i] = 0;
        }
        for (i = 0; i < CTABLESIZE; i++) {
            decode_data->c_table[i] = c;
        }
    } else {
        i = 0;
        while (i < n) {
            c = decode_data->pt_table[decode_data->bit_buf >> 8];
            if (c >= NT) {
                mask = 1 << 7;
                do {
                    if (c >= (2 * NC - 1)) {
                        cli_dbgmsg("ERROR: bounds exceeded\n");
                        decode_data->status = CL_EFORMAT;
                        return CL_EFORMAT;
                    }
                    if (decode_data->bit_buf & mask) {
                        c = decode_data->right[c];
                    } else {
                        c = decode_data->left[c];
                    }
                    mask >>= 1;
                } while (c >= NT);
            }
            if (c >= 19) {
                cli_dbgmsg("UNARJ: bounds exceeded\n");
                decode_data->status = CL_EUNPACK;
                return CL_EUNPACK;
            }
            fill_buf(decode_data, (int)(decode_data->pt_len[c]));
            if (decode_data->status != CL_SUCCESS) {
                return decode_data->status;
            }
            if (c <= 2) {
                if (c == 0) {
                    c = 1;
                } else if (c == 1) {
                    c = arj_getbits(decode_data, 4) + 3;
                } else {
                    c = arj_getbits(decode_data, CBIT) + 20;
                }
                if (decode_data->status != CL_SUCCESS) {
                    return decode_data->status;
                }
                while (--c >= 0) {
                    if (i >= NC) {
                        cli_dbgmsg("ERROR: bounds exceeded\n");
                        decode_data->status = CL_EFORMAT;
                        return CL_EFORMAT;
                    }
                    decode_data->c_len[i++] = 0;
                }
            } else {
                if (i >= NC) {
                    cli_dbgmsg("ERROR: bounds exceeded\n");
                    decode_data->status = CL_EFORMAT;
                    return CL_EFORMAT;
                }
                decode_data->c_len[i++] = (unsigned char)(c - 2);
            }
        }
        while (i < NC) {
            decode_data->c_len[i++] = 0;
        }
        if (make_table(decode_data, NC, decode_data->c_len, 12, decode_data->c_table, CTABLESIZE) != CL_SUCCESS) {
            return CL_EUNPACK;
        }
    }
    return CL_SUCCESS;
}

static uint16_t decode_c(arj_decode_t *decode_data)
{
    uint16_t j, mask;

    if (decode_data->blocksize == 0) {
        decode_data->blocksize = arj_getbits(decode_data, 16);
        read_pt_len(decode_data, NT, TBIT, 3);
        read_c_len(decode_data);
        read_pt_len(decode_data, NT, PBIT, -1);
    }
    decode_data->blocksize--;
    j = decode_data->c_table[decode_data->bit_buf >> 4];
    if (j >= NC) {
        mask = 1 << 3;
        do {
            if (j >= (2 * NC - 1)) {
                cli_dbgmsg("ERROR: bounds exceeded\n");
                decode_data->status = CL_EUNPACK;
                return 0;
            }
            if (decode_data->bit_buf & mask) {
                j = decode_data->right[j];
            } else {
                j = decode_data->left[j];
            }
            mask >>= 1;
        } while (j >= NC);
    }
    fill_buf(decode_data, (int)(decode_data->c_len[j]));
    return j;
}

static uint16_t decode_p(arj_decode_t *decode_data)
{
    unsigned short j, mask;

    j = decode_data->pt_table[decode_data->bit_buf >> 8];
    if (j >= NP) {
        mask = 1 << 7;
        do {
            if (j >= (2 * NC - 1)) {
                cli_dbgmsg("ERROR: bounds exceeded\n");
                decode_data->status = CL_EUNPACK;
                return 0;
            }
            if (decode_data->bit_buf & mask) {
                j = decode_data->right[j];
            } else {
                j = decode_data->left[j];
            }
            mask >>= 1;
        } while (j >= NP);
    }
    fill_buf(decode_data, (int)(decode_data->pt_len[j]));
    if (j != 0) {
        j--;
        j = (1 << j) + arj_getbits(decode_data, (int)j);
    }
    return j;
}

static cl_error_t decode(arj_metadata_t *metadata)
{
    cl_error_t ret;

    arj_decode_t decode_data;
    uint32_t count = 0, out_ptr = 0;
    int16_t chr, i, j;

    memset(&decode_data, 0, sizeof(decode_data));
    decode_data.text = (unsigned char *)cli_max_calloc(DDICSIZ, 1);
    if (!decode_data.text) {
        return CL_EMEM;
    }
    decode_data.map       = metadata->map;
    decode_data.offset    = metadata->offset;
    decode_data.comp_size = metadata->comp_size;
    ret                   = decode_start(&decode_data);
    if (ret != CL_SUCCESS) {
        free(decode_data.text);
        metadata->offset = decode_data.offset;
        return ret;
    }
    decode_data.status = CL_SUCCESS;

    while (count < metadata->orig_size) {
        if ((chr = decode_c(&decode_data)) <= UCHAR_MAX) {
            decode_data.text[out_ptr] = (unsigned char)chr;
            count++;
            if (++out_ptr >= DDICSIZ) {
                out_ptr = 0;
                if (write_text(metadata->ofd, decode_data.text, DDICSIZ) != CL_SUCCESS) {
                    free(decode_data.text);
                    metadata->offset = decode_data.offset;
                    return CL_EWRITE;
                }
            }
        } else {
            j = chr - (UCHAR_MAX + 1 - THRESHOLD);
            count += j;
            i = decode_p(&decode_data);
            if ((i = out_ptr - i - 1) < 0) {
                i += DDICSIZ;
            }
            if ((i >= DDICSIZ) || (i < 0)) {
                cli_dbgmsg("UNARJ: bounds exceeded - probably a corrupted file.\n");
                break;
            }
            if (out_ptr > (uint32_t)i && out_ptr < DDICSIZ - MAXMATCH - 1) {
                while ((--j >= 0) && (i < DDICSIZ) && (out_ptr < DDICSIZ)) {
                    decode_data.text[out_ptr++] = decode_data.text[i++];
                }
            } else {
                while (--j >= 0) {
                    decode_data.text[out_ptr] = decode_data.text[i];
                    if (++out_ptr >= DDICSIZ) {
                        out_ptr = 0;
                        if (write_text(metadata->ofd, decode_data.text, DDICSIZ) != CL_SUCCESS) {
                            free(decode_data.text);
                            metadata->offset = decode_data.offset;
                            return CL_EWRITE;
                        }
                    }
                    if (++i >= DDICSIZ) {
                        i = 0;
                    }
                }
            }
        }
        if (decode_data.status != CL_SUCCESS) {
            free(decode_data.text);
            metadata->offset = decode_data.offset;
            return decode_data.status;
        }
    }
    if (out_ptr != 0) {
        write_text(metadata->ofd, decode_data.text, out_ptr);
    }

    free(decode_data.text);
    metadata->offset = decode_data.offset;
    return CL_SUCCESS;
}

#define ARJ_BFIL(dd)                             \
    {                                            \
        dd->getbuf |= dd->bit_buf >> dd->getlen; \
        fill_buf(dd, CODE_BIT - dd->getlen);     \
        dd->getlen = CODE_BIT;                   \
    }
#define ARJ_GETBIT(dd, c)                 \
    {                                     \
        if (dd->getlen <= 0) ARJ_BFIL(dd) \
        c = (dd->getbuf & 0x8000) != 0;   \
        dd->getbuf *= 2;                  \
        dd->getlen--;                     \
    }
#define ARJ_BPUL(dd, l)           \
    do {                          \
        int i;                    \
        int j = l;                \
        for (i = 0; i < j; i++) { \
            dd->getbuf *= 2;      \
        }                         \
        dd->getlen -= l;          \
    } while (0)
#define ARJ_GETBITS(dd, c, l)                       \
    {                                               \
        if (dd->getlen < l) ARJ_BFIL(dd)            \
        c = (uint16_t)dd->getbuf >> (CODE_BIT - l); \
        ARJ_BPUL(dd, l);                            \
    }

static uint16_t decode_ptr(arj_decode_t *decode_data)
{
    uint16_t c, width, plus, pwr;

    plus = 0;
    pwr  = 1 << STRTP;
    for (width = STRTP; width < STOPP; width++) {
        ARJ_GETBIT(decode_data, c);
        if (c == 0) {
            break;
        }
        plus += pwr;
        pwr <<= 1;
    }
    if (width != 0) {
        ARJ_GETBITS(decode_data, c, width);
    }
    c += plus;
    return c;
}

static uint16_t decode_len(arj_decode_t *decode_data)
{
    uint16_t c, width, plus, pwr;

    plus = 0;
    pwr  = 1 << STRTL;
    for (width = STRTL; width < STOPL; width++) {
        ARJ_GETBIT(decode_data, c);
        if (c == 0) {
            break;
        }
        plus += pwr;
        pwr <<= 1;
    }
    if (width != 0) {
        ARJ_GETBITS(decode_data, c, width);
    }
    c += plus;
    return c;
}

static cl_error_t decode_f(arj_metadata_t *metadata)
{
    cl_error_t ret;

    arj_decode_t decode_data, *dd;
    uint32_t count = 0, out_ptr = 0;
    int16_t chr, i, j, pos;

    dd = &decode_data;
    memset(&decode_data, 0, sizeof(decode_data));
    decode_data.text = (unsigned char *)cli_max_calloc(DDICSIZ, 1);
    if (!decode_data.text) {
        return CL_EMEM;
    }
    decode_data.map       = metadata->map;
    decode_data.offset    = metadata->offset;
    decode_data.comp_size = metadata->comp_size;
    ret                   = init_getbits(&decode_data);
    if (ret != CL_SUCCESS) {
        free(decode_data.text);
        metadata->offset = decode_data.offset;
        return ret;
    }
    decode_data.getlen = decode_data.getbuf = 0;
    decode_data.status                      = CL_SUCCESS;

    while (count < metadata->orig_size) {
        chr = decode_len(&decode_data);
        if (decode_data.status != CL_SUCCESS) {
            free(decode_data.text);
            metadata->offset = decode_data.offset;
            return decode_data.status;
        }
        if (chr == 0) {
            ARJ_GETBITS(dd, chr, CHAR_BIT);
            if (decode_data.status != CL_SUCCESS) {
                free(decode_data.text);
                metadata->offset = decode_data.offset;
                return decode_data.status;
            }
            decode_data.text[out_ptr] = (unsigned char)chr;
            count++;
            if (++out_ptr >= DDICSIZ) {
                out_ptr = 0;
                if (write_text(metadata->ofd, decode_data.text, DDICSIZ) != CL_SUCCESS) {
                    free(decode_data.text);
                    metadata->offset = decode_data.offset;
                    return CL_EWRITE;
                }
            }
        } else {
            j = chr - 1 + THRESHOLD;
            count += j;
            pos = decode_ptr(&decode_data);
            if (decode_data.status != CL_SUCCESS) {
                free(decode_data.text);
                metadata->offset = decode_data.offset;
                return decode_data.status;
            }
            if ((i = out_ptr - pos - 1) < 0) {
                i += DDICSIZ;
            }
            if ((i >= DDICSIZ) || (i < 0)) {
                cli_dbgmsg("UNARJ: bounds exceeded - probably a corrupted file.\n");
                break;
            }
            while (j-- > 0) {
                decode_data.text[out_ptr] = decode_data.text[i];
                if (++out_ptr >= DDICSIZ) {
                    out_ptr = 0;
                    if (write_text(metadata->ofd, decode_data.text, DDICSIZ) != CL_SUCCESS) {
                        free(decode_data.text);
                        metadata->offset = decode_data.offset;
                        return CL_EWRITE;
                    }
                }
                if (++i >= DDICSIZ) {
                    i = 0;
                }
            }
        }
    }
    if (out_ptr != 0) {
        write_text(metadata->ofd, decode_data.text, out_ptr);
    }

    free(decode_data.text);
    metadata->offset = decode_data.offset;
    return CL_SUCCESS;
}

static cl_error_t arj_unstore(arj_metadata_t *metadata, int ofd, uint32_t len)
{
    const unsigned char *data;
    uint32_t rem;
    unsigned int todo;
    size_t count;

    cli_dbgmsg("in arj_unstore\n");
    rem = len;

    while (rem > 0) {
        todo = (unsigned int)MIN(8192, rem);
        data = fmap_need_off_once_len(metadata->map, metadata->offset, todo, &count);
        if (!data || !count) {
            /* Truncated file, not enough bytes available */
            return CL_EFORMAT;
        }
        metadata->offset += count;
        if (cli_writen(ofd, data, count) != count) {
            /* File writing problem */
            return CL_EWRITE;
        }
        rem -= count;
    }
    return CL_SUCCESS;
}

static bool is_arj_archive(arj_metadata_t *metadata)
{
    const char header_id[2] = {0x60, 0xea};
    const char *mark;

    mark = fmap_need_off_once(metadata->map, metadata->offset, 2);
    if (!mark) {
        cli_dbgmsg("is_arj_archive: Failed to read the two-byte ARJ header ID at offset %zu\n", metadata->offset);
        return false;
    }
    metadata->offset += 2;
    if (memcmp(&mark[0], &header_id[0], 2) == 0) {
        return true;
    }
    cli_dbgmsg("is_arj_archive: The two-byte ARJ header ID did not match; This is not an ARJ archive\n");
    return false;
}

static bool arj_read_main_header(arj_metadata_t *metadata)
{
    uint16_t header_size, count;
    arj_main_hdr_t main_hdr;
    const char *filename = NULL;
    const char *comment  = NULL;
    struct text_norm_state fnstate, comstate;
    unsigned char *fnnorm  = NULL;
    unsigned char *comnorm = NULL;
    bool ret               = true;

    size_t filename_max_len = 0;
    size_t filename_len     = 0;
    size_t comment_max_len  = 0;
    size_t comment_len      = 0;
    size_t orig_offset      = metadata->offset;

    if (fmap_readn(metadata->map, &header_size, metadata->offset, 2) != 2)
        return false;

    metadata->offset += 2;
    header_size = le16_to_host(header_size);
    cli_dbgmsg("Header Size: %d\n", header_size);
    if (header_size == 0) {
        /* End of archive */
        ret = false;
        goto done;
    }
    if (header_size > HEADERSIZE_MAX) {
        cli_dbgmsg("arj_read_header: invalid header_size: %u\n", header_size);
        ret = false;
        goto done;
    }
    if ((header_size + sizeof(header_size)) > (metadata->map->len - metadata->offset)) {
        cli_dbgmsg("arj_read_header: invalid header_size: %u, exceeds length of file.\n", header_size);
        ret = false;
        goto done;
    }
    if (fmap_readn(metadata->map, &main_hdr, metadata->offset, 30) != 30) {
        ret = false;
        goto done;
    }
    metadata->offset += 30;

    cli_dbgmsg("ARJ Main File Header\n");
    cli_dbgmsg("First Header Size: %d\n", main_hdr.first_hdr_size);
    cli_dbgmsg("Version: %d\n", main_hdr.version);
    cli_dbgmsg("Min version: %d\n", main_hdr.min_version);
    cli_dbgmsg("Host OS: %d\n", main_hdr.host_os);
    cli_dbgmsg("Flags: 0x%x\n", main_hdr.flags);
    cli_dbgmsg("Security version: %d\n", main_hdr.security_version);
    cli_dbgmsg("File type: %d\n", main_hdr.file_type);

    if (main_hdr.first_hdr_size < 30) {
        cli_dbgmsg("Format error. First Header Size < 30\n");
        ret = false;
        goto done;
    }
    if (main_hdr.first_hdr_size > 30) {
        metadata->offset += main_hdr.first_hdr_size - 30;
    }

    filename_max_len = (header_size + sizeof(header_size)) - (metadata->offset - orig_offset);
    if (filename_max_len > header_size) {
        cli_dbgmsg("UNARJ: Format error. First Header Size invalid\n");
        ret = false;
        goto done;
    }
    if (filename_max_len > 0) {
        fnnorm   = cli_max_calloc(sizeof(unsigned char), filename_max_len + 1);
        filename = fmap_need_offstr(metadata->map, metadata->offset, filename_max_len + 1);
        if (!filename || !fnnorm) {
            cli_dbgmsg("UNARJ: Unable to allocate memory for filename\n");
            ret = false;
            goto done;
        }
        filename_len = CLI_STRNLEN(filename, filename_max_len);
    }
    metadata->offset += filename_len + 1;

    comment_max_len = (header_size + sizeof(header_size)) - (metadata->offset - orig_offset);
    if (comment_max_len > header_size) {
        cli_dbgmsg("UNARJ: Format error. First Header Size invalid\n");
        ret = false;
        goto done;
    }
    if (comment_max_len > 0) {
        comnorm = cli_max_calloc(sizeof(unsigned char), comment_max_len + 1);
        comment = fmap_need_offstr(metadata->map, metadata->offset, comment_max_len + 1);
        if (!comment || !comnorm) {
            cli_dbgmsg("UNARJ: Unable to allocate memory for comment\n");
            ret = false;
            goto done;
        }
        comment_len = CLI_STRNLEN(comment, comment_max_len);
    }
    metadata->offset += comment_len + 1;

    text_normalize_init(&fnstate, fnnorm, filename_max_len);
    text_normalize_init(&comstate, comnorm, comment_max_len);

    text_normalize_buffer(&fnstate, (const unsigned char *)filename, filename_len);
    text_normalize_buffer(&comstate, (const unsigned char *)comment, comment_len);

    cli_dbgmsg("Filename: %s\n", fnnorm);
    cli_dbgmsg("Comment: %s\n", comnorm);

    metadata->offset += 4; /* crc */
    /* Skip past any extended header data */
    for (;;) {
        const uint16_t *countp = fmap_need_off_once(metadata->map, metadata->offset, 2);
        if (!countp) {
            ret = false;
            goto done;
        }
        count = cli_readint16(countp);
        metadata->offset += 2;
        cli_dbgmsg("Extended header size: %d\n", count);
        if (count == 0) {
            break;
        }
        /* Skip extended header + 4byte CRC */
        metadata->offset += count + 4;
    }

done:

    if (fnnorm) {
        free(fnnorm);
        fnnorm = NULL;
    }

    if (comnorm) {
        free(comnorm);
        comnorm = NULL;
    }
    return ret;
}

static cl_error_t arj_read_file_header(arj_metadata_t *metadata)
{
    uint16_t header_size, count;
    const char *filename = NULL, *comment = NULL;
    arj_file_hdr_t file_hdr;
    struct text_norm_state fnstate, comstate;
    unsigned char *fnnorm  = NULL;
    unsigned char *comnorm = NULL;
    cl_error_t ret         = CL_SUCCESS;

    size_t filename_max_len = 0;
    size_t filename_len     = 0;
    size_t comment_max_len  = 0;
    size_t comment_len      = 0;
    size_t orig_offset      = metadata->offset;

    if (fmap_readn(metadata->map, &header_size, metadata->offset, 2) != 2)
        return CL_EFORMAT;
    header_size = le16_to_host(header_size);
    metadata->offset += 2;

    cli_dbgmsg("Header Size: %d\n", header_size);
    if (header_size == 0) {
        /* End of archive */
        ret = CL_BREAK;
        goto done;
    }
    if (header_size > HEADERSIZE_MAX) {
        cli_dbgmsg("arj_read_file_header: invalid header_size: %u\n ", header_size);
        ret = CL_EFORMAT;
        goto done;
    }
    if ((header_size + sizeof(header_size)) > (metadata->map->len - metadata->offset)) {
        cli_dbgmsg("arj_read_file_header: invalid header_size: %u, exceeds length of file.\n", header_size);
        ret = CL_EFORMAT;
        goto done;
    }
    if (fmap_readn(metadata->map, &file_hdr, metadata->offset, 30) != 30) {
        ret = CL_EFORMAT;
        goto done;
    }
    metadata->offset += 30;
    file_hdr.comp_size = le32_to_host(file_hdr.comp_size);
    file_hdr.orig_size = le32_to_host(file_hdr.orig_size);

    cli_dbgmsg("ARJ File Header\n");
    cli_dbgmsg("First Header Size: %d\n", file_hdr.first_hdr_size);
    cli_dbgmsg("Version: %d\n", file_hdr.version);
    cli_dbgmsg("Min version: %d\n", file_hdr.min_version);
    cli_dbgmsg("Host OS: %d\n", file_hdr.host_os);
    cli_dbgmsg("Flags: 0x%x\n", file_hdr.flags);
    cli_dbgmsg("Method: %d\n", file_hdr.method);
    cli_dbgmsg("File type: %d\n", file_hdr.file_type);
    cli_dbgmsg("File type: %d\n", file_hdr.password_mod);
    cli_dbgmsg("Compressed size: %u\n", file_hdr.comp_size);
    cli_dbgmsg("Original size: %u\n", file_hdr.orig_size);

    if (file_hdr.first_hdr_size < 30) {
        cli_dbgmsg("Format error. First Header Size < 30\n");
        ret = CL_EFORMAT;
        goto done;
    }

    /* Note: this skips past any extended file start position data (multi-volume) */
    if (file_hdr.first_hdr_size > 30) {
        metadata->offset += file_hdr.first_hdr_size - 30;
    }

    filename_max_len = (header_size + sizeof(header_size)) - (metadata->offset - orig_offset);
    if (filename_max_len > header_size) {
        cli_dbgmsg("UNARJ: Format error. First Header Size invalid\n");
        ret = CL_EFORMAT;
        goto done;
    }
    if (filename_max_len > 0) {
        fnnorm = cli_max_calloc(sizeof(unsigned char), filename_max_len + 1);
        if (!fnnorm) {
            cli_dbgmsg("UNARJ: Unable to allocate memory for filename\n");
            ret = CL_EMEM;
            goto done;
        }
        filename = fmap_need_offstr(metadata->map, metadata->offset, filename_max_len + 1);
        if (!filename) {
            cli_dbgmsg("UNARJ: Filename is out of file\n");
            ret = CL_EFORMAT;
            goto done;
        }
        filename_len = CLI_STRNLEN(filename, filename_max_len);
    }
    metadata->offset += filename_len + 1;

    comment_max_len = (header_size + sizeof(header_size)) - (metadata->offset - orig_offset);
    if (comment_max_len > header_size) {
        cli_dbgmsg("UNARJ: Format error. First Header Size invalid\n");
        ret = CL_EFORMAT;
        goto done;
    }
    if (comment_max_len > 0) {
        comnorm = cli_max_calloc(sizeof(unsigned char), comment_max_len + 1);
        if (!comnorm) {
            cli_dbgmsg("UNARJ: Unable to allocate memory for comment\n");
            ret = CL_EMEM;
            goto done;
        }
        comment = fmap_need_offstr(metadata->map, metadata->offset, comment_max_len + 1);
        if (!comment) {
            cli_dbgmsg("UNARJ: comment is out of file\n");
            ret = CL_EFORMAT;
            goto done;
        }
        comment_len += CLI_STRNLEN(comment, comment_max_len);
    }
    metadata->offset += comment_len + 1;

    text_normalize_init(&fnstate, fnnorm, filename_max_len);
    text_normalize_init(&comstate, comnorm, comment_max_len);

    text_normalize_buffer(&fnstate, (const unsigned char *)filename, filename_len);
    text_normalize_buffer(&comstate, (const unsigned char *)comment, comment_len);

    cli_dbgmsg("Filename: %s\n", fnnorm);
    cli_dbgmsg("Comment: %s\n", comnorm);
    metadata->filename = CLI_STRNDUP(filename, filename_len);

    /* Skip CRC */
    metadata->offset += 4;

    /* Skip past any extended header data */
    for (;;) {
        const uint16_t *countp = fmap_need_off_once(metadata->map, metadata->offset, 2);
        if (!countp) {
            if (metadata->filename)
                free(metadata->filename);
            metadata->filename = NULL;
            ret                = CL_EFORMAT;
            goto done;
        }
        count = cli_readint16(countp);
        metadata->offset += 2;
        cli_dbgmsg("Extended header size: %d\n", count);
        if (count == 0) {
            break;
        }
        /* Skip extended header + 4byte CRC */
        metadata->offset += count + 4;
    }
    metadata->comp_size = file_hdr.comp_size;
    metadata->orig_size = file_hdr.orig_size;
    metadata->method    = file_hdr.method;
    metadata->encrypted = ((file_hdr.flags & GARBLE_FLAG) != 0) ? true : false;
    metadata->ofd       = -1;
    if (!metadata->filename) {
        ret = CL_EMEM;
        goto done;
    }

done:

    if (fnnorm) {
        free(fnnorm);
        fnnorm = NULL;
    }

    if (comnorm) {
        free(comnorm);
        comnorm = NULL;
    }
    return ret;
}

cl_error_t cli_unarj_open(fmap_t *map, const char *dirname, arj_metadata_t *metadata)
{
    UNUSEDPARAM(dirname);
    cli_dbgmsg("in cli_unarj_open\n");
    metadata->map    = map;
    metadata->offset = 0;
    if (!is_arj_archive(metadata)) {
        cli_dbgmsg("cli_unarj_open: is_arj_archive check failed\n");
        return CL_EFORMAT;
    }
    if (!arj_read_main_header(metadata)) {
        cli_dbgmsg("cli_unarj_open: Failed to read main header\n");
        return CL_EFORMAT;
    }
    return CL_SUCCESS;
}

cl_error_t cli_unarj_header_check(
    cli_ctx *ctx,
    uint32_t offset,
    size_t *size)
{
    cl_error_t status = CL_EFORMAT;
    bool bool_ret;
    cl_error_t ret;
    arj_metadata_t metadata = {0};
    int files_found         = 0;

    cli_dbgmsg("in cli_unarj_header_check\n");

    if (!ctx || !ctx->fmap || !size) {
        status = CL_ENULLARG;
        goto done;
    }

    metadata.map    = ctx->fmap;
    metadata.offset = offset;
    *size           = 0;

    bool_ret = is_arj_archive(&metadata);
    if (false == bool_ret) {
        cli_dbgmsg("Not in ARJ format\n");
        status = CL_EFORMAT;
        goto done;
    }

    cli_dbgmsg("cli_unarj_header_check: is_arj_archive-check passed\n");

    bool_ret = arj_read_main_header(&metadata);
    if (false == bool_ret) {
        cli_dbgmsg("Failed to read main header\n");
        status = CL_EFORMAT;
        goto done;
    }

    cli_dbgmsg("cli_unarj_header_check: Successfully read main header\n");

    do {
        metadata.filename  = NULL;
        metadata.comp_size = 0;
        metadata.orig_size = 0;

        ret = cli_unarj_prepare_file(&metadata);
        if (ret == CL_SUCCESS) {
            cli_dbgmsg("cli_unarj_header_check: Successfully read file header\n");
            files_found++;

            /* Skip the file data */
            metadata.offset += metadata.comp_size;

        } else if (ret == CL_BREAK) {
            cli_dbgmsg("cli_unarj_header_check: End of archive\n");
        } else {
            cli_dbgmsg("cli_unarj_header_check: Error reading file header: %s\n", cl_strerror(ret));
        }

        CLI_FREE_AND_SET_NULL(metadata.filename);
    } while (ret == CL_SUCCESS);

    if (files_found > 0) {
        /* Successfully found at least one file */
        status = CL_SUCCESS;
        *size  = metadata.offset - offset;
        cli_dbgmsg("cli_unarj_header_check: Successfully found %d files in valid ARJ archive of %zu bytes\n", files_found, *size);
    } else {
        status = CL_EFORMAT;
        cli_dbgmsg("cli_unarj_header_check: No files found; Invalid ARJ archive\n");
    }

done:
    CLI_FREE_AND_SET_NULL(metadata.filename);

    return status;
}

cl_error_t cli_unarj_prepare_file(arj_metadata_t *metadata)
{
    cli_dbgmsg("in cli_unarj_prepare_file\n");

    if (NULL == metadata) {
        cli_dbgmsg("cli_unarj_prepare_file: invalid NULL arguments\n");
        return CL_ENULLARG;
    }

    /* Each file is preceded by the ARJ file marker */
    if (!is_arj_archive(metadata)) {
        cli_dbgmsg("Not in ARJ format\n");
        return CL_EFORMAT;
    }

    return arj_read_file_header(metadata);
}

cl_error_t cli_unarj_extract_file(const char *dirname, arj_metadata_t *metadata)
{
    cl_error_t ret = CL_SUCCESS;
    char filename[1024];

    cli_dbgmsg("in cli_unarj_extract_file\n");
    if (!metadata || !dirname) {
        return CL_ENULLARG;
    }

    if (metadata->encrypted) {
        cli_dbgmsg("PASSWORDed file (skipping)\n");
        metadata->offset += metadata->comp_size;
        cli_dbgmsg("Target offset: %lu\n", (unsigned long int)metadata->offset);
        return CL_SUCCESS;
    }

    snprintf(filename, 1024, "%s" PATHSEP "file.uar", dirname);
    cli_dbgmsg("Filename: %s\n", filename);
    metadata->ofd = open(filename, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, 0600);
    if (metadata->ofd < 0) {
        return CL_EOPEN;
    }
    switch (metadata->method) {
        case 0:
            ret = arj_unstore(metadata, metadata->ofd, metadata->comp_size);
            break;
        case 1:
        case 2:
        case 3:
            ret = decode(metadata);
            break;
        case 4:
            ret = decode_f(metadata);
            break;
        default:
            ret = CL_EFORMAT;
            break;
    }
    return ret;
}
