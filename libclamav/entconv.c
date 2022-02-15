/*
 *  HTML Entity & Encoding normalization.
 *
 *  Copyright (C) 2013-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
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
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#ifdef CL_THREAD_SAFE
#include <pthread.h>
#endif

#include <assert.h>

#include "clamav.h"
#include "others.h"
#include "htmlnorm.h"
#include "hashtab.h"
#include "entconv.h"
#include "entitylist.h"
#include "encoding_aliases.h"
#include "msdoc.h"

#define MODULE_NAME "entconv: "

#define MAX_LINE 1024

#ifndef EILSEQ
#define EILSEQ 84
#endif

#ifndef HAVE_ICONV
typedef struct {
    enum encodings encoding;
    size_t size;
} * iconv_t;
#endif

static unsigned char tohex[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

/* TODO: gcc refuses to inline because it consider call unlikely and code size grows */
static inline unsigned char* u16_normalize(uint16_t u16, unsigned char* out, const ssize_t limit)
{
    assert(limit > 0 && "u16_normalize must be called with positive limit");
    /* \0 is just ignored */
    if (!u16) {
        return out;
    }

    if (u16 < 0xff) {
        assert((uint8_t)u16 != 0);
        *out++ = (uint8_t)u16;
    } else if (u16 == 0x3002 || u16 == 0xFF0E || u16 == 0xFE52) {
        /* bb #4097 */
        *out++ = '.';
    } else {
        size_t i;
        /* normalize only >255 to speed up */
        if (limit <= 8) {
            /* not enough space available */
            return NULL;
        }
        /* inline version of
         * out += snprintf(out, max_num_length, "&#x%x;", u16) */
        out[0] = '&';
        out[1] = '#';
        out[2] = 'x';
        out[7] = ';';
        for (i = 6; i >= 3; --i) {
            out[i] = tohex[u16 & 0xf];
            u16 >>= 4;
        }
        out += 8;
    }
    return out;
}

/* buffer must be at least 2 bytes in size */
unsigned char* u16_normalize_tobuffer(uint16_t u16, unsigned char* dst, size_t dst_size)
{
    unsigned char* out = u16_normalize(u16, dst, dst_size - 1);
    if (out) {
        *out++ = '\0';
        return out;
    }
    return NULL;
}

const char* entity_norm(struct entity_conv* conv, const unsigned char* entity)
{
    struct cli_element* e = cli_hashtab_find(&entities_htable, (const char*)entity, strlen((const char*)entity));
    if (e && e->key) {
        unsigned char* out = u16_normalize((uint16_t)e->data, conv->entity_buff, sizeof(conv->entity_buff) - 1);
        if (out) {
            *out++ = '\0';
            return (const char*)conv->entity_buff;
        }
    }
    return NULL;
}

#ifndef HAVE_ICONV
static size_t encoding_bytes(const char* fromcode, enum encodings* encoding)
{
    /* special case for these unusual byteorders */
    struct cli_element* e = cli_hashtab_find(&aliases_htable, fromcode, strlen(fromcode));
    if (e && e->key) {
        *encoding = (enum encodings)e->data;
    } else {
        *encoding = E_OTHER;
    }

    switch (*encoding) {
        case E_UCS4:
        case E_UCS4_1234:
        case E_UCS4_4321:
        case E_UCS4_2143:
        case E_UCS4_3412:
            return 4;
        case E_UTF16:
        case E_UTF16_BE:
        case E_UTF16_LE:
            return 2;
        case E_UTF8:
        case E_UNKNOWN:
        case E_OTHER:
        default:
            return 1;
    }
}

static iconv_t iconv_open(const char* tocode, const char* fromcode)
{
    UNUSEDPARAM(tocode);

    iconv_t iconv = cli_malloc(sizeof(*iconv));
    if (!iconv)
        return NULL;

    cli_dbgmsg(MODULE_NAME "Internal iconv\n");

    /* TODO: check that tocode is UTF16BE */
    iconv->size = encoding_bytes(fromcode, &iconv->encoding);

    return iconv;
}

static int iconv_close(iconv_t cd)
{
    if (cd)
        free(cd);
    return 0;
}

static int iconv(iconv_t iconv_struct, char** inbuf, size_t* inbytesleft,
                 char** outbuf, size_t* outbytesleft)
{
    const uint8_t* input;
    uint8_t* output;
    size_t maxcopy, i;
    if (!inbuf || !outbuf) {
        return 0;
    }
    maxcopy = (*inbytesleft > *outbytesleft ? *outbytesleft : *inbytesleft) & ~(iconv_struct->size - 1);
    input   = (const uint8_t*)*inbuf;
    output  = (uint8_t*)*outbuf;

    /*,maxcopy is aligned to data size */
    /* output is always utf16be !*/
    switch (iconv_struct->encoding) {
        case E_UCS4:
        case E_UCS4_1234: {
            for (i = 0; i < maxcopy; i += 4) {
                if (!input[i + 2] && !input[i + 3]) {
                    output[i / 2]     = input[i + 1]; /* is compiler smart enough to replace /2, with >>1 ? */
                    output[i / 2 + 1] = input[i];
                } else {
                    cli_dbgmsg(MODULE_NAME "Warning: unicode character out of utf16 range!\n");
                    output[i / 2]     = 0xff;
                    output[i / 2 + 1] = 0xff;
                }
            }
            break;
        }
        case E_UCS4_4321: {
            const uint16_t* in = (const uint16_t*)input; /*UCS4_4321, and UTF16_BE have same endianness, no need for byteswap here*/
            uint16_t* out      = (uint16_t*)output;
            for (i = 0; i < maxcopy / 2; i += 2) {
                if (!in[i]) {
                    out[i / 2] = in[i + 1];
                } else {
                    out[i / 2] = 0xffff;
                }
            }
            break;
        }
        case E_UCS4_2143: {
            const uint16_t* in = (const uint16_t*)input;
            uint16_t* out      = (uint16_t*)output;
            for (i = 0; i < maxcopy / 2; i += 2) {
                if (!in[i + 1])
                    out[i / 2] = in[i];
                else
                    out[i / 2] = 0xffff;
            }
            break;
        }
        case E_UCS4_3412: {
            for (i = 0; i < maxcopy; i += 4) {
                if (!input[i] && !input[i + 1]) {
                    output[i / 2]     = input[i + 3];
                    output[i / 2 + 1] = input[i + 2];
                } else {
                    output[i / 2]     = 0xff;
                    output[i / 2 + 1] = 0xff;
                }
            }
            break;
        }
        case E_UTF16:
        case E_UTF16_LE: {
            for (i = 0; i < maxcopy; i += 2) {
                output[i]     = input[i + 1];
                output[i + 1] = input[i];
            }
            break;
        }
        case E_UTF16_BE:
            memcpy(output, input, maxcopy);
            break;
        case E_UNKNOWN:
        case E_OTHER: {
            const size_t max_copy = *inbytesleft > (*outbytesleft / 2) ? (*outbytesleft / 2) : *inbytesleft;
            for (i = 0; i < max_copy; i++) {
                output[i * 2]     = 0;
                output[i * 2 + 1] = input[i];
            }
            *outbytesleft -= max_copy * 2;
            *inbytesleft -= max_copy;
            *inbuf += max_copy;
            *outbuf += max_copy * 2;
            if (*inbytesleft)
                return E2BIG;
            return 0;
        }
        case E_UTF8: {
            const size_t maxread  = *inbytesleft;
            const size_t maxwrite = *outbytesleft;
            size_t j;
            for (i = 0, j = 0; i < maxread && j < maxwrite;) {
                if (input[i] < 0x7F) {
                    output[j++] = 0;
                    output[j++] = input[i++];
                } else if ((input[i] & 0xE0) == 0xC0) {
                    if ((input[i + 1] & 0xC0) == 0x80) {
                        /* 2 bytes long 110yyyyy zzzzzzzz -> 00000yyy yyzzzzzz*/
                        output[j++] = ((input[i] & 0x1F) >> 2) & 0x07;
                        output[j++] = ((input[i] & 0x1F) << 6) | (input[i + 1] & 0x3F);
                    } else {
                        cli_dbgmsg(MODULE_NAME "invalid UTF8 character encountered\n");
                        break;
                    }
                    i += 2;
                } else if ((input[i] & 0xE0) == 0xE0) {
                    if ((input[i + 1] & 0xC0) == 0x80 && (input[i + 2] & 0xC0) == 0x80) {
                        /* 3 bytes long 1110xxxx 10yyyyyy 10zzzzzzzz -> xxxxyyyy yyzzzzzz*/
                        output[j++] = (input[i] << 4) | ((input[i + 1] >> 2) & 0x0F);
                        output[j++] = (input[i + 1] << 6) | (input[i + 2] & 0x3F);
                    } else {
                        cli_dbgmsg(MODULE_NAME "invalid UTF8 character encountered\n");
                        break;
                    }
                    i += 3;
                } else if ((input[i] & 0xF8) == 0xF0) {
                    if ((input[i + 1] & 0xC0) == 0x80 && (input[i + 2] & 0xC0) == 0x80 && (input[i + 3] & 0xC0) == 0x80) {
                        /* 4 bytes long 11110www 10xxxxxx 10yyyyyy 10zzzzzz -> 000wwwxx xxxxyyyy yyzzzzzz*/
                        cli_dbgmsg(MODULE_NAME "UTF8 character out of UTF16 range encountered\n");
                        output[j++] = 0xff;
                        output[j++] = 0xff;

                        /*out[j++] = ((input[i] & 0x07) << 2) | ((input[i+1] >> 4) & 0x3);
                                                        out[j++] = (input[i+1] << 4) | ((input[i+2] >> 2) & 0x0F);
                                                        out[j++] = (input[i+2] << 6) | (input[i+2] & 0x3F);*/
                    } else {
                        cli_dbgmsg(MODULE_NAME "invalid UTF8 character encountered\n");
                        break;
                    }
                    i += 4;
                } else {
                    cli_dbgmsg(MODULE_NAME "invalid UTF8 character encountered\n");
                    break;
                }
            }
            *inbytesleft -= i;
            *outbytesleft -= j;
            *inbuf += i;
            *outbuf += j;
            if (*inbytesleft && *outbytesleft) {
                errno = EILSEQ; /* we had an early exit */
                return -1;
            }
            if (*inbytesleft) {
                errno = E2BIG;
                return -1;
            }
            return 0;
        }
    }

    *outbytesleft -= maxcopy;
    *inbytesleft -= maxcopy;
    *inbuf += maxcopy;
    *outbuf += maxcopy;
    if (*inbytesleft) {
        errno = E2BIG;
        return -1;
    }
    return 0;
}

#else

#endif

static inline const char* detect_encoding(const unsigned char* bom, uint8_t* bom_found, uint8_t* enc_width)
{
    const char* encoding = NULL;
    int has_bom          = 0;
    uint8_t enc_bytes    = 1; /* default is UTF8, which has a minimum of 1 bytes */
    /* undecided 32-bit encodings are treated as ucs4, and
     * 16 bit as utf16*/
    switch (bom[0]) {
        case 0x00:
            if (bom[1] == 0x00) {
                if (bom[2] == 0xFE && bom[3] == 0xFF) {
                    encoding  = UCS4_1234; /* UCS-4 big-endian*/
                    has_bom   = 1;
                    enc_bytes = 4;
                } else if (bom[2] == 0xFF && bom[3] == 0xFE) {
                    encoding  = UCS4_2143; /* UCS-4 unusual order 2143 */
                    has_bom   = 1;
                    enc_bytes = 4;
                } else if (bom[2] == 0x00 && bom[3] == 0x3C) {
                    /* undecided, treat as ucs4 */
                    encoding  = UCS4_1234;
                    enc_bytes = 4;
                } else if (bom[2] == 0x3C && bom[3] == 0x00) {
                    encoding  = UCS4_2143;
                    enc_bytes = 4;
                }
            } /* 0x00 0x00 */
            else if (bom[1] == 0x3C) {
                if (bom[2] == 0x00) {
                    if (bom[3] == 0x00) {
                        encoding  = UCS4_3412;
                        enc_bytes = 4;
                    } else if (bom[3] == 0x3F) {
                        encoding  = UTF16_BE;
                        enc_bytes = 2;
                    }
                } /*0x00 0x3C 0x00*/
            }     /*0x00 0x3C*/
            break;
        case 0xFF:
            if (bom[1] == 0xFE) {
                if (bom[2] == 0x00 && bom[3] == 0x00) {
                    encoding  = UCS4_4321;
                    enc_bytes = 4;
                    has_bom   = 1;
                } else {
                    encoding  = UTF16_LE;
                    has_bom   = 1;
                    enc_bytes = 2;
                }
            } /*0xFF 0xFE*/
            break;
        case 0xFE:
            if (bom[1] == 0xFF) {
                if (bom[2] == 0x00 && bom[3] == 0x00) {
                    encoding  = UCS4_3412;
                    enc_bytes = 4;
                    has_bom   = 1;
                } else {
                    encoding  = UTF16_BE;
                    has_bom   = 1;
                    enc_bytes = 2;
                }
            } /*0xFE 0xFF*/
            break;
        case 0xEF:
            if (bom[1] == 0xBB && bom[2] == 0xBF) {
                encoding = UTF8;
                has_bom  = 1;
                /*enc_bytes = 4;- default, maximum 4 bytes*/
            } /*0xEF 0xBB 0xBF*/
            break;
        case 0x3C:
            if (bom[1] == 0x00) {
                if (bom[2] == 0x00 && bom[3] == 0x00) {
                    encoding  = UCS4_4321;
                    enc_bytes = 4;
                } else if (bom[2] == 0x3F && bom[3] == 0x00) {
                    encoding  = UTF16_LE;
                    enc_bytes = 2;
                }
            } /*0x3C 0x00*/
            else if (bom[1] == 0x3F && bom[2] == 0x78 && bom[3] == 0x6D) {
                encoding  = NULL;
                enc_bytes = 1;
            } /*0x3C 3F 78 6D*/
            break;
        case 0x4C:
            if (bom[1] == 0x6F && bom[2] == 0xA7 && bom[3] == 0x94) {
                cli_dbgmsg(MODULE_NAME "EBCDIC encoding is not supported in line mode\n");
                encoding  = NULL;
                enc_bytes = 1;
            } /*4C 6F A7 94*/
            break;
    } /*switch*/
    *enc_width = enc_bytes;
    *bom_found = has_bom;
    return encoding;
}

/* detects UTF-16(LE/BE), UCS-4(all 4 variants).
 * UTF-8 and simple ASCII are ignored, because we can process those as text */
const char* encoding_detect_bom(const unsigned char* bom, const size_t length)
{
    uint8_t has_bom;
    uint8_t enc_width;
    const char* encoding;

    if (length < 4) {
        return NULL;
    }
    encoding = detect_encoding(bom, &has_bom, &enc_width);
    return enc_width > 1 ? encoding : NULL;
}

/*()-./0123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz*/
static const uint8_t encname_chars[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

/* checks that encoding is sane, and normalizes to uppercase */
static char* normalize_encoding(const unsigned char* enc)
{
    char* norm;
    size_t i, len;

    if (!enc)
        return NULL;
    len = strlen((const char*)enc);
    if (len > 32)
        return NULL;
    for (i = 0; i < len; i++) {
        if (!encname_chars[enc[i]])
            return NULL;
    }
    norm = cli_malloc(len + 1);
    if (!norm)
        return NULL;
    for (i = 0; i < len; i++)
        norm[i] = toupper(enc[i]);
    norm[len] = '\0';
    return norm;
}

/* sarge leaks on iconv_open/iconv_close, so lets not open/close so many times,
 * just keep on each thread its own pool of iconvs*/

struct iconv_cache {
    iconv_t* tab;
    size_t len;
    size_t last;
    struct cli_hashtable hashtab;
};

static void iconv_cache_init(struct iconv_cache* cache)
{
    /*	cache->tab = NULL;
        cache->len = 0;
        cache->used = 0; - already done by memset*/
    cli_dbgmsg(MODULE_NAME "Initializing iconv pool:%p\n", (void*)cache);
    cli_hashtab_init(&cache->hashtab, 32);
}

static void iconv_cache_destroy(struct iconv_cache* cache)
{
    size_t i;
    cli_dbgmsg(MODULE_NAME "Destroying iconv pool:%p\n", (void*)cache);
    for (i = 0; i < cache->last; i++) {
        cli_dbgmsg(MODULE_NAME "closing iconv:%p\n", cache->tab[i]);
        iconv_close(cache->tab[i]);
    }
    cli_hashtab_clear(&cache->hashtab);
    free(cache->hashtab.htable);
    free(cache->tab);
    free(cache);
}

#ifdef CL_THREAD_SAFE
static pthread_key_t iconv_pool_tls_key;
static pthread_once_t iconv_pool_tls_key_once = PTHREAD_ONCE_INIT;

/* destructor called for all threads that exit via pthread_exit, or cancellation. Unfortunately that doesn't include
 * the main thread, so we have to call this manually for the main thread.*/

static int cache_atexit_registered = 0;

static void iconv_pool_tls_instance_destroy(void* ptr)
{
    if (ptr) {
        iconv_cache_destroy(ptr);
    }
}

static void iconv_cache_cleanup_main(void)
{
    struct iconv_cache* cache = pthread_getspecific(iconv_pool_tls_key);
    if (cache) {
        iconv_pool_tls_instance_destroy(cache);
        pthread_setspecific(iconv_pool_tls_key, NULL);
    }
    pthread_key_delete(iconv_pool_tls_key);
}

static void iconv_pool_tls_key_alloc(void)
{
    pthread_key_create(&iconv_pool_tls_key, iconv_pool_tls_instance_destroy);
    if (!cache_atexit_registered) {
        cli_dbgmsg(MODULE_NAME "iconv:registering atexit\n");
        if (atexit(iconv_cache_cleanup_main)) {
            cli_dbgmsg(MODULE_NAME "failed to register atexit\n");
        }
        cache_atexit_registered = 1;
    }
}

static void init_iconv_pool_ifneeded(void)
{
    pthread_once(&iconv_pool_tls_key_once, iconv_pool_tls_key_alloc);
}

static inline struct iconv_cache* cache_get_tls_instance(void)
{
    struct iconv_cache* cache = pthread_getspecific(iconv_pool_tls_key);
    if (!cache) {
        cache = cli_calloc(1, sizeof(*cache));
        if (!cache) {
            cli_dbgmsg(MODULE_NAME "!Out of memory allocating TLS iconv instance\n");
            return NULL;
        }
        iconv_cache_init(cache);
        pthread_setspecific(iconv_pool_tls_key, cache);
    }
    return cache;
}

#else

static struct iconv_cache* global_iconv_cache = NULL;
static int iconv_global_inited                = 0;

static void iconv_cache_cleanup_main(void)
{
    iconv_cache_destroy(global_iconv_cache);
}

static inline void init_iconv_pool_ifneeded()
{
    if (!iconv_global_inited) {
        global_iconv_cache = cli_calloc(1, sizeof(*global_iconv_cache));
        if (global_iconv_cache) {
            iconv_cache_init(global_iconv_cache);
            atexit(iconv_cache_cleanup_main);
            iconv_global_inited = 1;
        }
    }
}

static inline struct iconv_cache* cache_get_tls_instance(void)
{
    return global_iconv_cache;
}

#endif

static iconv_t iconv_open_cached(const char* fromcode)
{
    struct iconv_cache* cache;
    size_t idx;
    const size_t fromcode_len = strlen((const char*)fromcode);
    struct cli_element* e;
    iconv_t iconv_struct;

    init_iconv_pool_ifneeded();
    cache = cache_get_tls_instance(); /* gets TLS iconv pool */
    if (!cache) {
        cli_dbgmsg(MODULE_NAME "!Unable to get TLS iconv cache!\n");
        errno = EINVAL;
        return (iconv_t)-1;
    }

    e = cli_hashtab_find(&cache->hashtab, fromcode, fromcode_len);
    if (e && ((size_t)e->data == (size_t)-1 || (size_t)e->data > cache->len)) {
        e = NULL;
    }
    if (e) {
        size_t dummy_in, dummy_out;
        /* reset state */
        iconv(cache->tab[(size_t)e->data], NULL, &dummy_in, NULL, &dummy_out);
        return cache->tab[(size_t)e->data];
    }
    cli_dbgmsg(MODULE_NAME "iconv not found in cache, for encoding:%s\n", fromcode);
    iconv_struct = iconv_open("UTF-16BE", (const char*)fromcode);
    if (iconv_struct != (iconv_t)-1) {
        idx = cache->last++;
        if (idx >= cache->len) {
            cache->len += 16;
            cache->tab = cli_realloc2(cache->tab, cache->len * sizeof(cache->tab[0]));
            if (!cache->tab) {
                cli_dbgmsg(MODULE_NAME "!Out of mem in iconv-pool\n");
                errno = ENOMEM;
                /* Close descriptor before returning -1 */
                iconv_close(iconv_struct);
                return (iconv_t)-1;
            }
        }

        cli_hashtab_insert(&cache->hashtab, fromcode, fromcode_len, (const cli_element_data)idx);
        cache->tab[idx] = iconv_struct;
        cli_dbgmsg(MODULE_NAME "iconv_open(),for:%s -> %p\n", fromcode, (void*)cache->tab[idx]);
        return cache->tab[idx];
    }
    return (iconv_t)-1;
}

static int in_iconv_u16(const m_area_t* in_m_area, iconv_t* iconv_struct, m_area_t* out_m_area)
{
    char tmp4[4];
    size_t inleft = in_m_area->length - in_m_area->offset;
    size_t rc, alignfix;
    char* input    = (char*)in_m_area->buffer + in_m_area->offset;
    size_t outleft = out_m_area->length > 0 ? out_m_area->length : 0;
    char* out      = (char*)out_m_area->buffer;

    out_m_area->offset = 0;
    if (!inleft) {
        return 0;
    }
    /* convert encoding conv->tmp_area. conv->out_area */
    alignfix = inleft % 4; /* iconv gives an error if we give him 3 bytes to convert,
                               and we are using ucs4, ditto for utf16, and 1 byte*/
    inleft -= alignfix;

    if (!inleft && alignfix) {
        /* EOF, and we have less than 4 bytes to convert */
        memset(tmp4, 0, 4);
        memcpy(tmp4, input, alignfix);
        input    = tmp4;
        inleft   = 4;
        alignfix = 0;
    }

    while (inleft && (outleft >= 2)) { /* iconv doesn't like inleft to be 0 */
        const size_t outleft_last = outleft;
        assert(*iconv_struct != (iconv_t)-1);
        rc = iconv(*iconv_struct, &input, &inleft, &out, &outleft);
        if (rc == (size_t)-1) {
            if (errno == E2BIG) {
                /* not enough space in output buffer */
                break;
            }
            /*cli_dbgmsg(MODULE_NAME "iconv error:%s\n", cli_strerror(errno, err, sizeof(err)));*/
        } else if (outleft == outleft_last) {
            cli_dbgmsg(MODULE_NAME "iconv stall (no output)\n");
        } else {
            /* everything ok */
            continue;
        }
        /*cli_dbgmsg(MODULE_NAME "resuming (inleft:%lu, outleft:%lu, inpos:%ld, %ld)\n",
                                        inleft, outleft, input - (char*)in_m_area->buffer,
                                        out - (char*)out_m_area->buffer);*/
        /* output raw byte, and resume at next byte */
        if (outleft < 2) break;
        outleft -= 2;
        *out++ = 0;
        *out++ = *input++;
        inleft--;
    }
    cli_dbgmsg("in_iconv_u16: unprocessed bytes: %lu\n", (unsigned long)inleft);
    if (out_m_area->length >= 0 && out_m_area->length >= (off_t)outleft) {
        out_m_area->length -= (off_t)outleft;
    } else {
        cli_dbgmsg(MODULE_NAME "outleft overflown, ignoring\n");
        out_m_area->length = 0;
    }
    out_m_area->offset = 0;
    return 0;
}

int encoding_normalize_toascii(const m_area_t* in_m_area, const char* initial_encoding, m_area_t* out_m_area)
{
    iconv_t iconv_struct;
    off_t i, j;
    char* encoding;

    if (!initial_encoding || !in_m_area || !out_m_area) {
        return CL_ENULLARG;
    }

    encoding = normalize_encoding((const unsigned char*)initial_encoding);
    if (!encoding) {
        cli_dbgmsg(MODULE_NAME "encoding name is not valid, ignoring\n");
        return -1;
    }

    cli_dbgmsg(MODULE_NAME "Encoding %s\n", encoding);
    iconv_struct = iconv_open_cached(encoding);
    if (iconv_struct == (iconv_t)-1) {
        cli_dbgmsg(MODULE_NAME "Encoding not accepted by iconv_open(): %s\n", encoding);
        free(encoding);
        return -1;
    }
    free(encoding);
    in_iconv_u16(in_m_area, &iconv_struct, out_m_area);
    for (i = 0, j = 0; i < out_m_area->length; i += 2) {
        const unsigned char c = (out_m_area->buffer[i] << 4) + out_m_area->buffer[i + 1];
        if (c) {
            out_m_area->buffer[j++] = c;
        }
    }
    out_m_area->length = j;
    return 0;
}

cl_error_t cli_codepage_to_utf8(char* in, size_t in_size, uint16_t codepage, char** out, size_t* out_size)
{
    cl_error_t status = CL_BREAK;

    char* out_utf8       = NULL;
    size_t out_utf8_size = 0;

#if defined(HAVE_ICONV)
    iconv_t conv = (iconv_t)-1;
#elif defined(WIN32)
    LPWSTR lpWideCharStr = NULL;
    int cchWideChar      = 0;
#endif

    if (NULL == in || in_size == 0 || NULL == out || NULL == out_size) {
        cli_dbgmsg("cli_codepage_to_utf8: Invalid args.\n");
        status = CL_EARG;
        goto done;
    }

    *out      = NULL;
    *out_size = 0;

    switch (codepage) {
        case CODEPAGE_US_7BIT_ASCII: /* US-ASCII (7-bit) */
        case CODEPAGE_UTF8: {        /* Unicode (UTF-8) */
            char* track;
            int byte_count, sigbit_count;

            out_utf8_size = in_size;
            out_utf8      = cli_calloc(1, out_utf8_size + 1);
            if (NULL == out_utf8) {
                cli_errmsg("cli_codepage_to_utf8: Failure allocating buffer for utf8 filename.\n");
                status = CL_EMEM;
                goto done;
            }
            memcpy(out_utf8, in, in_size);

            track = out_utf8 + in_size - 1;
            if ((codepage == CODEPAGE_UTF8) && (*track & 0x80)) {
                /*
                 * UTF-8 with a most significant bit.
                 */

                /* locate the start of the last character */
                for (byte_count = 1; (track != out_utf8); track--, byte_count++) {
                    if (((uint8_t)*track & 0xC0) != 0x80)
                        break;
                }

                /* count number of set (1) significant bits */
                for (sigbit_count = 0; sigbit_count < (int)(sizeof(uint8_t) * 8); sigbit_count++) {
                    if (((uint8_t)*track & (0x80 >> sigbit_count)) == 0)
                        break;
                }

                if (byte_count != sigbit_count) {
                    cli_dbgmsg("cli_codepage_to_utf8: cleaning out %d bytes from incomplete "
                               "utf-8 character length %d\n",
                               byte_count, sigbit_count);
                    for (; byte_count > 0; byte_count--, track++) {
                        *track = '\0';
                    }
                }
            }
            break;
        }
        default: {

#if defined(WIN32) && !defined(HAVE_ICONV)

            /*
             * Do conversion using native Win32 APIs.
             */

            if (CODEPAGE_UTF16_LE != codepage) { /* not already UTF16-LE (Windows Unicode) */
                /*
                 * First, Convert from codepage -> UCS-2 LE with MultiByteToWideChar(codepage)
                 */
                if (CODEPAGE_UTF16_BE == codepage) {
                    /*
                     * MultiByteToWideChar() does not support conversions from UTF-16BE to UTF-16LE.
                     * However, conversion is simply a matter of swapping the bytes for each WCHAR_T.
                     * See: https://stackoverflow.com/questions/29054217/multibytetowidechar-for-unicode-code-pages-1200-1201-12000-12001
                     */
                    int i = 0;

                    uint16_t* pCodeUnits = (uint16_t*)in;
                    cchWideChar          = (int)in_size / 2;

                    lpWideCharStr = cli_malloc((cchWideChar) * sizeof(WCHAR)); /* No need for a null terminator here, we'll deal with the exact size */
                    if (NULL == lpWideCharStr) {
                        cli_dbgmsg("cli_codepage_to_utf8: failed to allocate memory for wide char string.\n");
                        status = CL_EMEM;
                        goto done;
                    }

                    for (i = 0; i < cchWideChar; i++) {
                        lpWideCharStr[i] = (WCHAR)(((pCodeUnits[i] << 8) & 0xFF00) |
                                                   ((pCodeUnits[i] >> 8) & 0x00FF));
                    }
                    in = (char*)lpWideCharStr;
                    /* in_size didn't change */

                } else {
                    cchWideChar = MultiByteToWideChar(
                        codepage,
                        0,
                        in,
                        (int)in_size,
                        NULL,
                        0);
                    if (0 == cchWideChar) {
                        DWORD error = GetLastError();
                        cli_dbgmsg("cli_codepage_to_utf8: failed to determine string size needed for ansi to widechar conversion: %d.\n", error);
                        status = CL_EPARSE;
                        goto done;
                    }

                    lpWideCharStr = cli_malloc((cchWideChar) * sizeof(WCHAR)); /* No need for a null terminator here, we'll deal with the exact size */
                    if (NULL == lpWideCharStr) {
                        cli_dbgmsg("cli_codepage_to_utf8: failed to allocate memory for wide char string.\n");
                        status = CL_EMEM;
                        goto done;
                    }

                    cchWideChar = MultiByteToWideChar(
                        codepage,
                        0,
                        in,
                        (int)in_size,
                        lpWideCharStr,
                        cchWideChar);
                    if (0 == cchWideChar) {
                        cli_dbgmsg("cli_codepage_to_utf8: failed to convert multibyte string to widechars.\n");
                        status = CL_EPARSE;
                        goto done;
                    }

                    in      = (char*)lpWideCharStr;
                    in_size = cchWideChar * sizeof(WCHAR);
                }
            }

            /*
             * Convert from UCS-2 LE -> UTF8 with WideCharToMultiByte(CP_UTF8)
             */
            out_utf8_size = WideCharToMultiByte(
                CP_UTF8,
                0,
                (LPCWCH)in,
                (int)in_size / sizeof(WCHAR),
                NULL,
                0,
                NULL,
                NULL);
            if (0 == out_utf8_size) {
                cli_dbgmsg("cli_codepage_to_utf8: failed to determine string size needed for widechar conversion.\n");
                status = CL_EPARSE;
                goto done;
            }

            out_utf8 = cli_malloc(out_utf8_size + 1); /* Add a null terminator to this string */
            if (NULL == out_utf8) {
                cli_dbgmsg("cli_codepage_to_utf8: failed to allocate memory for wide char to utf-8 string.\n");
                status = CL_EMEM;
                goto done;
            }

            out_utf8_size = WideCharToMultiByte(
                CP_UTF8,
                0,
                (LPCWCH)in,
                (int)in_size / sizeof(WCHAR),
                out_utf8,
                (int)out_utf8_size,
                NULL,
                NULL);
            if (0 == out_utf8_size) {
                cli_dbgmsg("cli_codepage_to_utf8: failed to convert widechar string to utf-8.\n");
                status = CL_EPARSE;
                goto done;
            }

            /* Set a null byte, since null-terminator is not provided when in_size is provided */
            out_utf8[out_utf8_size] = '\0';

#elif defined(HAVE_ICONV)

            uint32_t attempt, i;
            const char* encoding = NULL;

            for (i = 0; i < NUMCODEPAGES; ++i) {
                if (codepage == codepage_entries[i].codepage) {
                    encoding = codepage_entries[i].encoding;
                    break;
                } else if (codepage < codepage_entries[i].codepage) {
                    break; /* fail-out early, requires sorted array */
                }
            }

            if (NULL == encoding) {
                cli_dbgmsg("cli_codepage_to_utf8: Invalid codepage parameter passed in.\n");
                goto done;
            }

            for (attempt = 1; attempt <= 3; attempt++) {
                char* inbuf         = in;
                size_t inbufsize    = in_size;
                size_t iconvRet     = -1;
                size_t outbytesleft = 0;

                char* out_utf8_tmp   = NULL;
                char* out_utf8_index = NULL;

                /* Charset to UTF-8 should never exceed in_size * 6;
                 * We can shrink final buffer after the conversion, if needed. */
                out_utf8_size = (in_size * 2) * attempt;

                outbytesleft = out_utf8_size;

                out_utf8 = cli_calloc(1, out_utf8_size + 1);
                if (NULL == out_utf8) {
                    cli_errmsg("cli_codepage_to_utf8: Failure allocating buffer for utf8 data.\n");
                    status = CL_EMEM;
                    goto done;
                }
                out_utf8_index = out_utf8;

                conv = iconv_open("UTF-8//TRANSLIT", encoding);
                if (conv == (iconv_t)-1) {
                    // Try again w/out the //TRANSLIT, required because musl doesn't supprot it.
                    // See: https://github.com/akrennmair/newsbeuter/issues/364#issuecomment-250208235
                    conv = iconv_open("UTF-8", encoding);
                    if (conv == (iconv_t)-1) {
                        cli_warnmsg("cli_codepage_to_utf8: Failed to open iconv.\n");
                        goto done;
                    }
                }

                iconvRet = iconv(conv, &inbuf, &inbufsize, &out_utf8_index, &outbytesleft);
                iconv_close(conv);
                conv = (iconv_t)-1;
                if ((size_t)-1 == iconvRet) {
                    switch (errno) {
                        case E2BIG:
                            cli_warnmsg("cli_codepage_to_utf8: iconv error: There is not sufficient room at *outbuf.\n");
                            free(out_utf8);
                            out_utf8 = NULL;
                            continue; /* Try again, with a larger buffer. */
                        case EILSEQ:
                            cli_warnmsg("cli_codepage_to_utf8: iconv error: An invalid multibyte sequence has been encountered in the input.\n");
                            break;
                        case EINVAL:
                            cli_dbgmsg("cli_codepage_to_utf8: iconv error: An incomplete multibyte sequence has been encountered in the input.\n");
                            break;
                        default:
                            cli_warnmsg("cli_codepage_to_utf8: iconv error: Unexpected error code %d.\n", errno);
                    }
                    status = CL_EPARSE;
                    goto done;
                }

                /* iconv succeeded, but probably didn't use the whole buffer. Free up the extra memory. */
                out_utf8_tmp = cli_realloc(out_utf8, out_utf8_size - outbytesleft + 1);
                if (NULL == out_utf8_tmp) {
                    cli_errmsg("cli_codepage_to_utf8: failure cli_realloc'ing converted filename.\n");
                    status = CL_EMEM;
                    goto done;
                }
                out_utf8      = out_utf8_tmp;
                out_utf8_size = out_utf8_size - outbytesleft;
                break;
            }

#else

            /*
             * No way to do the conversion.
             */
            goto done;

#endif
        }
    }

    *out      = out_utf8;
    *out_size = out_utf8_size;

    status = CL_SUCCESS;

done:

#if defined(WIN32) && !defined(HAVE_ICONV)
    if (NULL != lpWideCharStr) {
        free(lpWideCharStr);
    }
#endif

#if defined(HAVE_ICONV)
    if (conv != (iconv_t)-1) {
        iconv_close(conv);
    }
#endif

    if (CL_SUCCESS != status) {
        if (NULL != out_utf8) {
            free(out_utf8);
        }
    }

    return status;
}

char* cli_utf16toascii(const char* str, unsigned int length)
{
    char* decoded;
    unsigned int i, j;

    if (length < 2) {
        cli_dbgmsg("cli_utf16toascii: length < 2\n");
        return NULL;
    }

    if (length % 2)
        length--;

    if (!(decoded = cli_calloc(length / 2 + 1, sizeof(char))))
        return NULL;

    for (i = 0, j = 0; i < length; i += 2, j++) {
        decoded[j] = ((unsigned char)str[i + 1]) << 4;
        decoded[j] += str[i];
    }

    return decoded;
}

char* cli_utf16_to_utf8(const char* utf16, size_t length, encoding_t type)
{
    /* utf8 -
     * 4 bytes for utf16 high+low surrogate (4 bytes input)
     * 3 bytes for utf16 otherwise (2 bytes input) */
    size_t i, j;
    size_t needed = length * 3 / 2 + 2;
    char* s2;

    if (length < 2)
        return cli_strdup("");
    if (length % 2) {
        cli_warnmsg("utf16 length is not multiple of two: %lu\n", (long)length);
        length--;
    }

    s2 = cli_malloc(needed);
    if (!s2)
        return NULL;

    i = 0;

    if ((utf16[0] == '\xff' && utf16[1] == '\xfe') ||
        (utf16[0] == '\xfe' && utf16[1] == '\xff')) {
        i += 2;
        if (type == E_UTF16)
            type = (utf16[0] == '\xff') ? E_UTF16_LE : E_UTF16_BE;
    } else if (type == E_UTF16) {
        type = E_UTF16_BE;
    }

    for (j = 0; i < length && j < needed; i += 2) {
        uint16_t c = cli_readint16(&utf16[i]);
        if (type == E_UTF16_BE)
            c = cbswap16(c);
        if (c < 0x80) {
            s2[j++] = c;
        } else if (c < 0x800) {
            s2[j]     = 0xc0 | (c >> 6);
            s2[j + 1] = 0x80 | (c & 0x3f);
            j += 2;
        } else if (c < 0xd800 || c >= 0xe000) {
            s2[j]     = 0xe0 | (c >> 12);
            s2[j + 1] = 0x80 | ((c >> 6) & 0x3f);
            s2[j + 2] = 0x80 | (c & 0x3f);
            j += 3;
        } else if (c < 0xdc00 && i + 3 < length) {
            uint16_t c2;
            /* UTF16 high+low surrogate */
            c  = c - 0xd800 + 0x40;
            c2 = i + 3 < length ? cli_readint16(&utf16[i + 2]) : 0;
            c2 -= 0xdc00;
            s2[j]     = 0xf0 | (c >> 8);
            s2[j + 1] = 0x80 | ((c >> 2) & 0x3f);
            s2[j + 2] = 0x80 | ((c & 3) << 4) | (c2 >> 6);
            s2[j + 3] = 0x80 | (c2 & 0x3f);
            j += 4;
            i += 2;
        } else {
            cli_dbgmsg("UTF16 surrogate encountered at wrong pos\n");
            /* invalid char */
            s2[j++] = 0xef;
            s2[j++] = 0xbf;
            s2[j++] = 0xbd;
        }
    }
    if (j >= needed)
        j = needed - 1;
    s2[j] = '\0';
    return s2;
}

int cli_isutf8(const char* buf, unsigned int len)
{
    unsigned int i, j;

    for (i = 0; i < len; i++) {
        if ((buf[i] & 0x80) == 0) { /* 0xxxxxxx is plain ASCII */
            continue;
        } else if ((buf[i] & 0x40) == 0) { /* 10xxxxxx never 1st byte */
            return 0;
        } else {
            unsigned int following;

            if ((buf[i] & 0x20) == 0) { /* 110xxxxx */
                /* c = buf[i] & 0x1f; */
                following = 1;
            } else if ((buf[i] & 0x10) == 0) { /* 1110xxxx */
                /* c = buf[i] & 0x0f; */
                following = 2;
            } else if ((buf[i] & 0x08) == 0) { /* 11110xxx */
                /* c = buf[i] & 0x07; */
                following = 3;
            } else if ((buf[i] & 0x04) == 0) { /* 111110xx */
                /* c = buf[i] & 0x03; */
                following = 4;
            } else if ((buf[i] & 0x02) == 0) { /* 1111110x */
                /* c = buf[i] & 0x01; */
                following = 5;
            } else {
                return 0;
            }

            for (j = 0; j < following; j++) {
                if (++i >= len)
                    return 0;

                if ((buf[i] & 0x80) == 0 || (buf[i] & 0x40))
                    return 0;

                /* c = (c << 6) + (buf[i] & 0x3f); */
            }
        }
    }

    return 1;
}
