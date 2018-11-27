/*
 *  Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 *
 *  Author: Shawn Webb
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

#if HAVE_CONF_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <math.h>

#include <sys/types.h>

#include "clamav.h"
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "libclamav/conv.h"

/** Get the expected decoded length of a base64-encoded string
 * @param[in] data Base64-encoded string
 * @param[in] len length of the string
 * @return The expected decoded length of the base64-encoded string
 */
static size_t base64_len(const char *data, size_t len)
{
    int padding=0;
    size_t i;

    if (!len)
        return 0;

    for (i=len-1; i > 0 && data[i] == '='; i--)
        padding++;

    return (size_t)((3*len)/4 - padding);
}

/** Decode a base64-encoded string
 * @param[in] data The base64-encoded string
 * @param[in] len Length of the base64-encoded string
 * @param[out] obuf If obuf is not set to NULL, store the decoded data in obuf. Otherwise, the decoded data is stored in a dynamically-allocated buffer.
 * @param[out] olen The length of the decoded data
 * @return The base64-decoded data
 */
void *cl_base64_decode(char *data, size_t len, void *obuf, size_t *olen, int oneline)
{
    BIO *bio, *b64;
    void *buf;

    buf = (obuf) ? obuf : malloc(base64_len(data, len)+1);
    if (!(buf))
        return NULL;

    b64 = BIO_new(BIO_f_base64());
    if (!(b64)) {
        if (!(obuf))
            free(buf);

        return NULL;
    }

    bio = BIO_new_mem_buf(data, len);
    if (!(bio)) {
        BIO_free(b64);
        if (!(obuf))
            free(buf);

        return NULL;
    }

    bio = BIO_push(b64, bio);
    if (oneline)
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    *olen = BIO_read(bio, buf, base64_len(data, len));

    BIO_free_all(bio);

    return buf;
}

/** Base64-encode data
 * @param[in] data The data to be encoded
 * @param[in] len The length of the data
 * @return A pointer to the base64-encoded data. The data is stored in a dynamically-allocated buffer.
 */
char *cl_base64_encode(void *data, size_t len)
{
    BIO *bio, *b64;
    char *buf, *p;
    size_t elen;

    b64 = BIO_new(BIO_f_base64());
    if (!(b64))
        return NULL;
    bio = BIO_new(BIO_s_mem());
    if (!(bio)) {
        BIO_free(b64);
        return NULL;
    }

    bio = BIO_push(b64, bio);
    BIO_write(bio, data, len);

    BIO_flush(bio);
    elen = (size_t)BIO_get_mem_data(bio, &buf);

    /* Ensure we're dealing with a NULL-terminated string */
    p = (char *)malloc(elen+1);
    if (NULL == p) {
        BIO_free(b64);
        return NULL;
    }
    memcpy((void *)p, (void *)buf, elen);
    p[elen] = 0x00;
    buf = p;

    BIO_free_all(bio);

    return buf;
}

#if defined(CONV_SELF_TEST)

int main(int argc, char *argv[])
{
    char *plaintext, *encoded, *decoded;
    unsigned char *sha_plaintext, *sha_decoded;
    size_t len;
    int ret=0;
    unsigned int shalen;

    initialize_crypto();

    plaintext = (argv[1]) ? argv[1] : "Hello. This is dog";
    sha_plaintext = sha256(plaintext, strlen(plaintext), NULL, NULL);
    if (!(sha_plaintext)) {
        fprintf(stderr, "Could not generate sha256 of plaintext\n");
        return 1;
    }

    encoded = base64_encode(plaintext, strlen(plaintext));
    if (!(encoded)) {
        fprintf(stderr, "Could not base64 encode plaintest\n");
        return 1;
    }
    fprintf(stderr, "Base64 encoded: %s\n", encoded);

    decoded = base64_decode(encoded, strlen(encoded), NULL, &len);
    if (!(decoded)) {
        fprintf(stderr, "Could not base64 decoded string\n");
        return 1;
    }

    sha_decoded = sha256(decoded, len, NULL, &shalen);
    if (!(sha_decoded)) {
        fprintf(stderr, "Could not generate sha256 of decoded data\n");
        return 1;
    }

    if (memcmp(sha_plaintext, sha_decoded, shalen)) {
        fprintf(stderr, "Decoded does not match plaintext: %s\n", decoded);
        ret = 1;
    }

    free(sha_decoded);
    free(sha_plaintext);
    free(encoded);
    free(decoded);

    cleanup_crypto();

    return ret;
}

#endif
