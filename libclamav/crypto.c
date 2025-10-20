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
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>

#ifdef _WIN32
#include <io.h>
#endif

#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define X509_CRL_get0_nextUpdate X509_CRL_get_nextUpdate
#endif

#if !defined(_WIN32)
#include <unistd.h>
#endif

#include "clamav.h"
#include "default.h"
#include "others.h"
#include "conv.h"
#include "str.h"
#include "iowrap.h"

#if defined(_WIN32)
char *strptime(const char *buf, const char *fmt, struct tm *tm);
#endif

#if defined(_WIN32)
#define EXCEPTION_PREAMBLE __try {
#define EXCEPTION_POSTAMBLE                                                 \
    }                                                                       \
    __except (filter_memcpy(GetExceptionCode(), GetExceptionInformation())) \
    {                                                                       \
        win_exception = true;                                               \
    }
#else
#define EXCEPTION_PREAMBLE
#define EXCEPTION_POSTAMBLE
#endif

#if !defined(MIN)
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#if !defined(HAVE_TIMEGM) && !defined(_WIN32)
/*
 * Solaris 10 and earlier don't have timegm. Provide a portable version of it.
 * A special thank you to Dave Simonson for helping test and develop this.
 */
time_t timegm(struct tm *t)
{
    time_t tl, tb;
    struct tm *tg;

    tl = mktime(t);
    if (tl == -1) {
        t->tm_hour--;
        tl = mktime(t);
        if (tl == -1)
            return -1; /* can't deal with output from strptime */
        tl += 3600;
    }

    tg           = gmtime(&tl);
    tg->tm_isdst = 0;
    tb           = mktime(tg);

    if (tb == -1) {
        tg->tm_hour--;
        tb = mktime(tg);
        if (tb == -1)
            return -1; /* can't deal with output from gmtime */

        tb += 3600;
    }

    return (tl - (tb - tl));
}
#endif

/**
 * @brief This function initializes the openssl crypto system
 *
 * Called by cl_init() and does not need to be cleaned up as de-init
 * is handled automatically by openssl 1.0.2.h and 1.1.0
 *
 * @return Always returns 0
 *
 */
int cl_initialize_crypto(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_digests();
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    ERR_load_crypto_strings();
#endif

    return 0;
}

/**
 * @brief This is a deprecated function that used to clean up ssl crypto inits
 *
 * @deprecated This function is deprecated and will be removed in a future release.
 *
 * Call to EVP_cleanup() has been removed since cleanup is now handled by
 * auto-deinit as of openssl 1.0.2h and 1.1.0
 *
 */
void cl_cleanup_crypto(void)
{
    return;
}

/**
 * @brief Generate a hash of data.
 *
 * @param alg               The hashing algorithm to use.
 *                          Suggested "alg" names include "md5", "sha1", "sha2-256", "sha2-384", and "sha2-512".
 *                          But the underlying hashing library is OpenSSL and you might be able to use
 *                          other algorithms supported by OpenSSL's EVP_get_digestbyname() function.
 *                          Note: For the `cl_scan*` functions (above) the supported algorithms are
 *                                presently limited to "md5", "sha1", "sha2-256".
 * @param data              The data to be hashed.
 * @param data_len          The length of the to-be-hashed data.
 * @param[inout] hash       A buffer to store the generated hash.
 *                          Set flags to CL_HASH_FLAG_ALLOCATE to dynamically allocate buffer.
 * @param[inout] hash_len   A pointer that stores how long the generated hash is.
 * @param flags             Flags to modify the behavior of the hashing function.
 *                          Use CL_HASH_FLAG_ALLOCATE to dynamically allocate the output buffer.
 *                          Use CL_HASH_FLAG_FIPS_BYPASS to bypass FIPS restrictions on which algorithms can be used.
 *
 * @return cl_error_t       CL_SUCCESS if the hash was generated successfully.
 *                          CL_E* error code if an error occurred.
 */
extern cl_error_t cl_hash_data_ex(
    const char *alg,
    const uint8_t *data,
    size_t data_len,
    uint8_t **hash,
    size_t *hash_len,
    uint32_t flags)
{
    cl_error_t status = CL_ERROR;

    EVP_MD_CTX *ctx = NULL;

#if OPENSSL_VERSION_MAJOR >= 3
    OSSL_LIB_CTX *ossl_ctx = NULL;
    EVP_MD *md             = NULL;
#else
    const EVP_MD *md = NULL;
#endif

    size_t required_hash_len;
    uint8_t *new_hash = NULL;
    unsigned int hash_len_final;

    size_t cur;
#if defined(_WIN32)
    bool win_exception = false;
#endif

    if (NULL == alg || NULL == data || NULL == hash || NULL == hash_len) {
        cli_errmsg("cl_hash_data_ex: Invalid arguments\n");
        status = CL_ENULLARG;
        goto done;
    }

#if OPENSSL_VERSION_MAJOR >= 3
    if (flags & CL_HASH_FLAG_FIPS_BYPASS) {
        /* Bypass FIPS restrictions the OpenSSL 3.0 way */
        ossl_ctx = OSSL_LIB_CTX_new();
        if (NULL == ossl_ctx) {
            cli_errmsg("cl_hash_data_ex: Failed to create new OpenSSL library context\n");
            status = CL_EMEM;
            goto done;
        }

        md = EVP_MD_fetch(ossl_ctx, to_openssl_alg(alg), "-fips");
    } else {
        /* Use FIPS compliant algorithms */
        md = EVP_MD_fetch(NULL, to_openssl_alg(alg), NULL);
    }
#else
    md = EVP_get_digestbyname(to_openssl_alg(alg));
#endif
    if (NULL == md) {
        cli_errmsg("cl_hash_data_ex: Unsupported hash algorithm: %s\n", alg);
        status = CL_EARG;
        goto done;
    }

    required_hash_len = (size_t)EVP_MD_size(md);

    if (flags & CL_HASH_FLAG_ALLOCATE) {
        new_hash = (uint8_t *)malloc(required_hash_len);
        if (new_hash == NULL) {
            cli_errmsg("cl_hash_data_ex: Failed to allocate memory for hash\n");
            status = CL_EMEM;
            goto done;
        }
    } else {
        if (*hash_len < required_hash_len) {
            cli_errmsg("cl_hash_data_ex: Provided hash buffer for '%s' is too small. Provided bytes: %zu, Required bytes: %zu\n", alg, *hash_len, required_hash_len);
            status = CL_EARG;
            goto done;
        }
        new_hash = *hash;
    }

    ctx = EVP_MD_CTX_new();
    if (NULL == ctx) {
        cli_errmsg("cl_hash_data_ex: Failed to create EVP_MD_CTX\n");
        status = CL_EMEM;
        goto done;
    }

#ifdef EVP_MD_CTX_FLAG_NON_FIPS_ALLOW
    if (flags & CL_HASH_FLAG_FIPS_BYPASS && OPENSSL_VERSION_NUMBER < 0x30000000L) {
        /* Bypass FIPS restrictions the OpenSSL 1.x way */
        EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
    }
#endif

    if (!EVP_DigestInit_ex(ctx, md, NULL)) {
        cli_errmsg("cl_hash_data_ex: Failed to initialize digest context\n");
        status = CL_EMEM;
        goto done;
    }

    cur = 0;
    while (cur < data_len) {
        size_t todo = MIN(
            (size_t)EVP_MD_block_size(md),
            data_len - cur);

        EXCEPTION_PREAMBLE
        if (!EVP_DigestUpdate(ctx, (const void *)(data + cur), todo)) {
            cli_errmsg("cl_hash_data_ex: Failed to update digest context\n");
            status = CL_EMEM;
            goto done;
        }
        EXCEPTION_POSTAMBLE

#if defined(_WIN32)
        if (win_exception) {
            cli_errmsg("cl_hash_data_ex: Exception occurred during hashing\n");
            status = CL_ERROR;
            goto done;
        }
#endif

        cur += todo;
    }

    if (!EVP_DigestFinal_ex(ctx, new_hash, &hash_len_final)) {
        cli_errmsg("cl_hash_data_ex: Failed to finalize digest context\n");
        status = CL_EMEM;
        goto done;
    }

    if (flags & CL_HASH_FLAG_ALLOCATE) {
        // give up ownership of the new hash buffer
        *hash    = new_hash;
        new_hash = NULL;
    }
    *hash_len = hash_len_final;

    status = CL_SUCCESS;

done:
    if (NULL != new_hash) {
        free(new_hash);
    }
    if (NULL != ctx) {
        EVP_MD_CTX_free(ctx);
    }
#if OPENSSL_VERSION_MAJOR >= 3
    if (NULL != md) {
        EVP_MD_free(md);
    }
    if (NULL != ossl_ctx) {
        OSSL_LIB_CTX_free(ossl_ctx);
    }
#endif
    return status;
}

/**
 * @brief Initialize a hash context.
 *
 * @param alg               The hash algorithm to use.
 * @param flags             Flags to modify the behavior of the hashing function.
 *                          Use CL_HASH_FLAG_FIPS_BYPASS to bypass FIPS restrictions on which algorithms can be used.
 * @param ctx_out           A pointer to a pointer that will receive the initialized hash context.
 *                          The caller is responsible for freeing this context using cl_hash_destroy_ex().
 * @return cl_error_t       CL_SUCCESS if the hash context was successfully initialized.
 */
extern cl_error_t cl_hash_init_ex(
    const char *alg,
    uint32_t flags,
    cl_hash_ctx_t **ctx_out)
{
    cl_error_t status = CL_ERROR;
    EVP_MD_CTX *ctx   = NULL;

#if OPENSSL_VERSION_MAJOR >= 3
    OSSL_LIB_CTX *ossl_ctx = NULL;
    EVP_MD *md             = NULL;
#else
    const EVP_MD *md = NULL;
#endif

    if (NULL == alg || NULL == ctx_out) {
        cli_errmsg("cl_hash_init_ex: Invalid arguments\n");
        status = CL_ENULLARG;
        goto done;
    }

#if OPENSSL_VERSION_MAJOR >= 3
    if (flags & CL_HASH_FLAG_FIPS_BYPASS) {
        /* Bypass FIPS restrictions the OpenSSL 3.0 way */
        ossl_ctx = OSSL_LIB_CTX_new();
        if (NULL == ossl_ctx) {
            cli_errmsg("cl_hash_data_ex: Failed to create new OpenSSL library context\n");
            status = CL_EMEM;
            goto done;
        }

        md = EVP_MD_fetch(ossl_ctx, to_openssl_alg(alg), "-fips");
    } else {
        /* Use FIPS compliant algorithms */
        md = EVP_MD_fetch(NULL, to_openssl_alg(alg), NULL);
    }
#else
    md = EVP_get_digestbyname(to_openssl_alg(alg));
#endif
    if (NULL == md) {
        cli_errmsg("cl_hash_data_ex: Unsupported hash algorithm: %s\n", alg);
        status = CL_EARG;
        goto done;
    }

    ctx = EVP_MD_CTX_new();
    if (NULL == ctx) {
        cli_errmsg("cl_hash_init_ex: Failed to create EVP_MD_CTX\n");
        status = CL_EMEM;
        goto done;
    }

#ifdef EVP_MD_CTX_FLAG_NON_FIPS_ALLOW
    if (flags & CL_HASH_FLAG_FIPS_BYPASS && OPENSSL_VERSION_NUMBER < 0x30000000L) {
        /* Bypass FIPS restrictions the OpenSSL 1.x way */
        EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
    }
#endif

    if (!EVP_DigestInit_ex(ctx, md, NULL)) {
        cli_errmsg("cl_hash_init_ex: Failed to initialize digest context\n");
        status = CL_EMEM;
        goto done;
    }

    *ctx_out = (cl_hash_ctx_t *)ctx;
    ctx      = NULL; // Ownership of ctx is transferred to the caller

    status = CL_SUCCESS;

done:
    if (NULL != ctx) {
        EVP_MD_CTX_free(ctx);
    }
#if OPENSSL_VERSION_MAJOR >= 3
    if (NULL != md) {
        EVP_MD_free(md);
    }
    if (NULL != ossl_ctx) {
        OSSL_LIB_CTX_free(ossl_ctx);
    }
#endif
    return status;
}

/**
 * @brief Update a hash context with new data.
 *
 * @param ctx               The hash context.
 * @param data              The data to hash.
 * @param length            The size of the data.
 * @return cl_error_t       CL_SUCCESS if the data was successfully added to the hash context.
 *                          CL_E* error code if an error occurred.
 */
extern cl_error_t cl_update_hash_ex(
    cl_hash_ctx_t *ctx,
    const uint8_t *data,
    size_t length)
{
    cl_error_t status = CL_ERROR;
#if defined(_WIN32)
    bool win_exception = false;
#endif

    if (NULL == ctx || NULL == data || length == 0) {
        cli_errmsg("cl_update_hash_ex: Invalid arguments\n");
        status = CL_ENULLARG;
        goto done;
    }

    EXCEPTION_PREAMBLE
    if (!EVP_DigestUpdate((EVP_MD_CTX *)ctx, data, length)) {
        cli_errmsg("cl_update_hash_ex: Failed to update digest context\n");
        status = CL_EMEM;
        goto done;
    }
    EXCEPTION_POSTAMBLE

#if defined(_WIN32)
    if (win_exception) {
        cli_errmsg("cl_update_hash_ex: Exception occurred during hashing\n");
        status = CL_ERROR;
        goto done;
    }
#endif

done:
    return status;
}

/**
 * @brief Finalize a hash context and get the resulting hash.
 *
 * @param ctx               The hash context.
 * @param[inout] hash       A buffer to store the generated hash.
 *                          Set flags to CL_HASH_FLAG_ALLOCATE to dynamically allocate buffer.
 * @param[inout] hash_len   A pointer that stores how long the generated hash is.
 * @param flags             Flags to modify the behavior of the hashing function.
 *                          Use CL_HASH_FLAG_ALLOCATE to dynamically allocate the output buffer.
 *
 * @return cl_error_t       CL_SUCCESS if the hash was successfully finalized.
 *                          CL_E* error code if an error occurred.
 */
extern cl_error_t cl_finish_hash_ex(
    cl_hash_ctx_t *ctx,
    uint8_t **hash,
    size_t *hash_len,
    uint32_t flags)
{
    cl_error_t status = CL_ERROR;

    size_t required_hash_len;
    uint8_t *new_hash = NULL;
    unsigned int hash_len_final;

    if (NULL == ctx || NULL == hash || NULL == hash_len) {
        cli_errmsg("cl_finish_hash_ex: Invalid arguments\n");
        status = CL_ENULLARG;
        goto done;
    }

    required_hash_len = (size_t)EVP_MD_CTX_size((EVP_MD_CTX *)ctx);

    if (flags & CL_HASH_FLAG_ALLOCATE) {
        new_hash = (uint8_t *)malloc(required_hash_len);
        if (new_hash == NULL) {
            cli_errmsg("cl_hash_data_ex: Failed to allocate memory for hash\n");
            status = CL_EMEM;
            goto done;
        }
    } else {
        if (*hash_len < required_hash_len) {
            cli_errmsg("cl_hash_data_ex: Provided hash buffer is too small. Provided bytes: %zu, Required bytes: %zu\n", *hash_len, required_hash_len);
            status = CL_EARG;
            goto done;
        }
        new_hash = *hash;
    }

    if (!EVP_DigestFinal_ex((EVP_MD_CTX *)ctx, new_hash, &hash_len_final)) {
        cli_errmsg("cl_hash_data_ex: Failed to finalize digest context\n");
        status = CL_EMEM;
        goto done;
    }

    if (flags & CL_HASH_FLAG_ALLOCATE) {
        // give up ownership of the new hash buffer
        *hash    = new_hash;
        new_hash = NULL;
    }
    *hash_len = hash_len_final;

    status = CL_SUCCESS;

done:
    if (NULL != ctx) {
        EVP_MD_CTX_free((EVP_MD_CTX *)ctx);
    }
    return status;
}

/**
 * @brief Destroy a hash context.
 *
 * @param ctx   The hash context.
 */
extern void cl_hash_destroy_ex(cl_hash_ctx_t *ctx)
{
    if (ctx) {
        EVP_MD_CTX_free((EVP_MD_CTX *)ctx);
    }
}

/**
 * @brief Generate a hash of a file.
 *
 * @param alg               The hashing algorithm to use.
 * @param fd                The file descriptor.
 * @param offset            The offset in the file to start hashing from.
 * @param length            The length of the data to hash. If 0, the entire file will be hashed.
 * @param[inout] hash       A buffer to store the generated hash.
 *                          Set flags to CL_HASH_FLAG_ALLOCATE to dynamically allocate buffer.
 * @param[inout] hash_len   A pointer that stores how long the generated hash is.
 * @param flags             Flags to modify the behavior of the hashing function.
 *                          Use CL_HASH_FLAG_ALLOCATE to dynamically allocate the output buffer.
 *                          Use CL_HASH_FLAG_FIPS_BYPASS to bypass FIPS restrictions on which algorithms can be used.
 *
 * @return cl_error_t       CL_SUCCESS if the hash was generated successfully.
 */
extern cl_error_t cl_hash_file_fd_ex(
    const char *alg,
    int fd,
    size_t offset,
    size_t length,
    uint8_t **hash,
    size_t *hash_len,
    uint32_t flags)
{
    cl_error_t status = CL_ERROR;

    STATBUF sb;

    EVP_MD_CTX *ctx = NULL;

#if OPENSSL_VERSION_MAJOR >= 3
    OSSL_LIB_CTX *ossl_ctx = NULL;
    EVP_MD *md             = NULL;
#else
    const EVP_MD *md = NULL;
#endif

    size_t required_hash_len;
    uint8_t *new_hash = NULL;
    unsigned int hash_len_final;

#if defined(_WIN32)
    bool win_exception = false;
#endif

    uint8_t *block = NULL;

#ifdef _WIN32
    unsigned int blocksize = 8192;
    int nread;
#else
    size_t blocksize;
    ssize_t nread;
#endif
    size_t byte_read = 0;

    if (NULL == alg || -1 == fd || NULL == hash || NULL == hash_len) {
        cli_errmsg("cl_hash_data_ex: Invalid arguments\n");
        status = CL_ENULLARG;
        goto done;
    }

#ifndef _WIN32
    if (fstat(fd, &sb) < 0) {
        cli_errmsg("cl_hash_data_ex: Failed to stat file descriptor %d: %s\n", fd, cl_strerror(CL_ESTAT));
        status = CL_ESTAT;
        goto done;
    }

    blocksize = sb.st_blksize;
#endif

    block = (uint8_t *)malloc(blocksize);
    if (NULL == block) {
        cli_errmsg("cl_hash_data_ex: Failed to allocate memory for block buffer\n");
        status = CL_EMEM;
        goto done;
    }

#if OPENSSL_VERSION_MAJOR >= 3
    if (flags & CL_HASH_FLAG_FIPS_BYPASS) {
        /* Bypass FIPS restrictions the OpenSSL 3.0 way */
        ossl_ctx = OSSL_LIB_CTX_new();
        if (NULL == ossl_ctx) {
            cli_errmsg("cl_hash_data_ex: Failed to create new OpenSSL library context\n");
            status = CL_EMEM;
            goto done;
        }

        md = EVP_MD_fetch(ossl_ctx, to_openssl_alg(alg), "-fips");
    } else {
        /* Use FIPS compliant algorithms */
        md = EVP_MD_fetch(NULL, to_openssl_alg(alg), NULL);
    }
#else
    md = EVP_get_digestbyname(to_openssl_alg(alg));
#endif
    if (NULL == md) {
        cli_errmsg("cl_hash_data_ex: Unsupported hash algorithm: %s\n", alg);
        status = CL_EARG;
        goto done;
    }

    required_hash_len = (size_t)EVP_MD_size(md);

    if (flags & CL_HASH_FLAG_ALLOCATE) {
        new_hash = (uint8_t *)malloc(required_hash_len);
        if (new_hash == NULL) {
            cli_errmsg("cl_hash_data_ex: Failed to allocate memory for hash\n");
            status = CL_EMEM;
            goto done;
        }
    } else {
        if (*hash_len < required_hash_len) {
            cli_errmsg("cl_hash_data_ex: Provided hash buffer for '%s' is too small. Provided bytes: %zu, Required bytes: %zu\n", alg, *hash_len, required_hash_len);
            status = CL_EARG;
            goto done;
        }
        new_hash = *hash;
    }

    ctx = EVP_MD_CTX_new();
    if (NULL == ctx) {
        cli_errmsg("cl_hash_data_ex: Failed to create EVP_MD_CTX\n");
        status = CL_EMEM;
        goto done;
    }

#ifdef EVP_MD_CTX_FLAG_NON_FIPS_ALLOW
    if (flags & CL_HASH_FLAG_FIPS_BYPASS && OPENSSL_VERSION_NUMBER < 0x30000000L) {
        /* Bypass FIPS restrictions the OpenSSL 1.x way */
        EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
    }
#endif

    if (!EVP_DigestInit_ex(ctx, md, NULL)) {
        cli_errmsg("cl_hash_data_ex: Failed to initialize digest context\n");
        status = CL_EMEM;
        goto done;
    }

    if (lseek(fd, offset, SEEK_SET) == (off_t)-1) {
        cli_errmsg("cl_hash_data_ex: Failed to seek to offset %zu: %s\n", offset, cl_strerror(CL_ESEEK));
        status = CL_ESEEK;
        goto done;
    }

    do {
        blocksize = MIN(blocksize, length - byte_read);

#ifdef _WIN32
        nread = _read(fd, block, blocksize);
#else
        nread = read(fd, block, blocksize);
#endif
        if (nread < 0) {
            cli_errmsg("cl_hash_data_ex: Failed to read from file descriptor %d: %s\n", fd, cl_strerror(CL_EREAD));
            status = CL_EREAD;
            goto done;
        } else if (nread == 0) {
            // End of file reached
            break;
        }

        if (SIZE_MAX - (size_t)nread < byte_read) {
            // Potential overflow
            cli_errmsg("cl_hash_data_ex: Potential overflow detected\n");
            status = CL_EREAD;
            goto done;
        }

        byte_read += nread;

        EXCEPTION_PREAMBLE
        if (!EVP_DigestUpdate(ctx, (const void *)block, nread)) {
            cli_errmsg("cl_hash_data_ex: Failed to update digest context\n");
            status = CL_EMEM;
            goto done;
        }
        EXCEPTION_POSTAMBLE

#if defined(_WIN32)
        if (win_exception) {
            cli_errmsg("cl_hash_data_ex: Exception occurred during hashing\n");
            status = CL_ERROR;
            goto done;
        }
#endif
    } while (true);

    if (!EVP_DigestFinal_ex(ctx, new_hash, &hash_len_final)) {
        cli_errmsg("cl_hash_data_ex: Failed to finalize digest context\n");
        status = CL_EMEM;
        goto done;
    }

    if (flags & CL_HASH_FLAG_ALLOCATE) {
        // give up ownership of the new hash buffer
        *hash    = new_hash;
        new_hash = NULL;
    }
    *hash_len = hash_len_final;

    status = CL_SUCCESS;

done:
    if (NULL != block) {
        free(block);
    }
    if (NULL != new_hash) {
        free(new_hash);
    }
    if (NULL != ctx) {
        EVP_MD_CTX_free(ctx);
    }
#if OPENSSL_VERSION_MAJOR >= 3
    if (NULL != md) {
        EVP_MD_free(md);
    }
    if (NULL != ossl_ctx) {
        OSSL_LIB_CTX_free(ossl_ctx);
    }
#endif
    return status;
}

unsigned char *cl_hash_data(const char *alg, const void *buf, size_t len, unsigned char *obuf, unsigned int *olen)
{
    EVP_MD_CTX *ctx;
    unsigned char *ret;
    size_t mdsz;

#if OPENSSL_VERSION_MAJOR >= 3
    OSSL_LIB_CTX *ossl_ctx = NULL;
    EVP_MD *md             = NULL;
#else
    const EVP_MD *md = NULL;
#endif

    unsigned int i;
    size_t cur;
#if defined(_WIN32)
    bool win_exception = false;
#endif

#if OPENSSL_VERSION_MAJOR >= 3
    /* Bypass FIPS restrictions the OpenSSL 3.0 way */
    ossl_ctx = OSSL_LIB_CTX_new();
    if (NULL == ossl_ctx) {
        cli_errmsg("cl_hash_data_ex: Failed to create new OpenSSL library context\n");
        return NULL;
    }

    md = EVP_MD_fetch(ossl_ctx, to_openssl_alg(alg), "-fips");
#else
    md = EVP_get_digestbyname(to_openssl_alg(alg));
#endif
    if (!(md))
        return NULL;

    mdsz = EVP_MD_size(md);

    ret = (obuf != NULL) ? obuf : (unsigned char *)malloc(mdsz);
    if (!(ret)) {
#if OPENSSL_VERSION_MAJOR >= 3
        EVP_MD_free(md);
        OSSL_LIB_CTX_free(ossl_ctx);
#endif
        return NULL;
    }

    ctx = EVP_MD_CTX_create();
    if (!(ctx)) {
        if (!(obuf))
            free(ret);

#if OPENSSL_VERSION_MAJOR >= 3
        EVP_MD_free(md);
        OSSL_LIB_CTX_free(ossl_ctx);
#endif
        return NULL;
    }

#ifdef EVP_MD_CTX_FLAG_NON_FIPS_ALLOW
    if (OPENSSL_VERSION_NUMBER < 0x30000000L) {
        /* Bypass FIPS restrictions the OpenSSL 1.x way */
        EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
    }
#endif

    if (!EVP_DigestInit_ex(ctx, md, NULL)) {
        if (!(obuf))
            free(ret);

        if ((olen))
            *olen = 0;

#if OPENSSL_VERSION_MAJOR >= 3
        EVP_MD_free(md);
        OSSL_LIB_CTX_free(ossl_ctx);
#endif
        EVP_MD_CTX_destroy(ctx);
        return NULL;
    }

    cur = 0;
    while (cur < len) {
        size_t todo = MIN((unsigned long)EVP_MD_block_size(md), (unsigned long)(len - cur));

        EXCEPTION_PREAMBLE
        if (!EVP_DigestUpdate(ctx, (void *)(((unsigned char *)buf) + cur), todo)) {
            if (!(obuf))
                free(ret);

            if ((olen))
                *olen = 0;

#if OPENSSL_VERSION_MAJOR >= 3
            EVP_MD_free(md);
            OSSL_LIB_CTX_free(ossl_ctx);
#endif
            EVP_MD_CTX_destroy(ctx);
            return NULL;
        }
        EXCEPTION_POSTAMBLE

#if defined(_WIN32)
        if (win_exception) {
            if (!(obuf))
                free(ret);

            if ((olen))
                *olen = 0;

#if OPENSSL_VERSION_MAJOR >= 3
            EVP_MD_free(md);
            OSSL_LIB_CTX_free(ossl_ctx);
#endif
            EVP_MD_CTX_destroy(ctx);
            return NULL;
        }
#endif

        cur += todo;
    }

    if (!EVP_DigestFinal_ex(ctx, ret, &i)) {
        if (!(obuf))
            free(ret);

        if ((olen))
            *olen = 0;

#if OPENSSL_VERSION_MAJOR >= 3
        EVP_MD_free(md);
        OSSL_LIB_CTX_free(ossl_ctx);
#endif
        EVP_MD_CTX_destroy(ctx);
        return NULL;
    }

#if OPENSSL_VERSION_MAJOR >= 3
    EVP_MD_free(md);
    OSSL_LIB_CTX_free(ossl_ctx);
#endif
    EVP_MD_CTX_destroy(ctx);

    if ((olen))
        *olen = i;

    return ret;
}

unsigned char *cl_hash_file_fd(int fd, const char *alg, unsigned int *olen)
{
    EVP_MD_CTX *ctx;

#if OPENSSL_VERSION_MAJOR >= 3
    OSSL_LIB_CTX *ossl_ctx = NULL;
    EVP_MD *md             = NULL;
#else
    const EVP_MD *md = NULL;
#endif

    unsigned char *res;

#if OPENSSL_VERSION_MAJOR >= 3
    /* Bypass FIPS restrictions the OpenSSL 3.0 way */
    ossl_ctx = OSSL_LIB_CTX_new();
    if (NULL == ossl_ctx) {
        cli_errmsg("cl_hash_data_ex: Failed to create new OpenSSL library context\n");
        return NULL;
    }

    md = EVP_MD_fetch(ossl_ctx, to_openssl_alg(alg), "-fips");
#else
    md = EVP_get_digestbyname(to_openssl_alg(alg));
#endif
    if (!(md))
        return NULL;

    ctx = EVP_MD_CTX_new();
    if (!(ctx)) {
#if OPENSSL_VERSION_MAJOR >= 3
        EVP_MD_free(md);
        OSSL_LIB_CTX_free(ossl_ctx);
#endif
        return NULL;
    }

#ifdef EVP_MD_CTX_FLAG_NON_FIPS_ALLOW
    if (OPENSSL_VERSION_NUMBER < 0x30000000L) {
        /* Bypass FIPS restrictions the OpenSSL 1.x way */
        EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
    }
#endif

    if (!EVP_DigestInit_ex(ctx, md, NULL)) {
#if OPENSSL_VERSION_MAJOR >= 3
        EVP_MD_free(md);
        OSSL_LIB_CTX_free(ossl_ctx);
#endif
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    res = cl_hash_file_fd_ctx(ctx, fd, olen);
#if OPENSSL_VERSION_MAJOR >= 3
    EVP_MD_free(md);
    OSSL_LIB_CTX_free(ossl_ctx);
#endif
    EVP_MD_CTX_free(ctx);

    return res;
}

unsigned char *cl_hash_file_fd_ctx(EVP_MD_CTX *ctx, int fd, unsigned int *olen)
{
    uint8_t *buf;
    uint8_t *hash;
    int mdsz;
    unsigned int hashlen;
    STATBUF sb;
#if defined(_WIN32)
    bool win_exception = false;
#endif

    unsigned int blocksize;

#ifdef _WIN32
    int nread;
#else
    ssize_t nread;
#endif

    mdsz = EVP_MD_CTX_size(ctx);

    if (FSTAT(fd, &sb) < 0) {
        return NULL;
    }

#ifdef _WIN32
    blocksize = 8192;
#else
    blocksize = sb.st_blksize;
#endif

    buf = (uint8_t *)malloc(blocksize);
    if (!(buf)) {
        return NULL;
    }

    hash = (uint8_t *)malloc(mdsz);
    if (!(hash)) {
        free(buf);
        return NULL;
    }

#ifdef _WIN32
    while ((nread = _read(fd, buf, blocksize)) > 0) {
#else
    while ((nread = read(fd, buf, blocksize)) > 0) {
#endif
        EXCEPTION_PREAMBLE
        if (!EVP_DigestUpdate(ctx, buf, nread)) {
            free(buf);
            free(hash);

            return NULL;
        }
        EXCEPTION_POSTAMBLE

#if defined(_WIN32)
        if (win_exception) {
            free(buf);
            free(hash);

            return NULL;
        }
#endif
    }

    if (!EVP_DigestFinal_ex(ctx, hash, &hashlen)) {
        free(hash);
        free(buf);

        return NULL;
    }

    if ((olen))
        *olen = hashlen;

    free(buf);

    return hash;
}

unsigned char *cl_hash_file_fp(FILE *fp, const char *alg, unsigned int *olen)
{
    return cl_hash_file_fd(fileno(fp), alg, olen);
}

unsigned char *cl_sha512(const void *buf, size_t len, unsigned char *obuf, unsigned int *olen)
{
    return cl_hash_data("sha2-512", buf, len, obuf, olen);
}

unsigned char *cl_sha384(const void *buf, size_t len, unsigned char *obuf, unsigned int *olen)
{
    return cl_hash_data("sha2-384", buf, len, obuf, olen);
}

unsigned char *cl_sha256(const void *buf, size_t len, unsigned char *obuf, unsigned int *olen)
{
    return cl_hash_data("sha2-256", buf, len, obuf, olen);
}

unsigned char *cl_sha1(const void *buf, size_t len, unsigned char *obuf, unsigned int *olen)
{
    return cl_hash_data("sha1", buf, len, obuf, olen);
}

int cl_verify_signature_hash(EVP_PKEY *pkey, const char *alg, unsigned char *sig, unsigned int siglen, unsigned char *digest)
{
    EVP_MD_CTX *ctx;
    const EVP_MD *md;
    size_t mdsz;

    md = EVP_get_digestbyname(to_openssl_alg(alg));
    if (!(md))
        return -1;

    ctx = EVP_MD_CTX_new();
    if (!(ctx))
        return -1;

    mdsz = EVP_MD_size(md);

    if (!EVP_VerifyInit_ex(ctx, md, NULL)) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (!EVP_VerifyUpdate(ctx, digest, mdsz)) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (EVP_VerifyFinal(ctx, sig, siglen, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return 0;
}

int cl_verify_signature_fd(EVP_PKEY *pkey, const char *alg, unsigned char *sig, unsigned int siglen, int fd)
{
    EVP_MD_CTX *ctx;
    const EVP_MD *md;
    size_t mdsz;
    uint8_t *digest;

    digest = cl_hash_file_fd(fd, alg, NULL);
    if (!(digest))
        return -1;

    md = EVP_get_digestbyname(to_openssl_alg(alg));
    if (!(md)) {
        free(digest);
        return -1;
    }

    mdsz = EVP_MD_size(md);

    ctx = EVP_MD_CTX_new();
    if (!(ctx)) {
        free(digest);
        return -1;
    }

    if (!EVP_VerifyInit_ex(ctx, md, NULL)) {
        free(digest);
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (!EVP_VerifyUpdate(ctx, digest, mdsz)) {
        free(digest);
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (EVP_VerifyFinal(ctx, sig, siglen, pkey) <= 0) {
        free(digest);
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    free(digest);
    EVP_MD_CTX_free(ctx);
    return 0;
}

int cl_verify_signature(EVP_PKEY *pkey, const char *alg, unsigned char *sig, unsigned int siglen, unsigned char *data, size_t datalen, int decode)
{
    EVP_MD_CTX *ctx;
    const EVP_MD *md;
    size_t mdsz;
    unsigned char *digest;

    if (decode) {
        unsigned char *newsig;
        size_t newsiglen;

        newsig = (unsigned char *)cl_base64_decode((char *)sig, siglen, NULL, &newsiglen, 1);
        if (!(newsig))
            return -1;

        sig    = newsig;
        siglen = newsiglen;
    }

    digest = cl_hash_data(alg, data, datalen, NULL, NULL);
    if (!(digest)) {
        if (decode)
            free(sig);

        return -1;
    }

    md = EVP_get_digestbyname(to_openssl_alg(alg));
    if (!(md)) {
        free(digest);
        if (decode)
            free(sig);

        return -1;
    }

    mdsz = EVP_MD_size(md);

    ctx = EVP_MD_CTX_new();
    if (!(ctx)) {
        free(digest);
        if (decode)
            free(sig);

        return -1;
    }

    if (!EVP_VerifyInit_ex(ctx, md, NULL)) {
        free(digest);
        if (decode)
            free(sig);

        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (!EVP_VerifyUpdate(ctx, digest, mdsz)) {
        free(digest);
        if (decode)
            free(sig);

        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (EVP_VerifyFinal(ctx, sig, siglen, pkey) <= 0) {
        free(digest);
        if (decode)
            free(sig);

        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (decode)
        free(sig);

    free(digest);
    EVP_MD_CTX_free(ctx);
    return 0;
}

int cl_verify_signature_hash_x509_keyfile(char *x509path, const char *alg, unsigned char *sig, unsigned int siglen, unsigned char *digest)
{
    X509 *x509;
    FILE *fp;
    int res;

    fp = fopen(x509path, "r");
    if (!(fp)) {
        return -1;
    }

    x509 = PEM_read_X509(fp, NULL, NULL, NULL);
    if (!(x509)) {
        fclose(fp);
        return -1;
    }

    fclose(fp);

    res = cl_verify_signature_hash_x509(x509, alg, sig, siglen, digest);

    X509_free(x509);

    return res;
}

int cl_verify_signature_fd_x509_keyfile(char *x509path, const char *alg, unsigned char *sig, unsigned int siglen, int fd)
{
    X509 *x509;
    FILE *fp;
    int res;

    fp = fopen(x509path, "r");
    if (!(fp)) {
        return -1;
    }

    x509 = PEM_read_X509(fp, NULL, NULL, NULL);
    if (!(x509)) {
        fclose(fp);
        return -1;
    }

    fclose(fp);

    res = cl_verify_signature_fd_x509(x509, alg, sig, siglen, fd);

    X509_free(x509);

    return res;
}

int cl_verify_signature_x509_keyfile(char *x509path, const char *alg, unsigned char *sig, unsigned int siglen, unsigned char *data, size_t datalen, int decode)
{
    X509 *x509;
    FILE *fp;
    int res;

    fp = fopen(x509path, "r");
    if (!(fp)) {
        return -1;
    }

    x509 = PEM_read_X509(fp, NULL, NULL, NULL);
    if (!(x509)) {
        fclose(fp);
        return -1;
    }

    fclose(fp);

    res = cl_verify_signature_x509(x509, alg, sig, siglen, data, datalen, decode);

    X509_free(x509);

    return res;
}

int cl_verify_signature_hash_x509(X509 *x509, const char *alg, unsigned char *sig, unsigned int siglen, unsigned char *digest)
{
    EVP_PKEY *pkey;
    int res;

    pkey = X509_get_pubkey(x509);
    if (!(pkey))
        return -1;

    res = cl_verify_signature_hash(pkey, alg, sig, siglen, digest);

    EVP_PKEY_free(pkey);

    return res;
}

int cl_verify_signature_fd_x509(X509 *x509, const char *alg, unsigned char *sig, unsigned int siglen, int fd)
{
    EVP_PKEY *pkey;
    int res;

    pkey = X509_get_pubkey(x509);
    if (!(pkey))
        return -1;

    res = cl_verify_signature_fd(pkey, alg, sig, siglen, fd);

    EVP_PKEY_free(pkey);

    return res;
}

int cl_verify_signature_x509(X509 *x509, const char *alg, unsigned char *sig, unsigned int siglen, unsigned char *data, size_t datalen, int decode)
{
    EVP_PKEY *pkey;
    int res;

    pkey = X509_get_pubkey(x509);
    if (!(pkey))
        return -1;

    res = cl_verify_signature(pkey, alg, sig, siglen, data, datalen, decode);

    EVP_PKEY_free(pkey);

    return res;
}

unsigned char *cl_sign_data_keyfile(char *keypath, const char *alg, unsigned char *hash, unsigned int *olen, int encode)
{
    FILE *fp;
    EVP_PKEY *pkey;
    unsigned char *res;

    fp = fopen(keypath, "r");
    if (!(fp)) {
        return NULL;
    }

    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (!(pkey)) {
        fclose(fp);
        return NULL;
    }

    fclose(fp);

    res = cl_sign_data(pkey, alg, hash, olen, encode);

    EVP_PKEY_free(pkey);

    return res;
}

unsigned char *cl_sign_data(EVP_PKEY *pkey, const char *alg, unsigned char *hash, unsigned int *olen, int encode)
{
    EVP_MD_CTX *ctx;
    const EVP_MD *md;
    unsigned int siglen;
    unsigned char *sig;

    md = EVP_get_digestbyname(to_openssl_alg(alg));
    if (!(md))
        return NULL;

    ctx = EVP_MD_CTX_new();
    if (!(ctx))
        return NULL;

    sig = (unsigned char *)calloc(1, EVP_PKEY_size(pkey));
    if (!(sig)) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    if (!EVP_SignInit_ex(ctx, md, NULL)) {
        free(sig);
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    if (!EVP_SignUpdate(ctx, hash, EVP_MD_size(md))) {
        free(sig);
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    if (!EVP_SignFinal(ctx, sig, &siglen, pkey)) {
        free(sig);
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    if (encode) {
        unsigned char *newsig = (unsigned char *)cl_base64_encode(sig, siglen);
        if (!(newsig)) {
            free(sig);
            EVP_MD_CTX_free(ctx);
            return NULL;
        }

        free(sig);
        sig    = newsig;
        siglen = (unsigned int)strlen((const char *)newsig);
    }

    *olen = siglen;
    EVP_MD_CTX_free(ctx);
    return sig;
}

unsigned char *cl_sign_file_fd(int fd, EVP_PKEY *pkey, const char *alg, unsigned int *olen, int encode)
{
    uint8_t *hash, *res;
    unsigned int hashlen;

    hash = cl_hash_file_fd(fd, alg, &hashlen);
    if (!(hash)) {
        return NULL;
    }

    res = cl_sign_data(pkey, alg, hash, olen, encode);

    free(hash);
    return res;
}

unsigned char *cl_sign_file_fp(FILE *fp, EVP_PKEY *pkey, const char *alg, unsigned int *olen, int encode)
{
    return cl_sign_file_fd(fileno(fp), pkey, alg, olen, encode);
}

EVP_PKEY *cl_get_pkey_file(char *keypath)
{
    EVP_PKEY *pkey;
    FILE *fp;

    fp = fopen(keypath, "r");
    if (!(fp))
        return NULL;

    if (!(pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL))) {
        fclose(fp);
        return NULL;
    }

    fclose(fp);

    return pkey;
}

X509 *cl_get_x509_from_mem(void *data, unsigned int len)
{
    X509 *cert;
    BIO *cbio;

    cbio = BIO_new_mem_buf(data, len);
    if (!(cbio))
        return NULL;

    cert = PEM_read_bio_X509(cbio, NULL, 0, NULL);
    BIO_free(cbio);

    return cert;
}

int cl_validate_certificate_chain_ts_dir(char *tsdir, char *certpath)
{
    char **authorities = NULL, **t;
    size_t nauths      = 0;
    int res;
    DIR *dp;
    struct dirent *dirent;

    dp = opendir(tsdir);
    if (!(dp))
        return CL_EOPEN;

    while ((dirent = readdir(dp))) {
        if (dirent->d_name[0] == '.')
            continue;

        if (!cli_strbcasestr(dirent->d_name, ".crt"))
            continue;

        t = (char **)realloc(authorities, sizeof(char **) * (nauths + 1));
        if (!(t)) {
            if (nauths) {
                while (nauths > 0)
                    free(authorities[--nauths]);
                free(authorities);
            }

            closedir(dp);
            return -1;
        }

        authorities         = t;
        authorities[nauths] = (char *)malloc(strlen(tsdir) + strlen(dirent->d_name) + 2);
        if (!authorities[nauths]) {
            if (nauths) {
                while (nauths > 0)
                    free(authorities[nauths--]);
                free(authorities[0]);
            }

            free(authorities);
            closedir(dp);
            return -1;
        }

        sprintf(authorities[nauths], "%s" PATHSEP "%s", tsdir, dirent->d_name);
        nauths++;
    }

    closedir(dp);

    t = (char **)realloc(authorities, sizeof(char **) * (nauths + 1));
    if (!(t)) {
        if (nauths) {
            while (nauths > 0)
                free(authorities[--nauths]);
            free(authorities);
        }

        return -1;
    }

    authorities         = t;
    authorities[nauths] = NULL;

    res = cl_validate_certificate_chain(authorities, NULL, certpath);

    while (nauths > 0)
        free(authorities[--nauths]);

    free(authorities);

    return res;
}

int cl_validate_certificate_chain(char **authorities, char *crlpath, char *certpath)
{
    X509_STORE *store = NULL;
    X509_STORE_CTX *store_ctx;
    X509_LOOKUP *lookup      = NULL;
    X509_CRL *crl            = NULL;
    X509_VERIFY_PARAM *param = NULL;
    X509 *cert;
    unsigned long i;
    int res;

    store = X509_STORE_new();
    if (!(store)) {
        return -1;
    }
    X509_STORE_set_flags(store, 0);

    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (!(lookup)) {
        X509_STORE_free(store);
        return -1;
    }

    if ((crlpath)) {

        crl = cl_load_crl(crlpath);
        if (!(crl)) {
            X509_STORE_free(store);
            return -1;
        }

        X509_STORE_add_crl(store, crl);
        param = X509_VERIFY_PARAM_new();
        if ((param)) {
            X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK);
            X509_STORE_set1_param(store, param);
        } else {
            X509_STORE_free(store);
            X509_CRL_free(crl);
            return -1;
        }
    }

    /* Support multi-tiered setups */
    for (i = 0; authorities[i]; i++) {
        if (!X509_LOOKUP_load_file(lookup, authorities[i], X509_FILETYPE_PEM)) {
            X509_STORE_free(store);
            if ((crl))
                X509_CRL_free(crl);
            if ((param))
                X509_VERIFY_PARAM_free(param);
            return -1;
        }
    }

    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
    if (!(lookup)) {
        X509_STORE_free(store);
        if ((crl))
            X509_CRL_free(crl);
        if ((param))
            X509_VERIFY_PARAM_free(param);
        return -1;
    }

    X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);

    store_ctx = X509_STORE_CTX_new();
    if (!(store_ctx)) {
        X509_STORE_free(store);
        if ((crl))
            X509_CRL_free(crl);
        if ((param))
            X509_VERIFY_PARAM_free(param);
        return -1;
    }

    cert = cl_load_cert(certpath);
    if (!(cert)) {
        X509_STORE_CTX_free(store_ctx);
        X509_STORE_free(store);
        if ((crl))
            X509_CRL_free(crl);
        if ((param))
            X509_VERIFY_PARAM_free(param);

        return -1;
    }

    if (!X509_STORE_CTX_init(store_ctx, store, cert, NULL)) {
        X509_STORE_CTX_free(store_ctx);
        X509_STORE_free(store);
        if ((crl))
            X509_CRL_free(crl);
        if ((param))
            X509_VERIFY_PARAM_free(param);

        X509_free(cert);

        return -1;
    }

    res = X509_verify_cert(store_ctx);

    X509_STORE_CTX_free(store_ctx);
    if ((crl))
        X509_CRL_free(crl);

    if ((param))
        X509_VERIFY_PARAM_free(param);

    X509_STORE_free(store);

    X509_free(cert);

    return (res > 0);
}

X509 *cl_load_cert(const char *certpath)
{
    X509 *cert;
    BIO *bio;

    bio = BIO_new(BIO_s_file());
    if (!(bio))
        return NULL;

    if (BIO_read_filename(bio, certpath) != 1) {
        BIO_free(bio);
        return NULL;
    }

    cert = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);

    BIO_free(bio);

    return cert;
}

struct tm *cl_ASN1_GetTimeT(ASN1_TIME *timeobj)
{
    struct tm *t;
    char *str;
    const char *fmt = NULL;
    time_t localt;
#ifdef _WIN32
    struct tm localtm, *ltm;
#else
    struct tm localtm;
#endif

    if (!(timeobj) || !(timeobj->data))
        return NULL;

    str = (char *)(timeobj->data);
    if (strlen(str) < 12)
        return NULL;

    t = (struct tm *)calloc(1, sizeof(struct tm));
    if (!(t))
        return NULL;

    if (timeobj->type == V_ASN1_UTCTIME) {
        /* two digit year */
        fmt = "%y%m%d%H%M%S";
        if (str[3] == '0') {
            str[2] = '0';
            str[3] = '9';
        } else {
            str[3]--;
        }
    } else if (timeobj->type == V_ASN1_GENERALIZEDTIME) {
        /* four digit year */
        fmt = "%Y%m%d%H%M%S";
        if (str[5] == '0') {
            str[4] = '0';
            str[5] = '9';
        } else {
            str[5]--;
        }
    }

    if (!(fmt)) {
        free(t);
        return NULL;
    }

    if (!strptime(str, fmt, t)) {
        free(t);
        return NULL;
    }

    /* Convert to local time */
    localt = time(NULL);
#ifdef _WIN32
    ltm = localtime(&localt);
    memcpy((void *)(&localtm), (void *)ltm, sizeof(struct tm));
#else
    localtime_r(&localt, &localtm);
#endif
    t->tm_isdst = localtm.tm_isdst;
    return t;
}

X509_CRL *cl_load_crl(const char *file)
{
    X509_CRL *x = NULL;
    FILE *fp;

    if (!(file))
        return NULL;

    fp = fopen(file, "r");
    if (!(fp))
        return NULL;

    x = PEM_read_X509_CRL(fp, NULL, NULL, NULL);

    fclose(fp);

    if ((x)) {
        const ASN1_TIME *tme;

        tme = X509_CRL_get0_nextUpdate(x);
        if (!tme || X509_cmp_current_time(tme) < 0) {
            X509_CRL_free(x);
            return NULL;
        }
    }

    return x;
}

void *cl_hash_init(const char *alg)
{
    EVP_MD_CTX *ctx;

#if OPENSSL_VERSION_MAJOR >= 3
    OSSL_LIB_CTX *ossl_ctx = NULL;
    EVP_MD *md             = NULL;
#else
    const EVP_MD *md = NULL;
#endif

#if OPENSSL_VERSION_MAJOR >= 3
    /* Bypass FIPS restrictions the OpenSSL 3.0 way */
    ossl_ctx = OSSL_LIB_CTX_new();
    if (NULL == ossl_ctx) {
        cli_errmsg("cl_hash_data_ex: Failed to create new OpenSSL library context\n");
        return NULL;
    }

    md = EVP_MD_fetch(ossl_ctx, to_openssl_alg(alg), "-fips");
#else
    md = EVP_get_digestbyname(to_openssl_alg(alg));
#endif
    if (!(md))
        return NULL;

    ctx = EVP_MD_CTX_new();
    if (!(ctx)) {
#if OPENSSL_VERSION_MAJOR >= 3
        EVP_MD_free(md);
        OSSL_LIB_CTX_free(ossl_ctx);
#endif
        return NULL;
    }

#ifdef EVP_MD_CTX_FLAG_NON_FIPS_ALLOW
    if (OPENSSL_VERSION_NUMBER < 0x30000000L) {
        /* Bypass FIPS restrictions the OpenSSL 1.x way */
        EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
    }
#endif

    if (!EVP_DigestInit_ex(ctx, md, NULL)) {
#if OPENSSL_VERSION_MAJOR >= 3
        EVP_MD_free(md);
        OSSL_LIB_CTX_free(ossl_ctx);
#endif
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

#if OPENSSL_VERSION_MAJOR >= 3
    EVP_MD_free(md);
    OSSL_LIB_CTX_free(ossl_ctx);
#endif
    return (void *)ctx;
}

int cl_update_hash(void *ctx, const void *data, size_t sz)
{
#if defined(_WIN32)
    bool win_exception = false;
#endif

    if (!(ctx) || !(data))
        return -1;

    EXCEPTION_PREAMBLE
    if (!EVP_DigestUpdate((EVP_MD_CTX *)ctx, data, sz))
        return -1;
    EXCEPTION_POSTAMBLE

#if defined(_WIN32)
    if (win_exception) {
        return -1;
    }
#endif

    return 0;
}

int cl_finish_hash(void *ctx, void *buf)
{
    int res = 0;

    if (!(ctx) || !(buf))
        return -1;

    if (!EVP_DigestFinal_ex((EVP_MD_CTX *)ctx, (unsigned char *)buf, NULL))
        res = -1;

    EVP_MD_CTX_free((EVP_MD_CTX *)ctx);

    return res;
}

void cl_hash_destroy(void *ctx)
{
    if (!(ctx))
        return;

    EVP_MD_CTX_free((EVP_MD_CTX *)ctx);
}
