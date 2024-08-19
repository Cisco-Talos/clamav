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
#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <openssl/opensslv.h>
#include <openssl/param_build.h>
#include <openssl/err.h>

// These are the public key components for the external signature
// Ideally these should be packaged in a way that allows individual entites
// to use their own keys if they should so desire.
#define CLI_NSTR_EXT_SIG "E32B3AC1D501EE975296A45BA65DD699100DADD340FF3BBD1F1030C66D6BB16DBFBD53DF4D97BBD42EF8FC777E7C114A6074A87DD8095A5C08B3DD7B85817713047647EF396C58358C5C22B5C3ADF85CE8D0ABC429F89E936EC917B64DD00E02A712E6666FAE1A71591092BCEE59E3141758C4719B4B08589117B0FF7CDBDBB261F8486A193E2E720AE0B16D40DD5E56E97346CBD8010DC81B35332F41C9E93E61490802DDCDFC823D581BA6888588968C68A3C95B93949AF411682E73323F7469473F668B0958F6966849FF03BDE808866D127A2C058B16F17C741A9EE50812A5C7841224E55BF7ADDB5AEAE8EB5476F9BC8740178AB35926D5DC375583C641"
#define CLI_ESTR_EXT_SIG "010001"

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
        winres = 1;                                                         \
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
 * This variable determines if we are operating in FIPS mode, default to no.
  */
int cli_fips_mode = 0;

/**
 * @brief This function determines if we are running in FIPS mode and sets the cl_fips_mode variable
 * 
 * This function is called by cl_init() and does not need to be called by the user
 * 
 * @return int Returns 1 if we are running in FIPS mode, 0 otherwise
 * 
 */

void cli_setup_fips_configuration(void)
{
    #if OPENSSL_VERSION_MAJOR == 1
    // OpenSSL 1.x (1.0 or 1.1)
    #ifdef OPENSSL_FIPS
        if (FIPS_mode()) {
            cli_infomsg_simple("cl_setup_fips_configuration: FIPS mode provider found.\n");
            cl_fips_mode = 1;
        } else {
            cli_infomsg_simple("cl_setup_fips_configuration: FIPS mode provider was not found.\n");
            cl_fips_mode = 0;
        }
    #else
        cl_fips_mode = 0;
    #endif

    #elif OPENSSL_VERSION_MAJOR == 3
        // OpenSSL 3.0.x
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        if (libctx == NULL) {
            cli_warnmsg("cl_setup_fips_configuration: Failed to create libctx.\n");
            cli_fips_mode = 0;
            return;
        }

        OSSL_PROVIDER *fips = OSSL_PROVIDER_load(libctx, "fips");
        if (fips != NULL) {
            cli_infomsg_simple("cl_setup_fips_configuration: FIPS mode provider found.\n");
            cli_fips_mode = 1;
            OSSL_PROVIDER_unload(fips);
            OSSL_LIB_CTX_free(libctx);
        } else {
            cli_infomsg_simple("cl_setup_fips_configuration: FIPS mode provider was not found.\n");
            cli_fips_mode = 0;
            OSSL_LIB_CTX_free(libctx);
        }
    #else
        #error "Unsupported OpenSSL version"
    #endif
}

/**
 * @brief Return the status of our FIPS condition.  
 * 
 * This function allows users of the library to determine if the library is running in FIPS mode.
 * 
 * @return int Returns 1 if we are running in FIPS mode, 0 otherwise
 */

int cli_get_fips_mode(void)
{
    return cli_fips_mode;
}

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

    cli_setup_fips_configuration();

    return 0;
}

/**
 * @brief This is a deprecated function that used to clean up ssl crypto inits
 *
 * Call to EVP_cleanup() has been removed since cleanup is now handled by
 * auto-deinit as of openssl 1.0.2h and 1.1.0
 *
 */
void cl_cleanup_crypto(void)
{
    return;
}

unsigned char *cl_hash_data(const char *alg, const void *buf, size_t len, unsigned char *obuf, unsigned int *olen)
{
    EVP_MD_CTX *ctx;
    unsigned char *ret;
    size_t mdsz;
    const EVP_MD *md;
    unsigned int i;
    size_t cur;
    int winres = 0;

    // If OpenSSL is running in FIPS mode, we need to use the FIPS-compliant md5 lookup of the algorithm
    if (cli_fips_mode && !strncasecmp(alg, "md5", 3))
        md = EVP_MD_fetch(NULL, alg, "-fips");
    else
        md = EVP_get_digestbyname(alg);

    if (!(md))
        return NULL;

    mdsz = EVP_MD_size(md);

    ret = (obuf != NULL) ? obuf : (unsigned char *)malloc(mdsz);
    if (!(ret))
        return NULL;

    ctx = EVP_MD_CTX_create();
    if (!(ctx)) {
        if (!(obuf))
            free(ret);

        return NULL;
    }

#ifdef EVP_MD_CTX_FLAG_NON_FIPS_ALLOW
    /* we will be using MD5, which is not allowed under FIPS */
    EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
#endif

    if (!EVP_DigestInit_ex(ctx, md, NULL)) {
        if (!(obuf))
            free(ret);

        if ((olen))
            *olen = 0;

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

            EVP_MD_CTX_destroy(ctx);
            return NULL;
        }
        EXCEPTION_POSTAMBLE

        if (winres) {
            if (!(obuf))
                free(ret);

            if ((olen))
                *olen = 0;

            EVP_MD_CTX_destroy(ctx);
            return NULL;
        }

        cur += todo;
    }

    if (!EVP_DigestFinal_ex(ctx, ret, &i)) {
        if (!(obuf))
            free(ret);

        if ((olen))
            *olen = 0;

        EVP_MD_CTX_destroy(ctx);
        return NULL;
    }

    EVP_MD_CTX_destroy(ctx);

    if ((olen))
        *olen = i;

    return ret;
}

unsigned char *cl_hash_file_fd(int fd, const char *alg, unsigned int *olen)
{
    EVP_MD_CTX *ctx;
    const EVP_MD *md;
    unsigned char *res;

    // If OpenSSL is running in FIPS mode, we need to use the FIPS-compliant md5 lookup of the algorithm
    if (cli_fips_mode && !strncasecmp(alg, "md5", 3))
        md = EVP_MD_fetch(NULL, alg, "-fips");
    else
        md = EVP_get_digestbyname(alg);

    if (!(md))
        return NULL;

    ctx = EVP_MD_CTX_create();
    if (!(ctx))
        return NULL;

#ifdef EVP_MD_CTX_FLAG_NON_FIPS_ALLOW
    /* we will be using MD5, which is not allowed under FIPS */
    EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
#endif

    if (!EVP_DigestInit_ex(ctx, md, NULL)) {
        EVP_MD_CTX_destroy(ctx);
        return NULL;
    }

    res = cl_hash_file_fd_ctx(ctx, fd, olen);
    EVP_MD_CTX_destroy(ctx);

    return res;
}

unsigned char *cl_hash_file_fd_ctx(EVP_MD_CTX *ctx, int fd, unsigned int *olen)
{
    unsigned char *buf;
    unsigned char *hash;
    int mdsz;
    unsigned int hashlen;
    STATBUF sb;
    int winres = 0;

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

    buf = (unsigned char *)malloc(blocksize);
    if (!(buf)) {
        return NULL;
    }

    hash = (unsigned char *)malloc(mdsz);
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

        if (winres) {
            free(buf);
            free(hash);

            return NULL;
        }
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
    return cl_hash_data("sha512", buf, len, obuf, olen);
}

unsigned char *cl_sha384(const void *buf, size_t len, unsigned char *obuf, unsigned int *olen)
{
    return cl_hash_data("sha384", buf, len, obuf, olen);
}

unsigned char *cl_sha256(const void *buf, size_t len, unsigned char *obuf, unsigned int *olen)
{
    return cl_hash_data("sha256", buf, len, obuf, olen);
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

    // If OpenSSL is running in FIPS mode, we need to use the FIPS-compliant md5 lookup of the algorithm
    if (cli_fips_mode && !strncasecmp(alg, "md5", 3))
        md = EVP_MD_fetch(NULL, alg, "-fips");
    else
        md = EVP_get_digestbyname(alg);

    if (!(md))
        return -1;

    ctx = EVP_MD_CTX_create();
    if (!(ctx))
        return -1;

    mdsz = EVP_MD_size(md);

#ifdef EVP_MD_CTX_FLAG_NON_FIPS_ALLOW
    /* we will be using MD5, which is not allowed under FIPS */
    EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
#endif

    if (!EVP_VerifyInit_ex(ctx, md, NULL)) {
        EVP_MD_CTX_destroy(ctx);
        return -1;
    }

    if (!EVP_VerifyUpdate(ctx, digest, mdsz)) {
        EVP_MD_CTX_destroy(ctx);
        return -1;
    }

    if (EVP_VerifyFinal(ctx, sig, siglen, pkey) <= 0) {
        EVP_MD_CTX_destroy(ctx);
        return -1;
    }

    EVP_MD_CTX_destroy(ctx);
    return 0;
}

int cl_verify_signature_fd(EVP_PKEY *pkey, const char *alg, unsigned char *sig, unsigned int siglen, int fd)
{
    EVP_MD_CTX *ctx;
    const EVP_MD *md;
    size_t mdsz;
    unsigned char *digest;

    digest = cl_hash_file_fd(fd, alg, NULL);
    if (!(digest))
        return -1;

    // If OpenSSL is running in FIPS mode, we need to use the FIPS-compliant md5 lookup of the algorithm
    if (cli_fips_mode && !strncasecmp(alg, "md5", 3))
        md = EVP_MD_fetch(NULL, alg, "-fips");
    else
        md = EVP_get_digestbyname(alg);

    if (!(md)) {
        free(digest);
        return -1;
    }

    mdsz = EVP_MD_size(md);

    ctx = EVP_MD_CTX_create();
    if (!(ctx)) {
        free(digest);
        return -1;
    }

#ifdef EVP_MD_CTX_FLAG_NON_FIPS_ALLOW
    /* we will be using MD5, which is not allowed under FIPS */
    EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
#endif

    if (!EVP_VerifyInit_ex(ctx, md, NULL)) {
        free(digest);
        EVP_MD_CTX_destroy(ctx);
        return -1;
    }

    if (!EVP_VerifyUpdate(ctx, digest, mdsz)) {
        free(digest);
        EVP_MD_CTX_destroy(ctx);
        return -1;
    }

    if (EVP_VerifyFinal(ctx, sig, siglen, pkey) <= 0) {
        free(digest);
        EVP_MD_CTX_destroy(ctx);
        return -1;
    }

    free(digest);
    EVP_MD_CTX_destroy(ctx);
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

    // If OpenSSL is running in FIPS mode, we need to use the FIPS-compliant md5 lookup of the algorithm
    if (cli_fips_mode && !strncasecmp(alg, "md5", 3))
        md = EVP_MD_fetch(NULL, alg, "-fips");
    else
        md = EVP_get_digestbyname(alg);

    if (!(md)) {
        free(digest);
        if (decode)
            free(sig);

        return -1;
    }

    mdsz = EVP_MD_size(md);

    ctx = EVP_MD_CTX_create();
    if (!(ctx)) {
        free(digest);
        if (decode)
            free(sig);

        return -1;
    }

#ifdef EVP_MD_CTX_FLAG_NON_FIPS_ALLOW
    /* we will be using MD5, which is not allowed under FIPS */
    EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
#endif

    if (!EVP_VerifyInit_ex(ctx, md, NULL)) {
        free(digest);
        if (decode)
            free(sig);

        EVP_MD_CTX_destroy(ctx);
        return -1;
    }

    if (!EVP_VerifyUpdate(ctx, digest, mdsz)) {
        free(digest);
        if (decode)
            free(sig);

        EVP_MD_CTX_destroy(ctx);
        return -1;
    }

    if (EVP_VerifyFinal(ctx, sig, siglen, pkey) <= 0) {
        free(digest);
        if (decode)
            free(sig);

        EVP_MD_CTX_destroy(ctx);
        return -1;
    }

    if (decode)
        free(sig);

    free(digest);
    EVP_MD_CTX_destroy(ctx);
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

    // If OpenSSL is running in FIPS mode, we need to use the FIPS-compliant md5 lookup of the algorithm
    if (cli_fips_mode && !strncasecmp(alg, "md5", 3))
        md = EVP_MD_fetch(NULL, alg, "-fips");
    else
        md = EVP_get_digestbyname(alg);

    if (!(md))
        return NULL;

    ctx = EVP_MD_CTX_create();
    if (!(ctx))
        return NULL;

    sig = (unsigned char *)calloc(1, EVP_PKEY_size(pkey));
    if (!(sig)) {
        EVP_MD_CTX_destroy(ctx);
        return NULL;
    }

#ifdef EVP_MD_CTX_FLAG_NON_FIPS_ALLOW
    /* we will be using MD5, which is not allowed under FIPS */
    EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
#endif

    if (!EVP_SignInit_ex(ctx, md, NULL)) {
        free(sig);
        EVP_MD_CTX_destroy(ctx);
        return NULL;
    }

    if (!EVP_SignUpdate(ctx, hash, EVP_MD_size(md))) {
        free(sig);
        EVP_MD_CTX_destroy(ctx);
        return NULL;
    }

    if (!EVP_SignFinal(ctx, sig, &siglen, pkey)) {
        free(sig);
        EVP_MD_CTX_destroy(ctx);
        return NULL;
    }

    if (encode) {
        unsigned char *newsig = (unsigned char *)cl_base64_encode(sig, siglen);
        if (!(newsig)) {
            free(sig);
            EVP_MD_CTX_destroy(ctx);
            return NULL;
        }

        free(sig);
        sig    = newsig;
        siglen = (unsigned int)strlen((const char *)newsig);
    }

    *olen = siglen;
    EVP_MD_CTX_destroy(ctx);
    return sig;
}

unsigned char *cl_sign_file_fd(int fd, EVP_PKEY *pkey, const char *alg, unsigned int *olen, int encode)
{
    unsigned char *hash, *res;
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
    const EVP_MD *md;

    // If OpenSSL is running in FIPS mode, we need to use the FIPS-compliant md5 lookup of the algorithm
    if (cli_fips_mode && !strncasecmp(alg, "md5", 3))
        md = EVP_MD_fetch(NULL, alg, "-fips");
    else
        md = EVP_get_digestbyname(alg);

    if (!(md))
        return NULL;

    ctx = EVP_MD_CTX_create();
    if (!(ctx)) {
        return NULL;
    }

#ifdef EVP_MD_CTX_FLAG_NON_FIPS_ALLOW
    /* we will be using MD5, which is not allowed under FIPS */
    EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
#endif

    if (!EVP_DigestInit_ex(ctx, md, NULL)) {
        EVP_MD_CTX_destroy(ctx);
        return NULL;
    }

    return (void *)ctx;
}

int cl_update_hash(void *ctx, const void *data, size_t sz)
{
    int winres = 0;

    if (!(ctx) || !(data))
        return -1;

    EXCEPTION_PREAMBLE
    if (!EVP_DigestUpdate((EVP_MD_CTX *)ctx, data, sz))
        return -1;
    EXCEPTION_POSTAMBLE

    if (winres)
        return -1;

    return 0;
}

int cl_finish_hash(void *ctx, void *buf)
{
    int res = 0;

    if (!(ctx) || !(buf))
        return -1;

    if (!EVP_DigestFinal_ex((EVP_MD_CTX *)ctx, (unsigned char *)buf, NULL))
        res = -1;

    EVP_MD_CTX_destroy((EVP_MD_CTX *)ctx);

    return res;
}

void cl_hash_destroy(void *ctx)
{
    if (!(ctx))
        return;

    EVP_MD_CTX_destroy((EVP_MD_CTX *)ctx);
}

#if OPENSSL_VERSION_MAJOR == 1
RSA *cli_build_ext_signing_key(void)
{
    RSA *rsa = RSA_new();
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();

    if (!rsa || !n || !e) {
        RSA_free(rsa);
        BN_free(n);
        BN_free(e);
        return NULL;
    }

    if (!BN_hex2bn(&n, CLI_NSTR_EXT_SIG) || !BN_hex2bn(&e, CLI_ESTR_EXT_SIG)) {
        RSA_free(rsa);
        BN_free(n);
        BN_free(e);
        return NULL;
    }
    rsa->n = n;
    rsa->e = e;

    return rsa;
}
#elif OPENSSL_VERSION_MAJOR == 3
// Do this the OpenSSL 3 way, avoiding deprecation warnings
EVP_PKEY *cli_build_ext_signing_key(void)
{
    EVP_PKEY *pkey = EVP_PKEY_new();
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    int result = 0;

    // Check bld and params
    if (!pkey || !n || !e || !bld) {
        EVP_PKEY_free(pkey);
        BN_free(n);
        BN_free(e);
        OSSL_PARAM_BLD_free(bld);
        return NULL;
    }

    // Set the public key components
    if (!BN_hex2bn(&n, CLI_NSTR_EXT_SIG) || !BN_hex2bn(&e, CLI_ESTR_EXT_SIG)) {
        EVP_PKEY_free(pkey);
        BN_free(n);
        BN_free(e);
        OSSL_PARAM_BLD_free(bld);
        return NULL;
    }

    result = OSSL_PARAM_BLD_push_BN(bld, "n", n);
    if (!result) {
        EVP_PKEY_free(pkey);
        BN_free(n);
        BN_free(e);
        OSSL_PARAM_BLD_free(bld);
        return NULL;
    }

    result = OSSL_PARAM_BLD_push_BN(bld, "e", e);
    if (!result) {
        EVP_PKEY_free(pkey);
        BN_free(n);
        BN_free(e);
        OSSL_PARAM_BLD_free(bld);
        return NULL;
    }

    result = OSSL_PARAM_BLD_push_BN(bld, "d", NULL);
    if (!result) {
        EVP_PKEY_free(pkey);
        BN_free(n);
        BN_free(e);
        OSSL_PARAM_BLD_free(bld);
        return NULL;
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    if (!params) {
        EVP_PKEY_free(pkey);
        BN_free(n);
        BN_free(e);
        OSSL_PARAM_BLD_free(bld);
        return NULL;
    }

    OSSL_PARAM_BLD_free(bld);
    BN_free(n);
    BN_free(e);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    if (params)
        OSSL_PARAM_free(params);
    
    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    return pkey;
}
#else
#error "Unsupported OpenSSL version"
#endif
