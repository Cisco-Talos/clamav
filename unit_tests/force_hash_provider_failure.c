/*
 * Test-only OpenSSL interposer for deterministic digest-cache failure tests.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

typedef EVP_MD *(*evp_md_fetch_fn)(OSSL_LIB_CTX *, const char *, const char *);
typedef OSSL_LIB_CTX *(*ossl_lib_ctx_new_fn)(void);

static void resolve_symbol(void *function_out, size_t function_size, const char *name)
{
    void *symbol = dlsym(RTLD_NEXT, name);

    if (function_size == sizeof(symbol)) {
        memcpy(function_out, &symbol, function_size);
    }
}

EVP_MD *EVP_MD_fetch(OSSL_LIB_CTX *ctx, const char *algorithm, const char *properties)
{
    static evp_md_fetch_fn real_fetch = NULL;

    if (NULL != ctx && NULL != algorithm && NULL != getenv("CLAMAV_TEST_MD5_FETCH_FAILURE") &&
        0 == strcmp(algorithm, "md5")) {
        return NULL;
    }

    if (NULL == real_fetch) {
        resolve_symbol(&real_fetch, sizeof(real_fetch), "EVP_MD_fetch");
    }
    if (NULL == real_fetch) {
        return NULL;
    }
    return real_fetch(ctx, algorithm, properties);
}

OSSL_LIB_CTX *OSSL_LIB_CTX_new(void)
{
    static ossl_lib_ctx_new_fn real_new = NULL;

    if (NULL != getenv("CLAMAV_TEST_OSSL_LIBCTX_FAILURE")) {
        return NULL;
    }

    if (NULL == real_new) {
        resolve_symbol(&real_new, sizeof(real_new), "OSSL_LIB_CTX_new");
    }
    if (NULL == real_new) {
        return NULL;
    }
    return real_new();
}
