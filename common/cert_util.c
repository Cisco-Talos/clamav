/*
 *  OpenSSL certificate caching.
 *
 *  Copyright (C) 2016-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Russ Kubik
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

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>
#include <pthread.h>

#include "cert_util.h"
#include "cert_util_internal.h"

#include "output.h"

static cert_store_t _cert_store = {
    .mutex = PTHREAD_MUTEX_INITIALIZER};

static cl_error_t _x509_to_pem(X509 *cert,
                               char **data,
                               int *len)
{
    cl_error_t ret = CL_EFORMAT;

    BIO *out       = NULL;
    long pem_len   = 0;
    char *pem_data = NULL;

    if (cert == NULL || data == NULL || len == NULL) {
        mprintf(LOGG_ERROR, "_x509_to_pem: Invalid argument\n");
        goto done;
    }

    /* Output the certs to a new BIO using the PEM format */
    out = BIO_new(BIO_s_mem());
    if (!out) {
        mprintf(LOGG_ERROR, "BIO_new failed\n");
        goto done;
    }

    PEM_write_bio_X509(out, cert);

    (void)BIO_flush(out);

    /* Convert the BIO to char* */
    pem_len = BIO_get_mem_data(out, &pem_data);
    if (pem_len <= 0 || !pem_data) {
        mprintf(LOGG_ERROR, "BIO_new: BIO_get_mem_data failed\n");
        BIO_free_all(out);
        goto done;
    }

    *data = calloc(1, pem_len + 1);
    if (!*data) {
        mprintf(LOGG_ERROR, "BIO_new: malloc failed\n");
        BIO_free_all(out);
        goto done;
    }
    memcpy(*data, pem_data, pem_len);
    (*data)[pem_len] = '\0';

    *len = (int)pem_len;

    BIO_free_all(out);

    ret = CL_SUCCESS;

done:
    return ret;
}

/**
 * @brief This method will convert a X509 certificate to PEM format and append
 *        it to a string buffer.
 *
 * @note If realloc fails to reserve memory for *cert_data it will free whatever
 *       is currently in *cert_data before returning. total_buf_len is also set
 *       to 0 (zero) in this case.
 *
 * @param[in] *ca_cert Pointer to CA certificate
 * @param[out] **cert_data Pointer to allocated string buffer
 * @param[out] *total_buf_len Total of string buffer length after appending
 *                            CA certificate (ca_cert)
 * @param[in,out] *remaining_buf_len Remaining data left allowed in CA certificate
 *                                   chain after appending CA certificate
 *                                   (ca_cert)
 *
 * @return 0 on success, -1 on error
 */
static cl_error_t _x509_to_pem_append(X509 *ca_cert,
                                      char **cert_data,
                                      int *total_buf_len,
                                      size_t *remaining_buf_len)
{
    char *pem_data = NULL;
    char *tmp;
    int pem_data_len = 0;
    cl_error_t ret   = CL_EOPEN;
    int current_len  = 0;

    if (ca_cert == NULL || total_buf_len == NULL ||
        remaining_buf_len == NULL || *cert_data == NULL) {
        mprintf(LOGG_ERROR, "NULL parameter given\n");
        goto done;
    }

    current_len = *total_buf_len;

    if (CL_SUCCESS != _x509_to_pem(ca_cert, &pem_data, &pem_data_len)) {
        mprintf(LOGG_ERROR, "Failed to convert x509 certificate to PEM\n");
        goto done;
    }

    if (pem_data_len > (int)*remaining_buf_len) {
        tmp = realloc(*cert_data, current_len + pem_data_len + 1);
        if (tmp == NULL) {
            mprintf(LOGG_ERROR, "Could not realloc enough memory for PEM "
                                "certificate\n");

            free(*cert_data);
            *cert_data     = NULL;
            *total_buf_len = 0;

            goto done;
        }
        *cert_data         = tmp;
        tmp                = NULL;
        *remaining_buf_len = 0;
    } else {
        *remaining_buf_len -= pem_data_len;
    }

    memcpy(&((*cert_data)[current_len]), pem_data, pem_data_len);
    *total_buf_len               = current_len + pem_data_len;
    (*cert_data)[*total_buf_len] = '\0';

    ret = CL_SUCCESS;

done:

    free(pem_data);
    pem_data = NULL;
    return ret;
}

cert_store_t *cert_store_get_int(void)
{
    return &_cert_store;
}

void cert_store_unload_int(void)
{
    if (_cert_store.loaded) {
        cert_store_free_cert_list_int(&_cert_store.system_certs);
        cert_store_free_cert_list_int(&_cert_store.trusted_certs);
        _cert_store.loaded = false;
    }
}

void cert_store_free_cert_list_int(cert_list_t *cert_list)
{
    size_t i;

    if (cert_list && cert_list->certificates) {
        for (i = 0; i < cert_list->count; ++i) {
            X509_free(cert_list->certificates[i]);
            cert_list->certificates[i] = NULL;
        }

        free(cert_list->certificates);
        cert_list->certificates = NULL;
        cert_list->count        = 0L;
    }
}

void cert_store_unload(void)
{
    int pt_err;

    pt_err = pthread_mutex_lock(&_cert_store.mutex);
    if (pt_err) {
        errno = pt_err;
        mprintf(LOGG_ERROR, "Mutex lock failed\n");
    }

    cert_store_unload_int();

    pt_err = pthread_mutex_unlock(&_cert_store.mutex);
    if (pt_err) {
        errno = pt_err;
        mprintf(LOGG_ERROR, "Mutex unlock failed\n");
    }
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L /* 1.1.0+ */
static cl_error_t x509_cert_name_cmp(X509 *cert_a, X509 *cert_b, int *cmp_out)
{
    cl_error_t status = CL_EMEM;

    X509_NAME *a = NULL;
    X509_NAME *b = NULL;

    BIO *bio_out_a = NULL;
    BIO *bio_out_b = NULL;

    BUF_MEM *biomem_a;
    BUF_MEM *biomem_b;

    bio_out_a = BIO_new(BIO_s_mem());
    if (!bio_out_a)
        goto done;

    bio_out_b = BIO_new(BIO_s_mem());
    if (!bio_out_b)
        goto done;

    a = X509_get_subject_name(cert_a);

    if (-1 == X509_NAME_print_ex(bio_out_a, a, 0, XN_FLAG_SEP_SPLUS_SPC)) {
        mprintf(LOGG_ERROR, "Failed to print x509 certificate name!\n");
        goto done;
    }
    BIO_get_mem_ptr(bio_out_a, &biomem_a);

    b = X509_get_subject_name(cert_b);

    if (-1 == X509_NAME_print_ex(bio_out_b, b, 0, XN_FLAG_SEP_SPLUS_SPC)) {
        mprintf(LOGG_ERROR, "Failed to print x509 certificate name!\n");
        goto done;
    }
    BIO_get_mem_ptr(bio_out_b, &biomem_b);

    *cmp_out = strncmp(biomem_a->data, biomem_b->data, MIN(biomem_a->length, biomem_b->length));
    status   = CL_SUCCESS;

done:
    if (NULL != bio_out_a)
        BIO_free(bio_out_a);
    if (NULL != bio_out_b)
        BIO_free(bio_out_b);

    return status;
}

cl_error_t x509_get_cert_name(X509 *cert, char **name)
{
    cl_error_t status = CL_EMEM;

    X509_NAME *a = NULL;
    BIO *bio_out = NULL;
    BUF_MEM *biomem;
    char *cert_name = NULL;

    if (NULL == cert || NULL == name) {
        status = CL_EARG;
        goto done;
    }

    *name = NULL;

    bio_out = BIO_new(BIO_s_mem());
    if (!bio_out)
        goto done;

    a = X509_get_subject_name(cert);

    if (-1 == X509_NAME_print_ex(bio_out, a, 0, XN_FLAG_SEP_SPLUS_SPC)) {
        mprintf(LOGG_ERROR, "Failed to print x509 certificate name!\n");
        goto done;
    }
    BIO_get_mem_ptr(bio_out, &biomem);

    cert_name = malloc(biomem->length + 1);
    if (!cert_name) {
        mprintf(LOGG_ERROR, "Failed to allocate memory for certificate name biomem structure!\n");
        goto done;
    }

    memcpy(cert_name, biomem->data, biomem->length);
    cert_name[biomem->length] = '\0';

    *name  = cert_name;
    status = CL_SUCCESS;

done:
    if (NULL != bio_out)
        BIO_free(bio_out);

    return status;
}
#endif

cl_error_t cert_store_export_pem(char **cert_data,
                                 int *cert_data_len,
                                 X509 *additional_ca_cert)
{
    const uint32_t STARTING_RAW_PEM_LENGTH = 350 * 1024;
    uint32_t i;
    cl_error_t ret = CL_EOPEN;
    bool locked    = false;
    int pt_err;

    size_t remaining_buf_len    = STARTING_RAW_PEM_LENGTH;
    bool add_additional_ca_cert = true;

    if ((cert_data == NULL) || (cert_data_len == NULL)) {
        mprintf(LOGG_ERROR, "One or more arguments are NULL\n");
        goto done;
    }

    *cert_data = calloc(1, STARTING_RAW_PEM_LENGTH + 1);
    if (*cert_data == NULL) {
        mprintf(LOGG_ERROR, "Could not allocate memory for PEM certs\n");
        goto done;
    }
    *cert_data_len = 0;

    pt_err = pthread_mutex_lock(&_cert_store.mutex);
    if (pt_err) {
        errno = pt_err;
        mprintf(LOGG_ERROR, "Mutex lock failed\n");
    }
    locked = true;

    if (!_cert_store.loaded) {
        goto done;
    }

    /* Load system root ca certs into list */
    for (i = 0; i < _cert_store.system_certs.count; ++i) {
        if (_x509_to_pem_append(_cert_store.system_certs.certificates[i],
                                cert_data,
                                cert_data_len,
                                &remaining_buf_len) != 0) {
            goto done;
        }
        /*
         * Two certs by the same name can cause conflicts. Trust the
         * one in the OS certificate/key store if the additional CA
         * name matches that of one in the store.
         */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        /* OpenSSL >= 1.1.0 */
        if (additional_ca_cert) {
            int cmp = 0;
            if (CL_SUCCESS == x509_cert_name_cmp(_cert_store.system_certs.certificates[i],
                                                 additional_ca_cert,
                                                 &cmp)) {
                if (0 == cmp)
                    add_additional_ca_cert = false;
            }
        }
#else
        /* OpenSSL <= 1.0.2 */
        if (additional_ca_cert && additional_ca_cert->cert_info &&
            (strcmp(_cert_store.system_certs.certificates[i]->name,
                    additional_ca_cert->name) == 0)) {
            add_additional_ca_cert = false;
        }
#endif
    }

    /* Load trusted ca certs into list */
    for (i = 0; i < _cert_store.trusted_certs.count; ++i) {
        if (_x509_to_pem_append(_cert_store.trusted_certs.certificates[i],
                                cert_data,
                                cert_data_len,
                                &remaining_buf_len) != 0) {
            goto done;
        }
        /*
         * Two certs by the same name can cause conflicts. Trust the
         * one in the OS certificate/key store if the additional CA
         * name matches that of one in the store.
         */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        /* OpenSSL >= 1.1.0 */
        if (additional_ca_cert) {
            int cmp = 0;
            if (CL_SUCCESS == x509_cert_name_cmp(_cert_store.trusted_certs.certificates[i],
                                                 additional_ca_cert,
                                                 &cmp)) {
                if (0 == cmp)
                    add_additional_ca_cert = false;
            }
        }
#else
        /* OpenSSL <= 1.0.2 */
        if (additional_ca_cert && additional_ca_cert->cert_info &&
            (strcmp(_cert_store.trusted_certs.certificates[i]->name,
                    additional_ca_cert->name) == 0)) {
            add_additional_ca_cert = false;
        }
#endif
    }

    /* End with the additional CA certificate if provided */
    if (additional_ca_cert && add_additional_ca_cert && *cert_data) {
        /* Return an error only if we were unable to allocate memory */
        if (_x509_to_pem_append(additional_ca_cert,
                                cert_data,
                                cert_data_len,
                                &remaining_buf_len) != 0) {
            goto done;
        }
    }

    ret = CL_SUCCESS;
done:
    if (locked) {
        pt_err = pthread_mutex_unlock(&_cert_store.mutex);
        if (pt_err) {
            errno = pt_err;
            mprintf(LOGG_ERROR, "Mutex unlock failed\n");
        }
        locked = false;
    }

    if (ret != CL_SUCCESS && cert_data && *cert_data) {
        free(*cert_data);
        *cert_data = NULL;
    }

    return ret;
}

cl_error_t cert_store_set_trusted_int(X509 **trusted_certs, size_t trusted_cert_count)
{
    cl_error_t ret = CL_EOPEN;
    size_t i, j;
    cert_list_t tmp_trusted = {0};

    do {
        if ((trusted_certs == NULL) || (trusted_cert_count == 0)) {
            mprintf(LOGG_ERROR, "Empty trusted certificate list\n");
            break;
        }

        tmp_trusted.certificates = calloc(trusted_cert_count,
                                          sizeof(*tmp_trusted.certificates));
        if (!tmp_trusted.certificates) {
            mprintf(LOGG_ERROR, "Failed to reserve memory for trusted certs\n");
            break;
        }

        for (i = 0; i < trusted_cert_count; ++i) {
            bool found = false;

            /* Check if certificate already exists in system root cert list */
            for (j = 0; j < _cert_store.system_certs.count; ++j) {
                if (X509_cmp(trusted_certs[i],
                             _cert_store.system_certs.certificates[j]) == 0) {
                    found = true;
                }
            }

            if (found) {
                continue; /* certificate is already found in cert store */
            }

            tmp_trusted.certificates[tmp_trusted.count] =
                X509_dup(trusted_certs[i]);
            if (!tmp_trusted.certificates[tmp_trusted.count]) {
                mprintf(LOGG_ERROR, "X509_dup failed at index: %zu\n", i);
                continue; /* continue on error */
            }

            tmp_trusted.count++;
        }

        cert_store_free_cert_list_int(&_cert_store.trusted_certs);

        _cert_store.trusted_certs.certificates = tmp_trusted.certificates;
        _cert_store.trusted_certs.count        = tmp_trusted.count;

        tmp_trusted.certificates = NULL;
        tmp_trusted.count        = 0;

        ret = CL_SUCCESS;
    } while (0);

    return ret;
}

cl_error_t cert_store_set_trusted(X509 **trusted_certs, size_t trusted_cert_count)
{
    cl_error_t ret = CL_EOPEN;
    int pt_err;

    pt_err = pthread_mutex_lock(&_cert_store.mutex);
    if (pt_err) {
        errno = pt_err;
        mprintf(LOGG_ERROR, "Mutex lock failed\n");
    }

    if (_cert_store.loaded) {
        ret = cert_store_set_trusted_int(trusted_certs, trusted_cert_count);
    }

    pt_err = pthread_mutex_unlock(&_cert_store.mutex);
    if (pt_err) {
        errno = pt_err;
        mprintf(LOGG_ERROR, "Mutex unlock failed\n");
    }

    return ret;
}

size_t cert_store_remove_trusted(void)
{
    size_t count = 0;
    int pt_err;

    pt_err = pthread_mutex_lock(&_cert_store.mutex);
    if (pt_err) {
        errno = pt_err;
        mprintf(LOGG_ERROR, "Mutex lock failed\n");
    }

    if (_cert_store.loaded) {
        count = _cert_store.trusted_certs.count;
        cert_store_free_cert_list_int(&_cert_store.trusted_certs);
    }

    pt_err = pthread_mutex_unlock(&_cert_store.mutex);
    if (pt_err) {
        errno = pt_err;
        mprintf(LOGG_ERROR, "Mutex unlock failed\n");
    }

    return count;
}

void cert_fill_X509_store(X509_STORE *store, X509 **certs, size_t cert_count)
{
    size_t i;
    unsigned long err;

    if (store && certs && cert_count > 0) {
        for (i = 0; i < cert_count; ++i) {
            if (!certs[i]) {
                mprintf(LOGG_ERROR, "NULL cert at index %zu in X509 cert list; skipping\n", i);
                continue;
            }
            if (X509_STORE_add_cert(store, certs[i]) != 1) {
                char *name = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
                x509_get_cert_name(certs[i], &name);
#else
                name = certs[i]->name;
#endif
                err = ERR_get_error();
                if (X509_R_CERT_ALREADY_IN_HASH_TABLE == ERR_GET_REASON(err)) {
                    mprintf(LOGG_DEBUG, "Certificate skipped; already exists in store: %s\n",
                            (name ? name : ""));
                } else {
                    mprintf(LOGG_ERROR, "Failed to add certificate to store: %s (%lu) [%s]\n",
                            ERR_error_string(err, NULL), err,
                            (name ? name : ""));
                }
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
                if (NULL != name) {
                    free(name);
                    name = NULL;
                }
#endif
            }
        }
    }
}

void cert_store_export_certs(X509_STORE *store, X509 *additional_ca_cert)
{
    cert_store_t *cert_store = NULL;
    int pt_err;

    do {
        if (!store) {
            mprintf(LOGG_ERROR, "NULL X509 store\n");
            break;
        }

        cert_store = cert_store_get_int();
        if (!cert_store) {
            mprintf(LOGG_ERROR, "Failed to retrieve cert store\n");
            break;
        }

        pt_err = pthread_mutex_lock(&cert_store->mutex);
        if (pt_err) {
            errno = pt_err;
            mprintf(LOGG_ERROR, "Mutex lock failed\n");
        }

        if (!cert_store->loaded) {
            mprintf(LOGG_ERROR, "Cert store not loaded\n");
            break;
        }

        /* On Linux, system certificates are loaded by OpenSSL */
#if defined(_WIN32) || defined(DARWIN)
        cert_fill_X509_store(store,
                             cert_store->system_certs.certificates,
                             cert_store->system_certs.count);
#endif

        cert_fill_X509_store(store,
                             cert_store->trusted_certs.certificates,
                             cert_store->trusted_certs.count);

        /* Adding the additional CA cert to the trustchain */
        if ((additional_ca_cert != NULL) &&
            (X509_STORE_add_cert(store, additional_ca_cert) != 1)) {
            char *name        = NULL;
            unsigned long err = ERR_get_error();

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
            x509_get_cert_name(additional_ca_cert, &name);
#else
            name = additional_ca_cert->name;
#endif
            if (X509_R_CERT_ALREADY_IN_HASH_TABLE == ERR_GET_REASON(err)) {
                mprintf(LOGG_INFO, "Certificate is already in trust [%s]\n",
                        (name ? name : ""));
            } else {
                mprintf(LOGG_ERROR, "Failed to add CA certificate for the SSL context. "
                                    "Error: %d [%s]\n",
                        ERR_GET_REASON(err),
                        (name ? name : ""));
            }
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
            if (NULL != name) {
                free(name);
                name = NULL;
            }
#endif
        }
    } while (0);

    if (cert_store) {
        pt_err = pthread_mutex_unlock(&cert_store->mutex);
        if (pt_err) {
            errno = pt_err;
            mprintf(LOGG_ERROR, "Mutex unlock failed\n");
        }
    }
}

CURLcode sslctx_function(CURL *curl, void *ssl_ctx, void *userptr)
{
    CURLcode status          = CURLE_BAD_FUNCTION_ARGUMENT;
    cert_store_t *cert_store = NULL;

    UNUSEDPARAM(curl);
    UNUSEDPARAM(userptr);

    cert_store = cert_store_get_int();
    if (!cert_store) {
        mprintf(LOGG_ERROR, "Failed to retrieve cert store\n");
        goto done;
    }

    if (!cert_store->loaded) {
        if (CL_SUCCESS != cert_store_load(NULL, 0)) {
            mprintf(LOGG_ERROR, "Failed to load cert store\n");
            goto done;
        }
    }

    X509_STORE *store = SSL_CTX_get_cert_store((SSL_CTX *)ssl_ctx);

    cert_store_export_certs(store, NULL);

    status = CURLE_OK;

done:

    return status;
}

cl_error_t set_tls_client_certificate(CURL *curl)
{
    cl_error_t status = CL_ERROR;
    char *client_certificate;
    char *client_key;
    char *client_key_passwd;
    CURLcode curlcode = CURLE_OK;

    client_certificate = getenv("FRESHCLAM_CLIENT_CERT");
    if (client_certificate == NULL) {
        // No client certificate specified, so no need to set it.
        status = CL_SUCCESS;
        goto done;
    }

    client_key = getenv("FRESHCLAM_CLIENT_KEY");
    if (client_key == NULL) {
        // A client certificate was specified, but no client key was specified.
        logg(LOGG_WARNING, "The FRESHCLAM_CLIENT_CERT environment variable was set, but FRESHCLAM_CLIENT_KEY was not set. A client private key is also required if specifying a client certificate.\n");
        goto done;
    }

    client_key_passwd = getenv("FRESHCLAM_CLIENT_KEY_PASSWD");

    /* set the cert for client authentication */
    curlcode = curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
    if (CURLE_OK != curlcode) {
        logg(LOGG_WARNING, "Failed to set client certificate type for client authentication: %s\n", curl_easy_strerror(curlcode));
        goto done;
    }

    curlcode = curl_easy_setopt(curl, CURLOPT_SSLCERT, client_certificate);
    if (CURLE_OK != curlcode) {
        logg(LOGG_WARNING, "Failed to set client certificate to '%s' for client authentication: %s\n", client_certificate, curl_easy_strerror(curlcode));
        goto done;
    }

    /* set the private key type and path */
    curlcode = curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");
    if (CURLE_OK != curlcode) {
        logg(LOGG_WARNING, "Failed to set private key type for client authentication: %s\n", curl_easy_strerror(curlcode));
        goto done;
    }

    curlcode = curl_easy_setopt(curl, CURLOPT_SSLKEY, client_key);
    if (CURLE_OK != curlcode) {
        logg(LOGG_WARNING, "Failed to set private key to '%s' for client authentication: %s\n", client_key, curl_easy_strerror(curlcode));
        goto done;
    }

    /* the private key may require a password */
    if (client_key_passwd != NULL) {
        curlcode = curl_easy_setopt(curl, CURLOPT_KEYPASSWD, client_key_passwd);
        if (CURLE_OK != curlcode) {
            logg(LOGG_WARNING, "Failed to set the password for private key '%s': %s\n", client_key, curl_easy_strerror(curlcode));
            goto done;
        }
    }

    status = CL_SUCCESS;

done:
    return status;
}
