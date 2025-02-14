/*
 *  OpenSSL certificate caching.
 *
 *  Copyright (C) 2016-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Russ Kubik
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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

#ifndef _CERT_UTIL_H
#define _CERT_UTIL_H

#include <openssl/x509.h>

#include <curl/curl.h>

#include "clamav.h"

/* As defined by ub-common-name in https://www.ietf.org/rfc/rfc3280.txt */
#define X509_COMMON_NAME_MAX_LEN (64)

#if !(defined(C_DARWIN) || defined(_WIN32))
/**
 * @brief Set the tls ca bundle to a custom value using the CURL_CA_BUNDLE environment variable.
 *
 * @param curl Pointer to the curl connection handle.
 */
void set_tls_ca_bundle(CURL *curl);
#endif

/**
 * @brief Set the path for a client certificate PEM file and a private key PEM file using the FRESHCLAM_CLIENT_CERT, FRESHCLAM_CLIENT_KEY, and FRESHCLAM_CLIENT_KEY_PASSWD environment variables.
 *
 * @param curl Pointer to the curl connection handle.
 */
cl_error_t set_tls_client_certificate(CURL *curl);

/**
 * @brief Load system and trusted root certificates into memory. Any errors
 *        while loading trusted certificates will be ignored. If error checking
 *        is required for trusted certificates please use cert_store_set_trusted
 *        directly.
 *
 * @details To load the certificate store with system certificates only pass
 *          NULL for trusted_certs and 0 (zero) for trusted_cert_count. The
 *          certificates store will then only load root certificates from the
 *          system and skip setting trusted certificates (which are
 *          optional and can be set later with cert_store_set_trusted).
 *
 * @param[in] trusted_certs - List of X509 trusted root certificates (NULL for
 *                            empty or no trusted certificates)
 * @param[in] trusted_cert_count - Number of trusted root certificates (0 for
 *                                 empty or no trusted certificates)
 *
 * @return 0 on success or if the cert store is already loaded, -1 on error
 */
cl_error_t cert_store_load(X509 **trusted_certs, size_t trusted_cert_count);

/**
 * @brief Free system and trusted root certificates.
 */
void cert_store_unload(void);

/**
 * @brief Set trusted root certificates in the cert store. If trusted
 *        certificates already exist then they are removed.
 *
 * @param[in] trusted_certs - List of trusted X509 root certificates
 * @param[in] trusted_cert_count - Number of trusted X509 root certificates
 *
 * @return 0 on success or -1 on error
 */
cl_error_t cert_store_set_trusted(X509 **trusted_certs, size_t trusted_cert_count);

/**
 * @brief Remove trusted root certificates from the cert store.
 *
 * @return a count of how many trusted certificates were removed. 0 (zero) will
 *         be returned if the cert store is not initialized
 */
size_t cert_store_remove_trusted(void);

/**
 * @brief Export all system and trusted root certificates from the cert store
 *        into an SSL X509_STORE. The additional_ca_cert will also be exported
 *        if provided (not NULL).
 *
 * @param[out] store - SSL X509 store context
 * @param[in] additional_ca_cert - additional CA certificate to append (if not
 *                                 NULL)
 */
void cert_store_export_certs(X509_STORE *store, X509 *additional_ca_cert);

/**
 * @brief Export all system and trusted root certificates from the cert store as
 *        a null-terminated string. Certificates within the string will be
 *        PEM-encoded.
 *
 * @details An example user of this method is the EST library which, as part of
 *          its initialization, will ensure that the length of the CA chain
 *          matches a given length.
 *
 * @link common/est/src/src/est_client.c
 *
 * @param[out] cert_data - Root CA certificate PEM buffer
 * @param[out] cert_data_len - Length of cert_data buffer
 * @param[in]  additional_ca_cert - an additional CA certificate to append
 *
 * @return 0 on success, -1 on error
 */
cl_error_t cert_store_export_pem(char **cert_data,
                                 int *cert_data_len,
                                 X509 *additional_ca_cert);

/**
 * @brief Add certificates to X509 store. Duplicate certificates are skipped
 *        and errors are printed to the log.
 *
 * @param[in] store - Pointer to X509 store
 * @param[in] certs - List of X509 certificates
 * @param[in] cert_count - Number of X509 certificates
 */
void cert_fill_X509_store(X509_STORE *store, X509 **certs, size_t cert_count);

/**
 * @brief Callback function for libcurl to verify certificates for HTTPS connections.
 *
 * @param[in] curl - handle for curl connection.
 * @param[in] ssl_ctx - List of X509 certificates
 * @param[in] userptr - Number of X509 certificates
 */
CURLcode sslctx_function(CURL *curl, void *ssl_ctx, void *userptr);

#endif
