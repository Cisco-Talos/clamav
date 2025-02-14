/*
 *  OpenSSL certificate verification for Windows.
 *
 *  Copyright (C) 2019-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Micah Snyder
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

#include <Windows.h>
#include <wincrypt.h>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <curl/curl.h>

#include "output.h"

#include "cert_util.h"
#include "cert_util_internal.h"

cl_error_t cert_store_load(X509 **trusted_certs, size_t trusted_cert_count)
{
    uint32_t numCertificatesFound = 0;
    DWORD lastError;

    HCERTSTORE hStore              = NULL;
    PCCERT_CONTEXT pWinCertContext = NULL;
    X509 *x509                     = NULL;

    cl_error_t ret = CL_EOPEN;
    int pt_err;

    cert_store_t *store = NULL;
    bool locked         = false;

    hStore = CertOpenSystemStoreA(0, "ROOT");
    if (NULL == hStore) {
        mprintf(LOGG_ERROR, "Failed to open system certificate store.\n");
        goto done;
    }

    store = cert_store_get_int();
    if (!store) {
        mprintf(LOGG_ERROR, "Failed to retrieve cert store\n");
        goto done;
    }

    pt_err = pthread_mutex_lock(&store->mutex);
    if (pt_err) {
        errno = pt_err;
        mprintf(LOGG_ERROR, "Mutex lock failed\n");
    }
    locked = true;

    if (store->loaded) {
        mprintf(LOGG_INFO, "Cert store already loaded\n");
        ret = CL_SUCCESS;
        goto done;
    }

    store->system_certs.count        = 0;
    store->system_certs.certificates = NULL;

    while (NULL != (pWinCertContext = CertEnumCertificatesInStore(hStore, pWinCertContext))) {
        int addCertResult                 = 0;
        const unsigned char *encoded_cert = pWinCertContext->pbCertEncoded;

        x509 = NULL;
        x509 = d2i_X509(NULL, &encoded_cert, pWinCertContext->cbCertEncoded);
        if (NULL == x509) {
            mprintf(LOGG_ERROR, "Failed to convert system certificate to x509.\n");
            continue;
        }

        store->system_certs.certificates = realloc(
            store->system_certs.certificates,
            (numCertificatesFound + 1) * sizeof(*store->system_certs.certificates));
        if (store->system_certs.certificates == NULL) {
            mprintf(LOGG_ERROR, "Failed to reserve memory for system cert list\n");
            goto done;
        }

        store->system_certs.certificates[store->system_certs.count++] = x509;

        if (mprintf_verbose) {
            char *issuer     = NULL;
            size_t issuerLen = 0;
            issuerLen        = CertGetNameStringA(pWinCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, NULL, 0);

            issuer = malloc(issuerLen);
            if (NULL == issuer) {
                mprintf(LOGG_ERROR, "Failed to allocate memory for certificate name.\n");
                ret = CURLE_OUT_OF_MEMORY;
                goto done;
            }

            if (0 == CertGetNameStringA(pWinCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, issuer, issuerLen)) {
                mprintf(LOGG_ERROR, "Failed to get friendly display name for certificate.\n");
            } else {
                mprintf(LOGG_INFO, "Certificate loaded from Windows certificate store: %s\n", issuer);
            }

            free(issuer);
        }

        numCertificatesFound++;
    }

    lastError = GetLastError();
    switch (lastError) {
        case E_INVALIDARG:
            mprintf(LOGG_ERROR, "The handle in the hCertStore parameter is not the same as that in the certificate context pointed to by pPrevCertContext.\n");
            break;
        case CRYPT_E_NOT_FOUND:
        case ERROR_NO_MORE_FILES:
            if (0 == numCertificatesFound) {
                mprintf(LOGG_ERROR, "No certificates were found.\n");
            }
            break;
        default:
            mprintf(LOGG_ERROR, "Unexpected error code from CertEnumCertificatesInStore()\n");
    }

    if (trusted_certs && trusted_cert_count > 0) {
        if (cert_store_set_trusted_int(trusted_certs, trusted_cert_count) == 0) {
            mprintf(LOGG_DEBUG, "Trusted certificates loaded: %zu\n",
                    store->trusted_certs.count);
        } else {
            mprintf(LOGG_WARNING, "Continuing without trusted certificates\n");
            /* proceed as if we succeeded using only certificates from the
             * system */
        }
    }

    store->loaded = true;
    ret           = CL_SUCCESS;

done:
    if (locked) {
        pt_err = pthread_mutex_unlock(&store->mutex);
        if (pt_err) {
            errno = pt_err;
            mprintf(LOGG_ERROR, "Mutex unlock failed\n");
        }
        locked = false;
    }

    if (NULL != pWinCertContext) {
        CertFreeCertificateContext(pWinCertContext);
    }
    if (NULL != hStore) {
        CertCloseStore(hStore, 0);
    }

    return ret;
}
