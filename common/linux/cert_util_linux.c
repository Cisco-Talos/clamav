/*
 *  OpenSSL certificate verification for Linux.
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

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>

#include <curl/curl.h>

#include "output.h"
#include "cert_util.h"
#include "cert_util_internal.h"

void set_tls_ca_bundle(CURL *curl)
{
    char *ca_bundle;

    ca_bundle = getenv("CURL_CA_BUNDLE");
    if (ca_bundle == NULL) {
        return;
    }

    if (curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle) != CURLE_OK) {
        fprintf(stderr, "Failed to set CURLOPT_CAINFO!\n");
    }
}

cl_error_t cert_store_load(X509 **trusted_certs, size_t trusted_cert_count)
{
    cl_error_t ret      = CL_EOPEN;
    cert_store_t *store = NULL;
    int pt_err;

    do {
        store = cert_store_get_int();
        if (!store) {
            mprintf(LOGG_ERROR, "Failed to retrieve cert store\n");
            break;
        }

        pt_err = pthread_mutex_lock(&store->mutex);
        if (pt_err) {
            errno = pt_err;
            mprintf(LOGG_ERROR, "Mutex lock failed\n");
        }

        if (store->loaded) {
            ret = 0;
            break;
        }

        /* System certs do not need to be added as they can be accessed directly
         * by the SSL library. */
        store->system_certs.count        = 0;
        store->system_certs.certificates = NULL;

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
        ret           = 0;
    } while (0);

    if (store) {
        pt_err = pthread_mutex_unlock(&store->mutex);
        if (pt_err) {
            errno = pt_err;
            mprintf(LOGG_ERROR, "Mutex unlock failed\n");
        }
    }

    return ret;
}
