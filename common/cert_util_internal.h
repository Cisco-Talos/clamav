/*
 *  Internal certificate utility methods and data structures.
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

#ifndef _CERT_UTIL_INT_H
#define _CERT_UTIL_INT_H

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "clamav.h"

typedef struct {
    X509 **certificates;
    size_t count;
} cert_list_t;

typedef struct {
    pthread_mutex_t mutex;
    bool loaded;
    cert_list_t system_certs;
    cert_list_t trusted_certs;
} cert_store_t;

/**
 * @brief Accessor method for cert store.
 *
 * @return Pointer to cert store
 */
cert_store_t *cert_store_get_int(void);

/**
 * @brief Free all certificates loaded by config_store_load.
 *
 * @details This method does not hold the cert store lock and should not be
 *          called outside of cert_util.
 */
void cert_store_unload_int(void);

/**
 * @brief Free memory allocated by a cert_list_t structure.
 *
 * @param[in] cert_list - Pointer to a cert_list_t structure
 */
void cert_store_free_cert_list_int(cert_list_t *cert_list);

/**
 * @brief Set trusted root certificates in the cert store. If trusted
 *        certificates already exist in the cert store then they are removed.
 *
 * @details This method does not hold the cert store lock and should not be
 *          called outside of cert_util.
 *
 * @param[in] trusted_certs - List of X509 trusted root certificates
 * @param[in] trusted_cert_count - Number of trusted root certificates
 *
 * @return 0 on success or -1 on error
 */
cl_error_t cert_store_set_trusted_int(X509 **trusted_certs, size_t trusted_cert_count);

/**
 * @brief Get the name from an X509 certificate.
 * Required if OPENSSL_VERSION_NUMBER >= 0x10100000L ( 1.1.0+ )
 * because the X509 structure is now opaque.
 *
 * The name must be free()'d by the caller.
 *
 * @param[in] cert - The cert in question.
 * @param[out] name - The NULL terminated name.
 * @return cl_error_t CL_SUCCESS on success.
 */
cl_error_t x509_get_cert_name(X509 *cert, char **name);

#endif
