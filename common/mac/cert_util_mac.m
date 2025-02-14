/*
 *  OpenSSL certificate verification for macOS.
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

#include <Foundation/Foundation.h>
#import <Security/SecRequirement.h>
#import <Security/SecBase.h>
#import <Security/SecCode.h>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <Security/Security.h>

#include <sys/syslimits.h>
#import <sys/proc_info.h>
#import <libproc.h>

#include <sys/stat.h>
#include <libgen.h>
#include <mach-o/dyld.h>

#include <curl/curl.h>

#include "output.h"

#include "cert_util.h"
#include "cert_util_internal.h"

/* Macro to obtain the number of elements in a fixed sized array that was either
 * statically declared or declared on the stack in the same scope.  The macro
 * will generate a divide-by-zero compiler warning if the input is a pointer.
 *
 * See also:
 * http://stackoverflow.com/questions/8018843/macro-definition-array-size
 */
#define ARRAY_SIZE(a) ((sizeof(a) / sizeof(*(a))) / ((size_t)(!(sizeof(a) % sizeof(*(a))))))

/* Keychain types available on macOS.  User specific keychains are omitted for
 * simplicity. */
typedef enum keychain_type {
    KEYCHAIN_TYPE_SYSTEM_ROOT,
    KEYCHAIN_TYPE_SYSTEM
} keychain_type_t;

/* Basic information about a keychain */
typedef struct keychain_info {
    const char *name;
    const char *file_path;
} keychain_info_t;

/* Table to support name and file path lookup for each keychain type */
static const keychain_info_t _KEYCHAIN_INFO[] =
    {
        {.name      = "system root",
         .file_path = "/System/Library/Keychains/SystemRootCertificates.keychain"},
        {.name      = "system",
         .file_path = "/Library/Keychains/System.keychain"}};

/*!
 * @brief       Get basic information about the specified keychain.
 * @param[in]   keychain_type   Keychain type
 * @return      The keychain information.  All pointers contained in this
 *              point to read only data and so do not need to be freed.
 */
static keychain_info_t _get_keychain_info(keychain_type_t keychain_type)
{
    return _KEYCHAIN_INFO[keychain_type];
}

/*!
 * @brief       Get a reference to an allocated array of certificates contained
 *              in the specified keychain.
 * @param[in]   keychain_type   Keychain type
 * @return      If successful, reference to allocated array of certificates. The
 *              caller is responsible for calling CFRelease on the returned
 *              reference after use.
 * @return      NULL otherwise
 */
static CFTypeRef _get_cert_ref(keychain_type_t keychain_type)
{
    keychain_info_t kc_info = _get_keychain_info(keychain_type);

    CFTypeRef keys[] = {
        kSecMatchSearchList,
        kSecClass,
        kSecReturnRef,
        kSecMatchLimit,
        kSecMatchTrustedOnly,
        kSecMatchValidOnDate,
    };
    CFTypeRef values[] = {
        /* NOTE: must match the order specified above */
        kCFNull,              /* place holder for match search list */
        kSecClassCertificate, /* kSecClass */
        kCFBooleanTrue,       /* kSecReturnRef */
        kSecMatchLimitAll,    /* kSecMatchLimit */
        kCFBooleanTrue,       /* kSecMatchTrustedOnly */
        kCFNull,              /* kSecMatchValidOnDate */
    };

    CFDictionaryRef query = NULL;
    CFTypeRef items       = NULL;

    SecKeychainRef keychain = NULL;
    CFArrayRef search_list  = NULL;

    SecKeychainStatus keychainStatus = 0;

    OSStatus status;

    status = SecKeychainOpen(kc_info.file_path, &keychain);

    if (status != errSecSuccess) {
        mprintf(LOGG_ERROR, "Failed to open %s keychain: %s (%d)\n",
                kc_info.name,
                kc_info.file_path,
                status);
        goto done;
    }

    status = SecKeychainGetStatus(keychain, &keychainStatus);
    if (status != errSecSuccess) {
        mprintf(LOGG_ERROR, "Failed to get the status of the %s keychain: %d\n",
                kc_info.name,
                status);
        goto done;
    }
    if (!(keychainStatus & kSecReadPermStatus)) {
        mprintf(LOGG_ERROR, "The %s keychain is not readable: %" PRIu32 "\n",
                kc_info.name,
                keychainStatus);
        goto done;
    }

    if (keychain_type == KEYCHAIN_TYPE_SYSTEM_ROOT) {
        /*
         * The SystemRootCertificates.keychain is a system keychain file that should be locked
         * and should definitely not have writable permissions.  This may indicate that the file
         * has been tampered with.
         */
        if (keychainStatus & (kSecUnlockStateStatus | kSecWritePermStatus)) {
            mprintf(LOGG_ERROR, "System Root Certificates Keychain has invalid permissions: %" PRIu32 "\n",
                    keychainStatus);
            /* continue on error */
        }
    }

    search_list = CFArrayCreate(kCFAllocatorDefault,
                                (const void **)&keychain, 1, &kCFTypeArrayCallBacks);
    if (search_list == NULL) {
        mprintf(LOGG_ERROR, "Failed to create %s keychain search list\n",
                kc_info.name);
        goto done;
    }

    /* set the search list for the secItemCopyMatching call */
    values[0] = search_list;

    query = CFDictionaryCreate(NULL, keys, values, ARRAY_SIZE(keys),
                               &kCFCopyStringDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    if (query == NULL) {
        mprintf(LOGG_ERROR, "Failed to create %s keychain query dictionary\n",
                kc_info.name);
        goto done;
    }

    status = SecItemCopyMatching(query, &items);
    if (status != errSecSuccess) {
        if (status == errSecItemNotFound) {
            mprintf(LOGG_DEBUG, "No items found in %s keychain\n",
                    kc_info.name);
        } else {
            mprintf(LOGG_ERROR, "Unable to copy certificates from %s keychain (%d)\n",
                    kc_info.name,
                    status);
        }
    }

    CFRelease(query);
    query = NULL;
done:
    if (keychain) {
        CFRelease(keychain);
        keychain = NULL;
    }
    if (search_list) {
        CFRelease(search_list);
        search_list = NULL;
    }
    return items;
}

cl_error_t cert_store_load(X509 **trusted_certs, size_t trusted_cert_count)
{
    static const keychain_type_t keychains[] = {
        KEYCHAIN_TYPE_SYSTEM_ROOT,
        KEYCHAIN_TYPE_SYSTEM};

    typedef struct keychain_cert_data {
        CFArrayRef certs;
        CFIndex certs_count;
    } keychain_cert_data_t;

    keychain_cert_data_t keychain_cert_data_array[ARRAY_SIZE(keychains)] = {
        {.certs       = NULL,
         .certs_count = 0},
        /* All other array values initialized to 0 by default */
    };

    size_t kc_index = 0;

    cl_error_t ret = CL_EOPEN;
    int pt_err;

    cert_store_t *store        = NULL;
    CFIndex total_certificates = 0;
    CFIndex i                  = 0;
    bool locked                = false;

    store = cert_store_get_int();
    if (!store) {
        mprintf(LOGG_ERROR, "Failed to retrieve cert store\n");
        goto done;
    }

    /* Load certificates from keychains before entering the critical section.
     * On a default 10.12 installation loading the system roots keychain
     * could take up to 300 ms to complete. */

    for (kc_index = 0; kc_index < ARRAY_SIZE(keychains); kc_index++) {
        keychain_type_t kc            = keychains[kc_index];
        keychain_info_t kc_info       = _get_keychain_info(kc);
        keychain_cert_data_t *kc_data = &keychain_cert_data_array[kc_index];
        CFTypeRef items               = NULL;

        items = _get_cert_ref(kc);
        if (!items) {
            continue;
        }

        if (CFGetTypeID(items) != CFArrayGetTypeID()) {
            mprintf(LOGG_ERROR, "Expected array of certificates from %s keychain, "
                    "got type %lu\n",
                    kc_info.name,
                    CFGetTypeID(items));
            continue;
        }

        if (CFArrayGetCount(items) < 1) {
            CFRelease(items);
            items = NULL;
            continue;
        }

        kc_data->certs       = (CFArrayRef)items;
        kc_data->certs_count = CFArrayGetCount(items);

        mprintf(LOGG_DEBUG, "Found %ld certificates from %s keychain\n",
                kc_data->certs_count,
                kc_info.name);

        total_certificates += kc_data->certs_count;
    }

    if (total_certificates < 1) {
        mprintf(LOGG_ERROR, "No certificate found in keychains. Expect at least one "
                "certificate to be found in system root and system "
                "keychains\n");
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
        mprintf(LOGG_DEBUG, "Cert store already loaded\n");
        ret = CL_SUCCESS;
        goto done;
    }

    store->system_certs.count        = 0;
    store->system_certs.certificates = calloc(total_certificates,
                                              sizeof(*store->system_certs.certificates));
    if (store->system_certs.certificates == NULL) {
        mprintf(LOGG_ERROR, "Failed to reserve memory for system cert list\n");
        goto done;
    }

    for (kc_index = 0; kc_index < ARRAY_SIZE(keychains); kc_index++) {
        keychain_type_t kc            = keychains[kc_index];
        keychain_info_t kc_info       = _get_keychain_info(kc);
        keychain_cert_data_t *kc_data = &keychain_cert_data_array[kc_index];

        for (i = 0; i < kc_data->certs_count; i++) {
            const void *value = CFArrayGetValueAtIndex(kc_data->certs, i);

            if (CFGetTypeID(value) == SecCertificateGetTypeID()) {
                SecCertificateRef cert = (SecCertificateRef)value;
                CFDataRef cert_data    = SecCertificateCopyData(cert); /* DER representation of X.509 */

                if (cert_data) {
                    const unsigned char *der = CFDataGetBytePtr(cert_data);
                    CFIndex length           = CFDataGetLength(cert_data);

                    char *name = NULL;
                    X509 *x509 = d2i_X509(NULL, &der, length);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
                    x509_get_cert_name(x509, &name);
#else
                    name = x509->name;
#endif

                    if (x509) {
                        mprintf(LOGG_DEBUG, "Found %s trusted certificate %s\n",
                                kc_info.name,
                                (name ? name : "<no name>"));

                        store->system_certs.certificates[store->system_certs.count++] = x509;
                    } else {
                        mprintf(LOGG_ERROR, "Failed conversion of DER format to X.509\n");
                    }
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
                    if (NULL != name) {
                        free(name);
                        name = NULL;
                    }
#endif

                    CFRelease(cert_data);
                    cert_data = NULL;
                }
            }
        }
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

    for (kc_index = 0; kc_index < ARRAY_SIZE(keychains); kc_index++) {
        keychain_cert_data_t *kc_data = &keychain_cert_data_array[kc_index];

        if (kc_data->certs) {
            CFRelease(kc_data->certs);
            kc_data->certs       = NULL;
            kc_data->certs_count = 0;
        }
    }

    return ret;
}
