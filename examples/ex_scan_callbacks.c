/*
 *  Copyright (C) 2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Author: Valerie Snyder
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

/*
 * This example demonstrates using callbacks to record information about each
 * file found during a recursive scan.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <clamav.h>

#ifdef _WIN32
typedef int ssize_t;
#endif

/**
 * @brief Prompt the user for input on what to do next.
 *
 * @return cl_error_t
 */
static cl_error_t prompt_user_for_what_to_do(cl_scan_layer_t *layer, bool is_alert_callback)
{
    printf("What do you want to do?\n");
    printf(" 1) Abort scanning.\n");
    if (is_alert_callback)
        printf(" 2) Ignore alert and keep scanning.\n");
    else
        printf(" 2) Keep scanning.\n");
    if (is_alert_callback)
        printf(" 3) Agree with alert (will keep scanning because all-match mode is on).\n");
    else
        printf(" 3) Mark as infected (will keep scanning because all-match mode is on).\n");
    printf(" 4) Trust this layer (discarding all alerts) and skip the rest of this layer.\n");
    printf(" 5) Request all hashes for next time (will keep scanning).\n");
    printf("👉 ");

    int choice = 0;
    // read a single character without the user having to press enter
    if (scanf("%d", &choice) != 1) {
        // clear stdin
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
        printf("Invalid input. Please enter a number between 1 and 5.\n");
        return prompt_user_for_what_to_do(layer, is_alert_callback);
    }

    switch (choice) {
        case 1: {
            // Abort scanning
            return CL_BREAK;
        }
        case 2: {
            // Ignore alert and keep scanning
            return CL_SUCCESS;
        }
        case 3: {
            // Agree with alert or create new alert (will keep scanning because all-match mode is on)
            return CL_VIRUS;
        }
        case 4: {
            // Trust this layer (discarding all alerts) and skip the rest of this layer
            return CL_VERIFIED;
        }
        case 5: {
            // Request all hashes for next time (will keep scanning)
            cl_fmap_t *fmap = NULL;
            cl_error_t ret;

            /*
             * Indicate we want these hashes calculated later.
             * We could just get the hashes now using cl_fmap_get_hash(),
             * but this is just an example of how to request hashes
             * to be calculated later.
             */
            if (CL_SUCCESS != (ret = cl_scan_layer_get_fmap(layer, &fmap))) {
                printf("❌ cl_scan_layer_get_fmap() failed: %s\n", cl_strerror(ret));
            } else {
                if (CL_SUCCESS != (ret = cl_fmap_will_need_hash_later(fmap, "md5"))) {
                    printf("❌ cl_fmap_will_need_hash_later(md5) failed: %s\n", cl_strerror(ret));
                }
                if (CL_SUCCESS != (ret = cl_fmap_will_need_hash_later(fmap, "sha1"))) {
                    printf("❌ cl_fmap_will_need_hash_later(sha1) failed: %s\n", cl_strerror(ret));
                }
                if (CL_SUCCESS != (ret = cl_fmap_will_need_hash_later(fmap, "sha256"))) {
                    printf("❌ cl_fmap_will_need_hash_later(sha256) failed: %s\n", cl_strerror(ret));
                }
            }
            return is_alert_callback ? CL_VIRUS : CL_SUCCESS;
        }
        default: {
            printf("Invalid choice. Continuing scan.\n");
            return is_alert_callback ? CL_VIRUS : CL_SUCCESS;
        }
    }
}

/**
 * @brief Check if the data matches the given hash.
 *
 * Note: Not bothering with md5 because clamav.h API does not provide it. 🤯
 *
 * @param data The data to check.
 * @param len The length of the data.
 * @param hash_type The type of hash (e.g., "md5", "sha1", "sha256").
 * @param hash The hash to compare against.
 * @return true if the data matches the hash, false otherwise.
 */
static bool check_hash(const uint8_t *data, size_t len, const char *hash_type, const char *hash)
{
    bool status = false;
    uint8_t computed_hash[SHA256_HASH_SIZE];
    unsigned int computed_hash_len = 0;
    size_t i;

    char computed_hash_string[SHA256_HASH_SIZE * 2 + 1] = {0};

    if (strcmp(hash_type, "sha1") == 0) {
        // Compute SHA1 hash of data
        (void)cl_sha1(data, len, computed_hash, &computed_hash_len);
        if (computed_hash_len != SHA1_HASH_SIZE) {
            printf("Unexpected SHA1 hash length: %u\n", computed_hash_len);
            goto done;
        }

        // Convert computed hash to hex string
        for (i = 0; i < SHA1_HASH_SIZE; i++) {
            snprintf(&computed_hash_string[i * 2], 3, "%02x", computed_hash[i]);
        }

    } else if (strcmp(hash_type, "sha256") == 0) {
        // Compute SHA256 hash of data and compare with provided hash
        (void)cl_sha256(data, len, computed_hash, &computed_hash_len);
        if (computed_hash_len != SHA256_HASH_SIZE) {
            printf("Unexpected SHA256 hash length: %u\n", computed_hash_len);
            goto done;
        }

        // Convert computed hash to hex string
        for (i = 0; i < SHA256_HASH_SIZE; i++) {
            snprintf(&computed_hash_string[i * 2], 3, "%02x", computed_hash[i]);
        }

    } else {
        printf("Unsupported hash type: %s\n", hash_type);
        goto done;
    }

    // Compare with provided hash
    if (strcmp(computed_hash_string, hash) != 0) {
        printf("%s hash mismatch: computed %s, expected %s\n", hash_type, computed_hash_string, hash);
        goto done;
    }

    status = true;

done:
    return status;
}

static cl_error_t print_layer_info(cl_scan_layer_t *layer)
{
    cl_error_t status = CL_ERROR;

    cl_fmap_t *fmap         = NULL;
    cl_scan_layer_t *parent = NULL;

    const char *file_type    = NULL;
    uint32_t recursion_level = 0;
    uint64_t object_id       = 0;
    const char *last_alert   = NULL;
    uint32_t attributes      = 0;

    const char *file_name = NULL;

    size_t file_size = 0;

    const char *file_path         = NULL;
    size_t offset_from_path_fn    = 0;
    size_t file_size_from_path_fn = 0;
    int fd_from_path_fn           = -1;
    uint8_t *file_data_from_path  = NULL;

    int fd                      = -1;
    size_t offset_from_fd_fn    = 0;
    size_t file_size_from_fd_fn = 0;
    uint8_t *file_data_from_fd  = NULL;

    const uint8_t *file_data      = NULL;
    size_t file_size_from_data_fn = 0;

    bool have_md5    = false;
    bool have_sha1   = false;
    bool have_sha256 = false;

    const char *md5_hash    = NULL;
    const char *sha1_hash   = NULL;
    const char *sha256_hash = NULL;

    while (NULL != layer) {
        /*
         * Collect, print, and verify attributes for each layer
         */

        if (CL_SUCCESS != (status = cl_scan_layer_get_fmap(layer, &fmap))) {
            printf("❌ cl_scan_layer_get_fmap() failed: %s\n", cl_strerror(status));
            goto done;
        }

        status = cl_scan_layer_get_recursion_level(layer, &recursion_level);
        if (status != CL_SUCCESS) {
            printf("❌ cl_scan_layer_get_recursion_level() failed: %s\n", cl_strerror(status));
            goto done;
        }
        printf("Recursion Level:    " STDu32 "\n", recursion_level);

        status = cl_scan_layer_get_object_id(layer, &object_id);
        if (status != CL_SUCCESS) {
            printf("❌ cl_scan_layer_get_object_id() failed: %s\n", cl_strerror(status));
            goto done;
        }
        printf("Object ID:          " STDu64 "\n", object_id);

        status = cl_fmap_get_name(fmap, &file_name);
        if (status != CL_SUCCESS) {
            printf("❌ cl_fmap_get_name() failed: %s\n", cl_strerror(status));
            goto done;
        }
        printf("File Name:          %s\n", file_name ? file_name : "<no name>");

        status = cl_scan_layer_get_type(layer, &file_type);
        if (status != CL_SUCCESS) {
            printf("❌ cl_scan_layer_get_type() failed: %s\n", cl_strerror(status));
            goto done;
        }
        printf("File Type:          %s\n", file_type ? file_type : "<no type>");

        status = cl_scan_layer_get_attributes(layer, &attributes);
        if (status != CL_SUCCESS) {
            printf("❌ cl_scan_layer_get_attributes() failed: %s\n", cl_strerror(status));
            goto done;
        }
        if (attributes & LAYER_ATTRIBUTES_DECRYPTED) {
            printf("File Attributes:    Decrypted\n");
        }
        if (attributes & LAYER_ATTRIBUTES_NORMALIZED) {
            printf("File Attributes:    Normalized\n");
        }
        if (attributes & LAYER_ATTRIBUTES_EMBEDDED) {
            printf("File Attributes:    Embedded\n");
        }
        if (attributes & LAYER_ATTRIBUTES_NORMALIZED) {
            printf("File Attributes:    Embedded\n");
        }
        if (attributes & LAYER_ATTRIBUTES_RETYPED) {
            printf("File Attributes:    Re-typed\n");
        }
        if (attributes == LAYER_ATTRIBUTES_NONE) {
            printf("File Attributes:    None\n");
        }

        status = cl_scan_layer_get_last_alert(layer, &last_alert);
        if (status != CL_SUCCESS) {
            printf("❌ cl_scan_layer_get_last_alert() failed: %s\n", cl_strerror(status));
            goto done;
        }
        if (last_alert) {
            printf("Last Alert:         %s\n", last_alert);
        }

        /*
         * Get each hash type (if one exists)
         */
        status = cl_fmap_have_hash(fmap, "md5", &have_md5);
        if (status != CL_SUCCESS) {
            printf("❌ cl_fmap_have_hash(md5) failed: %s\n", cl_strerror(status));
            goto done;
        }
        if (have_md5) {
            status = cl_fmap_get_hash(fmap, "md5", &md5_hash);
            if (status != CL_SUCCESS) {
                printf("❌ cl_fmap_get_hash(md5) failed: %s\n", cl_strerror(status));
                goto done;
            }
        }
        printf("MD5 Hash:           %s\n", have_md5 ? md5_hash : "<no hash>");

        status = cl_fmap_have_hash(fmap, "sha1", &have_sha1);
        if (status != CL_SUCCESS) {
            printf("❌ cl_fmap_have_hash(sha1) failed: %s\n", cl_strerror(status));
            goto done;
        }
        if (have_sha1) {
            status = cl_fmap_get_hash(fmap, "sha1", &sha1_hash);
            if (status != CL_SUCCESS) {
                printf("❌ cl_fmap_get_hash(sha1) failed: %s\n", cl_strerror(status));
                goto done;
            }
        }
        printf("SHA1 Hash:          %s\n", have_sha1 ? sha1_hash : "<no hash>");

        status = cl_fmap_have_hash(fmap, "sha256", &have_sha256);
        if (status != CL_SUCCESS) {
            printf("❌ cl_fmap_have_hash(sha256) failed: %s\n", cl_strerror(status));
            goto done;
        }
        if (have_sha256) {
            status = cl_fmap_get_hash(fmap, "sha256", &sha256_hash);
            if (status != CL_SUCCESS) {
                printf("❌ cl_fmap_get_hash(sha256) failed: %s\n", cl_strerror(status));
                goto done;
            }
        }
        printf("SHA256 Hash:        %s\n", have_sha256 ? sha256_hash : "<no hash>");

        status = cl_fmap_get_size(fmap, &file_size);
        if (status != CL_SUCCESS) {
            printf("❌ cl_fmap_get_size() failed: %s\n", cl_strerror(status));
            goto done;
        }
        printf("File Size:          %zu bytes\n", file_size);

        /*
         * Check cl_fmap_get_data()
         */
        status = cl_fmap_get_data(fmap, 0, file_size, &file_data, &file_size_from_data_fn);
        if (status != CL_SUCCESS) {
            printf("❌ cl_fmap_get_data() failed: %s\n", cl_strerror(status));
            goto done;
        }

        /* Verify the alleged size */
        if (file_size_from_data_fn != file_size) {
            printf("❌ Size mismatch: cl_fmap_get_data() => %zu != cl_fmap_get_size() => %zu\n", file_size_from_data_fn, file_size);
            goto done;
        }

        /* Verify the data using the hashes (skip md5 because clamav.h does not provide it 🤭) */
        if (have_sha1) {
            if (!check_hash(file_data, file_size, "sha1", sha1_hash)) {
                printf("❌ SHA1 hash verification failed!\n");
                goto done;
            }
        }
        if (have_sha256) {
            if (!check_hash(file_data, file_size, "sha256", sha256_hash)) {
                printf("❌ SHA256 hash verification failed!\n");
                goto done;
            }
        }

        if (have_sha1 || have_sha256) {
            printf("✔️ Successfully verified data provided by cl_fmap_get_data()\n");
        }

        /*
         * Check cl_fmap_get_path()
         */
        status = cl_fmap_get_path(fmap, &file_path, &offset_from_path_fn, &file_size_from_path_fn);
        if (status != CL_SUCCESS && status != CL_EACCES) {
            printf("❌ cl_fmap_get_path() failed: %s\n", cl_strerror(status));
            goto done;
        }

        if (NULL != file_path) {
            /* Verify the alleged size */
            if (file_size_from_path_fn != file_size) {
                printf("❌ Size mismatch: cl_fmap_get_path() => %zu != cl_fmap_get_size() => %zu\n", file_size_from_path_fn, file_size);
                goto done;
            }

            file_data_from_path = (uint8_t *)malloc(file_size);
            if (NULL == file_data_from_path) {
                printf("❌ malloc() failed\n");
                status = CL_EMEM;
                goto done;
            }

            // read the data from the file path
            fd_from_path_fn = open(file_path, O_RDONLY);
            if (fd_from_path_fn == -1) {
                printf("❌ open(%s) failed\n", file_path);
                status = CL_EOPEN;
                goto done;
            }

            // Seek to the offset
            if (lseek(fd_from_path_fn, offset_from_path_fn, SEEK_SET) == -1) {
                printf("❌ lseek(%s) failed\n", file_path);
                status = CL_ESEEK;
                goto done;
            }

            ssize_t bytes_read = read(fd_from_path_fn, file_data_from_path, file_size);
            if (bytes_read < 0) {
                printf("❌ read(%s) failed. Errno: %s (%d)\n", file_path, strerror(errno), errno);
                status = CL_EREAD;
                goto done;
            }
            if ((size_t)bytes_read != file_size) {
                printf("❌ read(%s) returned %zd bytes, expected %zu bytes\n", file_path, bytes_read, file_size);
                status = CL_EREAD;
                goto done;
            }

            /* verify the data using the hashes (skip md5 because clamav.h does not provide it 🤭) */
            if (have_sha1) {
                if (!check_hash(file_data_from_path, file_size, "sha1", sha1_hash)) {
                    printf("❌ SHA1 hash verification failed!\n");
                    goto done;
                }
            }
            if (have_sha256) {
                if (!check_hash(file_data_from_path, file_size, "sha256", sha256_hash)) {
                    printf("❌ SHA256 hash verification failed!\n");
                    goto done;
                }
            }

            free(file_data_from_path);
            file_data_from_path = NULL;

            close(fd_from_path_fn);
            fd_from_path_fn = -1;

            printf("File Path:          %s\n", file_path);
            printf("Offset in File:     %zu\n", offset_from_path_fn);
            if (have_sha1 || have_sha256) {
                printf("✔️ Successfully verified data read using cl_fmap_get_path()\n");
            }
        } else {
            printf("👌No file path for this layer.\n");
        }

        /*
         * Check cl_fmap_get_fd()
         */
        status = cl_fmap_get_fd(fmap, &fd, &offset_from_fd_fn, &file_size_from_fd_fn);
        if (status != CL_SUCCESS && status != CL_EACCES) {
            printf("❌ cl_fmap_get_fd() failed: %s\n", cl_strerror(status));
            goto done;
        }

        if (-1 != fd) {
            /* Verify the alleged size */
            if (file_size_from_fd_fn != file_size) {
                printf("❌ Size mismatch: cl_fmap_get_fd() => %zu != cl_fmap_get_size() => %zu\n", file_size_from_fd_fn, file_size);
                goto done;
            }

            file_data_from_fd = (uint8_t *)malloc(file_size);
            if (NULL == file_data_from_fd) {
                printf("❌ malloc() failed\n");
                status = CL_EMEM;
                goto done;
            }

            // Seek to the offset
            if (lseek(fd, offset_from_fd_fn, SEEK_SET) == -1) {
                printf("❌ lseek(fd: %d) failed\n", fd);
                status = CL_ESEEK;
                goto done;
            }

            ssize_t bytes_read = read(fd, file_data_from_fd, file_size);
            if (bytes_read < 0) {
                printf("❌ read(fd: %d) failed. Errno: %s (%d)\n", fd, strerror(errno), errno);
                status = CL_EREAD;
                goto done;
            }
            if ((size_t)bytes_read != file_size) {
                printf("❌ read(fd: %d) returned %zd bytes, expected %zu bytes\n", fd, bytes_read, file_size);
                status = CL_EREAD;
                goto done;
            }

            /* Verify the data using the hashes (skip md5 because clamav.h does not provide it 🤭) */
            if (have_sha1) {
                if (!check_hash(file_data_from_fd, file_size, "sha1", sha1_hash)) {
                    printf("❌ SHA1 hash verification failed!\n");
                    goto done;
                }
            }
            if (have_sha256) {
                if (!check_hash(file_data_from_fd, file_size, "sha256", sha256_hash)) {
                    printf("❌ SHA256 hash verification failed!\n");
                    goto done;
                }
            }

            free(file_data_from_fd);
            file_data_from_fd = NULL;

            printf("File Desc:          %d\n", fd);
            printf("Offset in File:     %zu\n", offset_from_fd_fn);
            if (have_sha1 || have_sha256) {
                printf("✔️ Successfully verified data read using cl_fmap_get_fd()\n");
            }
        } else {
            printf("👌No file descriptor for this layer.\n");
        }

        /*
         * Clean up for this layer
         */
        if (NULL != md5_hash) {
            free((void *)md5_hash);
            md5_hash = NULL;
        }
        if (NULL != sha1_hash) {
            free((void *)sha1_hash);
            sha1_hash = NULL;
        }
        if (NULL != sha256_hash) {
            free((void *)sha256_hash);
            sha256_hash = NULL;
        }

        /*
         * Get the parent layer
         */
        status = cl_scan_layer_get_parent_layer(layer, &parent);
        if (status != CL_SUCCESS) {
            printf("❌ cl_scan_layer_get_parent_layer() failed: %s\n", cl_strerror(status));
            goto done;
        }
        layer = parent;

        printf("\n"); // print empty line between layers
    } // while layer != NULL

    status = CL_SUCCESS;

done:
    if (NULL != md5_hash) {
        free((void *)md5_hash);
        md5_hash = NULL;
    }
    if (NULL != sha1_hash) {
        free((void *)sha1_hash);
        sha1_hash = NULL;
    }
    if (NULL != sha256_hash) {
        free((void *)sha256_hash);
        sha256_hash = NULL;
    }
    if (-1 != fd_from_path_fn) {
        close(fd_from_path_fn);
        fd_from_path_fn = -1;
    }
    if (NULL != file_data_from_path) {
        free(file_data_from_path);
        file_data_from_path = NULL;
    }
    if (NULL != file_data_from_fd) {
        free(file_data_from_fd);
        file_data_from_fd = NULL;
    }

    // We don't free the file_data read from cl_fmap_get_data() because
    // the documentation does not say to do so.

    // We don't close the fd from cl_fmap_get_fd() because
    // the documentation does not say to do so.

    return status;
}

cl_error_t pre_hash_callback(cl_scan_layer_t *layer, void *context)
{
    (void)context; // unused

    printf("\n⭐In pre-hash callback⭐\n");
    print_layer_info(layer);

    return prompt_user_for_what_to_do(layer, false);
}

cl_error_t pre_scan_callback(cl_scan_layer_t *layer, void *context)
{
    (void)context; // unused

    printf("\n⭐In pre-scan callback⭐\n");
    print_layer_info(layer);

    return prompt_user_for_what_to_do(layer, false);
}

cl_error_t post_scan_callback(cl_scan_layer_t *layer, void *context)
{
    (void)context; // unused

    printf("\n⭐In post-scan callback⭐\n");
    print_layer_info(layer);

    return prompt_user_for_what_to_do(layer, false);
}

cl_error_t alert_callback(cl_scan_layer_t *layer, void *context)
{
    (void)context; // unused

    printf("\n⭐In alert callback⭐\n");
    print_layer_info(layer);

    return prompt_user_for_what_to_do(layer, true);
}

cl_error_t file_type_callback(cl_scan_layer_t *layer, void *context)
{
    (void)context; // unused

    printf("\n⭐In file-type callback⭐\n");
    print_layer_info(layer);

    return prompt_user_for_what_to_do(layer, false);
}

/*
 * Exit codes:
 *  0: clean
 *  1: infected
 *  2: error
 */

int main(int argc, char **argv)
{
    int status     = 2;
    cl_error_t ret = CL_ERROR;

    int target_fd = -1;

    unsigned long int size = 0;
    long double mb;
    const char *virname;
    const char *filename;
    const char *db_filepath;
    struct cl_engine *engine = NULL;
    struct cl_scan_options options;
    unsigned int signo = 0;

    if (argc != 3) {
        printf("Usage: %s <database> <file>\n", argv[0]);
        return 2;
    }

    db_filepath = argv[1];
    filename    = argv[2];

    if ((target_fd = open(argv[2], O_RDONLY)) == -1) {
        printf("Can't open file %s\n", argv[2]);
        goto done;
    }

    if (CL_SUCCESS != (ret = cl_init(CL_INIT_DEFAULT))) {
        printf("Can't initialize libclamav: %s\n", cl_strerror(ret));
        goto done;
    }

    if (!(engine = cl_engine_new())) {
        printf("Can't create new engine\n");
        goto done;
    }

    /* Example version macro usage to determine if new feature is available */
#if defined(LIBCLAMAV_VERSION_NUM) && (LIBCLAMAV_VERSION_NUM >= 0x090400)
    /* Example feature usage disabling the scan time limit (for this interactive program). */
    cl_engine_set_num(engine, CL_ENGINE_MAX_SCANTIME, 0);
#endif
    /* Example feature usage raising the max file-size and scan-size to 1024MB */
    cl_engine_set_num(engine, CL_ENGINE_MAX_SCANSIZE, 1024 /*MB*/ * 1024 /*KB*/ * 1024 /*bytes*/);
    cl_engine_set_num(engine, CL_ENGINE_MAX_FILESIZE, 1024 /*MB*/ * 1024 /*KB*/ * 1024 /*bytes*/);

    /*
     * Load signatures.
     * At least 1 signature required to initialize stuff required for scanning.
     */
    if (CL_SUCCESS != (ret = cl_load(db_filepath, engine, &signo, CL_DB_STDOPT))) {
        printf("Database initialization error: %s\n", cl_strerror(ret));
        goto done;
    }

    /* Build engine */
    if (CL_SUCCESS != (ret = cl_engine_compile(engine))) {
        printf("Database initialization error: %s\n", cl_strerror(ret));
        goto done;
    }

    /* Enable all parsers plus heuristics, allmatch, and the gen-json metadata feature. */
    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;                                 /* enable all parsers */
    options.general |= CL_SCAN_GENERAL_HEURISTICS;       /* enable heuristic alert options */
    options.general |= CL_SCAN_GENERAL_ALLMATCHES;       /* run in all-match mode, so it keeps looking for alerts after the first one */
    options.general |= CL_SCAN_GENERAL_COLLECT_METADATA; /* collect metadata may enable collecting additional filenames (like in zip) */

    /*
     * Set our callbacks.
     */
    cl_engine_set_scan_callback(engine, &pre_hash_callback, CL_SCAN_CALLBACK_PRE_HASH);
    cl_engine_set_scan_callback(engine, &pre_scan_callback, CL_SCAN_CALLBACK_PRE_SCAN);
    cl_engine_set_scan_callback(engine, &post_scan_callback, CL_SCAN_CALLBACK_POST_SCAN);
    cl_engine_set_scan_callback(engine, &alert_callback, CL_SCAN_CALLBACK_ALERT);
    cl_engine_set_scan_callback(engine, &file_type_callback, CL_SCAN_CALLBACK_FILE_TYPE);

    printf("Testing scan layer callbacks on: %s (fd: %d)\n", filename, target_fd);

    // cl_debug();

    /*
     * Run the scan.
     * Note that the callbacks will be called during this function.
     */
    if (CL_VIRUS == (ret = cl_scandesc_ex(
                         target_fd,
                         filename,
                         &virname,
                         &size,
                         engine,
                         &options,
                         NULL, // context,
                         NULL, // hash_hint,
                         NULL, // hash_out,
                         NULL, // hash_alg,
                         NULL, // file_type_hint,
                         NULL  // file_type_out
                         ))) {
        printf("Virus detected: %s\n", virname);
    } else {
        if (ret != CL_SUCCESS) {
            printf("Error: %s\n", cl_strerror(ret));
            goto done;
        }
    }

    /* Calculate size of scanned data */
    mb = size * (CL_COUNT_PRECISION / 1024) / 1024.0;
    printf("Data scanned: %2.2Lf MB\n", mb);

    status = ret == CL_VIRUS ? 1 : 0;

done:

    if (-1 != target_fd) {
        close(target_fd);
    }
    if (NULL != engine) {
        cl_engine_free(engine);
    }

    return status;
}
