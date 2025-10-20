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

static cl_error_t get_all_calculated_hashes(
    cl_fmap_t *fmap,
    bool *have_md5_out,
    bool *have_sha1_out,
    bool *have_sha256_out,
    char **md5_hash_out,
    char **sha1_hash_out,
    char **sha256_hash_out);

const char *command_list =
    "1  - Return CL_BREAK to abort scanning. Will still encounter POST_SCAN-callbacks on the way out.\n"
    "2  - Return CL_SUCCESS to keep scanning. Will ignore an alert in the ALERT-callback.\n"
    "3  - Return CL_VIRUS to create a new alert and keep scanning. Will agree with alert in the ALERT-callback.\n"
    "4  - Return CL_VERIFIED to trust this layer (discarding all alerts) and skip the rest of this layer.\n"
    "5  - Request md5 hash when it calculates any hash. Does not return from the callback!\n"
    "6  - Request sha1 hash when it calculates any hash. Does not return from the callback!\n"
    "7  - Request sha2-256 hash when it calculates any hash. Does not return from the callback!\n"
    "8  - Get md5 hash. Does not return from the callback!\n"
    "9  - Get sha1 hash. Does not return from the callback!\n"
    "10 - Get sha2-256 hash. Does not return from the callback!\n"
    "11 - Print all hashes that have already been calculated. Does not return from the callback!\n";

/**
 * @brief Select an action based on user input.
 *
 * @param layer             The current scan layer.
 * @param is_alert_callback Indicates if this is an alert callback.
 * @param choice            The user's choice.
 * @return cl_error_t       The result of the action or else CL_EDUP to indicate the caller should run this again
 *                          with another choice. This is so that the user can select an action does not return.
 */
cl_error_t select_choice(cl_scan_layer_t *layer, int choice)
{
    switch (choice) {
        case 1: {
            // Return CL_BREAK to abort scanning. Will still encounter POST_SCAN-callbacks on the way out.
            return CL_BREAK;
        }
        case 2: {
            // Return CL_SUCCESS to keep scanning. Will ignore an alert in the ALERT-callback.
            return CL_SUCCESS;
        }
        case 3: {
            // Return CL_VIRUS to create a new alert and keep scanning. Will agree with alert in the ALERT-callback.
            return CL_VIRUS;
        }
        case 4: {
            // Return CL_VERIFIED to trust this layer (discarding all alerts) and skip the rest of this layer.
            return CL_VERIFIED;
        }
        case 5: {
            // Request md5 hash when it calculates any hash. Does not return from the callback!
            cl_fmap_t *fmap = NULL;
            cl_error_t ret;

            /*
             * Indicate we want this hash calculated later.
             * We could just get the hash now using cl_fmap_get_hash(),
             * but this is just an example of how to request hashes
             * to be calculated later.
             */
            if (CL_SUCCESS != (ret = cl_scan_layer_get_fmap(layer, &fmap))) {
                printf("❌ cl_scan_layer_get_fmap() failed: %s\n", cl_strerror(ret));
            } else {
                if (CL_SUCCESS != (ret = cl_fmap_will_need_hash_later(fmap, "md5"))) {
                    printf("❌ cl_fmap_will_need_hash_later(md5) failed: %s\n", cl_strerror(ret));
                }
            }

            printf("\n✅ Requested md5 hash for next time.\n\n");

            return CL_EDUP; // Indicate the caller should run this again with another choice to a return code.
        }
        case 6: {
            // Request sha1 hash when it calculates any hash. Does not return from the callback!
            cl_fmap_t *fmap = NULL;
            cl_error_t ret;

            /*
             * Indicate we want this hash calculated later.
             * We could just get the hash now using cl_fmap_get_hash(),
             * but this is just an example of how to request hashes
             * to be calculated later.
             */
            if (CL_SUCCESS != (ret = cl_scan_layer_get_fmap(layer, &fmap))) {
                printf("❌ cl_scan_layer_get_fmap() failed: %s\n", cl_strerror(ret));
            } else {
                if (CL_SUCCESS != (ret = cl_fmap_will_need_hash_later(fmap, "sha1"))) {
                    printf("❌ cl_fmap_will_need_hash_later(sha1) failed: %s\n", cl_strerror(ret));
                }
            }

            printf("\n✅ Requested sha1 hash for next time.\n\n");

            return CL_EDUP; // Indicate the caller should run this again with another choice to a return code.
        }
        case 7: {
            // Request sha2-256 hash when it calculates any hash. Does not return from the callback!
            cl_fmap_t *fmap = NULL;
            cl_error_t ret;

            /*
             * Indicate we want this hash calculated later.
             * We could just get the hash now using cl_fmap_get_hash(),
             * but this is just an example of how to request hashes
             * to be calculated later.
             */
            if (CL_SUCCESS != (ret = cl_scan_layer_get_fmap(layer, &fmap))) {
                printf("❌ cl_scan_layer_get_fmap() failed: %s\n", cl_strerror(ret));
            } else {
                if (CL_SUCCESS != (ret = cl_fmap_will_need_hash_later(fmap, "sha256"))) {
                    printf("❌ cl_fmap_will_need_hash_later(sha256) failed: %s\n", cl_strerror(ret));
                }
            }

            printf("\n✅ Requested sha2-256 hash for next time.\n\n");

            return CL_EDUP; // Indicate the caller should run this again with another choice to a return code.
        }
        case 8: {
            // Get md5 hash. Does not return from the callback!
            cl_fmap_t *fmap = NULL;
            cl_error_t ret;
            char *md5_hash = NULL;

            if (CL_SUCCESS != (ret = cl_scan_layer_get_fmap(layer, &fmap))) {
                printf("❌ cl_scan_layer_get_fmap() failed: %s\n", cl_strerror(ret));
                return ret;
            }

            ret = cl_fmap_get_hash(fmap, "md5", &md5_hash);
            if (CL_SUCCESS != ret || !md5_hash) {
                printf("❌ Failed to get md5 hash: %s\n", cl_strerror(CL_ECVD));
                return CL_ECVD;
            }

            printf("\n✅ MD5 Hash: %s\n\n", md5_hash);

            free(md5_hash); // Free the allocated hash string.
            return CL_EDUP; // Indicate the caller should run this again with another choice to a return code.
        }
        case 9: {
            // Get sha1 hash. Does not return from the callback!
            cl_fmap_t *fmap = NULL;
            cl_error_t ret;
            char *sha1_hash = NULL;

            if (CL_SUCCESS != (ret = cl_scan_layer_get_fmap(layer, &fmap))) {
                printf("❌ cl_scan_layer_get_fmap() failed: %s\n", cl_strerror(ret));
                return ret;
            }

            ret = cl_fmap_get_hash(fmap, "sha1", &sha1_hash);
            if (CL_SUCCESS != ret || !sha1_hash) {
                printf("❌ Failed to get sha1 hash: %s\n", cl_strerror(CL_ECVD));
                return CL_ECVD;
            }

            printf("\n✅ SHA1 Hash: %s\n\n", sha1_hash);

            free(sha1_hash); // Free the allocated hash string.
            return CL_EDUP;  // Indicate the caller should run this again with another choice to a return code.
        }
        case 10: {
            // Get sha2-256 hash. Does not return from the callback!
            cl_fmap_t *fmap = NULL;
            cl_error_t ret;
            char *sha2_256_hash = NULL;

            if (CL_SUCCESS != (ret = cl_scan_layer_get_fmap(layer, &fmap))) {
                printf("❌ cl_scan_layer_get_fmap() failed: %s\n", cl_strerror(ret));
                return ret;
            }

            ret = cl_fmap_get_hash(fmap, "sha2-256", &sha2_256_hash);
            if (CL_SUCCESS != ret || !sha2_256_hash) {
                printf("❌ Failed to get sha2-256 hash: %s\n", cl_strerror(CL_ECVD));
                return CL_ECVD;
            }

            printf("\n✅ SHA2-256 Hash: %s\n\n", sha2_256_hash);

            free(sha2_256_hash); // Free the allocated hash string.
            return CL_EDUP;      // Indicate the caller should run this again with another choice to a return code.
        }
        case 11: {
            // Print all hashes that have already been calculated. Does not return from the callback!
            cl_fmap_t *fmap = NULL;
            cl_error_t ret;

            if (CL_SUCCESS != (ret = cl_scan_layer_get_fmap(layer, &fmap))) {
                printf("❌ cl_scan_layer_get_fmap() failed: %s\n", cl_strerror(ret));
                return ret;
            }

            get_all_calculated_hashes(
                fmap,
                NULL, // have_md5_out
                NULL, // have_sha1_out
                NULL, // have_sha256_out
                NULL, // md5_hash_out
                NULL, // sha1_hash_out
                NULL  // sha256_hash_out
            );

            return CL_EDUP; // Indicate the caller should run this again with another choice to a return code.
        }
        default: {
            printf("Invalid choice. Aborting scan.\n");
            return CL_BREAK;
        }
    }
}

/**
 * @brief Prompt the user for input on what to do next.
 *
 * @return cl_error_t
 */
static cl_error_t prompt_user_for_what_to_do(cl_scan_layer_t *layer, bool is_alert_callback)
{
    cl_error_t ret;

    printf("What do you want to do?\n"
           "%s",
           command_list);
    printf("👉 ");

    int choice = 0;
    // read a single character without the user having to press enter
    if (scanf("%d", &choice) != 1) {
        // clear stdin
        int c;
        while ((c = getchar()) != '\n' && c != EOF) {
            continue;
        }
        printf("Invalid input. Please enter a number between 1 and 11.\n");
        return prompt_user_for_what_to_do(layer, is_alert_callback);
    }

    ret = select_choice(layer, choice);
    if (CL_EDUP == ret) {
        // Run this function again to get another choice.
        return prompt_user_for_what_to_do(layer, is_alert_callback);
    }

    return ret;
}

typedef struct {
    int *script_commands;
    size_t num_script_commands;
    size_t current_command_index;
} script_context_t;

void free_script_context(script_context_t *context)
{
    if (context) {
        free(context->script_commands);
        free(context);
    }
}

/**
 * @brief Get the choice from the script which is a series of commands to run that we stored in the script_context.
 *
 * @param context               The script context containing the commands to run.
 * @param layer                 The scan layer.
 * @param is_alert_callback     Whether this is an alert callback.
 * @return cl_error_t
 */
static cl_error_t consult_script_for_what_to_do(script_context_t *context, cl_scan_layer_t *layer)
{
    cl_error_t ret;

    if (context->current_command_index >= context->num_script_commands) {
        printf("No more commands in script. Aborting scan.\n");
        return CL_BREAK;
    }

    int choice = context->script_commands[context->current_command_index++];

    ret = select_choice(layer, choice);
    if (CL_EDUP == ret) {
        // Run this function again to get another choice.
        return consult_script_for_what_to_do(context, layer);
    }

    return ret;
}

/**
 * @brief Read script commands from a file.
 *
 * @param script_filepath    The path to the script file.
 * @return script_context_t* A context containing the script commands, or NULL on failure.
 *                           The caller is responsible for freeing the context with free_script_context().
 */
script_context_t *read_script_commands(const char *script_filepath)
{
    int status = -1;

    script_context_t *context = NULL;

    char *script_contents = NULL;
    FILE *script_file     = NULL;

    if (NULL == script_filepath) {
        printf("No script file provided.\n");
        goto done;
    }

    // Load script commands from file
    script_file = fopen(script_filepath, "r");
    if (!script_file) {
        printf("Can't open script file %s\n", script_filepath);
        goto done;
    }

    // Read the whole file into a string
    fseek(script_file, 0, SEEK_END);
    long script_size = ftell(script_file);
    if (script_size < 0) {
        printf("Error reading script file %s\n", script_filepath);
        goto done;
    }

    fseek(script_file, 0, SEEK_SET);
    script_contents = calloc(script_size + 1, sizeof(char));
    if (!script_contents) {
        printf("Memory allocation failed for script contents\n");
        goto done;
    }

    size_t bytes_read = fread(script_contents, 1, script_size, script_file);
    if (bytes_read != (size_t)script_size && ferror(script_file) != 0) {
        printf("Error reading script file %s. Bytes read: %zu, Script size: %zu\n",
               script_filepath, bytes_read, (size_t)script_size);
        status = 2;
        goto done;
    }

    // Allocate context for script commands
    context = malloc(sizeof(script_context_t));
    if (NULL == context) {
        printf("Memory allocation failed for script context\n");
        goto done;
    }

    context->script_commands       = NULL;
    context->num_script_commands   = 0;
    context->current_command_index = 0;

    // split the script contents into commands
    char *command = strtok(script_contents, "\n");
    while (command != NULL) {
        // Ignore empty lines and comments
        if (strlen(command) > 0 && command[0] != '#') {
            // Allocate more space for the commands
            int *new_commands = realloc(context->script_commands, (context->num_script_commands + 1) * sizeof(int));
            if (new_commands == NULL) {
                printf("Memory allocation failed for script commands\n");
                goto done;
            }
            context->script_commands = new_commands;

            // Get the command as an integer
            char *endptr;
            context->script_commands[context->num_script_commands] = strtol(command, &endptr, 10);
            if (*endptr != '\0') {
                printf("Invalid command in script: %s\n", command);
                goto done;
            }

            context->num_script_commands++;
        }
        command = strtok(NULL, "\n");
    }

    status = 0;

done:
    if (NULL != script_contents) {
        free(script_contents);
    }
    if (NULL != script_file) {
        fclose(script_file);
    }

    if (status != 0) {
        if (NULL != context) {
            free_script_context(context);
            context = NULL;
        }
    }

    return context;
}

/**
 * @brief Check if the data matches the given hash.
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

    if (strcmp(hash_type, "md5") == 0) {
        // Compute MD5 hash of data
        (void)cl_hash_data(hash_type, data, len, computed_hash, &computed_hash_len);
        if (computed_hash_len != MD5_HASH_SIZE) {
            printf("Unexpected MD5 hash length: %u\n", computed_hash_len);
            goto done;
        }

        // Convert computed hash to hex string
        for (i = 0; i < MD5_HASH_SIZE; i++) {
            snprintf(&computed_hash_string[i * 2], 3, "%02x", computed_hash[i]);
        }

    } else if (strcmp(hash_type, "sha1") == 0) {
        // Compute SHA1 hash of data
        (void)cl_hash_data(hash_type, data, len, computed_hash, &computed_hash_len);
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
        (void)cl_hash_data(hash_type, data, len, computed_hash, &computed_hash_len);
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

static cl_error_t get_all_calculated_hashes(
    cl_fmap_t *fmap,
    bool *have_md5_out,
    bool *have_sha1_out,
    bool *have_sha256_out,
    char **md5_hash_out,
    char **sha1_hash_out,
    char **sha256_hash_out)
{
    cl_error_t status = CL_ERROR;

    bool have_md5    = false;
    bool have_sha1   = false;
    bool have_sha256 = false;

    char *md5_hash    = NULL;
    char *sha1_hash   = NULL;
    char *sha256_hash = NULL;

    /*
     * Get each hash type (if one exists)
     */
    status = cl_fmap_have_hash(fmap, "md5", &have_md5);
    if (status != CL_SUCCESS) {
        printf("❌ cl_fmap_have_hash(md5) failed: %s\n", cl_strerror(status));
        goto done;
    }
    if (have_md5) {
        if (have_md5_out) {
            *have_md5_out = true;
        }

        status = cl_fmap_get_hash(fmap, "md5", &md5_hash);
        if (status != CL_SUCCESS) {
            printf("❌ cl_fmap_get_hash(md5) failed: %s\n", cl_strerror(status));
            goto done;
        }

        if (md5_hash_out) {
            *md5_hash_out = md5_hash;
        }
    }
    printf("MD5 Hash:           %s\n", have_md5 ? md5_hash : "<no hash>");

    status = cl_fmap_have_hash(fmap, "sha1", &have_sha1);
    if (status != CL_SUCCESS) {
        printf("❌ cl_fmap_have_hash(sha1) failed: %s\n", cl_strerror(status));
        goto done;
    }
    if (have_sha1) {
        if (have_sha1_out) {
            *have_sha1_out = true;
        }

        status = cl_fmap_get_hash(fmap, "sha1", &sha1_hash);
        if (status != CL_SUCCESS) {
            printf("❌ cl_fmap_get_hash(sha1) failed: %s\n", cl_strerror(status));
            goto done;
        }

        if (sha1_hash_out) {
            *sha1_hash_out = sha1_hash;
        }
    }
    printf("SHA1 Hash:          %s\n", have_sha1 ? sha1_hash : "<no hash>");

    status = cl_fmap_have_hash(fmap, "sha256", &have_sha256);
    if (status != CL_SUCCESS) {
        printf("❌ cl_fmap_have_hash(sha256) failed: %s\n", cl_strerror(status));
        goto done;
    }
    if (have_sha256) {
        if (have_sha256_out) {
            *have_sha256_out = true;
        }

        status = cl_fmap_get_hash(fmap, "sha256", &sha256_hash);
        if (status != CL_SUCCESS) {
            printf("❌ cl_fmap_get_hash(sha256) failed: %s\n", cl_strerror(status));
            goto done;
        }

        if (sha256_hash_out) {
            *sha256_hash_out = sha256_hash;
        }
    }
    printf("SHA256 Hash:        %s\n", have_sha256 ? sha256_hash : "<no hash>");

done:
    return CL_SUCCESS;
}

cl_error_t verify_data_using_hashes(
    const uint8_t *file_data,
    size_t file_size,
    bool have_md5,
    bool have_sha1,
    bool have_sha256,
    char *md5_hash,
    char *sha1_hash,
    char *sha256_hash)
{
    cl_error_t status = CL_ERROR;

    /*
     * Verify the data using the hashes
     */
    if (have_md5 && !check_hash(file_data, file_size, "md5", md5_hash)) {
        printf("❌ MD5 hash verification failed.\n");
        goto done;
    }
    if (have_sha1 && !check_hash(file_data, file_size, "sha1", sha1_hash)) {
        printf("❌ SHA1 hash verification failed.\n");
        goto done;
    }
    if (have_sha256 && !check_hash(file_data, file_size, "sha256", sha256_hash)) {
        printf("❌ SHA256 hash verification failed.\n");
        goto done;
    }

    status = CL_SUCCESS;

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

    char *md5_hash    = NULL;
    char *sha1_hash   = NULL;
    char *sha256_hash = NULL;

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

        status = get_all_calculated_hashes(
            fmap, &have_md5, &have_sha1, &have_sha256,
            &md5_hash, &sha1_hash, &sha256_hash);
        if (status != CL_SUCCESS) {
            printf("❌ Failed to get all calculated hashes: %s\n", cl_strerror(status));
            goto done;
        }

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

        /* verify the data using the hashes */
        status = verify_data_using_hashes(
            file_data, file_size,
            have_md5, have_sha1, have_sha256,
            md5_hash, sha1_hash, sha256_hash);
        if (CL_SUCCESS != status) {
            printf("❌ Hash verification failed for data read from file descriptor.\n");
            goto done;
        }

        if (have_md5 || have_sha1 || have_sha256) {
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

            /* verify the data using the hashes */
            status = verify_data_using_hashes(
                file_data_from_path, file_size,
                have_md5, have_sha1, have_sha256,
                md5_hash, sha1_hash, sha256_hash);
            if (CL_SUCCESS != status) {
                printf("❌ Hash verification failed for data read from file descriptor.\n");
                goto done;
            }

            free(file_data_from_path);
            file_data_from_path = NULL;

            close(fd_from_path_fn);
            fd_from_path_fn = -1;

            printf("File Path:          %s\n", file_path);
            printf("Offset in File:     %zu\n", offset_from_path_fn);
            if (have_md5 || have_sha1 || have_sha256) {
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

            /* verify the data using the hashes */
            status = verify_data_using_hashes(
                file_data_from_fd, file_size,
                have_md5, have_sha1, have_sha256,
                md5_hash, sha1_hash, sha256_hash);
            if (CL_SUCCESS != status) {
                printf("❌ Hash verification failed for data read from file descriptor.\n");
                goto done;
            }

            free(file_data_from_fd);
            file_data_from_fd = NULL;

            printf("File Desc:          %d\n", fd);
            printf("Offset in File:     %zu\n", offset_from_fd_fn);
            if (have_md5 || have_sha1 || have_sha256) {
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
            have_md5 = false;
        }
        if (NULL != sha1_hash) {
            free((void *)sha1_hash);
            sha1_hash = NULL;
            have_sha1 = false;
        }
        if (NULL != sha256_hash) {
            free((void *)sha256_hash);
            sha256_hash = NULL;
            have_sha256 = false;
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

const char *cl_error_t_to_string(cl_error_t clerror)
{
    switch (clerror) {
        case CL_SUCCESS:
            return "CL_SUCCESS";
        case CL_VIRUS:
            return "CL_VIRUS";
        case CL_ENULLARG:
            return "CL_ENULLARG";
        case CL_EARG:
            return "CL_EARG";
        case CL_EMALFDB:
            return "CL_EMALFDB";
        case CL_ECVD:
            return "CL_ECVD";
        case CL_EVERIFY:
            return "CL_EVERIFY";
        case CL_EUNPACK:
            return "CL_EUNPACK";
        case CL_EPARSE:
            return "CL_EPARSE";
        case CL_EOPEN:
            return "CL_EOPEN";
        case CL_ECREAT:
            return "CL_ECREAT";
        case CL_EUNLINK:
            return "CL_EUNLINK";
        case CL_ESTAT:
            return "CL_ESTAT";
        case CL_EREAD:
            return "CL_EREAD";
        case CL_ESEEK:
            return "CL_ESEEK";
        case CL_EWRITE:
            return "CL_EWRITE";
        case CL_EDUP:
            return "CL_EDUP";
        case CL_EACCES:
            return "CL_EACCES";
        case CL_ETMPFILE:
            return "CL_ETMPFILE";
        case CL_ETMPDIR:
            return "CL_ETMPDIR";
        case CL_EMAP:
            return "CL_EMAP";
        case CL_EMEM:
            return "CL_EMEM";
        case CL_ETIMEOUT:
            return "CL_ETIMEOUT";
        case CL_EMAXREC:
            return "CL_EMAXREC";
        case CL_EMAXSIZE:
            return "CL_EMAXSIZE";
        case CL_EMAXFILES:
            return "CL_EMAXFILES";
        case CL_EFORMAT:
            return "CL_EFORMAT";
        case CL_EBYTECODE:
            return "CL_EBYTECODE";
        case CL_EBYTECODE_TESTFAIL:
            return "CL_EBYTECODE_TESTFAIL";
        case CL_ELOCK:
            return "CL_ELOCK";
        case CL_EBUSY:
            return "CL_EBUSY";
        case CL_ESTATE:
            return "CL_ESTATE";
        case CL_ERROR:
            return "CL_ERROR";
        case CL_VERIFIED:
            return "CL_VERIFIED";
        case CL_BREAK:
            return "CL_BREAK";
        default:
            return "Unknown error code";
    }
}

const char *cl_verdict_t_to_string(cl_verdict_t verdict)
{
    switch (verdict) {
        case CL_VERDICT_NOTHING_FOUND:
            return "CL_VERDICT_NOTHING_FOUND";
        case CL_VERDICT_TRUSTED:
            return "CL_VERDICT_TRUSTED";
        case CL_VERDICT_STRONG_INDICATOR:
            return "CL_VERDICT_STRONG_INDICATOR";
        case CL_VERDICT_POTENTIALLY_UNWANTED:
            return "CL_VERDICT_POTENTIALLY_UNWANTED";
        default:
            return "Unknown verdict value";
    }
}

cl_error_t pre_hash_callback(cl_scan_layer_t *layer, void *context)
{
    cl_error_t status;
    script_context_t *script_context = (script_context_t *)context;

    printf("\n⭐In PRE_HASH callback⭐\n");
    print_layer_info(layer);

    if (script_context) {
        status = consult_script_for_what_to_do(script_context, layer);
    } else {
        status = prompt_user_for_what_to_do(layer, false);
    }

    if (CL_EDUP != status) {
        // If the script returned CL_EDUP, we should not continue with the scan.
        printf("↩️Returning: %s\n", cl_error_t_to_string(status));
    }

    return status;
}

cl_error_t pre_scan_callback(cl_scan_layer_t *layer, void *context)
{
    cl_error_t status;
    script_context_t *script_context = (script_context_t *)context;

    printf("\n⭐In PRE_SCAN callback⭐\n");
    print_layer_info(layer);

    if (script_context) {
        status = consult_script_for_what_to_do(script_context, layer);
    } else {
        status = prompt_user_for_what_to_do(layer, false);
    }

    if (CL_EDUP != status) {
        // If the script returned CL_EDUP, we should not continue with the scan.
        printf("↩️Returning: %s\n", cl_error_t_to_string(status));
    }

    return status;
}

cl_error_t post_scan_callback(cl_scan_layer_t *layer, void *context)
{
    cl_error_t status;
    script_context_t *script_context = (script_context_t *)context;

    printf("\n⭐In POST_SCAN callback⭐\n");
    print_layer_info(layer);

    if (script_context) {
        status = consult_script_for_what_to_do(script_context, layer);
    } else {
        status = prompt_user_for_what_to_do(layer, false);
    }

    if (CL_EDUP != status) {
        // If the script returned CL_EDUP, we should not continue with the scan.
        printf("↩️Returning: %s\n", cl_error_t_to_string(status));
    }

    return status;
}

cl_error_t alert_callback(cl_scan_layer_t *layer, void *context)
{
    cl_error_t status;
    script_context_t *script_context = (script_context_t *)context;

    printf("\n⚠️In ALERT callback⚠️\n");
    print_layer_info(layer);

    if (script_context) {
        status = consult_script_for_what_to_do(script_context, layer);
    } else {
        status = prompt_user_for_what_to_do(layer, true);
    }

    if (CL_EDUP != status) {
        // If the script returned CL_EDUP, we should not continue with the scan.
        printf("↩️Returning: %s\n", cl_error_t_to_string(status));
    }

    return status;
}

cl_error_t file_type_callback(cl_scan_layer_t *layer, void *context)
{
    cl_error_t status;
    script_context_t *script_context = (script_context_t *)context;

    printf("\n⭐In FILE_TYPE callback⭐\n");
    print_layer_info(layer);

    if (script_context) {
        status = consult_script_for_what_to_do(script_context, layer);
    } else {
        status = prompt_user_for_what_to_do(layer, false);
    }

    if (CL_EDUP != status) {
        // If the script returned CL_EDUP, we should not continue with the scan.
        printf("↩️Returning: %s\n", cl_error_t_to_string(status));
    }

    return status;
}

static void printBytes(uint64_t bytes)
{
    if (bytes >= (1024 * 1024 * 1024)) {
        printf("%.02f GiB", bytes / (double)(1024 * 1024 * 1024));
    } else if (bytes >= (1024 * 1024)) {
        printf("%.02f MiB", bytes / (double)(1024 * 1024));
    } else if (bytes >= 1024) {
        printf("%.02f KiB", bytes / (double)(1024));
    } else {
        printf("%" PRIu64 " B", bytes);
    }
}

int file_props_callback(const char *j_propstr, int rc, void *context)
{
    (void)context; // Unused in this example

    printf("\n⭐In FILE_PROPS callback⭐\n");

    if (j_propstr) {
        printf("%s\n", j_propstr);
    }

    printf("Metadata JSON Return Code: %s (%d)\n", cl_error_t_to_string((cl_error_t)rc), rc);

    // Pass through the return code so as not to alter the scan return code.
    // A real application might want to handle this differently.
    return rc;
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

    const char *filename        = NULL;
    const char *db_filepath     = NULL;
    const char *script_filepath = NULL;
    const char *hash_hint       = NULL;
    const char *hash_alg        = NULL;
    const char *file_type_hint  = NULL;
    bool allmatch               = true;
    bool gen_json               = false;
    bool debug_mode             = false;

    script_context_t *script_context = NULL;

    uint64_t size = 0;

    cl_verdict_t verdict = CL_VERDICT_NOTHING_FOUND;
    const char *alert_name;

    struct cl_engine *engine = NULL;
    struct cl_scan_options options;
    unsigned int signo = 0;

    char *hash_out      = NULL;
    char *file_type_out = NULL;

    bool disable_cache = false;

    int i = 0;

    const char *help_string =
        "Usage: %s -d <database> -f <file>\n"
        "Example: %s -d /path/to/clamav.db -f /path/to/file.txt\n"
        "\n"
        "Options:\n"
        "--help (-h)                : Help message.\n"
        "--database (-d) FILE       : Path to the ClamAV database.\n"
        "--file (-f)     FILE       : Path to the file to scan.\n"
        "--hash-hint     HASH       : (optional) Hash of file to scan.\n"
        "--hash-alg      ALGORITHM  : (optional) Hash algorithm of hash-hint.\n"
        "                             Will also change the hash algorithm reported at end of scan.\n"
        "--file-type-hint CL_TYPE_* : (optional) File type hint for the file to scan.\n"
        "--script        FILE       : (optional) Path for non-interactive test script.\n"
        "                             Script must be a new-line delimited list of integers from 1-to-5\n"
        "                             Corresponding to the interactive scan options.\n"
        "--one-match (-1)           : Disable allmatch (stops scans after one match).\n"
        "--gen-json                 : Generate scan metadata JSON.\n"
        "--disable-cache            : Disable caching of clean scan results.\n"
        "\n"
        "Scripted scan options are:\n"
        "%s";

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf(help_string, argv[0], argv[0], command_list);
            status = 0;
            goto done;
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--database") == 0) {
            db_filepath = argv[++i];
            printf("Database file: %s\n", db_filepath);
        } else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--file") == 0) {
            filename = argv[++i];
            printf("File to scan: %s\n", filename);
        } else if (strcmp(argv[i], "--script") == 0) {
            script_filepath = argv[++i];
            printf("Script file: %s\n", script_filepath);
        } else if (strcmp(argv[i], "--hash-hint") == 0) {
            hash_hint = argv[++i];
            printf("Hash hint: %s\n", hash_hint);
        } else if (strcmp(argv[i], "--hash-alg") == 0) {
            hash_alg = argv[++i];
            printf("Hash algorithm: %s\n", hash_alg);
        } else if (strcmp(argv[i], "--file-type-hint") == 0) {
            file_type_hint = argv[++i];
            printf("File type hint: %s\n", file_type_hint);
        } else if (strcmp(argv[i], "--one-match") == 0 || strcmp(argv[i], "-1") == 0) {
            allmatch = false;
            printf("Disabling allmatch (stops scans after one match).\n");
        } else if (strcmp(argv[i], "--gen-json") == 0) {
            gen_json = true;
            printf("Enabling scan metadata JSON feature.\n");
        } else if (strcmp(argv[i], "--debug") == 0) {
            debug_mode = true;
            printf("Enabling debug mode.\n");
        } else if (strcmp(argv[i], "--disable-cache") == 0) {
            printf("Disabling caching of clean scan results.\n");
            disable_cache = true;
        } else {
            printf("Unknown option: %s\n", argv[i]);
            printf(help_string, argv[0], argv[0], command_list);
            status = 2;
            goto done;
        }
    }

    printf("\n");

    if (NULL == db_filepath || NULL == filename) {
        printf("Usage: %s <database> <file>\n", argv[0]);
        status = 2;
        goto done;
    }

    if (NULL != script_filepath) {
        printf("Running in non-interactive mode using script: %s\n", script_filepath);
        script_context = read_script_commands(script_filepath);
        if (NULL == script_context) {
            printf("Failed to read script commands from %s\n", script_filepath);
            status = 2;
            goto done;
        }
    }

    if ((target_fd = open(filename, O_RDONLY)) == -1) {
        printf("Can't open file %s\n", filename);
        goto done;
    }

    if (CL_SUCCESS != (ret = cl_init(CL_INIT_DEFAULT))) {
        printf("Can't initialize libclamav: %s\n", cl_strerror(ret));
        goto done;
    }

    if (debug_mode) {
        cl_debug();
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

    if (disable_cache) {
        cl_engine_set_num(engine, CL_ENGINE_DISABLE_CACHE, 1); // Disable cache for clean results
    }

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
    options.parse |= ~0;                           /* enable all parsers */
    options.general |= CL_SCAN_GENERAL_HEURISTICS; /* enable heuristic alert options */
    if (allmatch) {
        options.general |= CL_SCAN_GENERAL_ALLMATCHES; /* run in all-match mode, so it keeps looking for alerts after the first one */
    }
    if (gen_json) {
        options.general |= CL_SCAN_GENERAL_COLLECT_METADATA; /* collect metadata may enable collecting additional filenames (like in zip) */
    }

    /*
     * Set our callbacks.
     */
    cl_engine_set_scan_callback(engine, &pre_hash_callback, CL_SCAN_CALLBACK_PRE_HASH);
    cl_engine_set_scan_callback(engine, &pre_scan_callback, CL_SCAN_CALLBACK_PRE_SCAN);
    cl_engine_set_scan_callback(engine, &post_scan_callback, CL_SCAN_CALLBACK_POST_SCAN);
    cl_engine_set_scan_callback(engine, &alert_callback, CL_SCAN_CALLBACK_ALERT);
    cl_engine_set_scan_callback(engine, &file_type_callback, CL_SCAN_CALLBACK_FILE_TYPE);
    if (gen_json) {
        cl_engine_set_clcb_file_props(engine, &file_props_callback);
    }

    printf("Testing scan layer callbacks on: %s (fd: %d)\n", filename, target_fd);

    /*
     * Run the scan.
     * Note that the callbacks will be called during this function.
     */
    ret = cl_scandesc_ex(
        target_fd,
        filename,
        &verdict,
        &alert_name,
        &size,
        engine,
        &options,
        script_context,
        hash_hint,
        &hash_out,
        hash_alg,
        file_type_hint,
        &file_type_out);

    /* Calculate size of scanned data */
    printf("\n");
    printf("Data scanned: ");
    printBytes(size);
    printf("\n");
    if (hash_out) {
        printf("Hash:         %s\n", hash_out);
    } else {
        printf("No hash provided for this file.\n");
    }
    if (file_type_out) {
        printf("File Type:    %s\n", file_type_out);
    } else {
        printf("No file type provided for this file.\n");
    }
    printf("Verdict:      %s\n", cl_verdict_t_to_string(verdict));
    if (alert_name) {
        printf("Alert Name:   %s\n", alert_name);
    }
    printf("Return Code:  %s (%d)\n", cl_error_t_to_string(ret), ret);

    status = ret == CL_VIRUS ? 1 : 0;

done:

    if (-1 != target_fd) {
        close(target_fd);
    }
    if (NULL != engine) {
        cl_engine_free(engine);
    }
    if (NULL != hash_out) {
        free(hash_out);
    }
    if (NULL != file_type_out) {
        free(file_type_out);
    }
    if (NULL != script_context) {
        free_script_context(script_context);
    }

    return status;
}
