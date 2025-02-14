/*
 *  Copyright (C) 2020-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#include <stdbool.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <clamav.h>

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

/** Max # of bytes to show for archive inspection preview */
#define MAX_PREVIEW 10

cl_error_t inspection_callback(
    int fd,
    const char *type,
    const char **ancestors, // array of null-terminated strings, array size == recursion_level
    size_t parent_file_size,
    const char *file_name,
    size_t file_size,
    const char *file_buffer,
    uint32_t recursion_level,
    uint32_t attributes, // E.g.: was normalized, decrypted, etc. See LAYER_ATTRIBUTES_* flags in clamav.h
    void *context)       // Could be used to retrieve / store contextual information for app
{
    size_t i = 0;

    // printf("Message: %s\n", (char *)context.blah);
    UNUSEDPARAM(context);

    printf("ancestors:          ");
    for (i = 0; i < recursion_level; i++) {
        printf("%s", ancestors[i]);
        if (i + 1 < recursion_level) {
            printf(" > ");
        }
    }
    printf("\n");
    printf("parent size:        %zu\n", parent_file_size);
    printf("file name:          %s\n", file_name);
    printf("file desc:          %d\n", fd);
    printf("file size:          %zu\n", file_size);
    printf("file type:          %s\n", type);
    printf("recursion level:    %u\n", recursion_level);
    printf("decrypted:          %s\n", attributes & LAYER_ATTRIBUTES_DECRYPTED ? "yes" : "no");
    printf("normalized:         %s\n", attributes & LAYER_ATTRIBUTES_NORMALIZED ? "yes" : "no");
    printf("file preview: ");
    for (i = 0; i < MIN(file_size, MAX_PREVIEW); i++) {
        uint8_t byte = file_buffer[i];
        printf("%02x ", byte);
    }
    printf("\n\n");

    return CL_CLEAN; /* keep scanning */
}

cl_error_t post_callback(
    int fd,
    int result,
    const char *virname,
    void *context) // Could be used to retrieve / store contextual information for app
{
    (void)fd;
    (void)context;

    printf("result:             %d\n", result);
    printf("virname:            %s\n", virname);
    printf("\n\n");

    return CL_CLEAN; // respect the original result
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

    int db_fd     = -1;
    int target_fd = -1;

    unsigned long int size = 0;
    long double mb;
    const char *virname;
    const char *filename;
    struct cl_engine *engine = NULL;
    struct cl_scan_options options;
    char database_filepath[256];
    bool created_database = false;

    STATBUF st;
    char *mem = NULL;
    ssize_t bytes_read;
    cl_fmap_t *map = NULL;

    if (argc != 2) {
        printf("Usage: %s file\n", argv[0]);
        return 2;
    }

    filename = argv[1];

    if ((target_fd = open(argv[1], O_RDONLY)) == -1) {
        printf("Can't open file %s\n", argv[1]);
        goto done;
    }

    if (FSTAT(target_fd, &st)) {
        printf("fmap: fstat failed\n");
        goto done;
    }

    if (NULL == (mem = malloc((size_t)st.st_size))) {
        printf("malloc failed, buffer size: %zu\n", (size_t)st.st_size);
        goto done;
    }

    bytes_read = read(target_fd, mem, (size_t)st.st_size);
    if (bytes_read != (ssize_t)st.st_size) {
        printf("read failed, buffer size: %zu\n", (size_t)st.st_size);
        goto done;
    }

    map = cl_fmap_open_memory(mem, (size_t)st.st_size);

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
    /* Example feature usage lowering max scan time to 15 seconds. */
    cl_engine_set_num(engine, CL_ENGINE_MAX_SCANTIME, 15000);
#endif
    cl_engine_set_num(engine, CL_ENGINE_MAX_SCANSIZE, 1024 /*MB*/ * 1024 /*KB*/ * 1024 /*bytes*/);
    cl_engine_set_num(engine, CL_ENGINE_MAX_FILESIZE, 1024 /*MB*/ * 1024 /*KB*/ * 1024 /*bytes*/);

    /* load a pwdb signature, to demonstrate the "was decrypted" feature */
#define PWDB_FILENAME "./ex3.pwdb"
    unsigned int signo = 0;
    if (-1 == (db_fd = open(PWDB_FILENAME, O_CREAT | O_RDWR, 0600))) {
        printf("Failed to create ex3.pwdb database\n");
        goto done;
    }

#define PWDB_SIGNATURE "SignatureName;Engine:80-1000;0;virus"
    if (-1 == write(db_fd, PWDB_SIGNATURE, strlen(PWDB_SIGNATURE))) {
        printf("Failed write to ex3.pwdb database\n");
        goto done;
    }

    if (CL_SUCCESS != (ret = cl_load(PWDB_FILENAME, engine, &signo, CL_DB_STDOPT))) {
        printf("Database load error: %s\n", cl_strerror(ret));
        goto done;
    }

    close(db_fd);

    /* build engine */
    if (CL_SUCCESS != (ret = cl_engine_compile(engine))) {
        printf("Database initialization error: %s\n", cl_strerror(ret));
        goto done;
    }

    /* scan file descriptor */
    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;                           /* enable all parsers */
    options.general |= CL_SCAN_GENERAL_HEURISTICS; /* enable heuristic alert options */
    options.general |= CL_SCAN_GENERAL_ALLMATCHES; /* run in all-match mode, so it keeps looking for alerts after the first one */

    options.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE;
    options.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_DOC;

    /*
     * Set our callbacks for inspecting embedded files during the scan.
     */
    cl_engine_set_clcb_file_inspection(engine, &inspection_callback);
    /*
     * Set our callbacks for inspecting embedded files during the scan.
     */
    cl_engine_set_clcb_post_scan(engine, &post_callback);

    printf("Testing file inspection on FD %d - %s\n", target_fd, filename);

    if (CL_VIRUS == (ret = cl_scanmap_callback(
                         map,
                         filename,
                         &virname,
                         &size,
                         engine,
                         &options,
                         (void *)"Hello, World!"))) {
        printf("Virus detected: %s\n", virname);
    } else {
        if (ret != CL_CLEAN) {
            printf("Error: %s\n", cl_strerror(ret));
            goto done;
        }
    }
    /* calculate size of scanned data */
    mb = size * (CL_COUNT_PRECISION / 1024) / 1024.0;
    printf("Data scanned: %2.2Lf MB\n", mb);

    status = ret == CL_VIRUS ? 1 : 0;

done:

    if (NULL != map) {
        cl_fmap_close(map);
    }
    if (NULL != mem) {
        free(mem);
    }
    unlink(PWDB_FILENAME);
    if (-1 != db_fd) {
        close(db_fd);
    }
    if (-1 != target_fd) {
        close(target_fd);
    }
    if (NULL != engine) {
        cl_engine_free(engine);
    }
    if (true == created_database) {
        unlink(database_filepath);
    }

    return status;
}
