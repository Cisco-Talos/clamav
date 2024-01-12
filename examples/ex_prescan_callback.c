/*
 *  Copyright (C) 2020-2024 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

cl_error_t scan_callback(int fd, const char *type, void *context)
{
    char buf[10];
    ssize_t bytes_read = 0;
    (void)context; /* Could be used to retrieve/store info */

    printf("fd: %u, type: %s, initial bytes: ", fd, type);
    if (-1 != (bytes_read = read(fd, &buf, sizeof(buf)))) {
        /* Was able to read a few bytes */
        ssize_t i = 0;
        for (i = 0; i < bytes_read; i++) {
            printf("%02x", (unsigned int)buf[i]);
        }
        printf("\n");
    }
    return CL_CLEAN; /* keep scanning */
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

    char *db_filepath = NULL;
    int db_fd         = -1;
    int target_fd     = -1;

    unsigned long int size = 0;
    long double mb;
    const char *virname;
    const char *filename;
    struct cl_engine *engine = NULL;
    struct cl_scan_options options;

    if (argc != 2) {
        printf("Usage: %s file\n", argv[0]);
        return 2;
    }

    filename = argv[1];

    if ((target_fd = open(argv[1], O_RDONLY)) == -1) {
        printf("Can't open file %s\n", argv[1]);
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
    /* Example feature usage lowering max scan time to 15 seconds. */
    cl_engine_set_num(engine, CL_ENGINE_MAX_SCANTIME, 15000);
#endif
    cl_engine_set_num(engine, CL_ENGINE_MAX_SCANSIZE, 1024 /*MB*/ * 1024 /*KB*/ * 1024 /*bytes*/);
    cl_engine_set_num(engine, CL_ENGINE_MAX_FILESIZE, 1024 /*MB*/ * 1024 /*KB*/ * 1024 /*bytes*/);

    /* build engine */
    if (CL_SUCCESS != (ret = cl_engine_compile(engine))) {
        printf("Database initialization error: %s\n", cl_strerror(ret));
        goto done;
    }

    /* scan file descriptor */
    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;                                 /* enable all parsers */
    options.general |= CL_SCAN_GENERAL_HEURISTICS;       /* enable heuristic alert options */
    options.general |= CL_SCAN_GENERAL_ALLMATCHES;       /* run in all-match mode, so it keeps looking for alerts after the first one */
    options.general |= CL_SCAN_GENERAL_COLLECT_METADATA; /* collect metadata may enable collecting additional filenames (like in zip) */

    /*
     * Set our callbacks for inspecting embedded files during the scan.
     */
    cl_engine_set_clcb_pre_scan(engine, &scan_callback);

    printf("Testing prescan on FD %d - %s\n", target_fd, filename);

    if (CL_VIRUS == (ret = cl_scandesc(target_fd, filename, &virname, &size, engine, &options))) {
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

    if (-1 != db_fd) {
        close(db_fd);
    }
    if (-1 != target_fd) {
        close(target_fd);
    }
    if (NULL != engine) {
        cl_engine_free(engine);
    }
    if (NULL != db_filepath) {
        free(db_filepath);
    }

    return status;
}
