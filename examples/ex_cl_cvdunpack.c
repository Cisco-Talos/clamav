/*
 *  Compilation: gcc -Wall ex1.c -o ex1 -lclamav
 *
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *  Author: Tomasz Kojm <tkojm@clamav.net>
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

#ifndef O_BINARY
#define O_BINARY 0
#endif

/*
 * Exit codes: 0 is success. See `cl_error_t` enum from clamav.h.
 */
int main(int argc, char **argv)
{
    cl_error_t ret;

    const char *filename;
    const char *destination_directory;
    uint32_t dboptions = 0;

    switch (argc) {
        case 2:
            filename              = argv[1];
            destination_directory = ".";
            break;
        case 3:
            filename              = argv[1];
            destination_directory = argv[2];
            break;
        case 4:
            if (strcmp(argv[1], "--no-verify") == 0) {
                filename              = argv[2];
                destination_directory = argv[3];
                dboptions             = CL_DB_UNSIGNED;
            } else {
                printf("Usage: %s [--no-verify] file [destination_directory]\n", argv[0]);
                return CL_EARG;
            }
            break;
        default:
            printf("Usage: %s [--no-verify] file [destination_directory]\n", argv[0]);
            return CL_EARG;
    }

    // Note: using NULL for certs_directory will disable external digital signature verification.

    ret = cl_cvdunpack_ex(filename, destination_directory, NULL, dboptions);
    if (ret != CL_SUCCESS) {
        printf("ERROR: %s\n", cl_strerror(ret));
    }

    return (int)ret;
}
