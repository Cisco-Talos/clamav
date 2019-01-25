/*
 *  Compilation: gcc -Wall ex1.c -o ex1 -lclamav
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <clamav.h>

/*
 * Exit codes:
 *  0: clean
 *  1: infected
 *  2: error
 */

int main(int argc, char **argv)
{
	int fd, ret;
	unsigned long int size = 0;
	unsigned int sigs = 0;
	long double mb;
	const char *virname;
    const char *filename;
	struct cl_engine *engine;
    struct cl_scan_options options;

    if(argc != 2) {
	printf("Usage: %s file\n", argv[0]);
	return 2;
    }

    filename = argv[1];

    if((fd = open(argv[1], O_RDONLY)) == -1) {
	printf("Can't open file %s\n", argv[1]);
	return 2;
    }

    if((ret = cl_init(CL_INIT_DEFAULT)) != CL_SUCCESS) {
	printf("Can't initialize libclamav: %s\n", cl_strerror(ret));
	return 2;
    }

    if(!(engine = cl_engine_new())) {
	printf("Can't create new engine\n");
	return 2;
    }

    /* load all available databases from default directory */
    if((ret = cl_load(cl_retdbdir(), engine, &sigs, CL_DB_STDOPT)) != CL_SUCCESS) {
	printf("cl_load: %s\n", cl_strerror(ret));
	close(fd);
        cl_engine_free(engine);
	return 2;
    }

    printf("Loaded %u signatures.\n", sigs);

    /* build engine */
    if((ret = cl_engine_compile(engine)) != CL_SUCCESS) {
	printf("Database initialization error: %s\n", cl_strerror(ret));;
        cl_engine_free(engine);
	close(fd);
	return 2;
    }

    /* scan file descriptor */
    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0; /* enable all parsers */
    options.general |= CL_SCAN_GENERAL_HEURISTICS; /* enable heuristic alert options */

    if((ret = cl_scandesc(fd, filename, &virname, &size, engine, &options)) == CL_VIRUS) {
	printf("Virus detected: %s\n", virname);
    } else {
	if(ret == CL_CLEAN) {
	    printf("No virus detected.\n");
	} else {
	    printf("Error: %s\n", cl_strerror(ret));
	    cl_engine_free(engine);
	    close(fd);
	    return 2;
	}
    }
    close(fd);

    /* free memory */
    cl_engine_free(engine);

    /* calculate size of scanned data */
    mb = size * (CL_COUNT_PRECISION / 1024) / 1024.0;
    printf("Data scanned: %2.2Lf MB\n", mb);

    return ret == CL_VIRUS ? 1 : 0;
}
