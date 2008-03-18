/*
 *  Compilation: gcc -Wall ex1.c -o ex1 -lclamav
 *
 *  Copyright (C) 2007 - 2008 Sourcefire, Inc.
 *  Author: Tomasz Kojm <tkojm@clamav.net>
 *
 *  Copyright (C) 2002 - 2006 Tomasz Kojm <tkojm@clamav.net>
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
	struct cl_engine *engine = NULL;
	struct cl_limits limits;


    if(argc != 2) {
	printf("Usage: %s file\n", argv[0]);
	exit(2);
    }

    if((fd = open(argv[1], O_RDONLY)) == -1) {
	printf("Can't open file %s\n", argv[1]);
	exit(2);
    }

    /* load all available databases from default directory */
    if((ret = cl_load(cl_retdbdir(), &engine, &sigs, CL_DB_STDOPT))) {
	printf("cl_load: %s\n", cl_strerror(ret));
	close(fd);
	exit(2);
    }

    printf("Loaded %d signatures.\n", sigs);

    /* build engine */
    if((ret = cl_build(engine))) {
	printf("Database initialization error: %s\n", cl_strerror(ret));;
	cl_free(engine);
	close(fd);
	exit(2);
    }

    /* set up archive limits */
    memset(&limits, 0, sizeof(struct cl_limits));
    limits.maxscansize = 100 * 1048576; /* during the scanning of archives this
					 * size (100 MB) will never be exceeded
					 */
    limits.maxfilesize = 10 * 1048576; /* compressed files will only be
					* decompressed and scanned up to this
					* size (10 MB)
					*/
    limits.maxfiles = 10000; /* max files */
    limits.maxreclevel = 16; /* maximum recursion level for archives */

    /* scan file descriptor */
    if((ret = cl_scandesc(fd, &virname, &size, engine, &limits, CL_SCAN_STDOPT)) == CL_VIRUS) {
	printf("Virus detected: %s\n", virname);
    } else {
	if(ret == CL_CLEAN) {
	    printf("No virus detected.\n");
	} else {
	    printf("Error: %s\n", cl_strerror(ret));
	    cl_free(engine);
	    close(fd);
	    exit(2);
	}
    }
    close(fd);

    /* calculate size of scanned data */
    mb = size * (CL_COUNT_PRECISION / 1024) / 1024.0;
    printf("Data scanned: %2.2Lf MB\n", mb);

    /* free memory */
    cl_free(engine);

    exit(ret == CL_VIRUS ? 1 : 0);
}
