/*
 *  Compilation: gcc -Wall ex1.c -o ex1 -lclamav
 *
 *  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <clamav.h>

int main(int argc, char **argv)
{
	int fd, ret, no = 0;
	unsigned long int size = 0;
	long double mb;
	const char *virname;
	struct cl_node *root = NULL;
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

    if((ret = cl_loaddbdir(cl_retdbdir(), &root, &no))) {
	printf("cl_loaddbdir: %s\n", cl_perror(ret));
	close(fd);
	exit(2);
    }

    printf("Loaded %d signatures.\n", no);

    /* build engine */
    if((ret = cl_build(root))) {
	printf("Database initialization error: %s\n", cl_strerror(ret));;
	cl_free(root);
	close(fd);
	exit(2);
    }

    /* set up archive limits */
    memset(&limits, 0, sizeof(struct cl_limits));
    limits.maxfiles = 1000; /* max files */
    limits.maxfilesize = 10 * 1048576; /* maximal archived file size == 10 Mb */
    limits.maxreclevel = 5; /* maximal recursion level */
    limits.maxratio = 200; /* maximal compression ratio */
    limits.archivememlim = 0; /* disable memory limit for bzip2 scanner */

    /* scan descriptor */
    if((ret = cl_scandesc(fd, &virname, &size, root, &limits, CL_SCAN_STDOPT)) == CL_VIRUS)
	printf("Virus detected: %s\n", virname);
    else {
	printf("No virus detected.\n");
	if(ret != CL_CLEAN)
	    printf("Error: %s\n", cl_perror(ret));
    }
    close(fd);

    mb = size * (CL_COUNT_PRECISION / 1024) / 1024.0;
    printf("Data scanned: %2.2Lf Mb\n", mb);

    cl_free(root);
    exit(ret == CL_VIRUS ? 1 : 0);
}
