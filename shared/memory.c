/*
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
#include <unistd.h>

void *mmalloc(size_t size)
{
	void *alloc;

    alloc = malloc(size);

    if(!alloc) {
	fprintf(stderr, "CRITICAL: Can't allocate memory (%ld bytes).\n", (long int) size);
	_exit(71);
	return NULL; /* shut up gcc */
    } else return alloc;
}

void *mcalloc(size_t nmemb, size_t size)
{
	void *alloc;

    alloc = calloc(nmemb, size);

    if(!alloc) {
	fprintf(stderr, "CRITICAL: Can't allocate memory (%ld bytes).\n", (long int) nmemb * size);
	_exit(70);
	return NULL;
    } else return alloc;
}
