/*
 *  Copyright (C) 2002 Nigel Horne <njh@bandsman.co.uk>
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
 *
 * $LOG$
 */
static	char	const	rcsid[] = "$Id: blob.c,v 1.4 2004/02/06 13:46:08 kojm Exp $";

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdlib.h>
#include <string.h>
#if	C_DARWIN
#include <sys/types.h>
#include <sys/malloc.h>
#else
#ifdef HAVE_MALLOC_H /* tk: FreeBSD-CURRENT doesn't support malloc.h */
#include <malloc.h>
#endif
#endif
#include "mbox.h"
#include "blob.h"
#include "others.h"


/*#define	OPTIMIZE_SPACE	/* for machines short of RAM */

#ifndef	CL_DEBUG
#define	NDEBUG	/* map CLAMAV debug onto standard */
#endif

#include <assert.h>

blob *
blobCreate(void)
{
#ifdef	CL_DEBUG
	blob *b = (blob *)cli_calloc(1, sizeof(blob));
	b->magic = BLOB;
	cli_dbgmsg("blobCreate\n");
	return b;
#else
	return (blob *)cli_calloc(1, sizeof(blob));
#endif
}

void
blobDestroy(blob *b)
{
#ifdef	CL_DEBUG
	cli_dbgmsg("blobDestroy %d\n", b->magic);
#else
	cli_dbgmsg("blobDestroy\n");
#endif

	assert(b != NULL);
	assert(b->magic == BLOB);

	if(b->name)
		free(b->name);
	if(b->data)
		free(b->data);
#ifdef	CL_DEBUG
	b->magic = INVALID;
#endif
	free(b);
}

void
blobArrayDestroy(blob *blobList[], int n)
{
	while(--n >= 0) {
		cli_dbgmsg("blobArrayDestroy: %d\n", n);
		if(blobList[n]) {
			blobDestroy(blobList[n]);
			blobList[n] = NULL;
		}
	}
}

void
blobSetFilename(blob *b, const char *filename)
{
	char *ptr;

	assert(b != NULL);
	assert(b->magic == BLOB);
	assert(filename != NULL);

	if(b->name)
		free(b->name);
	b->name = strdup(filename);

	assert(b->name != NULL);

	for(ptr = b->name; *ptr; ptr++) {
#ifdef	MSDOS
		if((*ptr == '/') || (*ptr == '\\'))
#else
		if(*ptr == '/')
#endif
			*ptr = '_';
	}

	cli_dbgmsg("blobSetFilename: %s\n", filename);
}

const char *
blobGetFilename(const blob *b)
{
	assert(b != NULL);
	assert(b->magic == BLOB);

	return(b->name);
}

void
blobAddData(blob *b, const unsigned char *data, size_t len)
{
	assert(b != NULL);
	assert(b->magic == BLOB);
	assert(data != NULL);

	if(len == 0)
		return;

	if(b->data == NULL) {
		assert(b->len == 0);
#ifdef	OPTIMIZE_SPACE
		b->size = len * 4;
#else
		b->size = 128 * 1024;
#endif

		b->data = cli_malloc(b->size);
	} else if(b->size < b->len + len) {
#ifdef	OPTIMIZE_SPACE
		b->size += len * 4;
#else
		b->size += 128 * 1024;
#endif
		b->data = cli_realloc(b->data, b->size);
	}

	assert(b->data != NULL);

	memcpy(&b->data[b->len], data, len);
	b->len += len;
}

unsigned char *
blobGetData(const blob *b)
{
	assert(b != NULL);
	assert(b->magic == BLOB);

	return(b->data);
}

unsigned long
blobGetDataSize(const blob *b)
{
	assert(b != NULL);
	assert(b->magic == BLOB);

	return(b->len);
}
