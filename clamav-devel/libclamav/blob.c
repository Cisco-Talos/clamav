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
 * $Log: blob.c,v $
 * Revision 1.14  2004/08/01 08:20:58  nigelhorne
 * Scan pathnames in Cygwin
 *
 * Revision 1.13  2004/06/16 08:07:39  nigelhorne
 * Added thread safety
 *
 * Revision 1.12  2004/05/21 11:31:48  nigelhorne
 * Fix logic error in blobClose
 *
 * Revision 1.11  2004/04/17 14:18:58  nigelhorne
 * Some filenames not scanned in MACOS/X
 *
 * Revision 1.10  2004/03/25 22:40:46  nigelhorne
 * Removed even more calls to realloc and some duplicated code
 *
 * Revision 1.9  2004/03/24 09:08:25  nigelhorne
 * Reduce number of calls to cli_realloc for FreeBSD performance
 *
 * Revision 1.8  2004/03/23 10:58:52  nigelhorne
 * More restrictive about which characters can be used in filename on DOS based systems
 *
 * Revision 1.7  2004/02/15 08:45:53  nigelhorne
 * Avoid scanning the same file twice
 *
 * Revision 1.6  2004/02/10 19:23:54  nigelhorne
 * Change LOG to Log
 *
 */
static	char	const	rcsid[] = "$Id: blob.c,v 1.14 2004/08/01 08:20:58 nigelhorne Exp $";

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdlib.h>
#include <string.h>
#if	C_DARWIN
#include <sys/types.h>
#endif
#include "mbox.h"
#include "blob.h"
#include "others.h"

#ifndef	CL_DEBUG
#define	NDEBUG	/* map CLAMAV debug onto standard */
#endif

#include <assert.h>

blob *
blobCreate(void)
{
#ifdef	CL_DEBUG
	blob *b = (blob *)cli_calloc(1, sizeof(blob));
	if(b)
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
	assert(b != NULL);
	assert(b->magic == BLOB);
	assert(filename != NULL);

	if(b->name)
		free(b->name);
	b->name = strdup(filename);

	if(b->name) {
		char *ptr;

		for(ptr = b->name; *ptr; ptr++) {
#if	defined(MSDOS) || defined(C_CYGWIN) || defined(WIN32)
			if(strchr("/*?<>|\"+=,;: ", *ptr))
#elif   defined(C_DARWIN)
			if((*ptr == '/') || (*ptr >= '\200'))
#else
			if(*ptr == '/')
#endif
				*ptr = '_';
		}
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

	if(b->isClosed) {
		/*
		 * Should be cli_dbgmsg, but I want to see them for now,
		 * and cli_dbgmsg doesn't support debug levels
		 */
		cli_warnmsg("Reopening closed blob\n");
		b->isClosed = 0;
	}
	if(b->data == NULL) {
		assert(b->len == 0);
		assert(b->size == 0);

		b->size = len * 4;
		b->data = cli_malloc(b->size);
	} else if(b->size < b->len + len) {
		unsigned char *p = cli_realloc(b->data, b->size + (len * 4));

		if(p == NULL)
			return;

		b->size += len * 4;
		b->data = p;
	}

	if(b->data) {
		memcpy(&b->data[b->len], data, len);
		b->len += len;
	}
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

void
blobClose(blob *b)
{
	/*
	 * Nothing more is going to be added to this blob. If it'll save more
	 * than a trivial amount (say 64 bytes) of memory, shrink the allocation
	 */
	if((b->size - b->len) >= 64) {
		unsigned char *ptr = cli_realloc(b->data, b->len);

		if(ptr == NULL)
			return;

		cli_dbgmsg("blobClose: recovered %u bytes from %u\n",
			b->size - b->len, b->size);
		b->size = b->len;
		b->data = ptr;
	}
	b->isClosed = 1;
}

/*
 * Returns 0 if the blobs are the same
 */
int
blobcmp(const blob *b1, const blob *b2)
{
	unsigned long s1, s2;

	assert(b1 != NULL);
	assert(b2 != NULL);

	if(b1 == b2)
		return 0;

	s1 = blobGetDataSize(b1);
	s2 = blobGetDataSize(b2);

	if(s1 != s2)
		return 1;

	return memcmp(blobGetData(b1), blobGetData(b2), s1);
}

void
blobGrow(blob *b, size_t len)
{
	assert(b != NULL);
	assert(b->magic == BLOB);

	if(len == 0)
		return;

	if(b->isClosed) {
		/*
		 * Should be cli_dbgmsg, but I want to see them for now,
		 * and cli_dbgmsg doesn't support debug levels
		 */
		cli_warnmsg("Growing closed blob\n");
		b->isClosed = 0;
	}
	if(b->data == NULL) {
		assert(b->len == 0);
		assert(b->size == 0);

		b->data = cli_malloc(len);
		if(b->data)
			b->size = len;
	} else {
		unsigned char *ptr = cli_realloc(b->data, b->size + len);

		if(ptr) {
			b->size += len;
			b->data = ptr;
		}
	}
}
