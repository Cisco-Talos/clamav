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
 * Revision 1.28  2004/12/21 16:42:10  nigelhorne
 * Patch for OS/2
 *
 * Revision 1.27  2004/12/16 15:29:51  nigelhorne
 * Tidy
 *
 * Revision 1.26  2004/12/04 17:03:19  nigelhorne
 * Fix filename handling on MACOS/X
 *
 * Revision 1.25  2004/11/29 13:15:41  nigelhorne
 * Avoid crash if the output file didn't open
 *
 * Revision 1.24  2004/10/01 13:50:47  nigelhorne
 * Minor code tidy
 *
 * Revision 1.23  2004/09/21 09:26:35  nigelhorne
 * Closing a closed blob is no longer fatal
 *
 * Revision 1.22  2004/09/18 14:59:26  nigelhorne
 * Code tidy
 *
 * Revision 1.21  2004/09/06 08:34:47  nigelhorne
 * Randomise extracted file names from tar file
 *
 * Revision 1.20  2004/08/30 11:35:45  nigelhorne
 * Now compiles on AIX and OSF
 *
 * Revision 1.19  2004/08/27 16:39:38  nigelhorne
 * Fix MACOS/X filenames
 *
 * Revision 1.18  2004/08/27 09:41:44  nigelhorne
 * Better filename handling in MACOS/X
 *
 * Revision 1.17  2004/08/23 10:23:58  nigelhorne
 * Fix compilation problem on Cygwin
 *
 * Revision 1.16  2004/08/22 15:08:58  nigelhorne
 * messageExport
 *
 * Revision 1.15  2004/08/22 10:34:24  nigelhorne
 * Use fileblob
 *
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
static	char	const	rcsid[] = "$Id: blob.c,v 1.28 2004/12/21 16:42:10 nigelhorne Exp $";

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/param.h>	/* for NAME_MAX */

#ifdef	C_DARWIN
#include <sys/types.h>
#endif

#include "mbox.h"
#include "blob.h"
#include "others.h"

#ifndef	CL_DEBUG
#define	NDEBUG	/* map CLAMAV debug onto standard */
#endif

/* Maximum filenames under various systems */
#ifndef	NAME_MAX	/* e.g. Linux */

#ifdef	MAXNAMELEN	/* e.g. Solaris */
#define	NAME_MAX	MAXNAMELEN
#else

#ifdef	FILENAME_MAX	/* e.g. SCO */
#define	NAME_MAX	FILENAME_MAX
#endif

#endif

#endif

#ifndef	O_BINARY
#define	O_BINARY	0
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
	assert(blobList != NULL);

	while(--n >= 0) {
		cli_dbgmsg("blobArrayDestroy: %d\n", n);
		if(blobList[n]) {
			blobDestroy(blobList[n]);
			blobList[n] = NULL;
		}
	}
}

/*ARGSUSED*/
void
blobSetFilename(blob *b, const char *dir, const char *filename)
{
	assert(b != NULL);
	assert(b->magic == BLOB);
	assert(filename != NULL);

	cli_dbgmsg("blobSetFilename: %s\n", filename);

	if(b->name)
		free(b->name);

	b->name = strdup(filename);

	if(b->name)
		sanitiseName(b->name);
}

const char *
blobGetFilename(const blob *b)
{
	assert(b != NULL);
	assert(b->magic == BLOB);

	return b->name;
}

void
blobAddData(blob *b, const unsigned char *data, size_t len)
{
#ifdef	HAVE_GETPAGESIZE
	static int pagesize;
	int growth;
#endif

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
	/*
	 * The payoff here is between reducing the number of calls to
	 * malloc/realloc and not overallocating memory. A lot of machines
	 * are more tight with memory than one may imagine which is why
	 * we don't just allocate a *huge* amount and be done with it. Closing
	 * the blob helps because that reclaims memory. If you know the maximum
	 * size of a blob before you start adding data, use blobGrow() that's
	 * the most optimum
	 */
#ifdef	HAVE_GETPAGESIZE
	if(pagesize == 0) {
		pagesize = getpagesize();
		if(pagesize == 0)
			pagesize = 4096;
	}
	growth = pagesize;
	if(len >= pagesize)
		growth = ((len / pagesize) + 1) * pagesize;

	/*printf("len %u, growth = %u\n", len, growth);*/

	if(b->data == NULL) {
		assert(b->len == 0);
		assert(b->size == 0);

		b->size = growth;
		b->data = cli_malloc(growth);
	} else if(b->size < b->len + len) {
		unsigned char *p = cli_realloc(b->data, b->size + growth);

		if(p == NULL)
			return;

		b->size += growth;
		b->data = p;
	}
#else
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
#endif

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
	assert(b != NULL);
	assert(b->magic == BLOB);

	if(b->isClosed) {
		cli_dbgmsg("Attempt to close a previously closed blob\n");
		return;
	}

	/*
	 * Nothing more is going to be added to this blob. If it'll save more
	 * than a trivial amount (say 64 bytes) of memory, shrink the allocation
	 */
	if((b->size - b->len) >= 64) {
		if(b->len == 0) {	/* Not likely */
			free(b->data);
			b->data = NULL;
			cli_dbgmsg("blobClose: recovered all %u bytes\n",
				b->size);
			b->size = 0;
		} else {
			unsigned char *ptr = cli_realloc(b->data, b->len);

			if(ptr == NULL)
				return;

			cli_dbgmsg("blobClose: recovered %u bytes from %u\n",
				b->size - b->len, b->size);
			b->size = b->len;
			b->data = ptr;
		}
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

	if((s1 == 0) && (s2 == 0))
		return 0;

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

fileblob *
fileblobCreate(void)
{
#ifdef	CL_DEBUG
	fileblob *fb = (fileblob *)cli_calloc(1, sizeof(fileblob));
	if(fb)
		fb->b.magic = BLOB;
	cli_dbgmsg("blobCreate\n");
	return fb;
#else
	return (fileblob *)cli_calloc(1, sizeof(fileblob));
#endif
}

void
fileblobDestroy(fileblob *fb)
{
	assert(fb != NULL);

	if(fb->b.name && fb->fp) {
		if(ftell(fb->fp) == 0L) {
			cli_dbgmsg("fileblobDestroy: not saving empty file\n");
			unlink(fb->b.name);
		}
		fclose(fb->fp);
		free(fb->b.name);

		assert(fb->b.data == NULL);
	} else if(fb->b.data) {
		cli_errmsg("fileblobDestroy: file not saved: report to bugs@clamav.net\n");
		free(fb->b.data);
		if(fb->b.name)
			free(fb->b.name);
	}
	free(fb);
}

void
fileblobSetFilename(fileblob *fb, const char *dir, const char *filename)
{
	int fd;
	const char *suffix;
	size_t suffixLen = 0;
	char fullname[NAME_MAX + 1];

	if(fb->b.name)
		return;

	/*
	 * Some programs are broken and use an idea of a ".suffix"
	 * to determine the file type rather than looking up the
	 * magic number. CPM has a lot to answer for...
	 * FIXME: the suffix now appears twice in the filename...
	 */
	suffix = strrchr(filename, '.');
	if(suffix == NULL)
		suffix = "";
	else {
		suffixLen = strlen(suffix);
		if(suffixLen > 4) {
			/* Found a full stop which isn't a suffix */
			suffix = "";
			suffixLen = 0;
		}
	}
	blobSetFilename(&fb->b, dir, filename);

	/*
	 * Reload the filename, it may be different from the one we've
	 * asked for, e.g. '/'s taken out
	 */
	filename = blobGetFilename(&fb->b);

	snprintf(fullname, sizeof(fullname) - 1 - suffixLen, "%s/%.*sXXXXXX", dir,
		(int)(sizeof(fullname) - 9 - suffixLen - strlen(dir)), filename);
#if	defined(C_LINUX) || defined(C_BSD) || defined(HAVE_MKSTEMP) || defined(C_SOLARIS) || defined(C_CYGWIN)
	cli_dbgmsg("fileblobSetFilename: mkstemp(%s)\n", fullname);
	fd = mkstemp(fullname);
#else
	(void)mktemp(fullname);
	fd = open(fullname, O_WRONLY|O_CREAT|O_EXCL|O_TRUNC|O_BINARY, 0600);
#endif

	if(fd < 0) {
		cli_errmsg("Can't create temporary file %s: %s\n", fullname, strerror(errno));
		cli_dbgmsg("%lu %d %d\n", suffixLen, sizeof(fullname), strlen(fullname));
		return;
	}

	cli_dbgmsg("Saving attachment as %s\n", fullname);

	fb->fp = fdopen(fd, "wb");

	if(fb->fp == NULL) {
		cli_errmsg("Can't create file %s: %s\n", fullname, strerror(errno));
		cli_dbgmsg("%lu %d %d\n", suffixLen, sizeof(fullname), strlen(fullname));
		close(fd);

		return;
	}
	if(fb->b.data) {
		if(fwrite(fb->b.data, fb->b.len, 1, fb->fp) != 1)
			cli_errmsg("fileblobSetFilename: Can't write to temporary file %s: %s\n", fb->b.name, strerror(errno));
		free(fb->b.data);
		fb->b.data = NULL;
		fb->b.len = fb->b.size = 0;
	}

	/*
	 * Add the suffix back to the end of the filename. Tut-tut, filenames
	 * should be independant of their usage on UNIX type systems.
	 */
	if(suffixLen > 1) {
		char stub[NAME_MAX + 1];

		snprintf(stub, sizeof(stub), "%s%s", fullname, suffix);
#ifdef	C_LINUX
		rename(stub, fullname);
#elif	defined(defined(C_CYGWIN) || defined(C_INTERIX) || defined(C_OS2)
		if(cli_filecopy(stub, filename) == 0)
			unlink(stub);
#else
		link(stub, fullname);
		unlink(stub);
#endif
	}
}

void
fileblobAddData(fileblob *fb, const unsigned char *data, size_t len)
{
	if(len == 0)
		return;

	if(fb->fp) {
		if(fwrite(data, len, 1, fb->fp) != 1)
			cli_errmsg("fileblobAddData: Can't write %u bytes to temporary file %s: %s\n", len, fb->b.name, strerror(errno));
	} else
		blobAddData(&(fb->b), data, len);
}

const char *
fileblobGetFilename(const fileblob *fb)
{
	return blobGetFilename(&(fb->b));
}

/*
 * Different operating systems allow different characters in their filenames
 */
void
sanitiseName(char *name)
{
	while(*name) {
#ifdef	C_DARWIN
		*name &= '\177';
#endif
#if	defined(MSDOS) || defined(C_CYGWIN) || defined(WIN32) || defined(C_OS2)
		if(strchr("/*?<>|\\\"+=,;: ", *name))
#else
		if(*name == '/')
#endif
			*name = '_';
		name++;
	}
}
