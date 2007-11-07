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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */
static	char	const	rcsid[] = "$Id: blob.c,v 1.64 2007/02/12 22:25:14 njh Exp $";

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef	C_WINDOWS
#include "stdafx.h"
#include <io.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#ifdef	HAVE_SYS_PARAM_H
#include <sys/param.h>	/* for NAME_MAX */
#endif

#ifdef	C_DARWIN
#include <sys/types.h>
#endif

#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "others.h"
#include "mbox.h"
#include "matcher.h"
#include "scanners.h"

#ifndef	CL_DEBUG
#define	NDEBUG	/* map CLAMAV debug onto standard */
#endif

#ifndef	O_BINARY
#define	O_BINARY	0
#endif

#include <assert.h>

#if	defined(C_MINGW) || defined(C_WINDOWS)
#include <windows.h>
#endif

#define	MAX_SCAN_SIZE	20*1024	/*
				 * The performance benefit of scanning
				 * early disappears on medium and
				 * large sized files
				 */

static	const	char	*blobGetFilename(const blob *b);

blob *
blobCreate(void)
{
#ifdef	CL_DEBUG
	blob *b = (blob *)cli_calloc(1, sizeof(blob));
	if(b)
		b->magic = BLOBCLASS;
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
	assert(b->magic == BLOBCLASS);

	if(b->name)
		free(b->name);
	if(b->data)
		free(b->data);
#ifdef	CL_DEBUG
	b->magic = INVALIDCLASS;
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
	assert(b->magic == BLOBCLASS);
	assert(filename != NULL);

	cli_dbgmsg("blobSetFilename: %s\n", filename);

	if(b->name)
		free(b->name);

	b->name = cli_strdup(filename);

	if(b->name)
		sanitiseName(b->name);
}

static const char *
blobGetFilename(const blob *b)
{
	assert(b != NULL);
	assert(b->magic == BLOBCLASS);

	return b->name;
}

/*
 * Returns <0 for failure
 */
int
blobAddData(blob *b, const unsigned char *data, size_t len)
{
#ifdef	HAVE_GETPAGESIZE
	static int pagesize;
	int growth;
#endif

	assert(b != NULL);
	assert(b->magic == BLOBCLASS);
	assert(data != NULL);

	if(len == 0)
		return 0;

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
	if(len >= (size_t)pagesize)
		growth = ((len / pagesize) + 1) * pagesize;

	/*cli_dbgmsg("blobGrow: b->size %lu, b->len %lu, len %lu, growth = %u\n",
		b->size, b->len, len, growth);*/

	if(b->data == NULL) {
		assert(b->len == 0);
		assert(b->size == 0);

		b->size = growth;
		b->data = cli_malloc(growth);
	} else if(b->size < b->len + (off_t)len) {
		unsigned char *p = cli_realloc(b->data, b->size + growth);

		if(p == NULL)
			return -1;

		b->size += growth;
		b->data = p;
	}
#else
	if(b->data == NULL) {
		assert(b->len == 0);
		assert(b->size == 0);

		b->size = (off_t)len * 4;
		b->data = cli_malloc(b->size);
	} else if(b->size < b->len + (off_t)len) {
		unsigned char *p = cli_realloc(b->data, b->size + (len * 4));

		if(p == NULL)
			return -1;

		b->size += (off_t)len * 4;
		b->data = p;
	}
#endif

	if(b->data) {
		memcpy(&b->data[b->len], data, len);
		b->len += (off_t)len;
	}
	return 0;
}

unsigned char *
blobGetData(const blob *b)
{
	assert(b != NULL);
	assert(b->magic == BLOBCLASS);

	if(b->len == 0)
		return NULL;
	return b->data;
}

size_t
blobGetDataSize(const blob *b)
{
	assert(b != NULL);
	assert(b->magic == BLOBCLASS);

	return b->len;
}

void
blobClose(blob *b)
{
	assert(b != NULL);
	assert(b->magic == BLOBCLASS);

	if(b->isClosed) {
		cli_warnmsg("Attempt to close a previously closed blob\n");
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
			cli_dbgmsg("blobClose: recovered all %lu bytes\n",
				(unsigned long)b->size);
			b->size = 0;
		} else {
			unsigned char *ptr = cli_realloc(b->data, b->len);

			if(ptr == NULL)
				return;

			cli_dbgmsg("blobClose: recovered %lu bytes from %lu\n",
				(unsigned long)(b->size - b->len),
				(unsigned long)b->size);
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
	size_t s1, s2;

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

/*
 * Return clamav return code
 */
int
blobGrow(blob *b, size_t len)
{
	assert(b != NULL);
	assert(b->magic == BLOBCLASS);

	if(len == 0)
		return CL_SUCCESS;

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
			b->size = (off_t)len;
	} else {
		unsigned char *ptr = cli_realloc(b->data, b->size + len);

		if(ptr) {
			b->size += (off_t)len;
			b->data = ptr;
		}
	}

	return (b->data) ? CL_SUCCESS : CL_EMEM;
}

fileblob *
fileblobCreate(void)
{
#ifdef	CL_DEBUG
	fileblob *fb = (fileblob *)cli_calloc(1, sizeof(fileblob));
	if(fb)
		fb->b.magic = BLOBCLASS;
	cli_dbgmsg("blobCreate\n");
	return fb;
#else
	return (fileblob *)cli_calloc(1, sizeof(fileblob));
#endif
}

/*
 * Returns CL_CLEAN or CL_VIRUS. Destroys the fileblob and removes the file
 * if possible
 */
int
fileblobScanAndDestroy(fileblob *fb)
{
	if(cli_leavetemps_flag) {
		/* Can't remove the file, the caller must scan */
		fileblobDestroy(fb);
		return CL_CLEAN;
	}
		
	switch(fileblobScan(fb)) {
		case CL_VIRUS:
			fileblobDestructiveDestroy(fb);
			return CL_VIRUS;
		case CL_BREAK:
			fileblobDestructiveDestroy(fb);
			return CL_CLEAN;
		default:
			fileblobDestroy(fb);
			return CL_CLEAN;
	}
}

/*
 * Destroy the fileblob, and remove the file associated with it
 */
void
fileblobDestructiveDestroy(fileblob *fb)
{
	if(fb->fp && fb->fullname) {
		fclose(fb->fp);
		cli_dbgmsg("fileblobDestructiveDestroy: %s\n", fb->fullname);
		if(unlink(fb->fullname) < 0)
			cli_warnmsg("fileblobDestructiveDestroy: Can't delete file %s\n", fb->fullname);
		free(fb->fullname);
		fb->fp = NULL;
		fb->fullname = NULL;
	}
	if(fb->b.name) {
		free(fb->b.name);
		fb->b.name = NULL;
	}
	fileblobDestroy(fb);
}

/*
 * Destroy the fileblob, and remove the file associated with it if that file is
 * empty
 */
void
fileblobDestroy(fileblob *fb)
{
	assert(fb != NULL);
	assert(fb->b.magic == BLOBCLASS);

	if(fb->b.name && fb->fp) {
		fclose(fb->fp);
		if(fb->fullname) {
			cli_dbgmsg("fileblobDestroy: %s\n", fb->fullname);
			if(!fb->isNotEmpty) {
				cli_dbgmsg("fileblobDestroy: not saving empty file\n");
				if(unlink(fb->fullname) < 0)
					cli_warnmsg("fileblobDestroy: Can't delete empty file %s\n", fb->fullname);
			}
		}
		free(fb->b.name);

		assert(fb->b.data == NULL);
	} else if(fb->b.data) {
		free(fb->b.data);
		if(fb->b.name) {
			cli_errmsg("fileblobDestroy: %s not saved: report to http://bugs.clamav.net\n",
				(fb->fullname) ? fb->fullname : fb->b.name);
			free(fb->b.name);
		} else
			cli_errmsg("fileblobDestroy: file not saved (%lu bytes): report to http://bugs.clamav.net\n",
				(unsigned long)fb->b.len);
	}
	if(fb->fullname)
		free(fb->fullname);
#ifdef	CL_DEBUG
	fb->b.magic = INVALIDCLASS;
#endif
	free(fb);
}

void
fileblobSetFilename(fileblob *fb, const char *dir, const char *filename)
{
	int fd;
	char fullname[NAME_MAX + 1];

	if(fb->b.name)
		return;

	assert(filename != NULL);
	assert(dir != NULL);

	blobSetFilename(&fb->b, dir, filename);

	/*
	 * Reload the filename, it may be different from the one we've
	 * asked for, e.g. '/'s taken out
	 */
	filename = blobGetFilename(&fb->b);

	assert(filename != NULL);

#ifdef	C_QNX6
	/*
	 * QNX6 support from mikep@kaluga.org to fix bug where mkstemp
	 * can return ETOOLONG even when the file name isn't too long
	 */
	snprintf(fullname, sizeof(fullname), "%s/clamavtmpXXXXXXXXXXXXX", dir);
#elif	defined(C_WINDOWS)
	sprintf_s(fullname, sizeof(fullname) - 1, "%s\\%.*sXXXXXX", dir,
		(int)(sizeof(fullname) - 9 - strlen(dir)), filename);
#else
	sprintf(fullname, "%s/%.*sXXXXXX", dir,
		(int)(sizeof(fullname) - 9 - strlen(dir)), filename);
#endif

#if	defined(C_LINUX) || defined(C_BSD) || defined(HAVE_MKSTEMP) || defined(C_SOLARIS) || defined(C_CYGWIN) || defined(C_QNX6)
	cli_dbgmsg("fileblobSetFilename: mkstemp(%s)\n", fullname);
	fd = mkstemp(fullname);
	if((fd < 0) && (errno == EINVAL)) {
		/*
		 * This happens with some Linux flavours when (mis)handling
		 * filenames with foreign characters
		 */
		snprintf(fullname, sizeof(fullname), "%s/clamavtmpXXXXXXXXXXXXX", dir);
		cli_dbgmsg("fileblobSetFilename: retry as mkstemp(%s)\n", fullname);
		fd = mkstemp(fullname);
	}
#elif	defined(C_WINDOWS)
	cli_dbgmsg("fileblobSetFilename: _mktemp_s(%s)\n", fullname);
	if(_mktemp_s(fullname, strlen(fullname) + 1) != 0) {
		char *name;

		/* _mktemp_s only allows 26 files */
		cli_dbgmsg("fileblobSetFilename: _mktemp_s(%s) failed: %s\n", fullname, strerror(errno));
		name = cli_gentemp(dir);
		if(name == NULL)
			return;
		fd = open(name, O_WRONLY|O_CREAT|O_EXCL|O_TRUNC|O_BINARY, 0600);
		if(fd >= 0)
			strncpy(fullname, name, sizeof(fullname) - 1);
		free(name);
	} else
		fd = open(fullname, O_WRONLY|O_CREAT|O_EXCL|O_TRUNC|O_BINARY, 0600);
#else
	cli_dbgmsg("fileblobSetFilename: mktemp(%s)\n", fullname);
	(void)mktemp(fullname);
	fd = open(fullname, O_WRONLY|O_CREAT|O_EXCL|O_TRUNC|O_BINARY, 0600);
#endif

	if(fd < 0) {
		cli_errmsg("Can't create temporary file %s: %s\n", fullname, strerror(errno));
		cli_dbgmsg("%lu %lu\n", (unsigned long)sizeof(fullname),
			(unsigned long)strlen(fullname));
		return;
	}

	cli_dbgmsg("Creating %s\n", fullname);

	fb->fp = fdopen(fd, "wb");

	if(fb->fp == NULL) {
		cli_errmsg("Can't create file %s: %s\n", fullname, strerror(errno));
		cli_dbgmsg("%lu %lu\n", (unsigned long)sizeof(fullname),
			(unsigned long)strlen(fullname));
		close(fd);

		return;
	}
	if(fb->b.data)
		if(fileblobAddData(fb, fb->b.data, fb->b.len) == 0) {
			free(fb->b.data);
			fb->b.data = NULL;
			fb->b.len = fb->b.size = 0;
			fb->isNotEmpty = 1;
		}

	/*
	 * If this strdup fails, then if the file is empty it won't be removed
	 * until later. Since this is only a trivial issue, there is no need
	 * to error if it fails to allocate
	 */
	fb->fullname = cli_strdup(fullname);
}

int
fileblobAddData(fileblob *fb, const unsigned char *data, size_t len)
{
	if(len == 0)
		return 0;

	assert(data != NULL);

	if(fb->fp) {
#if	defined(MAX_SCAN_SIZE) && (MAX_SCAN_SIZE > 0)
		const cli_ctx *ctx = fb->ctx;

		if(fb->isInfected)	/* pretend all was written */
			return 0;
		if(ctx) {
			int do_scan = 1;

			if(ctx->limits)
				if(fb->bytes_scanned >= ctx->limits->maxfilesize)
					do_scan = 0;

			if(fb->bytes_scanned > MAX_SCAN_SIZE)
				do_scan = 0;
			if(do_scan) {
				if(ctx->scanned)
					*ctx->scanned += (unsigned long)len / CL_COUNT_PRECISION;
				fb->bytes_scanned += (unsigned long)len;

				if((len > 5) && (cli_scanbuff(data, (unsigned int)len, ctx->virname, ctx->engine, CL_TYPE_UNKNOWN_DATA) == CL_VIRUS)) {
					cli_dbgmsg("fileblobAddData: found %s\n", *ctx->virname);
					fb->isInfected = 1;
				}
			}
		}
#endif

		if(fwrite(data, len, 1, fb->fp) != 1) {
			cli_errmsg("fileblobAddData: Can't write %lu bytes to temporary file %s: %s\n",
				(unsigned long)len, fb->b.name, strerror(errno));
			return -1;
		}
		fb->isNotEmpty = 1;
		return 0;
	}
	return blobAddData(&(fb->b), data, len);
}

const char *
fileblobGetFilename(const fileblob *fb)
{
	return blobGetFilename(&(fb->b));
}

void
fileblobSetCTX(fileblob *fb, cli_ctx *ctx)
{
	fb->ctx = ctx;
}

/*
 * Performs a full scan on the fileblob, returning ClamAV status:
 *	CL_BREAK means clean
 *	CL_CLEAN means unknown
 *	CL_VIRUS means infected
 */
int
fileblobScan(const fileblob *fb)
{
#ifndef	C_WINDOWS
	int rc, fd;
#endif

	if(fb->isInfected)
		return CL_VIRUS;
	if(fb->fullname == NULL) {
		/* shouldn't happen, scan called before fileblobSetFilename */
		cli_warnmsg("fileblobScan, fullname == NULL\n");
		return CL_ENULLARG;	/* there is no CL_UNKNOWN */
	}
	if(fb->ctx == NULL) {
		/* fileblobSetCTX hasn't been called */
		cli_dbgmsg("fileblobScan, ctx == NULL\n");
		return CL_CLEAN;	/* there is no CL_UNKNOWN */
	}
#ifndef	C_WINDOWS
	/*
	 * FIXME: On Windows, cli_readn gives "bad file descriptor" when called
	 * by cli_check_mydoom_log from the call to cli_magic_scandesc here
	 * which implies that the file descriptor is getting closed somewhere,
	 * but I can't see where.
	 * One possible fix would be to duplicate cli_scanfile here.
	 */
	fflush(fb->fp);
	fd = dup(fileno(fb->fp));
	if(fd == -1) {
		cli_warnmsg("%s: dup failed\n", fb->fullname);
		return CL_CLEAN;
	}
	/* cli_scanfile is static :-( */
	/*if(cli_scanfile(fb->fullname, fb->ctx) == CL_VIRUS) {
		cli_dbgmsg("%s is infected\n", fb->fullname);
		return CL_VIRUS;
	}*/

	rc = cli_magic_scandesc(fd, fb->ctx);
	close(fd);

	if(rc == CL_VIRUS) {
		cli_dbgmsg("%s is infected\n", fb->fullname);
		return CL_VIRUS;
	}
	cli_dbgmsg("%s is clean\n", fb->fullname);
	return CL_BREAK;
#else	/*C_WINDOWS*/
	/* Ensure that the file is saved and scanned */
	return CL_CLEAN;	/* there is no CL_UNKNOWN :-( */
#endif	/*C_WINDOWS*/
}

/*
 * Doesn't perform a full scan just lets the caller know if something suspicious has
 * been seen yet
 */
int
fileblobInfected(const fileblob *fb)
{
	return fb->isInfected;
}

/*
 * Different operating systems allow different characters in their filenames
 * FIXME: What does QNX want? There is no #ifdef C_QNX, but if there were
 * it may be best to treat it like MSDOS
 */
void
sanitiseName(char *name)
{
	while(*name) {
#ifdef	C_DARWIN
		*name &= '\177';
#endif
		/* Also check for tab - "Heinz Martin" <Martin@hemag.ch> */
#if	defined(MSDOS) || defined(C_OS2)
		/*
		 * Don't take it from this that ClamAV supports DOS, it doesn't
		 * I don't know if spaces are legal in OS/2.
		 */
		if(strchr("%/*?<>|\\\"+=,;:\t ~", *name))
#elif	defined(C_CYGWIN) || defined(C_WINDOWS)
		if(strchr("%/*?<>|\\\"+=,;:\t~", *name))
#else
		if(*name == '/')
#endif
			*name = '_';
		name++;
	}
}
