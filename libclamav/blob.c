/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Nigel Horne
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

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
#include "filetypes.h"

#include <assert.h>

/* Scheduled for rewrite in 0.94 (bb#804). Disabling for now */
/* #define	MAX_SCAN_SIZE	20*1024	/\* */
/* 				 * The performance benefit of scanning */
/* 				 * early disappears on medium and */
/* 				 * large sized files */
/* 				 *\/ */

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

/*
 * No longer needed to be growable, so turn into a normal memory area which
 * the caller must free. The passed blob is destroyed
 */
void *
blobToMem(blob *b)
{
	void *ret;

	assert(b != NULL);
	assert(b->magic == BLOBCLASS);

	if(!b->isClosed)
		blobClose(b);
	if(b->name)
		free(b->name);
#ifdef	CL_DEBUG
	b->magic = INVALIDCLASS;
#endif
	ret = (void *)b->data;
	free(b);

	return ret;
}

/*ARGSUSED*/
void
blobSetFilename(blob *b, const char *dir, const char *filename)
{
	assert(b != NULL);
	assert(b->magic == BLOBCLASS);
	assert(filename != NULL);

    UNUSEDPARAM(dir);

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
#if	HAVE_CLI_GETPAGESIZE
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
#if	HAVE_CLI_GETPAGESIZE
	if(pagesize == 0) {
		pagesize = cli_getpagesize();
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
		if(!fb->ctx || !fb->ctx->engine->keeptmp)
			cli_unlink(fb->fullname);
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
				cli_unlink(fb->fullname); 
			}
		}
		free(fb->b.name);

		assert(fb->b.data == NULL);
	} else if(fb->b.data) {
		free(fb->b.data);
		if(fb->b.name) {
			cli_errmsg("fileblobDestroy: %s not saved: report to https://bugzilla.clamav.net\n",
				(fb->fullname) ? fb->fullname : fb->b.name);
			free(fb->b.name);
		} else
			cli_errmsg("fileblobDestroy: file not saved (%lu bytes): report to https://bugzilla.clamav.net\n",
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
fileblobPartialSet(fileblob *fb, const char *fullname, const char *arg)
{
    UNUSEDPARAM(arg);

	if(fb->b.name)
		return;

	assert(fullname != NULL);

	cli_dbgmsg("fileblobPartialSet: saving to %s\n", fullname);

	fb->fd = open(fullname, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY|O_EXCL, 0600);
	if(fb->fd < 0) {
		cli_errmsg("fileblobPartialSet: unable to create file: %s\n",fullname);
		return;
	}
	fb->fp = fdopen(fb->fd, "wb");

	if(fb->fp == NULL) {
		cli_errmsg("fileblobSetFilename: fdopen failed\n");
		close(fb->fd);
		return;
	}
	blobSetFilename(&fb->b, fb->ctx ? fb->ctx->engine->tmpdir : NULL, fullname);
	if(fb->b.data)
		if(fileblobAddData(fb, fb->b.data, fb->b.len) == 0) {
			free(fb->b.data);
			fb->b.data = NULL;
			fb->b.len = fb->b.size = 0;
			fb->isNotEmpty = 1;
		}
	fb->fullname = cli_strdup(fullname);
}

void
fileblobSetFilename(fileblob *fb, const char *dir, const char *filename)
{
	char *fullname;

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
	
	if (cli_gentempfd(dir, &fullname, &fb->fd)!=CL_SUCCESS) return;

	cli_dbgmsg("fileblobSetFilename: file %s saved to %s\n", filename, fullname);

	fb->fp = fdopen(fb->fd, "wb");

	if(fb->fp == NULL) {
		cli_errmsg("fileblobSetFilename: fdopen failed\n");
		close(fb->fd);
		free(fullname);
		return;
	}
	if(fb->b.data)
		if(fileblobAddData(fb, fb->b.data, fb->b.len) == 0) {
			free(fb->b.data);
			fb->b.data = NULL;
			fb->b.len = fb->b.size = 0;
			fb->isNotEmpty = 1;
		}
	fb->fullname = fullname;
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

			if(cli_checklimits("fileblobAddData", ctx, fb->bytes_scanned, 0, 0)!=CL_CLEAN)
			        do_scan = 0;

			if(fb->bytes_scanned > MAX_SCAN_SIZE)
				do_scan = 0;
			if(do_scan) {
				if(ctx->scanned)
					*ctx->scanned += (unsigned long)len / CL_COUNT_PRECISION;
				fb->bytes_scanned += (unsigned long)len;
				
				if((len > 5) && cli_updatelimits(ctx, len)==CL_CLEAN && (cli_scanbuff(data, (unsigned int)len, 0, ctx->virname, ctx->engine, CL_TYPE_BINARY_DATA, NULL) == CL_VIRUS)) {
				    cli_dbgmsg("fileblobAddData: found %s\n", cli_get_last_virus_str(ctx->virname));
					fb->isInfected = 1;
				}
			}
		}
#endif

		if(fwrite(data, len, 1, fb->fp) != 1) {
			cli_errmsg("fileblobAddData: Can't write %lu bytes to temporary file %s\n",
				(unsigned long)len, fb->b.name);
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
	int rc;
	cli_ctx *ctx = fb->ctx;
	STATBUF sb;
	int virus_found = 0;

	if(fb->isInfected)
		return CL_VIRUS;
	if(fb->fp == NULL || fb->fullname == NULL) {
		/* shouldn't happen, scan called before fileblobSetFilename */
		cli_warnmsg("fileblobScan, fullname == NULL\n");
		return CL_ENULLARG;	/* there is no CL_UNKNOWN */
	}
	if(fb->ctx == NULL) {
		/* fileblobSetCTX hasn't been called */
		cli_dbgmsg("fileblobScan, ctx == NULL\n");
		return CL_CLEAN;	/* there is no CL_UNKNOWN */
	}

	fflush(fb->fp);
	lseek(fb->fd, 0, SEEK_SET);
	FSTAT(fb->fd, &sb);
	if(cli_matchmeta(fb->ctx, fb->b.name, sb.st_size, sb.st_size, 0, 0, 0, NULL) == CL_VIRUS) {
            if (!SCAN_ALLMATCHES)
                return CL_VIRUS;
            virus_found = 1;
        }

	rc = cli_magic_scandesc(fb->fd, fb->fullname, fb->ctx);
	if(rc == CL_VIRUS || virus_found != 0) {
		cli_dbgmsg("%s is infected\n", fb->fullname);
		return CL_VIRUS;
	}
	cli_dbgmsg("%s is clean\n", fb->fullname);
	return CL_BREAK;
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
	char c;
	while((c = *name)) {
		if(c!='.' && c!='_' && (c>'z' || c<'0' || (c>'9' && c<'A') || (c>'Z' && c<'a')))
			*name = '_';
		name++;
	}
}
