/*
 *  Copyright (C) 2009 Sourcefire, Inc.
 *
 *  Authors: aCaB
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

/* 7zip scanner */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "others.h"
#include "lzma_iface.h"
#include "scanners.h"
#include "matcher.h"
#include "7z/7zFile.h"
#include "7z/7zCrc.h"
#include "7z/Archive/7z/7zIn.h"
#include "7z/Archive/7z/7zExtract.h"

static ISzAlloc allocImp = { __lzma_wrap_alloc, __lzma_wrap_free}, allocTempImp = { __lzma_wrap_alloc, __lzma_wrap_free};

int cli_7unz (int fd, cli_ctx *ctx) {
    CFileInStream archiveStream;
    CLookToRead lookStream;
    CSzArEx db;
    UInt32 blockIndex = 0xFFFFFFFF;
    unsigned char *buf = NULL;
    size_t bufsz = 0;
    UInt32 i;
    int dupfd, ret = CL_CLEAN;
    unsigned int fu=0;

    if((dupfd = dup(fd)) == -1) {
	cli_errmsg("cli_7unz: dup() failed\n");
	return CL_EDUP;
    }
    FileInStream_CreateVTable(&archiveStream);
    archiveStream.file.file = fdopen(dupfd, "rb");
    if(!archiveStream.file.file) {
	cli_errmsg("cli_7unz: fdopen() failed\n");
	return CL_EOPEN;
    }
    LookToRead_CreateVTable(&lookStream, False);
    lookStream.realStream = &archiveStream.s;
    LookToRead_Init(&lookStream);

    SzArEx_Init(&db);
    if(SzArEx_Open(&db, &lookStream.s, &allocImp, &allocTempImp) != SZ_OK) {
	SzArEx_Free(&db, &allocImp);
	cli_dbgmsg("cli_7unz: possibly damaged archive\n");
	return CL_CLEAN;
    }
    for (i = 0; i < db.db.NumFiles; i++) {
	CSzFileItem *f = db.db.Files + i;
        size_t offset;
        size_t usize;

	if(f->IsDir || !f->Size) continue;
	if(ctx->engine->maxfilesize && f->Size > ctx->engine->maxfilesize) {
	    cli_dbgmsg("cli_7unz: skipping stream due to size limits (%llu vs %llu)\n", (long long)f->Size, (long long)ctx->engine->maxfilesize);
	    continue;
	}
	if(cli_matchmeta(ctx, f->Name, 0, f->Size, 0, i + 1, 0, NULL) == CL_VIRUS) {
	    ret = CL_VIRUS;
	    break;
	}
	if (ctx->engine->maxfiles && fu>=ctx->engine->maxfiles) {
	    cli_dbgmsg("cli_7unz: Files limit reached (max: %u)\n", ctx->engine->maxfiles);
	    ret=CL_EMAXFILES;
	    break;
	}
	cli_dbgmsg("cli_7unz: Extracting file %s\n", f->Name);
	if(SzAr_Extract(&db, &lookStream.s, i, &blockIndex, &buf, &bufsz, &offset, &usize, &allocImp, &allocTempImp) == SZ_OK) {
	    char *fname;
	    int ofd;

	    if(!usize) {
		cli_dbgmsg("cli_7unz: stream uncompressed to an empty file\n");
		continue;
	    }
	    fu++;
	    if(!(fname = cli_gentemp(ctx->engine->tmpdir))) {
		ret = CL_EMEM;
		break;
	    }
	    if((ofd = open(fname, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRUSR|S_IWUSR)) < 0) {
		cli_errmsg("cli_7unz: failed to create file %s\n", fname);
		free(fname);
		ret = CL_ECREAT;
		break;
	    }
	    if(cli_writen(ofd, buf, usize) <= 0) {
		close(ofd);
		if(cli_unlink(fname)) ret = CL_EUNLINK;
		else ret = CL_EWRITE;
		free(fname);
		break;
	    }
	    cli_dbgmsg("cli_7unz: extracted to %s\n", fname);
	    lseek(ofd, 0, SEEK_SET);
	    ret = cli_magic_scandesc(ofd, ctx);
	    close(ofd);
	    if(!ctx->engine->keeptmp)
		if(cli_unlink(fname)) ret = CL_EUNLINK;
	    free(fname);
	    if(ret == CL_EUNLINK || ret == CL_VIRUS)
		break;
	} else {
	    cli_dbgmsg("cli_7unz: decompression failed\n");
	}
    }
    if(buf) free(buf);
    SzArEx_Free(&db, &allocImp);
    fclose(archiveStream.file.file);
    return ret;
}
