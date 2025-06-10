/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2011-2013 Sourcefire, Inc.
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

#if defined(_WIN32)
#include <WinSock2.h>
#include <Windows.h>
#endif

#include "clamav.h"
#include "7z_iface.h"
#include "lzma_iface.h"
#include "scanners.h"
#include "others.h"
#include "fmap.h"

#include "7z/7z.h"
#include "7z/7zAlloc.h"
#include "7z/7zFile.h"

static ISzAlloc allocImp = {__lzma_wrap_alloc, __lzma_wrap_free}, allocTempImp = {__lzma_wrap_alloc, __lzma_wrap_free};

static SRes FileInStream_fmap_Read(void *pp, void *buf, size_t *size)
{
    CFileInStream *p = (CFileInStream *)pp;
    size_t read_sz;

    if (*size == 0)
        return 0;

    read_sz = fmap_readn(p->file.fmap, buf, p->s.curpos, *size);
    if (read_sz == (size_t)-1) {
        *size = 0;
        return SZ_ERROR_READ;
    }

    p->s.curpos += read_sz;

    *size = read_sz;
    return SZ_OK;
}

static SRes FileInStream_fmap_Seek(void *pp, Int64 *pos, ESzSeek origin)
{
    CFileInStream *p = (CFileInStream *)pp;

    switch (origin) {
        case SZ_SEEK_SET:
            p->s.curpos = *pos;
            break;
        case SZ_SEEK_CUR:
            p->s.curpos += *pos;
            *pos = p->s.curpos;
            break;
        case SZ_SEEK_END:
            p->s.curpos = p->file.fmap->len + *pos;
            *pos        = p->s.curpos;
            break;
        default:
            return 1;
    }
    return 0;
}

#define UTFBUFSZ 256
int cli_7unz(cli_ctx *ctx, size_t offset)
{
    CFileInStream archiveStream;
    CLookToRead lookStream;
    CSzArEx db;
    SRes res;
    UInt16 utf16buf[UTFBUFSZ], *utf16name = utf16buf;
    int namelen            = UTFBUFSZ;
    cl_error_t found       = CL_CLEAN;
    Int64 begin_of_archive = offset;

    /* Replacement for
       FileInStream_CreateVTable(&archiveStream); */
    archiveStream.s.Read    = FileInStream_fmap_Read;
    archiveStream.s.Seek    = FileInStream_fmap_Seek;
    archiveStream.s.curpos  = 0;
    archiveStream.file.fmap = ctx->fmap;

    LookToRead_CreateVTable(&lookStream, False);

    if (archiveStream.s.Seek(&archiveStream.s, &begin_of_archive, SZ_SEEK_SET) != 0)
        return CL_CLEAN;

    lookStream.realStream = &archiveStream.s;
    LookToRead_Init(&lookStream);

    SzArEx_Init(&db);
    res = SzArEx_Open(&db, &lookStream.s, &allocImp, &allocTempImp);
    if (res == SZ_ERROR_ENCRYPTED && SCAN_HEURISTIC_ENCRYPTED_ARCHIVE) {
        cli_dbgmsg("cli_7unz: Encrypted header found in archive.\n");
        found = cli_append_potentially_unwanted(ctx, "Heuristics.Encrypted.7Zip");
    } else if (res == SZ_OK) {
        UInt32 i, blockIndex = 0xFFFFFFFF;
        Byte *outBuffer        = 0;
        size_t outBufferSize   = 0;
        unsigned int encrypted = 0;

        for (i = 0; i < db.db.NumFiles; i++) {
            size_t offset           = 0;
            size_t outSizeProcessed = 0;
            const CSzFileItem *f    = db.db.Files + i;
            char *name;
            char *tmp_name;
            size_t j;
            int newnamelen, fd;

            // abort if we would exceed max files or max scan time.
            if ((found = cli_checklimits("7unz", ctx, 0, 0, 0)))
                break;

            if (f->IsDir)
                continue;

            // skip this file if we would exceed max file size or max scan size. (we already checked for the max files and max scan time)
            if (cli_checklimits("7unz", ctx, f->Size, 0, 0))
                continue;

            if (!db.FileNameOffsets)
                newnamelen = 0; /* no filename */
            else {
                newnamelen = SzArEx_GetFileNameUtf16(&db, i, NULL);
                if (newnamelen > namelen) {
                    if (namelen > UTFBUFSZ)
                        free(utf16name);
                    utf16name = cli_max_malloc(newnamelen * 2);
                    if (!utf16name) {
                        found = CL_EMEM;
                        break;
                    }
                    namelen = newnamelen;
                }
                SzArEx_GetFileNameUtf16(&db, i, utf16name);
            }

            name = (char *)utf16name;
            for (j = 0; j < (size_t)newnamelen; j++) /* FIXME */
                name[j] = utf16name[j];
            name[j] = 0;
            cli_dbgmsg("cli_7unz: extracting %s\n", name);

            res = SzArEx_Extract(&db, &lookStream.s, i, &blockIndex, &outBuffer, &outBufferSize, &offset, &outSizeProcessed, &allocImp, &allocTempImp);
            if (res == SZ_ERROR_ENCRYPTED) {
                encrypted = 1;
                if (SCAN_HEURISTIC_ENCRYPTED_ARCHIVE) {
                    cli_dbgmsg("cli_7unz: Encrypted files found in archive.\n");
                    found = cli_append_potentially_unwanted(ctx, "Heuristics.Encrypted.7Zip");
                    if (found != CL_SUCCESS) {
                        break;
                    }
                }
            }
            if (CL_VIRUS == cli_matchmeta(ctx, name, 0, f->Size, encrypted, i, f->CrcDefined ? f->Crc : 0)) {
                found = CL_VIRUS;
                break;
            }
            if (res != SZ_OK)
                cli_dbgmsg("cli_unz: extraction failed with %d\n", res);
            else if ((outBuffer == NULL) || (outSizeProcessed == 0)) {
                cli_dbgmsg("cli_unz: extracted empty file\n");
            } else {
                if ((found = cli_gentempfd(ctx->this_layer_tmpdir, &tmp_name, &fd)))
                    break;

                cli_dbgmsg("cli_7unz: Saving to %s\n", tmp_name);
                if (cli_writen(fd, outBuffer + offset, outSizeProcessed) != outSizeProcessed) {
                    found = CL_EWRITE;
                }

                found = cli_magic_scan_desc(fd, tmp_name, ctx, name, LAYER_ATTRIBUTES_NONE);

                close(fd);
                if (!ctx->engine->keeptmp && cli_unlink(tmp_name))
                    found = CL_EUNLINK;

                free(tmp_name);
                if (found != CL_SUCCESS)
                    break;
            }
        }
        IAlloc_Free(&allocImp, outBuffer);
    }
    SzArEx_Free(&db, &allocImp);
    if (namelen > UTFBUFSZ)
        free(utf16name);

    if (res == SZ_OK)
        cli_dbgmsg("cli_7unz: completed successfully\n");
    else if (res == SZ_ERROR_UNSUPPORTED)
        cli_dbgmsg("cli_7unz: unsupported\n");
    else if (res == SZ_ERROR_MEM)
        cli_dbgmsg("cli_7unz: oom\n");
    else if (res == SZ_ERROR_CRC)
        cli_dbgmsg("cli_7unz: crc mismatch\n");
    else if (res == SZ_ERROR_ENCRYPTED)
        cli_dbgmsg("cli_7unz: encrypted\n");
    else
        cli_dbgmsg("cli_7unz: error %d\n", res);

    return found;
}
