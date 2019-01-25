/*
 * Interface to libclamunrar
 *
 * Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 * Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 * Authors: Trog, Torok Edvin, Tomasz Kojm, Micah Snyder
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "libclamunrar/rar.hpp"
#include "libclamunrar/dll.hpp"

extern "C" {

#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <wchar.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "unrar_iface.h"


#ifndef MIN
   #define MIN(x,y) ((x)<(y)?(x):(y))
#endif

#ifndef MAX
   #define MAX(x,y) ((x)>(y)?(x):(y))
#endif

/* tell compiler about branches that are very rarely taken,
 * such as debug paths, and error paths */
#if (__GNUC__ >= 4) || (__GNUC__ == 3 && __GNUC_MINOR__ >= 2)
#define UNLIKELY(cond) __builtin_expect(!!(cond), 0)
#define LIKELY(cond) __builtin_expect(!!(cond), 1)
#else
#define UNLIKELY(cond) (cond)
#define LIKELY(cond) (cond)
#endif

#define unrar_dbgmsg (!UNLIKELY(unrar_debug)) ? (void)0 : unrar_dbgmsg_internal

#define CMTBUFSIZE (64 * 1024)

int CALLBACK CallbackProc(UINT msg,LPARAM UserData,LPARAM P1,LPARAM P2);

static void unrar_dbgmsg_internal(const char* str, ...)
{
    va_list ap;
    va_start(ap, str);
    vfprintf(stderr, str, ap);
    va_end(ap);
}

uint8_t unrar_debug = 0;

/**
 * @brief  Translate an ERAR_<code> to the appropriate UNRAR_<code>
 *
 * @param errorCode ERAR_<code>
 * @return cl_unrar_error_t UNRAR_OK, UNRAR_ENCRYPTED, or UNRAR_ERR.
 */
static cl_unrar_error_t unrar_retcode(int retcode)
{
    cl_unrar_error_t status = UNRAR_ERR;

    switch (retcode) {
    case ERAR_SUCCESS: {
        unrar_dbgmsg("unrar_retcode: Success!\n");
        status = UNRAR_OK;
        break;
    }
    case ERAR_END_ARCHIVE: {
        unrar_dbgmsg("unrar_retcode: No more files in archive.\n");
        status = UNRAR_BREAK;
        break;
    }
    case ERAR_NO_MEMORY: {
        unrar_dbgmsg("unrar_retcode: Not enough memory!\n");
        status = UNRAR_EMEM;
        break;
    }
    case ERAR_MISSING_PASSWORD: {
        unrar_dbgmsg("unrar_retcode: Encrypted file header found in archive.\n");
        status = UNRAR_ENCRYPTED;
        break;
    }
    case ERAR_BAD_PASSWORD: {
        unrar_dbgmsg("unrar_retcode: Encrypted archive or encrypted file in archive.\n");
        status = UNRAR_ENCRYPTED;
        break;
    }
    case ERAR_BAD_DATA: {
        unrar_dbgmsg("unrar_retcode: Bad data / File CRC error.\n");
        break;
    }
    case ERAR_UNKNOWN_FORMAT: {
        unrar_dbgmsg("unrar_retcode: Unknown archive format.\n");
        break;
    }
    case ERAR_EOPEN: {
        unrar_dbgmsg("unrar_retcode: Volume open error.\n");
        status = UNRAR_EOPEN;
        break;
    }
    case ERAR_ECREATE: {
        unrar_dbgmsg("unrar_retcode: File create error.\n");
        break;
    }
    case ERAR_ECLOSE: {
        unrar_dbgmsg("unrar_retcode: File close error.\n");
        break;
    }
    case ERAR_EREAD: {
        unrar_dbgmsg("unrar_retcode: Read error.\n");
        break;
    }
    case ERAR_EWRITE: {
        unrar_dbgmsg("unrar_retcode: Write error.\n");
        break;
    }
    case ERAR_EREFERENCE: {
        unrar_dbgmsg("unrar_retcode: Error attempting to unpack the reference record without its source file.\n");
        break;
    }
    default: {
        unrar_dbgmsg("unrar_retcode: Unexpected error code: %d\n", retcode);
    }
    }
    return status;
}

static size_t unrar_strnlen(const char *s, size_t n)
{
    size_t i = 0;
    for(; (i < n) && s[i] != '\0'; ++i);
    return i;
}

static char *unrar_strndup(const char *s, size_t n)
{
    char *alloc;
    size_t len;

    if(!s) {
        return NULL;
    }

    len = unrar_strnlen(s, n);
    alloc = (char *)malloc(len+1);

    if(!alloc) {
        return NULL;
    } else
        memcpy(alloc, s, len);

    alloc[len] = '\0';
    return alloc;
}

cl_unrar_error_t unrar_open(const char* filename, void** hArchive, char** comment, uint32_t* comment_size, uint8_t debug_flag)
{
    struct RAROpenArchiveDataEx* archiveData = NULL;
    HANDLE archiveHandle = NULL;
    cl_unrar_error_t status = UNRAR_ERR;

    if (NULL == filename || NULL == hArchive || NULL == comment || NULL == comment_size) {
        unrar_dbgmsg("unrar_open: Invalid arguments.\n");
        goto done;
    }

    /* Enable debug messages in unrar_iface.cpp */
    unrar_debug = debug_flag;

    archiveData = (struct RAROpenArchiveDataEx*)calloc(sizeof(struct RAROpenArchiveDataEx), 1);
    if (archiveData == NULL) {
        unrar_dbgmsg("unrar_open: Not enough memory to allocate main archive header data structure.\n");
        status = UNRAR_EMEM;
    }
    archiveData->ArcName = (char *)filename;
    archiveData->OpenMode = RAR_OM_EXTRACT;
    archiveData->CmtBuf = (char*)calloc(1, CMTBUFSIZE);
    if (archiveData->CmtBuf == NULL) {
        unrar_dbgmsg("unrar_open: Not enough memory to allocate main archive header comment buffer.\n");
        status = UNRAR_EMEM;
    }
    archiveData->CmtBufSize = CMTBUFSIZE;

    if (NULL == (archiveHandle = RAROpenArchiveEx(archiveData))) {
        /* Failed to open archive */
        unrar_dbgmsg("unrar_open: Failed to open archive: %s\n", filename);
        status = unrar_retcode(archiveData->OpenResult);
        goto done;
    }

    switch (archiveData->CmtState) {
    case 0: {
        unrar_dbgmsg("unrar_open: Comments are not present in this archive.\n");
        break;
    }
    case ERAR_BAD_DATA: {
        unrar_dbgmsg("unrar_open: Archive Comments may be broken.\n");
    }
    case ERAR_SMALL_BUF: {
        unrar_dbgmsg("unrar_open: Archive Comments are not present in this file.\n");
    }
    case 1: {
        unrar_dbgmsg("unrar_open: Archive Comments:\n\t %s\n", archiveData->CmtBuf);
        break;
    }
    case ERAR_NO_MEMORY: {
        unrar_dbgmsg("unrar_open: Memory error when reading archive comments!\n");
        status = UNRAR_EMEM;
        break;
    }
    default: {
        unrar_dbgmsg("unrar_open: Unknown archive comment state %u!\n", archiveData->CmtState);
    }
    }

    if (archiveData->CmtSize > 0) {
        *comment_size = MIN(archiveData->CmtSize, archiveData->CmtBufSize);
        *comment = unrar_strndup(archiveData->CmtBuf, *comment_size);
        if (NULL == *comment) {
            unrar_dbgmsg("unrar_open: Error duplicating comment buffer.\n");
            *comment_size = 0;
            status = UNRAR_EMEM;
        }
    }

    unrar_dbgmsg("unrar_open: Volume attribute (archive volume):              %s\n", (archiveData->Flags & ROADF_VOLUME) ? "yes" : "no");
    unrar_dbgmsg("unrar_open: Archive comment present:                        %s\n", (archiveData->Flags & ROADF_COMMENT) ? "yes" : "no");
    unrar_dbgmsg("unrar_open: Archive lock attribute:                         %s\n", (archiveData->Flags & ROADF_LOCK) ? "yes" : "no");
    unrar_dbgmsg("unrar_open: Solid attribute (solid archive):                %s\n", (archiveData->Flags & ROADF_SOLID) ? "yes" : "no");
    unrar_dbgmsg("unrar_open: New volume naming scheme ('volname.partN.rar'): %s\n", (archiveData->Flags & ROADF_NEWNUMBERING) ? "yes" : "no");
    unrar_dbgmsg("unrar_open: Authenticity information present (obsolete):    %s\n", (archiveData->Flags & ROADF_SIGNED) ? "yes" : "no");
    unrar_dbgmsg("unrar_open: Recovery record present:                        %s\n", (archiveData->Flags & ROADF_RECOVERY) ? "yes" : "no");
    unrar_dbgmsg("unrar_open: Block headers are encrypted:                    %s\n", (archiveData->Flags & ROADF_ENCHEADERS) ? "yes" : "no");
    unrar_dbgmsg("unrar_open: First volume (set only by RAR 3.0 and later):   %s\n", (archiveData->Flags & ROADF_FIRSTVOLUME) ? "yes" : "no");

    unrar_dbgmsg("unrar_open: Opened archive: %s\n", filename);
    *hArchive = (void*)archiveHandle;
    status = UNRAR_OK;

done:

    if (NULL != archiveData) {
        if (NULL != archiveData->CmtBuf) {
            free(archiveData->CmtBuf);
            archiveData->CmtBuf = NULL;
        }
        free(archiveData);
    }

    return status;
}

/**
 * @brief  Get file metadata from the next file header.
 *
 * @param hArchive              Handle to the archive we're extracting.
 * @param[in/out] file_metadata Pointer to a pre-allocated metadata structure.
 * @return cl_unrar_error_t     UNRAR_OK if metadata retrieved, UNRAR_BREAK if no more files, UNRAR_ENCRYPTED if header was encrypted, else maybe UNRAR_EMEM or UNRAR_ERR.
 */
cl_unrar_error_t unrar_peek_file_header(void* hArchive, unrar_metadata_t* file_metadata)
{
    cl_unrar_error_t status = UNRAR_ERR;

    struct RARHeaderDataEx headerData;
    int read_header_ret = 0;

    wchar_t RedirName[1024];

    if (NULL == hArchive || NULL == file_metadata) {
        unrar_dbgmsg("unrar_peek_file_header: Invalid arguments.\n");
        goto done;
    }

    memset(&headerData, 0, sizeof(struct RARHeaderDataEx));
    memset(file_metadata, 0, sizeof(unrar_metadata_t));

    /*
     * File header comments are not functional in unrar 5.6.5 and the struct member only exists for backwards compatibility.
     * The unrar user manual says to set headerData.CmtBuff = NULL, and headerData.CmtBufSize = 0.
     */
    headerData.CmtBuf = NULL;
    headerData.CmtBufSize = 0;

    headerData.RedirNameSize = 1024 * sizeof(wchar_t);
    headerData.RedirName = (wchar_t*)&RedirName;
    memset(headerData.RedirName, 0, headerData.RedirNameSize);

    read_header_ret = RARReadHeaderEx(hArchive, &headerData);
    if (ERAR_SUCCESS != read_header_ret) {
        status = unrar_retcode(read_header_ret);
        goto done;
    }

    file_metadata->unpack_size = headerData.UnpSize + ((int64_t)headerData.UnpSizeHigh << 32);
    file_metadata->pack_size = headerData.PackSize + ((int64_t)headerData.PackSizeHigh << 32);
    file_metadata->filename = unrar_strndup(headerData.FileName, 1024);
    file_metadata->crc = headerData.FileCRC;
    file_metadata->encrypted = (headerData.Flags & RHDF_ENCRYPTED) ? 1 : 0;
    file_metadata->is_dir = (headerData.Flags & RHDF_DIRECTORY) ? 1 : 0;
    file_metadata->method = headerData.Method;

    unrar_dbgmsg("unrar_peek_file_header:   Name:          %s\n", headerData.FileName);
    unrar_dbgmsg("unrar_peek_file_header:   Directory?:    %u\n", file_metadata->is_dir);
    unrar_dbgmsg("unrar_peek_file_header:   Target Dir:    %ls\n", headerData.DirTarget);
    unrar_dbgmsg("unrar_peek_file_header:   RAR Version:   %u\n", headerData.UnpVer);
    unrar_dbgmsg("unrar_peek_file_header:   Packed Size:   %lld\n", file_metadata->pack_size);
    unrar_dbgmsg("unrar_peek_file_header:   Unpacked Size: %lld\n", file_metadata->unpack_size);

    // PrintTime("mtime",HeaderData.MtimeLow,HeaderData.MtimeHigh);
    // PrintTime("ctime",HeaderData.CtimeLow,HeaderData.CtimeHigh);
    // PrintTime("atime",HeaderData.AtimeLow,HeaderData.AtimeHigh);

    if (headerData.RedirType != 0) {
        unrar_dbgmsg("unrar_peek_file_header:   link type %d, target %ls\n", headerData.RedirType, headerData.RedirName);
    }

    status = UNRAR_OK;

done:

    if (NULL != headerData.CmtBuf) {
        free(headerData.CmtBuf);
        headerData.CmtBuf = NULL;
    }

    return status;
}

cl_unrar_error_t unrar_extract_file(void* hArchive, const char* destPath, char *outputBuffer)
{
    cl_unrar_error_t status = UNRAR_ERR;
    int process_file_ret = 0;

    if (NULL == hArchive || NULL == destPath) {
        unrar_dbgmsg("unrar_extract_file: Invalid arguments.\n");
        goto done;
    }

    if (NULL != outputBuffer) {
        LPARAM UserData = (LPARAM) outputBuffer;
        RARSetCallback(hArchive, CallbackProc, UserData);
    }

    process_file_ret = RARProcessFile(hArchive, RAR_EXTRACT, NULL, (char *)destPath);
    if (ERAR_BAD_DATA == process_file_ret) {
        unrar_dbgmsg("unrar_extract_file: Warning: Bad data/Invalid CRC. Attempting to scan anyways...\n");
    }
    else if (ERAR_SUCCESS != process_file_ret) {
        status = unrar_retcode(process_file_ret);
        goto done;
    }

#ifdef _WIN32
    unrar_dbgmsg("unrar_extract_file: Extracted file to: %s\n", destPath);
#else
    unrar_dbgmsg("unrar_extract_file: Extracted file to: %s\n", destPath);
#endif

    status = UNRAR_OK;

done:

    return status;
}

cl_unrar_error_t unrar_skip_file(void* hArchive)
{
    cl_unrar_error_t status = UNRAR_ERR;
    int process_file_ret = 0;

    if (NULL == hArchive) {
        unrar_dbgmsg("unrar_skip_file: Invalid arguments.\n");
        goto done;
    }

    process_file_ret = RARProcessFile(hArchive, RAR_SKIP, NULL, NULL);
    if (ERAR_SUCCESS != process_file_ret) {
        status = unrar_retcode(process_file_ret);
        goto done;
    }

    unrar_dbgmsg("unrar_skip_file: File skipped.\n");

    status = UNRAR_OK;

done:

    return status;
}

void unrar_close(void* hArchive)
{
    RARCloseArchive(hArchive);
}

int CALLBACK CallbackProc(UINT msg, LPARAM UserData, LPARAM P1, LPARAM P2)
{
    int status = 1; /* -1 to cancel, 1 to continue */

    switch (msg) {
    case UCM_CHANGEVOLUMEW: {
        /* We don't support RAR's split into multiple volumes
         * ClamAV is not aware of more than 1 file at a time */
        status = -1;
        unrar_dbgmsg("CallbackProc: Archive has multiple volumes, but we don't support multiple volumes.\n");
        break;
    }
    case UCM_PROCESSDATA: {
        char * UserBuffer = (char *)UserData;

        if (UserBuffer == NULL) {
            /* No buffer provided, continue with extraction to a temp file. */
            status = 1;
            unrar_dbgmsg("CallbackProc: Extracting to a new tempfile!\n");
        } else {
            /* Buffer provided, write to it and cancel extraction to the temp file. */
            memcpy(UserBuffer, (char *)P1, P2);

            status = -1;
            unrar_dbgmsg("CallbackProc: Extracting %lu bytes of data to a provided buffer.\n", P2);
        }
        break;
    }
    case UCM_NEEDPASSWORDW: {
        /* Let's try an empty password.  Probably won't work. */
        wchar_t *password_buffer = (wchar_t *)P1;

        if (NULL == password_buffer || P2 == 0) {
            status = -1;
            unrar_dbgmsg("CallbackProc: P1 callback argument is invalid.\n");
            break;
        }

        memset(password_buffer, 0, P2 * sizeof(wchar_t));

        status = 1;
        unrar_dbgmsg("CallbackProc: Password required, attempting empty password.\n");
        break;
    }
    default: {
        /* ... */
        unrar_dbgmsg("CallbackProc: Unexpected callback type!\n");
    }
    }
    return status;
}

} /* extern "C" */
