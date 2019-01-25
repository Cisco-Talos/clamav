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

#ifndef __UNRAR_IFACE_H
#define __UNRAR_IFACE_H

#include <stdint.h>
#include <sys/types.h>

#define unrar_open libclamunrar_iface_LTX_unrar_open
#define unrar_peek_file_header libclamunrar_iface_LTX_unrar_peek_file_header
#define unrar_extract_file libclamunrar_iface_LTX_unrar_extract_file
#define unrar_skip_file libclamunrar_iface_LTX_unrar_skip_file
#define unrar_close libclamunrar_iface_LTX_unrar_close

typedef enum cl_unrar_error_tag {
    UNRAR_OK = 0,
    UNRAR_BREAK,
    UNRAR_ENCRYPTED,
    UNRAR_EMEM,
    UNRAR_ERR,
    UNRAR_EOPEN
} cl_unrar_error_t;

typedef struct unrar_metadata_tag
{
    uint64_t pack_size;
    uint64_t unpack_size;
    char *filename;
    uint32_t crc;
    unsigned int encrypted;
    uint8_t method;
    uint32_t is_dir;
} unrar_metadata_t;

cl_unrar_error_t unrar_open(const char *filename, void **hArchive, char **comment, uint32_t *comment_size, uint8_t debug_flag);
cl_unrar_error_t unrar_peek_file_header(void *hArchive, unrar_metadata_t *file_metadata);
cl_unrar_error_t unrar_extract_file(void* hArchive, const char* destPath, char *outputBuffer);
cl_unrar_error_t unrar_skip_file(void *hArchive);
void unrar_close(void *hArchive);

#endif
