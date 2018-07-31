/*
 *  Interface to libclamunrar
 *  Copyright (C) 2015 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007 Sourcefire, Inc.
 *  Authors: Trog, Torok Edvin, Tomasz Kojm
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License version 2.1 as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301, USA.
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
    UNRAR_ERR
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
