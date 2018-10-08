/*
 *  Copyright (C) 2018 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  EGG is an archive format created by ESTsoft used by their ALZip
 *  archiving software.
 *
 *  This software is written from scratch based solely from ESTsoft's
 *  file format documentation and from testing with EGG format archives.
 *  ESTsoft's "unEGG" module was not used in the creation of this capability
 *  in order to avoid to licensing restrictions on the ESTsoft "unEGG" module.
 *
 *  Authors: Micah Snyder
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

#ifndef _EGG_H
#define _EGG_H

#include <clamav.h>
#include <others.h>

typedef enum {
    EGG_OK = 0,
    EGG_BREAK,
    EGG_ENCRYPTED,
    EGG_EMEM,
    EGG_ERR
} cl_egg_error_t;

typedef struct cl_egg_metadata {
    uint64_t pack_size;
    uint64_t unpack_size;
    char* filename;
    struct cl_egg_metadata* next;
    unsigned int encrypted;
    uint32_t is_dir;
} cl_egg_metadata;

cl_egg_error_t cli_egg_open(fmap_t* map, size_t sfx_offset, void** hArchive, char** comment, uint32_t* comment_size);
cl_egg_error_t cli_egg_peek_file_header(void* hArchive, cl_egg_metadata* file_metadata);
cl_egg_error_t cli_egg_extract_file(void* hArchive, const char** filename, const char** output_buffer, size_t* output_buffer_length);
cl_egg_error_t cli_egg_skip_file(void* hArchive);
void cli_egg_close(void* hArchive);

#endif // _EGG_H
