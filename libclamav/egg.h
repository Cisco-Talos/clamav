/*
 *  Copyright (C) 2019-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  EGG is an archive format created by ESTsoft used by their ALZip
 *  archiving software.
 *
 *  This software is written from scratch based solely from ESTsoft's
 *  file format documentation and from testing with EGG format archives.
 *  ESTsoft's "unEGG" module was not used in the creation of this capability
 *  in order to avoid to licensing restrictions on the ESTsoft "unEGG" module.
 *
 *  Authors: Valerie Snyder
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

/**
 * @brief Metadata list node structure modeled after the ClamAV RAR metadata structure.
 *
 * Information is primarily used by the scan metadata feature.
 */
typedef struct cl_egg_metadata {
    uint64_t pack_size;
    uint64_t unpack_size;
    char* filename;
    struct cl_egg_metadata* next;
    unsigned int encrypted;
    uint32_t is_dir;
} cl_egg_metadata;

/**
 * @brief Given an fmap to en EGG archive, open a handle for extracting archive contents.
 *
 * A best effort will be made for split archives, though it is incapable of properly extracting split
 * archives since it can only accept 1 file at a time.
 *
 * @param map               fmap representing archive file.
 * @param sfx_offset        0 for a regular file, or an offset into the fmap for the EGG archive if found embedded in another file.
 * @param[out] hArchive     Handle to opened archive.
 * @param[out] comments     Array of null terminated archive comments, if present in archive. Array will be free'd by cli_egg_close()
 * @param[out] nComments    Number of archive comments in array.
 * @return cl_error_t   CL_SUCCESS if success.
 */
cl_error_t cli_egg_open(
    fmap_t* map,
    void** hArchive,
    char*** comments,
    uint32_t* nComments);

/**
 * @brief Peek at the next file in the archive, without incremented the current file index.
 *
 * @param hArchive          An open EGG archive handle from cli_egg_open()
 * @param file_metadata     Metadata describing the next file to be extracted (or skipped).
 * @return cl_error_t   CL_SUCCESS if success.
 */
cl_error_t cli_egg_peek_file_header(
    void* hArchive,
    cl_egg_metadata* file_metadata);

/**
 * @brief Extract the next file in the archive.
 *
 * Does not return all of the metadata provided by cli_egg_peek_file_header(), so both should be used to get file information.
 * The current file index will be incremented on both success and failure.
 *
 * @param hArchive                  An open EGG archive handle from cli_egg_open()
 * @param[out] filename             The filename of the extracted file, in UTF-8.
 * @param[out] output_buffer        A malloc'd buffer of the file contents.  Must be free()'d by caller. Set to NULL on failure.
 * @param[out] output_buffer_length Size of buffer in bytes.
 * @return cl_error_t               CL_SUCCESS if success.
 */
cl_error_t cli_egg_extract_file(
    void* hArchive,
    const char** filename,
    const char** output_buffer,
    size_t* output_buffer_length);

/**
 * @brief Skip the next file.
 *
 * This is useful to skip things like directories, encrypted files, or file that are too large.
 *
 * @param hArchive          An open EGG archive handle from cli_egg_open()
 * @return cl_error_t   CL_SUCCESS if success.
 */
cl_error_t cli_egg_skip_file(void* hArchive);

/**
 * @brief Close the handle to the EGG archive and free the associated resources.
 *
 * @param hArchive  An open EGG archive handle from cli_egg_open()
 */
void cli_egg_close(void* hArchive);

#endif // _EGG_H
