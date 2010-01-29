/*
 *  Interface to libclamunrar
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#define unrar_open libclamunrar_iface_LTX_unrar_open
#define unrar_extract_next_prepare libclamunrar_iface_LTX_unrar_extract_next_prepare
#define unrar_extract_next libclamunrar_iface_LTX_unrar_extract_next
#define unrar_close libclamunrar_iface_LTX_unrar_close

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif

#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

#define UNRAR_OK	 0
#define UNRAR_BREAK	 1
#define UNRAR_PASSWD	 2
#define UNRAR_EMEM	-1
#define UNRAR_ERR	-2

typedef struct unrar_comment_header_tag
{
    uint16_t head_crc __attribute__ ((packed));
    uint8_t head_type;
    uint16_t flags __attribute__ ((packed));
    uint16_t head_size __attribute__ ((packed));
    uint16_t unpack_size __attribute__ ((packed));
    uint8_t unpack_ver;
    uint8_t method;
    uint16_t comm_crc __attribute__ ((packed));
} unrar_comment_header_t;

#define UNRAR_MAIN_HEADER_TAG_LEN 13
typedef struct unrar_main_header_tag
{
    uint16_t head_crc __attribute__ ((packed));
    uint8_t head_type;
    uint16_t flags __attribute__ ((packed));
    uint16_t head_size __attribute__ ((packed));
    uint16_t highposav __attribute__ ((packed));
    uint32_t posav __attribute__ ((packed));
} unrar_main_header_t;

typedef struct unrar_file_header_tag
{
    uint16_t head_crc __attribute__ ((packed));
    uint8_t head_type;
    uint16_t flags __attribute__ ((packed));
    uint16_t head_size __attribute__ ((packed));
    uint32_t pack_size __attribute__ ((packed));
    uint32_t unpack_size __attribute__ ((packed));
    uint8_t host_os;
    uint32_t file_crc __attribute__ ((packed));
    uint32_t file_time __attribute__ ((packed));
    uint8_t unpack_ver;
    uint8_t method;
    uint16_t name_size __attribute__ ((packed));
    uint32_t file_attr __attribute__ ((packed));
    uint32_t high_pack_size __attribute__ ((packed));   /* optional */
    uint32_t high_unpack_size __attribute__ ((packed)); /* optional */
    unsigned char *filename __attribute__ ((packed));
    off_t start_offset __attribute__ ((packed));
    off_t next_offset __attribute__ ((packed));
} unrar_fileheader_t;

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif

#ifdef HAVE_PRAGMA_PATCH_HPPA
#pragma pack
#endif

typedef struct unrar_metadata_tag
{
    uint64_t pack_size;
    uint64_t unpack_size;
    char *filename;
    struct unrar_metadata_tag *next;
    uint32_t crc;
    unsigned int encrypted;
    uint8_t method;
} unrar_metadata_t;

typedef struct unrar_state_tag {
    unrar_fileheader_t *file_header;
    unrar_metadata_t *metadata;
    unrar_metadata_t *metadata_tail;
    void *unpack_data;
    unrar_main_header_t *main_hdr;
    char *comment_dir;
    unsigned long file_count;
    uint64_t maxfilesize;
    int fd, ofd;
    char filename[1024];
} unrar_state_t;


int unrar_open(int fd, const char *dirname, unrar_state_t *state);
int unrar_extract_next_prepare(unrar_state_t *state, const char *dirname);
int unrar_extract_next(unrar_state_t *state, const char *dirname);
void unrar_close(unrar_state_t *state);

#endif
