/*
 *  Extract component parts of MS CHM files
 *
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
 *
 *  Authors: Trog
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

#ifndef __CHM_UNPACK_H
#define __CHM_UNPACK_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "cltypes.h"
#include "others.h"
#include "fmap.h"

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif

#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

#define CHM_ITSF_MIN_LEN (0x60)
typedef struct chm_itsf_header_tag
{
	unsigned char signature[4];
	int32_t version __attribute__ ((packed));
	int32_t header_len __attribute__ ((packed));
	uint32_t unknown __attribute__ ((packed));
	uint32_t last_modified __attribute__ ((packed));
	uint32_t lang_id __attribute__ ((packed));
	unsigned char dir_clsid[16];
	unsigned char stream_clsid[16];
	uint64_t sec0_offset __attribute__ ((packed));
	uint64_t sec0_len __attribute__ ((packed));
	uint64_t dir_offset __attribute__ ((packed));
	uint64_t dir_len __attribute__ ((packed));
	uint64_t data_offset __attribute__ ((packed));
} chm_itsf_header_t;

#define CHM_ITSP_LEN (0x54)
typedef struct chm_itsp_header_tag
{
	unsigned char signature[4];
	int32_t version __attribute__ ((packed));
	int32_t header_len __attribute__ ((packed));
	int32_t unknown1 __attribute__ ((packed));
	uint32_t block_len __attribute__ ((packed));
	int32_t blockidx_intvl __attribute__ ((packed));
	int32_t index_depth __attribute__ ((packed));
	int32_t index_root __attribute__ ((packed));
	int32_t index_head __attribute__ ((packed));
	int32_t index_tail __attribute__ ((packed));
	int32_t unknown2 __attribute__ ((packed));
	uint32_t num_blocks __attribute__ ((packed));
	uint32_t lang_id __attribute__ ((packed));
	unsigned char system_clsid[16];
	unsigned char unknown4[16];
} chm_itsp_header_t;

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

typedef struct chm_sys_entry_tag
{
	uint64_t offset;
	uint64_t length;
} chm_sys_entry_t;

typedef struct chm_metadata_tag {
	uint64_t file_length;
	uint64_t file_offset;
	chm_sys_entry_t sys_control;
	chm_sys_entry_t sys_content;
	chm_sys_entry_t sys_reset;
	off_t m_length;
	chm_itsf_header_t itsf_hdr;
	chm_itsp_header_t itsp_hdr;
	int ufd;
	int ofd;
	uint32_t num_chunks;
	off_t chunk_offset;
	const char *chunk_data;
	const char *chunk_current;
	const char *chunk_end;
	fmap_t *map;
	uint16_t chunk_entries;
} chm_metadata_t;

int cli_chm_open(const char *dirname, chm_metadata_t *metadata, cli_ctx *ctx);
int cli_chm_prepare_file(chm_metadata_t *metadata);
int cli_chm_extract_file(char *dirname, chm_metadata_t *metadata, cli_ctx *ctx);
void cli_chm_close(chm_metadata_t *metadata);
#endif
