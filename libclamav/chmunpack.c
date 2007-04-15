/*
 *  Extract component parts of MS CHM files
 *
 *  Copyright (C) 2004-2005 trog@uncon.org
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>

#if defined(HAVE_ATTRIB_PACKED) || defined(HAVE_PRAGMA_PACK) || defined(HAVE_PRAGMA_PACK_HPPA)
#if HAVE_MMAP
#if HAVE_SYS_MMAN_H
#include <sys/mman.h>
#else /* HAVE_SYS_MMAN_H */
#undef HAVE_MMAP
#endif /* HAVE_SYS_MMAN_H */
#endif /* HAVE_MMAP */
#else/* PACKED */
#undef HAVE_MMAP
#endif

#include "others.h"
#include "mspack.h"
#include "cltypes.h"
#include "chmunpack.h"

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif

#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

#ifndef	O_BINARY
#define	O_BINARY	0
#endif

#define CHM_ITSF_MIN_LEN (0x60)
typedef struct itsf_header_tag
{
	unsigned char signature[4] __attribute__ ((packed));
	int32_t version __attribute__ ((packed));
	int32_t header_len __attribute__ ((packed));
	uint32_t unknown __attribute__ ((packed));
	uint32_t last_modified __attribute__ ((packed));
	uint32_t lang_id __attribute__ ((packed));
	unsigned char dir_clsid[16] __attribute__ ((packed));
	unsigned char stream_clsid[16] __attribute__ ((packed));
	uint64_t sec0_offset __attribute__ ((packed));
	uint64_t sec0_len __attribute__ ((packed));
	uint64_t dir_offset __attribute__ ((packed));
	uint64_t dir_len __attribute__ ((packed));
	uint64_t data_offset __attribute__ ((packed));
} itsf_header_t;

#define CHM_ITSP_LEN (0x54)
typedef struct itsp_header_tag
{
	unsigned char signature[4] __attribute__ ((packed));
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
	unsigned char system_clsid[16] __attribute__ ((packed));
	unsigned char unknown4[16] __attribute__ ((packed));
} itsp_header_t;

#define CHM_CHUNK_HDR_LEN (0x14)
typedef struct chunk_header_tag
{
	unsigned char signature[4] __attribute__ ((packed));
	uint32_t free_space __attribute__ ((packed));
	uint32_t unknown __attribute__ ((packed));
	int32_t block_prev __attribute__ ((packed));
	int32_t block_next __attribute__ ((packed));
	unsigned char *chunk_data;
	uint16_t num_entries;
} chunk_header_t;

typedef struct file_list_tag
{
	unsigned char *name;
	uint64_t section;
	uint64_t offset;
	uint64_t length;
	struct file_list_tag *next;
} file_list_t;

#define CHM_CONTROL_LEN (0x18)
typedef struct lzx_control_tag {
	uint32_t length __attribute__ ((packed));
	unsigned char signature[4] __attribute__ ((packed));
	uint32_t version __attribute__ ((packed));
	uint32_t reset_interval __attribute__ ((packed));
	uint32_t window_size __attribute__ ((packed));
	uint32_t cache_size __attribute__ ((packed));
} lzx_control_t;

/* Don't need to include rt_offset in the strucuture len*/
#define CHM_RESET_TABLE_LEN (0x24)
typedef struct lzx_reset_table_tag {
	uint32_t num_entries __attribute__ ((packed));
	uint32_t entry_size __attribute__ ((packed));
	uint32_t table_offset __attribute__ ((packed));
	uint64_t uncom_len __attribute__ ((packed));
	uint64_t com_len __attribute__ ((packed));
	uint64_t frame_len __attribute__ ((packed));
	off_t rt_offset __attribute__ ((packed));
} lzx_reset_table_t;

typedef struct lzx_content_tag {
	uint64_t offset;
	uint64_t length;
} lzx_content_t;

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

#define chm_endian_convert_16(x) le16_to_host(x) 
#define chm_endian_convert_32(x) le32_to_host(x) 
#define chm_endian_convert_64(x) le64_to_host(x)

/* Read in a block of data from either the mmap area or the given fd */
static int chm_read_data(int fd, unsigned char *dest, off_t offset, off_t len,
			unsigned char *m_area, off_t m_length)
{
	if ((offset < 0) || (len < 0) || ((offset+len) < 0)) {
		return FALSE;
	}
	if (m_area != NULL) {
		if ((offset+len) > m_length) {
			return FALSE;
		}
		memcpy(dest, m_area+offset, len);
	} else {
		if (lseek(fd, offset, SEEK_SET) != offset) {
			return FALSE;
		}
		if (cli_readn(fd, dest, len) != len) {
			return FALSE;
		}
	}
	return TRUE;
}

static uint64_t chm_copy_file_data(int ifd, int ofd, uint64_t len)
{
	unsigned char data[8192];
	uint64_t count, rem;
	unsigned int todo;
	
	rem = len;

	while (rem > 0) {
		todo = MIN(8192, rem);
		count = cli_readn(ifd, data, todo);
		if (count != todo) {
			return len-rem;
		}
		if (cli_writen(ofd, data, count) != (int64_t)count) {
			return len-rem-count;
		}
		rem -= count;
	}
	return len;
}

static void free_file_list(file_list_t *file_l)
{
	file_list_t *next;
	
	while (file_l) {
		next = file_l->next;
		if (file_l->name) {
			free(file_l->name);
		}
		free(file_l);
		file_l = next;
	}
}

static void itsf_print_header(itsf_header_t *itsf_hdr)
{
	if (!itsf_hdr) {
		return;
	}
	
	cli_dbgmsg("---- ITSF ----\n");
	cli_dbgmsg("Signature:\t%c%c%c%c\n", itsf_hdr->signature[0],
		itsf_hdr->signature[1],itsf_hdr->signature[2],itsf_hdr->signature[3]);
	cli_dbgmsg("Version:\t%d\n", itsf_hdr->version);
	cli_dbgmsg("Header len:\t%ld\n", itsf_hdr->header_len);
	cli_dbgmsg("Lang ID:\t%d\n", itsf_hdr->lang_id);
	cli_dbgmsg("Sec0 offset:\t%llu\n", itsf_hdr->sec0_offset);
	cli_dbgmsg("Sec0 len:\t%llu\n", itsf_hdr->sec0_len);
	cli_dbgmsg("Dir offset:\t%llu\n", itsf_hdr->dir_offset);
	cli_dbgmsg("Dir len:\t%llu\n", itsf_hdr->dir_len);
	if (itsf_hdr->version > 2) {
		cli_dbgmsg("Data offset:\t%llu\n\n", itsf_hdr->data_offset);
	}
}

static int itsf_read_header(int fd, itsf_header_t *itsf_hdr, unsigned char *m_area, off_t m_length)
{
#if defined(HAVE_ATTRIB_PACKED) || defined(HAVE_PRAGMA_PACK) || defined(HAVE_PRAGMA_PACK_HPPA)
	if (!chm_read_data(fd, (unsigned char *) itsf_hdr, 0, CHM_ITSF_MIN_LEN,
				m_area,	m_length)) {
		return FALSE;
	}
#else
	if (cli_readn(fd, &itsf_hdr->signature, 4) != 4) {
		return FALSE;
	}
	if (cli_readn(fd, &itsf_hdr->version, 4) != 4) {
		return FALSE;
	}
	if (cli_readn(fd, &itsf_hdr->header_len, 4) != 4) {
		return FALSE;
	}
	if (cli_readn(fd, &itsf_hdr->unknown, 4) != 4) {
		return FALSE;
	}
	if (cli_readn(fd, &itsf_hdr->last_modified, 4) != 4) {
		return FALSE;
	}
	if (cli_readn(fd, &itsf_hdr->lang_id, 4) != 4) {
		return FALSE;
	}
	if (cli_readn(fd, &itsf_hdr->dir_clsid, 16) != 16) {
		return FALSE;
	}
	if (cli_readn(fd, &itsf_hdr->stream_clsid, 16) != 16) {
		return FALSE;
	}
	if (cli_readn(fd, &itsf_hdr->sec0_offset, 8) != 8) {
		return FALSE;
	}
	if (cli_readn(fd, &itsf_hdr->sec0_len, 8) != 8) {
		return FALSE;
	}
	if (cli_readn(fd, &itsf_hdr->dir_offset, 8) != 8) {
		return FALSE;
	}
	if (cli_readn(fd, &itsf_hdr->dir_len, 8) != 8) {
		return FALSE;
	}
	if (itsf_hdr->version > 2) {
		if (cli_readn(fd, &itsf_hdr->data_offset, 8) != 8) {
			return FALSE;
		}
	}
#endif
	if (memcmp(itsf_hdr->signature, "ITSF", 4) != 0) {
		cli_dbgmsg("ITSF signature mismatch\n");
		return FALSE;
	}
	itsf_hdr->version = chm_endian_convert_32(itsf_hdr->version);
	itsf_hdr->header_len = chm_endian_convert_32(itsf_hdr->header_len);
	itsf_hdr->last_modified = chm_endian_convert_32(itsf_hdr->last_modified);
	itsf_hdr->lang_id = chm_endian_convert_32(itsf_hdr->lang_id);
	itsf_hdr->sec0_offset = chm_endian_convert_64(itsf_hdr->sec0_offset);
	itsf_hdr->sec0_len = chm_endian_convert_64(itsf_hdr->sec0_len);
	itsf_hdr->dir_offset = chm_endian_convert_64(itsf_hdr->dir_offset);
	itsf_hdr->dir_len = chm_endian_convert_64(itsf_hdr->dir_len);
	if (itsf_hdr->version > 2) {
		itsf_hdr->data_offset = chm_endian_convert_64(itsf_hdr->data_offset);
	}
	return TRUE;
}

static void itsp_print_header(itsp_header_t *itsp_hdr)
{
	if (!itsp_hdr) {
		return;
	}
	
	cli_dbgmsg("---- ITSP ----\n");
	cli_dbgmsg("Signature:\t%c%c%c%c\n", itsp_hdr->signature[0],
		itsp_hdr->signature[1],itsp_hdr->signature[2],itsp_hdr->signature[3]);
	cli_dbgmsg("Version:\t%d\n", itsp_hdr->version);
	cli_dbgmsg("Block len:\t%ld\n", itsp_hdr->block_len);
	cli_dbgmsg("Block idx int:\t%d\n", itsp_hdr->blockidx_intvl);
	cli_dbgmsg("Index depth:\t%d\n", itsp_hdr->index_depth);
	cli_dbgmsg("Index root:\t%d\n", itsp_hdr->index_root);
	cli_dbgmsg("Index head:\t%u\n", itsp_hdr->index_head);
	cli_dbgmsg("Index tail:\t%u\n", itsp_hdr->index_tail);
	cli_dbgmsg("Num Blocks:\t%u\n", itsp_hdr->num_blocks);
	cli_dbgmsg("Lang ID:\t%lu\n\n", itsp_hdr->lang_id);
}

static int itsp_read_header(int fd, itsp_header_t *itsp_hdr, off_t offset,
				unsigned char *m_area, off_t m_length)
{
#if defined(HAVE_ATTRIB_PACKED) || defined(HAVE_PRAGMA_PACK) || defined(HAVE_PRAGMA_PACK_HPPA)
	if (!chm_read_data(fd, (unsigned char *) itsp_hdr, offset, CHM_ITSP_LEN,
				m_area,	m_length)) {
		return FALSE;
	}
#else
	if (lseek(fd, offset, SEEK_SET) != offset) {
		return FALSE;
	}
	if (cli_readn(fd, &itsp_hdr->signature, 4) != 4) {
		return FALSE;
	}
	if (cli_readn(fd, &itsp_hdr->version, 4) != 4) {
		return FALSE;
	}
	if (cli_readn(fd, &itsp_hdr->header_len, 4) != 4) {
		return FALSE;
	}
	if (cli_readn(fd, &itsp_hdr->unknown1, 4) != 4) {
		return FALSE;
	}
	if (cli_readn(fd, &itsp_hdr->block_len, 4) != 4) {
		return FALSE;
	}
	if (cli_readn(fd, &itsp_hdr->blockidx_intvl, 4) != 4) {
		return FALSE;
	}
	if (cli_readn(fd, &itsp_hdr->index_depth, 4) != 4) {
		return FALSE;
	}
	if (cli_readn(fd, &itsp_hdr->index_root, 4) != 4) {
		return FALSE;
	}
	if (cli_readn(fd, &itsp_hdr->index_head, 4) != 4) {
		return FALSE;
	}
	if (cli_readn(fd, &itsp_hdr->index_tail, 4) != 4) {
		return FALSE;
	}
	if (cli_readn(fd, &itsp_hdr->unknown2, 4) != 4) {
		return FALSE;
	}
	if (cli_readn(fd, &itsp_hdr->num_blocks, 4) != 4) {
		return FALSE;
	}
	if (cli_readn(fd, &itsp_hdr->lang_id, 4) != 4) {
		return FALSE;
	}
	if (cli_readn(fd, &itsp_hdr->system_clsid, 16) != 16) {
		return FALSE;
	}
	if (cli_readn(fd, &itsp_hdr->unknown4, 16) != 16) {
		return FALSE;
	}
#endif
	if (memcmp(itsp_hdr->signature, "ITSP", 4) != 0) {
		cli_dbgmsg("ITSP signature mismatch\n");
		return FALSE;
	}
	
	itsp_hdr->version = chm_endian_convert_32(itsp_hdr->version);
	itsp_hdr->header_len = chm_endian_convert_32(itsp_hdr->header_len);
	itsp_hdr->block_len = chm_endian_convert_32(itsp_hdr->block_len);
	itsp_hdr->blockidx_intvl = chm_endian_convert_32(itsp_hdr->blockidx_intvl);
	itsp_hdr->index_depth = chm_endian_convert_32(itsp_hdr->index_depth);
	itsp_hdr->index_root = chm_endian_convert_32(itsp_hdr->index_root);
	itsp_hdr->index_head = chm_endian_convert_32(itsp_hdr->index_head);
	itsp_hdr->index_tail = chm_endian_convert_32(itsp_hdr->index_tail);
	itsp_hdr->num_blocks = chm_endian_convert_32(itsp_hdr->num_blocks);
	itsp_hdr->lang_id = chm_endian_convert_32(itsp_hdr->lang_id);
	
	if ((itsp_hdr->version != 1) || (itsp_hdr->header_len != CHM_ITSP_LEN)) {
		cli_dbgmsg("ITSP header mismatch\n");
		return FALSE;
	}
	return TRUE;
}

static uint64_t read_enc_int(unsigned char **start, unsigned char *end)
{
	uint64_t retval=0;
	unsigned char *current;
	
	current = *start;
	
	if (current > end) {
		return 0;
	}
	
	do {
		if (current > end) {
			return 0;
		}
		retval = (retval << 7) | (*current & 0x7f);
	} while (*current++ & 0x80);
	
	*start = current;
	return retval;
}

/* Read chunk entries */
/* Note: the file lists end up in reverse order to the order in the chunk */
static int read_chunk_entries(unsigned char *chunk, uint32_t chunk_len,
					uint16_t num_entries,
					file_list_t *file_l, file_list_t *sys_file_l)
{
	unsigned char *current, *end;
	uint64_t name_len;
	file_list_t *file_e;

	end = chunk + chunk_len;
	current = chunk + CHM_CHUNK_HDR_LEN;
	
	while (num_entries--) {
		if (current > end) {
			cli_dbgmsg("read chunk entries failed\n");
			return FALSE;
		}

		file_e = (file_list_t *) cli_malloc(sizeof(file_list_t));
		if (!file_e) {
			return FALSE;
		}
		file_e->next = NULL;
		
		name_len = read_enc_int(&current, end);
		if (((current + name_len) > end) || ((current + name_len) < chunk)) {
			cli_dbgmsg("Bad CHM name_len detected\n");
			free(file_e);
			return FALSE;
		}
		if (name_len > 0xFFFFFF) {
			cli_dbgmsg("CHM file name too long: %llu\n", name_len);
			file_e->name = (unsigned char *) cli_strdup("truncated");
	                if (!file_e->name) {
        	                free(file_e);
                	        return FALSE;
                	}
		} else {
			file_e->name = (unsigned char *) cli_malloc(name_len+1);
			if (!file_e->name) {
				free(file_e);
				return FALSE;
			}
			strncpy(file_e->name, current, name_len);
			file_e->name[name_len] = '\0';
		}
		current += name_len;
		file_e->section = read_enc_int(&current, end);
		file_e->offset = read_enc_int(&current, end);
		file_e->length = read_enc_int(&current, end);
		if ((name_len >= 2) && (file_e->name[0] == ':') &&
				(file_e->name[1] == ':')) {
			file_e->next = sys_file_l->next;
			sys_file_l->next = file_e;
		} else {
			file_e->next = file_l->next;
			file_l->next = file_e;
		}
		cli_dbgmsg("Section: %llu Offset: %llu Length: %llu, Name: %s\n",
					file_e->section, file_e->offset,
					file_e->length, file_e->name);
	}
	return TRUE;
}

static void print_chunk(chunk_header_t *chunk)
{

	cli_dbgmsg("---- Chunk ----\n");
	cli_dbgmsg("Signature:\t%c%c%c%c\n", chunk->signature[0],
		chunk->signature[1],chunk->signature[2],chunk->signature[3]);
	cli_dbgmsg("Free Space:\t%u\n", chunk->free_space);
	if (memcmp(chunk->signature, "PMGL", 4) == 0) {
		cli_dbgmsg("Prev Block:\t%d\n", chunk->block_prev);
		cli_dbgmsg("Next Block:\t%d\n", chunk->block_next);
		cli_dbgmsg("Num entries:\t%d\n\n", chunk->num_entries);
	}
	return;
}

static int read_chunk(int fd, off_t offset, uint32_t chunk_len,
					unsigned char *m_area, off_t m_length,
					file_list_t *file_l, file_list_t *sys_file_l)
{
	chunk_header_t *chunk_hdr;
	int retval = FALSE;
	
	if (chunk_len < 8 || chunk_len > 33554432) {
		return FALSE;
	}
	
	chunk_hdr = (chunk_header_t *) cli_malloc(sizeof(chunk_header_t));
	if (!chunk_hdr) {
		return FALSE;
	}
	
	chunk_hdr->chunk_data = (unsigned char *) cli_malloc(chunk_len);
	if (!chunk_hdr->chunk_data) {
		free(chunk_hdr);
		return FALSE;
	}
	
#if defined(HAVE_ATTRIB_PACKED) || defined(HAVE_PRAGMA_PACK) || defined(HAVE_PRAGMA_PACK_HPPA)
	/* 8 bytes reads the signature and the free_space */
	if (!chm_read_data(fd, chunk_hdr->signature, offset, 8,
				m_area,	m_length)) {
		goto abort;
	}
	if (!chm_read_data(fd, chunk_hdr->chunk_data, offset, chunk_len,
				m_area,	m_length)) {
		goto abort;
	}
#else	
	if (lseek(fd, offset, SEEK_SET) != offset) {
		goto abort;
	}
	if (cli_readn(fd, chunk_hdr->chunk_data, chunk_len) != chunk_len) {
		goto abort;
	}
	if (lseek(fd, offset, SEEK_SET) != offset) {
		goto abort;
	}
	if (cli_readn(fd, &chunk_hdr->signature, 4) != 4) {
		goto abort;
	}
	if (cli_readn(fd, &chunk_hdr->free_space, 4) != 4) {
		goto abort;
	}
#endif
	chunk_hdr->free_space = chm_endian_convert_32(chunk_hdr->free_space);
	
	if (memcmp(chunk_hdr->signature, "PMGL", 4) == 0) {
#if defined(HAVE_ATTRIB_PACKED) || defined(HAVE_PRAGMA_PACK) || defined(HAVE_PRAGMA_PACK_HPPA)
		if (!chm_read_data(fd, (unsigned char *) &chunk_hdr->unknown, offset+8, 12,
					m_area,	m_length)) {
			goto abort;
		}
#else
		if (cli_readn(fd, &chunk_hdr->unknown, 4) != 4) {
			goto abort;
		}
		if (cli_readn(fd, &chunk_hdr->block_next, 4) != 4) {
			goto abort;
		}
		if (cli_readn(fd, &chunk_hdr->block_prev, 4) != 4) {
			goto abort;
		}
#endif
		chunk_hdr->block_next = chm_endian_convert_32(chunk_hdr->block_next);
		chunk_hdr->block_prev = chm_endian_convert_32(chunk_hdr->block_prev);
		
		chunk_hdr->num_entries = (uint16_t)((((uint8_t const *)(chunk_hdr->chunk_data))[chunk_len-2] << 0)
					| (((uint8_t const *)(chunk_hdr->chunk_data))[chunk_len-1] << 8));
		read_chunk_entries(chunk_hdr->chunk_data, chunk_len,
                        chunk_hdr->num_entries, file_l, sys_file_l);
	} else if (memcmp(chunk_hdr->signature, "PMGI", 4) != 0) {
		goto abort;
	}

	print_chunk(chunk_hdr);
	retval=TRUE;
abort:
	free(chunk_hdr->chunk_data);
	free(chunk_hdr);
	return retval;
}

static void print_sys_control(lzx_control_t *lzx_control)
{
	if (!lzx_control) {
		return;
	}

	cli_dbgmsg("---- Control ----\n");	
	cli_dbgmsg("Length:\t\t%lu\n", lzx_control->length);
	cli_dbgmsg("Signature:\t%c%c%c%c\n", lzx_control->signature[0],
		lzx_control->signature[1],lzx_control->signature[2],lzx_control->signature[3]);
	cli_dbgmsg("Version:\t%d\n", lzx_control->version);
	cli_dbgmsg("Reset Interval:\t%d\n", lzx_control->reset_interval);
	cli_dbgmsg("Window Size:\t%d\n", lzx_control->window_size);
	cli_dbgmsg("Cache Size:\t%d\n\n", lzx_control->cache_size);
}

static lzx_control_t *read_sys_control(int fd, itsf_header_t *itsf_hdr, file_list_t *file_e,
					unsigned char *m_area, off_t m_length)
{
	off_t offset;
	lzx_control_t *lzx_control;
	
	if (file_e->length != 28) {
		return NULL;
	}
	offset = itsf_hdr->data_offset + file_e->offset;
	if (offset < 0) {
		return NULL;
	}

	lzx_control = (lzx_control_t *) cli_malloc(sizeof(lzx_control_t));
	if (!lzx_control) {
		return NULL;
	}
#if defined(HAVE_ATTRIB_PACKED) || defined(HAVE_PRAGMA_PACK) || defined(HAVE_PRAGMA_PACK_HPPA)
	if (!chm_read_data(fd, (unsigned char *) lzx_control, offset, CHM_CONTROL_LEN,
				m_area,	m_length)) {
		goto abort;
	}
#else
	if (lseek(fd, offset, SEEK_SET) != offset) {
		goto abort;
	}
	if (cli_readn(fd, &lzx_control->length, 4) != 4) {
		goto abort;
	}
	if (cli_readn(fd, &lzx_control->signature, 4) != 4) {
		goto abort;
	}
	if (cli_readn(fd, &lzx_control->version, 4) != 4) {
		goto abort;
	}
	if (cli_readn(fd, &lzx_control->reset_interval, 4) != 4) {
		goto abort;
	}
	if (cli_readn(fd, &lzx_control->window_size, 4) != 4) {
		goto abort;
	}
	if (cli_readn(fd, &lzx_control->cache_size, 4) != 4) {
		goto abort;
	}
#endif
	lzx_control->length = chm_endian_convert_32(lzx_control->length);
	lzx_control->version = chm_endian_convert_32(lzx_control->version);
	lzx_control->reset_interval = chm_endian_convert_32(lzx_control->reset_interval);
	lzx_control->window_size = chm_endian_convert_32(lzx_control->window_size);
	lzx_control->cache_size = chm_endian_convert_32(lzx_control->cache_size);
	
	if (strncmp("LZXC", lzx_control->signature, 4) != 0) {
		cli_dbgmsg("bad sys_control signature");
		goto abort;
	}
	switch(lzx_control->version) {
		case 1:
			break;
		case 2:
			lzx_control->reset_interval *= LZX_FRAME_SIZE;
			lzx_control->window_size *= LZX_FRAME_SIZE;
			break;
		default:
			cli_dbgmsg("Unknown sys_control version:%d\n", lzx_control->version);
			goto abort;
	}
			
	print_sys_control(lzx_control);
	return lzx_control;
abort:
	free(lzx_control);
	return NULL;
}

static void print_sys_content(lzx_content_t *lzx_content)
{
	if (!lzx_content) {
		return;
	}
	
	cli_dbgmsg("---- Content ----\n");
	cli_dbgmsg("Offset:\t%llu\n", lzx_content->offset);
	cli_dbgmsg("Length:\t%llu\n\n", lzx_content->length);
}

static lzx_content_t *read_sys_content(int fd, itsf_header_t *itsf_hdr, file_list_t *file_e)
{
	lzx_content_t *lzx_content;
	
	lzx_content = (lzx_content_t *) cli_malloc(sizeof(lzx_content_t));
	if (!lzx_content) {
		return NULL;
	}
	lzx_content->offset = itsf_hdr->data_offset + file_e->offset;
	lzx_content->length = file_e->length;
	
	print_sys_content(lzx_content);
	return lzx_content;
}

static void print_sys_reset_table(lzx_reset_table_t *lzx_reset_table)
{
	if (!lzx_reset_table) {
		return;
	}
	
	cli_dbgmsg("---- Reset Table ----\n");
	cli_dbgmsg("Num Entries:\t%lu\n", lzx_reset_table->num_entries);
	cli_dbgmsg("Entry Size:\t%lu\n", lzx_reset_table->entry_size);
	cli_dbgmsg("Table Offset:\t%lu\n", lzx_reset_table->table_offset);
	cli_dbgmsg("Uncom Len:\t%llu\n", lzx_reset_table->uncom_len);
	cli_dbgmsg("Com Len:\t%llu\n", lzx_reset_table->com_len);
	cli_dbgmsg("Frame Len:\t%llu\n\n", lzx_reset_table->frame_len);
}

static lzx_reset_table_t *read_sys_reset_table(int fd, itsf_header_t *itsf_hdr, file_list_t *file_e,
						unsigned char *m_area, off_t m_length)
{
	off_t offset;
	lzx_reset_table_t *lzx_reset_table;

	if (file_e->length < 40) {
		return NULL;
	}
	/* Skip past unknown entry in offset calc */
	offset = itsf_hdr->data_offset + file_e->offset + 4;
	
	if (offset < 0) {
		return NULL;
	}

	lzx_reset_table = (lzx_reset_table_t *) cli_malloc(sizeof(lzx_reset_table_t));
	if (!lzx_reset_table) {
		return NULL;
	}
	
	/* Save the entry offset for later use */
	lzx_reset_table->rt_offset = offset-4;

#if defined(HAVE_ATTRIB_PACKED) || defined(HAVE_PRAGMA_PACK) || defined(HAVE_PRAGMA_PACK_HPPA)
	if (!chm_read_data(fd, (unsigned char *) lzx_reset_table, offset, CHM_RESET_TABLE_LEN,
				m_area,	m_length)) {
		goto abort;
	}
#else	
	if (lseek(fd, offset, SEEK_SET) != offset) {
		goto abort;
	}
	if (cli_readn(fd, &lzx_reset_table->num_entries, 4) != 4) {
		goto abort;
	}
	if (cli_readn(fd, &lzx_reset_table->entry_size, 4) != 4) {
		goto abort;
	}
	if (cli_readn(fd, &lzx_reset_table->table_offset, 4) != 4) {
		goto abort;
	}
	if (cli_readn(fd, &lzx_reset_table->uncom_len, 8) != 8) {
		goto abort;
	}
	if (cli_readn(fd, &lzx_reset_table->com_len, 8) != 8) {
		goto abort;
	}
	if (cli_readn(fd, &lzx_reset_table->frame_len, 8) != 8) {
		goto abort;
	}
#endif
	lzx_reset_table->num_entries = chm_endian_convert_32(lzx_reset_table->num_entries);
	lzx_reset_table->entry_size = chm_endian_convert_32(lzx_reset_table->entry_size);
	lzx_reset_table->table_offset = chm_endian_convert_32(lzx_reset_table->table_offset);
	lzx_reset_table->uncom_len = chm_endian_convert_64(lzx_reset_table->uncom_len);
	lzx_reset_table->com_len = chm_endian_convert_64(lzx_reset_table->com_len);
	lzx_reset_table->frame_len = chm_endian_convert_64(lzx_reset_table->frame_len);

	if (lzx_reset_table->frame_len != LZX_FRAME_SIZE) {
		cli_dbgmsg("bad sys_reset_table frame_len: 0x%x\n",lzx_reset_table->frame_len);
		goto abort;
	}
	if ((lzx_reset_table->entry_size != 4) && (lzx_reset_table->entry_size != 8)) {
		cli_dbgmsg("bad sys_reset_table entry_size: 0x%x\n",lzx_reset_table->entry_size);
		goto abort;
	}
	print_sys_reset_table(lzx_reset_table);
	return lzx_reset_table;
abort:
	free(lzx_reset_table);
	return NULL;
}

/* *****************************************************************/
/* This section interfaces to the mspack files. As such, this is a */
/* little bit dirty compared to my usual code */

#define CHM_SYS_CONTROL_NAME "::DataSpace/Storage/MSCompressed/ControlData"
#define CHM_SYS_CONTENT_NAME "::DataSpace/Storage/MSCompressed/Content"
#define CHM_SYS_RESETTABLE_NAME "::DataSpace/Storage/MSCompressed/Transform/{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/ResetTable"

static int chm_decompress_stream(int fd, const char *dirname, itsf_header_t *itsf_hdr,
				file_list_t *file_l, file_list_t *sys_file_l,
				unsigned char *m_area, off_t m_length)
{
	file_list_t *entry;
	lzx_content_t *lzx_content=NULL;
	lzx_reset_table_t *lzx_reset_table=NULL;
	lzx_control_t *lzx_control=NULL;
	int window_bits, count, length, tmpfd, ofd, retval=FALSE;
	uint64_t com_offset;
	struct lzx_stream * stream;
	unsigned char filename[1024];
	
	snprintf(filename, 1024, "%s/clamav-unchm.bin", dirname);
	tmpfd = open(filename, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU);
	if (tmpfd<0) {
		cli_dbgmsg("open failed for %s\n", filename);
		return FALSE;
	}

	entry = sys_file_l->next;
	while (entry) {
		if (strcmp(entry->name, CHM_SYS_CONTROL_NAME) == 0) {
			lzx_control = read_sys_control(fd, itsf_hdr, entry, m_area, m_length);
		} else if (strcmp(entry->name, CHM_SYS_CONTENT_NAME) == 0) {
			lzx_content = read_sys_content(fd, itsf_hdr, entry);
		} else if (strcmp(entry->name, CHM_SYS_RESETTABLE_NAME) == 0) {
			lzx_reset_table = read_sys_reset_table(fd, itsf_hdr, entry, m_area, m_length);
		}
		entry = entry->next;
	}
	
	if (!lzx_content || !lzx_reset_table || !lzx_control) {
		goto abort;
	}
	
	switch (lzx_control->window_size) {
		case 0x008000:
			window_bits = 15;
			break;
		case 0x010000:
			window_bits = 16;
			break;
		case 0x020000:
			window_bits = 17;
			break;
		case 0x040000:
			window_bits = 18;
			break;
		case 0x080000:
			window_bits = 19;
			break;
		case 0x100000:
			window_bits = 20;
			break;
		case 0x200000:
			window_bits = 21;
			break;
		default:
			cli_dbgmsg("bad control window size: 0x%x\n", lzx_control->window_size);
			goto abort;
	}
	
	if (lzx_control->reset_interval % LZX_FRAME_SIZE) {
		cli_dbgmsg("bad reset_interval: 0x%x\n", lzx_control->window_size);
		goto abort;
	}
	
	length = lzx_reset_table->uncom_len;
	length += lzx_control->reset_interval;
	length &= -lzx_control->reset_interval;
	
	com_offset = lzx_content->offset;
	cli_dbgmsg("Compressed offset: %llu\n", com_offset);
	
	stream = lzx_init(fd, tmpfd, window_bits,
			lzx_control->reset_interval / LZX_FRAME_SIZE,
			4096, length, NULL, NULL);
	lseek(fd, com_offset, SEEK_SET);
	if (!stream) {
		cli_dbgmsg("lzx_init failed\n");
		goto abort;
	}
	
	lzx_decompress(stream, length);
	lzx_free(stream);
	
	entry = file_l->next;
	close(tmpfd);
	
	/* Reopen the file for reading */
	tmpfd = open(filename, O_RDONLY|O_BINARY);
	if (tmpfd < 0) {
		cli_dbgmsg("re-open output failed\n");
		goto abort;
	}
	
	/* Delete the file */
	unlink(filename);
	
	count=0;
	while(entry) {
		if (entry->section != 1) {
			entry = entry->next;
			continue;
		}
		if (lseek(tmpfd, entry->offset, SEEK_SET) != (off_t)entry->offset) {
			cli_dbgmsg("seek in output failed\n");
			entry = entry->next;
			continue;
		}
		
		snprintf(filename, 1024, "%s/%d-%llu.chm", dirname, count, entry->offset);
		ofd = open(filename, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU);
		if (ofd < 0) {
			entry = entry->next;
			continue;
		}
		if (chm_copy_file_data(tmpfd, ofd, entry->length) != entry->length) {
			cli_dbgmsg("failed to copy %lu bytes\n", entry->length);
		}
		
		close(ofd);		
		entry = entry->next;
		count++;
	}
	close(tmpfd);
	tmpfd=-1;
	retval = TRUE;
	
abort:
	if (tmpfd>=0) {
		close(tmpfd);
	}
	if (lzx_content) {
		free(lzx_content);
	}
	if (lzx_reset_table) {
		free(lzx_reset_table);
	}
	if (lzx_control) {
		free(lzx_control);
	}
	return retval;
}

/* ************ End dirty section ********************/

int chm_unpack(int fd, const char *dirname)
{
	int retval=FALSE;
	unsigned char *m_area=NULL;
	off_t m_length=0, offset;
	file_list_t *file_l, *sys_file_l;
	struct stat statbuf;
	itsf_header_t itsf_hdr;
	itsp_header_t itsp_hdr;
	uint32_t num_chunks;

	/* These two lists contain the list of files and system files in
	the archive. The first entry in the list is an empty entry */
	
        file_l = (file_list_t *) cli_malloc(sizeof(file_list_t));
	if (!file_l) {
		return FALSE;
	}
	file_l->next = NULL;
	file_l->name = NULL;
	sys_file_l = (file_list_t *) cli_malloc(sizeof(file_list_t));
	if (!sys_file_l) {
		free(file_l);
		return FALSE;
	}
	sys_file_l->next = NULL;
	sys_file_l->name = NULL;
	
#ifdef HAVE_MMAP
	if (fstat(fd, &statbuf) == 0) {
		if (statbuf.st_size < CHM_ITSF_MIN_LEN) {
			goto abort;
		}
		m_length = statbuf.st_size;
		m_area = (unsigned char *) mmap(NULL, m_length, PROT_READ, MAP_PRIVATE, fd, 0);
		if (m_area == MAP_FAILED) {
			m_area = NULL;
		}
	}
#endif

	if (!itsf_read_header(fd, &itsf_hdr, m_area, m_length)) {
		goto abort;
	}
	itsf_print_header(&itsf_hdr);

	if (!itsp_read_header(fd, &itsp_hdr, itsf_hdr.dir_offset, m_area, m_length)) {
		goto abort;
	}
	itsp_print_header(&itsp_hdr);
	
	offset = itsf_hdr.dir_offset+CHM_ITSP_LEN;
	
	/* TODO: need to check this first calculation,
		currently have no files of this type */
	if (itsp_hdr.index_head > 0) {
		offset += itsp_hdr.index_head * itsp_hdr.block_len;
	}

	num_chunks = itsp_hdr.index_tail - itsp_hdr.index_head + 1;
	
	/* Versions before 3 didn't have a data_offset */
	/* TODO: need to check this calculation,
		 currently have no files of this type */
	if (itsf_hdr.version < 3) {
		itsf_hdr.data_offset = itsf_hdr.dir_offset + CHM_ITSP_LEN + (itsp_hdr.block_len*itsp_hdr.num_blocks);
	}

	while (num_chunks) {
		if (!read_chunk(fd, offset, itsp_hdr.block_len, m_area,
					m_length, file_l, sys_file_l)) {
			goto abort;
		}

		num_chunks--;
		offset += itsp_hdr.block_len;
	}

	chm_decompress_stream(fd, dirname, &itsf_hdr, file_l, sys_file_l, m_area, m_length);

	/* Signal success */
	retval = TRUE;
abort:
	free_file_list(file_l);
	free_file_list(sys_file_l);

#ifdef HAVE_MMAP
	if (m_area) {
		munmap(m_area, m_length);
	}
#endif
	return retval;
}
