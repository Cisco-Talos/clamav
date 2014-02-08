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
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libclamav/crypto.h"

#include "fmap.h"
#include "others.h"
#include "mspack.h"
#include "cltypes.h"
#include "chmunpack.h"
#include "cab.h"

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif

#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

#define CHM_CHUNK_HDR_LEN (0x14)

#define CHM_CONTROL_LEN (0x18)
typedef struct lzx_control_tag {
	uint32_t length __attribute__ ((packed));
	unsigned char signature[4];
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

#define CHM_SYS_CONTROL_NAME "::DataSpace/Storage/MSCompressed/ControlData"
#define CHM_SYS_CONTENT_NAME "::DataSpace/Storage/MSCompressed/Content"
#define CHM_SYS_RESETTABLE_NAME "::DataSpace/Storage/MSCompressed/Transform/{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/ResetTable"

#define CHM_SYS_CONTROL_LEN 44
#define CHM_SYS_CONTENT_LEN 40
#define CHM_SYS_RESETTABLE_LEN 105

#define chm_endian_convert_16(x) le16_to_host(x) 
#define chm_endian_convert_32(x) le32_to_host(x) 
#define chm_endian_convert_64(x) le64_to_host(x)

/* Read in a block of data from either the mmap area or the given fd */
static int chm_read_data(fmap_t *map, char *dest, off_t offset, off_t len)
{
    const void *src = fmap_need_off_once(map, offset, len);
    if(!src) return FALSE;
    memcpy(dest, src, len);
    return TRUE;
}

/* Read callback for lzx compressed data */
static int chm_readn(struct cab_file *file, unsigned char *buffer, int bytes) {
    int ret = fmap_readn(file->cab->map, buffer, file->cab->cur_offset, bytes);
    if(ret > 0)
	file->cab->cur_offset += ret;
    return ret;
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

static void itsf_print_header(chm_itsf_header_t *itsf_hdr)
{
	if (!itsf_hdr) {
		return;
	}
	
	cli_dbgmsg("---- ITSF ----\n");
	cli_dbgmsg("Signature:\t%c%c%c%c\n", itsf_hdr->signature[0],
		itsf_hdr->signature[1],itsf_hdr->signature[2],itsf_hdr->signature[3]);
	cli_dbgmsg("Version:\t%d\n", itsf_hdr->version);
	cli_dbgmsg("Header len:\t%d\n", itsf_hdr->header_len);
	cli_dbgmsg("Lang ID:\t%d\n", itsf_hdr->lang_id);
	cli_dbgmsg("Sec0 offset:\t%lu\n", (unsigned long int) itsf_hdr->sec0_offset);
	cli_dbgmsg("Sec0 len:\t%lu\n", (unsigned long int) itsf_hdr->sec0_len);
	cli_dbgmsg("Dir offset:\t%lu\n", (unsigned long int) itsf_hdr->dir_offset);
	cli_dbgmsg("Dir len:\t%lu\n", (unsigned long int) itsf_hdr->dir_len);
	if (itsf_hdr->version > 2) {
		cli_dbgmsg("Data offset:\t%lu\n\n", (unsigned long int) itsf_hdr->data_offset);
	}
}

static int itsf_read_header(chm_metadata_t *metadata)
{
	chm_itsf_header_t *itsf_hdr = &metadata->itsf_hdr;
	if (!chm_read_data(metadata->map, (char *)itsf_hdr, 0, CHM_ITSF_MIN_LEN))
		return FALSE;
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

static void itsp_print_header(chm_itsp_header_t *itsp_hdr)
{
	if (!itsp_hdr) {
		return;
	}
	
	cli_dbgmsg("---- ITSP ----\n");
	cli_dbgmsg("Signature:\t%c%c%c%c\n", itsp_hdr->signature[0],
		itsp_hdr->signature[1],itsp_hdr->signature[2],itsp_hdr->signature[3]);
	cli_dbgmsg("Version:\t%d\n", itsp_hdr->version);
	cli_dbgmsg("Block len:\t%u\n", itsp_hdr->block_len);
	cli_dbgmsg("Block idx int:\t%d\n", itsp_hdr->blockidx_intvl);
	cli_dbgmsg("Index depth:\t%d\n", itsp_hdr->index_depth);
	cli_dbgmsg("Index root:\t%d\n", itsp_hdr->index_root);
	cli_dbgmsg("Index head:\t%u\n", itsp_hdr->index_head);
	cli_dbgmsg("Index tail:\t%u\n", itsp_hdr->index_tail);
	cli_dbgmsg("Num Blocks:\t%u\n", itsp_hdr->num_blocks);
	cli_dbgmsg("Lang ID:\t%u\n\n", itsp_hdr->lang_id);
}

static int itsp_read_header(chm_metadata_t *metadata, off_t offset)
{
	chm_itsp_header_t *itsp_hdr = &metadata->itsp_hdr;
	if (!chm_read_data(metadata->map, (char *)itsp_hdr, offset, CHM_ITSP_LEN))
		return FALSE;
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

static uint64_t read_enc_int(const char **start, const char *end)
{
	uint64_t retval=0;
	const char *current;
	
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

/* Read control entries */
static int read_control_entries(chm_metadata_t *metadata)
{
	const char *name;
	uint64_t name_len, section, offset, length;

	while (metadata->chunk_entries--) {
		if (metadata->chunk_current > metadata->chunk_end) {
			cli_dbgmsg("read chunk entries failed\n");
			return FALSE;
		}

		name_len = read_enc_int(&metadata->chunk_current, metadata->chunk_end);
		if (((metadata->chunk_current + name_len) > metadata->chunk_end) || ((metadata->chunk_current + name_len) < metadata->chunk_data)) {
			cli_dbgmsg("Bad CHM name_len detected\n");
			return FALSE;
		}
		name = metadata->chunk_current;
		metadata->chunk_current += name_len;
		section = read_enc_int(&metadata->chunk_current, metadata->chunk_end);
		offset = read_enc_int(&metadata->chunk_current, metadata->chunk_end);
		length = read_enc_int(&metadata->chunk_current, metadata->chunk_end);
		
		/* CHM_SYS_CONTENT_LEN is the shortest name we are searching for */
		if ((name_len >= CHM_SYS_CONTENT_LEN) && (name[0] == ':') &&
				(name[1] == ':')) {
			if ((name_len == CHM_SYS_CONTROL_LEN) && (strcmp(name, CHM_SYS_CONTROL_NAME) == 0)) {
				cli_dbgmsg("found CHM_SYS_CONTROL_NAME\n");
				metadata->sys_control.offset = offset;
				metadata->sys_control.length = length;
			} else if ((name_len == CHM_SYS_CONTENT_LEN) && (strcmp(name, CHM_SYS_CONTENT_NAME) == 0)) {
				cli_dbgmsg("found CHM_SYS_CONTENT_NAME\n");
				metadata->sys_content.offset = offset;
				metadata->sys_content.length = length;
			} else if ((name_len == CHM_SYS_RESETTABLE_LEN) && (strcmp(name, CHM_SYS_RESETTABLE_NAME) == 0)) {
				cli_dbgmsg("found CHM_SYS_RESETTABLE_NAME\n");
				metadata->sys_reset.offset = offset;
				metadata->sys_reset.length = length;
			}
		}
	}
	return TRUE;
}

static int prepare_file(chm_metadata_t *metadata)
{
	uint64_t name_len, section;

	while (metadata->chunk_entries != 0) {
		if (metadata->chunk_current >= metadata->chunk_end) {
			return CL_EFORMAT;
		}
	
		name_len = read_enc_int(&metadata->chunk_current, metadata->chunk_end);
		if (((metadata->chunk_current + name_len) >= metadata->chunk_end) ||
				((metadata->chunk_current + name_len) < metadata->chunk_data)) {
			cli_dbgmsg("Bad CHM name_len detected\n");
			return CL_EFORMAT;
		}
		metadata->chunk_current += name_len;
		section = read_enc_int(&metadata->chunk_current, metadata->chunk_end);
		metadata->file_offset = read_enc_int(&metadata->chunk_current, metadata->chunk_end);
		metadata->file_length = read_enc_int(&metadata->chunk_current, metadata->chunk_end);
		metadata->chunk_entries--;
		if (section == 1) {
			return CL_SUCCESS;
		}
	}
	
	return CL_BREAK;
}

static int read_chunk(chm_metadata_t *metadata)
{
	cli_dbgmsg("in read_chunk\n");

	if (metadata->itsp_hdr.block_len < 8 || metadata->itsp_hdr.block_len > 33554432) {
		return CL_EFORMAT;
	}

	if (metadata->chunk_offset > metadata->m_length) {
		return CL_EFORMAT;
	}
	if ((metadata->chunk_offset + metadata->itsp_hdr.block_len) > metadata->m_length) {
		return CL_EFORMAT;
	}
	metadata->chunk_data = fmap_need_off_once(metadata->map, metadata->chunk_offset, metadata->itsp_hdr.block_len);
	if(!metadata->chunk_data) return CL_EFORMAT;

	metadata->chunk_current = metadata->chunk_data + CHM_CHUNK_HDR_LEN;
	metadata->chunk_end = metadata->chunk_data + metadata->itsp_hdr.block_len;

	if (memcmp(metadata->chunk_data, "PMGL", 4) == 0) {
		metadata->chunk_entries = (uint16_t)((((uint8_t const *)(metadata->chunk_data))[metadata->itsp_hdr.block_len-2] << 0)
					| (((uint8_t const *)(metadata->chunk_data))[metadata->itsp_hdr.block_len-1] << 8));
	} else if (memcmp(metadata->chunk_data, "PMGI", 4) != 0) {
		return CL_BREAK;
	}

	return CL_SUCCESS;
}

static void print_sys_control(lzx_control_t *lzx_control)
{
	if (!lzx_control) {
		return;
	}

	cli_dbgmsg("---- Control ----\n");	
	cli_dbgmsg("Length:\t\t%u\n", lzx_control->length);
	cli_dbgmsg("Signature:\t%c%c%c%c\n", lzx_control->signature[0],
		lzx_control->signature[1],lzx_control->signature[2],lzx_control->signature[3]);
	cli_dbgmsg("Version:\t%d\n", lzx_control->version);
	cli_dbgmsg("Reset Interval:\t%d\n", lzx_control->reset_interval);
	cli_dbgmsg("Window Size:\t%d\n", lzx_control->window_size);
	cli_dbgmsg("Cache Size:\t%d\n\n", lzx_control->cache_size);
}

static int read_sys_control(chm_metadata_t *metadata, lzx_control_t *lzx_control)
{
	off_t offset;
	
	if (metadata->sys_control.length != 28) {
		return FALSE;
	}
	offset = metadata->itsf_hdr.data_offset + metadata->sys_control.offset;
	if (offset < 0) {
		return FALSE;
	}

	if (!chm_read_data(metadata->map, (char *) lzx_control, offset, CHM_CONTROL_LEN)) {
		return FALSE;
	}

	lzx_control->length = chm_endian_convert_32(lzx_control->length);
	lzx_control->version = chm_endian_convert_32(lzx_control->version);
	lzx_control->reset_interval = chm_endian_convert_32(lzx_control->reset_interval);
	lzx_control->window_size = chm_endian_convert_32(lzx_control->window_size);
	lzx_control->cache_size = chm_endian_convert_32(lzx_control->cache_size);
	
	if (strncmp((const char *) "LZXC", (const char *) lzx_control->signature, 4) != 0) {
		cli_dbgmsg("bad sys_control signature\n");
		return FALSE;
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
			return FALSE;
	}
			
	print_sys_control(lzx_control);
	return TRUE;
}

static void print_sys_content(lzx_content_t *lzx_content)
{
	if (!lzx_content) {
		return;
	}
	
	cli_dbgmsg("---- Content ----\n");
	cli_dbgmsg("Offset:\t%lu\n", (unsigned long int) lzx_content->offset);
	cli_dbgmsg("Length:\t%lu\n\n", (unsigned long int) lzx_content->length);
}

static int read_sys_content(chm_metadata_t *metadata, lzx_content_t *lzx_content)
{
	lzx_content->offset = metadata->itsf_hdr.data_offset + metadata->sys_content.offset;
	lzx_content->length = metadata->sys_content.length;
	
	print_sys_content(lzx_content);
	return TRUE;
}

static void print_sys_reset_table(lzx_reset_table_t *lzx_reset_table)
{
	if (!lzx_reset_table) {
		return;
	}
	
	cli_dbgmsg("---- Reset Table ----\n");
	cli_dbgmsg("Num Entries:\t%u\n", lzx_reset_table->num_entries);
	cli_dbgmsg("Entry Size:\t%u\n", lzx_reset_table->entry_size);
	cli_dbgmsg("Table Offset:\t%u\n", lzx_reset_table->table_offset);
	cli_dbgmsg("Uncom Len:\t%lu\n", (unsigned long int) lzx_reset_table->uncom_len);
	cli_dbgmsg("Com Len:\t%lu\n", (unsigned long int) lzx_reset_table->com_len);
	cli_dbgmsg("Frame Len:\t%lu\n\n", (unsigned long int) lzx_reset_table->frame_len);
}

static int read_sys_reset_table(chm_metadata_t *metadata, lzx_reset_table_t *lzx_reset_table)
{
	off_t offset;

	if (metadata->sys_reset.length < 40) {
		return FALSE;
	}
	/* Skip past unknown entry in offset calc */
	offset = metadata->itsf_hdr.data_offset + metadata->sys_reset.offset + 4;
	
	if (offset < 0) {
		return FALSE;
	}
	
	/* Save the entry offset for later use */
	lzx_reset_table->rt_offset = offset-4;

	if (!chm_read_data(metadata->map, (char *) lzx_reset_table, offset, CHM_RESET_TABLE_LEN)) {
		return FALSE;
	}

	lzx_reset_table->num_entries = chm_endian_convert_32(lzx_reset_table->num_entries);
	lzx_reset_table->entry_size = chm_endian_convert_32(lzx_reset_table->entry_size);
	lzx_reset_table->table_offset = chm_endian_convert_32(lzx_reset_table->table_offset);
	lzx_reset_table->uncom_len = chm_endian_convert_64(lzx_reset_table->uncom_len);
	lzx_reset_table->com_len = chm_endian_convert_64(lzx_reset_table->com_len);
	lzx_reset_table->frame_len = chm_endian_convert_64(lzx_reset_table->frame_len);

	if (lzx_reset_table->frame_len != LZX_FRAME_SIZE) {
		cli_dbgmsg("bad sys_reset_table frame_len: 0x%lx\n", (long unsigned int) lzx_reset_table->frame_len);
		return FALSE;
	}
	if ((lzx_reset_table->entry_size != 4) && (lzx_reset_table->entry_size != 8)) {
		cli_dbgmsg("bad sys_reset_table entry_size: 0x%x\n",lzx_reset_table->entry_size);
		return FALSE;
	}
	print_sys_reset_table(lzx_reset_table);
	return TRUE;
}

/* *****************************************************************/
/* This section interfaces to the mspack files. As such, this is a */
/* little bit dirty compared to my usual code */

static int chm_decompress_stream(chm_metadata_t *metadata, const char *dirname, cli_ctx *ctx)
{
	lzx_content_t lzx_content;
	lzx_reset_table_t lzx_reset_table;
	lzx_control_t lzx_control;
	int window_bits, length, tmpfd, retval=-1;
	struct lzx_stream * stream;
	char filename[1024];
	struct cab_file file;
	struct cab_archive cab;
	
	snprintf(filename, 1024, "%s"PATHSEP"clamav-unchm.bin", dirname);
	tmpfd = open(filename, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU);
	if (tmpfd<0) {
		cli_dbgmsg("open failed for %s\n", filename);
		return -1;
	}

	if (!metadata->sys_control.length || !metadata->sys_content.length ||!metadata->sys_reset.length) {
		cli_dbgmsg("Control file missing\n");
		goto abort;
	}

	if (!read_sys_control(metadata, &lzx_control)) {
		goto abort;
	}
	if (!read_sys_content(metadata, &lzx_content)) {
		goto abort;
	}
	if (!read_sys_reset_table(metadata, &lzx_reset_table)) {
		goto abort;
	}
	
	switch (lzx_control.window_size) {
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
			cli_dbgmsg("bad control window size: 0x%x\n", lzx_control.window_size);
			goto abort;
	}
	
	if (lzx_control.reset_interval % LZX_FRAME_SIZE) {
		cli_dbgmsg("bad reset_interval: 0x%x\n", lzx_control.window_size);
		goto abort;
	}
	
	length = lzx_reset_table.uncom_len;
	length += lzx_control.reset_interval;
	length &= -lzx_control.reset_interval;
	
	cli_dbgmsg("Compressed offset: %lu\n", (unsigned long int) lzx_content.offset);

	memset(&file, 0, sizeof(struct cab_file));
	file.max_size = ctx->engine->maxfilesize;
	file.cab = &cab;
	cab.map = metadata->map;
	cab.cur_offset = lzx_content.offset;
	stream = lzx_init(tmpfd, window_bits,
			lzx_control.reset_interval / LZX_FRAME_SIZE,
			4096, length, &file, chm_readn);
	if (!stream) {
		cli_dbgmsg("lzx_init failed\n");
		goto abort;
	}
	
	lzx_decompress(stream, length);
	lzx_free(stream);
	
#ifndef _WIN32
	/* Delete the file */
	if(cli_unlink(filename))
		retval = -1;
	else
#endif
		retval = tmpfd;
	
abort:
	if ((retval == -1) && (tmpfd >= 0)) {
		close(tmpfd);
	}
	return retval;
}

/* ************ End dirty section ********************/

static int chm_init_metadata(chm_metadata_t *metadata)
{
	if (!metadata) {
		return CL_ENULLARG;
	}
	
	metadata->sys_control.length = metadata->sys_content.length = metadata->sys_reset.length = 0;
	metadata->map = NULL;
	metadata->ufd = -1;
	metadata->num_chunks = metadata->chunk_entries = 0;
	metadata->chunk_data = NULL;
	return CL_SUCCESS;
}

void cli_chm_close(chm_metadata_t *metadata)
{
	if (metadata->ufd >= 0) {
		close(metadata->ufd);
	}
}

int cli_chm_extract_file(char *dirname, chm_metadata_t *metadata, cli_ctx *ctx)
{
	char filename[1024];
	uint64_t len;

	cli_dbgmsg("in cli_chm_extract_file\n");
	
	if (lseek(metadata->ufd, metadata->file_offset, SEEK_SET) != (off_t) metadata->file_offset) {
		cli_dbgmsg("seek in uncompressed stream failed\n");
		return CL_EFORMAT;
	}
	snprintf(filename, 1024, "%s"PATHSEP"%lu.chm", dirname, (unsigned long int) metadata->file_offset);
	metadata->ofd = open(filename, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU);
	if (metadata->ofd < 0) {
		return CL_ECREAT;
	}
	len = ctx->engine->maxfilesize ? (MIN(ctx->engine->maxfilesize, metadata->file_length)) : metadata->file_length;
	if (chm_copy_file_data(metadata->ufd, metadata->ofd, len) != len) {
		cli_dbgmsg("failed to copy %lu bytes\n", (unsigned long int) len);
		close(metadata->ofd);
		return CL_EFORMAT; /* most likely a corrupted file */
	}
		
	return CL_SUCCESS;
}	

int cli_chm_prepare_file(chm_metadata_t *metadata)
{
	int retval;
	
	cli_dbgmsg("in cli_chm_prepare_file\n");

	do {
		if (metadata->chunk_entries == 0) {
			if (metadata->num_chunks == 0) {
				return CL_BREAK;
			}
			if ((retval = read_chunk(metadata)) != CL_SUCCESS) {
				return retval;
			}
			metadata->num_chunks--;
			metadata->chunk_offset += metadata->itsp_hdr.block_len;
		}
		retval = prepare_file(metadata);
	} while (retval == CL_BREAK); /* Ran out of chunk entries before finding a file */
	return retval;
}

int cli_chm_open(const char *dirname, chm_metadata_t *metadata, cli_ctx *ctx)
{
	STATBUF statbuf;
	int retval;

	cli_dbgmsg("in cli_chm_open\n");
	
	if ((retval = chm_init_metadata(metadata)) != CL_SUCCESS) {
		return retval;
	}

	metadata->map = *ctx->fmap;
	if(metadata->map->len < CHM_ITSF_MIN_LEN)
		return CL_ESTAT;
	metadata->m_length = metadata->map->len;

	if (!itsf_read_header(metadata)) {
		goto abort;
	}
	itsf_print_header(&metadata->itsf_hdr);

	if (!itsp_read_header(metadata, metadata->itsf_hdr.dir_offset)) {
		goto abort;
	}
	itsp_print_header(&metadata->itsp_hdr);

	metadata->chunk_offset = metadata->itsf_hdr.dir_offset+CHM_ITSP_LEN;
	
	/* TODO: need to check this first calculation,
		currently have no files of this type */
	if (metadata->itsp_hdr.index_head > 0) {
		metadata->chunk_offset += metadata->itsp_hdr.index_head * metadata->itsp_hdr.block_len;
	}

	metadata->num_chunks = metadata->itsp_hdr.index_tail - metadata->itsp_hdr.index_head + 1;
	
	/* Versions before 3 didn't have a data_offset */
	/* TODO: need to check this calculation,
		 currently have no files of this type */
	if (metadata->itsf_hdr.version < 3) {
		metadata->itsf_hdr.data_offset = metadata->itsf_hdr.dir_offset + CHM_ITSP_LEN +
				(metadata->itsp_hdr.block_len*metadata->itsp_hdr.num_blocks);
	}
	
	while (metadata->num_chunks) {
		if (read_chunk(metadata) != CL_SUCCESS) {
			cli_dbgmsg("read_chunk failed\n");
			goto abort;
		}
		if (read_control_entries(metadata) == FALSE) {
			goto abort;
		}
		metadata->num_chunks--;
		metadata->chunk_offset += metadata->itsp_hdr.block_len;
	}

	if (!metadata->sys_content.length || !metadata->sys_control.length || !metadata->sys_reset.length) {
		cli_dbgmsg("sys file missing\n");
		goto abort;
	}
	
	metadata->ufd = chm_decompress_stream(metadata, dirname, ctx);
	if (metadata->ufd == -1) {
		goto abort;
	}
	
	metadata->chunk_entries = 0;
	metadata->chunk_data = NULL;
	metadata->chunk_offset = metadata->itsf_hdr.dir_offset+CHM_ITSP_LEN;
	metadata->num_chunks = metadata->itsp_hdr.index_tail - metadata->itsp_hdr.index_head + 1;

	return CL_SUCCESS;

abort:
	return CL_EFORMAT;
}
