/*
 *  Extract RAR archives
 *
 *  Copyright (C) 2005-2006 trog@uncon.org
 *
 *  This code is based on the work of Alexander L. Roshal
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "unrar.h"
#include "unrar20.h"
#include "unrar15.h"
#include "clamav.h"
#include "others.h"
#include "cltypes.h"

#ifndef O_BINARY
#define O_BINARY        0
#endif

#define int64to32(x) ((unsigned int)(x))
#define rar_endian_convert_16(v)	le16_to_host(v)
#define rar_endian_convert_32(v)	le32_to_host(v)

#ifdef RAR_HIGH_DEBUG
#define rar_dbgmsg printf
#else
static void rar_dbgmsg(const char* fmt,...){}
#endif

static uint64_t copy_file_data(int ifd, int ofd, uint64_t len)
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
		if (cli_writen(ofd, data, count) != count) {
			return len-rem-count;
		}
		rem -= count;
	}
	return len;
}

static int is_rar_archive(int fd)
{
	mark_header_t mark;
	const mark_header_t rar_hdr[2] = {{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00},
		{'U', 'n', 'i', 'q', 'u', 'E', '!'}};

	if (cli_readn(fd, &mark, SIZEOF_MARKHEAD) != SIZEOF_MARKHEAD) {
		return FALSE;
	}
	
	if (memcmp(&mark, &rar_hdr[0], SIZEOF_MARKHEAD) == 0) {
		return TRUE;
	}
	if (memcmp(&mark, &rar_hdr[1], SIZEOF_MARKHEAD) == 0) {
		return TRUE;
	}

	cli_dbgmsg("Not a rar archive\n");
	return FALSE;
}

static int is_sfx_rar_archive(int fd)
{
	unsigned char buff[8192];
	const mark_header_t rar_hdr = {0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00};
	off_t offset=0, size, pos;
	
	lseek(fd, 0, SEEK_SET);
	for (;;) {
		size = cli_readn(fd, buff, 8192);
		if ((size == 0) || (size <= 9)) {
			return FALSE;
		}
		for (pos=0 ; pos < size-9 ; pos++) {
			if (buff[0] == 0x52) {
				if (memcmp(buff, &rar_hdr, 7) == 0) {
					offset += pos;
					lseek(fd, offset, SEEK_SET);
					return TRUE;
				}
			}
		}
		offset += size-9;
		lseek(fd, offset, SEEK_SET);
	}
	return FALSE;
}

static void *read_header(int fd, header_type hdr_type)
{
	uint8_t encrypt_ver;

	switch(hdr_type) {
	case MAIN_HEAD: {
		main_header_t *main_hdr;
		
		main_hdr = (main_header_t *) cli_malloc(sizeof(main_header_t));
		if (!main_hdr) {
			return NULL;
		}
		if (cli_readn(fd, main_hdr, SIZEOF_NEWMHD) != SIZEOF_NEWMHD) {
			free(main_hdr);
			return NULL;
		}
		main_hdr->flags = rar_endian_convert_16(main_hdr->flags);
		main_hdr->head_size = rar_endian_convert_16(main_hdr->head_size);
		main_hdr->head_crc = rar_endian_convert_16(main_hdr->head_crc);
		if (main_hdr->flags & MHD_ENCRYPTVER) {
	                if (cli_readn(fd, &encrypt_ver, sizeof(uint8_t)) != sizeof(uint8_t)) {
                        	free(main_hdr);
                        	return NULL;
			}
			cli_dbgmsg("RAR Encrypt version: %d\n", encrypt_ver);
                }

		return main_hdr;
		}
	case FILE_HEAD: {
		file_header_t *file_hdr;
		
		file_hdr = (file_header_t *) cli_malloc(sizeof(file_header_t));
		if (!file_hdr) {
			return NULL;
		}
		if (cli_readn(fd, file_hdr, SIZEOF_NEWLHD) != SIZEOF_NEWLHD) {
			free(file_hdr);
			return NULL;
		}
		file_hdr->flags = rar_endian_convert_16(file_hdr->flags);
		file_hdr->head_size = rar_endian_convert_16(file_hdr->head_size);
		file_hdr->pack_size = rar_endian_convert_32(file_hdr->pack_size);
		file_hdr->unpack_size = rar_endian_convert_32(file_hdr->unpack_size);
		file_hdr->file_crc = rar_endian_convert_32(file_hdr->file_crc);
		file_hdr->name_size = rar_endian_convert_16(file_hdr->name_size);
		if(file_hdr->flags & 0x100) {
			if (cli_readn(fd, (char *) file_hdr + SIZEOF_NEWLHD, 8) != 8) {
				free(file_hdr);
				return NULL;
			}
			file_hdr->high_pack_size = rar_endian_convert_32(file_hdr->high_pack_size);
			file_hdr->high_unpack_size = rar_endian_convert_32(file_hdr->high_unpack_size);
		} else {
			file_hdr->high_pack_size = 0;
			file_hdr->high_unpack_size = 0;
		}

		return file_hdr;
		}
	case COMM_HEAD: {
		comment_header_t *comment_hdr;

		comment_hdr = (comment_header_t *) cli_malloc(sizeof(comment_header_t));
		if (!comment_hdr) {
			return NULL;
		}
		if (cli_readn(fd, comment_hdr, SIZEOF_COMMHEAD) != SIZEOF_COMMHEAD) {
			free(comment_hdr);
			return NULL;
		}
		comment_hdr->unpack_size = rar_endian_convert_16(comment_hdr->unpack_size);
		comment_hdr->comm_crc = rar_endian_convert_16(comment_hdr->comm_crc);
		return comment_hdr;
		}
	default:
		cli_dbgmsg("ERROR: Unknown header type requested\n");
		return NULL;
	}
	return NULL;
}

static file_header_t *read_block(int fd, header_type hdr_type)
{
	file_header_t *file_header;
	off_t offset;
	
	for (;;) {
		offset = lseek(fd, 0, SEEK_CUR);
		rar_dbgmsg("read_block offset=%ld\n", offset);
		file_header = read_header(fd, FILE_HEAD);
		if (!file_header) {
			return NULL;
		}
		rar_dbgmsg(" head_size=%u\n", file_header->head_size);
		file_header->start_offset = offset;
		file_header->next_offset = offset + file_header->head_size;
		if (file_header->flags & LONG_BLOCK) {
			file_header->next_offset += file_header->pack_size;
		}
		if (file_header->next_offset <= offset) {
			free(file_header);
			return NULL;
		}

		/* Check if the block is of the requested type */
		if (file_header->head_type == hdr_type) {
			/* TODO check what to do with SUBBLOCKS */
			break;
		}
		cli_dbgmsg("Found block type: 0x%x\n", file_header->head_type);
		cli_dbgmsg("Head Size: %.4x\n", file_header->head_size);
		if (lseek(fd, file_header->next_offset, SEEK_SET) != file_header->next_offset) {
			cli_dbgmsg("seek: %ld\n", file_header->next_offset);
			return NULL;
		}
		free(file_header);
	}
	rar_dbgmsg("read_block out offset=%ld\n", lseek(fd, 0, SEEK_CUR));
	cli_dbgmsg("Found file block.\n");
	cli_dbgmsg("Pack Size: %u\n", file_header->pack_size);
	cli_dbgmsg("UnPack Version: 0x%.2x\n", file_header->unpack_ver);
	cli_dbgmsg("Pack Method: 0x%.2x\n", file_header->method);
	file_header->filename = (unsigned char *) cli_malloc(file_header->name_size+1);
	if (!file_header->filename) {
		free(file_header);
		return NULL;
	}
	if (cli_readn(fd, file_header->filename, file_header->name_size) != file_header->name_size) {
		free(file_header->filename);
		free(file_header);
		return NULL;
	}
	file_header->filename[file_header->name_size] = '\0';
	cli_dbgmsg("Filename: %s\n", file_header->filename);

	return file_header;
}

void addbits(unpack_data_t *unpack_data, int bits)
{

	/*rar_dbgmsg("addbits: in_addr=%d in_bit=%d\n", unpack_data->in_addr, unpack_data->in_bit);*/
	bits += unpack_data->in_bit;
	unpack_data->in_addr += bits >> 3;
	unpack_data->in_bit = bits & 7;
}

unsigned int getbits(unpack_data_t *unpack_data)
{
	unsigned int bit_field;

	/*rar_dbgmsg("getbits: in_addr=%d in_bit=%d\n", unpack_data->in_addr, unpack_data->in_bit);*/
	bit_field = (unsigned int) unpack_data->in_buf[unpack_data->in_addr] << 16;
	bit_field |= (unsigned int) unpack_data->in_buf[unpack_data->in_addr+1] << 8;
	bit_field |= (unsigned int) unpack_data->in_buf[unpack_data->in_addr+2];
	bit_field >>= (8-unpack_data->in_bit);
	/*rar_dbgmsg("getbits return(%d)\n", BitField & 0xffff);*/
	return(bit_field & 0xffff);
}

int unp_read_buf(int fd, unpack_data_t *unpack_data)
{
	int data_size, retval;
	unsigned int read_size;

	data_size = unpack_data->read_top - unpack_data->in_addr;
	if (data_size < 0) {
		return FALSE;
	}
	
	/* Is buffer read pos more than half way? */
	if (unpack_data->in_addr > MAX_BUF_SIZE/2) {
		if (data_size > 0) {
			memmove(unpack_data->in_buf, unpack_data->in_buf+unpack_data->in_addr,
					data_size);
		}
		unpack_data->in_addr = 0;
		unpack_data->read_top = data_size;
	} else {
		data_size = unpack_data->read_top;
	}
	/* RAR2 depends on us only reading upto the end of the current compressed file */
	if (unpack_data->pack_size < ((MAX_BUF_SIZE-data_size)&~0xf)) {
		read_size = unpack_data->pack_size;
	} else {
		read_size = (MAX_BUF_SIZE-data_size)&~0xf;
	}
	retval = cli_readn(fd, unpack_data->in_buf+data_size, read_size);	
	if (retval > 0) {
		unpack_data->read_top += retval;
		unpack_data->pack_size -= retval;
	}
	unpack_data->read_border = unpack_data->read_top - 30;
	if(unpack_data->read_border < unpack_data->in_addr) {
		const ssize_t fill = ((unpack_data->read_top + 30) < MAX_BUF_SIZE) ? 30 : (MAX_BUF_SIZE - unpack_data->read_top);
		if(fill)
			memset(unpack_data->in_buf + unpack_data->read_top, 0, fill);
	}
	return (retval!=-1);
}

static void unp_write_data(unpack_data_t *unpack_data, uint8_t *data, int size)
{
	rar_dbgmsg("in unp_write_data length=%d\n", size);
	cli_writen(unpack_data->ofd, data, size);
	unpack_data->written_size += size;
}

static void unp_write_area(unpack_data_t *unpack_data, unsigned int start_ptr, unsigned int end_ptr)
{
	if (end_ptr < start_ptr) {
		unp_write_data(unpack_data, &unpack_data->window[start_ptr], -start_ptr & MAXWINMASK);
		unp_write_data(unpack_data, unpack_data->window, end_ptr);
	} else {
		unp_write_data(unpack_data, &unpack_data->window[start_ptr], end_ptr-start_ptr);
	}
}

void unp_write_buf_old(unpack_data_t *unpack_data)
{
	rar_dbgmsg("in unp_write_buf_old\n");
	if (unpack_data->unp_ptr < unpack_data->wr_ptr) {
		unp_write_data(unpack_data, &unpack_data->window[unpack_data->wr_ptr],
				-unpack_data->wr_ptr & MAXWINMASK);
		unp_write_data(unpack_data, unpack_data->window, unpack_data->unp_ptr);
	} else {
		unp_write_data(unpack_data, &unpack_data->window[unpack_data->wr_ptr],
				unpack_data->unp_ptr - unpack_data->wr_ptr);
	}
	unpack_data->wr_ptr = unpack_data->unp_ptr;
}

void make_decode_tables(unsigned char *len_tab, struct Decode *decode, int size)
{
	int len_count[16], tmp_pos[16], i;
	long m,n;
	
	memset(len_count, 0, sizeof(len_count));
	memset(decode->DecodeNum,0,size*sizeof(*decode->DecodeNum));
	for (i=0 ; i < size ; i++) {
		len_count[len_tab[i] & 0x0f]++;
	}
	
	len_count[0]=0;
	for (tmp_pos[0]=decode->DecodePos[0]=decode->DecodeLen[0]=0,n=0,i=1;i<16;i++) {
		n=2*(n+len_count[i]);
		m=n<<(15-i);
		if (m>0xFFFF) {
			m=0xFFFF;
		}
		decode->DecodeLen[i]=(unsigned int)m;
		tmp_pos[i]=decode->DecodePos[i]=decode->DecodePos[i-1]+len_count[i-1];
	}
	
	for (i=0;i<size;i++) {
		if (len_tab[i]!=0) {
			decode->DecodeNum[tmp_pos[len_tab[i] & 0x0f]++]=i;
		}
	}
	decode->MaxNum=size;
}

int decode_number(unpack_data_t *unpack_data, struct Decode *decode)
{
	unsigned int bits, bit_field, n;
	
	bit_field = getbits(unpack_data) & 0xfffe;
	rar_dbgmsg("decode_number BitField=%u\n", bit_field);
	if (bit_field < decode->DecodeLen[8])
		if (bit_field < decode->DecodeLen[4])
			if (bit_field < decode->DecodeLen[2])
				if (bit_field < decode->DecodeLen[1])
					bits=1;
				else
					bits=2;
			else
				if (bit_field < decode->DecodeLen[3])
					bits=3;
				else
					bits=4;
		else
			if (bit_field < decode->DecodeLen[6])
				if (bit_field < decode->DecodeLen[5])
					bits=5;
				else
					bits=6;
			else
				if (bit_field < decode->DecodeLen[7])
					bits=7;
				else
					bits=8;
	else
		if (bit_field < decode->DecodeLen[12])
			if (bit_field < decode->DecodeLen[10])
				if (bit_field < decode->DecodeLen[9])
					bits=9;
				else
					bits=10;
			else
				if (bit_field < decode->DecodeLen[11])
					bits=11;
				else
					bits=12;
		else
			if (bit_field < decode->DecodeLen[14])
				if (bit_field < decode->DecodeLen[13])
					bits=13;
				else
					bits=14;
			else
				bits=15;

	rar_dbgmsg("decode_number: bits=%d\n", bits);

	addbits(unpack_data, bits);
	n=decode->DecodePos[bits]+((bit_field-decode->DecodeLen[bits-1])>>(16-bits));
	if (n >= decode->MaxNum) {
		n=0;
	}
	/*rar_dbgmsg("decode_number return(%d)\n", decode->DecodeNum[n]);*/

	return(decode->DecodeNum[n]);
}

void unpack_init_data(int solid, unpack_data_t *unpack_data)
{
	if (!solid) {
		memset(unpack_data->old_dist, 0, sizeof(unpack_data->old_dist));
		unpack_data->old_dist_ptr= 0;
		unpack_data->last_dist= 0;
		unpack_data->last_length=0;
		unpack_data->unp_ptr = 0;
		unpack_data->wr_ptr = 0;
	}

	unpack_data->in_bit = 0;
	unpack_data->in_addr = 0;
	unpack_data->read_top = 0;
	
	unpack_data->written_size = 0;

	unpack_init_data20(solid, unpack_data);

}

static int rar_unpack(int fd, int method, int solid, unpack_data_t *unpack_data)
{
	int retval = FALSE;
	switch(method) {
	case 15:
		retval = rar_unpack15(fd, solid, unpack_data);
		break;
	case 20:
	case 26:
		retval = rar_unpack20(fd, solid, unpack_data);
		break;
	case 29:
		cli_warnmsg("RARv3 is not supported.\n");
		break;
	default:
		cli_errmsg("ERROR: Unknown RAR pack method: %d\n", method);
		break;
	}
	return retval;
}

int cli_unrar_open(int fd, const char *dirname, rar_state_t* state)
{
	int ofd, retval;
	unsigned char filename[1024];
	unpack_data_t *unpack_data;
	main_header_t *main_hdr;
	off_t offset;

	cli_dbgmsg("in cli_unrar\n");
	if(!state) {
		return CL_ENULLARG;
	}
	if (!is_rar_archive(fd)) {
		return CL_EFORMAT;
	}
	unpack_data = cli_malloc(sizeof(unpack_data_t));
	if(!unpack_data) {
	    cli_dbgmsg("unrar: cli_unrar: cli_malloc failed for unpack_data\n");
	    return CL_EMEM;
	}
	
	main_hdr = read_header(fd, MAIN_HEAD);
	if (!main_hdr) {
		free(unpack_data);
		return CL_ERAR;
	}
	cli_dbgmsg("Head CRC: %.4x\n", main_hdr->head_crc);
	cli_dbgmsg("Head Type: %.2x\n", main_hdr->head_type);
	cli_dbgmsg("Flags: %.4x\n", main_hdr->flags);
	cli_dbgmsg("Head Size: %.4x\n", main_hdr->head_size);

	snprintf(filename,1024,"%s/comments",dirname);
	if(mkdir(filename,0700)) {
		cli_dbgmsg("cli_unrar: Unable to create comment temporary directory\n");
		free(main_hdr);
		free(unpack_data);
		return CL_ETMPDIR;
	}
	state->comment_dir = cli_strdup(filename);
	if(!state->comment_dir) {
		free(main_hdr);
		free(unpack_data);
		return CL_EMEM;
	}

	if (main_hdr->head_size < SIZEOF_NEWMHD) {
		free(main_hdr);
		free(unpack_data);
		free(state->comment_dir);
		return CL_EFORMAT;
	}
	if (main_hdr->flags & MHD_COMMENT) {
		comment_header_t *comment_header;
		cli_dbgmsg("RAR main comment\n");
		offset = lseek(fd, 0, SEEK_CUR);
		cli_dbgmsg("Offset: %x\n", offset);
		comment_header = read_header(fd, COMM_HEAD);
		if (comment_header) {
			cli_dbgmsg("Comment type: 0x%.2x\n", comment_header->head_type);
			cli_dbgmsg("Head size: 0x%.4x\n", comment_header->head_size);
			cli_dbgmsg("UnPack Size: 0x%.4x\n", comment_header->unpack_size);
			cli_dbgmsg("UnPack Version: 0x%.2x\n", comment_header->unpack_ver);
			cli_dbgmsg("Pack Method: 0x%.2x\n", comment_header->method);
			snprintf(filename, 1024, "%s/main.cmt", state->comment_dir);
			ofd = open(filename, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, 0600);
			if (ofd < 0) {
				free(comment_header);
				cli_dbgmsg("ERROR: Failed to open output file\n");
				free(main_hdr);
				free(unpack_data);
				free(state->comment_dir);
				return CL_EIO;
			} else {
				if (comment_header->method == 0x30) {
					cli_dbgmsg("Copying stored comment (not packed)\n");
					copy_file_data(fd, ofd, comment_header->unpack_size);
				} else {
					unpack_data->ofd = ofd;
					unpack_data->dest_unp_size = comment_header->unpack_size;
					unpack_data->pack_size = comment_header->head_size - SIZEOF_COMMHEAD;
                        		retval = rar_unpack(fd, comment_header->unpack_ver, FALSE, unpack_data);
					/*unpack_free_data(unpack_data);*/
				}
				close(ofd);
			}
			free(comment_header);
		}
		lseek(fd, offset, SEEK_SET);
	}

	if (main_hdr->head_size > SIZEOF_NEWMHD) {
		if (!lseek(fd, main_hdr->head_size - SIZEOF_NEWMHD, SEEK_CUR)) {
			free(main_hdr);
			free(unpack_data);
			free(state->comment_dir);
			return CL_EFORMAT; /* truncated? */
		}
	}

	state->unpack_data = unpack_data;
	state->main_hdr = main_hdr;
	state->metadata_tail = state->metadata = NULL;
	state->file_count = 1;
	state->offset = offset;
	state->fd = fd;

	return CL_SUCCESS;
}

int cli_unrar_extract_next_prepare(rar_state_t* state,const char* dirname)
{
	unsigned char filename[1024];
	int ofd;

	rar_metadata_t *new_metadata;
	state->file_header = read_block(state->fd, FILE_HEAD);
	if (!state->file_header) {
		return CL_BREAK;/* end of archive */
	}
	new_metadata = cli_malloc(sizeof(rar_metadata_t));
	if (!new_metadata) {
		return CL_EMEM;
	}
	new_metadata->pack_size = state->file_header->high_pack_size * 0x100000000 + state->file_header->pack_size;
	new_metadata->unpack_size = state->file_header->high_unpack_size * 0x100000000 + state->file_header->unpack_size;
	new_metadata->crc = state->file_header->file_crc;
	new_metadata->method = state->file_header->method;
	new_metadata->filename = cli_strdup(state->file_header->filename);
	new_metadata->next = NULL;
	new_metadata->encrypted = FALSE;
	if (state->metadata_tail == NULL) {
		state->metadata_tail = state->metadata = new_metadata;
	} else {
		state->metadata_tail->next = new_metadata;
		state->metadata_tail = new_metadata;
	}
	if (state->file_header->flags & LHD_COMMENT) {
		comment_header_t *comment_header;
		
		cli_dbgmsg("File comment present\n");
		comment_header = read_header(state->fd, COMM_HEAD);
		if (comment_header) {
			cli_dbgmsg("Comment type: 0x%.2x\n", comment_header->head_type);
			cli_dbgmsg("Head size: 0x%.4x\n", comment_header->head_size);
			cli_dbgmsg("UnPack Size: 0x%.4x\n", comment_header->unpack_size);
			cli_dbgmsg("UnPack Version: 0x%.2x\n", comment_header->unpack_ver);
			cli_dbgmsg("Pack Method: 0x%.2x\n", comment_header->method);
			
			if ((comment_header->unpack_ver < 15) || (comment_header->unpack_ver > 29) ||
					(comment_header->method > 0x30)) {
				cli_dbgmsg("Can't process file comment - skipping\n");
			} else {
				snprintf(filename, 1024, "%s/%lu.cmt", state->comment_dir, state->file_count);
				ofd = open(filename, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, 0600);
				if (ofd < 0) {
					free(comment_header);
					cli_dbgmsg("ERROR: Failed to open output file\n");
				} else {
					cli_dbgmsg("Copying file comment (not packed)\n");
					copy_file_data(state->fd, ofd, comment_header->unpack_size);
					close(ofd);
				}
			}
			free(comment_header);
		}
	}
	return CL_SUCCESS;
}

int cli_unrar_extract_next(rar_state_t* state,const char* dirname)
{
	int ofd;
	int retval;

	if (lseek(state->fd, state->file_header->start_offset+state->file_header->head_size, SEEK_SET) !=
			state->file_header->start_offset+state->file_header->head_size) {
		cli_dbgmsg("Seek failed: %ld\n", state->offset+state->file_header->head_size);
		free(state->file_header->filename);
		free(state->file_header);
		return CL_ERAR;
	}
	if (state->file_header->flags & LHD_PASSWORD) {
		cli_dbgmsg("PASSWORDed file: %s\n", state->file_header->filename);
		state->metadata_tail->encrypted = TRUE;

	} else if(state->file_header->flags & (LHD_SPLIT_BEFORE | LHD_SPLIT_AFTER)) {
	        cli_dbgmsg("Skipping split file\n");

	} else if((state->main_hdr->flags & MHD_VOLUME) && (state->main_hdr->flags & MHD_SOLID)) {
	        cli_dbgmsg("Skipping file inside multi-volume solid archive\n");

	} else /*if (file_header->unpack_size)*/ {
		snprintf(state->filename, 1024, "%s/%lu.ura", dirname, state->file_count);
		ofd = open(state->filename, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, 0600);
		if (ofd < 0) {
			free(state->file_header->filename);
			free(state->file_header);
			cli_dbgmsg("ERROR: Failed to open output file\n");
			return CL_EOPEN;
		}
		state->unpack_data->ofd = ofd;
		if (state->file_header->method == 0x30) {
			cli_dbgmsg("Copying stored file (not packed)\n");
			copy_file_data(state->fd, ofd, state->file_header->pack_size);
		} else {
			state->unpack_data->dest_unp_size = state->file_header->unpack_size;
			state->unpack_data->pack_size = state->file_header->pack_size;
			if (state->file_header->unpack_ver <= 15) {
				retval = rar_unpack(state->fd, 15, (state->file_count>1) &&
						((state->main_hdr->flags&MHD_SOLID)!=0), state->unpack_data);
			} else {
				if ((state->file_count == 1) && (state->file_header->flags & LHD_SOLID)) {
					cli_warnmsg("RAR: Bad header. First file can't be SOLID.\n");
					cli_warnmsg("RAR: Clearing flag and continuing.\n");
					state->file_header->flags -= LHD_SOLID;
				}
				retval = rar_unpack(state->fd, state->file_header->unpack_ver,
							state->file_header->flags & LHD_SOLID,	state->unpack_data);
			}
			if (!retval) {
				cli_dbgmsg("Corrupt file detected\n");
				if (state->file_header->flags & LHD_SOLID) {
					cli_dbgmsg("SOLID archive, can't continue\n");
					free(state->file_header->filename);
					free(state->file_header);
					
					return CL_ERAR;
				}
			}
		}
		
	}
	if (lseek(state->fd, state->file_header->next_offset, SEEK_SET) != state->file_header->next_offset) {
		cli_dbgmsg("ERROR: seek failed: %ld\n", state->file_header->next_offset);
		free(state->file_header->filename);
		free(state->file_header);
		return CL_ERAR;
	}
	free(state->file_header->filename);
	free(state->file_header);
	state->file_count++;
	return CL_SUCCESS;
}

void cli_unrar_close(rar_state_t* state)
{
	free(state->main_hdr);
	free(state->unpack_data);
	free(state->comment_dir);
}
