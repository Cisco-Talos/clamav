/*
 *  Extract RAR archives
 *
 *  Copyright (C) 2005-2006 trog@uncon.org
 *
 *  This code is based on the work of Alexander L. Roshal (C)
 *
 *  The unRAR sources may be used in any software to handle RAR
 *  archives without limitations free of charge, but cannot be used
 *  to re-create the RAR compression algorithm, which is proprietary.
 *  Distribution of modified unRAR sources in separate form or as a
 *  part of other software is permitted, provided that it is clearly
 *  stated in the documentation and source comments that the code may
 *  not be used to develop a RAR (WinRAR) compatible archiver.
 *
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
#include "unrarppm.h"
#include "unrarvm.h"
#include "unrarfilter.h"
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

static void dump_tables(unpack_data_t *unpack_data)
{
	int i;
	
	/* Dump LD table */
	cli_dbgmsg("LD Table MaxNum=%d\n", unpack_data->LD.MaxNum);
	cli_dbgmsg("\tDecodeLen:");
	for (i=0 ; i < 16; i++) {
		cli_dbgmsg(" %.8d", unpack_data->LD.DecodeLen[i]);
	}
	cli_dbgmsg("\n\tDecodePos:");
	for (i=0 ; i < 16; i++) {
		cli_dbgmsg(" %.8d", unpack_data->LD.DecodePos[i]);
	}
	cli_dbgmsg("\n\tDecodeNum:");
	for (i=0 ; i < NC; i++) {
		cli_dbgmsg(" %.8d", unpack_data->LD.DecodeNum[i]);
	}
	
	
	cli_dbgmsg("\nDD Table MaxNum=%d\n", unpack_data->DD.MaxNum);
	cli_dbgmsg("\tDecodeLen:");
	for (i=0 ; i < 16; i++) {
		cli_dbgmsg(" %.8d", unpack_data->DD.DecodeLen[i]);
	}
	cli_dbgmsg("\n\tDecodePos:");
	for (i=0 ; i < 16; i++) {
		cli_dbgmsg(" %.8d", unpack_data->DD.DecodePos[i]);
	}
	cli_dbgmsg("\n\tDecodeNum:");
	for (i=0 ; i < DC; i++) {
		cli_dbgmsg(" %.8d", unpack_data->DD.DecodeNum[i]);
	}
	
	cli_dbgmsg("\nLDD Table MaxNum=%d\n", unpack_data->LDD.MaxNum);
	cli_dbgmsg("\tDecodeLen:");
	for (i=0 ; i < 16; i++) {
		cli_dbgmsg(" %.8d", unpack_data->LDD.DecodeLen[i]);
	}
	cli_dbgmsg("\n\tDecodePos:");
	for (i=0 ; i < 16; i++) {
		cli_dbgmsg(" %.8d", unpack_data->LDD.DecodePos[i]);
	}
	cli_dbgmsg("\n\tDecodeNum:");
	for (i=0 ; i < LDC; i++) {
		cli_dbgmsg(" %.8d", unpack_data->LDD.DecodeNum[i]);
	}
	
	cli_dbgmsg("\nRD Table MaxNum=%d\n", unpack_data->RD.MaxNum);
	cli_dbgmsg("\tDecodeLen:");
	for (i=0 ; i < 16; i++) {
		cli_dbgmsg(" %.8d", unpack_data->RD.DecodeLen[i]);
	}
	cli_dbgmsg("\n\tDecodePos:");
	for (i=0 ; i < 16; i++) {
		cli_dbgmsg(" %.8d", unpack_data->RD.DecodePos[i]);
	}
	cli_dbgmsg("\n\tDecodeNum:");
	for (i=0 ; i < RC; i++) {
		cli_dbgmsg(" %.8d", unpack_data->RD.DecodeNum[i]);
	}
	
	cli_dbgmsg("\nBD Table MaxNum=%d\n", unpack_data->BD.MaxNum);
	cli_dbgmsg("\tDecodeLen:");
	for (i=0 ; i < 16; i++) {
		cli_dbgmsg(" %.8d", unpack_data->BD.DecodeLen[i]);
	}
	cli_dbgmsg("\n\tDecodePos:");
	for (i=0 ; i < 16; i++) {
		cli_dbgmsg(" %.8d", unpack_data->BD.DecodePos[i]);
	}
	cli_dbgmsg("\n\tDecodeNum:");
	for (i=0 ; i < BC; i++) {
		cli_dbgmsg(" %.8d", unpack_data->BD.DecodeNum[i]);
	}
	cli_dbgmsg("\n");
}

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
	
static void insert_old_dist(unpack_data_t *unpack_data, unsigned int distance)
{
	unpack_data->old_dist[3] = unpack_data->old_dist[2];
	unpack_data->old_dist[2] = unpack_data->old_dist[1];
	unpack_data->old_dist[1] = unpack_data->old_dist[0];
	unpack_data->old_dist[0] = distance;
}

static void insert_last_match(unpack_data_t *unpack_data, unsigned int length, unsigned int distance)
{
	unpack_data->last_dist = distance;
	unpack_data->last_length = length;
}

static void copy_string(unpack_data_t *unpack_data, unsigned int length, unsigned int distance)
{
	unsigned int dest_ptr;
	
	dest_ptr = unpack_data->unp_ptr - distance;
	if (dest_ptr < MAXWINSIZE-260 && unpack_data->unp_ptr < MAXWINSIZE - 260) {
		unpack_data->window[unpack_data->unp_ptr++] = unpack_data->window[dest_ptr++];
		while (--length > 0) {
			unpack_data->window[unpack_data->unp_ptr++] = unpack_data->window[dest_ptr++];
		}
	} else {
		while (length--) {
			unpack_data->window[unpack_data->unp_ptr] =
						unpack_data->window[dest_ptr++ & MAXWINMASK];
			unpack_data->unp_ptr = (unpack_data->unp_ptr + 1) & MAXWINMASK;
		}
	}
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

unsigned int rar_get_char(int fd, unpack_data_t *unpack_data)
{
	if (unpack_data->in_addr > MAX_BUF_SIZE-30) {
		if (!unp_read_buf(fd, unpack_data)) {
			cli_errmsg("rar_get_char: unp_read_buf FAILED\n");
			return -1;
		}
	}
	rar_dbgmsg("rar_get_char = %u\n", unpack_data->in_buf[unpack_data->in_addr]);
	return(unpack_data->in_buf[unpack_data->in_addr++]);
}

static void unp_write_data(unpack_data_t *unpack_data, uint8_t *data, int size)
{
	rar_dbgmsg("in unp_write_data length=%d\n", size);
	cli_writen(unpack_data->ofd, data, size);
	unpack_data->written_size += size;
	unpack_data->unp_crc = rar_crc(unpack_data->unp_crc, data, size);
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

static void execute_code(unpack_data_t *unpack_data, struct rarvm_prepared_program *prg)
{
	rar_dbgmsg("in execute_code\n");
	rar_dbgmsg("global_size: %ld\n", prg->global_size);
	if (prg->global_size > 0) {
		prg->init_r[6] = int64to32(unpack_data->written_size);
		rarvm_set_value(FALSE, (unsigned int *)&prg->global_data[0x24],
				int64to32(unpack_data->written_size));
		rarvm_set_value(FALSE, (unsigned int *)&prg->global_data[0x28],
				int64to32(unpack_data->written_size>>32));
		rarvm_execute(&unpack_data->rarvm_data, prg);
	}
}

		
static void unp_write_buf(unpack_data_t *unpack_data)
{
	unsigned int written_border, part_length, filtered_size;
	unsigned int write_size, block_start, block_length, block_end;
	struct UnpackFilter *flt, *next_filter;
	struct rarvm_prepared_program *prg, *next_prg;
	uint8_t *filtered_data;
	int i, j;
	
	rar_dbgmsg("in unp_write_buf\n");
	written_border = unpack_data->wr_ptr;
	write_size = (unpack_data->unp_ptr - written_border) & MAXWINMASK;
	for (i=0 ; i < unpack_data->PrgStack.num_items ; i++) {
		flt = unpack_data->PrgStack.array[i];
		if (flt == NULL) {
			continue;
		}
		if (flt->next_window) {
			flt->next_window = FALSE;
			continue;
		}
		block_start = flt->block_start;
		block_length = flt->block_length;
		if (((block_start-written_border)&MAXWINMASK) < write_size) {
			if (written_border != block_start) {
				unp_write_area(unpack_data, written_border, block_start);
				written_border = block_start;
				write_size = (unpack_data->unp_ptr - written_border) & MAXWINMASK;
			}
			if (block_length <= write_size) {
				block_end = (block_start + block_length) & MAXWINMASK;
				if (block_start < block_end || block_end==0) {
					rarvm_set_memory(&unpack_data->rarvm_data, 0,
							unpack_data->window+block_start, block_length);
				} else {
					part_length = MAXWINMASK - block_start;
					rarvm_set_memory(&unpack_data->rarvm_data, 0,
							unpack_data->window+block_start, part_length);
					rarvm_set_memory(&unpack_data->rarvm_data, part_length,
							unpack_data->window, block_end);
				}
				prg = &flt->prg;
				execute_code(unpack_data, prg);
				
				filtered_data = prg->filtered_data;
				filtered_size = prg->filtered_data_size;
				
				rar_filter_delete(unpack_data->PrgStack.array[i]);
				unpack_data->PrgStack.array[i] = NULL;
				while (i+1 < unpack_data->PrgStack.num_items) {
					next_filter = unpack_data->PrgStack.array[i+1];
					if (next_filter==NULL ||
							next_filter->block_start!=block_start ||
							next_filter->block_length!=filtered_size ||
							next_filter->next_window) {
						break;
					}
					rarvm_set_memory(&unpack_data->rarvm_data, 0,
							filtered_data, filtered_size);
					next_prg = &unpack_data->PrgStack.array[i+1]->prg;
					execute_code(unpack_data, next_prg);
					filtered_data = next_prg->filtered_data;
					filtered_size = next_prg->filtered_data_size;
					i++;
					rar_filter_delete(unpack_data->PrgStack.array[i]);
					unpack_data->PrgStack.array[i] = NULL;
				}
				unp_write_data(unpack_data, filtered_data, filtered_size);
				written_border = block_end;
				write_size = (unpack_data->unp_ptr - written_border) & MAXWINMASK;
			} else {
				for (j=i ; j < unpack_data->PrgStack.num_items ; j++) {
					flt = unpack_data->PrgStack.array[j];
					if (flt != NULL && flt->next_window) {
						flt->next_window = FALSE;
					}
				}
				unpack_data->wr_ptr = written_border;
				return;
				
			}
		}
	}
	unp_write_area(unpack_data, written_border, unpack_data->unp_ptr);
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

static int read_tables(int fd, unpack_data_t *unpack_data)
{
	uint8_t bit_length[BC];
	unsigned char table[HUFF_TABLE_SIZE];
	unsigned int bit_field;
	int i, length, zero_count, number, n;
	const int table_size=HUFF_TABLE_SIZE;
	
	cli_dbgmsg("in read_tables Offset=%ld in_addr=%d read_top=%d\n", lseek(fd, 0, SEEK_CUR),
				unpack_data->in_addr, unpack_data->read_top);
	if (unpack_data->in_addr > unpack_data->read_top-25) {
		if (!unp_read_buf(fd, unpack_data)) {
			cli_dbgmsg("ERROR: read_tables unp_read_buf failed\n");
			return FALSE;
		}
	}
	addbits(unpack_data, (8-unpack_data->in_bit) & 7);
	bit_field = getbits(unpack_data);
	rar_dbgmsg("BitField = 0x%x\n", bit_field);
	if (bit_field & 0x8000) {
		unpack_data->unp_block_type = BLOCK_PPM;
		rar_dbgmsg("Calling ppm_decode_init\n");
		if(!ppm_decode_init(&unpack_data->ppm_data, fd, unpack_data, &unpack_data->ppm_esc_char)) {
		    cli_dbgmsg("unrar: read_tables: ppm_decode_init failed\n");
		    return FALSE;
		}
		return(TRUE);
	}
	unpack_data->unp_block_type = BLOCK_LZ;
	unpack_data->prev_low_dist = 0;
	unpack_data->low_dist_rep_count = 0;

	if (!(bit_field & 0x4000)) {
		memset(unpack_data->unp_old_table, 0, sizeof(unpack_data->unp_old_table));
	}
	addbits(unpack_data, 2);
	
	for (i=0 ; i < BC ; i++) {
		length = (uint8_t)(getbits(unpack_data) >> 12);
		addbits(unpack_data, 4);
		if (length == 15) {
			zero_count = (uint8_t)(getbits(unpack_data) >> 12);
			addbits(unpack_data, 4);
			if (zero_count == 0) {
				bit_length[i] = 15;
			} else {
				zero_count += 2;
				while (zero_count-- > 0 &&
						i<sizeof(bit_length)/sizeof(bit_length[0])) {
					bit_length[i++]=0;
				}
				i--;
			}
		} else {
			bit_length[i] = length;
		}
	}
	make_decode_tables(bit_length,(struct Decode *)&unpack_data->BD,BC);
	
	for (i=0;i<table_size;) {
		if (unpack_data->in_addr > unpack_data->read_top-5) {
			if (!unp_read_buf(fd, unpack_data)) {
				cli_dbgmsg("ERROR: read_tables unp_read_buf failed 2\n");
				return FALSE;
			}
		}
		number = decode_number(unpack_data, (struct Decode *)&unpack_data->BD);
		if (number < 16) {
			table[i] = (number+unpack_data->unp_old_table[i]) & 0xf;
			i++;
		} else if (number < 18) {
			if (number == 16) {
				n = (getbits(unpack_data) >> 13) + 3;
				addbits(unpack_data, 3);
			} else {
				n = (getbits(unpack_data) >> 9) + 11;
				addbits(unpack_data, 7);
			}
			while (n-- > 0 && i < table_size) {
				table[i] = table[i-1];
				i++;
			}
		} else {
			if (number == 18) {
				n = (getbits(unpack_data) >> 13) + 3;
				addbits(unpack_data, 3);
			} else {
				n = (getbits(unpack_data) >> 9) + 11;
				addbits(unpack_data, 7);
			}
			while (n-- > 0 && i < table_size) {
				table[i++] = 0;
			}
		}
	}
	unpack_data->tables_read = TRUE;
	if (unpack_data->in_addr > unpack_data->read_top) {
		cli_dbgmsg("ERROR: read_tables check failed\n");
		return FALSE;
	}
	make_decode_tables(&table[0], (struct Decode *)&unpack_data->LD,NC);
	make_decode_tables(&table[NC], (struct Decode *)&unpack_data->DD,DC);
	make_decode_tables(&table[NC+DC], (struct Decode *)&unpack_data->LDD,LDC);
	make_decode_tables(&table[NC+DC+LDC], (struct Decode *)&unpack_data->RD,RC);
	memcpy(unpack_data->unp_old_table,table,sizeof(unpack_data->unp_old_table));
	

	/*dump_tables(unpack_data);*/
	rar_dbgmsg("ReadTables finished\n");
  	return TRUE;
}

static int read_end_of_block(int fd, unpack_data_t *unpack_data)
{
	unsigned int bit_field;
	int new_table, new_file=FALSE;
	
	bit_field = getbits(unpack_data);
	if (bit_field & 0x8000) {
		new_table = TRUE;
		addbits(unpack_data, 1);
	} else {
		new_file = TRUE;
		new_table = (bit_field & 0x4000);
		addbits(unpack_data, 2);
	}
	unpack_data->tables_read = !new_table;
	rar_dbgmsg("NewFile=%d NewTable=%d TablesRead=%d\n", new_file,
			new_table, unpack_data->tables_read);
	return !(new_file || (new_table && !read_tables(fd, unpack_data)));
}

static void init_filters(unpack_data_t *unpack_data)
{	
	if (unpack_data->old_filter_lengths) {
		free(unpack_data->old_filter_lengths);
		unpack_data->old_filter_lengths = NULL;
	}
	unpack_data->old_filter_lengths_size = 0;
	unpack_data->last_filter = 0;
	
	rar_filter_array_reset(&unpack_data->Filters);
	rar_filter_array_reset(&unpack_data->PrgStack);
}

static int add_vm_code(unpack_data_t *unpack_data, unsigned int first_byte,
			unsigned char *vmcode, int code_size)
{
	rarvm_input_t rarvm_input;
	unsigned int filter_pos, new_filter, block_start, init_mask, cur_size;
	struct UnpackFilter *filter, *stack_filter;
	int i, empty_count, stack_pos, vm_codesize, static_size, data_size;
	unsigned char *vm_code, *global_data;
	
	rar_dbgmsg("in add_vm_code first_byte=0x%x code_size=%d\n", first_byte, code_size);
	rarvm_input.in_buf = vmcode;
	rarvm_input.buf_size = code_size;
	rarvm_input.in_addr = 0;
	rarvm_input.in_bit = 0;

	if (first_byte & 0x80) {
		filter_pos = rarvm_read_data(&rarvm_input);
		if (filter_pos == 0) {
			init_filters(unpack_data);
		} else {
			filter_pos--;
		}
	} else {
		filter_pos = unpack_data->last_filter;
	}
	rar_dbgmsg("filter_pos = %u\n", filter_pos);
	if (filter_pos > unpack_data->Filters.num_items ||
			filter_pos > unpack_data->old_filter_lengths_size) {
		cli_dbgmsg("filter_pos check failed\n");
		return FALSE;
	}
	unpack_data->last_filter = filter_pos;
	new_filter = (filter_pos == unpack_data->Filters.num_items);
	rar_dbgmsg("Filters.num_items=%d\n", unpack_data->Filters.num_items);
	rar_dbgmsg("new_filter=%d\n", new_filter);
	if (new_filter) {
		if (!rar_filter_array_add(&unpack_data->Filters, 1)) {
			cli_dbgmsg("rar_filter_array_add failed\n");
			return FALSE;
		}
		unpack_data->Filters.array[unpack_data->Filters.num_items-1] =
					filter = rar_filter_new();
		if (!unpack_data->Filters.array[unpack_data->Filters.num_items-1]) {
			cli_dbgmsg("rar_filter_new failed\n");
			return FALSE;
		}	
		unpack_data->old_filter_lengths_size++;
		unpack_data->old_filter_lengths = (int *) cli_realloc2(unpack_data->old_filter_lengths,
				sizeof(int) * unpack_data->old_filter_lengths_size);
		if(!unpack_data->old_filter_lengths) {
		    cli_dbgmsg("unrar: add_vm_code: cli_realloc2 failed for unpack_data->old_filter_lengths\n");
		    return FALSE;
		}
		unpack_data->old_filter_lengths[unpack_data->old_filter_lengths_size-1] = 0;
		filter->exec_count = 0;
	} else {
		filter = unpack_data->Filters.array[filter_pos];
		filter->exec_count++;
	}
	
	stack_filter = rar_filter_new();

	empty_count = 0;
	for (i=0 ; i < unpack_data->PrgStack.num_items; i++) {
		unpack_data->PrgStack.array[i-empty_count] = unpack_data->PrgStack.array[i];
		if (unpack_data->PrgStack.array[i] == NULL) {
			empty_count++;
		}
		if (empty_count > 0) {
			unpack_data->PrgStack.array[i] = NULL;
		}
	}
	
	if (empty_count == 0) {
		rar_filter_array_add(&unpack_data->PrgStack, 1);
		empty_count = 1;
	}
	stack_pos = unpack_data->PrgStack.num_items - empty_count;
	unpack_data->PrgStack.array[stack_pos] = stack_filter;
	stack_filter->exec_count = filter->exec_count;
	
	block_start = rarvm_read_data(&rarvm_input);
	rar_dbgmsg("block_start=%u\n", block_start);
	if (first_byte & 0x40) {
		block_start += 258;
	}
	stack_filter->block_start = (block_start + unpack_data->unp_ptr) & MAXWINMASK;
	if (first_byte & 0x20) {
		stack_filter->block_length = rarvm_read_data(&rarvm_input);
	} else {
		stack_filter->block_length = filter_pos < unpack_data->old_filter_lengths_size ?
				unpack_data->old_filter_lengths[filter_pos] : 0;
	}
	rar_dbgmsg("block_length=%u\n", stack_filter->block_length);
	stack_filter->next_window = unpack_data->wr_ptr != unpack_data->unp_ptr &&
		((unpack_data->wr_ptr - unpack_data->unp_ptr) & MAXWINMASK) <= block_start;
		
	unpack_data->old_filter_lengths[filter_pos] = stack_filter->block_length;
	
	memset(stack_filter->prg.init_r, 0, sizeof(stack_filter->prg.init_r));
	stack_filter->prg.init_r[3] = VM_GLOBALMEMADDR;
	stack_filter->prg.init_r[4] = stack_filter->block_length;
	stack_filter->prg.init_r[5] = stack_filter->exec_count;
	if (first_byte & 0x10) {
		init_mask = rarvm_getbits(&rarvm_input) >> 9;
		rarvm_addbits(&rarvm_input, 7);
		for (i=0 ; i<7 ; i++) {
			if (init_mask & (1<<i)) {
				stack_filter->prg.init_r[i] =
					rarvm_read_data(&rarvm_input);
				rar_dbgmsg("prg.init_r[%d] = %u\n", i, stack_filter->prg.init_r[i]);
			}
		}
	}
	if (new_filter) {
		vm_codesize = rarvm_read_data(&rarvm_input);
		if (vm_codesize >= 0x1000 || vm_codesize == 0 || (vm_codesize > rarvm_input.buf_size)) {
			cli_dbgmsg("ERROR: vm_codesize=0x%x buf_size=0x%x\n", vm_codesize, rarvm_input.buf_size);
			return FALSE;
		}
		vm_code = (unsigned char *) cli_malloc(vm_codesize);
		if(!vm_code) {
		    cli_dbgmsg("unrar: add_vm_code: cli_malloc failed for vm_code\n");
		    return FALSE;
		}
		for (i=0 ; i < vm_codesize ; i++) {
			vm_code[i] = rarvm_getbits(&rarvm_input) >> 8;
			rarvm_addbits(&rarvm_input, 8);
		}
		if(!rarvm_prepare(&unpack_data->rarvm_data, &rarvm_input, &vm_code[0], vm_codesize, &filter->prg)) {
		    cli_dbgmsg("unrar: add_vm_code: rarvm_prepare failed\n");
		    free(vm_code);
		    return FALSE;
		}
		free(vm_code);
	}
	stack_filter->prg.alt_cmd = &filter->prg.cmd.array[0];
	stack_filter->prg.cmd_count = filter->prg.cmd_count;
	
	static_size = filter->prg.static_size;
	if (static_size > 0 && static_size < VM_GLOBALMEMSIZE) {
		stack_filter->prg.static_data = cli_malloc(static_size);
		if(!stack_filter->prg.static_data) {
		    cli_dbgmsg("unrar: add_vm_code: cli_malloc failed for stack_filter->prg.static_data\n");
		    return FALSE;
		}
		memcpy(stack_filter->prg.static_data, filter->prg.static_data, static_size);
	}
	
	if (stack_filter->prg.global_size < VM_FIXEDGLOBALSIZE) {
		free(stack_filter->prg.global_data);
		stack_filter->prg.global_data = cli_malloc(VM_FIXEDGLOBALSIZE);
		if(!stack_filter->prg.global_data) {
		    cli_dbgmsg("unrar: add_vm_code: cli_malloc failed for stack_filter->prg.global_data\n");
		    return FALSE;
		}
		memset(stack_filter->prg.global_data, 0, VM_FIXEDGLOBALSIZE);
		stack_filter->prg.global_size = VM_FIXEDGLOBALSIZE;
	}
	global_data = &stack_filter->prg.global_data[0];
	for (i=0 ; i<7 ; i++) {
		rar_dbgmsg("init_r[%d]=%u\n", i, stack_filter->prg.init_r[i]);
		rarvm_set_value(FALSE, (unsigned int *)&global_data[i*4],
				stack_filter->prg.init_r[i]);
	}
	rarvm_set_value(FALSE, (unsigned int *)&global_data[0x1c], stack_filter->block_length);
	rarvm_set_value(FALSE, (unsigned int *)&global_data[0x20], 0);
	rarvm_set_value(FALSE, (unsigned int *)&global_data[0x2c], stack_filter->exec_count);
	memset(&global_data[0x30], 0, 16);
	for (i=0 ; i< 30 ; i++) {
		rar_dbgmsg("global_data[%d] = %d\n", i, global_data[i]);
	}
	if (first_byte & 8) {
		data_size = rarvm_read_data(&rarvm_input);
		if (data_size >= 0x10000) {
			return FALSE;
		}
		cur_size = stack_filter->prg.global_size;
		if (cur_size < data_size+VM_FIXEDGLOBALSIZE) {
			stack_filter->prg.global_size += data_size+VM_FIXEDGLOBALSIZE-cur_size;
			stack_filter->prg.global_data = cli_realloc2(stack_filter->prg.global_data,
				stack_filter->prg.global_size);
			if(!stack_filter->prg.global_data) {
			    cli_dbgmsg("unrar: add_vm_code: cli_realloc2 failed for stack_filter->prg.global_data\n");
			    return FALSE;
			}
		}
		global_data = &stack_filter->prg.global_data[VM_FIXEDGLOBALSIZE];
		for (i=0 ; i< data_size ; i++) {
			if ((rarvm_input.in_addr+2) > rarvm_input.buf_size) {
				cli_dbgmsg("Buffer truncated\n");
				return FALSE;
			}
			global_data[i] = rarvm_getbits(&rarvm_input) >> 8;
			rar_dbgmsg("global_data[%d] = %d\n", i, global_data[i]);
			rarvm_addbits(&rarvm_input, 8);
		}
	}
	return TRUE;
}

static int read_vm_code(unpack_data_t *unpack_data, int fd)
{
	unsigned int first_byte;
	int length, i, retval;
	unsigned char *vmcode;
	
	first_byte = getbits(unpack_data)>>8;
	addbits(unpack_data, 8);
	length = (first_byte & 7) + 1;
	if (length == 7) {
		length = (getbits(unpack_data) >> 8) + 7;
		addbits(unpack_data, 8);
	} else if (length == 8) {
		length = getbits(unpack_data);
		addbits(unpack_data, 16);
	}
	vmcode = (unsigned char *) cli_malloc(length + 2);
	rar_dbgmsg("VM code length: %d\n", length);
	if (!vmcode) {
		return FALSE;
	}
	for (i=0 ; i < length ; i++) {
		if (unpack_data->in_addr >= unpack_data->read_top-1 &&
				!unp_read_buf(fd, unpack_data) && i<length-1) {
			return FALSE;
		}
		vmcode[i] = getbits(unpack_data) >> 8;
		addbits(unpack_data, 8);
	}
	retval = add_vm_code(unpack_data, first_byte, vmcode, length);
	free(vmcode);
	return retval;
}

static int read_vm_code_PPM(unpack_data_t *unpack_data, int fd)
{
	unsigned int first_byte;
	int length, i, ch, retval, b1, b2;
	unsigned char *vmcode;
	
	first_byte = ppm_decode_char(&unpack_data->ppm_data, fd, unpack_data);
	if ((int)first_byte == -1) {
		return FALSE;
	}
	length = (first_byte & 7) + 1;
	if (length == 7) {
		b1 = ppm_decode_char(&unpack_data->ppm_data, fd, unpack_data);
		if (b1 == -1) {
			return FALSE;
		}
		length = b1 + 7;
	} else if (length == 8) {
		b1 = ppm_decode_char(&unpack_data->ppm_data, fd, unpack_data);
		if (b1 == -1) {
			return FALSE;
		}
		b2 = ppm_decode_char(&unpack_data->ppm_data, fd, unpack_data);
		if (b2 == -1) {
			return FALSE;
		}
		length = b1*256 + b2;
	}
	vmcode = (unsigned char *) cli_malloc(length + 2);
	rar_dbgmsg("VM PPM code length: %d\n", length);
	if (!vmcode) {
		return FALSE;
	}
	for (i=0 ; i < length ; i++) {
		ch = ppm_decode_char(&unpack_data->ppm_data, fd, unpack_data);
		if (ch == -1) {
			free(vmcode);
			return FALSE;
		}
		vmcode[i] = ch;
	}
	retval = add_vm_code(unpack_data, first_byte, vmcode, length);
	free(vmcode);
	return retval;
}

void unpack_init_data(int solid, unpack_data_t *unpack_data)
{
	if (!solid) {
		unpack_data->tables_read = FALSE;
		memset(unpack_data->old_dist, 0, sizeof(unpack_data->old_dist));
		unpack_data->old_dist_ptr= 0;
		memset(unpack_data->unp_old_table, 0, sizeof(unpack_data->unp_old_table));
		unpack_data->last_dist= 0;
		unpack_data->last_length=0;
		unpack_data->ppm_esc_char = 2;
		unpack_data->unp_ptr = 0;
		unpack_data->wr_ptr = 0;
		init_filters(unpack_data);
	}
	unpack_data->in_bit = 0;
	unpack_data->in_addr = 0;
	unpack_data->read_top = 0;
	unpack_data->ppm_error = FALSE;
	
	unpack_data->written_size = 0;
	rarvm_init(&unpack_data->rarvm_data);
	unpack_data->unp_crc = 0xffffffff;
	
	unpack_init_data20(solid, unpack_data);

}

static void unpack_free_data(unpack_data_t *unpack_data)
{
	if (!unpack_data) {
		return;
	}
	/*init_filters(unpack_data);*/
	rarvm_free(&unpack_data->rarvm_data);
}

static int rar_unpack29(int fd, int solid, unpack_data_t *unpack_data)
{
	unsigned char ldecode[]={0,1,2,3,4,5,6,7,8,10,12,14,16,20,24,28,
			32,40,48,56,64,80,96,112,128,160,192,224};
	unsigned char lbits[]=  {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5};
	int ddecode[DC]={0,1,2,3,4,6,8,12,16,24,32,48,64,96,128,192,256,384,512,768,1024,
		1536,2048,3072,4096,6144,8192,12288,16384,24576,32768,49152,65536,
		98304,131072,196608,262144,327680,393216,458752,524288,589824,655360,
		720896,786432,851968,917504,983040,1048576,1310720,1572864,
		1835008,2097152,2359296,2621440,2883584,3145728,3407872,3670016,3932160};
	uint8_t dbits[DC]= {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,
		11,11,12,12,13,13,14,14,15,15,16,16,16,16,16,16,16,16,16,
		16,16,16,16,16,18,18,18,18,18,18,18,18,18,18,18,18};
	unsigned char sddecode[]={0,4,8,16,32,64,128,192};
	unsigned char sdbits[]=  {2,2,3, 4, 5, 6,  6,  6};
	unsigned int bits, distance;
	int retval=TRUE, i, number, length, dist_number, low_dist, ch, next_ch;
	int length_number, failed;

	cli_dbgmsg("Offset: %ld\n", lseek(fd, 0, SEEK_CUR));
	if (!solid) {
		cli_dbgmsg("Not solid\n");
	}
	unpack_init_data(solid, unpack_data);
	if (!unp_read_buf(fd, unpack_data)) {
		return FALSE;
	}
	if (!solid || !unpack_data->tables_read) {
		cli_dbgmsg("Read tables\n");
		if (!read_tables(fd, unpack_data)) {
			return FALSE;
		}
	}

	cli_dbgmsg("init done\n");
	while(1) {
		unpack_data->unp_ptr &= MAXWINMASK;
		rar_dbgmsg("UnpPtr = %d\n", unpack_data->unp_ptr);
		if (unpack_data->in_addr > unpack_data->read_border) {
			if (!unp_read_buf(fd, unpack_data)) {
				retval = FALSE;
				break;
			}
		}
		if (((unpack_data->wr_ptr - unpack_data->unp_ptr) & MAXWINMASK) < 260 &&
				unpack_data->wr_ptr != unpack_data->unp_ptr) {
			unp_write_buf(unpack_data);
		}
		if (unpack_data->unp_block_type == BLOCK_PPM) {
			ch = ppm_decode_char(&unpack_data->ppm_data, fd, unpack_data);
			rar_dbgmsg("PPM char: %d\n", ch);
			if (ch == -1) {
				retval = FALSE;
				unpack_data->ppm_error = TRUE;
				break;
			}
			if (ch == unpack_data->ppm_esc_char) {
				next_ch = ppm_decode_char(&unpack_data->ppm_data,
							fd, unpack_data);
				rar_dbgmsg("PPM next char: %d\n", next_ch);
				if (next_ch == -1) {
					retval = FALSE;
					unpack_data->ppm_error = TRUE;
					break;
				}
				if (next_ch == 0) {
					if (!read_tables(fd, unpack_data)) {
						retval = FALSE;
						break;
					}
					continue;
				}
				if (next_ch == 2 || next_ch == -1) {
					break;
				}
				if (next_ch == 3) {
					if (!read_vm_code_PPM(unpack_data, fd)) {
						retval = FALSE;
						break;
					}
					continue;
				}
				if (next_ch == 4) {
					unsigned int length;
					distance = 0;
					failed = FALSE;
					for (i=0 ; i < 4 && !failed; i++) {
						ch = ppm_decode_char(&unpack_data->ppm_data,
								fd, unpack_data);
						if (ch == -1) {
							failed = TRUE;
						} else {
							if (i==3) {
								length = (uint8_t)ch;
							} else {
								distance = (distance << 8) +
										(uint8_t)ch;
							}
						}
					}
					if (failed) {
						retval = FALSE;
						break;
					}
					copy_string(unpack_data, length+32, distance+2);
					continue;
				}
				if (next_ch == 5) {
					int length = ppm_decode_char(&unpack_data->ppm_data,
								fd, unpack_data);
					rar_dbgmsg("PPM length: %d\n", length);
					if (length == -1) {
						retval = FALSE;
						break;
					}
					copy_string(unpack_data, length+4, 1);
					continue;
				}
			}
			unpack_data->window[unpack_data->unp_ptr++] = ch;
			continue;
		} else {
			number = decode_number(unpack_data, (struct Decode *)&unpack_data->LD);
			rar_dbgmsg("number = %d\n", number);
			if (number < 256) {
				unpack_data->window[unpack_data->unp_ptr++] = (uint8_t) number;
				continue;
			}
			if (number >= 271) {
				length = ldecode[number-=271]+3;
				if ((bits=lbits[number]) > 0) {
					length += getbits(unpack_data) >> (16-bits);
					addbits(unpack_data, bits);
				}
				dist_number = decode_number(unpack_data,
							(struct Decode *)&unpack_data->DD);
				distance = ddecode[dist_number] + 1;
				if ((bits = dbits[dist_number]) > 0) {
					if (dist_number > 9) {
						if (bits > 4) {
							distance += ((getbits(unpack_data) >>
									(20-bits)) << 4);
							addbits(unpack_data, bits-4);
						}
						if (unpack_data->low_dist_rep_count > 0) {
							unpack_data->low_dist_rep_count--;
							distance += unpack_data->prev_low_dist;
						} else {
							low_dist = decode_number(unpack_data,
								(struct Decode *) &unpack_data->LDD);
							if (low_dist == 16) {
								unpack_data->low_dist_rep_count =
									LOW_DIST_REP_COUNT-1;
								distance += unpack_data->prev_low_dist;
							} else {
								distance += low_dist;
								unpack_data->prev_low_dist = low_dist;
							}
						}
					} else {
						distance += getbits(unpack_data) >> (16-bits);
						addbits(unpack_data, bits);
					}
				}
				
				if (distance >= 0x2000) {
					length++;
					if (distance >= 0x40000L) {
						length++;
					}
				}
				
				insert_old_dist(unpack_data, distance);
				insert_last_match(unpack_data, length, distance);
				copy_string(unpack_data, length, distance);
				continue;
			}
			if (number == 256) {
				if (!read_end_of_block(fd, unpack_data)) {
					break;
				}
				continue;
			}
			if (number == 257) {
				if (!read_vm_code(unpack_data, fd)) {
					retval = FALSE;
					break;
				}
				continue;
			}
			if (number == 258) {
				if (unpack_data->last_length != 0) {
					copy_string(unpack_data, unpack_data->last_length,
							unpack_data->last_dist);
				}
				continue;
			}
			if (number < 263) {
				dist_number = number-259;
				distance = unpack_data->old_dist[dist_number];
				for (i=dist_number ; i > 0 ; i--) {
					unpack_data->old_dist[i] = unpack_data->old_dist[i-1];
				}
				unpack_data->old_dist[0] = distance;
				
				length_number = decode_number(unpack_data,
							(struct Decode *)&unpack_data->RD);
				length = ldecode[length_number]+2;
				if ((bits = lbits[length_number]) > 0) {
					length += getbits(unpack_data) >> (16-bits);
					addbits(unpack_data, bits);
				}
				insert_last_match(unpack_data, length, distance);
				copy_string(unpack_data, length, distance);
				continue;
			}
			if (number < 272) {
				distance = sddecode[number-=263]+1;
				if ((bits = sdbits[number]) > 0) {
					distance += getbits(unpack_data) >> (16-bits);
					addbits(unpack_data, bits);
				}
				insert_old_dist(unpack_data, distance);
				insert_last_match(unpack_data, 2, distance);
				copy_string(unpack_data, 2, distance);
				continue;
			}
	
		}
	}
	if (retval) {
		unp_write_buf(unpack_data);
	}
	cli_dbgmsg("Finished length: %ld\n", unpack_data->written_size);
	return retval;
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
		retval = rar_unpack29(fd, solid, unpack_data);
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
	unpack_data->rarvm_data.mem = NULL;
	unpack_data->old_filter_lengths = NULL;
	unpack_data->PrgStack.array = unpack_data->Filters.array = NULL;
	unpack_data->PrgStack.num_items = unpack_data->Filters.num_items = 0;
	unpack_data->unp_crc = 0xffffffff;

	/* unpack_init_data(FALSE, unpack_data); */
	ppm_constructor(&unpack_data->ppm_data);
	
	main_hdr = read_header(fd, MAIN_HEAD);
	if (!main_hdr) {
		ppm_destructor(&unpack_data->ppm_data);
		init_filters(unpack_data);
		unpack_free_data(unpack_data);
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
		ppm_destructor(&unpack_data->ppm_data);
		init_filters(unpack_data);
		unpack_free_data(unpack_data);
		free(unpack_data);
		return CL_ETMPDIR;
	}
	state->comment_dir = cli_strdup(filename);
	if(!state->comment_dir) {
		free(main_hdr);
		ppm_destructor(&unpack_data->ppm_data);
		init_filters(unpack_data);
		unpack_free_data(unpack_data);
		free(unpack_data);
		return CL_EMEM;
	}

	if (main_hdr->head_size < SIZEOF_NEWMHD) {
		free(main_hdr);
		ppm_destructor(&unpack_data->ppm_data);
		init_filters(unpack_data);
		unpack_free_data(unpack_data);
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
				ppm_destructor(&unpack_data->ppm_data);
				init_filters(unpack_data);
				unpack_free_data(unpack_data);
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
					unpack_free_data(unpack_data);
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
			ppm_destructor(&unpack_data->ppm_data);
			init_filters(unpack_data);
			unpack_free_data(unpack_data);
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
			cli_dbgmsg("Expected File CRC: 0x%x\n", state->file_header->file_crc);
			cli_dbgmsg("Computed File CRC: 0x%x\n", state->unpack_data->unp_crc^0xffffffff);
			if (state->unpack_data->unp_crc != 0xffffffff) {
				if (state->file_header->file_crc != (state->unpack_data->unp_crc^0xffffffff)) {
					cli_warnmsg("RAR CRC error. If the file is not corrupted, please report at http://bugs.clamav.net/\n");
				}
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
	unpack_free_data(state->unpack_data);
	state->file_count++;
	return CL_SUCCESS;
}

void cli_unrar_close(rar_state_t* state)
{
	ppm_destructor(&state->unpack_data->ppm_data);
	free(state->main_hdr);
	init_filters(state->unpack_data);
	unpack_free_data(state->unpack_data);
	free(state->unpack_data);
	free(state->comment_dir);
}
