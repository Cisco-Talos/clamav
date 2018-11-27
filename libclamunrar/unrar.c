/*
 *  Extract RAR archives
 *
 *  Copyright (C) 2005-2006 trog@uncon.org
 *  Patches added by Sourcefire, Inc. Copyright (C) 2007-2013
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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "libclamunrar/unrar.h"
#include "libclamunrar/unrarppm.h"
#include "libclamunrar/unrarvm.h"
#include "libclamunrar/unrarfilter.h"
#include "libclamunrar/unrar20.h"
#include "libclamunrar/unrar15.h"

#define int64to32(x) ((unsigned int)(x))

#ifdef RAR_HIGH_DEBUG
#define rar_dbgmsg printf
#else
static void rar_dbgmsg(const char* fmt,...){(void)fmt;}
#endif

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

void rar_addbits(unpack_data_t *unpack_data, int bits)
{

	/*rar_dbgmsg("rar_addbits: in_addr=%d in_bit=%d\n", unpack_data->in_addr, unpack_data->in_bit);*/
	bits += unpack_data->in_bit;
	unpack_data->in_addr += bits >> 3;
	unpack_data->in_bit = bits & 7;
}

unsigned int rar_getbits(unpack_data_t *unpack_data)
{
	unsigned int bit_field;

	/*rar_dbgmsg("rar_getbits: in_addr=%d in_bit=%d\n", unpack_data->in_addr, unpack_data->in_bit);*/
	bit_field = (unsigned int) unpack_data->in_buf[unpack_data->in_addr] << 16;
	bit_field |= (unsigned int) unpack_data->in_buf[unpack_data->in_addr+1] << 8;
	bit_field |= (unsigned int) unpack_data->in_buf[unpack_data->in_addr+2];
	bit_field >>= (8-unpack_data->in_bit);
	/*rar_dbgmsg("rar_getbits return(%d)\n", BitField & 0xffff);*/
	return(bit_field & 0xffff);
}

int rar_unp_read_buf(int fd, unpack_data_t *unpack_data)
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
	if (unpack_data->pack_size < (uint32_t)((MAX_BUF_SIZE-data_size)&~0xf)) {
		read_size = unpack_data->pack_size;
	} else {
		read_size = (MAX_BUF_SIZE-data_size)&~0xf;
	}
	retval = read(fd, unpack_data->in_buf+data_size, read_size);	
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
		if (!rar_unp_read_buf(fd, unpack_data)) {
			rar_dbgmsg("rar_get_char: rar_unp_read_buf FAILED\n"); /* FIXME: cli_errmsg */
			return -1;
		}
	}
	rar_dbgmsg("rar_get_char = %u\n", unpack_data->in_buf[unpack_data->in_addr]);
	return(unpack_data->in_buf[unpack_data->in_addr++]);
}

static void unp_write_data(unpack_data_t *unpack_data, uint8_t *data, int size)
{
	int ret;
	rar_dbgmsg("in unp_write_data length=%d\n", size);

	unpack_data->true_size += size;
	unpack_data->unp_crc = rar_crc(unpack_data->unp_crc, data, size);
	if(unpack_data->max_size) {
	    if(unpack_data->written_size >= unpack_data->max_size)
		return;

	    if(unpack_data->written_size + size > unpack_data->max_size)
		size = unpack_data->max_size - unpack_data->written_size;
	}
	if((ret = write(unpack_data->ofd, data, size)) > 0)
	    unpack_data->written_size += ret;
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

void rar_unp_write_buf_old(unpack_data_t *unpack_data)
{
	rar_dbgmsg("in rar_unp_write_buf_old\n");
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
	size_t i, j;
	
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

void rar_make_decode_tables(unsigned char *len_tab, struct Decode *decode, int size)
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

int rar_decode_number(unpack_data_t *unpack_data, struct Decode *decode)
{
	unsigned int bits, bit_field, n;
	
	bit_field = rar_getbits(unpack_data) & 0xfffe;
	rar_dbgmsg("rar_decode_number BitField=%u\n", bit_field);
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

	rar_dbgmsg("rar_decode_number: bits=%d\n", bits);

	rar_addbits(unpack_data, bits);
	n=decode->DecodePos[bits]+((bit_field-decode->DecodeLen[bits-1])>>(16-bits));
	if (n >= decode->MaxNum) {
		n=0;
	}
	/*rar_dbgmsg("rar_decode_number return(%d)\n", decode->DecodeNum[n]);*/

	return(decode->DecodeNum[n]);
}

static int read_tables(int fd, unpack_data_t *unpack_data)
{
	uint8_t bit_length[BC];
	unsigned char table[HUFF_TABLE_SIZE];
	unsigned int bit_field;
	int length, zero_count, number, n;
	size_t i;
	const size_t table_size=HUFF_TABLE_SIZE;
	
	rar_dbgmsg("in read_tables Offset=%ld in_addr=%d read_top=%d\n", lseek(fd, 0, SEEK_CUR),
				unpack_data->in_addr, unpack_data->read_top);
	if (unpack_data->in_addr > unpack_data->read_top-25) {
		if (!rar_unp_read_buf(fd, unpack_data)) {
			rar_dbgmsg("ERROR: read_tables rar_unp_read_buf failed\n");
			return FALSE;
		}
	}
	rar_addbits(unpack_data, (8-unpack_data->in_bit) & 7);
	bit_field = rar_getbits(unpack_data);
	rar_dbgmsg("BitField = 0x%x\n", bit_field);
	if (bit_field & 0x8000) {
		unpack_data->unp_block_type = BLOCK_PPM;
		rar_dbgmsg("Calling ppm_decode_init\n");
		if(!ppm_decode_init(&unpack_data->ppm_data, fd, unpack_data, &unpack_data->ppm_esc_char)) {
		    rar_dbgmsg("unrar: read_tables: ppm_decode_init failed\n");
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
	rar_addbits(unpack_data, 2);
	
	for (i=0 ; i < BC ; i++) {
		length = (uint8_t)(rar_getbits(unpack_data) >> 12);
		rar_addbits(unpack_data, 4);
		if (length == 15) {
			zero_count = (uint8_t)(rar_getbits(unpack_data) >> 12);
			rar_addbits(unpack_data, 4);
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
	rar_make_decode_tables(bit_length,(struct Decode *)&unpack_data->BD,BC);
	memset(table, 0, sizeof(table));
	for (i=0;i<table_size;) {
		if (unpack_data->in_addr > unpack_data->read_top-5) {
			if (!rar_unp_read_buf(fd, unpack_data)) {
				rar_dbgmsg("ERROR: read_tables rar_unp_read_buf failed 2\n");
				return FALSE;
			}
		}
		number = rar_decode_number(unpack_data, (struct Decode *)&unpack_data->BD);
		if (number < 16) {
			table[i] = (number+unpack_data->unp_old_table[i]) & 0xf;
			i++;
		} else if (number < 18) {
			if (number == 16) {
				n = (rar_getbits(unpack_data) >> 13) + 3;
				rar_addbits(unpack_data, 3);
			} else {
				n = (rar_getbits(unpack_data) >> 9) + 11;
				rar_addbits(unpack_data, 7);
			}
			if (i == 0) {
				rar_dbgmsg("We cannot have \"repeat previous\" code at the first position\n");
				return FALSE;
			}
			while (n-- > 0 && i < table_size) {
				table[i] = table[i-1];
				i++;
			}
		} else {
			if (number == 18) {
				n = (rar_getbits(unpack_data) >> 13) + 3;
				rar_addbits(unpack_data, 3);
			} else {
				n = (rar_getbits(unpack_data) >> 9) + 11;
				rar_addbits(unpack_data, 7);
			}
			while (n-- > 0 && i < table_size) {
				table[i++] = 0;
			}
		}
	}
	unpack_data->tables_read = TRUE;
	if (unpack_data->in_addr > unpack_data->read_top) {
		rar_dbgmsg("ERROR: read_tables check failed\n");
		return FALSE;
	}
	rar_make_decode_tables(&table[0], (struct Decode *)&unpack_data->LD,NC);
	rar_make_decode_tables(&table[NC], (struct Decode *)&unpack_data->DD,DC);
	rar_make_decode_tables(&table[NC+DC], (struct Decode *)&unpack_data->LDD,LDC);
	rar_make_decode_tables(&table[NC+DC+LDC], (struct Decode *)&unpack_data->RD,RC);
	memcpy(unpack_data->unp_old_table,table,sizeof(unpack_data->unp_old_table));
	

	/*dump_tables(unpack_data);*/
	rar_dbgmsg("ReadTables finished\n");
  	return TRUE;
}

static int read_end_of_block(int fd, unpack_data_t *unpack_data)
{
	unsigned int bit_field;
	int new_table, new_file=FALSE;
	
	bit_field = rar_getbits(unpack_data);
	if (bit_field & 0x8000) {
		new_table = TRUE;
		rar_addbits(unpack_data, 1);
	} else {
		new_file = TRUE;
		new_table = (bit_field & 0x4000);
		rar_addbits(unpack_data, 2);
	}
	unpack_data->tables_read = !new_table;
	rar_dbgmsg("NewFile=%d NewTable=%d TablesRead=%d\n", new_file,
			new_table, unpack_data->tables_read);
	return !(new_file || (new_table && !read_tables(fd, unpack_data)));
}

void rar_init_filters(unpack_data_t *unpack_data)
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
	unsigned int filter_pos, new_filter, block_start, init_mask, cur_size, data_size;
	struct UnpackFilter *filter, *stack_filter;
	size_t i, empty_count, stack_pos;
	unsigned int vm_codesize;
	long static_size;
	unsigned char *vm_code, *global_data;
	
	rar_dbgmsg("in add_vm_code first_byte=0x%x code_size=%d\n", first_byte, code_size);
	rarvm_input.in_buf = vmcode;
	rarvm_input.buf_size = code_size;
	rarvm_input.in_addr = 0;
	rarvm_input.in_bit = 0;

	if (first_byte & 0x80) {
		filter_pos = rarvm_read_data(&rarvm_input);
		if (filter_pos == 0) {
			rar_init_filters(unpack_data);
		} else {
			filter_pos--;
		}
	} else {
		filter_pos = unpack_data->last_filter;
	}
	rar_dbgmsg("filter_pos = %u\n", filter_pos);
	if ((size_t) filter_pos > unpack_data->Filters.num_items ||
			filter_pos > unpack_data->old_filter_lengths_size) {
		rar_dbgmsg("filter_pos check failed\n");
		return FALSE;
	}
	unpack_data->last_filter = filter_pos;
	new_filter = (filter_pos == unpack_data->Filters.num_items);
	rar_dbgmsg("Filters.num_items=%d\n", unpack_data->Filters.num_items);
	rar_dbgmsg("new_filter=%d\n", new_filter);
	if (new_filter) {
		if (!rar_filter_array_add(&unpack_data->Filters, 1)) {
			rar_dbgmsg("rar_filter_array_add failed\n");
			return FALSE;
		}
		unpack_data->Filters.array[unpack_data->Filters.num_items-1] =
					filter = rar_filter_new();
		if (!unpack_data->Filters.array[unpack_data->Filters.num_items-1]) {
			rar_dbgmsg("rar_filter_new failed\n");
			return FALSE;
		}	
		unpack_data->old_filter_lengths_size++;
		unpack_data->old_filter_lengths = (int *) rar_realloc2(unpack_data->old_filter_lengths,
				sizeof(int) * unpack_data->old_filter_lengths_size);
		if(!unpack_data->old_filter_lengths) {
		    rar_dbgmsg("unrar: add_vm_code: rar_realloc2 failed for unpack_data->old_filter_lengths\n");
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
		if (vm_codesize >= 0x1000 || vm_codesize == 0 || vm_codesize > (unsigned int)rarvm_input.buf_size) {
			rar_dbgmsg("ERROR: vm_codesize=0x%x buf_size=0x%x\n", vm_codesize, rarvm_input.buf_size);
			return FALSE;
		}
		vm_code = (unsigned char *) rar_malloc(vm_codesize);
		if(!vm_code) {
		    rar_dbgmsg("unrar: add_vm_code: rar_malloc failed for vm_code\n");
		    return FALSE;
		}
		for (i=0 ; i < (size_t) vm_codesize ; i++) {
			vm_code[i] = rarvm_getbits(&rarvm_input) >> 8;
			rarvm_addbits(&rarvm_input, 8);
		}
		if(!rarvm_prepare(&unpack_data->rarvm_data, &rarvm_input, &vm_code[0], (int) vm_codesize, &filter->prg)) {
		    rar_dbgmsg("unrar: add_vm_code: rarvm_prepare failed\n");
		    free(vm_code);
		    return FALSE;
		}
		free(vm_code);
	}
	stack_filter->prg.alt_cmd = &filter->prg.cmd.array[0];
	stack_filter->prg.cmd_count = filter->prg.cmd_count;
	
	static_size = filter->prg.static_size;
	if (static_size > 0 && static_size < VM_GLOBALMEMSIZE) {
		stack_filter->prg.static_data = rar_malloc(static_size);
		if(!stack_filter->prg.static_data) {
		    rar_dbgmsg("unrar: add_vm_code: rar_malloc failed for stack_filter->prg.static_data\n");
		    return FALSE;
		}
		memcpy(stack_filter->prg.static_data, filter->prg.static_data, static_size);
	}
	
	if (stack_filter->prg.global_size < VM_FIXEDGLOBALSIZE) {
		free(stack_filter->prg.global_data);
		stack_filter->prg.global_data = rar_malloc(VM_FIXEDGLOBALSIZE);
		if(!stack_filter->prg.global_data) {
		    rar_dbgmsg("unrar: add_vm_code: rar_malloc failed for stack_filter->prg.global_data\n");
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
		cur_size = (unsigned int)stack_filter->prg.global_size;
		if (cur_size < data_size + VM_FIXEDGLOBALSIZE) {
			stack_filter->prg.global_size += (long)data_size + VM_FIXEDGLOBALSIZE - cur_size;
			stack_filter->prg.global_data = (unsigned char*)rar_realloc2(stack_filter->prg.global_data,
				stack_filter->prg.global_size);
			if(!stack_filter->prg.global_data) {
			    rar_dbgmsg("unrar: add_vm_code: rar_realloc2 failed for stack_filter->prg.global_data\n");
			    return FALSE;
			}
		}
		global_data = &stack_filter->prg.global_data[VM_FIXEDGLOBALSIZE];
		for (i=0 ; i < (size_t)data_size ; i++) {
			if (rarvm_input.in_addr + 2 > rarvm_input.buf_size) {
				rar_dbgmsg("Buffer truncated\n");
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
	
	first_byte = rar_getbits(unpack_data)>>8;
	rar_addbits(unpack_data, 8);
	length = (first_byte & 7) + 1;
	if (length == 7) {
		length = (rar_getbits(unpack_data) >> 8) + 7;
		rar_addbits(unpack_data, 8);
	} else if (length == 8) {
		length = rar_getbits(unpack_data);
		rar_addbits(unpack_data, 16);
	}
	vmcode = (unsigned char *) rar_malloc(length + 2);
	rar_dbgmsg("VM code length: %d\n", length);
	if (!vmcode) {
		return FALSE;
	}
	for (i=0 ; i < length ; i++) {
		if (unpack_data->in_addr >= unpack_data->read_top-1 &&
				!rar_unp_read_buf(fd, unpack_data) && i<length-1) {
			free(vmcode);
			return FALSE;
		}
		vmcode[i] = rar_getbits(unpack_data) >> 8;
		rar_addbits(unpack_data, 8);
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
	vmcode = (unsigned char *) rar_malloc(length + 2);
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

void rar_unpack_init_data(int solid, unpack_data_t *unpack_data)
{
	if (!solid) {
		unpack_data->tables_read = FALSE;
		memset(unpack_data->old_dist, 0, sizeof(unpack_data->old_dist));
		unpack_data->old_dist_ptr= 0;
		memset(unpack_data->unp_old_table, 0, sizeof(unpack_data->unp_old_table));
		memset(&unpack_data->LDD, 0, sizeof(unpack_data->LDD));
		memset(&unpack_data->LD, 0, sizeof(unpack_data->LD));
		memset(&unpack_data->DD, 0, sizeof(unpack_data->DD));
		memset(&unpack_data->RD, 0, sizeof(unpack_data->RD));
		memset(&unpack_data->BD, 0, sizeof(unpack_data->BD));
		unpack_data->last_dist= 0;
		unpack_data->last_length=0;
		unpack_data->ppm_esc_char = 2;
		unpack_data->unp_ptr = 0;
		unpack_data->wr_ptr = 0;
		unpack_data->unp_block_type = BLOCK_LZ;
		rar_init_filters(unpack_data);
	}
	unpack_data->in_bit = 0;
	unpack_data->in_addr = 0;
	unpack_data->read_top = 0;
	unpack_data->read_border = 0;
	unpack_data->written_size = 0;
	unpack_data->true_size = 0;
	rarvm_init(&unpack_data->rarvm_data);
	unpack_data->unp_crc = 0xffffffff;
	
	unpack_init_data20(solid, unpack_data);

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

	rar_dbgmsg("Offset: %ld\n", lseek(fd, 0, SEEK_CUR));
	if (!solid) {
		rar_dbgmsg("Not solid\n");
	}
	rar_unpack_init_data(solid, unpack_data);
	if (!rar_unp_read_buf(fd, unpack_data)) {
		return FALSE;
	}
	if (!solid || !unpack_data->tables_read) {
		rar_dbgmsg("Read tables\n");
		if (!read_tables(fd, unpack_data)) {
			return FALSE;
		}
	}

	rar_dbgmsg("init done\n");
	while(1) {
		unpack_data->unp_ptr &= MAXWINMASK;
		rar_dbgmsg("UnpPtr = %d\n", unpack_data->unp_ptr);
		if (unpack_data->in_addr > unpack_data->read_border) {
			if (!rar_unp_read_buf(fd, unpack_data)) {
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
				ppm_cleanup(&unpack_data->ppm_data);
				unpack_data->unp_block_type = BLOCK_LZ;
				retval = FALSE;
				break;
			}
			if (ch == unpack_data->ppm_esc_char) {
				next_ch = ppm_decode_char(&unpack_data->ppm_data,
							fd, unpack_data);
				rar_dbgmsg("PPM next char: %d\n", next_ch);
				if (next_ch == -1) {
					retval = FALSE;
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
					unsigned int length = 0;
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
			number = rar_decode_number(unpack_data, (struct Decode *)&unpack_data->LD);
			rar_dbgmsg("number = %d\n", number);
			if (number < 256) {
				unpack_data->window[unpack_data->unp_ptr++] = (uint8_t) number;
				continue;
			}
			if (number >= 271) {
				length = ldecode[number-=271]+3;
				if ((bits=lbits[number]) > 0) {
					length += rar_getbits(unpack_data) >> (16-bits);
					rar_addbits(unpack_data, bits);
				}
				dist_number = rar_decode_number(unpack_data,
							(struct Decode *)&unpack_data->DD);
				distance = ddecode[dist_number] + 1;
				if ((bits = dbits[dist_number]) > 0) {
					if (dist_number > 9) {
						if (bits > 4) {
							distance += ((rar_getbits(unpack_data) >>
									(20-bits)) << 4);
							rar_addbits(unpack_data, bits-4);
						}
						if (unpack_data->low_dist_rep_count > 0) {
							unpack_data->low_dist_rep_count--;
							distance += unpack_data->prev_low_dist;
						} else {
							low_dist = rar_decode_number(unpack_data,
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
						distance += rar_getbits(unpack_data) >> (16-bits);
						rar_addbits(unpack_data, bits);
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
				
				length_number = rar_decode_number(unpack_data,
							(struct Decode *)&unpack_data->RD);
				length = ldecode[length_number]+2;
				if ((bits = lbits[length_number]) > 0) {
					length += rar_getbits(unpack_data) >> (16-bits);
					rar_addbits(unpack_data, bits);
				}
				insert_last_match(unpack_data, length, distance);
				copy_string(unpack_data, length, distance);
				continue;
			}
			if (number < 272) {
				distance = sddecode[number-=263]+1;
				if ((bits = sdbits[number]) > 0) {
					distance += rar_getbits(unpack_data) >> (16-bits);
					rar_addbits(unpack_data, bits);
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
	return retval;
}

int rar_unpack(int fd, int method, int solid, unpack_data_t *unpack_data)
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
		retval = rar_unpack29(fd, solid, unpack_data);
		if(retval == FALSE) {
		    rarvm_free(&unpack_data->rarvm_data);
		    retval = rar_unpack20(fd, solid, unpack_data);
		    if(retval == FALSE) {
			rarvm_free(&unpack_data->rarvm_data);
			retval = rar_unpack15(fd, solid, unpack_data);
		    }
		}
		break;
	}
	rar_dbgmsg("Written size: %ld\n", unpack_data->written_size);
	rar_dbgmsg("True size: %ld\n", unpack_data->true_size);

	return retval;
}
