/*
 *  Extract RAR archives
 *
 *  Copyright (C) 2005 trog@uncon.org
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

#include "libclamunrar/unrar.h"
#include "libclamunrar/unrar15.h"
#include <string.h>

#define STARTL1  2
static unsigned int dec_l1[]={0x8000,0xa000,0xc000,0xd000,0xe000,0xea00,
			0xee00,0xf000,0xf200,0xf200,0xffff};
static unsigned int pos_l1[]={0,0,0,2,3,5,7,11,16,20,24,32,32};

#define STARTL2  3
static unsigned int dec_l2[]={0xa000,0xc000,0xd000,0xe000,0xea00,0xee00,
			0xf000,0xf200,0xf240,0xffff};
static unsigned int pos_l2[]={0,0,0,0,5,7,9,13,18,22,26,34,36};

#define STARTHF0  4
static unsigned int dec_hf0[]={0x8000,0xc000,0xe000,0xf200,0xf200,0xf200,
			0xf200,0xf200,0xffff};
static unsigned int pos_hf0[]={0,0,0,0,0,8,16,24,33,33,33,33,33};


#define STARTHF1  5
static unsigned int dec_hf1[]={0x2000,0xc000,0xe000,0xf000,0xf200,0xf200,
			0xf7e0,0xffff};
static unsigned int pos_hf1[]={0,0,0,0,0,0,4,44,60,76,80,80,127};


#define STARTHF2  5
static unsigned int dec_hf2[]={0x1000,0x2400,0x8000,0xc000,0xfa00,0xffff,
			0xffff,0xffff};
static unsigned int pos_hf2[]={0,0,0,0,0,0,2,7,53,117,233,0,0};


#define STARTHF3  6
static unsigned int dec_hf3[]={0x800,0x2400,0xee00,0xfe80,0xffff,0xffff,
			0xffff};
static unsigned int pos_hf3[]={0,0,0,0,0,0,0,2,16,218,251,0,0};


#define STARTHF4  8
static unsigned int dec_hf4[]={0xff00,0xffff,0xffff,0xffff,0xffff,0xffff};
static unsigned int pos_hf4[]={0,0,0,0,0,0,0,0,0,255,0,0,0};

static void unpack_init_data15(int solid, unpack_data_t *unpack_data)
{
	if (!solid) {
		unpack_data->avr_plcb = unpack_data->avr_ln1 = unpack_data->avr_ln2 =
			unpack_data->avr_ln3 = unpack_data->num_huf =
			unpack_data->buf60 = 0;
		unpack_data->avr_plc = 0x3500;
		unpack_data->max_dist3 = 0x2001;
		unpack_data->nhfb = unpack_data->nlzb = 0x80;
	}
	
	unpack_data->flags_cnt = 0;
	unpack_data->flag_buf = 0;
	unpack_data->st_mode = 0;
	unpack_data->lcount = 0;
	unpack_data->read_top = 0;
}

static void corr_huff(unpack_data_t *unpack_data, unsigned int *char_set,
			unsigned int *num_to_place)
{
	int i, j;
	
	for (i=7 ; i >= 0 ; i--) {
		for (j=0 ; j < 32 ; j++, char_set++) {
			*char_set = (*char_set & ~0xff) | i;
		}
	}
	memset(num_to_place, 0, sizeof(unpack_data->ntopl));
	for (i=6 ; i >= 0 ; i--) {
		num_to_place[i] = (7-i) * 32;
	}
}

static void init_huff(unpack_data_t *unpack_data)
{
	unsigned int i;
	
	for (i=0 ; i<256 ; i++) {
		unpack_data->place[i] = unpack_data->placea[i] = unpack_data->placeb[i] = i;
		unpack_data->placec[i] = (~i+1) & 0xff;
		unpack_data->chset[i] = unpack_data->chsetb[i] = i << 8;
		unpack_data->chseta[i] = i;
		unpack_data->chsetc[i] = ((~i+1) & 0xff) << 8;
	}
	memset(unpack_data->ntopl, 0, sizeof(unpack_data->ntopl));
	memset(unpack_data->ntoplb, 0, sizeof(unpack_data->ntoplb));
	memset(unpack_data->ntoplc, 0, sizeof(unpack_data->ntoplc));
	corr_huff(unpack_data, unpack_data->chsetb, unpack_data->ntoplb);
}

static void copy_string15(unpack_data_t *unpack_data, unsigned int distance,
				unsigned int length)
{
	unpack_data->dest_unp_size -= length;
	while (length--) {
		unpack_data->window[unpack_data->unp_ptr] =
			unpack_data->window[(unpack_data->unp_ptr - distance) & MAXWINMASK];
		unpack_data->unp_ptr = (unpack_data->unp_ptr + 1) & MAXWINMASK;
	}
}

static unsigned int decode_num(unpack_data_t *unpack_data, int num, unsigned int start_pos,
			unsigned int *dec_tab, unsigned int *pos_tab)
{
	int i;
	
	for (num&=0xfff0, i=0 ; dec_tab[i] <= num ; i++) {
		start_pos++;
	}
	rar_addbits(unpack_data, start_pos);
	return (((num-(i ? dec_tab[i-1]:0)) >> (16-start_pos)) + pos_tab[start_pos]);
}

static void huff_decode(unpack_data_t *unpack_data)
{
	unsigned int cur_byte, new_byte_place, length, distance, bit_field;
	int byte_place;
	
	bit_field = rar_getbits(unpack_data);
	
	if (unpack_data->avr_plc > 0x75ff) {
		byte_place = decode_num(unpack_data, bit_field,
					STARTHF4, dec_hf4, pos_hf4);
	} else if (unpack_data->avr_plc > 0x5dff) {
		byte_place = decode_num(unpack_data, bit_field,
					STARTHF3, dec_hf3, pos_hf3);
	} else if (unpack_data->avr_plc > 0x35ff) {
		byte_place = decode_num(unpack_data, bit_field,
					STARTHF2, dec_hf2, pos_hf2);
	} else if (unpack_data->avr_plc > 0x0dff) {
		byte_place = decode_num(unpack_data, bit_field,
					STARTHF1, dec_hf1, pos_hf1);
	} else {
		byte_place = decode_num(unpack_data, bit_field,
					STARTHF0, dec_hf0, pos_hf0);
	}
	
	byte_place &= 0xff;
	if (unpack_data->st_mode) {
		if (byte_place == 0 && bit_field > 0xfff) {
			byte_place = 0x100;
		}
		if (--byte_place == -1) {
			bit_field = rar_getbits(unpack_data);
			rar_addbits(unpack_data, 1);
			if (bit_field & 0x8000) {
				unpack_data->num_huf = unpack_data->st_mode = 0;
				return;
			} else {
				length = (bit_field & 0x4000) ? 4 : 3;
				rar_addbits(unpack_data, 1);
				distance = decode_num(unpack_data, rar_getbits(unpack_data),
					STARTHF2, dec_hf2, pos_hf2);
				distance = (distance << 5) | (rar_getbits(unpack_data) >> 11);
				rar_addbits(unpack_data, 5);
				copy_string15(unpack_data, distance, length);
				return;
			}
		}
	} else if (unpack_data->num_huf++ >= 16 && unpack_data->flags_cnt == 0) {
		unpack_data->st_mode = 1;
	}
	unpack_data->avr_plc += byte_place;
	unpack_data->avr_plc -= unpack_data->avr_plc >> 8;
	unpack_data->nhfb += 16;
	if (unpack_data->nhfb > 0xff) {
		unpack_data->nhfb = 0x90;
		unpack_data->nlzb >>= 1;
	}
	
	unpack_data->window[unpack_data->unp_ptr++] = 
			(unsigned char) (unpack_data->chset[byte_place & 0xff] >>8);
	--unpack_data->dest_unp_size;
	
	while (1) {
		cur_byte = unpack_data->chset[byte_place & 0xff];
		new_byte_place = unpack_data->ntopl[cur_byte++ & 0xff]++;
		if ((cur_byte & 0xff) > 0xa1) {
			corr_huff(unpack_data, unpack_data->chset, unpack_data->ntopl);
		} else {
			break;
		}
	}
	
	unpack_data->chset[byte_place & 0xff] = unpack_data->chset[new_byte_place & 0xff];
	unpack_data->chset[new_byte_place & 0xff] = cur_byte;
}

	
	
static void get_flag_buf(unpack_data_t *unpack_data)
{
	unsigned int flags, new_flags_place, flags_place;
	
	flags_place = decode_num(unpack_data, rar_getbits(unpack_data), STARTHF2,
				dec_hf2, pos_hf2);
	for (;;) {
		flags = unpack_data->chsetc[flags_place & 0xff];
		unpack_data->flag_buf = flags >> 8;
		new_flags_place = unpack_data->ntoplc[flags++ & 0xff]++;
		if ((flags & 0xff) != 0) {
			break;
		}
		corr_huff(unpack_data, unpack_data->chsetc, unpack_data->ntoplc);
	}
	unpack_data->chsetc[flags_place & 0xff] = unpack_data->chsetc[new_flags_place & 0xff];
	unpack_data->chsetc[new_flags_place & 0xff] = flags;
}

static void short_lz(unpack_data_t *unpack_data)
{
	static unsigned int short_len1[]={1,3,4,4,5,6,7,8,8,4,4,5,6,6,4,0};
	static unsigned int short_xor1[]={0,0xa0,0xd0,0xe0,0xf0,0xf8,0xfc,0xfe,
			0xff,0xc0,0x80,0x90,0x98,0x9c,0xb0};
	static unsigned int short_len2[]={2,3,3,3,4,4,5,6,6,4,4,5,6,6,4,0};
	static unsigned int short_xor2[]={0,0x40,0x60,0xa0,0xd0,0xe0,0xf0,0xf8,
			0xfc,0xc0,0x80,0x90,0x98,0x9c,0xb0};

	unsigned int length, save_length, last_distance, distance, bit_field;
	int distance_place;
	
	unpack_data->num_huf = 0;
	bit_field = rar_getbits(unpack_data);
	if (unpack_data->lcount == 2) {
		rar_addbits(unpack_data, 1);
		if (bit_field >= 0x8000) {
			copy_string15(unpack_data,
				(unsigned int)unpack_data->last_dist,
				unpack_data->last_length);
			return;
		}
		bit_field <<= 1;
		unpack_data->lcount = 0;
	}
	
	bit_field >>= 8;
	short_len1[1] = short_len2[3] = unpack_data->buf60+3;
	if (unpack_data->avr_ln1 < 37) {
		for (length=0 ;; length++) {
			if (((bit_field^short_xor1[length]) &
					(~(0xff>>short_len1[length]))) == 0) {
				break;
			}
		}
		rar_addbits(unpack_data, short_len1[length]);
	} else {
		for (length=0; ;length++) {
				if (((bit_field^short_xor2[length]) &
						(~(0xff>>short_len2[length]))) == 0) {
					break;
				}
		}
		rar_addbits(unpack_data, short_len2[length]);
	}
	
	if (length >= 9) {
		if (length == 9) {
			unpack_data->lcount++;
			copy_string15(unpack_data, (unsigned int) unpack_data->last_dist,
				unpack_data->last_length);
			return;
		}
		if (length == 14) {
			unpack_data->lcount = 0;
			length = decode_num(unpack_data, rar_getbits(unpack_data),
					STARTL2, dec_l2, pos_l2) + 5;
			distance = (rar_getbits(unpack_data) >> 1) | 0x8000;
			rar_addbits(unpack_data, 15);
			unpack_data->last_length = length;
			unpack_data->last_dist = distance;
			copy_string15(unpack_data, distance, length);
			return;
		}
		
		unpack_data->lcount = 0;
		save_length = length;
		distance = unpack_data->old_dist[(unpack_data->old_dist_ptr-(length-9)) & 3];
		length = decode_num(unpack_data,
				rar_getbits(unpack_data), STARTL1, dec_l1, pos_l1) + 2;
		if (length == 0x101 && save_length == 10) {
			unpack_data->buf60 ^= 1;
			return;
		}
		if (distance > 256) {
			length++;
		}
		if (distance >= unpack_data->max_dist3) {
			length++;
		}
		
		unpack_data->old_dist[unpack_data->old_dist_ptr++] = distance;
		unpack_data->old_dist_ptr = unpack_data->old_dist_ptr & 3;
		unpack_data->last_length = length;
		unpack_data->last_dist = distance;
		copy_string15(unpack_data, distance, length);
		return;
	}
	
	unpack_data->lcount = 0;
	unpack_data->avr_ln1 += length;
	unpack_data->avr_ln1 -= unpack_data->avr_ln1 >> 4;
	
	distance_place = decode_num(unpack_data, rar_getbits(unpack_data),
					STARTHF2, dec_hf2, pos_hf2) & 0xff;
	distance = unpack_data->chseta[distance_place & 0xff];
	if (--distance_place != -1) {
		unpack_data->placea[distance & 0xff]--;
		last_distance = unpack_data->chseta[distance_place & 0xff];
		unpack_data->placea[last_distance & 0xff]++;
		unpack_data->chseta[(distance_place+1) & 0xff] = last_distance;
		unpack_data->chseta[distance_place & 0xff] = distance;
	}
	length += 2;
	unpack_data->old_dist[unpack_data->old_dist_ptr++] = ++distance;
	unpack_data->old_dist_ptr = unpack_data->old_dist_ptr & 3;
	unpack_data->last_length = length;
	unpack_data->last_dist = distance;
	copy_string15(unpack_data, distance, length);
}

static void long_lz(unpack_data_t *unpack_data)
{
	unsigned int length, distance, distance_place, new_distance_place;
	unsigned int old_avr2, old_avr3, bit_field;
	
	unpack_data->num_huf = 0;
	unpack_data->nlzb += 16;
	
	if (unpack_data->nlzb > 0xff) {
		unpack_data->nlzb = 0x90;
		unpack_data->nhfb >>= 1;
	}
	old_avr2 = unpack_data->avr_ln2;
	
	bit_field = rar_getbits(unpack_data);
	if (unpack_data->avr_ln2 >= 122) {
		length = decode_num(unpack_data, bit_field, STARTL2, dec_l2, pos_l2);
	} else if (unpack_data->avr_ln2 >= 64) {
		length = decode_num(unpack_data, bit_field, STARTL1, dec_l1, pos_l1);
	} else if (bit_field < 0x100) {
		length = bit_field;
		rar_addbits(unpack_data, 16);
	} else {
		for (length=0 ; ((bit_field << length) & 0x8000)==0 ; length++) {
			/* Empty loop */
		}
		rar_addbits(unpack_data, length+1);
	}
	
	unpack_data->avr_ln2 += length;
	unpack_data->avr_ln2 -= unpack_data->avr_ln2 >> 5;
	
	bit_field = rar_getbits(unpack_data);
	if (unpack_data->avr_plcb > 0x28ff) {
		distance_place = decode_num(unpack_data, bit_field, STARTHF2,
					dec_hf2, pos_hf2);
	} else if (unpack_data->avr_plcb > 0x6ff) {
		distance_place = decode_num(unpack_data, bit_field, STARTHF1,
					dec_hf1, pos_hf1);
	} else {
		distance_place = decode_num(unpack_data, bit_field, STARTHF0,
					dec_hf0, pos_hf0);
	}
	
	unpack_data->avr_plcb += distance_place;
	unpack_data->avr_plcb -= unpack_data->avr_plcb >> 8;
	for (;;) {
		distance = unpack_data->chsetb[distance_place & 0xff];
		new_distance_place = unpack_data->ntoplb[distance++ & 0xff]++;
		if (!(distance & 0xff)) {
			corr_huff(unpack_data, unpack_data->chsetb, unpack_data->ntoplb);
		} else {
			break;
		}
	}
	
	unpack_data->chsetb[distance_place & 0xff] = unpack_data->chsetb[new_distance_place & 0xff];
	unpack_data->chsetb[new_distance_place & 0xff] = distance;
	
	distance = ((distance & 0xff00) | (rar_getbits(unpack_data) >> 8)) >> 1;
	rar_addbits(unpack_data, 7);
	
	old_avr3 = unpack_data->avr_ln3;
	if (length != 1 && length != 4) {
		if (length==0 && distance <= unpack_data->max_dist3) {
			unpack_data->avr_ln3++;
			unpack_data->avr_ln3 -= unpack_data->avr_ln3 >> 8;
		} else if (unpack_data->avr_ln3 > 0) {
			unpack_data->avr_ln3--;
		}
	}
	
	length += 3;
	
	if (distance >= unpack_data->max_dist3) {
		length++;
	}
	if (distance <= 256) {
		length += 8;
	}
	if (old_avr3 > 0xb0 || (unpack_data->avr_plc >= 0x2a00 && old_avr2 < 0x40)) {
		unpack_data->max_dist3 = 0x7f00;
	} else {
		unpack_data->max_dist3 = 0x2001;
	}
	unpack_data->old_dist[unpack_data->old_dist_ptr++] = distance;
	unpack_data->old_dist_ptr = unpack_data->old_dist_ptr & 3;
	unpack_data->last_length = length;
	unpack_data->last_dist = distance;
	copy_string15(unpack_data, distance, length);
}

int rar_unpack15(int fd, int solid, unpack_data_t *unpack_data)
{
	rar_unpack_init_data(solid, unpack_data);
	unpack_init_data15(solid, unpack_data);
	if (!rar_unp_read_buf(fd, unpack_data)) {
		return FALSE;
	}
	if (!solid) {
		init_huff(unpack_data);
		unpack_data->unp_ptr = 0;
	} else {
		unpack_data->unp_ptr = unpack_data->wr_ptr;
	}
	--unpack_data->dest_unp_size;
	
	if (unpack_data->dest_unp_size >= 0) {
		get_flag_buf(unpack_data);
		unpack_data->flags_cnt = 8;
	}
	
	while (unpack_data->dest_unp_size >= 0) {
		unpack_data->unp_ptr &= MAXWINMASK;
		
		if (unpack_data->in_addr > unpack_data->read_top-30 &&
				!rar_unp_read_buf(fd, unpack_data)) {
			break;
		}
		
		if (((unpack_data->wr_ptr - unpack_data->unp_ptr) & MAXWINMASK) < 270 &&
				(unpack_data->wr_ptr != unpack_data->unp_ptr)) {
			rar_unp_write_buf_old(unpack_data);
		}
		if (unpack_data->st_mode) {
			huff_decode(unpack_data);
			continue;
		}
		
		if (--unpack_data->flags_cnt < 0) {
			get_flag_buf(unpack_data);
			unpack_data->flags_cnt = 7;
		}
		
		if (unpack_data->flag_buf & 0x80) {
			unpack_data->flag_buf <<= 1;
			if (unpack_data->nlzb > unpack_data->nhfb) {
				long_lz(unpack_data);
			} else {
				huff_decode(unpack_data);
			}
		} else {
			unpack_data->flag_buf <<= 1;
			if (--unpack_data->flags_cnt < 0) {
				get_flag_buf(unpack_data);
				unpack_data->flags_cnt = 7;
			}
			if (unpack_data->flag_buf & 0x80) {
				unpack_data->flag_buf <<= 1;
				if (unpack_data->nlzb > unpack_data->nhfb) {
					huff_decode(unpack_data);
				} else {
					long_lz(unpack_data);
				}
			} else {
				unpack_data->flag_buf <<= 1;
				short_lz(unpack_data);
			}
		}
	}
	rar_unp_write_buf_old(unpack_data);
	return TRUE;
}
