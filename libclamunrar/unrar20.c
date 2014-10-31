/*
 *  Extract RAR archives
 *
 *  Copyright (C) 2005 trog@uncon.org
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

#include <stdio.h>
#include <string.h>

#include "libclamunrar/unrar.h"
#include "libclamunrar/unrar20.h"

#ifdef RAR_HIGH_DEBUG
#define rar_dbgmsg printf
#else
static void rar_dbgmsg(const char* fmt,...){}
#endif

void unpack_init_data20(int solid, unpack_data_t *unpack_data)
{
	if (!solid) {
		unpack_data->unp_channel_delta = 0;
		unpack_data->unp_cur_channel = 0;
		unpack_data->unp_audio_block = 0;
		unpack_data->unp_channels = 1;
		memset(unpack_data->audv, 0, sizeof(unpack_data->audv));
		memset(unpack_data->unp_old_table20, 0, sizeof(unpack_data->unp_old_table20));
		memset(unpack_data->MD, 0, sizeof(unpack_data->MD));
	}
}

static void copy_string20(unpack_data_t *unpack_data, unsigned int length, unsigned int distance)
{
	unsigned int dest_ptr;
	
	unpack_data->last_dist = unpack_data->old_dist[unpack_data->old_dist_ptr++ & 3] = distance;
	unpack_data->last_length = length;
	unpack_data->dest_unp_size -= length;
	
	dest_ptr = unpack_data->unp_ptr - distance;
	if (dest_ptr < MAXWINSIZE-300 && unpack_data->unp_ptr < MAXWINSIZE-300) {
		unpack_data->window[unpack_data->unp_ptr++] = unpack_data->window[dest_ptr++];
		unpack_data->window[unpack_data->unp_ptr++] = unpack_data->window[dest_ptr++];
		while (length > 2) {
			length--;
			unpack_data->window[unpack_data->unp_ptr++] = unpack_data->window[dest_ptr++];
		}
	} else while (length--) {
		unpack_data->window[unpack_data->unp_ptr] = unpack_data->window[dest_ptr++ & MAXWINMASK];
		unpack_data->unp_ptr = (unpack_data->unp_ptr+1) & MAXWINMASK;
	}
}
			
static int read_tables20(int fd, unpack_data_t *unpack_data)
{
	unsigned char bit_length[BC20];
	unsigned char table[MC20 * 4];
	int table_size, n, i, number;
	unsigned int bit_field;
	
	rar_dbgmsg("in read_tables20\n");
	
	if (unpack_data->in_addr > unpack_data->read_top-25) {
		if (!rar_unp_read_buf(fd, unpack_data)) {
			return FALSE;
		}
	}
	bit_field = rar_getbits(unpack_data);
	unpack_data->unp_audio_block = (bit_field & 0x8000);
	
	if (!(bit_field & 0x4000)) {
		memset(unpack_data->unp_old_table20, 0, sizeof(unpack_data->unp_old_table20));
	}
	rar_addbits(unpack_data, 2);
	
	if (unpack_data->unp_audio_block) {
		unpack_data->unp_channels = ((bit_field>>12) & 3) + 1;
		if (unpack_data->unp_cur_channel >= unpack_data->unp_channels) {
			unpack_data->unp_cur_channel = 0;
		}
		rar_addbits(unpack_data, 2);
		table_size = MC20 * unpack_data->unp_channels;
	} else {
		table_size = NC20+DC20+RC20;
	}
	
	for (i=0 ; i < BC20 ; i++) {
		bit_length[i] = (unsigned char) (rar_getbits(unpack_data) >> 12);
		rar_addbits(unpack_data, 4);
	}
	rar_make_decode_tables(bit_length, (struct Decode *)&unpack_data->BD, BC20);

	memset(table, 0, sizeof(table));
	for (i=0; i<table_size;) {
		if (unpack_data->in_addr > unpack_data->read_top-5) {
			if (!rar_unp_read_buf(fd, unpack_data)) {
				return FALSE;
			}
		}
		number = rar_decode_number(unpack_data, (struct Decode *)&unpack_data->BD);
		if (number < 16) {
			table[i] = (number + unpack_data->unp_old_table20[i]) & 0xf;
			i++;
		} else if (number == 16) {
			n = (rar_getbits(unpack_data) >> 14) + 3;
			rar_addbits(unpack_data, 2);
			while ((n-- > 0) && (i < table_size)) {
				table[i] = table[i-1];
				i++;
			}
		} else {
			if (number == 17) {
				n = (rar_getbits(unpack_data) >> 13) + 3;
				rar_addbits(unpack_data, 3);
			} else {
				n = (rar_getbits(unpack_data) >> 9) + 11;
				rar_addbits(unpack_data, 7);
			}
			while ((n-- > 0) && (i < table_size)) {
				table[i++] = 0;
			}
		}
	}
	if (unpack_data->in_addr > unpack_data->read_top) {
		return TRUE;
	}
	if (unpack_data->unp_audio_block) {
		for (i=0 ; i < unpack_data->unp_channels ; i++) {
			rar_make_decode_tables(&table[i*MC20], (struct Decode *)&unpack_data->MD[i], MC20);
		}
	} else {
		rar_make_decode_tables(&table[0], (struct Decode *)&unpack_data->LD, NC20);
		rar_make_decode_tables(&table[NC20], (struct Decode *)&unpack_data->DD, DC20);
		rar_make_decode_tables(&table[NC20+DC20], (struct Decode *)&unpack_data->RD, RC20);
	}
	memcpy(unpack_data->unp_old_table20, table, sizeof(unpack_data->unp_old_table20));
	return TRUE;
}

static void read_last_tables(int fd, unpack_data_t *unpack_data)
{
	if (unpack_data->read_top >= unpack_data->in_addr+5) {
		if (unpack_data->unp_audio_block) {
			if (rar_decode_number(unpack_data,
				(struct Decode *)&unpack_data->MD[unpack_data->unp_cur_channel]) == 256) {
				read_tables20(fd, unpack_data);
			}
		} else if (rar_decode_number(unpack_data, (struct Decode *)&unpack_data->LD) == 269) {
			read_tables20(fd, unpack_data);
		}
	}
}

static unsigned char decode_audio(unpack_data_t *unpack_data, int delta)
{
	struct AudioVariables *v;
	int pch, d, i;
	unsigned int ch, mindif, num_min_dif;
	
	v = &unpack_data->audv[unpack_data->unp_cur_channel];
	v->byte_count++;
	v->D4 = v->D3;
	v->D3 = v->D2;
	v->D2 = v->last_delta - v->D1;
	v->D1 = v->last_delta;
	
	pch = 8 * v->last_char + v->K1 * v->D1 + v->K2 * v->D2 + v->K3 *
		v->D3 + v->K4 * v->D4 + v->K5 * unpack_data->unp_channel_delta;
	pch = (pch >> 3) & 0xff;
	
	ch = pch - delta;
	
	d = ((signed char) delta) << 3;
	
	v->dif[0] += abs(d);
	v->dif[1] += abs(d - v->D1);
	v->dif[2] += abs(d + v->D1);
	v->dif[3] += abs(d - v->D2);
	v->dif[4] += abs(d + v->D2);
	v->dif[5] += abs(d - v->D3);
	v->dif[6] += abs(d + v->D3);
	v->dif[7] += abs(d - v->D4);
	v->dif[8] += abs(d + v->D4);
	v->dif[9] += abs(d - unpack_data->unp_channel_delta);
	v->dif[10] += abs(d + unpack_data->unp_channel_delta);

	unpack_data->unp_channel_delta = v->last_delta = (signed char) (ch - v->last_char);
	v->last_char = ch;
	
	if ((v->byte_count & 0x1f) == 0) {
		mindif = v->dif[0];
		num_min_dif = 0;
		v->dif[0] = 0;
		for (i = 1 ; i < 11 ; i++) {
			if (v->dif[i] < mindif) {
				mindif = v->dif[i];
				num_min_dif = i;
			}
			v->dif[i]=0; /* ?????? looks wrong to me */
		}
		switch(num_min_dif) {
			case 1:
				if (v->K1 >= -16) {
					v->K1--;
				}
				break;
			case 2:
				if (v->K1 < 16) {
					v->K1++;
				}
				break;
			case 3:
				if (v->K2 >= -16) {
					v->K2--;
				}
				break;
			case 4:
				if (v->K2 < 16) {
					v->K2++;
				}
				break;
			case 5:
				if (v->K3 >= -16) {
					v->K3--;
				}
				break;
			case 6:
				if (v->K3 < 16) {
					v->K3++;
				}
				break;
			case 7:
				if (v->K4 >= -16) {
					v->K4--;
				}
				break;
			case 8:
				if (v->K4 < 16) {
					v->K4++;
				}
				break;
			case 9:
				if (v->K5 >= -16) {
					v->K5--;
				}
				break;
			case 10:
				if (v->K5 < 16) {
					v->K5++;
				}
				break;
		}
	}
	return ((unsigned char) ch);
}

int rar_unpack20(int fd, int solid, unpack_data_t *unpack_data)
{
	unsigned char ldecode[]={0,1,2,3,4,5,6,7,8,10,12,14,16,20,24,28,
			32,40,48,56,64,80,96,112,128,160,192,224};
	unsigned char lbits[]={0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5};
	int ddecode[]={0,1,2,3,4,6,8,12,16,24,32,48,64,96,128,192,256,384,512,
			768,1024,1536,2048,3072,4096,6144,8192,12288,16384,24576,
			32768U,49152U,65536,98304,131072,196608,262144,327680,393216,
			458752,524288,589824,655360,720896,786432,851968,917504,983040};
	unsigned char dbits[]={0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,
			12,12,13,13,14,14,15,15,16,16,16,16,16,16,16,16,16,16,16,16,16,16};
	unsigned char sddecode[]={0,4,8,16,32,64,128,192};
	unsigned char sdbits[]={2,2,3,4,5,6,6,6};
	unsigned int bits, distance;
	int retval=TRUE, audio_number, number, length, dist_number, length_number;
	
	rar_dbgmsg("in rar_unpack20\n");

	rar_unpack_init_data(solid, unpack_data);
	if (!rar_unp_read_buf(fd, unpack_data)) {
		rar_dbgmsg("rar_unp_read_buf 1 failed\n");
		return FALSE;
	}
	if (!solid) {
		if (!read_tables20(fd, unpack_data)) {
			rar_dbgmsg("read_tables20 failed\n");
			return FALSE;
		}
	}
	--unpack_data->dest_unp_size;
	
	while (unpack_data->dest_unp_size >= 0) {
		rar_dbgmsg("dest_unp_size = %ld\n", unpack_data->dest_unp_size);
		unpack_data->unp_ptr &= MAXWINMASK;
		
		if (unpack_data->in_addr > unpack_data->read_top-30) {
			if (!rar_unp_read_buf(fd, unpack_data)) {
				rar_dbgmsg("rar_unp_read_buf 2 failed\n");
				break;
			}
		}
		if (((unpack_data->wr_ptr - unpack_data->unp_ptr) & MAXWINMASK) < 270 &&
				(unpack_data->wr_ptr != unpack_data->unp_ptr)) {
			rar_unp_write_buf_old(unpack_data);
		}
		if (unpack_data->unp_audio_block) {
			audio_number = rar_decode_number(unpack_data,
				(struct Decode *)&unpack_data->MD[unpack_data->unp_cur_channel]);
			if (audio_number == 256) {
				if (!read_tables20(fd, unpack_data)) {
					retval = FALSE;
					break;
				}
				continue;
			}
			unpack_data->window[unpack_data->unp_ptr++] =
					decode_audio(unpack_data, audio_number);
			if (++unpack_data->unp_cur_channel == unpack_data->unp_channels) {
				unpack_data->unp_cur_channel = 0;
			}
			--unpack_data->dest_unp_size;
			continue;
		}
		
		number = rar_decode_number(unpack_data, (struct Decode *)&unpack_data->LD);
		if (number < 256) {
			unpack_data->window[unpack_data->unp_ptr++] = (unsigned char) number;
			--unpack_data->dest_unp_size;
			continue;
		}
		if (number > 269) {
			length = ldecode[number-=270]+3;
			if ((bits = lbits[number]) > 0) {
				length += rar_getbits(unpack_data) >> (16-bits);
				rar_addbits(unpack_data, bits);
			}
			
			dist_number = rar_decode_number(unpack_data, (struct Decode *)&unpack_data->DD);
			distance = ddecode[dist_number] + 1;
			if ((bits = dbits[dist_number]) > 0) {
				distance += rar_getbits(unpack_data)>>(16-bits);
				rar_addbits(unpack_data, bits);
			}
			
			if (distance >= 0x2000) {
				length++;
				if (distance >= 0x40000L) {
					length++;
				}
			}
			
			copy_string20(unpack_data, length, distance);
			continue;
		}
		if (number == 269) {
			if (!read_tables20(fd, unpack_data)) {
				retval = FALSE;
				break;
			}
			continue;
		}
		if (number == 256) {
			copy_string20(unpack_data, unpack_data->last_length, unpack_data->last_dist);
			continue;
		}
		if (number < 261) {
			distance = unpack_data->old_dist[(unpack_data->old_dist_ptr-(number-256)) & 3];
			length_number = rar_decode_number(unpack_data, (struct Decode *)&unpack_data->RD);
			length = ldecode[length_number]+2;
			if ((bits = lbits[length_number]) > 0) {
				length += rar_getbits(unpack_data) >> (16-bits);
				rar_addbits(unpack_data, bits);
			}
			if (distance >= 0x101) {
				length++;
				if (distance >= 0x2000) {
					length++;
					if (distance >= 0x40000) {
						length++;
					}
				}
			}
			copy_string20(unpack_data, length, distance);
			continue;
		}
		if (number < 270) {
			distance = sddecode[number-=261]+1;
			if ((bits=sdbits[number]) > 0) {
				distance += rar_getbits(unpack_data) >> (16-bits);
				rar_addbits(unpack_data, bits);
			}
			copy_string20(unpack_data, 2, distance);
			continue;
		}
	}
	if (retval) {
		read_last_tables(fd, unpack_data);
		rar_unp_write_buf_old(unpack_data);
	}
	return retval;
}
