/*
 *  Extract component parts of ARJ archives.
 *
 *  Copyright (C) 2007 trog@uncon.org
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
#include <string.h>
#include <stdlib.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <clamav.h>
#include <ctype.h>

#include "clamav.h"
#include "cltypes.h"
#include "others.h"
#include "unarj.h"

#define FIRST_HDR_SIZE		30
#define COMMENT_MAX		2048
#define FNAME_MAX		512
#define HEADERSIZE_MAX		(FIRST_HDR_SIZE + 10 + FNAME_MAX + COMMENT_MAX)
#define MAXDICBIT		16
#define DDICSIZ			26624
#define THRESHOLD		3
#ifndef UCHAR_MAX
#define UCHAR_MAX		(255)
#endif
#ifndef CHAR_BIT
#define CHAR_BIT		(8)
#endif
#define MAXMATCH		256
#ifndef FALSE
#define FALSE	(0)
#define TRUE	(1)
#endif

#define CODE_BIT	16
#define NT		(CODE_BIT + 3)
#define PBIT		5
#define TBIT		5
#define NC		(UCHAR_MAX + MAXMATCH + 2 - THRESHOLD)
#define NP		(MAXDICBIT + 1)
#define CBIT		9
#define CTABLESIZE	4096
#define PTABLESIZE	256
#define STRTP		9
#define STOPP		13

#define STRTL		0
#define STOPL		7

#if NT > NP
#define NPT NT
#else
#define NPT NP
#endif

#ifndef MIN
#define MIN(a,b) ((a < b) ? a : b)
#endif

#define GARBLE_FLAG     0x01

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif

#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

#ifndef O_BINARY
#define O_BINARY        0
#endif

typedef struct arj_main_hdr_tag {
	uint8_t first_hdr_size;		/* must be 30 bytes */
	uint8_t version;
	uint8_t min_version;
	uint8_t host_os;
	uint8_t flags;
	uint8_t security_version;
	uint8_t file_type;
	uint8_t pad;
	uint32_t time_created __attribute__ ((packed));
	uint32_t time_modified __attribute__ ((packed));
	uint32_t archive_size __attribute__ ((packed));
	uint32_t sec_env_file_position __attribute__ ((packed));
	uint16_t entryname_pos __attribute__ ((packed));
	uint16_t sec_trail_size __attribute__ ((packed));
	uint16_t host_data __attribute__ ((packed));
} arj_main_hdr_t;

typedef struct arj_file_hdr_tag {
	uint8_t first_hdr_size;		/* must be 30 bytes */
	uint8_t version;
	uint8_t min_version;
	uint8_t host_os;
	uint8_t flags;
	uint8_t method;
	uint8_t file_type;
	uint8_t password_mod;
	uint32_t time_modified __attribute__ ((packed));
	uint32_t comp_size __attribute__ ((packed));
	uint32_t orig_size __attribute__ ((packed));
	uint32_t orig_crc __attribute__ ((packed));
	uint16_t entryname_pos __attribute__ ((packed));
	uint16_t file_mode __attribute__ ((packed));
	uint16_t host_data __attribute__ ((packed));
} arj_file_hdr_t;

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

typedef struct arj_decode_tag {
	int fd;
	unsigned char *text;
	uint16_t blocksize;
	uint16_t bit_buf;
	unsigned char sub_bit_buf;
	int bit_count;
	uint32_t comp_size;
	int16_t getlen, getbuf;
	uint16_t left[2 * NC - 1];
	uint16_t right[2 * NC - 1];
	unsigned char c_len[NC];
	uint16_t c_table[CTABLESIZE];
	unsigned char pt_len[NPT];
	uint16_t pt_table[PTABLESIZE];
} arj_decode_t;

static int fill_buf(arj_decode_t *decode_data, int n)
{
	decode_data->bit_buf = (decode_data->bit_buf << n) & 0xFFFF;
	while (n > decode_data->bit_count) {
		decode_data->bit_buf |= decode_data->sub_bit_buf << (n -= decode_data->bit_count);
		if (decode_data->comp_size != 0) {
			decode_data->comp_size--;
			if (cli_readn(decode_data->fd, &decode_data->sub_bit_buf, 1) != 1) {
				return CL_EIO;
			}
		} else {
			decode_data->sub_bit_buf = 0;
		}
		decode_data->bit_count = CHAR_BIT;
	}
	decode_data->bit_buf |= decode_data->sub_bit_buf >> (decode_data->bit_count -= n);
	return CL_SUCCESS;
}

static int init_getbits(arj_decode_t *decode_data)
{
	decode_data->bit_buf = 0;
	decode_data->sub_bit_buf = 0;
	decode_data->bit_count = 0;
	return fill_buf(decode_data, 2 * CHAR_BIT);
}

static unsigned short arj_getbits(arj_decode_t *decode_data, int n)
{
	unsigned short x;
	
	x = decode_data->bit_buf >> (2 * CHAR_BIT - n);
	fill_buf(decode_data, n);
	return x;
}

static int decode_start(arj_decode_t *decode_data)
{
	decode_data->blocksize = 0;
	return init_getbits(decode_data);
}

static int write_text(int ofd, unsigned char *data, int length)
{
	int count;
	
	count = cli_writen(ofd, data, length);
	if (count != length) {
		return CL_EIO;
	} else {
		return CL_SUCCESS;
	}
}

static int make_table(arj_decode_t *decode_data, int nchar, unsigned char *bitlen, int tablebits,
			unsigned short *table, int tablesize)
{
	unsigned short count[17], weight[17], start[18], *p;
	unsigned int i, k, len, ch, jutbits, avail, nextcode, mask;
	
	for (i = 1; i <=16; i++) {
		count[i] = 0;
	}
	for (i = 0; (int)i < nchar; i++) {
		count[bitlen[i]]++;
	}
	
	start[1] = 0;
	for (i = 1; i <= 16; i++) {
		start[i+1] = start[i] + (count[i] << (16 - i));
	}
	if (start[17] != (unsigned short) (1 << 16)) {
		return CL_EARJ;
	}
	
	jutbits = 16 - tablebits;
	for (i = 1; (int)i <= tablebits; i++) {
		start[i] >>= jutbits;
		weight[i] = 1 << (tablebits - i);
	}
	while (i <= 16) {
		weight[i] = 1 << (16 - i);
		i++;
	}
	
	i = start[tablebits + 1] >> jutbits;
	if (i != (unsigned short) (1 << 16)) {
		k = 1 << tablebits;
		while (i != k) {
			table[i++] = 0;
		}
	}
	
	avail = nchar;
	mask = 1 << (15 - tablebits);
	for (ch = 0; (int)ch < nchar; ch++) {
		if ((len = bitlen[ch]) == 0) {
			continue;
		}
		k = start[len];
		nextcode = k + weight[len];
		if ((int)len <= tablebits) {
			if (nextcode > (unsigned int) tablesize) {
				return CL_EARJ;
			}
			for (i = start[len]; i < nextcode; i++) {
				table[i] = ch;
			}
		} else {
			p = &table[k >> jutbits];
			i = len - tablebits;
			while (i != 0) {
				if (*p == 0) {
					decode_data->right[avail] = decode_data->left[avail] = 0;
					*p = avail++;
				}
				if (k & mask) {
					p = &decode_data->right[*p];
				} else {
					p = &decode_data->left[*p];
				}
				k <<= 1;
				i--;
			}
			*p = ch;
		}
		start[len] = nextcode;
	}
	return CL_SUCCESS;
}

static void read_pt_len(arj_decode_t *decode_data, int nn, int nbit, int i_special)
{
	int i, n;
	short c;
	unsigned short mask;
	
	n = arj_getbits(decode_data, nbit);
	if (n == 0) {
		c = arj_getbits(decode_data, nbit);
		for (i = 0; i < nn; i++) {
			decode_data->pt_len[i] = 0;
		}
		for (i = 0; i < 256; i++) {
			decode_data->pt_table[i] = c;
		}
	} else {
		i = 0;
		while ((i < n) && (i < NPT)) {
			c = decode_data->bit_buf >> 13;
			if (c == 7) {
				mask = 1 << 12;
				while (mask & decode_data->bit_buf) {
					mask >>= 1;
					c++;
				}
			}
			fill_buf(decode_data, (c < 7) ? 3 : (int)(c - 3));
			decode_data->pt_len[i++] = (unsigned char) c;
			if (i == i_special) {
				c = arj_getbits(decode_data, 2);
				while ((--c >= 0) && (i < NPT)) {
					decode_data->pt_len[i++] = 0;
				}
			}
		}
		while ((i < nn) && (i < NPT)) {
			decode_data->pt_len[i++] = 0;
		}
		make_table(decode_data, nn, decode_data->pt_len, 8, decode_data->pt_table, PTABLESIZE);
	}
}

static int read_c_len(arj_decode_t *decode_data)
{
	short i, c, n;
	unsigned short mask;
	
	n = arj_getbits(decode_data, CBIT);
	if (n == 0) {
		c = arj_getbits(decode_data, CBIT);
		for (i = 0; i < NC; i++) {
			decode_data->c_len[i] = 0;
		}
		for (i = 0; i < CTABLESIZE; i++) {
			decode_data->c_table[i] = c;
		}
	} else {
		i = 0;
		while (i < n) {
			c = decode_data->pt_table[decode_data->bit_buf >> 8];
			if (c >= NT) {
				mask = 1 << 7;
				do {
					if (c >= (2 * NC - 1)) {
						cli_warnmsg("ERROR: bounds exceeded\n");
						return CL_EFORMAT;
					}
					if (decode_data->bit_buf & mask) {
						c = decode_data->right[c];
					} else {
						c = decode_data->left[c];
					}
					mask >>= 1;
				} while (c >= NT);
			}
			fill_buf(decode_data, (int)(decode_data->pt_len[c]));
			if (c <= 2) {
				if (c == 0) {
					c = 1;
				} else if (c == 1) {
					c = arj_getbits(decode_data, 4) + 3;
				} else {
					c = arj_getbits(decode_data, CBIT) + 20;
				}
				while (--c >= 0) {
					if (i >= NC) {
						cli_warnmsg("ERROR: bounds exceeded\n");
						return CL_EFORMAT;
					}
					decode_data->c_len[i++] = 0;
				}
			} else {
				if (i >= NC) {
					cli_warnmsg("ERROR: bounds exceeded\n");
					return CL_EFORMAT;
				}
				decode_data->c_len[i++] = (unsigned char) (c - 2);
			}
		}
		while (i < NC) {
			decode_data->c_len[i++] = 0;
		}
		make_table(decode_data, NC, decode_data->c_len, 12, decode_data->c_table, CTABLESIZE);
	}
	return CL_SUCCESS;
}


static uint16_t decode_c(arj_decode_t *decode_data)
{
	uint16_t j, mask;
	
	if (decode_data->blocksize == 0) {
		decode_data->blocksize = arj_getbits(decode_data, 16);
		read_pt_len(decode_data, NT, TBIT, 3);
		read_c_len(decode_data);
		read_pt_len(decode_data, NT, PBIT, -1);
	}
	decode_data->blocksize--;
	j = decode_data->c_table[decode_data->bit_buf >> 4];
	if (j >= NC) {
		mask = 1 << 3;
		do {
			if (j >= (2 * NC - 1)) {
				cli_warnmsg("ERROR: bounds exceeded\n");
				return 0;
			}
			if (decode_data->bit_buf & mask) {
				j = decode_data->right[j];
			} else {
				j = decode_data->left[j];
			}
			mask >>= 1;
		} while (j >= NC);
	}
	fill_buf(decode_data, (int)(decode_data->c_len[j]));
	return j;
}

static uint16_t decode_p(arj_decode_t *decode_data)
{
	unsigned short j, mask;
	
	j = decode_data->pt_table[decode_data->bit_buf >> 8];
	if (j >= NP) {
		mask = 1 << 7;
		do {
			if (j >= (2 * NC - 1)) {
				cli_warnmsg("ERROR: bounds exceeded\n");
				return 0;
			}
			if (decode_data->bit_buf & mask) {
				j = decode_data->right[j];
			} else {
				j = decode_data->left[j];
			}
			mask >>= 1;
		} while (j >= NP);
	}
	fill_buf(decode_data, (int)(decode_data->pt_len[j]));
	if (j != 0) {
		j--;
		j = (1 << j) + arj_getbits(decode_data, (int)j);
	}
	return j;
}

static int decode(int fd, arj_metadata_t *metadata)
{
	int ret;

	arj_decode_t decode_data;
	uint32_t count=0, out_ptr=0;
	int16_t chr, i, j;

	decode_data.text = (unsigned char *) cli_malloc(DDICSIZ);
	if (!decode_data.text) {
		return CL_EMEM;
	}
	decode_data.fd = fd;
	decode_data.comp_size = metadata->comp_size;
	ret = decode_start(&decode_data);
	if (ret != CL_SUCCESS) {
		return ret;
	}

	while (count < metadata->orig_size) {
		if ((chr = decode_c(&decode_data)) <= UCHAR_MAX) {
			decode_data.text[out_ptr] = (unsigned char) chr;
			count++;
			if (++out_ptr >= DDICSIZ) {
				out_ptr = 0;
				write_text(metadata->ofd, decode_data.text, DDICSIZ);
			}
		} else {
			j = chr - (UCHAR_MAX + 1 - THRESHOLD);
			count += j;
			i = decode_p(&decode_data);
			if ((i = out_ptr - i - 1) < 0) {
				i += DDICSIZ;
			}
			if ((i >= DDICSIZ) || (i < 0)) {
				cli_warnmsg("UNARJ: bounds exceeded - probably a corrupted file.\n");
				break;
			}
			if (out_ptr > i && out_ptr < DDICSIZ - MAXMATCH - 1) {
				while ((--j >= 0) && (i < DDICSIZ) && (out_ptr < DDICSIZ)) {
					decode_data.text[out_ptr++] = decode_data.text[i++];
				}
			} else {
				while (--j >= 0) {				
					decode_data.text[out_ptr] = decode_data.text[i];
					if (++out_ptr >= DDICSIZ) {
						out_ptr = 0;
						write_text(metadata->ofd, decode_data.text, DDICSIZ);
					}
					if (++i >= DDICSIZ) {
						i = 0;
					}
				}
			}
		}
	}
	if (out_ptr != 0) {
		write_text(metadata->ofd, decode_data.text, out_ptr);
	}
	
	free(decode_data.text);
	return CL_SUCCESS;
}

#define ARJ_BFIL(dd) {dd->getbuf|=dd->bit_buf>>dd->getlen;fill_buf(dd,CODE_BIT-dd->getlen);dd->getlen=CODE_BIT;}
#define ARJ_GETBIT(dd,c) {if(dd->getlen<=0)ARJ_BFIL(dd) c=(dd->getbuf&0x8000)!=0;dd->getbuf<<=1;dd->getlen--;}
#define ARJ_BPUL(dd,l) {dd->getbuf<<=l;dd->getlen-=l;}
#define ARJ_GETBITS(dd,c,l) {if(dd->getlen<l)ARJ_BFIL(dd) c=(uint16_t)dd->getbuf>>(CODE_BIT-l);ARJ_BPUL(dd,l)}

static uint16_t decode_ptr(arj_decode_t *decode_data)
{
	uint16_t c, width, plus, pwr;
	
	plus = 0;
	pwr = 1 << STRTP;
	for (width = STRTP; width < STOPP; width++) {
		ARJ_GETBIT(decode_data, c);
		if (c == 0) {
			break;
		}
		plus += pwr;
		pwr <<= 1;
	}
	if (width != 0) {
		ARJ_GETBITS(decode_data, c, width);
	}
	c += plus;
	return c;
}

static uint16_t decode_len(arj_decode_t *decode_data)
{
	uint16_t c, width, plus, pwr;

	plus = 0;
	pwr = 1 << STRTL;
	for (width = STRTL; width < STOPL; width++) {
		ARJ_GETBIT(decode_data, c);
		if (c == 0) {
			break;
		}
		plus += pwr;
		pwr <<= 1;
	}
	if (width != 0) {
		ARJ_GETBITS(decode_data, c, width);
	}
	c += plus;
	return c;
}

static int decode_f(int fd, arj_metadata_t *metadata)
{
	int ret;

	arj_decode_t decode_data, *dd;
	uint32_t count=0, out_ptr=0;
	int16_t chr, i, j, pos;

	dd = &decode_data;
	decode_data.text = (unsigned char *) cli_malloc(DDICSIZ);
	if (!decode_data.text) {
		return CL_EMEM;
	}
	decode_data.fd = fd;
	decode_data.comp_size = metadata->comp_size;
	ret = init_getbits(&decode_data);
	if (ret != CL_SUCCESS) {
		return ret;
	}
    	decode_data.getlen = decode_data.getbuf = 0;

	while (count < metadata->orig_size) {
		chr = decode_len(&decode_data);
		if (chr == 0) {
			ARJ_GETBITS(dd, chr, CHAR_BIT);
			decode_data.text[out_ptr] = (unsigned char) chr;
			count++;
			if (++out_ptr >= DDICSIZ) {
				out_ptr = 0;
				write_text(metadata->ofd, decode_data.text, DDICSIZ);
			}
		} else {
			j = chr - 1 + THRESHOLD;
			count += j;
			pos = decode_ptr(&decode_data);
			if ((i = out_ptr - pos - 1) < 0) {
				i += DDICSIZ;
			}
			if ((i >= DDICSIZ) || (i < 0)) {
				cli_warnmsg("UNARJ: bounds exceeded - probably a corrupted file.\n");
				break;
			}
			while (j-- > 0) {
				decode_data.text[out_ptr] = decode_data.text[i];
				if (++out_ptr >= DDICSIZ) {
					out_ptr = 0;
					write_text(metadata->ofd, decode_data.text, DDICSIZ);
				}
				if (++i >= DDICSIZ) {
					i = 0;
				}
			}
		}
	}
	if (out_ptr != 0) {
		write_text(metadata->ofd, decode_data.text, out_ptr);
	}
	
	free(decode_data.text);
	return CL_SUCCESS;
}	

static uint32_t arj_unstore(int ifd, int ofd, uint32_t len)
{
	unsigned char data[8192];
	uint32_t count, rem;
	unsigned int todo;

	cli_dbgmsg("in arj_unstore\n");
	rem = len;

	while (rem > 0) {
		todo = (unsigned int) MIN(8192, rem);
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

static int is_arj_archive(int fd)
{
	const char header_id[2] = {0x60, 0xea};
	char mark[2];
	
	if (cli_readn(fd, &mark[0], 2) != 2) {
		return FALSE;
	}
	if (memcmp(&mark[0], &header_id[0], 2) == 0) {
		return TRUE;
	}
	cli_dbgmsg("Not an ARJ archive\n");
	return FALSE;
}

static int arj_read_main_header(int fd)
{
	uint16_t header_size, count;
	uint32_t crc;
	arj_main_hdr_t main_hdr;
	char *filename, *comment;
	off_t header_offset;

	if (cli_readn(fd, &header_size, 2) != 2) {
		return FALSE;
	}
	header_offset = lseek(fd, 0, SEEK_CUR);
	header_size = le16_to_host(header_size);
	cli_dbgmsg("Header Size: %d\n", header_size);
	if (header_size == 0) {
		/* End of archive */
		return FALSE;
	}
	if (header_size > HEADERSIZE_MAX) {
		cli_dbgmsg("arj_read_header: invalid header_size: %u\n ", header_size);
		return FALSE;
	}
	
	if (cli_readn(fd, &main_hdr, 30) != 30) {
		return FALSE;
	}
	
	cli_dbgmsg("ARJ Main File Header\n");
	cli_dbgmsg("First Header Size: %d\n", main_hdr.first_hdr_size);
	cli_dbgmsg("Version: %d\n", main_hdr.version);
	cli_dbgmsg("Min version: %d\n", main_hdr.min_version);
	cli_dbgmsg("Host OS: %d\n", main_hdr.host_os);
	cli_dbgmsg("Flags: 0x%x\n", main_hdr.flags);
	cli_dbgmsg("Security version: %d\n", main_hdr.security_version);
	cli_dbgmsg("File type: %d\n", main_hdr.file_type);

	if (main_hdr.first_hdr_size < 30) {
		cli_dbgmsg("Format error. First Header Size < 30\n");
		return FALSE;
	}
	if (main_hdr.first_hdr_size > 30) {
		if (lseek(fd, main_hdr.first_hdr_size - 30, SEEK_CUR) == -1) {
			return FALSE;
		}
	}

	filename = (char *) cli_malloc(header_size);
	if (!filename) {
		return FALSE;
	}
	for (count=0 ; count < header_size ; count++) {
		if (cli_readn(fd, &filename[count], 1) != 1) {
			free(filename);
			return FALSE;
		}
		if (filename[count] == '\0') {
			break;
		}
	}
	if (count == header_size) {
		free(filename);
		return FALSE;
	}
	comment = (char *) cli_malloc(header_size);
	if (!comment) {
		free(filename);
		return FALSE;
	}
	for (count=0 ; count < header_size ; count++) {
		if (cli_readn(fd, &comment[count], 1) != 1) {
			free(filename);
			free(comment);
			return FALSE;
		}
		if (comment[count] == '\0') {
			break;
		}
	}
	if (count == header_size) {
		free(filename);
		free(comment);
		return FALSE;
	}
	cli_dbgmsg("Filename: %s\n", filename);
	cli_dbgmsg("Comment: %s\n", comment);
	
	free(filename);
	free(comment);
	
	if (cli_readn(fd, &crc, 4) != 4) {
		return FALSE;
	}
	
	/* Skip past any extended header data */
	for (;;) {
		if (cli_readn(fd, &count, 2) != 2) {
			return FALSE;
		}
		count = le16_to_host(count);
		cli_dbgmsg("Extended header size: %d\n", count);
		if (count == 0) {
			break;
		}
		/* Skip extended header + 4byte CRC */
		if (lseek(fd, (off_t) (count + 4), SEEK_CUR) == -1) {
			return FALSE;
		}
	}
	return TRUE;
}

static int arj_read_file_header(int fd, arj_metadata_t *metadata)
{
	uint16_t header_size, count;
	char *filename, *comment;
	arj_file_hdr_t file_hdr;
	
	if (cli_readn(fd, &header_size, 2) != 2) {
		return CL_EFORMAT;
	}
	header_size = le16_to_host(header_size);
	cli_dbgmsg("Header Size: %d\n", header_size);
	if (header_size == 0) {
		/* End of archive */
		return CL_BREAK;
	}
	if (header_size > HEADERSIZE_MAX) {
		cli_dbgmsg("arj_read_file_header: invalid header_size: %u\n ", header_size);
		return CL_EFORMAT;
	}
	
	if (cli_readn(fd, &file_hdr, 30) != 30) {
		return CL_EFORMAT;
	}
	file_hdr.comp_size = le32_to_host(file_hdr.comp_size);
	file_hdr.orig_size = le32_to_host(file_hdr.orig_size);
	
	cli_dbgmsg("ARJ File Header\n");
	cli_dbgmsg("First Header Size: %d\n", file_hdr.first_hdr_size);
	cli_dbgmsg("Version: %d\n", file_hdr.version);
	cli_dbgmsg("Min version: %d\n", file_hdr.min_version);
	cli_dbgmsg("Host OS: %d\n", file_hdr.host_os);
	cli_dbgmsg("Flags: 0x%x\n", file_hdr.flags);
	cli_dbgmsg("Method: %d\n", file_hdr.method);
	cli_dbgmsg("File type: %d\n", file_hdr.file_type);
	cli_dbgmsg("File type: %d\n", file_hdr.password_mod);
	cli_dbgmsg("Compressed size: %u\n", file_hdr.comp_size);
	cli_dbgmsg("Original size: %u\n", file_hdr.orig_size);	

	if (file_hdr.first_hdr_size < 30) {
		cli_dbgmsg("Format error. First Header Size < 30\n");
		return CL_EFORMAT;
	}

	/* Note: this skips past any extended file start position data (multi-volume) */
	if (file_hdr.first_hdr_size > 30) {
		if (lseek(fd, file_hdr.first_hdr_size - 30, SEEK_CUR) == -1) {
			return CL_EFORMAT;
		}
	}

	filename = (char *) cli_malloc(header_size);
	if (!filename) {
		return CL_EMEM;
	}
	for (count=0 ; count < header_size ; count++) {
		if (cli_readn(fd, &filename[count], 1) != 1) {
			free(filename);
			return CL_EFORMAT;
		}
		if (filename[count] == '\0') {
			break;
		}
	}
	if (count == header_size) {
		free(filename);
		return CL_EFORMAT;
	}

	comment = (char *) cli_malloc(header_size);
	if (!comment) {
		free(filename);
		return CL_EFORMAT;
	}
	for (count=0 ; count < header_size ; count++) {
		if (cli_readn(fd, &comment[count], 1) != 1) {
			free(filename);
			free(comment);
			return CL_EFORMAT;
		}
		if (comment[count] == '\0') {
			break;
		}
	}
	if (count == header_size) {
		free(filename);
		free(comment);
		return CL_EFORMAT;
	}
	cli_dbgmsg("Filename: %s\n", filename);
	cli_dbgmsg("Comment: %s\n", comment);
	metadata->filename = cli_strdup(filename);

	free(filename);
	free(comment);

	/* Skip CRC */
	if (lseek(fd, (off_t) 4, SEEK_CUR) == -1) {
		return CL_EFORMAT;
	}
	
	/* Skip past any extended header data */
	for (;;) {
		if (cli_readn(fd, &count, 2) != 2) {
			return CL_EFORMAT;
		}
		count = le16_to_host(count);
		cli_dbgmsg("Extended header size: %d\n", count);
		if (count == 0) {
			break;
		}
		/* Skip extended header + 4byte CRC */
		if (lseek(fd, (off_t) (count + 4), SEEK_CUR) == -1) {
			return CL_EFORMAT;
		}
	}
	metadata->comp_size = file_hdr.comp_size;
	metadata->orig_size = file_hdr.orig_size;
	metadata->method = file_hdr.method;
	metadata->encrypted = ((file_hdr.flags & GARBLE_FLAG) != 0) ? TRUE : FALSE;
	metadata->ofd = -1;
	if (!metadata->filename) {
		return CL_EMEM;
	}
	
	return CL_SUCCESS;
}

int cli_unarj_open(int fd, const char *dirname)
{

	cli_dbgmsg("in cli_unarj_open\n");

	if (!is_arj_archive(fd)) {
		cli_dbgmsg("Not in ARJ format\n");
		return CL_EFORMAT;
	}
	if (!arj_read_main_header(fd)) {
		cli_dbgmsg("Failed to read main header\n");
		return CL_EFORMAT;
	}
	return CL_SUCCESS;
}

int cli_unarj_prepare_file(int fd, const char *dirname, arj_metadata_t *metadata)
{
	cli_dbgmsg("in cli_unarj_prepare_file\n");
	if (!metadata || !dirname || (fd < 0)) {
		return CL_ENULLARG;
	}
	/* Each file is preceeded by the ARJ file marker */
	if (!is_arj_archive(fd)) {
		cli_dbgmsg("Not in ARJ format\n");
		return CL_EFORMAT;
	}
	return arj_read_file_header(fd, metadata);
}

int cli_unarj_extract_file(int fd, const char *dirname, arj_metadata_t *metadata)
{
	off_t offset;
	int ret = CL_SUCCESS;
	char filename[1024];
	
	cli_dbgmsg("in cli_unarj_extract_file\n");
	if (!metadata || !dirname || (fd < 0)) {
		return CL_ENULLARG;
	}

	if (metadata->encrypted) {
		cli_dbgmsg("PASSWORDed file (skipping)\n");
		offset = lseek(fd, 0, SEEK_CUR) + metadata->comp_size;
		cli_dbgmsg("Target offset: %ld\n", offset);
		if (lseek(fd, offset, SEEK_SET) != offset) {
			return CL_EARJ;
		}
		return CL_SUCCESS;
	}
	
	snprintf(filename, 1024, "%s/file.uar", dirname);
	cli_dbgmsg("Filename: %s\n", filename);
	metadata->ofd = open(filename, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, 0600);
	if (metadata->ofd < 0) {
		return CL_EOPEN;
	}
	switch (metadata->method) {
		case 0:
			ret = arj_unstore(fd, metadata->ofd, metadata->comp_size);
			if (ret != metadata->comp_size) {
				ret = CL_EIO;
			} else {
				ret = CL_SUCCESS;
			}
			break;
		case 1:
		case 2:
		case 3:
			decode(fd, metadata);
			break;
		case 4:
			decode_f(fd, metadata);
			break;
		default:
			ret = CL_EFORMAT;
			break;
	}
	return ret;
}
