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

#ifndef UNRAR_H
#define UNRAR_H 1

#include <sys/types.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif

/*	#define RAR_HIGH_DEBUG */

struct unpack_data_tag;

#include "cltypes.h"
#include "clamav.h"

#define FALSE (0)
#define TRUE (1)
#ifndef MIN
#define MIN(a,b) ((a < b) ? a : b)
#endif

typedef struct rar_metadata_tag
{
	uint64_t pack_size;
	uint64_t unpack_size;
	uint32_t crc;
	unsigned int encrypted;
	uint8_t method;
	unsigned char *filename;
	struct rar_metadata_tag *next;
} rar_metadata_t;


#define SIZEOF_MARKHEAD 7
#define SIZEOF_NEWMHD 13
#define SIZEOF_NEWLHD 32
#define SIZEOF_SHORTBLOCKHEAD 7
#define SIZEOF_LONGBLOCKHEAD 11
#define SIZEOF_SUBBLOCKHEAD 14
#define SIZEOF_COMMHEAD 13
#define SIZEOF_PROTECTHEAD 26
#define SIZEOF_AVHEAD 14
#define SIZEOF_SIGNHEAD 15
#define SIZEOF_UOHEAD 18
#define SIZEOF_MACHEAD 22
#define SIZEOF_EAHEAD 24
#define SIZEOF_BEEAHEAD 24
#define SIZEOF_STREAMHEAD 26

#define MHD_VOLUME		0x0001
#define MHD_COMMENT		0x0002
#define MHD_LOCK		0x0004
#define MHD_SOLID		0x0008
#define MHD_PACK_COMMENT	0x0010
#define MHD_NEWNUMBERING	0x0010
#define MHD_AV			0x0020
#define MHD_PROTECT		0x0040
#define MHD_PASSWORD		0x0080
#define MHD_FIRSTVOLUME		0x0100
#define MHD_ENCRYPTVER		0x0200

#define LHD_SPLIT_BEFORE	0x0001
#define LHD_SPLIT_AFTER		0x0002
#define LHD_PASSWORD		0x0004
#define LHD_COMMENT		0x0008
#define LHD_SOLID		0x0010

#define LONG_BLOCK         0x8000

#define NC                 299  /* alphabet = {0, 1, 2, ..., NC - 1} */
#define DC                 60
#define RC		    28
#define LDC		    17
#define BC		    20
#define HUFF_TABLE_SIZE    (NC+DC+RC+LDC)

#define MAX_BUF_SIZE        32768
#define MAXWINSIZE          0x400000
#define MAXWINMASK          (MAXWINSIZE-1)
#define LOW_DIST_REP_COUNT  16

typedef struct mark_header_tag
{
	unsigned char mark[SIZEOF_MARKHEAD];
} mark_header_t;

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif

#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

typedef struct main_header_tag
{
	uint16_t head_crc __attribute__ ((packed));
	uint8_t head_type;
	uint16_t flags __attribute__ ((packed));
	uint16_t head_size __attribute__ ((packed));
	uint16_t highposav __attribute__ ((packed));
	uint32_t posav __attribute__ ((packed));
} main_header_t;

typedef struct file_header_tag
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
} file_header_t;

typedef struct comment_header_tag
{
	uint16_t head_crc __attribute__ ((packed));
	uint8_t head_type;
	uint16_t flags __attribute__ ((packed));
	uint16_t head_size __attribute__ ((packed));
	uint16_t unpack_size __attribute__ ((packed));
	uint8_t unpack_ver;
	uint8_t method;
	uint16_t comm_crc __attribute__ ((packed));
} comment_header_t;

struct Decode
{
  unsigned int MaxNum;
  unsigned int DecodeLen[16];
  unsigned int DecodePos[16];
  unsigned int DecodeNum[2];
};

struct RepDecode
{
  unsigned int MaxNum;
  unsigned int DecodeLen[16];
  unsigned int DecodePos[16];
  unsigned int DecodeNum[RC];
};

struct BitDecode
{
  unsigned int MaxNum;
  unsigned int DecodeLen[16];
  unsigned int DecodePos[16];
  unsigned int DecodeNum[BC];
};

struct LitDecode
{
  unsigned int MaxNum;
  unsigned int DecodeLen[16];
  unsigned int DecodePos[16];
  unsigned int DecodeNum[NC];
};

struct DistDecode
{
  unsigned int MaxNum;
  unsigned int DecodeLen[16];
  unsigned int DecodePos[16];
  unsigned int DecodeNum[DC];
};

/* RAR2 structures */
#define MC20 257
struct MultDecode
{
  unsigned int MaxNum;
  unsigned int DecodeLen[16];
  unsigned int DecodePos[16];
  unsigned int DecodeNum[MC20];
};

struct AudioVariables
{
  int K1,K2,K3,K4,K5;
  int D1,D2,D3,D4;
  int last_delta;
  unsigned int dif[11];
  unsigned int byte_count;
  int last_char;
};
/* *************** */

typedef struct unpack_data_tag
{
	int ofd;
	
	unsigned char in_buf[MAX_BUF_SIZE];
	uint8_t window[MAXWINSIZE];
	int in_addr;
	int in_bit;
	unsigned int unp_ptr;
	unsigned int wr_ptr;
	int read_top;
	int read_border;
	struct LitDecode LD;
	struct DistDecode DD;
	struct RepDecode RD;
	struct BitDecode BD;
	unsigned int old_dist[4];
	unsigned int old_dist_ptr;
	unsigned int last_dist;
	unsigned int last_length;
	int64_t written_size;
	int64_t dest_unp_size;
	uint32_t pack_size;

	/* RAR2 variables */
	int unp_cur_channel, unp_channel_delta, unp_audio_block, unp_channels;
	unsigned char unp_old_table20[MC20 * 4];
	struct MultDecode MD[4];
	struct AudioVariables audv[4];
	
	/* RAR1 variables */
	unsigned int  flag_buf, avr_plc, avr_plcb, avr_ln1, avr_ln2, avr_ln3;
	int buf60, num_huf, st_mode, lcount, flags_cnt;
	unsigned int nhfb, nlzb, max_dist3;
	unsigned int chset[256], chseta[256], chsetb[256], chsetc[256];
	unsigned int place[256], placea[256], placeb[256], placec[256];
	unsigned int ntopl[256], ntoplb[256], ntoplc[256];
} unpack_data_t;

typedef struct rar_state_tag {
	file_header_t* file_header;
	rar_metadata_t *metadata;
	rar_metadata_t *metadata_tail;
	unpack_data_t *unpack_data;
	main_header_t *main_hdr;
	const char* comment_dir;
	unsigned long file_count;
	off_t offset;
	int fd;
	char  filename[1024];
} rar_state_t;

typedef enum
{
	ALL_HEAD=0,
	MARK_HEAD=0x72,
	MAIN_HEAD=0x73,
	FILE_HEAD=0x74,
	COMM_HEAD=0x75,
	AV_HEAD=0x76,
	SUB_HEAD=0x77,
	PROTECT_HEAD=0x78,
	SIGN_HEAD=0x79,
	NEWSUB_HEAD=0x7a,
	ENDARC_HEAD=0x7b
} header_type;

enum BLOCK_TYPES
{
	BLOCK_LZ,
	BLOCK_PPM
};


int cli_unrar_extract_next(rar_state_t* state,const char* dirname);
int cli_unrar_extract_next_prepare(rar_state_t* state,const char* dirname);
int cli_unrar_open(int fd, const char *dirname, rar_state_t* state);
void cli_unrar_close(rar_state_t* state);
unsigned int rar_get_char(int fd, unpack_data_t *unpack_data);
void addbits(unpack_data_t *unpack_data, int bits);
unsigned int getbits(unpack_data_t *unpack_data);
int unp_read_buf(int fd, unpack_data_t *unpack_data);
void unpack_init_data(int solid, unpack_data_t *unpack_data);
void make_decode_tables(unsigned char *len_tab, struct Decode *decode, int size);
void unp_write_buf_old(unpack_data_t *unpack_data);
int decode_number(unpack_data_t *unpack_data, struct Decode *decode);

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

#endif
