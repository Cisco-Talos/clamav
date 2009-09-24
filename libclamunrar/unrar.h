/*
 * Extract RAR archives
 *
 * Copyright (C) 2005-2006 trog@uncon.org
 *
 * This code is based on the work of Alexander L. Roshal (C)
 *
 * The unRAR sources may be used in any software to handle RAR
 * archives without limitations free of charge, but cannot be used
 * to re-create the RAR compression algorithm, which is proprietary.
 * Distribution of modified unRAR sources in separate form or as a
 * part of other software is permitted, provided that it is clearly
 * stated in the documentation and source comments that the code may
 * not be used to develop a RAR (WinRAR) compatible archiver.
 *
 */

#ifndef UNRAR_H
#define UNRAR_H 1

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <sys/types.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif

struct unpack_data_tag;

#include "libclamunrar/unrarhlp.h"
#include "libclamunrar/unrarppm.h"
#include "libclamunrar/unrarvm.h"
#include "libclamunrar/unrarcmd.h"
#include "libclamunrar/unrarfilter.h"

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

struct Decode
{
  unsigned int MaxNum;
  unsigned int DecodeLen[16];
  unsigned int DecodePos[16];
  unsigned int DecodeNum[2];
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

struct LowDistDecode
{
  unsigned int MaxNum;
  unsigned int DecodeLen[16];
  unsigned int DecodePos[16];
  unsigned int DecodeNum[LDC];
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

struct UnpackFilter
{
  unsigned int block_start;
  unsigned int block_length;
  unsigned int exec_count;
  int next_window;
  struct rarvm_prepared_program prg;
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
	int tables_read;
	int read_top;
	int read_border;
	int unp_block_type;
	int prev_low_dist;
	int low_dist_rep_count;
	unsigned char unp_old_table[HUFF_TABLE_SIZE];
	struct LitDecode LD;
	struct DistDecode DD;
	struct LowDistDecode LDD;
	struct RepDecode RD;
	struct BitDecode BD;
	unsigned int old_dist[4];
	unsigned int old_dist_ptr;
	unsigned int last_dist;
	unsigned int last_length;
	ppm_data_t ppm_data;
	int ppm_esc_char;
	rar_filter_array_t Filters;
	rar_filter_array_t PrgStack;
	int *old_filter_lengths;
	int last_filter, old_filter_lengths_size;
	int64_t written_size;
	int64_t true_size;
	int64_t max_size;
	int64_t dest_unp_size;
	rarvm_data_t rarvm_data;
	unsigned int unp_crc;
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

unsigned int rar_get_char(int fd, unpack_data_t *unpack_data);
void rar_addbits(unpack_data_t *unpack_data, int bits);
unsigned int rar_getbits(unpack_data_t *unpack_data);
int rar_unp_read_buf(int fd, unpack_data_t *unpack_data);
void rar_unpack_init_data(int solid, unpack_data_t *unpack_data);
void rar_make_decode_tables(unsigned char *len_tab, struct Decode *decode, int size);
void rar_unp_write_buf_old(unpack_data_t *unpack_data);
int rar_decode_number(unpack_data_t *unpack_data, struct Decode *decode);
void rar_init_filters(unpack_data_t *unpack_data);
int rar_unpack(int fd, int method, int solid, unpack_data_t *unpack_data);

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

#endif
