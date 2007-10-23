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


#ifndef UNRAR_PPM_H
#define UNRAR_PPM_H 1

#include "cltypes.h"

#define N1 4
#define N2 4
#define N3 4
#define N4 26
#define N_INDEXES 38

typedef struct rar_mem_blk_tag
{
	uint16_t stamp, nu;
	struct rar_mem_blk_tag *next, *prev;
} rar_mem_blk_t;

struct rar_node
{
	struct rar_node *next;
};

typedef struct sub_allocator_tag
{
	long sub_allocator_size;
	int16_t indx2units[N_INDEXES], units2indx[128], glue_count;
	uint8_t *heap_start, *lo_unit, *hi_unit;
	struct rar_node free_list[N_INDEXES];
	
	uint8_t *ptext, *units_start, *heap_end, *fake_units_start;
} sub_allocator_t;

typedef struct range_coder_tag
{
	unsigned int low, code, range;
	unsigned int low_count, high_count, scale;
}range_coder_t;

struct ppm_context;

struct see2_context_tag
{
	uint16_t summ;
	uint8_t shift, count;
};

struct state_tag
{
	uint8_t symbol;
	uint8_t freq;
	struct ppm_context *successor;
};

struct freq_data_tag
{
	uint16_t summ_freq;
	struct state_tag *stats;
};

struct ppm_context {
	uint16_t num_stats;
	union {
		struct freq_data_tag u;
		struct state_tag one_state;
	} con_ut;
	struct ppm_context *suffix;
};

typedef struct ppm_data_tag
{
	sub_allocator_t sub_alloc;
	range_coder_t coder;
	int num_masked, init_esc, order_fall, max_order, run_length, init_rl;
	struct ppm_context *min_context, *max_context;
	struct state_tag *found_state;
	uint8_t char_mask[256], ns2indx[256], ns2bsindx[256], hb2flag[256];
	uint8_t esc_count, prev_success, hi_bits_flag;
	struct see2_context_tag see2cont[25][16], dummy_sse2cont;
	uint16_t bin_summ[128][64];
} ppm_data_t;

int ppm_decode_init(ppm_data_t *ppm_data, int fd, struct unpack_data_tag *unpack_data, int *EscChar);
int ppm_decode_char(ppm_data_t *ppm_data, int fd, struct unpack_data_tag *unpack_data);
void ppm_constructor(ppm_data_t *ppm_data);
void ppm_destructor(ppm_data_t *ppm_data);

#endif
