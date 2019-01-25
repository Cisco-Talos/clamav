/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Trog, Török Edvin
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <ctype.h>
#ifndef _WIN32
#include <netinet/in.h>
#endif

#include "clamav.h"
#include "others.h"
#include "special.h"
#include "matcher.h"

/* NOTE: Photoshop stores data in BIG ENDIAN format, this is the opposite
	to virtually everything else */

#define special_endian_convert_16(v) be16_to_host(v)
#define special_endian_convert_32(v) be32_to_host(v)

int cli_check_mydoom_log(cli_ctx *ctx)
{
	const uint32_t *record;
	uint32_t check, key;
	fmap_t *map = *ctx->fmap;
	unsigned int blocks = map->len / (8*4);

    cli_dbgmsg("in cli_check_mydoom_log()\n");
    if(blocks<2)
	return CL_CLEAN;
    if(blocks>5)
	blocks = 5;

    record = fmap_need_off_once(map, 0, 8*4*blocks);
    if(!record)
	return CL_CLEAN;
    while(blocks) { /* This wasn't probably intended but that's what the current code does anyway */
	if(record[--blocks] == 0xffffffff)
	    return CL_CLEAN;
    }

    key = ~be32_to_host(record[0]);
    check = (be32_to_host(record[1])^key) +
	(be32_to_host(record[2])^key) +
	(be32_to_host(record[3])^key) +
	(be32_to_host(record[4])^key) +
	(be32_to_host(record[5])^key) +
	(be32_to_host(record[6])^key) +
	(be32_to_host(record[7])^key);
    if ((~check) != key)
	return CL_CLEAN;

    key = ~be32_to_host(record[8]);
    check = (be32_to_host(record[9])^key) +
	(be32_to_host(record[10])^key) +
	(be32_to_host(record[11])^key) +
	(be32_to_host(record[12])^key) +
	(be32_to_host(record[13])^key) +
	(be32_to_host(record[14])^key) +
	(be32_to_host(record[15])^key);
    if ((~check) != key)
	return CL_CLEAN;

    return cli_append_virus(ctx, "Heuristics.Worm.Mydoom.M.log");
}

static int jpeg_check_photoshop_8bim(cli_ctx *ctx, off_t *off)
{
	const unsigned char *buf;
	uint16_t ntmp;
	uint8_t nlength, id[2];
	uint32_t size;
	off_t offset = *off;
	int retval;
	fmap_t *map = *ctx->fmap;

	if(!(buf = fmap_need_off_once(map, offset, 4 + 2 + 1))) {
		cli_dbgmsg("read bim failed\n");
		return -1;
	}
	if (memcmp(buf, "8BIM", 4) != 0) {
		cli_dbgmsg("missed 8bim\n");
		return -1;
	}

	id[0] = (uint8_t)buf[4];
        id[1] = (uint8_t)buf[5];
	cli_dbgmsg("ID: 0x%.2x%.2x\n", id[0], id[1]);
	nlength = buf[6];
	ntmp = nlength + ((((uint16_t)nlength)+1) & 0x01);
	offset += 4 + 2 + 1 + ntmp;

	if (fmap_readn(map, &size, offset, 4) != 4) {
		return -1;
	}
	size = special_endian_convert_32(size);
	if (size == 0) {
		return -1;
	}
	if ((size & 0x01) == 1) {
		size++;
	}

	*off = offset + 4 + size;
	/* Is it a thumbnail image: 0x0409 or 0x040c */
	if ((id[0] == 0x04) && ((id[1] == 0x09) || (id[1] == 0x0c))) {
		/* Yes */
		cli_dbgmsg("found thumbnail\n");
	}
	else {
		/* No - Seek past record */
		return 0;
	}

	/* Jump past header */
	offset += 4 + 28;

	retval = cli_check_jpeg_exploit(ctx, offset);
	if (retval == 1) {
		cli_dbgmsg("Exploit found in thumbnail\n");
	}
	return retval;
}

static int jpeg_check_photoshop(cli_ctx *ctx, off_t offset)
{
	int retval;
	const unsigned char *buffer;
	off_t old;
	fmap_t *map = *ctx->fmap;

	if(!(buffer = fmap_need_off_once(map, offset, 14))) {
		return 0;
	}

	if (memcmp(buffer, "Photoshop 3.0", 14) != 0) {
		return 0;
	}
	offset += 14;

	cli_dbgmsg("Found Photoshop segment\n");
	do {
		old = offset;
		retval = jpeg_check_photoshop_8bim(ctx, &offset);
		if(offset <= old)
			break;
	} while (retval == 0);

	if (retval == -1) {
		retval = 0;
	}
	return retval;
}

int cli_check_jpeg_exploit(cli_ctx *ctx, off_t offset)
{
	const unsigned char *buffer;
	int retval;
	fmap_t *map = *ctx->fmap;

	cli_dbgmsg("in cli_check_jpeg_exploit()\n");
	if(ctx->recursion > ctx->engine->maxreclevel)
	    return CL_EMAXREC;

	if(!(buffer = fmap_need_off_once(map, offset, 2)))
		return 0;
	if ((buffer[0] != 0xff) || (buffer[1] != 0xd8)) {
		return 0;
	}
	offset += 2;
	for (;;) {
		off_t new_off;
		if(!(buffer = fmap_need_off_once(map, offset, 4))) {
			return 0;
		}
		/* Check for multiple 0xFF values, we need to skip them */
		if ((buffer[0] == 0xff) && (buffer[1] == 0xff)) {
			offset++;
			continue;
		}
		offset += 4;
		if ((buffer[0] == 0xff) && (buffer[1] == 0xfe)) {
			if (buffer[2] == 0x00) {
				if ((buffer[3] == 0x00) || (buffer[3] == 0x01)) {
					return 1;
				}
			}
		}
		if (buffer[0] != 0xff) {
			return -1;
		}
		if (buffer[1] == 0xda) {
			/* End of Image marker */
			return 0;
		}

		new_off = ((unsigned int) buffer[2] << 8) + buffer[3];
		if (new_off < 2) {
			return -1;
		}
		new_off -= 2;
		new_off += offset;

		if (buffer[1] == 0xed) {
			/* Possible Photoshop file */
			ctx->recursion++;
			retval=jpeg_check_photoshop(ctx, offset);
			ctx->recursion--;
			if (retval != 0)
				return retval;
		}
		offset = new_off;
	}
}

static uint32_t riff_endian_convert_32(uint32_t value, int big_endian)
{
	if (big_endian)
		return be32_to_host(value);
	else
		return le32_to_host(value);
}

static int riff_read_chunk(fmap_t *map, off_t *offset, int big_endian, int rec_level)
{
	uint32_t cache_buf;
	char *buffer;
	const uint32_t *buf;
	uint32_t chunk_size;
	off_t cur_offset = *offset;

	if (rec_level > 1000) {
		cli_dbgmsg("riff_read_chunk: recursion level exceeded\n");
		return 0;
	}

	if(!(buf = fmap_need_off_once(map, cur_offset, 4*2)))
	    return 0;
	cur_offset += 4*2;

	buffer = (char *)buf;
	memcpy (&cache_buf, buffer + sizeof (cache_buf),
			sizeof (cache_buf));
	chunk_size = riff_endian_convert_32(cache_buf, big_endian);

	if(!memcmp(buf, "anih", 4) && chunk_size != 36)
	    return 2;

	if (memcmp(buf, "RIFF", 4) == 0) {
		return 0;
	} else if (memcmp(buf, "RIFX", 4) == 0) {
		return 0;
	}
	
	if ((memcmp(buf, "LIST", 4) == 0) ||
		 (memcmp(buf, "PROP", 4) == 0) ||
		 (memcmp(buf, "FORM", 4) == 0) ||
		 (memcmp(buf, "CAT ", 4) == 0)) {
		if (!fmap_need_ptr_once(map, buf+2, 4)) {
			cli_dbgmsg("riff_read_chunk: read list type failed\n");
			return 0;
		}
		*offset = cur_offset+4;
		return riff_read_chunk(map, offset, big_endian, ++rec_level);
	}
	
	*offset = cur_offset + chunk_size + (chunk_size&1);
	if (*offset < cur_offset) {
		return 0;
	}
	/* FIXME: WTF!?
	if (lseek(fd, offset, SEEK_SET) != offset) {
		return 2;
	}
	*/
	return 1;
}

int cli_check_riff_exploit(cli_ctx *ctx)
{
	const uint32_t *buf;
	int big_endian, retval;
	off_t offset;
	fmap_t *map = *ctx->fmap;
	
	cli_dbgmsg("in cli_check_riff_exploit()\n");

	if(!(buf = fmap_need_off_once(map, 0, 4*3)))
	    return 0;

	if (memcmp(buf, "RIFF", 4) == 0) {
		big_endian = FALSE;
	} else if (memcmp(buf, "RIFX", 4) == 0) {
		big_endian = TRUE;
	} else {
		/* Not a RIFF file */
		return 0;
	}

	if (memcmp(&buf[2], "ACON", 4) != 0) {
		/* Only scan MS animated icon files */
		/* There is a *lot* of broken software out there that produces bad RIFF files */
		return 0;
	}

	offset = 4*3;
	do {
		retval = riff_read_chunk(map, &offset, big_endian, 1);
	} while (retval == 1);

	return retval;
}

static inline int swizz_j48(const uint16_t n[])
{
	cli_dbgmsg("swizz_j48: %u, %u, %u\n",n[0],n[1],n[2]);
	/* rules based on J48 tree */
	if (n[0] <= 961 || !n[1])
		return 0;
	if (n[0] <= 1006)
		return (n[2] > 0 && n[2] <= 6);
	else
		return n[1] <= 10 && n[2];
}

void cli_detect_swizz_str(const unsigned char *str, uint32_t len, struct swizz_stats *stats, int blob)
{
	unsigned char stri[4096];
	size_t i, j = 0;
	int bad = 0;
	int lastalnum = 0;
	uint8_t ngrams[17576];
	uint16_t all=0;
	uint16_t ngram_cnts[3];
	uint16_t words = 0;
	int ret;

	stats->entries++;
	for (i=0; (i < (size_t)len - 1) && (j < sizeof(stri) - 2); i += 2)
	{
		unsigned char c = str[i];
		if (str[i+1] || !c) {
			bad++;
			continue;
		}
		if (!isalnum(c)) {
			if (!lastalnum)
				continue;
			lastalnum = 0;
			c = ' ';
		} else {
			lastalnum = 1;
			if (isdigit(c))
				continue;
		}
		stri[j++] = tolower(c);
	}
	stri[j++] = '\0';
	if ((!blob && (bad >= 8)) || j < 4)
		return;
	memset(ngrams, 0, sizeof(ngrams));
	memset(ngram_cnts, 0, sizeof(ngram_cnts));
	for(i=0;i<j-2;i++) {
		if (stri[i] != ' ' && stri[i+1] != ' ' && stri[i+2] != ' ') {
			uint16_t idx = (stri[i] - 'a')*676 + (stri[i+1] - 'a')*26 + (stri[i+2] - 'a');
			if (idx < sizeof(ngrams)) {
				ngrams[idx]++;
				stats->gngrams[idx]++;
			}
		} else if (stri[i] == ' ')
			words++;
	}
	for(i=0;i<sizeof(ngrams);i++) {
		uint8_t v = ngrams[i];
		if (v > 3) v = 3;
		if (v) {
			ngram_cnts[v-1]++;
			all++;
		}
	}
	if (!all)
		return;
	cli_dbgmsg("cli_detect_swizz_str: %u, %u, %u\n",ngram_cnts[0],ngram_cnts[1],ngram_cnts[2]);
	/* normalize */
	for(i=0;i<sizeof(ngram_cnts)/sizeof(ngram_cnts[0]);i++) {
		uint32_t v = ngram_cnts[i];
		ngram_cnts[i] = (v<<10)/all;
	}
	ret = swizz_j48(ngram_cnts) ? CL_VIRUS : CL_CLEAN;
	if (words < 3) ret = CL_CLEAN;
	cli_dbgmsg("cli_detect_swizz_str: %s, %u words\n", ret == CL_VIRUS ? "suspicious" : "ok", words);
	if (ret == CL_VIRUS) {
		stats->suspicious += j;
		cli_dbgmsg("cli_detect_swizz_str: %s\n", stri);
	}
	stats->total += j;
}

static inline int swizz_j48_global(const uint32_t gn[])
{
	if (gn[0] <= 24185) {
		return gn[0] > 22980 && gn[8] > 0 && gn[8] <= 97;
	}
	if (!gn[8]) {
		if (gn[4] <= 311) {
			if (!gn[4]) {
				return gn[1] > 0 &&
					((gn[0] <= 26579 && gn[3] > 0) ||
					 (gn[0] > 28672 && gn[0] <= 30506));
			}
			if (gn[5] <= 616) {
				if (gn[6] <= 104) {
					return gn[9] <= 167;
				}
				return gn[6] <= 286;
			}
		}
		return 0;
	}
	return 1;
}

int cli_detect_swizz(struct swizz_stats *stats)
{
	uint32_t gn[10];
	uint32_t all = 0;
	size_t i;
	int global_swizz = CL_CLEAN;

	cli_dbgmsg("cli_detect_swizz: %lu/%lu, version:%d, manifest: %d \n",
			(unsigned long)stats->suspicious, (unsigned long)stats->total,
			stats->has_version, stats->has_manifest);
	memset(gn, 0, sizeof(gn));
	for(i=0;i<17576;i++) {
		uint8_t v = stats->gngrams[i];
		if (v > 10) v = 10;
		if (v) {
			gn[v-1]++;
			all++;
		}
	}
	if (all) {
		/* normalize */
		cli_dbgmsg("cli_detect_swizz: gn: ");
		for(i=0;i<sizeof(gn)/sizeof(gn[0]);i++) {
			uint32_t v = gn[i];
			gn[i] = (v<<15)/all;
			if (cli_debug_flag)
			    fprintf(stderr, "%lu, ", (unsigned long)gn[i]);
		}
		global_swizz = swizz_j48_global(gn) ? CL_VIRUS : CL_CLEAN;
		if (cli_debug_flag) {
		    fprintf(stderr, "\n");
		    cli_dbgmsg("cli_detect_swizz: global: %s\n", global_swizz ? "suspicious" : "clean");
		}
	}

	if (stats->errors > stats->entries || stats->errors >= SWIZZ_MAXERRORS) {
	    cli_dbgmsg("cli_detect_swizz: resources broken, ignoring\n");
	    return CL_CLEAN;
	}
	if (stats->total <= 337)
	    return CL_CLEAN;
	if (stats->suspicious<<10 > 40*stats->total)
	    return CL_VIRUS;
	if (!stats->suspicious)
	    return CL_CLEAN;
	return global_swizz;
}
