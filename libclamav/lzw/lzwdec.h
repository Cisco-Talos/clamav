/*
 *  Copyright (C) 2016 Cisco and/or its affiliates. All rights reserved.
 *
 *  Author: Kevin Lin
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
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#ifndef __LZWDEC_H__
#define __LZWDEC_H__

#include <stdint.h>

struct lzw_internal_state;

typedef struct lzw_stream_s {
    uint8_t *next_in;
    unsigned avail_in;
    unsigned total_in;

    uint8_t *next_out;
    unsigned avail_out;
    unsigned total_out;

    char *msg;

    uint32_t flags;
    struct lzw_internal_state *state;
} lzw_stream;

typedef lzw_stream *lzw_streamp;

#define LZW_OK             0
#define LZW_STREAM_END     1
#define LZW_STREAM_ERROR (-2)
#define LZW_DATA_ERROR   (-3)
#define LZW_MEM_ERROR    (-4)
#define LZW_BUF_ERROR    (-5)
#define LZW_DICT_ERROR   (-7)

/* option flags */
#define LZW_NOFLAGS        0x0
#define LZW_FLAG_EARLYCHG  0x1 /* code point changes one code earlier */
#define LZW_FLAG_EXTNCODE  0x2 /* use extended code points (12+ bits) */
/* state flags */
#define LZW_FLAG_FULLDICT     0x100 /* dictionary consumes all usable codes */
#define LZW_FLAG_EXTNCODEUSE  0x200 /* extended dictionary uses 12+ bit codes */
#define LZW_FLAG_INVALIDCODE  0x400 /* input references invalid code entry (data error) */

int lzwInit(lzw_streamp strm);
int lzwInflate(lzw_streamp strm);
int lzwInflateEnd(lzw_streamp strm);

#endif /* __LZWDEC_H__ */
