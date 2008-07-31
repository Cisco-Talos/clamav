/*
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
 *
 *  Authors: Alberto Wu
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

/* a cleaner state interface to LZMA */

#ifndef __LZMA_IFACE_H
#define __LZMA_IFACE_H

#include "cltypes.h"

typedef struct CLI_LZMA_tag CLI_LZMA;

struct stream_state {
	uint32_t avail_in;
	unsigned char *next_in;
	uint32_t avail_out;
	unsigned char *next_out;
};

int cli_LzmaInit(CLI_LZMA **, uint64_t);
void cli_LzmaShutdown(CLI_LZMA **);
int cli_LzmaDecode(CLI_LZMA **, struct stream_state*);
int cli_LzmaInitUPX(CLI_LZMA **, uint32_t);

#define LZMA_STREAM_END 2
#define LZMA_RESULT_OK 0
#define LZMA_RESULT_DATA_ERROR 1
#endif /* __LZMA_IFACE_H */
