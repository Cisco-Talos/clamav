/*
 *  Extract component parts of ARJ archives
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

#ifndef __UNARJ_H
#define __UNARJ_H

typedef struct arj_metadata_tag {
	uint32_t comp_size;
	uint32_t orig_size;
	uint8_t method;
	char *filename;
	int encrypted;
	int ofd;
} arj_metadata_t;

int cli_unarj_open(int fd, const char *dirname);
int cli_unarj_prepare_file(int fd, const char *dirname, arj_metadata_t *metadata);
int cli_unarj_extract_file(int fd, const char *dirname, arj_metadata_t *metadata);

#endif
