/*
 *  Extract VBA source code for component MS Office Documents
 *
 *  Copyright (C) 2004 trog@uncon.org
 *
 *  This code is based on the OpenOffice and libgsf sources.
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

#ifndef __VBA_EXTRACT_H
#define __VBA_EXTRACT_H

#include "cltypes.h"

typedef struct vba_project_tag {
	int count;
	char **name;
	uint32_t *offset;
	uint32_t *length;	/* for Word 6 macros */
	unsigned char *key;	/* for Word 6 macros */
	char *dir;
} vba_project_t;

vba_project_t *vba56_dir_read(const char *dir);
unsigned char *vba_decompress(int fd, uint32_t offset, int *size);
int cli_decode_ole_object(int fd, const char *dir);

char *ppt_vba_read(const char *dir);

vba_project_t *wm_dir_read(const char *dir);
unsigned char *wm_decrypt_macro(int fd, uint32_t offset, uint32_t len,
					unsigned char key);

#endif
