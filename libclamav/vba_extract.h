/*
 *  Extract VBA source code for component MS Office Documents
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Trog, Nigel Horne
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

#ifndef __VBA_EXTRACT_H
#define __VBA_EXTRACT_H

#include "others.h"
#include "clamav-types.h"
#include "uniq.h"

typedef struct vba_project_tag {
	char **name;
	uint32_t *colls;
	uint32_t *offset;
	uint32_t *length;	/* for Word 6 macros */
	unsigned char *key;	/* for Word 6 macros */
	char *dir;
	struct uniq *U;
	int count;
} vba_project_t;

vba_project_t	*cli_vba_readdir(const char *dir, struct uniq *U, uint32_t which);
vba_project_t	*cli_wm_readdir(int fd);
void 			cli_free_vba_project(vba_project_t *vba_project);

unsigned char	*cli_vba_inflate(int fd, off_t offset, int *size);
int	cli_scan_ole10(int fd, cli_ctx *ctx);
char	*cli_ppt_vba_read(int fd, cli_ctx *ctx);
unsigned char	*cli_wm_decrypt_macro(int fd, off_t offset, uint32_t len,
					unsigned char key);
#endif
