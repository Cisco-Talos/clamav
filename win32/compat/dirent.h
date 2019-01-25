/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>
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

#ifndef __DIRENT_H
#define __DIRENT_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#define _DIRENT_HAVE_D_TYPE
typedef unsigned short ino_t; /* WTF?!? */

struct dirent {
    ino_t d_ino;	/* inode number */
    unsigned char d_type;	/* type of file */
    char d_name[MAX_PATH];	/* filename */
};

typedef struct {
	HANDLE dh;
	WIN32_FIND_DATAW wfd;
	struct dirent ent;
	wchar_t entry[PATH_MAX];
} DIR;

enum {
	DT_BLOCK,
	DT_CHR,
	DT_DIR,
	DT_FIFO,
	DT_LNK,
	DT_REG,
	DT_SOCK,
	DT_UNKNOWN
};

DIR *opendir(const char *name);
struct dirent *readdir(DIR *dirp);
void rewinddir(DIR *dirp);
int closedir(DIR *dirp);

#endif /* __DIRENT_H */