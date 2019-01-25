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

#ifndef __W32_STAT_H
#define __W32_STAT_H

#include <sys/stat.h>

#define S_IRUSR S_IREAD
#define S_IWUSR S_IWRITE
#define S_IRWXU (S_IRUSR|S_IWUSR)
#define S_ISDIR(mode) ((_S_IFDIR & mode)!=0)
#define S_ISREG(mode) ((_S_IFREG & mode)!=0)
#define S_ISLNK(mode) (0)
#define F_OK 0
#define W_OK 2
#define R_OK 4
#define X_OK R_OK

int w32_stat(const char *path, struct stat *buf);

#define lstat stat
#define stat(path, buf) w32_stat(path, buf)

int w32_access(const char *pathname, int mode);

#define access(pathname, mode) w32_access(pathname, mode)

wchar_t *uncpath(const char *path);
int safe_open(const char *path, int flags, ... );

#endif

