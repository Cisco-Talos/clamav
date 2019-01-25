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

#include <errno.h>

#include "clamav.h"
#include "others.h"
#include "dirent.h"
#include "w32_stat.h"
#include "shared/misc.h"

DIR *opendir(const char *name) {
    DIR *d;
    DWORD attrs;
    int len;
    struct stat sb;
    wchar_t *wpath;

    if(stat(name, &sb) < 0)
	return NULL;

    if(!S_ISDIR(sb.st_mode)) {
	errno = ENOTDIR;
	return NULL;
    }
    if(!(d = cli_malloc(sizeof(*d)))) {
	errno = ENOMEM;
	return NULL;
    }
    wpath = uncpath(name);
    if(!wpath)
	return NULL;
    wcsncpy(d->entry, wpath, sizeof(d->entry) / sizeof(d->entry[0]));
    free(wpath);
    d->entry[sizeof(d->entry) / sizeof(d->entry[0])] = L'\0';
    len = wcslen(d->entry);

    if(len >= sizeof(d->entry) / sizeof(d->entry[0]) - 4) {
	free(d);
	errno = ENAMETOOLONG;
	return NULL;
    }
    while(len--) {
	if(d->entry[len] == L'\\')
	    d->entry[len] = L'\0';
	else
	    break;
    }

    wcsncat(d->entry, L"\\*.*", 4);
    d->dh = INVALID_HANDLE_VALUE;
    return d;
}

struct dirent *readdir(DIR *dirp) {
    while(1) {
	if(dirp->dh == INVALID_HANDLE_VALUE) {
	    if((dirp->dh = FindFirstFileW(dirp->entry, &dirp->wfd)) == INVALID_HANDLE_VALUE) {
		errno = ENOENT;
		return NULL;
	    }
	} else {
	    if(!(FindNextFileW(dirp->dh, &dirp->wfd))) {
		errno = (GetLastError() == ERROR_NO_MORE_FILES) ? 0 : ENOENT;
		return NULL;
	    }
	}
	if(!WideCharToMultiByte(CP_UTF8, 0, dirp->wfd.cFileName, -1, dirp->ent.d_name, sizeof(dirp->ent.d_name), NULL, NULL))
	    continue;/* FIXME: WARN HERE ! */
	dirp->ent.d_ino = dirp->wfd.ftCreationTime.dwLowDateTime ^ dirp->wfd.nFileSizeLow;
	if(!dirp->ent.d_ino) dirp->ent.d_ino = 0x1337;
	dirp->ent.d_type = (dirp->wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? DT_DIR : DT_REG;
	break;
    }
    return &dirp->ent;
}

void rewinddir(DIR *dirp) {
    if(dirp->dh != INVALID_HANDLE_VALUE)
	FindClose(dirp->dh);
    dirp->dh = INVALID_HANDLE_VALUE;
}

int closedir(DIR *dirp) {
    rewinddir(dirp);
    free(dirp);
    return 0;
}
