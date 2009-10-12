/*
 *  Copyright (C) 2009 Sourcefire, Inc.
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
#include "others.h"
#include "dirent.h"
#include "shared/misc.h"

DIR *opendir(const char *name) {
	DIR *d;
	DWORD attrs;

	if(!(d = cli_malloc(sizeof(*d)))) {
		errno = ENOMEM;
		return NULL;
	}
	if(!(MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, name, -1, d->entry, sizeof(d->entry) / sizeof(d->entry[0])))) {
		free(d);
		errno = (GetLastError() == ERROR_INSUFFICIENT_BUFFER) ? ENAMETOOLONG : ENOENT;
		return NULL;
	}
	/* FIXME: this should be UNC'd */
	if((attrs = GetFileAttributesW(d->entry)) == INVALID_FILE_ATTRIBUTES) {
		free(d);
		errno = ENOENT;
		return NULL;
	}
	if(!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
		free(d);
		errno = ENOTDIR;
		return NULL;
	}
	d->dh = INVALID_HANDLE_VALUE;
	return d;
}

struct dirent *readdir(DIR *dirp) {
	while(1) {
		BOOL cant_convert;
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
		if(!WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, dirp->wfd.cFileName, -1, dirp->ent.d_name, sizeof(dirp->ent.d_name), NULL, &cant_convert) ||
			cant_convert || 
			!WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, dirp->wfd.cAlternateFileName, -1, dirp->ent.d_name, sizeof(dirp->ent.d_name), NULL, &cant_convert) ||
			cant_convert ||
			!dirp->ent.d_name[0]) {
			/* FIXME: WARN HERE ! */
			continue;
		}
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