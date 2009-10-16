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

#include "others.h"

w32_stat(const char *path, struct stat *buf) {
    int len = strlen(path) + 2;
    wchar_t *wpath;
    WIN32_FILE_ATTRIBUTE_DATA attrs;

    if(len > PATH_MAX) {
	errno = ENAMETOOLONG;
	return -1;
    }
    if(!(wpath = cli_malloc(len * 2))) {
	errno = ENOMEM;
	return -1;
    }
    /* FIXME: make it UNC */
    if(!(len = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, path, -1, wpath, len))) {
	errno = ENOENT;	
	free(wpath);
	return -1;
    }
    if((len == 3 || (len == 7 && !wcsncmp(wpath, L"\\\\?\\", 4))) && (wpath[len-2] == L':') &&
	((wpath[len-3] >= L'A' && wpath[len-3] <= L'Z') || (wpath[len-3] >= L'a' && wpath[len-2] <= L'z')) ) {
	/* stat drives as dirs */
	wpath[len-1] = L'\\';
	wpath[len] = L'\0';
    }
    len = GetFileAttributesExW(wpath, GetFileExInfoStandard, &attrs);
    free(wpath);
    if(!len) {
	errno = ENOENT;
	return -1;
    }
    buf->st_dev = 1;
    buf->st_rdev = 1;
    buf->st_uid = 0;
    buf->st_gid = 0;
    buf->st_ino = 1;
    buf->st_atime = ((time_t)attrs.ftLastAccessTime.dwHighDateTime<<32) | attrs.ftLastAccessTime.dwLowDateTime;
    buf->st_ctime = ((time_t)attrs.ftCreationTime.dwHighDateTime<<32) | attrs.ftCreationTime.dwLowDateTime;
    buf->st_mtime = ((time_t)attrs.ftLastWriteTime.dwHighDateTime<<32) | attrs.ftLastWriteTime.dwLowDateTime;
    buf->st_mode = (attrs.dwFileAttributes == FILE_ATTRIBUTE_READONLY) ? S_IRUSR: S_IWUSR;
    buf->st_mode |= (attrs.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY) ? _S_IFDIR :  _S_IFREG;
    buf->st_nlink = 1;
    buf->st_size = ((uint64_t)attrs.nFileSizeHigh << (sizeof(attrs.nFileSizeLow)*8)) | attrs.nFileSizeLow;
    return 0;
}
