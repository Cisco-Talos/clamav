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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <io.h>

#include "others.h"
#include "shared/misc.h"

wchar_t *uncpath(const char *path) {
    DWORD len = 0;
    wchar_t *dest = cli_malloc((PATH_MAX + 1) * sizeof(wchar_t));

    if(!dest)
	return NULL;

    if(strncmp(path, "\\\\", 2)) {
	/* NOT already UNC */
	memcpy(dest, L"\\\\?\\", 8);

	if(!cli_is_abspath(path)) {
	    /* Relative path */
	    len = GetCurrentDirectoryW(PATH_MAX - 5, &dest[4]);
	    if(!len || len > PATH_MAX - 5) {
		free(dest);
		errno = (len || (GetLastError() == ERROR_INSUFFICIENT_BUFFER)) ? ENAMETOOLONG : ENOENT;
		return NULL;
	    }
	    len += 4;
	    dest[len] = L'\\';
	    len++;
	} else {
	    /* C:\ and friends */
	    len = 4;
	}
    } else {
	/* UNC already */
	len = 0;
    }
    if(!(len = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, path, -1, &dest[len], PATH_MAX - len)) || len > PATH_MAX - len) {
        free(dest);
	errno = (len || (GetLastError() == ERROR_INSUFFICIENT_BUFFER)) ? ENAMETOOLONG : ENOENT;
        return NULL;
    }

    len = wcslen(dest);
    if(len == 6 && !wcsncmp(dest, L"\\\\?\\", 4) && (dest[5] == L':') && ((dest[4] >= L'A' && dest[4] <= L'Z') || (dest[4] >= L'a' && dest[4] <= L'z'))) {
	dest[6] = L'\\';
	dest[7] = L'\0';
    }

    return dest;
}

int safe_open(const char *path, int flags, ... ) {
    wchar_t *wpath = uncpath(path);
    int ret;

    if(!wpath)
	return -1;

    if(flags & O_CREAT) {
	int mode;
	va_list ap;
	va_start(ap, flags);
	mode = va_arg(ap, int);
	va_end(ap);
	ret = _wopen(wpath, flags, mode);
    } else
	ret = _wopen(wpath, flags);
    free(wpath);
    return ret;
}


w32_stat(const char *path, struct stat *buf) {
    int len;
    wchar_t *wpath = uncpath(path);
    WIN32_FILE_ATTRIBUTE_DATA attrs;

    if(!wpath)
	return -1;

    len = wcslen(wpath);
    if(len > 2 && wpath[len-1] == L'.' && wpath[len-2] == L'\\')
	wpath[len-2] = L'\0'; /* windoze can't stat '.' ... */
    len = GetFileAttributesExW(wpath, GetFileExInfoStandard, &attrs);
    free(wpath);
    if(!len) {
	len = GetLastError();
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
