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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <io.h>

#include "clamav.h"
#include "others.h"
#include "shared/misc.h"

wchar_t *uncpath(const char *path) {
    DWORD len = 0;
    char utf8[PATH_MAX+1];
    wchar_t *stripme, *strip_from, *dest = cli_malloc((PATH_MAX + 1) * sizeof(wchar_t));

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
	    if(*path == '\\')
		len = 6; /* Current drive root */
	    else {
		len += 4; /* A 'really' relative path */
		dest[len] = L'\\';
		len++;
	    }
	} else {
	    /* C:\ and friends */
	    len = 4;
	}
    } else {
	/* UNC already */
	len = 0;
    }

    /* TODO: DROP THE ACP STUFF ONCE WE'RE ALL CONVERTED TO UTF-8 */
    if(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, &dest[len], PATH_MAX - len) &&
	WideCharToMultiByte(CP_UTF8, 0, &dest[len], -1, utf8, PATH_MAX, NULL, NULL) &&
	!strcmp(path, utf8)) {
    } else if(!(len = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, path, -1, &dest[len], PATH_MAX - len)) || len > PATH_MAX - len) {
        free(dest);
	errno = (len || (GetLastError() == ERROR_INSUFFICIENT_BUFFER)) ? ENAMETOOLONG : ENOENT;
        return NULL;
    }

    len = wcslen(dest);
    strip_from = &dest[3];
    /* append a backslash to naked drives and get rid of . and .. */
    if(!wcsncmp(dest, L"\\\\?\\", 4) && (dest[5] == L':') && ((dest[4] >= L'A' && dest[4] <= L'Z') || (dest[4] >= L'a' && dest[4] <= L'z'))) {
	if(len == 6) {
	    dest[6] = L'\\';
	    dest[7] = L'\0';
	}
	strip_from = &dest[6];
    }
    while((stripme = wcsstr(strip_from, L"\\."))) {
	wchar_t *copy_from, *copy_to;
	if(!stripme[2] || stripme[2] == L'\\') {
	    copy_from = &stripme[2];
	    copy_to = stripme;
	} else if (stripme[2] == L'.' && (!stripme[3] || stripme[3] == L'\\')) {
	    *stripme = L'\0';
	    copy_from = &stripme[3];
	    copy_to = wcsrchr(strip_from, L'\\');
	    if(!copy_to)
		copy_to = stripme;
	} else {
	    strip_from = &stripme[1];
	    continue;
	}
	while(1) {
	    *copy_to = *copy_from;
	    if(!*copy_from) break;
	    copy_to++;
	    copy_from++;
	}
    }

    /* strip double slashes */
    if((stripme = wcsstr(&dest[4], L"\\\\"))) {
	strip_from = stripme;
	while(1) {
	    wchar_t c = *strip_from;
	    strip_from++;
	    if(c == L'\\' && *strip_from == L'\\')
		continue;
	    *stripme = c;
	    stripme++;
	    if(!c)
		break;
	}
    }
    if(wcslen(dest) == 6 && !wcsncmp(dest, L"\\\\?\\", 4) && (dest[5] == L':') && ((dest[4] >= L'A' && dest[4] <= L'Z') || (dest[4] >= L'a' && dest[4] <= L'z'))) {
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

static time_t FileTimeToUnixTime(FILETIME t)
{
	LONGLONG ll = ((LONGLONG)t.dwHighDateTime << 32) | t.dwLowDateTime;
	ll -= 116444736000000000;
	return (time_t)(ll/10000000);
}

int w32_stat(const char *path, struct stat *buf) {
    int len;
    wchar_t *wpath = uncpath(path);
    WIN32_FILE_ATTRIBUTE_DATA attrs;

    if(!wpath) {
	errno = ENOMEM;
	return -1;
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
    buf->st_atime = FileTimeToUnixTime(attrs.ftLastAccessTime);
    buf->st_ctime = FileTimeToUnixTime(attrs.ftCreationTime);
    buf->st_mtime = FileTimeToUnixTime(attrs.ftLastWriteTime);
    buf->st_mode = (attrs.dwFileAttributes & FILE_ATTRIBUTE_READONLY) ? S_IRUSR: S_IRWXU;
    buf->st_mode |= (attrs.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? _S_IFDIR :  _S_IFREG;
    buf->st_nlink = 1;
    buf->st_size = ((uint64_t)attrs.nFileSizeHigh << (sizeof(attrs.nFileSizeLow)*8)) | attrs.nFileSizeLow;
    return 0;
}

int w32_access(const char *pathname, int mode) {
    wchar_t *wpath = uncpath(pathname);
    int ret;

    if(!wpath) {
	errno = ENOMEM;
	return -1;
    }

    ret = _waccess(wpath, mode);
    free(wpath);
    return ret;
}
