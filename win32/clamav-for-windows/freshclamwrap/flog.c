/*
 * Copyright (C) 2010 Sourcefire, Inc.
 * Authors: aCaB <acab@clamav.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
 * USA
 */

#include <windows.h>
#include <stdio.h>

#include "flog.h"

static HANDLE logh = INVALID_HANDLE_VALUE;

void flog_open(const char *path) {
    DWORD sz;
    logh = CreateFile(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(logh == INVALID_HANDLE_VALUE)
	return;
    sz = GetFileSize(logh, NULL);
    if(sz >= 10*1024*1024)
	SetEndOfFile(logh);
    else
	SetFilePointer(logh, 0, NULL, FILE_END);
    flog("Log file initialized");
}

void flog(const char *fmt, ...) {
    char buf[4096];
    SYSTEMTIME t;
    DWORD x;
    va_list ap;
    int len;

    if(logh == INVALID_HANDLE_VALUE)
	return;

    GetLocalTime(&t);
    _snprintf(buf, sizeof(buf), "%04u-%02u-%02u %02u:%02u:%02u - ", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    buf[sizeof(buf)-1] = '\0';
    len = strlen(buf);
    va_start(ap, fmt);
    vsnprintf(buf + len, sizeof(buf) - len, fmt, ap);
    va_end(ap);
    buf[sizeof(buf)-1] = '\0';
    len = strlen(buf);
    len = len < sizeof(buf) - 2 ? len : sizeof(buf) - 2;
    memcpy(buf + len, "\r\n", 2);
    len += 2;
    WriteFile(logh, buf, len, &x, NULL);
}

void flog_close(void) {
    if(logh == INVALID_HANDLE_VALUE)
	return;
    flog("Log file closed");
    CloseHandle(logh);
}

