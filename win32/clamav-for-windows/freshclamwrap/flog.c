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

static HANDLE logh;

void flog_open(const char *path) {
    logh = CreateFile(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    SetFilePointer(logh, 0, NULL, FILE_END);
    flog("Log file initialized");
}

void flog(const char *fmt, ...) {
    char buf[4096];
    SYSTEMTIME t;
    DWORD x;
    va_list ap;

    GetLocalTime(&t);
    _snprintf(buf, sizeof(buf), "%04u-%02u-%02u %02u:%02u:%02u - ", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    WriteFile(logh, buf, strlen(buf), &x, NULL);
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    WriteFile(logh, buf, strlen(buf), &x, NULL);
    WriteFile(logh, "\r\n", 2, &x, NULL);
}

void flog_close(void) {
    flog("Log file closed");
    CloseHandle(logh);
}
