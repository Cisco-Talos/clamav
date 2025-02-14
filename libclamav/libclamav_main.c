/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2010-2013 Sourcefire, Inc.
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

/* just a draft for now */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <Windows.h>
#include <WinSock2.h>
#include "pthread.h"

#ifndef LIBCLAMAV_STATIC
BOOL APIENTRY DllMain(HMODULE hm, DWORD why, LPVOID rsrv)
{
    WSADATA wsa;
    switch (why) {
        case DLL_PROCESS_ATTACH:
            if (WSAStartup(MAKEWORD(2, 2), &wsa))
                return FALSE;
            return pthread_win32_process_attach_np();
            break;

        case DLL_THREAD_ATTACH:
            return pthread_win32_thread_attach_np();
            break;

        case DLL_THREAD_DETACH:
            return pthread_win32_thread_detach_np();
            break;

        case DLL_PROCESS_DETACH:
            WSACleanup();
            pthread_win32_thread_detach_np();
            return pthread_win32_process_detach_np();
            break;
    }
}
#endif
