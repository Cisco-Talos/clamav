/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#include <string.h>
#include "pthread.h"
#include "libgen.h"
#include "shared/optparser.h"

void fix_paths(void);

#ifndef LIBCLAMAV_STATIC
BOOL APIENTRY DllMain(HMODULE hm, DWORD why, LPVOID rsrv) {
    WSADATA wsa;
    switch (why) {
    case DLL_PROCESS_ATTACH:
	if(WSAStartup(MAKEWORD(2,2), &wsa))
	    return FALSE;
	fix_paths();
	return pthread_win32_process_attach_np();
	break;

    case DLL_THREAD_ATTACH:
	return pthread_win32_thread_attach_np ();
	break;

    case DLL_THREAD_DETACH:
	return pthread_win32_thread_detach_np ();
	break;

    case DLL_PROCESS_DETACH:
	WSACleanup();
	pthread_win32_thread_detach_np ();
	return pthread_win32_process_detach_np ();
	break;
    }
}
#endif

/*
    The trick is:
    1 - Define BACKUP_DATADIR and BACKUP_CONFDIR macros directly, rather than
		defining them in clamav-config.h, because it is not guarded against multiple inclusions.
    2 - We define _static_ buffers to contain those strings.
    3 - We undef the macroes, which re-turns them back into extern pointers and we set them
		to point to the above defined buffer.
    4 - We now give the original macros the names of the above buffers and include optparser.c.
		This result in clam_options struct in optparser be defined with proper pointers.

	In platform.h, we export DATADIR and CONFDIR as extern pointers so they are available
	directly to libclamav users.
*/

#ifndef BACKUP_DATADIR
#define BACKUP_DATADIR "C:\\ClamAV\\db"
#endif
#ifndef BACKUP_CONFDIR
#define BACKUP_CONFDIR "C:\\ClamAV"
#endif
char _DATADIR[MAX_PATH] = BACKUP_DATADIR;
char _CONFDIR[MAX_PATH] = BACKUP_CONFDIR;
char _CONFDIR_CLAMD[MAX_PATH] = BACKUP_CONFDIR"\\clamd.conf";
char _CONFDIR_FRESHCLAM[MAX_PATH] = BACKUP_CONFDIR"\\freshclam.conf";
char _CONFDIR_MILTER[MAX_PATH] = BACKUP_CONFDIR"\\clamav-milter.conf";

#ifdef DATADIR
#undef DATADIR
#endif
#ifdef DATADIR
#undef CONFDIR
#endif
const char *DATADIR = _DATADIR;
const char *CONFDIR = _CONFDIR;
const char *CONFDIR_CLAMD = _CONFDIR_CLAMD;
const char *CONFDIR_FRESHCLAM = _CONFDIR_FRESHCLAM;
const char *CONFDIR_MILTER = _CONFDIR_MILTER;

#define DATADIR _DATADIR
#define CONFDIR _CONFDIR
#define CONFDIR_CLAMD _CONFDIR_CLAMD
#define CONFDIR_FRESHCLAM _CONFDIR_FRESHCLAM
#define CONFDIR_MILTER _CONFDIR_MILTER

#include "shared/optparser.c"

#define CLAMKEY "Software\\ClamAV"
void fix_paths(void) {
    int have_ddir = 0, have_cdir = 0;
    char path[MAX_PATH] = "";
    DWORD sizof;
    HKEY key;

    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, CLAMKEY, 0, KEY_QUERY_VALUE, &key) == ERROR_SUCCESS || RegOpenKeyEx(HKEY_CURRENT_USER, CLAMKEY, 0, KEY_QUERY_VALUE, &key) == ERROR_SUCCESS) {
	sizof = sizeof(path);
	if(RegQueryValueEx(key, "DataDir", 0, NULL, path, &sizof) == ERROR_SUCCESS) {
	    have_ddir = 1;
	    memcpy(_DATADIR, path, sizof);
	}
	sizof = sizeof(path);
	if(RegQueryValueEx(key, "ConfDir", 0, NULL, path, &sizof) == ERROR_SUCCESS) {
	    have_cdir = 1;
	    memcpy(_CONFDIR, path, sizof);
	}
	RegCloseKey(key);
    }
    if(!(have_ddir | have_cdir) && GetModuleFileName(NULL, path, sizeof(path))) {
	char *dir;
	path[sizeof(path)-1] = '\0';
	dir = dirname(path);
	if(!have_ddir)
	    snprintf(_DATADIR, sizeof(_DATADIR), "%s\\database", dir);
	if(!have_cdir) {
	    strncpy(_CONFDIR, dir, sizeof(_CONFDIR));
	    have_cdir = 1;
	}
    }
    _DATADIR[sizeof(_DATADIR) - 1] = '\0';
    _CONFDIR[sizeof(_CONFDIR) - 1] = '\0';
    if(have_cdir) {
	snprintf(_CONFDIR_CLAMD, sizeof(_CONFDIR_CLAMD), "%s\\%s", _CONFDIR, "clamd.conf");
	snprintf(_CONFDIR_FRESHCLAM, sizeof(_CONFDIR_FRESHCLAM), "%s\\%s", _CONFDIR, "freshclam.conf");
	snprintf(_CONFDIR_MILTER, sizeof(_CONFDIR_MILTER), "%s\\%s", _CONFDIR, "clamav-milter.conf");
    }
}
