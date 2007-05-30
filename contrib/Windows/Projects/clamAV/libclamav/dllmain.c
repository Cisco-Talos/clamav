/*
 *  Copyright (C) 2007 aCaB <acab@clamav.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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
#ifdef	_MSC_VER
#include <winsock.h>
#endif

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifndef C_WINDOWS
#error You seem to lack the OS, the environment or the tools to build this file.
#endif

#include <windows.h>
#include <winreg.h>
#include "clamav.h"
#include "others.h"

#undef	CONFDIR

#ifdef	LATER
/* These are exported in the .def file */
static char _CONFDIR[MAX_PATH];
static char _CONFFRESHCLAM[MAX_PATH];
static char _CONFCLAMD[MAX_PATH];

char *CONFDIR=_CONFDIR;
char *CONFFRESHCLAM=_CONFFRESHCLAM;
char *CONFCLAMD=_CONFCLAMD;

#else
const	char *CONFDIR = NULL;
const	char *CONFFRESHCLAM = NULL;
const	char *CONFCLAMD = NULL;
#endif

#ifdef _MANAGED
#pragma managed(push, off)
#endif
#include <winerror.h>
BOOL APIENTRY DllMain(HMODULE m, DWORD  wassup, LPVOID r)
{
#ifdef	LATER
	HKEY key;
	unsigned int cs=0;
	if (wassup!=DLL_PROCESS_ATTACH) return TRUE;

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\ClamAV", 0, KEY_QUERY_VALUE, &key) || RegQueryValueExA(key, "confdir", 0, 0, NULL, &cs)) {
		strcpy(CONFDIR, COPYDIR);
		strcpy(CONFFRESHCLAM, COPYDIR"\\freshclam.conf");
		strcpy(CONFCLAMD, COPYDIR"\\clamd.conf");
		return TRUE;
	}
	if (!cs || cs>=MAX_PATH || RegQueryValueExA(key, "confdir", 0, 0, CONFDIR, &cs)) {
		cli_errmsg("Unable to load libclamav: check your registry settings");
		return FALSE;
		RegCloseKey(key);
	}
	RegCloseKey(key);
	_snprintf(CONFFRESHCLAM, MAX_PATH, "%s\\freshclam.conf", CONFDIR);
	_snprintf(CONFCLAMD, MAX_PATH, "%s\\clamd.conf", CONFDIR);
#endif
	return TRUE;
}

#ifdef _MANAGED
#pragma managed(pop)
#endif
