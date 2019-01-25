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

#include "ltdl.h"

static DWORD lasterr = 0;
const lt_dlinfo dlinfo = {"libclamunrar_iface", "unrar", 1, 0, 0, 0 };

int lt_dlinit(void) {
	return 0;
}

lt_dlhandle lt_dlopen(const char *filename) {
	lt_dlhandle h = LoadLibrary(filename);
	if(!h) lasterr = GetLastError();
	return h;
}

void *lt_dlsym(lt_dlhandle handle, const char *name) {
	void *f = GetProcAddress(handle, name);
	if(!f) lasterr = GetLastError();
	return f;
}

const char *lt_dlerror(void) {
	char *err = "NO ERROR";
	if(lasterr)
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, lasterr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&err, 0, NULL);
	return err;
}

int lt_dladdsearchdir(const char *search_dir) {
	return 0;
}

const char *lt_dlgetsearchpath(void) {
	return NULL;
}

const lt_dlinfo *lt_dlgetinfo(lt_dlhandle handle) {
	return &dlinfo;
}