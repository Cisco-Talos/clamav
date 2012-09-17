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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clamav.h"
#include "shared/output.h"
#include "interface.h"
#include "iface_errors.h"

EXTERN_C IMAGE_DOS_HEADER __ImageBase; /* Reloc safe! */

BOOL init() {
    char whereami[PATH_MAX], *slash;
    int ret;

    ret = GetModuleFileName((HINSTANCE)&__ImageBase, whereami, sizeof(whereami) -1);
    if(!ret || ret == sizeof(whereami) -1) {
	printf("ERROR: GetModuleFileName failed\n");
	return FALSE;
    }

    whereami[sizeof(whereami)-1] = '\0';
    slash = strrchr(whereami, '\\');
    if(!slash) {
	printf("ERROR: No slash found in path %s\n", whereami);
	return FALSE;
    }

    slash++;
    *slash='\0';
    SetDllDirectory(whereami);
    __try {
	cl_set_clcb_msg(msg_callback);
	ret = cl_init(CL_INIT_DEFAULT);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) { ret = -1; }

    SetDllDirectory(NULL);
    if(ret) {
	printf("ERROR: Failed cl_init() returned %d\n", ret);
	return FALSE;
    }

    strncpy(slash, "clamav_log_verbose", sizeof(whereami) - (slash - whereami));
    whereami[sizeof(whereami)-1] = '\0';
    logg_verbose = access(whereami, 0) == -1 ? 0 : 1;

    strncpy(slash, "clamav.log", sizeof(whereami) - (slash - whereami));
    whereami[sizeof(whereami)-1] = '\0';
    logg_nowarn = 0;
    logg_lock = 0;
    logg_time = 1;
    // bb #5659: force log rotation at 100 MB
    logg_size = 104857600;
    logg_rotate = 1;
    logg_file = strdup(whereami);
    if(!logg_file) {
	printf("ERROR: failed to duplicate log filename\n");
	return FALSE;
    }
    strncpy(slash, "clamav.old.log", sizeof(whereami) - (slash - whereami));
    whereami[sizeof(whereami)-1] = '\0';
    if(!MoveFileEx(logg_file, whereami, MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
	DeleteFile(logg_file);
    logg_noflush = 1;/* only flush on errors and warnings */
    if(logg("ClamAV core initialized (version %s, flevel %d)\n", cl_retver(), cl_retflevel())<0) {
	printf("ERROR: logg failed\n");
	return FALSE;
    }

    if(init_errors()) {
	logg("!Failed to initialize errors\n");
	return FALSE;
    }
    ret = interface_setup();
    logg("ClamAV module initialization %s\n", ret == TRUE ? "succeded" : "failed! Aborting...");
    return ret;
}

extern struct cl_engine *engine;
extern FILE* logg_fp;
extern int uninitialize_called;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	    return init();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	    break;
	case DLL_PROCESS_DETACH:
	    // Can't use logg(), or logg_close() here because pthreads
	    // may have already been shut down, and pthread_mutex_lock would
	    // deadlock
	    if(logg_fp) {
		if (engine) {
		    if (uninitialize_called)
			fprintf(logg_fp, "Engine still active during detach!\n");
		    else
			fprintf(logg_fp, "Scan_Uninitialize not called, but process is terminating\n");
		}
		fprintf(logg_fp, "ClamAV module shutting down\n");
		fclose(logg_fp);
	    }
	}
	return TRUE;
}
