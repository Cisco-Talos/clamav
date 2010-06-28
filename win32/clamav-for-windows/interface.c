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
#include "clscanapi.h"
#include "interface.h"

#define FMT(s) __FUNCTION__": "s"\n"
#define FAIL(fmt, ...) do { logg(FMT(fmt), __VA_ARGS__); return CLAMAPI_FAILURE; } while(0)
#define WIN() do { logg("%s completed successfully\n", __FUNCTION__); return CLAMAPI_SUCCESS; } while(0)

HANDLE engine_event; /* refcount = 0 event */

HANDLE engine_mutex;
/* protects the following items */
struct cl_engine *engine = NULL;
struct cl_stat dbstat;
char dbdir[PATH_MAX];
unsigned int engine_refcnt;
/* end of protected items */

#define lock_engine()(WaitForSingleObject(engine_mutex, INFINITE) == WAIT_FAILED)
#define unlock_engine() do {ReleaseMutex(engine_mutex);} while(0)

BOOL interface_setup(void) {
    if(cl_init(CL_INIT_DEFAULT))
	return FALSE;
    if(!(engine_mutex = CreateMutex(NULL, FALSE, NULL)))
	return FALSE;
    if(!(engine_event = CreateEvent(NULL, TRUE, TRUE, NULL)))
	return FALSE;

    logg_verbose = 1;
    logg_nowarn = 0;
    logg_lock = 0;
    logg_time = 1;
    logg_size = -1;
    logg_file = "C:\\clam4win.log";
    logg("ClamAV support initialized\n");
    return TRUE;
}

static int load_db(void) {
    int ret;
    if((ret = cl_load(dbdir, engine, NULL, CL_DB_STDOPT)) != CL_SUCCESS) {
	engine = NULL;
	FAIL("Failed to load database: %s", cl_strerror(ret));
    }

    if((ret = cl_engine_compile(engine))) {
	cl_engine_free(engine);
	engine = NULL;
	FAIL("Failed to compile engine: %s", cl_strerror(ret));
    }

    engine_refcnt = 0;
    memset(&dbstat, 0, sizeof(dbstat));
    cl_statinidir(dbdir, &dbstat);
    WIN();
}


DWORD WINAPI reload(void *param) {
    while(1) {
	Sleep(1000*60);
	if(WaitForSingleObject(engine_event, INFINITE) == WAIT_FAILED) {
	    logg("Failed to wait on reload event");
	    continue;
	}
	while(1) {
	    if(lock_engine()) {
		logg("Failed to lock engine");
		break;
	    }
	    if(!engine || !cl_statchkdir(&dbstat)) {
		unlock_engine();
		break;
	    }
	    if(engine_refcnt) {
		unlock_engine();
		Sleep(0);
		continue;
	    }
	    cl_engine_free(engine);
	    load_db();
	    unlock_engine();
	    break;
	}
    }
}

static void free_engine_and_unlock(void) {
    cl_engine_free(engine);
    engine = NULL;
    unlock_engine();
}

int CLAMAPI Scan_Initialize(const wchar_t *pEnginesFolder, const wchar_t *pLicenseKey) {
    BOOL cant_convert;
    int ret;

    if(lock_engine())
	FAIL("Engine mutex fail");
    if(engine) {
	unlock_engine();
	FAIL("Already initialized");
    }
    if(!(engine = cl_engine_new())) {
	unlock_engine();
	FAIL("Not enough memory for a new engine");
    }
    if(!WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, pEnginesFolder, -1, dbdir, sizeof(dbdir), NULL, &cant_convert) || cant_convert) {
	free_engine_and_unlock();
	FAIL("Can't translate pEnginesFolder");
    }
    logg("Scan_Initialize(%s)\n", dbdir);
    ret = load_db();
    unlock_engine();
    return ret;
}

int CLAMAPI Scan_Uninitialize(void) {
 //   int rett;
 //   __asm {
	//MOV eax, [ebp + 4]
	//mov rett, eax
 //   }
 //   logg("%x", rett);
    if(lock_engine())
	FAIL("Engine mutex fail");
    if(!engine) {
	unlock_engine();
	FAIL("Attempted to uninit a NULL engine");
    }
    if(engine_refcnt) {
	volatile unsigned int refs = engine_refcnt;
	unlock_engine();
	FAIL("Attempted to uninit the engine with %u active instances", engine_refcnt);
    }
    free_engine_and_unlock();
    WIN();
}

typedef struct {
    CLAM_SCAN_CALLBACK scancb;
    void *scancb_ctx;
    void *callback2;
    LONG refcnt;
    int scanmode;
} instance;

int CLAMAPI Scan_CreateInstance(CClamAVScanner **ppScanner) {
    instance *inst = calloc(1, sizeof(*inst));
    if(!inst)
	FAIL("CreateInstance: OOM");
    if(lock_engine()) {
	free(inst);
	FAIL("Failed to lock engine");
    }
    if(!engine) {
	free(inst);
	unlock_engine();
	FAIL("Create instance called with no engine");
    }
    engine_refcnt++;
    ResetEvent(engine_event);
    unlock_engine();
    *ppScanner = (CClamAVScanner *)inst;
    WIN();
}

int CLAMAPI Scan_DestroyInstance(CClamAVScanner *pScanner) {
    instance *inst = (instance *)pScanner;
    volatile LONG refcnt = InterlockedCompareExchange(&inst->refcnt, 0, 0);
    if(refcnt)
	FAIL("Attemped to destroy an instance with active scanners");
    free(pScanner);
    if(lock_engine())
	FAIL("Failed to lock engine");
    if(!engine) {
	unlock_engine();
	FAIL("Destroy instance called with no engine");
    }
    if(!--engine_refcnt)
	SetEvent(engine_event);
    unlock_engine();
    WIN();
}

int CLAMAPI Scan_SetScanCallback(CClamAVScanner *pScanner, CLAM_SCAN_CALLBACK pfnCallback, void *pContext) {
    instance *inst = (instance *)pScanner;
    inst->scancb = pfnCallback;
    inst->scancb_ctx = pContext;
    WIN();
}

int CLAMAPI Scan_SetOption(CClamAVScanner *pScanner, int option, void *value, unsigned long inputLength) {
    instance *inst = (instance *)pScanner;
    switch(option) {
	case CLAM_OPTION_SCAN_MODE: {
	    int newmode;
	    if(inputLength != sizeof(int))
		FAIL("Bad scanmode value size: %lu", inputLength);
	    memcpy(&newmode, value, sizeof(int)); /* not sure about alignment */
	    if(newmode != CLAM_SCAN_FULL && newmode != CLAM_SCAN_LIGHT)
		FAIL("Bad scanmode: %d", newmode);
	    inst->scanmode = newmode;
	    WIN();
	}
	case CLAM_OPTION_SCAN_ARCHIVE:
	case CLAM_OPTION_SCAN_PACKED:
	case CLAM_OPTION_SCAN_EMAIL:
	case CLAM_OPTION_SCAN_DEEP:
	    /* make up my mind */
	    WIN();
	default:
	    FAIL("Unsupported option: %d", option);
    }
}

int CLAMAPI Scan_GetOption(CClamAVScanner *pScanner, int option, void *value, unsigned long inputLength, unsigned long *outLength) {
    instance *inst = (instance *)pScanner;
    switch(option) {
	case CLAM_OPTION_SCAN_MODE:
	    *outLength = sizeof(int);
	    if(inputLength < sizeof(int)) {
		FAIL("Bad scanmode value size: inputLength");
	    }
	    memcpy(value, &inst->scanmode, sizeof(int));
	    WIN();

	default:
	    FAIL("Unsupported option");
    }
}

#define CLAM_LIGHT_OPTS (CL_SCAN_STDOPT & ~(CL_SCAN_ARCHIVE | CL_SCAN_MAIL | CL_SCAN_ELF))
#define MAX_VIRNAME_LEN 1024

int CLAMAPI Scan_ScanObject(CClamAVScanner *pScanner, const wchar_t *pObjectPath, int objectType, int action, int impersonatePID, int *pScanStatus, PCLAM_SCAN_INFO_LIST *pInfoList) {
    HANDLE fhdl;
    int res;
    instance *inst = (instance *)pScanner;

    InterlockedIncrement(&inst->refcnt);

    if(objectType != CLAMAPI_OBJECT_TYPE_FILE) {
	InterlockedDecrement(&inst->refcnt);
	FAIL("Unsupported object type: %d", objectType);
    }

    if((fhdl = CreateFileW(pObjectPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS, NULL)) == INVALID_HANDLE_VALUE) {
	InterlockedDecrement(&inst->refcnt);
	FAIL("open() failed");
    }

    res = Scan_ScanObjectByHandle(pScanner, &fhdl, objectType, action, impersonatePID, pScanStatus, pInfoList);

    CloseHandle(fhdl);
    InterlockedDecrement(&inst->refcnt);
    return res;
}

int CLAMAPI Scan_ScanObjectByHandle(CClamAVScanner *pScanner, const void *pObject, int objectType, int action, int impersonatePID, int *pScanStatus, PCLAM_SCAN_INFO_LIST *pInfoList) {
    instance *inst = (instance *)pScanner;
    HANDLE duphdl, self;
    char *virname;
    int fd, res;
    CLAM_SCAN_INFO_LIST *infolist;
    PCLAM_SCAN_INFO scaninfo;

    InterlockedIncrement(&inst->refcnt);

    if(objectType != CLAMAPI_OBJECT_TYPE_FILE) {
	InterlockedDecrement(&inst->refcnt);
	FAIL("Unsupported object type: %d", objectType);
    }

    infolist = calloc(1, sizeof(CLAM_SCAN_INFO_LIST) + sizeof(CLAM_SCAN_INFO) + MAX_VIRNAME_LEN);
    if(!infolist) {
	InterlockedDecrement(&inst->refcnt);
	FAIL("ScanByHandle: OOM");
    }

    self = GetCurrentProcess();
    if(!DuplicateHandle(self, *(HANDLE *)pObject, self, &duphdl, GENERIC_READ, FALSE, 0)) {
	InterlockedDecrement(&inst->refcnt);
	free(infolist);
	FAIL("Duplicate handle failed");
    }

    if((fd = _open_osfhandle((intptr_t)duphdl, _O_RDONLY)) == -1) {
	InterlockedDecrement(&inst->refcnt);
	CloseHandle(duphdl);
	free(infolist);
	FAIL("open handle failed");
    }

    res = cl_scandesc(fd, &virname, NULL, engine, (inst->scanmode == CLAM_SCAN_FULL) ? CL_SCAN_STDOPT : CLAM_LIGHT_OPTS);

    close(fd);

    scaninfo = (PCLAM_SCAN_INFO)(infolist + 1);
    infolist->cbCount = 1;
    scaninfo->cbSize = sizeof(*scaninfo);
    scaninfo->objectType = objectType;
    scaninfo->pObjectPath = L"FIXME";
    scaninfo->scanStatus = 3;

    if(res == CL_VIRUS) {
	wchar_t *wvirname = (wchar_t *)(scaninfo + 1);

	scaninfo->pThreatName = wvirname;
	if(!MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, virname, -1, wvirname, MAX_VIRNAME_LEN))
	    scaninfo->pThreatName = L"INFECTED";
	logg("FOUND: %s\n", virname);
    }
    InterlockedDecrement(&inst->refcnt);
    if(inst->scancb) {
	int cb_act = 0;
	inst->scancb(scaninfo, &cb_act, inst->scancb_ctx);
	logg("scancb returned %d\n", cb_act);
	free(infolist);
    } else {
	*pInfoList = infolist;
    }
    WIN();
}


int CLAMAPI Scan_DeleteScanInfo(CClamAVScanner *pScanner, PCLAM_SCAN_INFO_LIST pInfoList) {
    free(pInfoList);
    WIN();
}


int CLAMAPI Scan_SetPasswordCallback(CClamAVScanner *pScanner, CLAM_PASSWORD_CALLBACK pfnCallback, void *pContext) {
    FAIL("I DON'T BELONG HERE");
}

int CLAMAPI Scan_ScanObjectInMemory(CClamAVScanner *pScanner, const void *pObject, unsigned int objectSize, int objectType, int action, int impersonatePID, int *pScanStatus, PCLAM_SCAN_INFO_LIST *pInfoList) {
    FAIL("I DON'T BELONG HERE");
}
