//TODO:
// unify refcounting
// check scan funcs
// after scan returns and ret!=CL_VIRUS pInfoList NULL or unchanged?
// changed set option value to 0 or non 0
// restore file position
// cb context per instance or per scanobj ??
// optional shit to really be OPTIONAL!

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
#define FAIL(errcode, fmt, ...) do { logg(FMT(fmt), __VA_ARGS__); return (errcode); } while(0)
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

cl_error_t prescan_cb(int fd, void *context);
cl_error_t postscan_cb(int fd, int result, const char *virname, void *context);

BOOL interface_setup(void) {
    if(!(engine_mutex = CreateMutex(NULL, FALSE, NULL)))
	return FALSE;
    if(!(engine_event = CreateEvent(NULL, TRUE, TRUE, NULL)))
	return FALSE;
    return TRUE;
}

static int load_db(void) {
    int ret;
    if((ret = cl_load(dbdir, engine, NULL, CL_DB_STDOPT)) != CL_SUCCESS) {
	engine = NULL;
	FAIL(ret, "Failed to load database: %s", cl_strerror(ret));
    }

    if((ret = cl_engine_compile(engine))) {
	cl_engine_free(engine);
	engine = NULL;
	FAIL(ret, "Failed to compile engine: %s", cl_strerror(ret));
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

int CLAMAPI Scan_Initialize(const wchar_t *pEnginesFolder, const wchar_t *pTempRoot, const wchar_t *pLicenseKey) {
    char tmpdir[PATH_MAX];
    BOOL cant_convert;
    int ret;

    if(lock_engine())
	FAIL(CL_EMEM, "Engine mutex fail");
    if(engine) {
	unlock_engine();
	FAIL(CL_EARG, "Already initialized");
    }
    if(!(engine = cl_engine_new())) {
	unlock_engine();
	FAIL(CL_EMEM, "Not enough memory for a new engine");
    }
    cl_engine_set_clcb_pre_scan(engine, prescan_cb);
    if(!WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, pTempRoot, -1, tmpdir, sizeof(tmpdir), NULL, &cant_convert) || cant_convert) {
	free_engine_and_unlock();
	FAIL(CL_EARG, "Can't translate pTempRoot");
    }
    if((ret = cl_engine_set_str(engine, CL_ENGINE_TMPDIR, tmpdir))) {
	free_engine_and_unlock();
	FAIL(ret, "Failed to set engine tempdir: %s", cl_strerror(ret));
    }
    if(!WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, pEnginesFolder, -1, dbdir, sizeof(dbdir), NULL, &cant_convert) || cant_convert) {
	free_engine_and_unlock();
	FAIL(CL_EARG, "Can't translate pEnginesFolder");
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
	FAIL(CL_EMEM, "Engine mutex fail");
    if(!engine) {
	unlock_engine();
	FAIL(CL_EARG, "Attempted to uninit a NULL engine");
    }
    if(engine_refcnt) {
	volatile unsigned int refs = engine_refcnt;
	unlock_engine();
	FAIL(CL_EARG, "Attempted to uninit the engine with %u active instances", engine_refcnt);
    }
    free_engine_and_unlock();
    WIN();
}

typedef struct {
    CLAM_SCAN_CALLBACK scancb;
    void *scancb_ctx;
    void *callback2;
    LONG refcnt;
    unsigned int scanopts;
} instance;

int CLAMAPI Scan_CreateInstance(CClamAVScanner **ppScanner) {
    instance *inst = calloc(1, sizeof(*inst));
    if(!inst)
	FAIL(CL_EMEM, "CreateInstance: OOM");
    if(lock_engine()) {
	free(inst);
	FAIL(CL_EMEM, "Failed to lock engine");
    }
    if(!engine) {
	free(inst);
	unlock_engine();
	FAIL(CL_ENULLARG, "Create instance called with no engine");
    }
    engine_refcnt++;
    ResetEvent(engine_event);
    unlock_engine();
    inst->scanopts = CL_SCAN_STDOPT;
    *ppScanner = (CClamAVScanner *)inst;
    WIN();
}

int CLAMAPI Scan_DestroyInstance(CClamAVScanner *pScanner) {
    instance *inst = (instance *)pScanner;
    volatile LONG refcnt = InterlockedCompareExchange(&inst->refcnt, 0, 0);
    if(refcnt)
	FAIL(CL_EARG, "Attemped to destroy an instance with active scanners");
    free(pScanner);
    if(lock_engine())
	FAIL(CL_EMEM, "Failed to lock engine");
    if(!engine) {
	unlock_engine();
	FAIL(CL_ENULLARG, "Destroy instance called with no engine");
    }
    if(!--engine_refcnt)
	SetEvent(engine_event);
    unlock_engine();
    WIN();
}

int CLAMAPI Scan_SetScanCallback(CClamAVScanner *pScanner, CLAM_SCAN_CALLBACK pfnCallback, void *pContext) {
    instance *inst = (instance *)pScanner;
    InterlockedIncrement(&inst->refcnt);
    inst->scancb = pfnCallback;
    inst->scancb_ctx = pContext;
    InterlockedDecrement(&inst->refcnt);
    
    WIN();
}

int CLAMAPI Scan_SetOption(CClamAVScanner *pScanner, int option, void *value, unsigned long inputLength) {
    instance *inst = (instance *)pScanner;
    unsigned int whichopt, newval;

    InterlockedIncrement(&inst->refcnt);
    switch(option) {
	case CLAM_OPTION_SCAN_ARCHIVE:
	    whichopt = CL_SCAN_ARCHIVE;
	    break;
	case CLAM_OPTION_SCAN_MAIL:
	    whichopt = CL_SCAN_MAIL;
	    break;
	case CLAM_OPTION_SCAN_OLE2:
	    whichopt = CL_SCAN_OLE2;
	    break;
	case CLAM_OPTION_SCAN_HTML:
	    whichopt = CL_SCAN_HTML;
	    break;
	case CLAM_OPTION_SCAN_PE:
	    whichopt = CL_SCAN_PE;
	    break;
	case CLAM_OPTION_SCAN_PDF:
	    whichopt = CL_SCAN_PDF;
	    break;
	case CLAM_OPTION_SCAN_ALGORITHMIC:
	    whichopt = CL_SCAN_ALGORITHMIC;
	    break;
	case CLAM_OPTION_SCAN_ELF:
	    whichopt = CL_SCAN_ELF;
	    break;
	default:
	    InterlockedDecrement(&inst->refcnt);
	    FAIL(CL_EARG, "Unsupported set option: %d", option);
    }

    newval = *(unsigned int *)value;
    if(!newval)
	inst->scanopts &= ~whichopt;
    else
	inst->scanopts |= whichopt;
    InterlockedDecrement(&inst->refcnt);
    WIN();
}

int CLAMAPI Scan_GetOption(CClamAVScanner *pScanner, int option, void *value, unsigned long inputLength, unsigned long *outLength) {
    instance *inst = (instance *)pScanner;
    unsigned int whichopt;

    InterlockedIncrement(&inst->refcnt);
    switch(option) {
	case CLAM_OPTION_SCAN_ARCHIVE:
	    whichopt = CL_SCAN_ARCHIVE;
	    break;
	case CLAM_OPTION_SCAN_MAIL:
	    whichopt = CL_SCAN_MAIL;
	    break;
	case CLAM_OPTION_SCAN_OLE2:
	    whichopt = CL_SCAN_OLE2;
	    break;
	case CLAM_OPTION_SCAN_HTML:
	    whichopt = CL_SCAN_HTML;
	    break;
	case CLAM_OPTION_SCAN_PE:
	    whichopt = CL_SCAN_PE;
	    break;
	case CLAM_OPTION_SCAN_PDF:
	    whichopt = CL_SCAN_PDF;
	    break;
	case CLAM_OPTION_SCAN_ALGORITHMIC:
	    whichopt = CL_SCAN_ALGORITHMIC;
	    break;
	case CLAM_OPTION_SCAN_ELF:
	    whichopt = CL_SCAN_ELF;
	    break;
	default:
	    InterlockedDecrement(&inst->refcnt);
	    FAIL(CL_EARG, "Unsupported set option: %d", option);
    }

    *(unsigned int *)value = (inst->scanopts & whichopt) != 0;
    InterlockedDecrement(&inst->refcnt);
    WIN();
}

#define CLAM_LIGHT_OPTS (CL_SCAN_STDOPT & ~(CL_SCAN_ARCHIVE | CL_SCAN_MAIL | CL_SCAN_ELF))
#define MAX_VIRNAME_LEN 1024

int CLAMAPI Scan_ScanObject(CClamAVScanner *pScanner, const wchar_t *pObjectPath, int *pScanStatus, PCLAM_SCAN_INFO_LIST *pInfoList) {
    HANDLE fhdl;
    int res;
    instance *inst = (instance *)pScanner;

    InterlockedIncrement(&inst->refcnt);

    if((fhdl = CreateFileW(pObjectPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS, NULL)) == INVALID_HANDLE_VALUE) {
	InterlockedDecrement(&inst->refcnt);
	FAIL(CL_EOPEN, "open() failed");
    }

    res = Scan_ScanObjectByHandle(pScanner, fhdl, pScanStatus, pInfoList);

    CloseHandle(fhdl);
    InterlockedDecrement(&inst->refcnt);
    return res;
}

struct scan_ctx {
    int entryfd;
    instance *inst;
};

int CLAMAPI Scan_ScanObjectByHandle(CClamAVScanner *pScanner, HANDLE object, int *pScanStatus, PCLAM_SCAN_INFO_LIST *pInfoList) {
    instance *inst = (instance *)pScanner;
    HANDLE duphdl, self;
    char *virname;
    int fd, res;
    struct scan_ctx sctx;

    InterlockedIncrement(&inst->refcnt);

    self = GetCurrentProcess();
    if(!DuplicateHandle(self, object, self, &duphdl, GENERIC_READ, FALSE, 0)) {
	InterlockedDecrement(&inst->refcnt);
	FAIL(CL_EDUP, "Duplicate handle failed");
    }

    if((fd = _open_osfhandle((intptr_t)duphdl, _O_RDONLY)) == -1) {
	InterlockedDecrement(&inst->refcnt);
	CloseHandle(duphdl);
	FAIL(CL_EOPEN, "Open handle failed");
    }

    sctx.entryfd = fd;
    sctx.inst = inst;
    res = cl_scandesc_callback(fd, &virname, NULL, engine, inst->scanopts, &sctx);
    InterlockedDecrement(&inst->refcnt);
    close(fd);

    if(res == CL_VIRUS) {
	CLAM_SCAN_INFO_LIST *infolist = calloc(1, sizeof(CLAM_SCAN_INFO_LIST) + sizeof(CLAM_SCAN_INFO) + MAX_VIRNAME_LEN);
	PCLAM_SCAN_INFO scaninfo;
	wchar_t *wvirname;

        if(!infolist)
	    FAIL(CL_EMEM, "ScanByHandle: OOM");

	scaninfo = (PCLAM_SCAN_INFO)(infolist + 1);
	infolist->cbCount = 1;
	scaninfo->cbSize = sizeof(*scaninfo);
	scaninfo->scanPhase = SCAN_PHASE_FINAL;
	scaninfo->errorCode = CLAMAPI_SUCCESS;
	scaninfo->pThreatType = L"FIXME";
	wvirname = (wchar_t *)(scaninfo + 1);
	scaninfo->pThreatName = wvirname;
	if(!MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, virname, -1, wvirname, MAX_VIRNAME_LEN))
	    scaninfo->pThreatName = L"INFECTED";
	logg("FOUND: %s\n", virname);
	*pInfoList = infolist;
	*pScanStatus = CLAM_INFECTED;
    } else {
        *pInfoList = NULL;
	*pScanStatus = CLAM_CLEAN;
    }
    WIN();
}


int CLAMAPI Scan_DeleteScanInfo(CClamAVScanner *pScanner, PCLAM_SCAN_INFO_LIST pInfoList) {
    free(pInfoList);
    WIN();
}

cl_error_t prescan_cb(int fd, void *context) {
    struct scan_ctx *sctx = (struct scan_ctx *)context;
    instance *inst = sctx->inst;
    CLAM_SCAN_INFO si;
    CLAM_ACTION act;

    logg("in prescan cb with %d %p\n", fd, context);
    si.cbSize = sizeof(si);
    si.flags = 0;
    si.scanPhase = (fd == sctx->entryfd) ? SCAN_PHASE_INITIAL : SCAN_PHASE_PRESCAN;
    si.errorCode = CLAMAPI_SUCCESS;
    si.pThreatType = NULL;
    si.pThreatName = NULL;
    si.object = (HANDLE)_get_osfhandle(fd);
    si.pInnerObjectPath = NULL;
    inst->scancb(&si, &act, inst->scancb_ctx);
    switch(act) {
	case CLAM_ACTION_SKIP:
	    logg("prescan cb result: SKIP\n");
	    return CL_BREAK;
	case CLAM_ACTION_ABORT:
	    logg("prescan cb result: ABORT\n");
	    return CL_VIRUS;
	default:
	    logg("prescan cb returned bogus value\n");
	case CLAM_ACTION_CONTINUE:
	    logg("prescan cb result: CONTINUE\n");
	    return CL_CLEAN;
    }
}

cl_error_t postscan_cb(int fd, int result, const char *virname, void *context) {
    struct scan_ctx *sctx = (struct scan_ctx *)context;
    instance *inst = sctx->inst;
    CLAM_SCAN_INFO si;
    CLAM_ACTION act;

    logg("in prostscan cb with %d %d %s %p\n", fd, result, virname, context);
    si.cbSize = sizeof(si);
    si.flags = 0;
    si.scanPhase = (fd == sctx->entryfd) ? SCAN_PHASE_FINAL : SCAN_PHASE_POSTSCAN;
    si.errorCode = CLAMAPI_SUCCESS;
    si.pThreatType = NULL;
    si.pThreatName = (result == CL_VIRUS) ? L"Fixme" : NULL; /* FIXME */
    si.object = (HANDLE)_get_osfhandle(fd);
    si.pInnerObjectPath = NULL;
    inst->scancb(&si, &act, inst->scancb_ctx);
    switch(act) {
	case CLAM_ACTION_SKIP:
	    logg("postscan cb result: SKIP\n");
	    return CL_BREAK;
	case CLAM_ACTION_ABORT:
	    logg("postscan cb result: ABORT\n");
	    return CL_VIRUS;
	default:
	    logg("postscan cb returned bogus value\n");
	case CLAM_ACTION_CONTINUE:
	    logg("prescan cb result: CONTINUE\n");
	    return CL_CLEAN;
    }
}

CLAMAPI const wchar_t * Scan_GetErrorMsg(int errorCode) {
    return L"w00t!"; /* FIXME */
}
