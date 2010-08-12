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

#define FMT(s) "!"__FUNCTION__": "s"\n"
#define FAIL(errcode, fmt, ...) do { logg(FMT(fmt), __VA_ARGS__); return (errcode); } while(0)
#define WIN() do { logg("~%s completed successfully\n", __FUNCTION__); return CLAMAPI_SUCCESS; } while(0)
#define INFN() do { logg("in %s\n", __FUNCTION__); } while(0)

#define MAX_VIRNAME_LEN 1024


HANDLE engine_event; /* engine unused event */

HANDLE engine_mutex;
/* protects the following items */
struct cl_engine *engine = NULL;
struct cl_stat dbstat;
char dbdir[PATH_MAX];
/* end of protected items */

typedef struct {
    CLAM_SCAN_CALLBACK scancb;
    void *scancb_ctx;
    unsigned int scanopts;
} instance;

struct {
    instance *inst;
    unsigned int refcnt;
} *instances = NULL;
unsigned int ninsts_total = 0;
unsigned int ninsts_avail = 0;
HANDLE instance_mutex;

BOOL minimal_definitions = FALSE;

#define lock_engine()(WaitForSingleObject(engine_mutex, INFINITE) == WAIT_FAILED)
#define unlock_engine() do {ReleaseMutex(engine_mutex);} while(0)

#define lock_instances()(WaitForSingleObject(instance_mutex, INFINITE) == WAIT_FAILED)
#define unlock_instances() do {ReleaseMutex(instance_mutex);} while(0)

cl_error_t prescan_cb(int fd, void *context);
cl_error_t postscan_cb(int fd, int result, const char *virname, void *context);

static wchar_t *threat_type(const char *virname) {
    if(!virname)
	return NULL;
    if(!strncmp(virname, "Trojan", 6))
	return L"Trojan";
    if(!strncmp(virname, "Worm", 4))
	return L"Worm";
    if(!strncmp(virname, "Exploit", 7))
	return L"Exploit";
    if(!strncmp(virname, "Adware", 6))
	return L"Adware";
    return L"Malware";
}

static int add_instance(instance *inst) {
    unsigned int i;

    INFN();
    if(lock_instances()) {
	logg("!add_instance: failed to lock instances\n");
	return 1;
    }
    if(!ninsts_avail) {
	void *freeme, *new_instances = calloc(ninsts_total + 256, sizeof(*instances));
	if(!new_instances) {
	    unlock_instances();
	    logg("!add_instance: failed to grow instances\n");
	    return 1;
	}
	freeme = instances;
	if(instances && ninsts_total)
	    memcpy(new_instances, instances, ninsts_total * sizeof(*instances));
	ninsts_total += 256;
	ninsts_avail += 256;
	instances = new_instances;
	if(freeme)
	    free(freeme);
	logg("add_instance: instances grown to %u\n", ninsts_total);
    }
    for(i=0; i<ninsts_total; i++) {
	if(instances[i].inst)
	    continue;
	instances[i].inst = inst;
	instances[i].refcnt = 0;
	ninsts_avail--;
	unlock_instances();
	ResetEvent(engine_event);
	return 0;
    }
    logg("!add_instances: you should not be reading this\n");
    unlock_instances();
    return 1;
}

static int del_instance(instance *inst) {
    unsigned int i;

    INFN();
    if(lock_instances()) {
	logg("!del_instance: failed to lock instances\n");
	return 1;
    }
    for(i=0; i<ninsts_total; i++) {
	if(instances[i].inst != inst)
	    continue;
	if(instances[i].refcnt) {
	    logg("!del_instance: attempted to free instance with %d active scanners\n", instances[i].refcnt);
	    unlock_instances();
	    return 1;
	}
	instances[i].inst = NULL;
	instances[i].refcnt = 0;
	ninsts_avail++;
	if(ninsts_avail == ninsts_total)
	    ResetEvent(engine_event);
	unlock_instances();
	return 0;
    }
    logg("!del_instances: instance not found\n");
    unlock_instances();
    return 1;
}

/* To be called with the instances locked */
static int is_instance(instance *inst) {
    unsigned int i;
    INFN();
    for(i=0; i<ninsts_total; i++)
	if(instances[i].inst == inst)
	    return 1;
    logg("^is_instance: lookup failed for instance %p\n", inst);
    return 0;
}

BOOL interface_setup(void) {
    if(!(engine_mutex = CreateMutex(NULL, FALSE, NULL)))
	return FALSE;
    if(!(engine_event = CreateEvent(NULL, TRUE, TRUE, NULL))) {
	CloseHandle(engine_mutex);
	return FALSE;
    }
    if(!(instance_mutex = CreateMutex(NULL, FALSE, NULL))) {
	CloseHandle(engine_mutex);
	CloseHandle(engine_event);
	return FALSE;
    }
    return TRUE;
}

static int sigload_callback(const char *type, const char *name, void *context) {
    if(minimal_definitions && strcmp(type, "fp"))
	return 1;
    return 0;
}

/* Must be called with engine_mutex locked ! */
static int load_db(void) {
    int ret;
    unsigned int signo = 0;
    INFN();

    cl_engine_set_clcb_sigload(engine, sigload_callback, NULL);
    if((ret = cl_load(dbdir, engine, &signo, CL_DB_STDOPT & ~CL_DB_PHISHING & ~CL_DB_PHISHING_URLS & CL_DB_OFFICIAL_ONLY)) != CL_SUCCESS) {
	engine = NULL;
	FAIL(ret, "Failed to load database: %s", cl_strerror(ret));
    }

    if((ret = cl_engine_compile(engine))) {
	cl_engine_free(engine);
	engine = NULL;
	FAIL(ret, "Failed to compile engine: %s", cl_strerror(ret));
    }

    logg("load_db: loaded %d signatures\n", signo);
    memset(&dbstat, 0, sizeof(dbstat));
    cl_statinidir(dbdir, &dbstat);
    WIN();
}


DWORD WINAPI reload(void *param) {
    return 0; /* FIXME */
    while(1) {
	Sleep(1000*60);
	if(WaitForSingleObject(engine_event, INFINITE) == WAIT_FAILED) {
	    logg("!reload: failed to wait on reload event");
	    continue;
	}
	while(1) {
	    if(lock_engine()) {
		logg("!reload: failed to lock engine");
		break;
	    }
	    if(!engine || !cl_statchkdir(&dbstat)) {
		unlock_engine();
		break;
	    }
	    if(lock_instances()) {
		unlock_engine();
		logg("!reload: failed to lock instances\n");
		break;
	    }
	    if(ninsts_avail != ninsts_total) {
		unlock_engine();
		unlock_instances();
		Sleep(5000);
		continue;
	    }
	    cl_engine_free(engine);
	    load_db();
	    unlock_engine();
	    unlock_instances();
	    break;
	}
    }
}

static void free_engine_and_unlock(void) {
    cl_engine_free(engine);
    engine = NULL;
    unlock_engine();
}

int CLAMAPI Scan_Initialize(const wchar_t *pEnginesFolder, const wchar_t *pTempRoot, const wchar_t *pLicenseKey, BOOL bLoadMinDefs) {
    char tmpdir[PATH_MAX];
    BOOL cant_convert;
    int ret;

    logg("in Scan_Initialize(pEnginesFolder = %S, pTempRoot = %S)\n", pEnginesFolder, pTempRoot);
    if(!pEnginesFolder)
	FAIL(CL_ENULLARG, "pEnginesFolder is NULL");
    if(!pTempRoot)
	FAIL(CL_ENULLARG, "pTempRoot is NULL");
    if(lock_engine())
	FAIL(CL_EMEM, "failed to lock engine");
    if(engine) {
	unlock_engine();
	FAIL(CL_EARG, "Already initialized");
    }

    if(!(engine = cl_engine_new())) {
	unlock_engine();
	FAIL(CL_EMEM, "Not enough memory for a new engine");
    }
    cl_engine_set_clcb_pre_scan(engine, prescan_cb);
    cl_engine_set_clcb_post_scan(engine, postscan_cb);
    
    minimal_definitions = bLoadMinDefs;
    if(bLoadMinDefs)
	logg("!MINIMAL DEFINITIONS MODE ON!");

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
    ret = load_db();
    unlock_engine();
    logg("Scan_Initialize: returning %d\n", ret);
    return ret;
}

int CLAMAPI Scan_Uninitialize(void) {
 //   int rett;
 //   __asm {
	//MOV eax, [ebp + 4]
	//mov rett, eax
 //   }
 //   logg("%x", rett);
    INFN();
    if(lock_engine())
	FAIL(CL_EMEM, "failed to lock engine");
    if(!engine) {
	unlock_engine();
	FAIL(CL_EARG, "attempted to uninit a NULL engine");
    }
   if(lock_instances()) {
	unlock_engine();
	FAIL(CL_EMEM, "failed to lock instances");
    }
    if(ninsts_avail != ninsts_total) {
	volatile unsigned int refcnt = ninsts_total - ninsts_avail;
	unlock_instances();
	unlock_engine();
	FAIL(CL_EARG, "Attempted to uninit the engine with %u active instances", refcnt);
    }
    unlock_instances();
    free_engine_and_unlock();
    WIN();
}

int CLAMAPI Scan_CreateInstance(CClamAVScanner **ppScanner) {
    instance *inst;

    INFN();
    if(!ppScanner)
	FAIL(CL_ENULLARG, "NULL pScanner");
    inst = calloc(1, sizeof(*inst));
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
    if(add_instance(inst)) {
	free(inst);
	unlock_engine();
	FAIL(CL_EMEM, "add_instance failed");
    }
    unlock_engine();
    inst->scanopts = CL_SCAN_STDOPT;
    *ppScanner = (CClamAVScanner *)inst;
    logg("Created new instance %p\n", inst);
    WIN();
}

int CLAMAPI Scan_DestroyInstance(CClamAVScanner *pScanner) {
    INFN();
    if(!pScanner)
	FAIL(CL_ENULLARG, "NULL pScanner");
    if(del_instance((instance *)pScanner))
	FAIL(CL_EMEM, "del_instance failed for %p", pScanner);
    free(pScanner);
    logg("in Scan_DestroyInstance: Instance %p destroyed\n", pScanner);
    WIN();
}

int CLAMAPI Scan_SetScanCallback(CClamAVScanner *pScanner, CLAM_SCAN_CALLBACK pfnCallback, void *pContext) {
    instance *inst;

    logg("in SetScanCallback(pScanner = %p, pfnCallback = %p, pContext = %p)\n", pScanner, pfnCallback, pContext);
    if(!pScanner)
	FAIL(CL_ENULLARG, "NULL pScanner");
    if(lock_instances())
	FAIL(CL_EMEM, "failed to lock instances for instance %p", pScanner);

    inst = (instance *)pScanner;
    if(is_instance(inst)) {
	inst->scancb = pfnCallback;
	inst->scancb_ctx = pContext;
	unlock_instances();
	WIN();
    }
    unlock_instances();
    FAIL(CL_EARG, "invalid instance %p", inst);
}

int CLAMAPI Scan_SetOption(CClamAVScanner *pScanner, int option, void *value, unsigned long inputLength) {
    instance *inst;
    unsigned int whichopt, newval;
    
    INFN();
    if(!pScanner)
	FAIL(CL_ENULLARG, "NULL pScanner");
    if(!value)
	FAIL(CL_ENULLARG, "NULL value");
    if(lock_instances())
	FAIL(CL_EMEM, "failed to lock instances");

    inst = (instance *)pScanner;
    if(!is_instance(inst)) {
	unlock_instances();
	FAIL(CL_EARG, "invalid instance %p", inst);
    }
    newval = *(unsigned int *)value;
    switch(option) {
	case CLAM_OPTION_SCAN_ARCHIVE:
	    logg("CLAM_OPTION_SCAN_ARCHIVE: %s on instance %p\n", newval ? "enabled" : "disabled", inst);
	    whichopt = CL_SCAN_ARCHIVE;
	    break;
	case CLAM_OPTION_SCAN_MAIL:
	    logg("CLAM_OPTION_SCAN_MAIL: %s on instance %p\n", newval ? "enabled" : "disabled", inst);
	    whichopt = CL_SCAN_MAIL;
	    break;
	case CLAM_OPTION_SCAN_OLE2:
	    logg("CLAM_OPTION_SCAN_OLE2: %s on instance %p\n", newval ? "enabled" : "disabled", inst);
	    whichopt = CL_SCAN_OLE2;
	    break;
	case CLAM_OPTION_SCAN_HTML:
	    logg("CLAM_OPTION_SCAN_HTML: %s on instance %p\n", newval ? "enabled" : "disabled", inst);
	    whichopt = CL_SCAN_HTML;
	    break;
	case CLAM_OPTION_SCAN_PE:
	    logg("CLAM_OPTION_SCAN_PE: %s on instance %p\n", newval ? "enabled" : "disabled", inst);
	    whichopt = CL_SCAN_PE;
	    break;
	case CLAM_OPTION_SCAN_PDF:
	    logg("CLAM_OPTION_SCAN_PDF: %s on instance %p\n", newval ? "enabled" : "disabled", inst);
	    whichopt = CL_SCAN_PDF;
	    break;
	case CLAM_OPTION_SCAN_ALGORITHMIC:
	    logg("CLAM_OPTION_SCAN_ALGORITHMIC: %s on instance %p\n", newval ? "enabled" : "disabled", inst);
	    whichopt = CL_SCAN_ALGORITHMIC;
	    break;
	case CLAM_OPTION_SCAN_ELF:
	    logg("CLAM_OPTION_SCAN_ELF: %s on instance %p\n", newval ? "enabled" : "disabled", inst);
	    whichopt = CL_SCAN_ELF;
	    break;
	default:
	    unlock_instances();
	    FAIL(CL_EARG, "Unsupported option: %d", option);
    }

    if(!newval)
	inst->scanopts &= ~whichopt;
    else
	inst->scanopts |= whichopt;
    unlock_instances();
    WIN();
}

int CLAMAPI Scan_GetOption(CClamAVScanner *pScanner, int option, void *value, unsigned long inputLength, unsigned long *outLength) {
    instance *inst;
    unsigned int whichopt;

    INFN();
    if(!pScanner)
	FAIL(CL_ENULLARG, "NULL pScanner");
    if(!value || !inputLength)
	FAIL(CL_ENULLARG, "NULL value");
    if(lock_instances())
	FAIL(CL_EMEM, "failed to lock instances");

    inst = (instance *)pScanner;
    if(!is_instance(inst)) {
	unlock_instances();
	FAIL(CL_EARG, "invalid instance %p", inst);
    }
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
	    unlock_instances();
	    FAIL(CL_EARG, "Unsupported option: %d", option);
    }

    *(unsigned int *)value = (inst->scanopts & whichopt) != 0;
    unlock_instances();
    WIN();
}

int CLAMAPI Scan_ScanObject(CClamAVScanner *pScanner, const wchar_t *pObjectPath, int *pScanStatus, PCLAM_SCAN_INFO_LIST *pInfoList) {
    HANDLE fhdl;
    int res;
    instance *inst = (instance *)pScanner;

    logg("in Scan_ScanObject(pScanner = %p, pObjectPath = %S)\n", pScanner, pObjectPath);
    if((fhdl = CreateFileW(pObjectPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS, NULL)) == INVALID_HANDLE_VALUE)
	FAIL(CL_EOPEN, "open() failed");

    logg("Scan_ScanObject (instance %p) invoking Scan_ScanObjectByHandle for handle %p (%S)\n", pScanner, fhdl, pObjectPath);
    res = Scan_ScanObjectByHandle(pScanner, fhdl, pScanStatus, pInfoList);
    logg("Scan_ScanObject (instance %p) invoking Scan_ScanObjectByHandle returned %d\n", pScanner, res);
    CloseHandle(fhdl);
    return res;
}

struct scan_ctx {
    int entryfd;
    instance *inst;
};

int CLAMAPI Scan_ScanObjectByHandle(CClamAVScanner *pScanner, HANDLE object, int *pScanStatus, PCLAM_SCAN_INFO_LIST *pInfoList) {
    instance *inst;
    HANDLE duphdl, self;
    char *virname;
    int fd, res;
    unsigned int i;
    struct scan_ctx sctx;
    DWORD perf;

    logg("in Scan_ScanObjectByHandle(pScanner = %p, HANDLE = %p, pScanStatus = %p, pInfoList = %p)\n", pScanner, object, pScanStatus, pInfoList);

    if(!pScanner)
	FAIL(CL_ENULLARG, "NULL pScanner");
    if(!pScanStatus)
	FAIL(CL_ENULLARG, "NULL pScanStatus on instance %p", pScanner);

    self = GetCurrentProcess();
    if(!DuplicateHandle(self, object, self, &duphdl, GENERIC_READ, FALSE, 0))
	FAIL(CL_EDUP, "Duplicate handle failed for instance %p", pScanner);

    if((fd = _open_osfhandle((intptr_t)duphdl, _O_RDONLY)) == -1) {
	CloseHandle(duphdl);
	FAIL(CL_EOPEN, "Open handle failed for instance %p", pScanner);
    }

    if(lock_instances()) {
	close(fd);
	FAIL(CL_EMEM, "failed to lock instances for instance %p", pScanner);
    }
    inst = (instance *)pScanner;
    for(i=0; i<ninsts_total; i++) {
	if(instances[i].inst == inst)
	    break;
    }
    if(i == ninsts_total) {
	unlock_instances();
	close(fd);
	FAIL(CL_EARG, "invalid instance %p", inst);
    }
    instances[i].refcnt++;
    unlock_instances();

    sctx.entryfd = fd;
    sctx.inst = inst;
    logg("Scan_ScanObjectByHandle (instance %p) invoking cl_scandesc with clamav context %p\n", inst, &sctx);
    perf = GetTickCount();
    res = cl_scandesc_callback(fd, &virname, NULL, engine, inst->scanopts, &sctx);
    perf = GetTickCount() - perf;
    close(fd);
    logg("Scan_ScanObjectByHandle (instance %p): cl_scandesc returned %d in %u ms\n", inst, res, perf);

    if(lock_instances())
	FAIL(CL_EMEM, "failed to lock instances for instance %p", pScanner);
    instances[i].refcnt--;
    unlock_instances();

    if(res == CL_VIRUS) {
	logg("Scan_ScanObjectByHandle (instance %p): file is INFECTED with %s\n", inst, virname);
	if(pInfoList) {
	    CLAM_SCAN_INFO_LIST *infolist = calloc(1, sizeof(CLAM_SCAN_INFO_LIST) + sizeof(CLAM_SCAN_INFO) + MAX_VIRNAME_LEN * 2);
	    PCLAM_SCAN_INFO scaninfo;
	    wchar_t *wvirname;
	    if(!infolist)
		FAIL(CL_EMEM, "ScanByHandle (instance %p): OOM while allocating result list", inst);
	    scaninfo = (PCLAM_SCAN_INFO)(infolist + 1);
	    infolist->cbCount = 1;
	    scaninfo->cbSize = sizeof(*scaninfo);
	    scaninfo->scanPhase = SCAN_PHASE_FINAL;
	    scaninfo->errorCode = CLAMAPI_SUCCESS;
	    scaninfo->pThreatType = threat_type(virname);
	    wvirname = (wchar_t *)(scaninfo + 1);
	    scaninfo->pThreatName = wvirname;
	    if(!MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, virname, -1, wvirname, MAX_VIRNAME_LEN))
		scaninfo->pThreatName = L"INFECTED";
	    *pInfoList = infolist;
	    logg("Scan_ScanObjectByHandle (instance %p): created result list %p\n", inst, infolist);
	}
	*pScanStatus = CLAM_INFECTED;
    } else if(res == CL_CLEAN) {
	logg("Scan_ScanObjectByHandle (instance %p): file is CLEAN\n", inst);
        if(pInfoList) *pInfoList = NULL;
	*pScanStatus = CLAM_CLEAN;
    } else {
	FAIL(res, "Scan failed for instance %p: %s", inst, cl_strerror(res));
    }
    WIN();
}


int CLAMAPI Scan_DeleteScanInfo(CClamAVScanner *pScanner, PCLAM_SCAN_INFO_LIST pInfoList) {
    logg("in Scan_DeleteScanInfo(pScanner = %p, pInfoList = %p)\n", pScanner, pInfoList);
    if(!pScanner)
	FAIL(CL_ENULLARG, "NULL pScanner");
    if(!pInfoList)
	FAIL(CL_ENULLARG, "NULL pInfoList");
    /* FIXME checking this is pointelss as the infolist is independent from pscanner */
 //   if(lock_instances())
	//FAIL(CL_EMEM, "failed to lock instances");

 //   inst = (instance *)pScanner;
 //   if(!is_instance(inst)) {
	//unlock_instances();
	//FAIL(CL_EARG, "invalid instance");
 //   }
 //   unlock_instances();

    free(pInfoList);
    WIN();
}

cl_error_t prescan_cb(int fd, void *context) {
    struct scan_ctx *sctx = (struct scan_ctx *)context;
    instance *inst;
    CLAM_SCAN_INFO si;
    CLAM_ACTION act;
    HANDLE fdhdl;
    DWORD perf;
    LONG lo = 0, hi = 0, hi2 = 0;

    if(!context) {
	logg("!prescan_cb called with NULL clamav context\n");
	return CL_CLEAN;
    }
    inst = sctx->inst;
    logg("in prescan_cb with clamav context %p, instance %p, fd %d)\n", context, inst, fd);
    si.cbSize = sizeof(si);
    si.flags = 0;
    si.scanPhase = (fd == sctx->entryfd) ? SCAN_PHASE_INITIAL : SCAN_PHASE_PRESCAN;
    si.errorCode = CLAMAPI_SUCCESS;
    si.pThreatType = NULL;
    si.pThreatName = NULL;
    fdhdl = si.object = (HANDLE)_get_osfhandle(fd);
    si.pInnerObjectPath = NULL;

    lo = SetFilePointer(fdhdl, 0, &hi, FILE_CURRENT);
    SetFilePointer(fdhdl, 0, &hi2, FILE_BEGIN);
    logg("prescan_cb (clamav context %p, instance %p) invoking callback %p with context %p\n", context, inst, inst->scancb, inst->scancb_ctx);
    perf = GetTickCount();
    inst->scancb(&si, &act, inst->scancb_ctx);
    perf = GetTickCount() - perf;
    logg("prescan_cb (clamav context %p, instance %p) callback completed in %u ms\n", context, inst, act);
    SetFilePointer(fdhdl, lo, &hi, FILE_BEGIN);
    switch(act) {
	case CLAM_ACTION_SKIP:
	    logg("prescan_cb (clamav context %p, instance %p) cb result: SKIP\n", context, inst);
	    return CL_BREAK;
	case CLAM_ACTION_ABORT:
	    logg("prescan_cb (clamav context %p, instance %p) cb result: ABORT\n", context, inst);
	    return CL_VIRUS;
	case CLAM_ACTION_CONTINUE:
	    logg("prescan_cb (clamav context %p, instance %p) cb result: CONTINUE\n", context, inst);
	    return CL_CLEAN;
	default:
	    logg("^prescan_cb (clamav context %p, instance %p) cb result: INVALID result %d, assuming continue\n", context, inst, act);
	    return CL_CLEAN;
    }
}

cl_error_t postscan_cb(int fd, int result, const char *virname, void *context) {
    struct scan_ctx *sctx = (struct scan_ctx *)context;
    instance *inst;
    CLAM_SCAN_INFO si;
    CLAM_ACTION act;
    HANDLE fdhdl;
    DWORD perf;
    wchar_t wvirname[MAX_VIRNAME_LEN];
    LONG lo = 0, hi = 0, hi2 = 0;

    if(!context) {
	logg("!postscan_cb called with NULL clamav context\n");
	return CL_CLEAN;
    }
    inst = sctx->inst;
    si.cbSize = sizeof(si);
    si.flags = 0;
    si.scanPhase = (fd == sctx->entryfd) ? SCAN_PHASE_FINAL : SCAN_PHASE_POSTSCAN;
    si.errorCode = CLAMAPI_SUCCESS;
    if(result == CL_VIRUS) {
	if(MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, virname, -1, wvirname, MAX_VIRNAME_LEN))
	    si.pThreatName = wvirname;
	else
	    si.pThreatName = L"INFECTED";
    } else
	    si.pThreatName = NULL;
    logg("in postscan_cb with clamav context %p, instance %p, fd %d, result %d, virusname %S)\n", context, inst, fd, result, si.pThreatName);
    si.pThreatType = threat_type(virname);
    fdhdl = si.object = (HANDLE)_get_osfhandle(fd);
    si.pInnerObjectPath = NULL;
    lo = SetFilePointer(fdhdl, 0, &hi, FILE_CURRENT);
    SetFilePointer(fdhdl, 0, &hi2, FILE_BEGIN);
    logg("postscan_cb (clamav context %p, instance %p) invoking callback %p with context %p\n", context, inst, inst->scancb, inst->scancb_ctx);
    perf = GetTickCount();
    inst->scancb(&si, &act, inst->scancb_ctx);
    perf = GetTickCount() - perf;
    logg("prescan_cb (clamav context %p, instance %p) callback completed in %u ms\n", context, inst, act);
    SetFilePointer(fdhdl, lo, &hi, FILE_BEGIN);
    switch(act) {
	case CLAM_ACTION_SKIP:
	    logg("postscan_cb (clamav context %p, instance %p) cb result: SKIP\n", context, inst);
	    return CL_BREAK;
	case CLAM_ACTION_ABORT:
	    logg("postscan_cb (clamav context %p, instance %p) cb result: ABORT\n", context, inst);
	    return CL_VIRUS;
	case CLAM_ACTION_CONTINUE:
	    logg("postscan_cb (clamav context %p, instance %p) cb result: CONTINUE\n", context, inst);
	    return CL_CLEAN;
	default:
	    logg("^postscan_cb (clamav context %p, instance %p) cb result: INVALID result %d, assuming continue\n", context, inst, act);
	    return CL_CLEAN;
    }
}
