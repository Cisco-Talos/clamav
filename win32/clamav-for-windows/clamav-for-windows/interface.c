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
#include "others.h"
#include "shared/output.h"
#include "mpool.h"
#include "clscanapi.h"
#include "interface.h"

int WINAPI SHCreateDirectoryExA(HWND, LPCTSTR, SECURITY_ATTRIBUTES *); /* cannot include Shlobj.h due to DATADIR collision */

#define FMT(s) "!"__FUNCTION__": "s"\n"
#define FAIL(errcode, fmt, ...) do { logg(FMT(fmt), __VA_ARGS__); return (errcode); } while(0)
#define WIN() do { logg("*%s completed successfully\n", __FUNCTION__); return CLAMAPI_SUCCESS; } while(0)
#define INFN() do { logg("*in %s\n", __FUNCTION__); } while(0)

#define MAX_VIRNAME_LEN 1024

HANDLE reload_event;
volatile LONG reload_waiters = 0;

HANDLE monitor_event;
HANDLE monitor_hdl = NULL;

HANDLE engine_mutex;
/* protects the following items */
struct cl_engine *engine = NULL;
char dbdir[PATH_MAX];
char tmpdir[PATH_MAX];
FILETIME last_chk_time = {0, 0};
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


DWORD WINAPI monitor_thread(VOID *p) {
    char watchme[PATH_MAX];
    HANDLE harr[2], fff;

    if(lock_engine()) {
	logg("^monitor_thread: failed to lock engine\n");
	return 0;
    }

    snprintf(watchme, sizeof(watchme), "%s\\forcerld", dbdir);
    watchme[sizeof(watchme)-1] = '\0';

    harr[0] = monitor_event;
    harr[1] = FindFirstChangeNotification(dbdir, FALSE, FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME);

    unlock_engine();

    if(harr[1] == INVALID_HANDLE_VALUE) {
	logg("^monitor_thread: failed to monitor directory changes on %s\n", dbdir);
	return 0;
    }

    logg("monitor_thread: watching directory changes on %s\n", dbdir);

    while(1) {
	WIN32_FIND_DATA wfd;
	SYSTEMTIME st;

	switch(WaitForMultipleObjects(2, harr, FALSE, INFINITE)) {
	case WAIT_OBJECT_0:
	    logg("*monitor_thread: terminating upon request\n");
	    FindCloseChangeNotification(harr[1]);
	    return 0;
	case WAIT_OBJECT_0 + 1:
	    break;
	default:
	    logg("*monitor_thread: unexpected wait failure - %u\n", GetLastError());
	    Sleep(1000);
	    continue;
	}
	FindNextChangeNotification(harr[1]);
	if((fff = FindFirstFile(watchme, &wfd)) == INVALID_HANDLE_VALUE)
	    continue;
	FindClose(fff);

	GetSystemTime(&st);
	SystemTimeToFileTime(&st, &wfd.ftCreationTime);
	if(CompareFileTime(&wfd.ftLastWriteTime, &wfd.ftCreationTime) > 0)
	    wfd.ftLastWriteTime = wfd.ftCreationTime;
	if(CompareFileTime(&wfd.ftLastWriteTime, &last_chk_time) <= 0)
	    continue;

	logg("monitor_thread: reload requested!\n");
	Scan_ReloadDatabase();
	GetSystemTime(&st);
	SystemTimeToFileTime(&st, &last_chk_time); /* FIXME: small race here */
    }
}

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
	logg("*add_instance: instances grown to %u\n", ninsts_total);
    }
    for(i=0; i<ninsts_total; i++) {
	if(instances[i].inst)
	    continue;
	instances[i].inst = inst;
	instances[i].refcnt = 0;
	ninsts_avail--;
	logg("*add_instance: now %u/%u instances available\n", ninsts_avail, ninsts_total);
	unlock_instances();
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
	return CL_ELOCK;
    }
    for(i=0; i<ninsts_total; i++) {
	if(instances[i].inst != inst)
	    continue;
	if(instances[i].refcnt) {
	    logg("^del_instance: attempted to free instance with %d active scanners\n", instances[i].refcnt);
	    unlock_instances();
	    return CL_EBUSY;
	}
	instances[i].inst = NULL;
	instances[i].refcnt = 0;
	ninsts_avail++;
	logg("*del_instance: %u / %u instances now available\n", ninsts_avail, ninsts_total);
	unlock_instances();
	return CL_SUCCESS;
    }
    logg("!del_instances: instance %p not found\n", inst);
    unlock_instances();
    return CL_EARG;
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
    if(!(reload_event = CreateEvent(NULL, TRUE, TRUE, NULL))) {
	CloseHandle(engine_mutex);
	return FALSE;
    }
    if(!(monitor_event = CreateEvent(NULL, TRUE, FALSE, NULL))) {
	CloseHandle(reload_event);
	CloseHandle(engine_mutex);
	return FALSE;
    }
    if(!(instance_mutex = CreateMutex(NULL, FALSE, NULL))) {
	CloseHandle(monitor_event);
	CloseHandle(reload_event);
	CloseHandle(engine_mutex);
	return FALSE;
    }
    return TRUE;
}

static int sigload_callback(const char *type, const char *name, void *context) {
    if(minimal_definitions && strcmp(type, "fp"))
	return 1;
    return 0;
}

const char* cli_ctime(const time_t *timep, char *buf, const size_t bufsize);
/* Must be called with engine_mutex locked ! */
static void touch_last_update(unsigned signo) {
    char touchme[PATH_MAX];
    HANDLE h;

    snprintf(touchme, sizeof(touchme), "%s\\lastupd", dbdir);
    touchme[sizeof(touchme)-1] = '\0';
    if((h = CreateFile(touchme, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE) {
	DWORD d;
	int err;
	unsigned ver = (unsigned)cl_engine_get_num(engine, CL_ENGINE_DB_VERSION, &err);
	if (ver) {
	    char timestr[32];
	    const char *tstr;
	    time_t t;
	    t = cl_engine_get_num(engine, CL_ENGINE_DB_TIME, NULL);
	    tstr = cli_ctime(&t, timestr, sizeof(timestr));
	    /* cut trailing \n */
	    timestr[strlen(tstr)-1] = '\0';
	    snprintf(touchme, sizeof(touchme), "daily %u/%u sigs\n"
		     "Database version: %u/%s\n"
		     "Known viruses: %u\n"
		     "Reloaded at: %d\n",
		     ver, signo, ver, tstr, signo, (unsigned)time(NULL));
	} else {
	    snprintf(touchme, sizeof(touchme), "no daily/%u sigs\n"
		     "Known viruses: %u\n"
		     "Reloaded at: %d\n",
		     signo, signo, (unsigned)time(NULL));
	}
	touchme[sizeof(touchme)-1] = '\0';
	if(WriteFile(h, touchme, strlen(touchme), &d, NULL)) {
	    /* SetEndOfFile(h); */
	    GetFileTime(h, NULL, NULL, &last_chk_time);
	}
	CloseHandle(h);
    } else
	logg("^touch_last_lastcheck: failed to touch lastreload\n");
}


/* Must be called with engine_mutex locked ! */
static int load_db(void) {
    unsigned int signo = 0;
    size_t used, total;
    int ret;


    INFN();

    cl_engine_set_clcb_sigload(engine, sigload_callback, NULL);
    if((ret = cl_load(dbdir, engine, &signo, CL_DB_STDOPT & ~CL_DB_PHISHING & ~CL_DB_PHISHING_URLS)) != CL_SUCCESS) {
	cl_engine_free(engine);
	engine = NULL;
	FAIL(ret, "Failed to load database: %s", cl_strerror(ret));
    }

    if((ret = cl_engine_compile(engine))) {
	cl_engine_free(engine);
	engine = NULL;
	FAIL(ret, "Failed to compile engine: %s", cl_strerror(ret));
    }

    logg("load_db: loaded %d signatures\n", signo);
    if (!mpool_getstats(engine, &used, &total))
	logg("load_db: memory %.3f MB / %.3f MB\n", used/(1024*1024.0), total/(1024*1024.0));

    touch_last_update(signo);

    WIN();
}

static void free_engine_and_unlock(void) {
    cl_engine_free(engine);
    engine = NULL;
    unlock_engine();
}

int CLAMAPI Scan_Initialize(const wchar_t *pEnginesFolder, const wchar_t *pTempRoot, const wchar_t *pLicenseKey, BOOL bLoadMinDefs) {
    BOOL cant_convert;
    int ret;

    logg("*in Scan_Initialize(pEnginesFolder = %S, pTempRoot = %S)\n", pEnginesFolder, pTempRoot);
    if(!pEnginesFolder)
	FAIL(CL_ENULLARG, "pEnginesFolder is NULL");
    if(!pTempRoot)
	FAIL(CL_ENULLARG, "pTempRoot is NULL");
    if(lock_engine())
	FAIL(CL_ELOCK, "failed to lock engine");
    if(engine) {
	unlock_engine();
	FAIL(CL_ESTATE, "Already initialized");
    }

    if(!(engine = cl_engine_new())) {
	unlock_engine();
	FAIL(CL_EMEM, "Not enough memory for a new engine");
    }
    cl_engine_set_clcb_pre_scan(engine, prescan_cb);
    cl_engine_set_clcb_post_scan(engine, postscan_cb);
    
    minimal_definitions = bLoadMinDefs;
    if(bLoadMinDefs)
	logg("^MINIMAL DEFINITIONS MODE ON!\n");

    if(!WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, pTempRoot, -1, tmpdir, sizeof(tmpdir), NULL, &cant_convert) || cant_convert) {
	free_engine_and_unlock();
	FAIL(CL_EARG, "Can't translate pTempRoot");
    }
    ret = strlen(tmpdir);
    while(ret>0 && tmpdir[--ret] == '\\')
	tmpdir[ret] = '\0';
    if(!ret || ret + 8 + 1 >= sizeof(tmpdir)) {
	free_engine_and_unlock();
	FAIL(CL_EARG, "Bad or too long pTempRoot '%s'", tmpdir);
    }
    memcpy(&tmpdir[ret+1], "\\clamtmp", 9);
    cli_rmdirs(tmpdir);
    if((ret = SHCreateDirectoryExA(NULL, tmpdir, NULL) != ERROR_SUCCESS) && ret != ERROR_ALREADY_EXISTS) {
	free_engine_and_unlock();
	FAIL(CL_ETMPDIR, "Cannot create pTempRoot '%s': error %d", tmpdir, ret);
    }
    if((ret = cl_engine_set_str(engine, CL_ENGINE_TMPDIR, tmpdir))) {
	free_engine_and_unlock();
	FAIL(ret, "Failed to set engine tempdir to '%s': %s", tmpdir, cl_strerror(ret));
    }
    if(!WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, pEnginesFolder, -1, dbdir, sizeof(dbdir), NULL, &cant_convert) || cant_convert) {
	free_engine_and_unlock();
	FAIL(CL_EARG, "Can't translate pEnginesFolder");
    }
    ret = load_db();
    unlock_engine();

    if(!ret) {
	ResetEvent(monitor_event);
	if(!(monitor_hdl = CreateThread(NULL, 0, monitor_thread, NULL, 0, NULL)))
	    logg("^Failed to start db monitoring thread\n");
    }

    logg("*Scan_Initialize: returning %d\n", ret);
    return ret;
}

int uninitialize_called = 0;
int CLAMAPI Scan_Uninitialize(void) {
 //   int rett;
 //   __asm {
	//MOV eax, [ebp + 4]
	//mov rett, eax
 //   }
 //   logg("%x", rett);
    uninitialize_called = 1;
    INFN();

    if(monitor_hdl) {
	SetEvent(monitor_event);
	if(WaitForSingleObject(monitor_hdl, 5000) != WAIT_OBJECT_0) {
	    logg("^Scan_Uninitialize: forcibly terminating monitor thread after 5 seconds\n");
	    TerminateThread(monitor_hdl, 0);
	}
    }
    monitor_hdl = NULL;

    if(lock_engine())
	FAIL(CL_ELOCK, "failed to lock engine");
    if(!engine) {
	unlock_engine();
	FAIL(CL_ESTATE, "attempted to uninit a NULL engine");
    }

    if(lock_instances()) {
	unlock_engine();
	FAIL(CL_ELOCK, "failed to lock instances");
    }
    if(ninsts_avail != ninsts_total) {
	volatile unsigned int refcnt = ninsts_total - ninsts_avail;
	unlock_instances();
	unlock_engine();
	FAIL(CL_EBUSY, "Attempted to uninit the engine with %u active instances", refcnt);
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
	FAIL(CL_ELOCK, "Failed to lock engine");
    }
    if(!engine) {
	free(inst);
	unlock_engine();
	FAIL(CL_ESTATE, "Create instance called with no engine");
    }
    if(add_instance(inst)) {
	free(inst);
	unlock_engine();
	FAIL(CL_EMEM, "add_instance failed");
    }
    unlock_engine();
    inst->scanopts = CL_SCAN_STDOPT | CL_SCAN_PERFORMANCE_INFO;
    *ppScanner = (CClamAVScanner *)inst;
    logg("Created new instance %p\n", inst);
    WIN();
}

// Caller: if we return error will retry once after 2 seconds.
// No point in retrying more times since we are shutting down anyway.
int CLAMAPI Scan_DestroyInstance(CClamAVScanner *pScanner) {
    int rc;
    INFN();
    if(!pScanner)
	FAIL(CL_ENULLARG, "NULL pScanner");
    if((rc = del_instance((instance *)pScanner))) {
	if (rc == CL_EBUSY) {
	    // wait for one of the scanner threads to finish, and retry again,
	    // thats better than caller always waiting 2 seconds to retry.
	    if (WaitForSingleObject(reload_event, 1000) != WAIT_OBJECT_0)
		logg("Scan_DestroyInstance: timeout");
	    rc = del_instance((instance *)pScanner);
	}
	if (rc)
	    FAIL(rc, "del_instance failed for %p", pScanner);
    }
    free(pScanner);
    logg("in Scan_DestroyInstance: Instance %p destroyed\n", pScanner);
    WIN();
}

int CLAMAPI Scan_SetScanCallback(CClamAVScanner *pScanner, CLAM_SCAN_CALLBACK pfnCallback, void *pContext) {
    instance *inst;

    logg("*in SetScanCallback(pScanner = %p, pfnCallback = %p, pContext = %p)\n", pScanner, pfnCallback, pContext);
    if(!pScanner)
	FAIL(CL_ENULLARG, "NULL pScanner");
    if(lock_instances())
	FAIL(CL_ELOCK, "failed to lock instances for instance %p", pScanner);

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
	FAIL(CL_ELOCK, "failed to lock instances");

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
	FAIL(CL_ELOCK, "failed to lock instances");

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


int CLAMAPI Scan_GetLimit(int option, unsigned int *value) {
    enum cl_engine_field limit;
    long long curlimit;
    int err;

    INFN();
    if(lock_engine())
	FAIL(CL_ELOCK, "Failed to lock engine");
    if(!engine) {
	unlock_engine();
	FAIL(CL_ESTATE, "Engine is NULL");
    }
    switch((enum CLAM_LIMIT_TYPE)option) {
    case CLAM_LIMIT_FILESIZE:
	limit = CL_ENGINE_MAX_FILESIZE;
	break;
    case CLAM_LIMIT_SCANSIZE:
	limit = CL_ENGINE_MAX_SCANSIZE;
	break;
    case CLAM_LIMIT_RECURSION:
	limit = CL_ENGINE_MAX_SCANSIZE;
	break;
    default:
	unlock_engine();
	FAIL(CL_EARG, "Unsupported limit type: %d", option);
    }
    curlimit = cl_engine_get_num(engine, limit, &err);
    if(err) {
	unlock_engine();
	FAIL(err, "Failed to get engine value: %s", cl_strerror(err));
    }
    if(curlimit > 0xffffffff)
	*value = 0xffffffff;
    else
	*value = (unsigned int)curlimit;
    unlock_engine();
    WIN();
}


int CLAMAPI Scan_SetLimit(int option, unsigned int value) {
    enum cl_engine_field limit;
    int err;

    INFN();
    if(lock_engine())
	FAIL(CL_ELOCK, "Failed to lock engine");
    if(!engine) {
	unlock_engine();
	FAIL(CL_ESTATE, "Engine is NULL");
    }
    switch((enum CLAM_LIMIT_TYPE)option) {
    case CLAM_LIMIT_FILESIZE:
	logg("CLAM_LIMIT_FILESIZE: set to %u\n", value);
	limit = CL_ENGINE_MAX_FILESIZE;
	break;
    case CLAM_LIMIT_SCANSIZE:
	logg("CLAM_LIMIT_SCANSIZE: set to %u\n", value);
	limit = CL_ENGINE_MAX_SCANSIZE;
	break;
    case CLAM_LIMIT_RECURSION:
	logg("CLAM_LIMIT_RECURSION: set to %u\n", value);
	limit = CL_ENGINE_MAX_SCANSIZE;
	break;
    default:
	unlock_engine();
	FAIL(CL_EARG, "Unsupported limit type: %d", option);
    }
    err = cl_engine_set_num(engine, limit, (long long)value);
    unlock_engine();
    if(err)
	FAIL(err, "Failed to set engine value: %s", cl_strerror(err));
    WIN();
}


static wchar_t *uncpathw(const wchar_t *path) {
    DWORD len = 0;
    unsigned int pathlen;
    wchar_t *stripme, *strip_from, *dest = malloc((PATH_MAX + 1) * sizeof(wchar_t));

    if(!dest)
	return NULL;

    pathlen = wcslen(path);
    if(wcsncmp(path, L"\\\\", 2)) {
	/* NOT already UNC */
	memcpy(dest, L"\\\\?\\", 8);
	if(pathlen < 2 || path[1] != L':' || *path < L'A' || *path > L'z' || (*path > L'Z' && *path < L'a')) {
	    /* Relative path */
	    len = GetCurrentDirectoryW(PATH_MAX - 5, &dest[4]);
	    if(!len || len > PATH_MAX - 5) {
		free(dest);
		return NULL;
	    }
	    if(*path == L'\\')
		len = 6; /* Current drive root */
	    else {
		len += 4; /* A 'really' relative path */
		dest[len] = L'\\';
		len++;
	    }
	} else {
	    /* C:\ and friends */
	    len = 4;
	}
    } else {
	/* UNC already */
	len = 0;
    }

    if(pathlen >= PATH_MAX - len) {
	free(dest);
        return NULL;
    }
    wcscpy(&dest[len], path);
    len = wcslen(dest);
    strip_from = &dest[3];
    /* append a backslash to naked drives and get rid of . and .. */
    if(!wcsncmp(dest, L"\\\\?\\", 4) && (dest[5] == L':') && ((dest[4] >= L'A' && dest[4] <= L'Z') || (dest[4] >= L'a' && dest[4] <= L'z'))) {
	if(len == 6) {
	    dest[6] = L'\\';
	    dest[7] = L'\0';
	}
	strip_from = &dest[6];
    }
    while((stripme = wcsstr(strip_from, L"\\."))) {
	wchar_t *copy_from, *copy_to;
	if(!stripme[2] || stripme[2] == L'\\') {
	    copy_from = &stripme[2];
	    copy_to = stripme;
	} else if (stripme[2] == L'.' && (!stripme[3] || stripme[3] == L'\\')) {
	    *stripme = L'\0';
	    copy_from = &stripme[3];
	    copy_to = wcsrchr(strip_from, L'\\');
	    if(!copy_to)
		copy_to = stripme;
	} else {
	    strip_from = &stripme[1];
	    continue;
	}
	while(1) {
	    *copy_to = *copy_from;
	    if(!*copy_from) break;
	    copy_to++;
	    copy_from++;
	}
    }

    /* strip double slashes */
    if((stripme = wcsstr(&dest[4], L"\\\\"))) {
	strip_from = stripme;
	while(1) {
	    wchar_t c = *strip_from;
	    strip_from++;
	    if(c == L'\\' && *strip_from == L'\\')
		continue;
	    *stripme = c;
	    stripme++;
	    if(!c)
		break;
	}
    }
    if(wcslen(dest) == 6 && !wcsncmp(dest, L"\\\\?\\", 4) && (dest[5] == L':') && ((dest[4] >= L'A' && dest[4] <= L'Z') || (dest[4] >= L'a' && dest[4] <= L'z'))) {
	dest[6] = L'\\';
	dest[7] = L'\0';
    }
    return dest;
}


int CLAMAPI Scan_ScanObject(CClamAVScanner *pScanner, const wchar_t *pObjectPath, int *pScanStatus, PCLAM_SCAN_INFO_LIST *pInfoList) {
    HANDLE fhdl;
    int res;
    instance *inst = (instance *)pScanner;

    logg("*in Scan_ScanObject(pScanner = %p, pObjectPath = %S)\n", pScanner, pObjectPath);
    if((fhdl = CreateFileW(pObjectPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS, NULL)) == INVALID_HANDLE_VALUE) {
	wchar_t *uncfname = uncpathw(pObjectPath);
	if(!uncfname)
	    FAIL(CL_EMEM, "uncpathw() failed");
	fhdl = CreateFileW(uncfname, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS, NULL);
	logg("*Scan_ScanObject translating '%S' to '%S'\n", pObjectPath, uncfname);
	free(uncfname);
	if(fhdl == INVALID_HANDLE_VALUE)
	    FAIL(CL_EOPEN, "open() failed");
    }
    logg("*Scan_ScanObject (instance %p) invoking Scan_ScanObjectByHandle for handle %p (%S)\n", pScanner, fhdl, pObjectPath);
    res = Scan_ScanObjectByHandle(pScanner, fhdl, pScanStatus, pInfoList);
    logg("*Scan_ScanObject (instance %p) invoking Scan_ScanObjectByHandle returned %d\n", pScanner, res);
    CloseHandle(fhdl);
    return res;
}

struct scan_ctx {
    int entryfd;
    instance *inst;
    DWORD cb_times;
    DWORD copy_times;
};

int CLAMAPI Scan_ScanObjectByHandle(CClamAVScanner *pScanner, HANDLE object, int *pScanStatus, PCLAM_SCAN_INFO_LIST *pInfoList) {
    instance *inst;
    HANDLE duphdl, self;
    char *virname = NULL;
    int fd, res;
    unsigned int i;
    struct scan_ctx sctx;
    DWORD perf;

    logg("*in Scan_ScanObjectByHandle(pScanner = %p, HANDLE = %p, pScanStatus = %p, pInfoList = %p)\n", pScanner, object, pScanStatus, pInfoList);

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
	FAIL(CL_ELOCK, "failed to lock instances for instance %p", pScanner);
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
    ResetEvent(reload_event);
    unlock_instances();

    sctx.entryfd = fd;
    sctx.inst = inst;
    sctx.cb_times = 0;
    sctx.copy_times = 0;
    logg("*Scan_ScanObjectByHandle (instance %p) invoking cl_scandesc with clamav context %p\n", inst, &sctx);
    perf = GetTickCount();
    res = cl_scandesc_callback(fd, &virname, NULL, engine, inst->scanopts, &sctx);

    do {
	CLAM_SCAN_INFO si;
	CLAM_ACTION act;
	DWORD cbperf;
	wchar_t wvirname[MAX_VIRNAME_LEN] = L"Clam.";
	LONG lo = 0, hi = 0, hi2 = 0;

	si.cbSize = sizeof(si);
	si.flags = 0;
	si.scanPhase = SCAN_PHASE_FINAL;
	si.errorCode = CLAMAPI_SUCCESS;
	if(res == CL_VIRUS) {
	    if(MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, virname, -1, &wvirname[5], MAX_VIRNAME_LEN - 5))
		si.pThreatName = wvirname;
	    else
		si.pThreatName = L"Clam.UNOFFICIAL";
	} else
	    si.pThreatName = NULL;
	logg("*in final_cb with clamav context %p, instance %p, fd %d, result %d, virusname %S)\n", &sctx, inst, fd, res, si.pThreatName);
	si.pThreatType = threat_type(virname);
	si.object = INVALID_HANDLE_VALUE;
	si.objectId = INVALID_HANDLE_VALUE;
	si.pInnerObjectPath = NULL;
	lo = SetFilePointer(duphdl, 0, &hi, FILE_CURRENT);
	SetFilePointer(duphdl, 0, &hi2, FILE_BEGIN);
	logg("*final_cb (clamav context %p, instance %p) invoking callback %p with context %p\n", &sctx, inst, inst->scancb, inst->scancb_ctx);
	cbperf = GetTickCount();
	inst->scancb(&si, &act, inst->scancb_ctx);
	cbperf = GetTickCount() - cbperf;
	sctx.cb_times += cbperf;
	logg("*final_cb (clamav context %p, instance %p) callback completed with %u (result ignored) in %u ms\n", &sctx, inst, act, cbperf);
	SetFilePointer(duphdl, lo, &hi, FILE_BEGIN);
    } while(0);

    perf = GetTickCount() - perf;
    close(fd);
    logg("*Scan_ScanObjectByHandle (instance %p): cl_scandesc returned %d in %u ms (%d ms own, %d ms copy)\n", inst, res, perf, perf - sctx.cb_times - sctx.copy_times, sctx.copy_times);

    if(lock_instances())
	FAIL(CL_ELOCK, "failed to lock instances for instance %p", pScanner);
    instances[i].refcnt--;
    if(!instances[i].refcnt)
	SetEvent(reload_event);
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
	    scaninfo->object = INVALID_HANDLE_VALUE;
	    scaninfo->objectId = INVALID_HANDLE_VALUE;
	    wvirname = (wchar_t *)(scaninfo + 1);
	    scaninfo->pThreatName = wvirname;
	    memcpy(wvirname, L"Clam.", 10);
	    if(!MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, virname, -1, &wvirname[5], MAX_VIRNAME_LEN-5))
		scaninfo->pThreatName = L"Clam.UNOFFICIAL";
	    *pInfoList = infolist;
	    logg("*Scan_ScanObjectByHandle (instance %p): created result list %p\n", inst, infolist);
	}
	*pScanStatus = CLAM_INFECTED;
    } else if(res == CL_CLEAN) {
	logg("*Scan_ScanObjectByHandle (instance %p): file is CLEAN\n", inst);
        if(pInfoList) *pInfoList = NULL;
	*pScanStatus = CLAM_CLEAN;
    } else {
	FAIL(res, "Scan failed for instance %p: %s", inst, cl_strerror(res));
    }
    WIN();
}


int CLAMAPI Scan_DeleteScanInfo(CClamAVScanner *pScanner, PCLAM_SCAN_INFO_LIST pInfoList) {
    logg("*in Scan_DeleteScanInfo(pScanner = %p, pInfoList = %p)\n", pScanner, pInfoList);
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
    char tmpf[4096];
    instance *inst;
    CLAM_SCAN_INFO si;
    CLAM_ACTION act;
    HANDLE fdhdl;
    DWORD perf, perf2 = 0;

    if(!context) {
	logg("!prescan_cb called with NULL clamav context\n");
	return CL_CLEAN;
    }
    inst = sctx->inst;
    logg("*in prescan_cb with clamav context %p, instance %p, fd %d)\n", context, inst, fd);
    si.cbSize = sizeof(si);
    si.flags = 0;
    si.scanPhase = (fd == sctx->entryfd) ? SCAN_PHASE_INITIAL : SCAN_PHASE_PRESCAN;
    si.errorCode = CLAMAPI_SUCCESS;
    si.pThreatType = NULL;
    si.pThreatName = NULL;
    si.pInnerObjectPath = NULL;

    if(si.scanPhase == SCAN_PHASE_PRESCAN) {
	long fpos;
	int rsz;
	perf2 = GetTickCount();
	while(1) {
	    static int tmpn;
	    snprintf(tmpf, sizeof(tmpf), "%s\\%08x.tmp", tmpdir, ++tmpn);
	    tmpf[sizeof(tmpf)-1] = '\0';
	    fdhdl = CreateFile(tmpf, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
	    if(fdhdl != INVALID_HANDLE_VALUE) {
		logg("*prescan_cb: dumping content to tempfile %s (handle %p)\n", tmpf, fdhdl);
		break;
	    }
	    if((perf = GetLastError()) != ERROR_FILE_EXISTS) {
		logg("!prescan_cb: failed to create tempfile %s - error %u\n", tmpf, perf);
		return CL_CLEAN;
	    }
	}

	fpos = lseek(fd, 0, SEEK_CUR);
	lseek(fd, 0, SEEK_SET);
	while((rsz = read(fd, tmpf, sizeof(tmpf))) > 0) {
	    int wsz = 0;
	    while(wsz != rsz) {
		DWORD rwsz;
		if(!WriteFile(fdhdl, &tmpf[wsz], rsz - wsz, &rwsz, NULL)) {
		    logg("!prescan_cb: failed to write to tempfile %s - error %u\n", GetLastError());
		    lseek(fd, fpos, SEEK_SET);
		    CloseHandle(fdhdl);
		    return CL_CLEAN;
		}
		wsz += rwsz;
	    }
	}
	if(rsz) {
	    logg("!prescan_cb: failed to read from clamav tempfile - errno = %d\n", errno);
	    lseek(fd, fpos, SEEK_SET);
	    CloseHandle(fdhdl);
	    return CL_CLEAN;
	}
	lseek(fd, fpos, SEEK_SET);
	SetFilePointer(fdhdl, 0, NULL, FILE_BEGIN);
	si.object = fdhdl;
	si.objectId = (HANDLE)_get_osfhandle(fd);
	perf2 = GetTickCount() - perf2;
	sctx->copy_times += perf2;
    } else { /* SCAN_PHASE_INITIAL */
	si.object = INVALID_HANDLE_VALUE;
	si.objectId = INVALID_HANDLE_VALUE;
    }
    logg("*prescan_cb (clamav context %p, instance %p) invoking callback %p with context %p\n", context, inst, inst->scancb, inst->scancb_ctx);
    perf = GetTickCount();
    inst->scancb(&si, &act, inst->scancb_ctx);
    perf = GetTickCount() - perf;
    sctx->cb_times += perf;
    logg("*prescan_cb (clamav context %p, instance %p) callback completed with %u in %u + %u ms\n", context, inst, act, perf, perf2);
    switch(act) {
	case CLAM_ACTION_SKIP:
	    logg("*prescan_cb (clamav context %p, instance %p) cb result: SKIP\n", context, inst);
	    return CL_BREAK;
	case CLAM_ACTION_ABORT:
	    logg("*prescan_cb (clamav context %p, instance %p) cb result: ABORT\n", context, inst);
	    return CL_VIRUS;
	case CLAM_ACTION_CONTINUE:
	    logg("*prescan_cb (clamav context %p, instance %p) cb result: CONTINUE\n", context, inst);
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
    DWORD perf;
    wchar_t wvirname[MAX_VIRNAME_LEN] = L"Clam.";

    if(!context) {
	logg("!postscan_cb called with NULL clamav context\n");
	return CL_CLEAN;
    }
    if(fd == sctx->entryfd)
	return CL_CLEAN; /* Moved to after cl_scandesc returns due to heuristic results not being yet set in magicscan */

    inst = sctx->inst;
    si.cbSize = sizeof(si);
    si.flags = 0;
    si.scanPhase = SCAN_PHASE_POSTSCAN;
    si.errorCode = CLAMAPI_SUCCESS;
    if(result == CL_VIRUS) {
	if(MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, virname, -1, &wvirname[5], MAX_VIRNAME_LEN-5))
	    si.pThreatName = wvirname;
	else
	    si.pThreatName = L"Clam.UNOFFICIAL";
    } else
	    si.pThreatName = NULL;
    logg("*in postscan_cb with clamav context %p, instance %p, fd %d, result %d, virusname %S)\n", context, inst, fd, result, si.pThreatName);
    si.pThreatType = threat_type(virname);
    si.objectId = (HANDLE)_get_osfhandle(fd);
    si.object = INVALID_HANDLE_VALUE;
    si.pInnerObjectPath = NULL;
    logg("*postscan_cb (clamav context %p, instance %p) invoking callback %p with context %p\n", context, inst, inst->scancb, inst->scancb_ctx);
    perf = GetTickCount();
    inst->scancb(&si, &act, inst->scancb_ctx);
    perf = GetTickCount() - perf;
    sctx->cb_times += perf;
    logg("*postscan_cb (clamav context %p, instance %p) callback completed with %u in %u ms\n", context, inst, act, perf);
    switch(act) {
	case CLAM_ACTION_SKIP:
	    logg("*postscan_cb (clamav context %p, instance %p) cb result: SKIP\n", context, inst);
	    return CL_BREAK;
	case CLAM_ACTION_ABORT:
	    logg("*postscan_cb (clamav context %p, instance %p) cb result: ABORT\n", context, inst);
	    return CL_VIRUS;
	case CLAM_ACTION_CONTINUE:
	    logg("*postscan_cb (clamav context %p, instance %p) cb result: CONTINUE\n", context, inst);
	    return CL_CLEAN;
	default:
	    logg("^postscan_cb (clamav context %p, instance %p) cb result: INVALID result %d, assuming continue\n", context, inst, act);
	    return CL_CLEAN;
    }
}

CLAMAPI void Scan_ReloadDatabase(void) {
    if(InterlockedIncrement(&reload_waiters)==1) {
	int reload_ok = 0;
	logg("*Scan_ReloadDatabase: Database reload requested received, waiting for idle state\n");
	while(1) {
	    unsigned int i;
	    struct cl_settings *settings;

	    if(WaitForSingleObject(reload_event, INFINITE) == WAIT_FAILED) {
		logg("!Scan_ReloadDatabase: failed to wait on reload event\n");
		continue;
	    }
	    logg("*Scan_ReloadDatabase: Now idle, acquiring engine lock\n");
	    if(lock_engine()) {
		logg("!Scan_ReloadDatabase: failed to lock engine\n");
		break;
	    }
	    if(!engine) {
		logg("!Scan_ReloadDatabase: engine is NULL\n");
		unlock_engine();
		break;
	    }
	    logg("*Scan_ReloadDatabase: Engine locked, acquiring instance lock\n");
	    if(lock_instances()) {
		logg("!Scan_ReloadDatabase: failed to lock instances\n");
		unlock_engine();
		break;
	    }
            for(i=0; i<ninsts_total; i++) {
		if(instances[i].inst && instances[i].refcnt)
		    break;
	    }
	    if(i!=ninsts_total) {
		logg("Scan_ScanObjectByHandle: some instances are still in use\n");
		ResetEvent(reload_event);
		unlock_instances();
		unlock_engine();
		continue;
	    }
	    settings = cl_engine_settings_copy(engine);
	    if (!settings) {
		logg("!Scan_ReloadDatabase: Not enough memory for engine settings\n");
		unlock_instances();
		unlock_engine();
		break;
	    }

	    logg("Scan_ReloadDatabase: Destroying old engine\n");
	    cl_engine_free(engine);
	    logg("Scan_ReloadDatabase: Loading new engine\n");

	    // NEW STUFF //
	    if(!(engine = cl_engine_new())) {
		logg("!Scan_ReloadDatabase: Not enough memory for a new engine\n");
		unlock_instances();
		unlock_engine();
		break;
	    }
	    cl_engine_settings_apply(engine, settings);
	    cl_engine_settings_free(settings);

	    load_db(); /* FIXME: FIAL? */
	    unlock_instances();
	    unlock_engine();
	    reload_ok = 1;
	    break;
	}
	if(reload_ok)
	    logg("Scan_ReloadDatabase: Database successfully reloaded\n");
	else
	    logg("!Scan_ReloadDatabase: Database reload failed\n");
    } else
	logg("*Database reload requested received while reload is pending\n");
    InterlockedDecrement(&reload_waiters);
}

void msg_callback(enum cl_msg severity, const char *fullmsg, const char *msg, void *ctx)
{
    struct scan_ctx *sctx = (struct scan_ctx*)ctx;
    const void *instance = sctx ? sctx->inst : NULL;
    int fd = sctx ? sctx->entryfd : -1;
    char sv;
    switch (severity) {
	case CL_MSG_ERROR:
	    sv = '!';
	    break;
	case CL_MSG_WARN:
	    sv = '^';
	    break;
	default:
	    sv = '*';
	    break;
    }

    logg("%c[LibClamAV] (instance %p, clamav context %p, fd %d): %s",
	 sv, instance, sctx, fd, msg);
}
