/*
 * Copyright (c) 2007 by Apple Computer, Inc., All Rights Reserved.
 * Copyright (c) 2011 Sourcefire, Inc.
 */

#include <kern/assert.h>
#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <libkern/OSAtomic.h>
#include <libkern/OSMalloc.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/kauth.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/conf.h>
#include <miscfs/devfs/devfs.h>

#pragma mark ***** Global Resources
/* These declarations are required to allocate memory and create locks.
 * They're created when we start and destroyed when we stop.
 */

static OSMallocTag  gMallocTag = NULL;
static lck_grp_t *  gLockGroup = NULL;

#define CLAMAUTH_EVENTS (KAUTH_VNODE_EXECUTE)

struct AuthEvent {
    UInt32 pid;
    UInt32 action;
    char path[MAXPATHLEN + 1];
};

#define EVENTQSIZE 64

struct AuthEventQueue {
    struct AuthEvent queue[EVENTQSIZE];
    int cnt, first, last;
};

void AuthEventInitQueue(struct AuthEventQueue *queue);
void AuthEventEnqueue(struct AuthEventQueue *queue, struct AuthEvent *event);
int AuthEventDequeue(struct AuthEventQueue *queue, struct AuthEvent *event);

void AuthEventInitQueue(struct AuthEventQueue *queue)
{
    memset(queue, 0, sizeof(struct AuthEventQueue));
    queue->first = queue->cnt = 0;
    queue->last = EVENTQSIZE - 1;
}

void AuthEventEnqueue(struct AuthEventQueue *queue, struct AuthEvent *event)
{
    queue->last = (queue->last + 1) % EVENTQSIZE;
    memcpy(&queue->queue[queue->last], event, sizeof(struct AuthEvent));
    queue->cnt++;
}

int AuthEventDequeue(struct AuthEventQueue *queue, struct AuthEvent *event)
{
    if(!queue->cnt)
        return 1;
    memcpy(event, &queue->queue[queue->first], sizeof(struct AuthEvent));
    queue->first = (queue->first + 1) % EVENTQSIZE;
    queue->cnt--;
    return 0;
}

struct AuthEventQueue gEventQueue;
static lck_mtx_t *gEventQueueLock = NULL;
static SInt32 gEventCount = 0;

static int CreateVnodePath(vnode_t vp, char **vpPathPtr)
    /* Creates a full path for a vnode.  vp may be NULL, in which 
     * case the returned path is NULL (that is, no memory is allocated).
     * vpPathPtr is a place to store the allocated path buffer.  
     * The caller is responsible for freeing this memory using OSFree 
     * (the size is always MAXPATHLEN).
     */
{
    int             err;
    int             pathLen;

    assert( vpPathPtr != NULL);
    assert(*vpPathPtr == NULL);
    
    err = 0;
    if (vp != NULL) {
        *vpPathPtr = OSMalloc(MAXPATHLEN, gMallocTag);
        if (*vpPathPtr == NULL) {
            err = ENOMEM;
        }
        if (err == 0) {
            pathLen = MAXPATHLEN;
            err = vn_getpath(vp, *vpPathPtr, &pathLen);
        }
    }
    
    return err;
}

#pragma mark ***** Listener Resources

/* Some scopes (for example KAUTH_SCOPE_VNODE) are called a /lot/.  Thus, 
 * it's a good idea to avoid taking mutexes in your listener if at all 
 * possible.  Thus, we use non-blocking synchronisation to protect the 
 * global data that's accessed by our listener (gPrefix and gListenerScope).  
 * Every time we enter a listener, we increment gActivationCount, and ever 
 * time we leave we decrement it.  When we want to change the listener, we 
 * first remove the listener, then we wait for the activation count to hit, 
 * then we can modify the globals protected by that activation count.
 *
 * IMPORTANT:
 * There is still a race condition here.  See RemoveListener for a description 
 * of the race and why we can't fix it.
 */

static SInt32 gActivationCount = 0;

static const char * gPrefix = NULL;         /* points into gConfiguration, so doesn't need to be freed */

static char * gListenerScope = NULL;        /* must be freed using OSFree */


static int VnodeScopeListener(
    kauth_cred_t    credential,
    void *          idata,
    kauth_action_t  action,
    uintptr_t       arg0,
    uintptr_t       arg1,
    uintptr_t       arg2,
    uintptr_t       arg3
)
    /* A Kauth listener that's called to authorize an action in the vnode scope */
{
    #pragma unused(credential)
    #pragma unused(idata)
    #pragma unused(arg3)
    int             err;
    vfs_context_t   context;
    vnode_t         vp;
    vnode_t         dvp;
    char *          vpPath;
    char *          dvpPath;
    struct AuthEvent event;
        
    (void) OSIncrementAtomic(&gActivationCount);

    context = (vfs_context_t) arg0;
    vp      = (vnode_t) arg1;
    dvp     = (vnode_t) arg2;
    
    vpPath = NULL;
    dvpPath = NULL;
    
    /* Convert the vnode, if any, to a path. */
    err = CreateVnodePath(vp, &vpPath);
    
    /* Convert the parent directory vnode, if any, to a path. */
    if (err == 0)
        err = CreateVnodePath(dvp, &dvpPath);

    /*
    if(action & CLAMAUTH_EVENTS) {
        printf("gPrefix: %s, vpPath: %s, dvpPath: %s\n", gPrefix, vpPath ? vpPath : "<null>", dvpPath ? dvpPath : "<null>");
    }
    */

    /* Tell the user about this request.  Note that we filter requests 
     * based on gPrefix.  If gPrefix is set, only requests where one 
     * of the paths is prefixed by gPrefix will be printed.
     */    
    if (err == 0) {
        if (  (gPrefix == NULL) 
           || (  ( (vpPath != NULL)  && strprefix(vpPath, gPrefix) ) 
              || ( (dvpPath != NULL) && strprefix(dvpPath, gPrefix) ) 
              ) 
           ) {
               if(action & CLAMAUTH_EVENTS)
                   printf(
                "scope=" KAUTH_SCOPE_VNODE ", uid=%ld, vp=%s, dvp=%s\n", 
                (long) kauth_cred_getuid(vfs_context_ucred(context)),
                (vpPath  != NULL) ?  vpPath : "<null>",
                (dvpPath != NULL) ? dvpPath : "<null>"
            );
            
            event.pid = vfs_context_pid(context);
            event.action = action;
            if(vpPath) {
                strncpy(event.path, vpPath, sizeof(event.path));
                event.path[sizeof(event.path) - 1] = 0;
            } else {
                event.path[0] = 0;
            }
            lck_mtx_lock(gEventQueueLock);
            if(action & CLAMAUTH_EVENTS) {
                // printf("gPrefix: %s, vpPath: %s, dvpPath: %s, action: %d\n", gPrefix, vpPath ? vpPath : "<null>", dvpPath ? dvpPath : "<null>", action);
                AuthEventEnqueue(&gEventQueue, &event);
            }
            lck_mtx_unlock(gEventQueueLock);
            (void) OSIncrementAtomic(&gEventCount);
        }
    } else {
        printf("ClamAuth.VnodeScopeListener: Error %d.\n", err);
    }
    
    if (vpPath != NULL) {
        OSFree(vpPath, MAXPATHLEN, gMallocTag);
    }
    if (dvpPath != NULL) {
        OSFree(dvpPath, MAXPATHLEN, gMallocTag);
    }

    (void) OSDecrementAtomic(&gActivationCount);

    return KAUTH_RESULT_DEFER;
}

#pragma mark ***** Listener Install/Remove

/* gConfigurationLock is a mutex that protects us from two threads trying to 
 * simultaneously modify the configuration.  The configuration is protect in 
 * N ways:
 *
 * o During startup, we register our sysctl OID last, so no one can start 
 *   modifying the configuration until everything is set up nicely.
 * 
 * o During normal operations, the sysctl handler (SysctlHandler) takes 
 *   the lock to prevent two threads from reconfiguring the system at the 
 *   same time.
 *
 * o During termination, the stop routine first removes the sysctl OID 
 *   and then takes the lock before it removes the listener.  The first 
 *   act prevents any new sysctl requests coming it, the second blocks 
 *   until current sysctl requests are done.
 *
 * IMPORTANT:
 * There is still a race condition here.  See the stop routine for a description 
 * of the race and why we can't fix it.
 */

static lck_mtx_t *      gConfigurationLock = NULL;

/* gListener is our handle to the installed scope listener.  We need to 
 * keep it around so that we can remove the listener when we're done.
 */

static kauth_listener_t gListener = NULL;

static void RemoveListener(void)
    /* Removes the installed scope listener, if any.
     *
     * Under almost all circumstances this routine runs under the 
     * gConfigurationLock.  The only time that this might not be the case 
     * is when the KEXT's start routine fails prior to gConfigurationLock 
     * being created.
     */
{
    /* First prevent any more threads entering our listener. */
    if (gListener != NULL) {
        kauth_unlisten_scope(gListener);
        gListener = NULL;
    }
    
    /* Then wait for any threads within out listener to stop.  Note that there 
     * is still a race condition here; there could still be a thread executing 
     * between the OSDecrementAtomic and the return from the listener function 
     * (for example, FileOpScopeListener).  However, there's no way to close 
     * this race because of the weak concurrency guarantee for kauth_unlisten_scope.
     * Moreover, the window is very small and, seeing as this only happens during 
     * reconfiguration, I'm not too worried.  However, I am worried enough 
     * to ensure that this loop runs at least once, so we always delay the teardown  
     * for at least one second waiting for the threads to drain from our 
     * listener.
     */
    
    do {
        struct timespec oneSecond;

        oneSecond.tv_sec  = 1;
        oneSecond.tv_nsec = 0;

        (void) msleep(&gActivationCount, NULL, PUSER, "com_apple_dts_kext_ClamAuth.RemoveListener", &oneSecond);
    } while ( gActivationCount > 0 );
    
    /* gListenerScope and gPrefix are both accessed by the listener callbacks 
     * without taking any form of lock.  So, we don't destroy them until after 
     * all the listener callbacks have drained.
     */
    
    if (gListenerScope != NULL) {
        OSFree(gListenerScope, strlen(gListenerScope) + 1, gMallocTag);
        gListenerScope = NULL;
    }
    gPrefix = NULL;
}

static void InstallListener(const char *scope, size_t scopeLen, const char *prefix)
    /* Installs a listener for the specified scope.  scope and scopeLen specifies 
     * the scope to listen for.  prefix is a parameter for the scope listener. 
     * It may be NULL.
     *
     * prefix points into the gConfiguration global variable, so this routine 
     * doesn't make a copy of it.  However, it has to make a copy of scope 
     * because scope can point to a place in the middle of the gConfiguration 
     * variable, so there's no guarantee it's null terminated (which we need it 
     * to be in order to call kauth_listen_scope.
     *
     * This routine always runs under the gConfigurationLock.
     */
{    
    assert(scope != NULL);
    assert(scopeLen > 0);
    
    /* Allocate memory for the scope string.  We need to keep a persistent 
     * copy of this string because kauth_listen_scope doesn't make a copy of 
     * its scope identifier input parameter.  Normally you'd use a constant 
     * string, which persists as long as the kext is loaded, but I can't do 
     * that because the scope identifier is supplied by the user via sysctl.
     */
    
    assert(gListenerScope == NULL);
    
    gListenerScope = OSMalloc(scopeLen + 1, gMallocTag);
    if (gListenerScope == NULL) {
        printf("ClamAuth.InstallListener: Could not allocate gListenerScope.\n");
    } else {
        memcpy(gListenerScope, scope, scopeLen);
        gListenerScope[scopeLen] = 0;

        /* Copy the prefix pointer over to gPrefix. */        
        assert(gPrefix == NULL);

        gPrefix = prefix;
                assert(gListener == NULL);
        
        gListener = kauth_listen_scope(gListenerScope, VnodeScopeListener, NULL);
        if (gListener == NULL) {
            printf("ClamAuth.InstallListener: Could not create gListener.\n");
        } else {
            printf("ClamAuth: Installed vnode listener\n");
        }
    }
    
    /* In the event of any failure, call RemoveListener which will 
     * do all the right cleanup.
     */    
    if ( gListenerScope == NULL || gListener == NULL ) {
        RemoveListener();
    }
}

static void ConfigureKauth(const char *configuration)
    /* This routine is called by the sysctl handler when it notices 
     * that the configuration has changed.  It's responsible for 
     * parsing the new configuration string and updating the listener.
     *
     * See SysctlHandler for a description of how I chose to handle the 
     * failure case.
     *
     * This routine always runs under the gConfigurationLock.
     */
{
    assert(configuration != NULL);
    
    /* Remove the existing listener. */
    RemoveListener();

    /* Parse the configuration string and install the new listener. */
    if (strcmp(configuration, "remove") == 0) {
        printf("ClamAuth.ConfigureKauth: Removed listener.\n");
    } else if ( strprefix(configuration, "add ") ) {
        const char *cursor;
        const char *scopeStart;
        const char *scopeEnd;
        const char *prefixStart;
        
        /* Skip the "add ". */        
        cursor = configuration + strlen("add ");
        
        /* Work out the span of the scope. */        
        scopeStart = cursor;
        while ( (*cursor != ' ') && (*cursor != 0) ) {
            cursor += 1;
        }
        scopeEnd = cursor;
        
        if (scopeStart == scopeEnd) {
            printf("ClamAuth.ConfigureKauth: Bad configuration '%s'.\n", configuration);
        } else {

            /* Look for a prefix. */
            if (*cursor == ' ') {
                cursor += 1;
            }
            if (*cursor == 0) {
                prefixStart = NULL;
            } else {
                prefixStart = cursor;
            }
            
            /* Tell the user what we're doing. */            
            if (prefixStart == NULL) {
                printf("ClamAuth.ConfigureKauth: scope = %.*s\n", (int) (scopeEnd - scopeStart), scopeStart);
            } else {
                printf("ClamAuth.ConfigureKauth: scope = %.*s, prefix = %s\n", (int) (scopeEnd - scopeStart), scopeStart, prefixStart);
            }

            InstallListener(scopeStart, scopeEnd - scopeStart, prefixStart);
        }
    } else {
        printf("ClamAuth.ConfigureKauth: Bad configuration '%s'.\n", configuration);
    }
}

/* gConfiguration holds our current configuration string.  It's modified by 
 * SysctlHandler (well, by sysctl_handle_string which is called by SysctlHandler).
 */

static char gConfiguration[1024];

static int SysctlHandler(
    struct sysctl_oid * oidp, 
    void *              arg1, 
    int                 arg2, 
    struct sysctl_req * req
)
    /* This routine is called by the kernel when the user reads or 
     * writes our sysctl variable.  The arguments are standard for 
     * a sysctl handler.
     */
{
    int     result;
    
    /* Prevent two threads trying to change our configuration at the same 
     * time.
     */    
    lck_mtx_lock(gConfigurationLock);
    
    /* Let sysctl_handle_string do all the heavy lifting of getting 
     * and setting the variable.
     */    
    result = sysctl_handle_string(oidp, arg1, arg2, req);
    
    /* On the way out, if we got no error and a new value was set, 
     * do our magic.
     */    
    if ( (result == 0) && (req->newptr != 0) ) {
        ConfigureKauth(gConfiguration);
    }
    
    lck_mtx_unlock(gConfigurationLock);

    return result;
}

/* Declare our sysctl OID (that is, a variable that the user can 
 * get and set using sysctl).  Once this OID is registered (which 
 * is done in the start routine, ClamAuth_start, below), the user 
 * user can get and set our configuration variable (gConfiguration) 
 * using the sysctl command line tool.
 *
 * We use OID using SYSCTL_OID rather than SYSCTL_STRING because 
 * we want to override the hander function that's call (we want 
 * SysctlHandler rather than sysctl_handle_string).
 */

SYSCTL_OID(
    _kern,                                          /* parent OID */
    OID_AUTO,                                       /* sysctl number, OID_AUTO means we're only accessible by name */
    com_apple_dts_kext_ClamAuth,                    /* our name */
    CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_KERN,     /* we're a string, more or less */
    gConfiguration,                                 /* sysctl_handle_string gets/sets this string */
    sizeof(gConfiguration),                         /* and this is its maximum length */
    SysctlHandler,                                  /* our handler */
    "A",                                            /* because that's what SYSCTL_STRING does */
    ""                                              /* just a comment */
);

/* gRegisteredOID tracks whether we've registered our OID or not. */

static boolean_t gRegisteredOID = FALSE;


/* /dev/clamauth handling */

static int ca_devidx = -1;
static void *ca_devnode = NULL;
int dev_open = 0;

static int ca_open(dev_t dev, int flag, int devtype, proc_t p)
{
    if(dev_open)
        return EBUSY;

    dev_open = 1;

    return 0;
}

static int ca_close(dev_t dev, int flag, int devtype, proc_t p)
{
    dev_open = 0;
    return 0;
}

static int ca_read(dev_t dev, uio_t uio, int ioflag)
{
    int ret = 0, size, retq = 0;
    struct AuthEvent event;
    char info[MAXPATHLEN + 128];
    struct timespec waittime;

    waittime.tv_sec  = 1;
    waittime.tv_nsec = 0;
    while(uio_resid(uio) > 0) {
        lck_mtx_lock(gEventQueueLock);
        retq = AuthEventDequeue(&gEventQueue, &event);
        lck_mtx_unlock(gEventQueueLock);
        if(retq != 1) {
            snprintf(info, sizeof(info), "PATH: %s, PID: %d, ACTION: %d\n", event.path, event.pid, event.action);
            size = MIN(uio_resid(uio), ((long long) strlen(info)));
            ret = uiomove(info, size, uio);
            if(ret)
                break;
        }  else {
        //(void) msleep(&gEventQueue, NULL, PUSER, "events", &waittime);
            break;
        }
    }

    if(ret) {
        printf("ClamAuth: uiomove() failed\n");
    }

    return ret;
}

static int ca_write(dev_t dev, uio_t uio, int ioflag)
{
    return EBADF;
}

static int ca_ioctl(dev_t dev, u_long cmd, caddr_t addr, int flag, proc_t p)
{
    return EBADF;
}

static int ca_select(dev_t dev, int flag, void * wql, proc_t p)
{
    return EBADF;
}

static struct cdevsw clamauth_cdevsw = {
    ca_open,
    ca_close,
    ca_read,
    ca_write,
    ca_ioctl,
    eno_stop,
    eno_reset,
    NULL,
    ca_select,
    eno_mmap,
    eno_strat,
    eno_getc,
    eno_putc,
    0
};

static int ca_remove(void)
{
    if(ca_devnode)
        devfs_remove(ca_devnode);

    if(ca_devidx != -1) {
        if(cdevsw_remove(ca_devidx, &clamauth_cdevsw) != ca_devidx) {
            printf("ClamAuth: cdevsw_remove() failed\n");
            return KERN_FAILURE;
        }
    }

    return KERN_SUCCESS;
}

#pragma mark ***** Start/Stop

/* Prototypes for our entry points */
extern kern_return_t com_apple_dts_kext_ClamAuth_start(kmod_info_t * ki, void * d);
extern kern_return_t com_apple_dts_kext_ClamAuth_stop(kmod_info_t * ki, void * d);

extern kern_return_t com_apple_dts_kext_ClamAuth_start(kmod_info_t * ki, void * d)
/* Called by the system to start up the kext. */
{
    #pragma unused(ki)
    #pragma unused(d)
    kern_return_t   err;

    ca_devidx = cdevsw_add(-1, &clamauth_cdevsw);
    if(ca_devidx == -1) {
        printf("ClamAuth: cdevsw_add() failed\n");
        return KERN_FAILURE;
    }

    ca_devnode = devfs_make_node(makedev(ca_devidx, 0), DEVFS_CHAR, UID_ROOT, GID_WHEEL, 0660, "clamauth");
    if(!ca_devnode) {
        printf("ClamAuth: Can't create /dev/clamauth\n");
        return ca_remove();
    }    
    
    /* Allocate our global resources, needed in order to allocate memory 
     * and locks throughout the rest of the program.
     */
    err = KERN_SUCCESS;
    gMallocTag = OSMalloc_Tagalloc("com.apple.dts.kext.ClamAuth", OSMT_DEFAULT);
    if (gMallocTag == NULL) {
        err = KERN_FAILURE;
    }
    if (err == KERN_SUCCESS) {
        gLockGroup = lck_grp_alloc_init("com.apple.dts.kext.ClamAuth", LCK_GRP_ATTR_NULL);
        if (gLockGroup == NULL) {
            err = KERN_FAILURE;
        }
    }
    
    /* Allocate the lock that protects our configuration. */
    if (err == KERN_SUCCESS) {
        gConfigurationLock = lck_mtx_alloc_init(gLockGroup, LCK_ATTR_NULL);
        if (gConfigurationLock == NULL) {
            err = KERN_FAILURE;
        }
    }

    /* Event queue lock */
    if (err == KERN_SUCCESS) {
        gEventQueueLock = lck_mtx_alloc_init(gLockGroup, LCK_ATTR_NULL);
        if (gEventQueueLock == NULL) {
            err = KERN_FAILURE;
        }
    }
    AuthEventInitQueue(&gEventQueue);

    /* Register our sysctl handler. */    
    if (err == KERN_SUCCESS) {
        sysctl_register_oid(&sysctl__kern_com_apple_dts_kext_ClamAuth);
        gRegisteredOID = TRUE;
    }
    
    /* If we failed, shut everything down. */
    if (err != KERN_SUCCESS) {
        printf("ClamAuth_start: Failed to initialize the driver\n");
        (void) com_apple_dts_kext_ClamAuth_stop(ki, d);
    } else
        printf("ClamAuth_start: ClamAV kernel driver loaded\n");

    return err;
}

extern kern_return_t com_apple_dts_kext_ClamAuth_stop(kmod_info_t * ki, void * d)
    /* Called by the system to shut down the kext. */
{
    #pragma unused(ki)
    #pragma unused(d)
    int ret;

    /* Remove our sysctl handler.  This prevents more threads entering the 
     * handler and trying to change the configuration.  There is still a 
     * race condition here though.  If a thread is already running in our 
     * sysctl handler, there's no way to guarantee that it's done before 
     * we destroy key resources (notably the gConfigurationLock mutex) that 
     * it depends on.  That's because sysctl_unregister_oid makes no attempt 
     * to wait until all threads running inside the OID handler are done 
     * before it returns.  I could do stuff to minimise the risk, but there's 
     * is no 100% way to close this race so I'm going to ignore it.
     */    
    if (gRegisteredOID) {
        sysctl_unregister_oid(&sysctl__kern_com_apple_dts_kext_ClamAuth);
        gRegisteredOID = FALSE;
    }

    /* remove the character device */
    ret = ca_remove();

    /* Shut down the scope listen, if any.  Not that we lock gConfigurationLock 
     * because RemoveListener requires it to be locked.  Further note that 
     * we only do this if the lock has actually been allocated.  If the startup 
     * routine fails, we can get called with gConfigurationLock set to NULL.
     */    
    if (gConfigurationLock != NULL) {
        lck_mtx_lock(gConfigurationLock);
    }
    RemoveListener();
    if (gConfigurationLock != NULL) {
        lck_mtx_unlock(gConfigurationLock);
    }
    
    /* Clean up the configuration lock. */    
    if (gConfigurationLock != NULL) {
        lck_mtx_free(gConfigurationLock, gLockGroup);
        gConfigurationLock = NULL;
    }

    /* Clean up the event queue lock. */    
    if (gEventQueueLock != NULL) {
        lck_mtx_free(gEventQueueLock, gLockGroup);
        gEventQueueLock = NULL;
    }

    /* Clean up our global resources. */
    if (gLockGroup != NULL) {
        lck_grp_free(gLockGroup);
        gLockGroup = NULL;
    }
    if (gMallocTag != NULL) {
        OSMalloc_Tagfree(gMallocTag);
        gMallocTag = NULL;
    }
    
    printf("ClamAuth_stop: ClamAV kernel driver removed\n");
    return ret;
}
