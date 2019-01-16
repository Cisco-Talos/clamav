/**
***     dlopen(), dlclose() dlsym(), dlerror() emulation for OS/400.
***
***     See Copyright for the status of this software.
***
***     Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.
**/

#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <except.h>             /* AS400 exceptions. */
#include <miptrnam.h>           /* MI pointers support. */
#include <qusec.h>              /* Error structures. */
#include <qp0lstdi.h>           /* Path to QSYS object name. */
#include <qp0z1170.h>           /* For Qp0zInitEnv(). */
#include <qleawi.h>             /* For QleActBndPgmLong() definitions. */
#include <qsy.h>                /* Qualified name structure. */
#include <qmhrtvm.h>            /* Retrieve message from message file. */

#include <mih/rinzstat.h>
#include <mih/matactex.h>

#include "libxml/hash.h"
#include "dlfcn.h"


/**
***     Maximum internal path length.
**/

#define MAXPATHLEN              5120


/**
***     Maximum error string length.
**/

#define MAX_ERR_STR             511


/**
***     Field address macro.
**/

#define offset_by(t, b, o)      ((t *) ((char *) (b) + (unsigned int) (o)))


/**
***     Global flags.
**/

#define INITED          000001          /* Package has been initialized. */
#define THREADS         000002          /* Multithreaded job. */
#define MULTIBUF        000004          /* One error buffer per thread. */


/**
***     DLL handle private structure.
**/

typedef struct {
        Qle_ABP_Info_Long_t     actinfo;        /* Activation information. */
        _SYSPTR                 pointer;        /* Pointer to DLL object. */
        unsigned int            actcount;       /* Activation count. */
}               dlinfo;


/**
***     Per-thread structure.
**/

typedef struct {
        unsigned int    lockcount;              /* Mutex lock count. */
        unsigned int    iserror;                /* Flag error present. */
        char            str[MAX_ERR_STR + 1];   /* Error string buffer. */
}               dlts_t;


static pthread_mutex_t  dlmutex = PTHREAD_MUTEX_INITIALIZER;
static xmlHashTablePtr  dldir = (xmlHashTablePtr) NULL; /* DLL directory. */
static unsigned int     dlflags = 0;                    /* Package flags. */
static pthread_key_t    dlkey;
static dlts_t           static_buf;             /* Static error buffer. */



static void
dlthreadterm(void * mem)

{
        free(mem);
        pthread_setspecific(dlkey, NULL);
}


static void
dlterm(void)

{
        void * p;

        if (dlflags & MULTIBUF) {
                p = pthread_getspecific(dlkey);

                if (p)
                        dlthreadterm(p);
                }

        if (dlflags & THREADS)
                pthread_mutex_lock(&dlmutex);

        if (dldir) {
                xmlHashFree(dldir, (xmlHashDeallocator) NULL);
                dldir = NULL;
                }

        if (dlflags & MULTIBUF)
                pthread_key_delete(dlkey);

        dlflags |= ~(INITED | MULTIBUF);
        pthread_mutex_unlock(&dlmutex);
        pthread_mutex_destroy(&dlmutex);
}


static void
dlinit(void)

{
        int locked;

        /**
        ***     Initialize the package.
        ***     Should be call once per process.
        **/

        locked = !pthread_mutex_lock(&dlmutex);

        if (!(dlflags & INITED)) {
                dlflags &= ~THREADS;

                if (locked)
                        dlflags |= THREADS;

                Qp0zInitEnv();
                dldir = xmlHashCreate(16);
                dlflags &= ~MULTIBUF;

                if (dlflags & THREADS)
                        if (!pthread_key_create(&dlkey, dlthreadterm))
                                dlflags |= MULTIBUF;

                atexit(dlterm);
                dlflags |= INITED;
                }

        if (locked)
                pthread_mutex_unlock(&dlmutex);
}


static void
dlthreadinit(void)

{
        dlts_t * p;

        if (!(dlflags & INITED))
                dlinit();

        if (dlflags & MULTIBUF) {
                p = pthread_getspecific(dlkey);

                if (!p) {
                        p = (dlts_t *) malloc(sizeof *p);

                        if (p) {
                                p->lockcount = 0;
                                p->iserror = 0;

                                if (pthread_setspecific(dlkey, p))
                                        free(p);
                                }
                        }
                }
}


static void
dllock(void)

{
        dlts_t * p;

        if (!(dlflags & THREADS))
                return;

        if (dlflags & MULTIBUF) {
                p = pthread_getspecific(dlkey);

                if (p && p->lockcount) {
                        p->lockcount++;
                        return;
                        }
                }
        else
                p = (dlts_t *) NULL;

        if (pthread_mutex_lock(&dlmutex))
                return;

        if (p)
                p->lockcount++;
}


static void
dlunlock(void)

{
        dlts_t * p;

        if (!(dlflags & THREADS))
                return;

        if (dlflags & MULTIBUF) {
                p = pthread_getspecific(dlkey);

                if (p && p->lockcount > 1) {
                        p->lockcount--;
                        return;
                        }
                }
        else
                p = (dlts_t *) NULL;

        if (pthread_mutex_unlock(&dlmutex))
                return;

        if (p)
                p->lockcount--;
}


const char *
dlerror(void)

{
        dlts_t * p;

        dlthreadinit();

        if (!(dlflags & MULTIBUF))
                p = &static_buf;
        else if (!(p = (dlts_t *) pthread_getspecific(dlkey)))
                p = &static_buf;

        if (!p->iserror)
                return (const char *) NULL;

        p->iserror = 0;
        return p->str;
}


static void
dlseterror_from_errno(unsigned int err_no)

{
        dlts_t * p;

        if (!(dlflags & MULTIBUF))
                p = &static_buf;
        else if (!(p = (dlts_t *) pthread_getspecific(dlkey)))
                p = &static_buf;

        strcpy(p->str, strerror(err_no));
        p->iserror = 1;
}


static void
dlseterror_from_exception(volatile _INTRPT_Hndlr_Parms_T * excp)

{
        int i;
        Qmh_Rtvm_RTVM0300_t * imp;
        char * cp;
        _INTRPT_Hndlr_Parms_T * p;
        dlts_t * q;
        char rtvmbuf[30000];
        Qus_EC_t errinfo;

        p = (_INTRPT_Hndlr_Parms_T *) excp;
        errinfo.Bytes_Provided = 0;             /* Exception on error. */
        QMHRTVM(rtvmbuf, sizeof rtvmbuf, "RTVM0300", p->Msg_Id,
            "QCPFMSG   QSYS      ", p->Ex_Data, p->Msg_Data_Len,
            "*YES      ", "*NO       ", &errinfo);
        imp = offset_by(Qmh_Rtvm_RTVM0300_t, rtvmbuf, 0);

        if (!(dlflags & MULTIBUF))
                q = &static_buf;
        else if (!(q = (dlts_t *) pthread_getspecific(dlkey)))
                q = &static_buf;

        if (i = imp->Length_Message_Returned)
                cp = offset_by(char, imp, imp->Offset_Message_Returned);
        else if (i = imp->Length_Help_Returned)
                cp = offset_by(char, imp, imp->Offset_Help_Returned);
        else {
                q->iserror = 0;
                return;
                }

        q->iserror = 1;

        if (i > sizeof q->str - 1)
                i = sizeof q->str - 1;

        memcpy(q->str, cp, i);
        q->str[i] = '\0';
}


static int
dlparentpath(const char * path, size_t len)

{
        if (len <= 1)
                return len;

        while (path[--len] != '/')
                ;

        return len? len: 1;
}


static int
dlmakepath(char * path, size_t pathlen, const char * tail, size_t taillen)

{
        int i;

        if (taillen && tail[0] == '/')
                pathlen = 0;

        for (;;) {
                while (taillen && *tail == '/') {
                        tail++;
                        taillen--;
                        }

                if (!taillen)
                        break;

                for (i = 0; i < taillen; i++)
                        if (tail[i] == '/')
                                break;

                if (*tail == '.')
                        switch (i) {

                        case 2:
                                if (tail[1] != '.')
                                        break;

                                pathlen = dlparentpath(path, pathlen);

                        case 1:
                                tail += i;
                                taillen -= i;
                                continue;
                                }

                if (pathlen + i + 1 >= MAXPATHLEN) {
                        errno = ENAMETOOLONG;
                        return -1;
                        }

                path[pathlen++] = '/';
                memcpy(path + pathlen, tail, i);
                pathlen += i;
                }

        if (!pathlen)
                path[pathlen++] = '/';

        path[pathlen] = '\0';
        return pathlen;
}


static int
dlresolveLink(const char * path, char * buf, size_t bufsiz)

{
        int n;
        int l1;
        int l2;
        struct stat sbuf;
        char buf1[MAXPATHLEN + 1];
        char buf2[MAXPATHLEN + 1];

        /**
        ***     Resolve symbolic link to IFS object name.
        **/

        if (!buf) {
                errno = EFAULT;
                return -1;
                }

        if (!path || !*path || !bufsiz) {
                errno = EINVAL;
                return -1;
                }

        if (*path != '/') {
                if (!getcwd(buf1, sizeof buf1))
                        return -1;

                l1 = strlen(buf1);
                }
        else
                l1 = 0;

        l1 = dlmakepath(buf1, l1, path, strlen(path));
        n = 0;

        for (;;) {
                if (l1 < 0)
                        return -1;

                if (n++ >= 256) {
                        errno = ELOOP;
                        return -1;
                        }

                if (lstat(buf1, &sbuf)) {
                        if (errno == ENOENT)
                                break;

                        return -1;
                        }

                if (!S_ISLNK(sbuf.st_mode))
                        break;

                if (sbuf.st_size > MAXPATHLEN) {
                        errno = ENAMETOOLONG;
                        return -1;
                        }

                l2 = readlink(buf1, buf2, MAXPATHLEN + 1);

                if (l2 < 0)
                        return -1;

                if (buf2[0] != '/')
                        l1 = dlparentpath(buf1, l1);

                l1 = dlmakepath(buf1, l1, buf2, l2);
                }

        if (l1 >= bufsiz) {
                errno = ENAMETOOLONG;
                return -1;
                }

        memcpy(buf, buf1, l1 + 1);
        return l1;
}


static int
dlGetObjectName(Qp0l_QSYS_Info_t * qsysinfo, const char * dir,
                        int dirlen, const char * link)

{
        int n;
        char * namebuf;
        Qlg_Path_Name_T * qptp;
        char pathbuf[sizeof(Qlg_Path_Name_T) + _QP0L_DIR_NAME_LG + 4];
        Qus_EC_t errinfo;
        struct stat sbuf;

        /**
        ***     Get QSYS object library/name/member and type corresponding to
        ***             the symbolic `link' in directory `dir'.
        **/

        if (!qsysinfo) {
                errno = EFAULT;
                return -1;
                }

        if (!dir && !link) {
                errno = EINVAL;
                return -1;
                }

        qptp = (Qlg_Path_Name_T *) pathbuf;
        namebuf = pathbuf + sizeof(Qlg_Path_Name_T);
        n = 0;

        /**
        ***     Build full path.
        **/

        if (dir) {
                if (dirlen < 0 || dirlen > _QP0L_DIR_NAME_LG + 4)
                        dirlen = _QP0L_DIR_NAME_LG + 4;

                while (*dir && n < dirlen)
                        namebuf[n++] = *dir++;
                }

        if (n && namebuf[n - 1] == '/')
                n--;

        if (link) {
                if (*link && *link != '/' && n < _QP0L_DIR_NAME_LG + 4)
                        namebuf[n++] = '/';

                while (*link && n < _QP0L_DIR_NAME_LG + 4)
                        namebuf[n++] = *link++;
                }

        if (!n || n > _QP0L_DIR_NAME_LG) {
                errno = ENAMETOOLONG;
                return -1;
                }

        namebuf[n] = '\0';
        n = dlresolveLink(namebuf, namebuf, _QP0L_DIR_NAME_LG + 1);

        if (n == -1)
                return -1;

        if (stat(namebuf, &sbuf))
                return -1;

        memset((char *) qptp, 0, sizeof *qptp);
        qptp->Path_Length = n;
        qptp->Path_Name_Delimiter[0] = '/';
        errinfo.Bytes_Provided = sizeof errinfo;
        Qp0lCvtPathToQSYSObjName(qptp, qsysinfo, "QSYS0100", sizeof *qsysinfo,
            0, &errinfo);
        return errinfo.Bytes_Available? -1: 0;
}


static const char *
getcomponent(char * dst, const char * src)

{
        int i;

        /**
        ***     Get a path component of at most 10 characters and
        ***             map it to upper case.
        ***     Return the address of the next delimiter in source.
        **/

        for (i = 0;; src++) {
                if (!*src || *src == ' ' || *src == '/') {
                        *dst = '\0';
                        return src;
                        }

                if (i < 10) {
                        *dst++ = toupper(*src);
                        i++;
                        }
                }
}


static int
dlpath2QSYS(Qp0l_QSYS_Info_t * qsysinfo, const char * path, const char * dftlib)

{
        unsigned int flags;
        char * cp;

        /**
        ***     Convert the given path to a QSYS object name.
        ***     Syntax rules for paths are:
        ***
        ***     '/'+ [ <library> [  '/'+ <file> [ '/'+ <member> ] ] '/'* ]
        ***     <library> '/'+ <file> [ '/'+ <member> ] '/'*
        ***     <file> '/'*
        ***
        ***     If default library is not given, *LIBL is assumed.
        ***     Components may no contain spaces. They are translated to
        ***             uppercase. Only the first 10 characters are significant.
        ***     There is no check for the validity of the given components and
        ***             for the object existence.
        ***     Component types are not in the path, but generated internally.
        ***     CCSID is not processed.
        ***
        ***     Return 0 upon success, else -1.
        **/

        if (!qsysinfo || !path) {
                errno = EFAULT;
                return -1;
                }

        /**
        ***     Strip leading spaces.
        **/

        while (*path == ' ')
                path++;

        /**
        ***     Check for null path.
        **/

        if (!*path) {
                errno = EINVAL;
                return -1;
                }

        /**
        ***     Preset the result structure.
        **/

        memset((char *) qsysinfo, 0, sizeof *qsysinfo);

        /**
        ***     Determine the format.
        **/

        if (*path == '/') {
                /**
                ***     Library component present.
                **/

                while (*++path == '/')
                        ;

                if (!*path || *path == ' ')
                        strcpy(qsysinfo->Lib_Name, "QSYS");
                else
                        path = getcomponent(qsysinfo->Lib_Name, path);

                /**
                ***     Check for file component and get it.
                **/

                if (*path == '/') {
                        while (*++path == '/')
                                ;

                        if (*path && *path != ' ')
                                path = getcomponent(qsysinfo->Obj_Name, path);
                        }
                }
        else {
                /**
                ***     The mandatory component is the <file>.
                **/

                path = getcomponent(qsysinfo->Obj_Name, path);

                while (*path == '/')
                        path++;

                /**
                ***     If there is a second component, move the first to
                ***             the library name and parse the file name.
                **/

                if (*path && *path != ' ') {
                        strcpy(qsysinfo->Lib_Name, qsysinfo->Obj_Name);
                        memset(qsysinfo->Obj_Name, 0,
                            sizeof qsysinfo->Obj_Name);
                        path = getcomponent(qsysinfo->Obj_Name, path);
                        }
                else
                        strcpy(qsysinfo->Lib_Name, dftlib? dftlib: "*LIBL");
                }

        /**
        ***     Check and set-up member.
        **/

        while (*path == '/')
                path++;

        if (*path && *path != ' ') {
                path = getcomponent(qsysinfo->Mbr_Name, path);
                strcpy(qsysinfo->Mbr_Type, "*MBR");

                while (*path == '/')
                        path++;
                }

        strcpy(qsysinfo->Lib_Type, "*LIB");

        if (qsysinfo->Obj_Name[0])
                strcpy(qsysinfo->Obj_Type, "*FILE");

        qsysinfo->Bytes_Returned = sizeof *qsysinfo;
        qsysinfo->Bytes_Available = sizeof *qsysinfo;

        /**
        ***     Strip trailing spaces.
        **/

        while (*path == ' ')
                path++;

        if (*path) {
                errno = EINVAL;
                return -1;
                }

        return 0;
}


static int
dl_ifs_link(Qp0l_QSYS_Info_t * qsysinfo, const char * pathname)

{
        /**
        ***     If `pathname' is a link found in IFS, set `qsysinfo' to its
        ***             DB2 name.
        ***     Return 0 if OK, else -1.
        **/

        return dlGetObjectName(qsysinfo, (const char *) NULL, 0, pathname);
}


static int
dl_path_link(Qp0l_QSYS_Info_t * qsysinfo, const char * pathvar,
        const char * filename, int (* testproc)(const Qp0l_QSYS_Info_t *))

{
        const char * p;
        const char * q;
        unsigned int i;
        const char * path;

        /**
        ***     If `filename' is not a path and is a link found in one of the
        ***             colon-separated paths in environment variable `pathvar',
        ***             set `qsysinfo' to its DB2 name.
        ***     Return 0 if OK, else -1.
        **/

        i = _QP0L_DIR_NAME_LG;

        for (p = filename; *p; p++)
                if (*p == '/' || !--i)
                        return -1;              /* Too long or a path. */

        /**
        ***     Make sure we have the LD_LIBRARY_PATH environment
        ***             variable value.
        **/

        path = getenv(pathvar);

        if (!path)
                return -1;                      /* No path list. */

        /**
        ***     Try in each path listed.
        **/

        q = path;

        if (!*q)
                return -1;                      /* No path list. */

        for (;;) {
                for (p = q; *p && *p != ':'; p++)
                        ;

                if (p > q)                      /* Ignore null path. */
                        if (!dlGetObjectName(qsysinfo, q, p - q, filename))
                                if (!testproc || (*testproc)(qsysinfo))
                                        return 0;       /* Found: return. */

                if (!*p)
                        break;

                q = p + 1;
                }

        errno = ENOENT;
        return -1;
}


static int
dl_DB2_path(Qp0l_QSYS_Info_t * qsysinfo, const char * pathname)

{
        if (dlpath2QSYS(qsysinfo, pathname, (const char *) NULL))
                return -1;

        if (qsysinfo->Mbr_Type[0])
                return -1;      /* Service program may not have members. */

        if (!qsysinfo->Obj_Type[0])
                return -1;      /* Object must be specified. */

        strcpy(qsysinfo->Obj_Type, "*SRVPGM");  /* Set our object type. */
        return 0;
}


static int
dl_DB2_name(char * dst, const char * name)

{
        int i;

        for (i = 0; i < 10; i++) {
                switch (*name) {

                default:
                        if (!islower(*name))
                                break;

                case '\0':
                case '/':
                case ' ':
                        return -1;
                        }

                *dst++ = *name++;
                }

        if (!i)
                return -1;

        *dst = '\0';
        return 0;
}


static int
dl_qualified_object(Qp0l_QSYS_Info_t * qsysinfo, const char * pathname)

{
        memset((char *) qsysinfo, 0, sizeof *qsysinfo);

        if (dl_DB2_name(qsysinfo->Obj_Name, pathname) ||
            dl_DB2_name(qsysinfo->Lib_Name, pathname + 10))
                return -1;

        strcpy(qsysinfo->Lib_Type, "*LIB");
        strcpy(qsysinfo->Obj_Type, "*SRVPGM");
        return 0;
}


static int
dl_lib_object(Qp0l_QSYS_Info_t * qsysinfo,
                                const char * libname, const char * pathname)

{
        int i;
        char * cp;

        strcpy(qsysinfo->Lib_Name, libname);
        strcpy(qsysinfo->Lib_Type, "*LIB");
        strcpy(qsysinfo->Obj_Type, "*SRVPGM");
        cp = qsysinfo->Obj_Name;

        while (*pathname == ' ')
                pathname++;

        for (i = 0;; pathname++) {
                switch (*pathname) {

                case '\0':
                case ' ':
                        break;

                case '/':
                        return -1;

                default:
                        if (i < 10)
                                *cp++ = toupper(*pathname);

                        i++;
                        continue;
                        }

                break;
                }

        while (*pathname == ' ')
                pathname++;

        if (!i || *pathname)
                return -1;

        *cp = '\0';
        return 0;
}


static int
dl_is_srvpgm(const Qp0l_QSYS_Info_t * qsysinfo)

{
        struct stat sbuf;
        char namebuf[100];

        if (!qsysinfo->Lib_Name[0] || strcmp(qsysinfo->Lib_Type, "*LIB") ||
            !qsysinfo->Obj_Name[0] || strcmp(qsysinfo->Obj_Type, "*SRVPGM") ||
            qsysinfo->Mbr_Name[0] || qsysinfo->Mbr_Type[0])
                return 0;

        /**
        ***     Build the IFS path name for the DB2 object.
        **/

        sprintf(namebuf, "%s/%s.LIB/%s.SRVPGM",
            strcmp(qsysinfo->Lib_Name, "QSYS")? "/QSYS.LIB": "",
            qsysinfo->Lib_Name, qsysinfo->Obj_Name);

        return stat(namebuf, &sbuf) == 0;
}


static int
dlreinit(dlinfo * dlip)

{
        RINZ_TEMPL_T t;
        RINZ_TEMPL_T * p;
        volatile _INTRPT_Hndlr_Parms_T excbuf;

        if (dlip->actinfo.Flags & QLE_ABP_WAS_ACTIVE)
                return 0;

        /**
        ***     Attempt to reinitialize the service program that was loaded.
        ***     The service program must be created to allow re-initialization:
        ***             ALWRINZ(*YES) for this to work. The default is
        ***             ALWRINZ(*NO).
        **/

#pragma exception_handler(err, excbuf, 0, _C2_MH_ESCAPE, _CTLA_HANDLE_NO_MSG)
        p = &t;
        t.rinz_pgm = dlip->pointer;
        t.rinz_agpmk = dlip->actinfo.Act_Grp_Mark;
        _RINZSTAT(p);
#pragma disable_handler

        return 0;

err:
        if (!memcmp((char *) excbuf.Msg_Id, "MCH4421", 7))
                return 0;       /* Program cannot be reinitialized. */

        dlseterror_from_exception(&excbuf);
        return -1;
}


void *
dlsym(void * handle, const char * symbol)

{
        dlinfo * dlip;
        void * p;
        int export_type;
        Qus_EC_t errinfo;
        volatile _INTRPT_Hndlr_Parms_T excbuf;
        static int zero = 0;

        dlthreadinit();

        if (!handle || !symbol) {
                dlseterror_from_errno(EFAULT);
                return (void *) NULL;
                }

        dlip = (dlinfo *) handle;

#pragma exception_handler(error, excbuf, 0, _C2_MH_ESCAPE, _CTLA_HANDLE_NO_MSG)
        errinfo.Bytes_Provided = 0;
        QleGetExpLong(&dlip->actinfo.Act_Mark, &zero, &zero,
            (char *) symbol, &p, &export_type, &errinfo);
        return p;
#pragma disable_handler

error:
        dlseterror_from_exception(&excbuf);
        return (void *) NULL;
}


int
dlclose(void * handle)

{
        dlinfo * dlip;
        void (* _fini)(void);

        dlthreadinit();

        if (!handle) {
                dlseterror_from_errno(EFAULT);
                return -1;
                }

        dlip = (dlinfo *) handle;

        if (dlip->actcount) {
                if (--(dlip->actcount))
                        return 0;

                if (_fini = dlsym(handle, "_fini"))
                        (*_fini)();
                }

        return dlreinit(dlip);
}


static void *
dlopenqsys(const Qp0l_QSYS_Info_t * dllinfo)

{
        dlinfo * dlip;
        dlinfo * dlip2;
        void (* _init)(void);
        unsigned int i;
        _SYSPTR pgmptr;
        unsigned long long actmark;
        Qus_EC_t errinfo;
        char actmarkstr[2 * sizeof actmark + 1];
        static int actinfo_size = sizeof dlip->actinfo;
        volatile _INTRPT_Hndlr_Parms_T excbuf;

        /**
        ***     Capture any type of error and if any occurs,
        ***             return not found.
        **/

#pragma exception_handler(error1, excbuf, 0, _C2_MH_ESCAPE, _CTLA_HANDLE_NO_MSG)
        pgmptr = rslvsp(WLI_SRVPGM, (char *) dllinfo->Obj_Name,
            (char *) dllinfo->Lib_Name ,_AUTH_NONE);

        if (!pgmptr) {
                errno = ENOENT;
                return (void *) NULL;
                }

        /**
        ***     Create a new DLL info block.
        **/

        dlip = (dlinfo *) malloc(sizeof *dlip);

        if (!dlip)
                return (void *) NULL;           /* Cannot create block. */
#pragma disable_handler

        dllock();

#pragma exception_handler(error2, excbuf, 0, _C2_MH_ESCAPE, _CTLA_HANDLE_NO_MSG)
        memset((char *) dlip, 0, sizeof *dlip);
        dlip->pointer = pgmptr;

        /**
        ***     Activate the DLL.
        **/

        errinfo.Bytes_Provided = 0;
        QleActBndPgmLong(&pgmptr, &actmark,
            &dlip->actinfo, &actinfo_size, &errinfo);
        dlip->actinfo.Act_Mark = actmark;

        /**
        ***     Dummy string encoding activation mark to use as hash table key.
        **/

        for (i = 0; actmark; actmark >>= 6)
                actmarkstr[i++] = 0x40 + (actmark & 0x3F);

        actmarkstr[i] = '\0';

        /**
        ***     Check if already activated.
        **/

        dlip2 = (dlinfo *) xmlHashLookup(dldir, actmarkstr);

        if (dlip2) {
                free((char *) dlip);
                dlip = dlip2;
                }
        else if (xmlHashAddEntry(dldir, (const xmlChar *) actmarkstr, dlip)) {
                dlreinit(dlip);
                free((char *) dlip);
                dlunlock();
                return (void *) NULL;
                }
#pragma disable_handler

#pragma exception_handler(error2, excbuf, 0, _C2_MH_ESCAPE, _CTLA_HANDLE_NO_MSG)

        /**
        ***     Bump activation counter.
        **/

        if (!(dlip->actcount++) && (_init = dlsym(dlip, "_init")))
                (*_init)();

        dlunlock();

        /**
        ***     Return the handle.
        **/

        return (void *) dlip;
#pragma disable_handler

error2:
        free((char *) dlip);
        dlunlock();

error1:
        dlseterror_from_exception(&excbuf);
        return (void *) NULL;
}


void *
dlopen(const char * filename, int flag)

{
        void * dlhandle;
        int sverrno;
        Qp0l_QSYS_Info_t dllinfo;

        sverrno = errno;
        errno = 0;

        dlthreadinit();

        if (!filename) {
                dlseterror_from_errno(EFAULT);
                errno = sverrno;
                return NULL;
                }

        /**
        ***     Try to locate the object in the following order:
        ***     _       `filename' is an IFS path.
        ***     _       `filename' is not a path and resides in one of
        ***                     LD_LIBRARY_PATH colon-separated paths.
        ***     _       `filename' is not a path and resides in one of
        ***                     PATH colon-separated paths.
        ***     _       `filename' is a DB2 path (as /library/object).
        ***     _       `filename' is a qualified object name.
        ***     _       `filename' is an object in *CURLIB.
        ***     _       `filename' is an object in *LIBL.
        **/

        if (!dl_ifs_link(&dllinfo, filename) && dl_is_srvpgm(&dllinfo))
                dlhandle = dlopenqsys(&dllinfo);
        else if (!dl_path_link(&dllinfo,
            "LD_LIBRARY_PATH", filename, dl_is_srvpgm))
                dlhandle = dlopenqsys(&dllinfo);
        else if (!dl_path_link(&dllinfo, "PATH", filename, dl_is_srvpgm))
                dlhandle = dlopenqsys(&dllinfo);
        else if (!dl_DB2_path(&dllinfo, filename) && dl_is_srvpgm(&dllinfo))
                dlhandle = dlopenqsys(&dllinfo);
        else if (!dl_qualified_object(&dllinfo, filename) &&
            dl_is_srvpgm(&dllinfo))
                dlhandle = dlopenqsys(&dllinfo);
        else if (!dl_lib_object(&dllinfo, "*CURLIB", filename) &&
            dl_is_srvpgm(&dllinfo))
                dlhandle = dlopenqsys(&dllinfo);
        else if (!dl_lib_object(&dllinfo, "*LIBL", filename) &&
            dl_is_srvpgm(&dllinfo))
                dlhandle = dlopenqsys(&dllinfo);
        else
                dlhandle = NULL;

        if (!dlhandle && errno)
                dlseterror_from_errno(errno);

        errno = sverrno;
        return dlhandle;
}
