/**
***     UTF-8/EBCDIC wrappers to system and C library procedures.
***
***     See Copyright for the status of this software.
***
***     Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.
**/

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <netdb.h>
#include <errno.h>

#include "config.h"

#include "libxml/xmlmemory.h"

#include "transcode.h"


static const char *     lxdles = NULL;


int
_lx_getaddrinfo(const char * node, const char * service,
        const struct addrinfo * hints, struct addrinfo * * res)

{
        xmlDictPtr d = NULL;
        int i;

        i = getaddrinfo(xmlTranscodeResult(node, NULL, &d, NULL),
            xmlTranscodeResult(service, NULL, &d, NULL), hints, res);
        xmlZapDict(&d);
        return i;
}


const char *
_lx_inet_ntop(int af, const void * src, char * dst, socklen_t size)

{
        const char * cp1 = inet_ntop(af, src, dst, size);
        char const * cp2;
        int i;

        if (!cp1)
                return cp1;

        if (!(cp2 = xmlTranscodeString(cp1, NULL, NULL)))
                return cp2;

        i = strlen(cp2);

        if (i >= size) {
                xmlFree((char *) cp2);
                errno = ENOSPC;
                return (const char *) NULL;
                }

        memcpy(dst, cp2, i + 1);
        xmlFree((char *) cp2);
        return dst;
}


void *
_lx_dlopen(const char * filename, int flag)

{
        xmlDictPtr d = NULL;
        void * result;

        result = dlopen(xmlTranscodeResult(filename, NULL, &d, NULL), flag);
        xmlZapDict(&d);
        return result;
}


void *
_lx_dlsym(void * handle, const char * symbol)

{
        xmlDictPtr d = NULL;
        void * result;

        result = dlsym(handle, xmlTranscodeResult(symbol, NULL, &d, NULL));
        xmlZapDict(&d);
        return result;
}


char *
_lx_dlerror(void)

{
        char * cp1 = (char *) dlerror();

        if (!cp1)
                return cp1;

        if (lxdles)
                xmlFree((char *) lxdles);

        lxdles = (const char *) xmlTranscodeString(cp1, NULL, NULL);
        return (char *) lxdles;
}


#ifdef LIBXML_ZLIB_ENABLED
#include <zlib.h>

gzFile
_lx_gzopen(const char * path, const char * mode)

{
        xmlDictPtr d = NULL;
        gzFile f;

        f = gzopen(xmlTranscodeResult(path, NULL, &d, NULL),
            xmlTranscodeResult(mode, NULL, &d, NULL));
        xmlZapDict(&d);
        return f;
}


gzFile
_lx_gzdopen(int fd, const char * mode)

{
        xmlDictPtr d = NULL;
        gzFile f;

        f = gzdopen(fd, xmlTranscodeResult(mode, NULL, &d, NULL));
        xmlZapDict(&d);
        return f;
}

int
_lx_inflateInit2_(z_streamp strm, int windowBits,
                                        const char * version, int stream_size)

{
        xmlDictPtr d = NULL;
        int r;

        r = inflateInit2_(strm, windowBits,
            xmlTranscodeResult(version, NULL, &d, NULL), stream_size);
        xmlZapDict(&d);
        return r;
}

int
_lx_deflateInit2_(z_streamp strm, int level, int method, int windowBits,
        int memLevel, int strategy, const char * version, int stream_size)

{
        xmlDictPtr d = NULL;
        int r;

        r = deflateInit2_(strm, level, method, windowBits, memLevel, strategy,
            xmlTranscodeResult(version, NULL, &d, NULL), stream_size);
        xmlZapDict(&d);
        return r;
}

#endif
