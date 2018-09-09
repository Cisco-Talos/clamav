/**
***     Replace system/C library calls by EBCDIC wrappers.
***     This is a layer inserted between libxml2 itself and the EBCDIC
***             environment.
***
***     See Copyright for the status of this software.
***
***     Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.
**/

#ifndef __WRAPPERS_H_
#define __WRAPPERS_H_

/**
***     OS/400 specific defines.
**/

#define __cplusplus__strings__

/**
***     Force header inclusions before renaming procedures to UTF-8 wrappers.
**/

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "dlfcn.h"


/**
***     UTF-8 wrappers prototypes.
**/

extern int      _lx_getaddrinfo(const char * node, const char * service,
                        const struct addrinfo * hints, struct addrinfo * * res);
extern const char *
                _lx_inet_ntop(int af,
                        const void * src, char * dst, socklen_t size);
extern void *   _lx_dlopen(const char * filename, int flag);
extern void *   _lx_dlsym(void * handle, const char * symbol);
extern char *   _lx_dlerror(void);


#ifdef LIBXML_ZLIB_ENABLED

#include <zlib.h>

extern gzFile   _lx_gzopen(const char * path, const char * mode);
extern gzFile   _lx_gzdopen(int fd, const char * mode);

#endif


/**
***     Rename data/procedures to UTF-8 wrappers.
**/

#define getaddrinfo     _lx_getaddrinfo
#define inet_ntop       _lx_inet_ntop
#define dlopen          _lx_dlopen
#define dlsym           _lx_dlsym
#define dlerror         _lx_dlerror
#define gzopen          _lx_gzopen
#define gzdopen         _lx_gzdopen
#define inflateInit2_   _lx_inflateInit2_
#define deflateInit2_   _lx_deflateInit2_

#endif
