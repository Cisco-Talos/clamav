/**
***     dlopen(), dlclose() dlsym(), dlerror() emulation for OS/400.
***
***     See Copyright for the status of this software.
***
***     Author: Patrick Monnerat <pm@datasphere.ch>, DATASPHERE S.A.
**/

#ifndef _DLFCN_H_
#define _DLFCN_H_


/**
***     Flags for dlopen().
***     Ignored for OS400.
**/

#define RTLD_LAZY               000
#define RTLD_NOW                001
#define RTLD_GLOBAL             010


/**
***     Prototypes.
**/

extern void *           dlopen(const char * filename, int flag);
extern void *           dlsym(void * handle, const char * symbol);
extern const char *     dlerror(void);
extern int              dlclose(void * handle);

#endif
