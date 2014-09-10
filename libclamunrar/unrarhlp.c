/*
 *  Copyright (C) 2007 Sourcefire, Inc.
 *
 *  The unRAR sources may be used in any software to handle RAR
 *  archives without limitations free of charge, but cannot be used
 *  to re-create the RAR compression algorithm, which is proprietary.
 *  Distribution of modified unRAR sources in separate form or as a
 *  part of other software is permitted, provided that it is clearly
 *  stated in the documentation and source comments that the code may
 *  not be used to develop a RAR (WinRAR) compatible archiver.
 */

#include <stdio.h>
#include <stdlib.h>

#include "libclamunrar/unrarhlp.h"

#ifdef RAR_HIGH_DEBUG
#define rar_dbgmsg printf
#else
static void rar_dbgmsg(const char* fmt,...){}
#endif

#define RAR_MAX_ALLOCATION 184549376

void *rar_malloc(size_t size)
{
	void *alloc;


    if(!size || size > RAR_MAX_ALLOCATION) {
	rar_dbgmsg("UNRAR: rar_malloc(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", size);
	return NULL;
    }

    alloc = malloc(size);

    if(!alloc) {
	fprintf(stderr, "UNRAR: rar_malloc(): Can't allocate memory (%lu bytes).\n", size);
	return NULL;
    } else return alloc;
}

void *rar_realloc2(void *ptr, size_t size)
{
	void *alloc;


    if(!size || size > RAR_MAX_ALLOCATION) {
	rar_dbgmsg("UNRAR: rar_realloc2(): Attempt to allocate %lu bytes. Please report to http://bugs.clamav.net\n", size);
	return NULL;
    }

    alloc = realloc(ptr, size);

    if(!alloc) {
	fprintf(stderr, "UNRAR: rar_realloc2(): Can't allocate memory (%lu bytes).\n", size);
	if(ptr)
	    free(ptr);
	return NULL;
    } else return alloc;
}
