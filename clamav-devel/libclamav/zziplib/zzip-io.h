/*
 * Author: 
 *	Guido Draheim <guidod@gmx.de>
 *
 *	Copyright (c) 2002 Guido Draheim
 * 	    All rights reserved
 *	    use under the restrictions of the
 *	    Lesser GNU General Public License
 *          note the additional license information 
 *          that can be found in COPYING.ZZIP
 *
 *  the interfaces for the plugin_io system
 *
 * Using the following you can provide your own file I/O functions to
 * e.g. read data directly from memory, provide simple
 * "encryption"/"decryption" of on-disk .zip-files...
 * Note that this currently only provides a subset of the functionality
 * in zziplib. It does not attempt to provide any directory functions,
 * but if your program 1) only uses ordinary on-disk files and you
 * just want this for file obfuscation, or 2) you only access your
 * .zip archives using zzip_open & co., this is sufficient.
 *
 * Currently the default io are the POSIX functions, except
 * for 'filesize' that is zziplibs own provided zzip_filesize function,
 * using standard POSIX fd's. You are however free to replace this with
 * whatever data type you need, so long as you provide implementations
 * for all the functions, and the data type fits an int.
 *
 * all functions receiving ext_io are able to cope with both arguments
 * set to zero which will let them default to a ZIP ext and posix io.
 */
#ifndef _ZZIP_IO_H
#define _ZZIP_IO_H

#include <zzip-conf.h>
#include <zziplib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct zzip_plugin_io
{
    int        (*open)(zzip_char_t* name, int flags, ...);
    int        (*close)(int fd);
    int        (*read)(int fd, void* buf, unsigned int len);
    zzip_off_t (*seeks)(int fd, zzip_off_t offset, int whence);
    zzip_off_t (*filesize)(int fd);
    long       use_mmap;
};

_zzip_export zzip_off_t
zzip_filesize(int fd);

/* get the default file I/O functions */
_zzip_export zzip_plugin_io_t zzip_get_default_io(void);

/*
 * Initializes a zzip_plugin_io_t to the zziplib default io.
 * This is useful if you only want to override e.g. the 'read' function.
 * all zzip functions that can receive a zzip_plugin_io_t can
 * handle a zero pointer in that place and default to posix io.
 */
_zzip_export
int zzip_init_io(struct zzip_plugin_io* io, int flags);

/* zzip_init_io flags : */
# define ZZIP_IO_USE_MMAP 1

#ifdef __cplusplus
};
#endif

#endif
