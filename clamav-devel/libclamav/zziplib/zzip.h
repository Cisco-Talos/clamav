/*
 * Author: 
 *      Guido Draheim <guidod@gmx.de>
 *      Tomi Ollila <Tomi.Ollila@iki.fi>
 *
 *      Copyright (c) 1999,2000,2001,2002 Guido Draheim
 *          All rights reserved
 *          use under the restrictions of the
 *          Lesser GNU General Public License
 *          note the additional license information 
 *          that can be found in COPYING.ZZIP
 *
 * This is the private header containing definitions that are not
 * use by a libzzip user application. Writing an extension lib that
 * uses libzzip will still want to include this. The extension
 * write should make way to have the ISO C9X integer types defined.
 */
#ifndef _ZZIP_LIB_H /* zzip.h */
#define _ZZIP_LIB_H

#include <zziplib.h>
#include <zzip-io.h>
#include <zzip-stdint.h>

/*
 * this structure cannot be wildly enlarged... (see zzip-zip.c)
 */
struct zzip_dir_hdr
{
    uint32_t    d_usize;        /* uncompressed size */
    uint32_t    d_csize;        /* compressed size */
    uint32_t    d_crc32;        /* the adler32-checksum */
    uint32_t    d_off;          /* offset of file in zipfile */
    uint16_t    d_reclen;       /* next dir_hdr structure offset */
    uint16_t    d_namlen;       /* explicit namelen of d_name */
    uint8_t     d_compr;        /* the compression type, 0 = store, 8 = inflate */
    char        d_name[1];      /* the actual name of the entry, may contain DIRSEPs */
};
#define _ZZIP_DIRENT_HAVE_D_NAMLEN
#define _ZZIP_DIRENT_HAVE_D_OFF
#define _ZZIP_DIRENT_HAVE_D_RECLEN

/*
 * you shall not use this struct anywhere else than in zziplib sources.
 */
struct zzip_dir
{
    int fd;
    int errcode; /* zzip_error_t */
    long refcount;
    struct {
        struct zzip_file * fp;  /* reduce a lot of alloc/deallocations by */
        char * buf32k;         /* caching one entry of these data structures */
    } cache;
    struct zzip_dir_hdr * hdr0;  /* zfi; */
    struct zzip_dir_hdr * hdr;   /* zdp; directory pointer, for dirent stuff */
    struct zzip_file * currentfp; /* last fp used... */
    struct zzip_dirent dirent;
    void*  realdir;               /* e.g. DIR* from posix dirent.h */
    char*  realname;
    zzip_strings_t* fileext;      /* list of fileext to test for */
    zzip_plugin_io_t io;          /* vtable for io routines */
}; 

#define ZZIP_32K 32768

/* try to open a zip-basename with default_fileext */
int      __zzip_try_open (zzip_char_t* filename, int filemode,
                          zzip_strings_t* ext, zzip_plugin_io_t io);

ZZIP_DIR * 
zzip_dir_fdopen(int fd, zzip_error_t * errcode_p);

ZZIP_DIR* 
zzip_dir_fdopen_ext_io(int fd, zzip_error_t * errorcode_p,
                       zzip_strings_t* ext, const zzip_plugin_io_t io);

ZZIP_DIR* /*depracated*/
zzip_dir_alloc_ext_io (zzip_strings_t* ext, const zzip_plugin_io_t io);

/* get 16/32 bits from little-endian zip-file to host byteorder */
uint32_t __zzip_get32(unsigned char * s);
uint16_t __zzip_get16(unsigned char * s);

#ifdef __i386__
#define ZZIP_GET32(x) (*(uint32_t*)(x))
#define ZZIP_GET16(x) (*(uint16_t*)(x))
#else
#define ZZIP_GET32(x) (__zzip_get32(x))
#define ZZIP_GET16(x) (__zzip_get16(x))
#endif

#endif /* _ZZIP_H */

