/*
 * Author: 
 *      Guido Draheim <guidod@gmx.de>
 *      Tomi Ollila <too@iki.fi>
 *
 *      Copyright (c) 1999,2000,2001,2002 Guido Draheim
 *          All rights reserved,
 *          use under the restrictions of the 
 *          Lesser GNU General Public License
 *          note the additional license information 
 *          that can be found in COPYING.ZZIP
 */

#include <zzip.h>                                  /* archive handling */
#include <zzip-file.h>
#include <zzipformat.h>

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#ifdef ZZIP_HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

//#include "__mmap.h"
//#include "__debug.h"

/* ------------------------- fetch helpers --------------------------------- */

/**
 * Make 32 bit value in host byteorder from little-endian mapped octet-data
 * (works also on machines which SIGBUS on misaligned data access (eg. 68000))
 */
uint32_t __zzip_get32(unsigned char * s)
{
  return ((uint32_t)s[3] << 24) | ((uint32_t)s[2] << 16)
    |    ((uint32_t)s[1] << 8)  |  (uint32_t)s[0];
}

/** => __zzip_get16
 * This function does the same for a 16 bit value.
 */
uint16_t __zzip_get16(unsigned char * s)
{
    return ((uint16_t)s[1] << 8) | (uint16_t)s[0];
}

/* -------------------------- low-level interface -------------------------- */

#if defined BUFSIZ 
#if BUFSIZ == 1024 || BUFSIZ == 512 || BUFSIZ == 256
#define ZZIP_BUFSIZ BUFSIZ
#endif
#endif

#ifndef ZZIP_BUFSIZ
#define ZZIP_BUFSIZ 512
/* #define ZZIP_BUFSIZ 64 */ /* for testing */
#endif

/**
 * This function is used by => zzip_file_open. It tries to find
 * the zip's central directory info that is usually a few
 * bytes off the end of the file.
 */
int 
__zzip_find_disk_trailer(int fd, zzip_off_t filesize, 
			 struct zzip_disk_trailer * trailer,
			 zzip_plugin_io_t io)
{
#ifdef DEBUG
#define return(val) { e=val; goto cleanup; }
#else
#define return(val) { e=val; goto cleanup; }
#endif
    register int e;
    
#ifndef _LOWSTK
    auto char buffer[2*ZZIP_BUFSIZ];
    char* buf = buffer;
#else
    char* buf = malloc(2*ZZIP_BUFSIZ);
#endif
    zzip_off_t offset = 0;
    size_t maplen = 0;
    char* fd_map = 0;

    if (!trailer)
        { return(EINVAL); }
  
    if (filesize < sizeof(struct zzip_disk_trailer))
        { return(ZZIP_DIR_TOO_SHORT); }
          
    if (!buf)
        { return(ZZIP_OUTOFMEM); }

    offset = filesize; /* a.k.a. old offset */
    while(1) /* outer loop */
    {
        register unsigned char* p;
        register unsigned char* s;

         if (offset <= 0) { return(ZZIP_DIR_EDH_MISSING); }

	 /* trailer cannot be farther away than 64K from fileend */
         if (filesize-offset > 64*1024) 
             { return(ZZIP_DIR_EDH_MISSING); }

	    fd_map = 0; /* have no mmap */
	    {
		zzip_off_t pagesize = ZZIP_BUFSIZ;
		if (offset == filesize && filesize > pagesize)
		    offset -= pagesize;
		if (offset < pagesize) {
		    maplen = offset + pagesize; offset = 0;
		} else {
		    offset -= pagesize; maplen = 2*pagesize;
		    if (offset & (pagesize-1)) { /* only on first run */
			pagesize -= offset & (pagesize-1);
			offset += pagesize;
			maplen -= pagesize; 
		    }    
		}
		if (offset + maplen > filesize) maplen = filesize - offset;
	    }
	    
            if (io->seeks(fd, offset, SEEK_SET) < 0)
                { return(ZZIP_DIR_SEEK); }
            if (io->read(fd, buf, maplen) < (long)maplen)
                { return(ZZIP_DIR_READ); }
            p = buf; /* success */


	/* now, check for the trailer-magic, hopefully near the end of file */
        for (s = p + maplen-1; (s >= p); s--)
        {
            if (*s == 'P'
             && p+maplen-1-s > sizeof(*trailer)-2
             && ZZIP_DISK_TRAILER_CHECKMAGIC(s))
            {
                /* if the file-comment is not present, it happens
                   that the z_comment field often isn't either */
                if (p+maplen-1-s > sizeof(*trailer))
                  { memcpy (trailer, s, sizeof(*trailer)); }
                else
                {
                    memcpy (trailer, s, sizeof(*trailer)-2);
                    trailer->z_comment[0] = 0; trailer->z_comment[1] = 0;
                }
                    
                { return(0); }
            }
        }
        
    } /*outer loop*/
               
 cleanup:
#   ifdef _LOWSTK
    free(buf);
#   endif
#   undef return
    return e; 
}

/*
 * making pointer alignments to values that can be handled as structures
 * is tricky. We assume here that an align(4) is sufficient even for
 * 64 bit machines. Note that binary operations are not usually allowed
 * to pointer types but we do need only the lower bits in this implementation,
 * so we can just cast the value to a long value.
 */
_zzip_inline char* __zzip_aligned4(char* p)
{
#define aligned4   __zzip_aligned4
    p += ((long)p)&1;
    p += ((long)p)&2;
    return p;
}

/**
 * This function is used by => zzip_file_open, it is usually called after
 * => __zzip_find_disk_trailer. It will parse the zip's central directory
 * information and create a zziplib private directory table in
 * memory.
 */
int 
__zzip_parse_root_directory(int fd, 
    struct zzip_disk_trailer * trailer, 
    struct zzip_dir_hdr ** hdr_return,
    zzip_plugin_io_t io)
{
    auto struct zzip_root_dirent dirent;
    struct zzip_dir_hdr * hdr;
    struct zzip_dir_hdr * hdr0;
    uint16_t * p_reclen = 0;
    short entries; 
    long offset;
    char* fd_map = 0;
    int32_t  fd_gap = 0;
    uint16_t u_entries  = ZZIP_GET16(trailer->z_entries);   
    uint32_t u_rootsize = ZZIP_GET32(trailer->z_rootsize);  
    uint32_t u_rootseek = ZZIP_GET32(trailer->z_rootseek);

    hdr0 = (struct zzip_dir_hdr*) malloc(u_rootsize);
    if (!hdr0) 
        return ZZIP_DIRSIZE;
    hdr = hdr0;

#  ifdef DEBUG
    if (sizeof(struct zzip_dir_hdr) > sizeof(struct zzip_root_dirent))
    { WARN1("internal sizeof-mismatch may break wreakage"); }
    /*  the internal directory structure is never bigger than the
     *  external zip central directory space had been beforehand
     *  (as long as the following assertion holds...) 
     */

    if (((unsigned)hdr0)&3)
    { NOTE1("this machine's malloc(3) returns sth. not u32-aligned"); }
    /* we assume that if this machine's malloc has returned a non-aligned 
     * memory block, then it is actually safe to access misaligned data, and 
     * since it does only affect the first hdr it should not even bring about
     * too much of that cpu's speed penalty
     */
#  endif

    for (entries=u_entries, offset=0; entries > 0; entries--)
    {
        register struct zzip_root_dirent * d;
        uint16_t u_extras, u_comment, u_namlen;

        if (fd_map) 
	{ d = (void*)(fd_map+fd_gap+offset); } /* fd_map+fd_gap==u_rootseek */
        else
        {
            if (io->seeks(fd, u_rootseek+offset, SEEK_SET) < 0)
                return ZZIP_DIR_SEEK;
            if (io->read(fd, &dirent, sizeof(dirent)) < sizeof(dirent))
                return ZZIP_DIR_READ;
            d = &dirent;
        }

#       if 0 && defined DEBUG
        zzip_debug_xbuf ((unsigned char*) d, sizeof(*d) + 8);
#       endif        
        
        u_extras  = ZZIP_GET16(d->z_extras); 
        u_comment = ZZIP_GET16(d->z_comment); 
        u_namlen  = ZZIP_GET16(d->z_namlen); 
    
    
        /* writes over the read buffer, Since the structure where data is
           copied is smaller than the data in buffer this can be done.
           It is important that the order of setting the fields is considered
           when filling the structure, so that some data is not trashed in
           first structure read.
           at the end the whole copied list of structures  is copied into
           newly allocated buffer */
        hdr->d_crc32 = ZZIP_GET32(d->z_crc32);
        hdr->d_csize = ZZIP_GET32(d->z_csize); 
        hdr->d_usize = ZZIP_GET32(d->z_usize); 
        hdr->d_off   = ZZIP_GET32(d->z_off);
        hdr->d_compr = (uint8_t)ZZIP_GET16(d->z_compr);
        if (hdr->d_compr > 255) hdr->d_compr = 255;

        if (fd_map) 
          { memcpy(hdr->d_name, fd_map+fd_gap+offset+sizeof(*d), u_namlen); }
        else 
          { io->read(fd, hdr->d_name, u_namlen); }
        hdr->d_name[u_namlen] = '\0'; 
        hdr->d_namlen = u_namlen;
    
        /* update offset by the total length of this entry -> next entry */
        offset += sizeof(*d) + u_namlen + u_extras + u_comment;
    
        if (offset > (long)u_rootsize)
            break;

        p_reclen = &hdr->d_reclen;
    
        {   register char* p = (char*) hdr; 
            register char* q = aligned4 (p + sizeof(*hdr) + u_namlen + 1);
            *p_reclen = q - p;
            hdr = (struct zzip_dir_hdr*) q;
        }
    }/*for*/
    
    if (!p_reclen)
        return 0; /* 0 (sane) entries in zip directory... */
    
    *p_reclen = 0; /* mark end of list */
    
    if (hdr_return) 
        *hdr_return = hdr0;
    
    return 0;
}

/* ------------------------- high-level interface ------------------------- */

#ifndef O_BINARY
#define O_BINARY 0
#endif

static zzip_strings_t* zzip_get_default_ext(void)
{
    static zzip_strings_t ext [] =
    {
       ".zip", ".ZIP", /* common extension */
#  ifdef ZZIP_USE_ZIPLIKES
       ".pk3", ".PK3", /* ID Software's Quake3 zipfiles */
       ".jar", ".JAR", /* Java zipfiles */ 
#  endif
       0
    };

    return ext;
}

/**
 * allocate a new ZZIP_DIR handle and do basic 
 * initializations before usage by => zzip_dir_fdopen
 * => zzip_dir_open => zzip_file_open or through
 * => zzip_open
 * (ext==null flags uses { ".zip" , ".ZIP" } )
 * (io ==null flags use of posix io defaults)
 */
ZZIP_DIR*
zzip_dir_alloc_ext_io (zzip_strings_t* ext, const zzip_plugin_io_t io)
{
    ZZIP_DIR* dir;
    if ((dir = (ZZIP_DIR *)calloc(1, sizeof(*dir))) == NULL)
        return 0; 

    /* dir->fileext is currently unused - so what, still initialize it */
    dir->fileext = ext ? ext : zzip_get_default_ext();
    dir->io = io ? io : zzip_get_default_io ();
    return dir;
}

/** => zzip_dir_alloc_ext_io
 * this function is obsolete - it was generally used for implementation
 * and exported to let other code build on it. It is now advised to
 * use => zzip_dir_alloc_ext_io now on explicitly, just set that second
 * argument to zero to achieve the same functionality as the old style.
 */
ZZIP_DIR*
zzip_dir_alloc (zzip_strings_t* fileext)
{
    return zzip_dir_alloc_ext_io (fileext, 0);
}

/**
 * will free the zzip_dir handle unless there are still 
 * zzip_files attached (that may use its cache buffer).
 * This is the inverse of => zzip_dir_alloc , and both
 * are helper functions used implicitly in other zzipcalls
 * e.g. => zzip_dir_close = zzip_close 
 *
 * returns zero on sucess
 * returns the refcount when files are attached.
 */
int 
zzip_dir_free(ZZIP_DIR * dir)
{
    if (dir->refcount)
        return (dir->refcount); /* still open files attached */

    if (dir->fd >= 0)      dir->io->close(dir->fd);
    if (dir->hdr0)         free(dir->hdr0);
    if (dir->cache.fp)     free(dir->cache.fp);
    if (dir->cache.buf32k) free(dir->cache.buf32k);
    if (dir->realname)     free(dir->realname);
    free(dir);
    return 0;
}

/**
 * It will also => free(2) the => ZZIP_DIR-handle given. 
 * the counterpart for => zzip_dir_open
 * see also => zzip_dir_free
 */
int 
zzip_dir_close(ZZIP_DIR * dir)
{
    dir->refcount &=~ 0x10000000; /* explicit dir close */
    return zzip_dir_free(dir);
}

/** 
 * used by the => zzip_dir_open and zzip_opendir(2) call. Opens the
 * zip-archive as specified with the fd which points to an
 * already openend file. This function then search and parse
 * the zip's central directory.
 * <p> 
 * NOTE: refcount is zero, so an _open/_close pair will also delete 
 *       this _dirhandle 
 */
ZZIP_DIR * 
zzip_dir_fdopen(int fd, zzip_error_t * errcode_p)
{
    return zzip_dir_fdopen_ext_io(fd, errcode_p, 0, 0);
}

static zzip_error_t __zzip_dir_parse (ZZIP_DIR* dir); /* forward */

/** => zzip_dir_fdopen
 * this function uses explicit ext and io instead of the internal 
 * defaults, setting these to zero is equivalent to => zzip_dir_fdopen
 */
ZZIP_DIR * 
zzip_dir_fdopen_ext_io(int fd, zzip_error_t * errcode_p,
                       zzip_strings_t* ext, const zzip_plugin_io_t io)
{
    zzip_error_t rv;
    ZZIP_DIR * dir;

    if ((dir = zzip_dir_alloc_ext_io (ext, io)) == NULL)
        { rv = ZZIP_OUTOFMEM; goto error; }

    dir->fd = fd;
    if ((rv = __zzip_dir_parse (dir)))
	goto error;

    dir->hdr = dir->hdr0;
    dir->refcount |= 0x10000000; 
  
    if (errcode_p) *errcode_p = rv;
    return dir;
error:
    if (dir) zzip_dir_free(dir);
    if (errcode_p) *errcode_p = rv;
    return NULL;
}

static zzip_error_t
__zzip_dir_parse (ZZIP_DIR* dir)
{
    zzip_error_t rv;
    zzip_off_t filesize;
    struct zzip_disk_trailer trailer;
    /* if (! dir || dir->fd < 0) 
     *     { rv = EINVAL; goto error; } 
     */

    if ((filesize = dir->io->filesize(dir->fd)) < 0)
        { rv = ZZIP_DIR_STAT; goto error; }

    if ((rv = __zzip_find_disk_trailer(dir->fd, filesize, &trailer, 
                                       dir->io)) != 0)
        { goto error; }
                
    
    if ( (rv = __zzip_parse_root_directory(dir->fd, &trailer, &dir->hdr0, 
                                           dir->io)) != 0)
        { goto error; }
 error:
    return rv;
}

/**
 * will attach a .zip extension and tries to open it
 * the with => open(2). This is a helper function for
 * => zzip_dir_open, => zzip_opendir and => zzip_open.
 */
int
__zzip_try_open(zzip_char_t* filename, int filemode, 
                zzip_strings_t* ext, zzip_plugin_io_t io)
{
    auto char file[PATH_MAX];
    int fd;
    int len = strlen (filename);
    
    if (len+4 >= PATH_MAX) return -1;
    memcpy(file, filename, len+1);

    if (!io) io = zzip_get_default_io();
    if (!ext) ext = zzip_get_default_ext();

    for ( ; *ext ; ++ext)
    {
        strcpy (file+len, *ext);
        fd = io->open(file, filemode);
        if (fd != -1) return fd;
    }
    return -1;
}    

/**
 * Opens the zip-archive (if available).
 * the two ext_io arguments will default to use posix io and 
 * a set of default fileext that can atleast add .zip ext itself.
 */
ZZIP_DIR* 
zzip_dir_open(zzip_char_t* filename, zzip_error_t* e)
{
    return zzip_dir_open_ext_io (filename, e, 0, 0);
}

/** => zzip_dir_open
 * this function uses explicit ext and io instead of the internal 
 * defaults. Setting these to zero is equivalent to => zzip_dir_open
 */
ZZIP_DIR* 
zzip_dir_open_ext_io(zzip_char_t* filename, zzip_error_t* e,
                     zzip_strings_t* ext, zzip_plugin_io_t io)
{
    int fd;

    if (!io) io = zzip_get_default_io();
    if (!ext) ext = zzip_get_default_ext();

    fd = io->open(filename, O_RDONLY|O_BINARY);
    if (fd != -1) 
      { return zzip_dir_fdopen_ext_io(fd, e, ext, io); }
    else
    {
        fd = __zzip_try_open(filename, O_RDONLY|O_BINARY, ext, io);
        if (fd != -1) 
          { return zzip_dir_fdopen_ext_io(fd, e, ext, io); }
        else
        {
            if (e) { *e = ZZIP_DIR_OPEN; } 
            return 0; 
        }
    }
}

/**
 * fills the dirent-argument with the values and 
 * increments the read-pointer of the dir-argument.
 * <p>
 * returns 0 if there no entry (anymore).
 */
int
zzip_dir_read(ZZIP_DIR * dir, ZZIP_DIRENT * d )
{
    if (! dir || ! dir->hdr || ! d) return 0;

    d->d_compr = dir->hdr->d_compr;
    d->d_csize = dir->hdr->d_csize;
    d->st_size = dir->hdr->d_usize;
    d->d_name  = dir->hdr->d_name;

    if (! dir->hdr->d_reclen) 
    { dir->hdr = 0; }
    else  
    { dir->hdr = (struct zzip_dir_hdr *)((char *)dir->hdr + dir->hdr->d_reclen); }
  
    return 1;
}

/* 
 * Local variables:
 * c-file-style: "stroustrup"
 * End:
 */
