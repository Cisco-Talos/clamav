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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "target.h"

#include <zzip.h>                                  /* archive handling */
#include <zzip-file.h>
#include <zzipformat.h>

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "others.h"

/*
#include "__mmap.h"
#include "__debug.h"
*/

#define __sizeof(X) ((zzip_ssize_t)(sizeof(X)))

/* per default, we use a little hack to correct bad z_rootseek parts */
#define ZZIP_CORRECT_ROOTSEEK 1

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

/** => __zzip_get32
 * This function does the same for a 16 bit value.
 */
uint16_t __zzip_get16(unsigned char * s)
{
    return ((uint16_t)s[1] << 8) | (uint16_t)s[0];
}

/* ---------------------------  internals  -------------------------------- */
/* internal functions of zziplib, avoid at all cost, changes w/o warning.
 * we do export them for debugging purpose and special external tools
 * which know what they do and which can adapt from version to version
 */

int __zzip_find_disk_trailer( int fd, zzip_off_t filesize, 
			      struct zzip_disk_trailer * trailer,
			      zzip_plugin_io_t io);
int __zzip_parse_root_directory( int fd, 
				 struct zzip_disk_trailer * trailer, 
				 struct zzip_dir_hdr ** hdr_return,
				 zzip_plugin_io_t io);

_zzip_inline char* __zzip_aligned4(char* p);

/* ------------------------  harden routines ------------------------------ */

#ifdef ZZIP_HARDEN
/*
 * check for inconsistent values in trailer and prefer lower seek value
 * - we fix values assuming the root directory was written at the end
 * and it is just before the zip trailer. Therefore, ...
 */
_zzip_inline static void __fixup_rootseek(
    zzip_off_t offset_of_trailer,
    struct zzip_disk_trailer* trailer)
{
    if (                    (zzip_off_t) ZZIP_GET32(trailer->z_rootseek) >
	offset_of_trailer - (zzip_off_t) ZZIP_GET32(trailer->z_rootsize) &&
	offset_of_trailer > (zzip_off_t) ZZIP_GET32(trailer->z_rootsize))
    {
	register zzip_off_t offset;
	offset = offset_of_trailer -  ZZIP_GET32(trailer->z_rootsize); 
	trailer->z_rootseek[0] = offset & 0xff;
	trailer->z_rootseek[1] = offset >> 8 & 0xff;
	trailer->z_rootseek[2] = offset >> 16 & 0xff;
	trailer->z_rootseek[3] = offset >> 24 & 0xff;
	/*
	HINT2("new rootseek=%li", 
	        (long) ZZIP_GET32(trailer->z_rootseek));
	*/
    }
}
#define __correct_rootseek(A,B,C)

#elif defined ZZIP_CORRECT_ROOTSEEK
/* store the seekvalue of the trailer into the "z_magic" field and with 
 * a 64bit off_t we overwrite z_disk/z_finaldisk as well. If you change
 * anything in zziplib or dump the trailer structure then watch out that
 * these are still unused, so that this code may still (ab)use those. */
#define __fixup_rootseek(_offset_of_trailer, _trailer)          \
                      *(zzip_off_t*)_trailer = _offset_of_trailer;
#define __correct_rootseek( _u_rootseek, _u_rootsize, _trailer) \
    if (_u_rootseek > *(zzip_off_t*)_trailer - _u_rootsize)     \
	_u_rootseek = *(zzip_off_t*)_trailer - _u_rootsize;
#else
#define __fixup_rootseek(A,B) 
#define __correct_rootseek(A,B,C)
#endif


#ifdef DEBUG
_zzip_inline static void __debug_dir_hdr (struct zzip_dir_hdr* hdr)
{
    if (sizeof(struct zzip_dir_hdr) > sizeof(struct zzip_root_dirent))
    { WARN1("internal sizeof-mismatch may break wreakage"); }
    /*  the internal directory structure is never bigger than the
     *  external zip central directory space had been beforehand
     *  (as long as the following assertion holds...) 
     */

    /*
    if (((unsigned)hdr)&3)
    { NOTE1("this machine's malloc(3) returns sth. not u32-aligned"); }
    */
    
    /* we assume that if this machine's malloc has returned a non-aligned 
     * memory block, then it is actually safe to access misaligned data, and 
     * since it does only affect the first hdr it should not even bring about
     * too much of that cpu's speed penalty
     */
}
#else
#define __debug_dir_hdr(X)
#endif

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
/*
#ifdef DEBUG
#define return(val) { e=val; HINT2("%s", zzip_strerror(e)); goto cleanup; }
#else
*/
#define return(val) { e=val; goto cleanup; }
/*
#endif
*/
    register int e;
    
#ifndef _LOWSTK
    auto char buffer[2*ZZIP_BUFSIZ];
    char* buf = buffer;
#else
    char* buf = cli_malloc(2*ZZIP_BUFSIZ);
#endif
    zzip_off_t offset = 0;
    zzip_off_t maplen = 0; /* mmap(),read(),getpagesize() use size_t !! */
    char* fd_map = 0;

    if (!trailer)
        { return(EINVAL); }
  
    if (filesize < __sizeof(struct zzip_disk_trailer))
        { return(ZZIP_DIR_TOO_SHORT); }
          
    if (!buf)
        { return(ZZIP_OUTOFMEM); }

    offset = filesize; /* a.k.a. old offset */
    while(1) /* outer loop */
    {
        register unsigned char* mapped;

         if (offset <= 0) { return(ZZIP_DIR_EDH_MISSING); }

	 /* trailer cannot be farther away than 64K from fileend */
         if (filesize-offset > 64*1024) 
             { return(ZZIP_DIR_EDH_MISSING); }

	/* the new offset shall overlap with the area after the old offset! */
        /*if (USE_MMAP && io->use_mmap)
        {
	    zzip_off_t mapoff = offset;
	    { 
		zzip_off_t pagesize = _zzip_getpagesize (io->use_mmap);
		if (pagesize < ZZIP_BUFSIZ) goto non_mmap;
		if (mapoff == filesize && filesize > pagesize) 
		    mapoff -= pagesize;
		if (mapoff < pagesize) {
		    maplen = mapoff + pagesize; mapoff = 0;
		} else {               
		    mapoff -= pagesize; maplen = 2*pagesize; 
		    if (mapoff & (pagesize-1)) {
			pagesize -= mapoff & (pagesize-1);
			mapoff += pagesize;
			maplen -= pagesize;
		    }   
		}
		if (mapoff + maplen > filesize) maplen = filesize - mapoff;
	    }

            fd_map = _zzip_mmap(io->use_mmap, fd, mapoff, (zzip_size_t)maplen);
            if (fd_map == MAP_FAILED) goto non_mmap;
	    mapped = fd_map; offset = mapoff;
	    HINT3("mapped *%p len=%li", fd_map, (long) maplen);
        } else */ {
        /* non_mmap: */
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
            if (io->read(fd, buf, (zzip_size_t)maplen) < (zzip_ssize_t)maplen)
                { return(ZZIP_DIR_READ); }
            mapped = (unsigned char *) buf; /* success */
	    /*
	    HINT5("offs=$%lx len=%li filesize=%li pagesize=%i", 
		(long)offset, (long)maplen, (long)filesize, ZZIP_BUFSIZ);
	    */
        }

	{/* now, check for the trailer-magic, hopefully near the end of file */
	    register unsigned char* end = mapped + maplen;
	    register unsigned char* tail;
	    for (tail = end-1; (tail >= mapped); tail--)
	    {
		if ((*tail == 'P') && /* quick pre-check for trailer magic */
		    end-tail >= __sizeof(*trailer)-2 &&
		    ZZIP_DISK_TRAILER_CHECKMAGIC(tail))
		{
		    /* if the file-comment is not present, it happens
		       that the z_comment field often isn't either */
		    if (end-tail >= __sizeof(*trailer))
		    {
			memcpy (trailer, tail, sizeof(*trailer)); 
		    }else{
			memcpy (trailer, tail, sizeof(*trailer)-2);
			trailer->z_comment[0] = 0; 
			trailer->z_comment[1] = 0;
		    }

		    __fixup_rootseek (offset + tail-mapped, trailer);
		    { return(0); }
		}
	    }
        }
        
         /*if (USE_MMAP && fd_map) 
	 { 
	     HINT3("unmap *%p len=%li",  fd_map, (long) maplen);
	     _zzip_munmap(io->use_mmap, fd_map, (zzip_size_t)maplen); fd_map = 0; 
	 }*/
    } /*outer loop*/
               
 cleanup:
    /*if (USE_MMAP && fd_map)
    { 
	HINT3("unmap *%p len=%li",  fd_map, (long) maplen);
	_zzip_munmap(io->use_mmap, fd_map, (zzip_size_t)maplen); 
    }*/
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
    p += ((long)p)&1;            /* warnings about truncation of a "pointer" */
    p += ((long)p)&2;            /* to a "long int" may be safely ignored :) */
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
    long offset;          /* offset from start of root directory */
    char* fd_map = 0; 
    int32_t  fd_gap = 0;
    struct stat sb;
    uint16_t u_entries  = ZZIP_GET16(trailer->z_entries);   
    uint32_t u_rootsize = ZZIP_GET32(trailer->z_rootsize);  
    uint32_t u_rootseek = ZZIP_GET32(trailer->z_rootseek);
    __correct_rootseek (u_rootseek, u_rootsize, trailer);

    if(fstat(fd, &sb) == -1) {
	cli_errmsg("zziplib: Can't fstat file descriptor %d\n", fd);
	return ZZIP_DIR_STAT;
    }

    if(u_rootsize > sb.st_size) {
	cli_errmsg("zziplib: Incorrect root size\n");
	return ZZIP_CORRUPTED;
    }

    hdr0 = (struct zzip_dir_hdr*) cli_malloc(u_rootsize);
    if (!hdr0) 
        return ZZIP_DIRSIZE;
    hdr = hdr0;                  __debug_dir_hdr (hdr);

    /*if (USE_MMAP && io->use_mmap)
    {
        fd_gap = u_rootseek & (_zzip_getpagesize(io->use_mmap)-1) ;
        HINT4(" mapseek=0x%x, maplen=%d, fd_gap=%d", 
	      u_rootseek-fd_gap, u_rootsize+fd_gap, fd_gap);
        fd_map = _zzip_mmap(io->use_mmap, 
			    fd, u_rootseek-fd_gap, u_rootsize+fd_gap);
        if (fd_map == MAP_FAILED) { 
            NOTE2("map failed: %s",strerror(errno)); 
            fd_map=0; 
	}else{
	    HINT3("mapped *%p len=%i", fd_map, u_rootsize+fd_gap);
	}
    }*/

    for (entries=u_entries, offset=0; entries > 0; entries--)
    {
        register struct zzip_root_dirent * d;
        uint16_t u_extras, u_comment, u_namlen;
	uint16_t u_flags;

        if (fd_map) 
	{ d = (void*)(fd_map+fd_gap+offset); } /* fd_map+fd_gap==u_rootseek */
        else
        {
            if (io->seeks(fd, u_rootseek+offset, SEEK_SET) < 0) {
		free(hdr0);
                return ZZIP_DIR_SEEK;
	    }
            if (io->read(fd, &dirent, sizeof(dirent)) < __sizeof(dirent)) {
		if(entries != u_entries) {
		    entries = 0;
		    break;
		} else {
		    free(hdr0);
		    return ZZIP_DIR_READ;
		}
	    }
            d = &dirent;
        }

	if (offset+sizeof(*d) > u_rootsize)
	{ /*FAIL2("%i's entry stretches beyond root directory", entries);*/ break;}

#       if 0 && defined DEBUG
        zzip_debug_xbuf ((unsigned char*) d, sizeof(*d) + 8);
#       endif        
        
        u_extras  = ZZIP_GET16(d->z_extras); 
        u_comment = ZZIP_GET16(d->z_comment); 
        u_namlen  = ZZIP_GET16(d->z_namlen); 
	u_flags   = ZZIP_GET16(d->z_flags);
        /*HINT5("offset=0x%lx, size %ld, dirent *%p, hdr %p\n",
	      offset+u_rootseek, (long)u_rootsize, d, hdr);
	*/
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
        if(hdr->d_off < 0)
        {
                free(hdr0);
                return ZZIP_DIR_READ;
        }
        hdr->d_compr = (uint8_t)ZZIP_GET16(d->z_compr);

	/* If d_compr is incorrect scanning will result in CL_EZIP (Zip
	 * module failure)
	 */
	if(!hdr->d_compr && hdr->d_csize != hdr->d_usize) {
	    cli_dbgmsg("Zziplib: File claims to be stored but csize != usize\n");
	    cli_dbgmsg("Zziplib: Switching to the inflate method\n");
	    hdr->d_compr = 8;
	} else if(hdr->d_compr && hdr->d_csize == hdr->d_usize) {
	    cli_dbgmsg("Zziplib: File claims to be deflated but csize == usize\n");
	    cli_dbgmsg("Zziplib: Switching to the stored method\n");
	    hdr->d_compr = 0;
	}

	hdr->d_flags = u_flags;

        /* bull: hdr->d_compr is uint8_t
	 * if (hdr->d_compr > 255) hdr->d_compr = 255; */

	if (offset+sizeof(*d) + u_namlen > u_rootsize)
	{ /*FAIL2("%i's name stretches beyond root directory", entries);*/ break;}

	if (fd_map) 
	{  memcpy(hdr->d_name, fd_map+fd_gap+offset+sizeof(*d), u_namlen); }
	else { io->read(fd, hdr->d_name, u_namlen); }
        hdr->d_name[u_namlen] = '\0'; 
        hdr->d_namlen = u_namlen;
    
        /* update offset by the total length of this entry -> next entry */
        offset += sizeof(*d) + u_namlen + u_extras + u_comment;
    
        if (offset > (long)u_rootsize)
	{ /*FAIL2("%i's end beyond root directory", entries);*/ entries--; break;}

        /*
        HINT5("file %d { compr=%d crc32=$%x offset=%d", 
	      entries,  hdr->d_compr, hdr->d_crc32, hdr->d_off);
        HINT5("csize=%d usize=%d namlen=%d extras=%d", 
	      hdr->d_csize, hdr->d_usize, u_namlen, u_extras);
        HINT5("comment=%d name='%s' %s <sizeof %d> } ", 
	      u_comment, hdr->d_name, "",(int) sizeof(*d));
	*/
  
        p_reclen = &hdr->d_reclen;
    
        {   register char* p = (char*) hdr; 
            register char* q = aligned4 (p + sizeof(*hdr) + u_namlen + 1);
            *p_reclen = (uint16_t)(q - p);
            hdr = (struct zzip_dir_hdr*) q;
        }
    }/*for*/
    
    /*if (USE_MMAP && fd_map) 
    {
	HINT3("unmap *%p len=%i",   fd_map, u_rootsize+fd_gap);
        _zzip_munmap(io->use_mmap, fd_map, u_rootsize+fd_gap);
    }*/
    
    if (p_reclen)
    {
	*p_reclen = 0; /* mark end of list */
    
	if (hdr_return) 
	    *hdr_return = hdr0;
    } else free(hdr0); /* else zero (sane) entries */

    return (entries ?  ZZIP_CORRUPTED : 0);
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
    if ((dir = (ZZIP_DIR *)cli_calloc(1, sizeof(*dir))) == NULL)
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
#if (defined(TARGET_CPU_SPARC64) || defined(TARGET_CPU_SPARC)) && defined(HAVE_ATTRIB_ALIGNED)
    struct zzip_disk_trailer trailer __attribute__((aligned));
#else
    struct zzip_disk_trailer trailer;
#endif
    /* if (! dir || dir->fd < 0) 
     *     { rv = EINVAL; goto error; } 
     */

    /*
    HINT2("------------------ fd=%i", (int) dir->fd);
    */
    if ((filesize = dir->io->filesize(dir->fd)) < 0)
        { rv = ZZIP_DIR_STAT; goto error; }

    /*
    HINT2("------------------ filesize=%ld", (long) filesize);
    */
    if ((rv = __zzip_find_disk_trailer(dir->fd, filesize, &trailer, 
                                       dir->io)) != 0)
        { goto error; }
                
    /*
    HINT5("directory = { entries= %d/%d, size= %d, seek= %d } ", 
	  ZZIP_GET16(trailer.z_entries),  ZZIP_GET16(trailer.z_finalentries),
	  ZZIP_GET32(trailer.z_rootsize), ZZIP_GET32(trailer.z_rootseek));
    */
    
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
    zzip_size_t len = strlen (filename);
    
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
    d->d_flags = dir->hdr->d_flags;
    d->d_off   = dir->hdr->d_off;
    d->d_crc32 = (int) dir->hdr->d_crc32;

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
