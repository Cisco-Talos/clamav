#include <stdio.h>
/*
 * Author: 
 *	Guido Draheim <guidod@gmx.de>
 *
 *	Copyright (c) 1999,2000,2001,2002 Guido Draheim
 * 	    All rights reserved,
 *	    use under the restrictions of the
 *	    Lesser GNU General Public License
 *          note the additional license information 
 *          that can be found in COPYING.ZZIP
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <zzip.h>                                   /* exported... */
#include <zzip-file.h>
#include <stddef.h> /* offsetof */
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef ZZIP_HAVE_SYS_STAT_H
#include <sys/stat.h>
#else
#include <stdio.h>
#endif

/*
#include "__dirent.h"
*/

#ifndef offsetof
#pragma warning had to DEFINE offsetof as it was not in stddef.h
#define offsetof(T,M) ((unsigned)(& ((T*)0)->M))
#endif

#ifdef ZZIP_HAVE_SYS_STAT_H
/* MSVC does have IFbitmask but not the corresponding IStests */
# if !defined S_ISDIR && defined S_IFDIR
# define S_ISDIR(_X_) ((_X_) & S_IFDIR)
# endif
# if !defined S_ISREG && defined S_IFREG
# define S_ISREG(_X_) ((_X_) & S_IFREG)
# endif
#endif

/** 
 * This function is the equivalent of a => rewinddir(2) for a realdir or
 * the zipfile in place of a directory. The ZZIP_DIR handle returned from
 * => zzip_opendir has a flag saying realdir or zipfile. As for a zipfile,
 * the filenames will include the filesubpath, so take care.
 */
void 
zzip_rewinddir(ZZIP_DIR * dir)
{
    if (! dir) return;

    /*
    if (USE_DIRENT && dir->realdir) 
    {
        _zzip_rewinddir(dir->realdir);
        return;
    }
    */

    if (dir->hdr0)
        dir->hdr = dir->hdr0;
    else
        dir->hdr = 0;
}

#if ! USE_DIRENT
#define real_readdir(_X_) 1
#else
static int
real_readdir(ZZIP_DIR* dir)
{
    struct stat st = { 0 };
    char filename[PATH_MAX];
    struct dirent* dirent = _zzip_readdir(dir->realdir);
    if (! dirent) return 0;

    dir->dirent.d_name = dirent->d_name;
    strcpy(filename, dir->realname);
    strcat(filename, "/");
    strcat(filename, dirent->d_name);

    if (stat(filename, &st) == -1)
        return -1;

    dir->dirent.d_csize = dir->dirent.st_size = st.st_size;
    dir->dirent.d_flags = 0;

    if (st.st_mode)
    {
        if (! S_ISREG(st.st_mode))
        {
            dir->dirent.d_compr = st.st_mode;
            dir->dirent.d_compr |= 0x80000000; 
	    /* makes it effectively negative, 
	     * but can still be fed to S_ISXXX(x) */
        }else
        {
            dir->dirent.d_compr = 0; /* stored */
        }
    }else
    {
            dir->dirent.d_compr = 0; /* stored */
    }

    return 1;
}
#endif

/**
 * This function is the equivalent of a => readdir(2) for a realdir 
 * or a zipfile referenced by the ZZIP_DIR returned from => zzip_opendir.
 *
 * The ZZIP_DIR handle (as returned by => zzip_opendir) contains a few more 
 * entries than being copied into the ZZIP_DIRENT. The only valid fields in
 * a ZZIP_DIRENT are d_name (the file name), d_compr (compression), d_csize
 * (compressed size), st_size (uncompressed size).
 */
ZZIP_DIRENT* 
zzip_readdir(ZZIP_DIR * dir)
{
    if (! dir) { errno=EBADF; return 0; }

    /*
    if (USE_DIRENT && dir->realdir)
    {
        if (! real_readdir(dir))
            return 0;
    }else */
    {
        if (! dir->hdr) return 0;

        dir->dirent.d_name  = dir->hdr->d_name;
        dir->dirent.d_compr = dir->hdr->d_compr;

        dir->dirent.d_csize = dir->hdr->d_csize;
        dir->dirent.st_size = dir->hdr->d_usize;

	dir->dirent.d_flags = dir->hdr->d_flags;

        dir->dirent.d_crc32 = (int) dir->hdr->d_crc32;

        if (! dir->hdr->d_reclen) dir->hdr = 0;
        else  dir->hdr = (struct zzip_dir_hdr *)
		  ((char *)dir->hdr + dir->hdr->d_reclen);
    }
    return &dir->dirent;
}

/** => zzip_rewinddir
 * This function is the equivalent of => telldir(2) for a realdir or zipfile.
 */
zzip_off_t 
zzip_telldir(ZZIP_DIR* dir)
{
    if (! dir) { errno=EBADF; return -1; }

    /* if (USE_DIRENT && dir->realdir)
    {
        return _zzip_telldir(dir->realdir);
    }else*/
    {
    	return ((zzip_off_t) ((char*) dir->hdr - (char*) dir->hdr0));
    }
}

/** => zzip_rewinddir
 * This function is the equivalent of => seekdir(2) for a realdir or zipfile.
 */
void
zzip_seekdir(ZZIP_DIR* dir, zzip_off_t offset)
{
    if (! dir) return; 
    
    /*if (USE_DIRENT && dir->realdir)
    {
        _zzip_seekdir(dir->realdir, offset);
    }else*/
    {
	dir->hdr = (struct zzip_dir_hdr*) 
	    (dir->hdr0 ? (char*) dir->hdr0 + (size_t) offset : 0);
    }
}

#if defined ZZIP_LARGEFILE_RENAME && defined EOVERFLOW && defined PIC
#undef zzip_seekdir /* zzip_seekdir64 */
#undef zzip_telldir /* zzip_telldir64 */

long   zzip_telldir(ZZIP_DIR* dir) 
{ 
    off_t off = zzip_telldir64 (dir); 
    long offs = off;
    if (offs != off) { errno = EOVERFLOW; return -1; }
    return offs;
}

void   zzip_seekdir(ZZIP_DIR* dir, long offset) 
{ 
    zzip_seekdir64 (dir, offset); 
}
#endif

/**
 * This function is the equivalent of => opendir(3) for a realdir or zipfile.
 * <p>
 * This function has some magic - if the given argument-path
 * is a directory, it will wrap a real => opendir(3) into the ZZIP_DIR
 * structure. Otherwise it will divert to => zzip_dir_open which 
 * can also attach a ".zip" extension if needed to find the archive.
 * <p>
 * the error-code is mapped to => errno(3).
 */
ZZIP_DIR* 
zzip_opendir(zzip_char_t* filename)
{
    return zzip_opendir_ext_io (filename, 0, 0, 0);
}

/** => zzip_opendir
 * This function uses explicit ext and io instead of the internal 
 * defaults, setting them to zero is equivalent to => zzip_opendir
 */
ZZIP_DIR* 
zzip_opendir_ext_io(zzip_char_t* filename, int o_modes,
		    zzip_strings_t* ext, zzip_plugin_io_t io)
{
    zzip_error_t e;
    ZZIP_DIR* dir;

#  ifdef ZZIP_HAVE_SYS_STAT_H
    struct stat st;
#  endif

    if (o_modes & (ZZIP_PREFERZIP|ZZIP_ONLYZIP)) goto try_zzip;
 try_real:

#  ifdef ZZIP_HAVE_SYS_STAT_H
    if (stat(filename, &st) >= 0 && S_ISDIR(st.st_mode)
    ){
      	/* if (USE_DIRENT)
	{
	    _zzip_DIR* realdir = _zzip_opendir(filename);
	    if (realdir)
	    {
		if (! (dir = (ZZIP_DIR *)calloc(1, sizeof (*dir))))
		{ 
		    _zzip_closedir(realdir); 
		    return 0; 
		}else
		{ 
		    dir->realdir = realdir; 
		    dir->realname = strdup(filename);
		    return dir; 
		}
	    }
        } */
        return 0;
    }
#  endif /* HAVE_SYS_STAT_H */

 try_zzip:
    dir = zzip_dir_open_ext_io (filename, &e, ext, io);
    if (! dir && (o_modes & ZZIP_PREFERZIP)) goto try_real;
    if (e) errno = zzip_errno(e); 
    return dir;
}

/**
 * This function is the equivalent of => closedir(3) for a realdir or zipfile.
 * <p>
 * This function is magic - if the given arg-ZZIP_DIR
 * is a real directory, it will call the real => closedir(3) and then
 * free the wrapping ZZIP_DIR structure. Otherwise it will divert 
 * to => zzip_dir_close which will free the ZZIP_DIR structure.
 */
int
zzip_closedir(ZZIP_DIR* dir)
{
    if (! dir) { errno = EBADF; return -1; }

    /*if (USE_DIRENT && dir->realdir)
    {
        _zzip_closedir(dir->realdir);
        free(dir->realname);
        free(dir);
        return 0;
    }else*/
    {
        zzip_dir_close(dir);
        return 0;
    }
}

/* 
 * Local variables:
 * c-file-style: "stroustrup"
 * End:
 */
