/*
 * Author: 
 *	Guido Draheim <guidod@gmx.de>
 *	Tomi Ollila <Tomi.Ollila@iki.fi>
 *
 *	Copyright (c) 1999,2000,2001,2002,2003 Guido Draheim
 * 	    All rights reserved, 
 *          usage allowed under the restrictions of the
 *	    Lesser GNU General Public License 
 *          note the additional license information 
 *          that can be found in COPYING.ZZIP
 *
 * if you see "unknown symbol" errors, check first that `-I ..` is part of
 * your compiler options - a special hint to VC/IDE users who tend to make up
 * their own workspace files. All includes look like #include <zzip|*.h>, so
 * you need to add an include path to the dir containing (!!) the ./zzip/ dir
 */

#ifndef _ZZIP_ZZIP_H /* zziplib.h */
#define _ZZIP_ZZIP_H

#include <zzip-conf.h>

#include <fcntl.h>
#include <stddef.h> /* size_t and friends */
/* msvc6 has neither ssize_t (we assume "int") nor off_t (assume "long") */

#ifdef __cplusplus
extern "C" {
#endif

/* the zzip_error_t is also used to pass back ZLIB errors... */
#define ZZIP_ERROR -4096

typedef enum 
{
    ZZIP_NO_ERROR = 0,	/* no error, may be used if user sets it. */
    ZZIP_OUTOFMEM =     ZZIP_ERROR-20, /* out of memory */
    ZZIP_DIR_OPEN =      ZZIP_ERROR-21, /* failed to open zipfile, see errno for details */
    ZZIP_DIR_STAT =      ZZIP_ERROR-22, /* failed to fstat zipfile, see errno for details */
    ZZIP_DIR_SEEK =      ZZIP_ERROR-23, /* failed to lseek zipfile, see errno for details */
    ZZIP_DIR_READ =      ZZIP_ERROR-24, /* failed to read zipfile, see errno for details */
    ZZIP_DIR_TOO_SHORT = ZZIP_ERROR-25,
    ZZIP_DIR_EDH_MISSING = ZZIP_ERROR-26,
    ZZIP_DIRSIZE =      ZZIP_ERROR-27,
    ZZIP_ENOENT =       ZZIP_ERROR-28,
    ZZIP_UNSUPP_COMPR = ZZIP_ERROR-29,
    ZZIP_CORRUPTED =    ZZIP_ERROR-31,
    ZZIP_UNDEF =        ZZIP_ERROR-32,
} zzip_error_t;

/*
 * zzip_open flags.
 */
#define ZZIP_CASEINSENSITIVE	O_APPEND /* do not use anymore. use CASLESS */
#define ZZIP_IGNOREPATH	        O_TRUNC  /* do not use anymore. use NOPATHS */
#define ZZIP_EXTRAFLAGS         (ZZIP_CASEINSENSITIVE|ZZIP_IGNOREPATH)

/* zzip_open_ext_io o_modes flags : new style. use these from now on! */
#define ZZIP_CASELESS           (1<<12) /* ignore filename case inside zips */
#define ZZIP_NOPATHS            (1<<13) /* ignore subdir paths, just filename*/
#define ZZIP_PREFERZIP          (1<<14) /* try first zipped file, then real*/
#define ZZIP_ONLYZIP            (1<<16) /* try _only_ zipped file, skip real*/
#define ZZIP_FACTORY            (1<<17) /* old file handle is not closed */
#define ZZIP_ALLOWREAL          (1<<18) /* real files use default_io (magic) */

/*
 * zzip largefile renames
 */
#ifdef ZZIP_LARGEFILE_RENAME
#define zzip_telldir zzip_telldir64
#define zzip_seekdir zzip_seekdir64
#endif

/*
 * zzip typedefs
 */
/* zzip_strings_t ext[] = { ".zip", ".jar", ".pk3", 0 } */
typedef  char _zzip_const * _zzip_const zzip_strings_t;
typedef  char _zzip_const       zzip_char_t;
typedef       _zzip_off_t       zzip_off_t;
typedef       _zzip_size_t      zzip_size_t;
typedef       _zzip_ssize_t     zzip_ssize_t;
typedef struct zzip_dir		ZZIP_DIR;
typedef struct zzip_file	ZZIP_FILE;
typedef struct zzip_dirent 	ZZIP_DIRENT;
typedef struct zzip_dirent 	ZZIP_STAT;

struct zzip_dirent
{
    int	 	d_compr;	/* compression method */
    int         d_csize;        /* compressed size */
    int	 	st_size;	/* file size / decompressed size */
    char * 	d_name;		/* file name / strdupped name */
};

/*
 * Getting error strings 
 * zzip/err.c
 */
_zzip_export    /* error in _opendir : */
zzip_char_t* 	zzip_strerror(int errcode); 
_zzip_export    /* error in other functions : */
zzip_char_t* 	zzip_strerror_of(ZZIP_DIR * dir); 
_zzip_export    /* error mapped to errno.h defines : */
int    	 	zzip_errno(int errcode); 


/*
 * Functions to grab information from ZZIP_DIR/ZZIP_FILE structure 
 * (if ever needed)
 * zzip/info.c
 */
_zzip_export
int  	 	zzip_error(ZZIP_DIR * dir);
_zzip_export
void 	 	zzip_seterror(ZZIP_DIR * dir, int errcode);
_zzip_export
zzip_char_t* 	zzip_compr_str(int compr);

_zzip_export
ZZIP_DIR * 	zzip_dirhandle(ZZIP_FILE * fp);
_zzip_export
int           	zzip_dirfd(ZZIP_DIR * dir);
_zzip_export
int            	zzip_dir_real(ZZIP_DIR * dir);
_zzip_export
int      	zzip_file_real(ZZIP_FILE * fp);
_zzip_export
void*           zzip_realdir(ZZIP_DIR * dir);
_zzip_export
int             zzip_realfd(ZZIP_FILE * fp);

/*
 * zip handle management
 * zzip/zip.c
 */
_zzip_export
ZZIP_DIR *      zzip_dir_alloc(zzip_strings_t* fileext);
_zzip_export
int             zzip_dir_free(ZZIP_DIR *);

/*
 * Opening/closing a zip archive
 * zzip-zip.c
 */
_zzip_export
ZZIP_DIR *  	zzip_dir_fdopen(int fd, zzip_error_t * errcode_p);
_zzip_export
ZZIP_DIR *  	zzip_dir_open(zzip_char_t* filename, zzip_error_t * errcode_p);
_zzip_export
int	  	zzip_dir_close(ZZIP_DIR * dir);
_zzip_export
int             zzip_dir_read(ZZIP_DIR * dir, ZZIP_DIRENT * dirent);


/*
 * Scanning files in zip archive
 * zzip/dir.c
 * zzip/zip.c
 */
_zzip_export
ZZIP_DIR * 	zzip_opendir(zzip_char_t* filename);
_zzip_export
int          	zzip_closedir(ZZIP_DIR * dir);
_zzip_export
ZZIP_DIRENT * 	zzip_readdir(ZZIP_DIR * dir);
_zzip_export
void 	 	zzip_rewinddir(ZZIP_DIR * dir);
_zzip_export
zzip_off_t  	zzip_telldir(ZZIP_DIR * dir);
_zzip_export
void	 	zzip_seekdir(ZZIP_DIR * dir, zzip_off_t offset);

/*
 * 'opening', 'closing' and reading invidual files in zip archive.
 * zzip/file.c
 */
_zzip_export
ZZIP_FILE * 	zzip_file_open(ZZIP_DIR * dir, zzip_char_t* name, int modes);
_zzip_export
int  		zzip_file_close(ZZIP_FILE * fp);
_zzip_export
zzip_ssize_t	zzip_file_read(ZZIP_FILE * fp, char* buf, zzip_size_t len);

_zzip_export
ZZIP_FILE * 	zzip_open(zzip_char_t* name, int flags);
_zzip_export
int	 	zzip_close(ZZIP_FILE * fp);
_zzip_export
zzip_ssize_t	zzip_read(ZZIP_FILE * fp, char * buf, zzip_size_t len);

/*
 * the stdc variant to open/read/close files. - Take note of the freopen()
 * call as it may reuse an existing preparsed copy of a zip central directory
 */
_zzip_export
ZZIP_FILE*      zzip_freopen(zzip_char_t* name, zzip_char_t* mode, ZZIP_FILE*);
_zzip_export
ZZIP_FILE*      zzip_fopen(zzip_char_t* name, zzip_char_t* mode);
_zzip_export
zzip_size_t     zzip_fread(void *ptr, zzip_size_t size, zzip_size_t nmemb, 
			   ZZIP_FILE * file);
_zzip_export
int  		zzip_fclose(ZZIP_FILE * fp);

/*
 *  seek and tell functions
 */
_zzip_export
int             zzip_rewind(ZZIP_FILE *fp);
_zzip_export
zzip_off_t      zzip_seek(ZZIP_FILE * fp, zzip_off_t offset, int whence);
_zzip_export
zzip_off_t      zzip_tell(ZZIP_FILE * fp);

/*
 * reading info of a single file 
 * zzip/stat.c
 */
_zzip_export
int		zzip_dir_stat(ZZIP_DIR * dir, zzip_char_t* name, 
			      ZZIP_STAT * zs, int flags);

#ifdef ZZIP_LARGEFILE_RENAME
#define zzip_open_shared_io  zzip_open_shared_io64
#define zzip_open_ext_io     zzip_open_ext_io64
#define zzip_opendir_ext_io  zzip_opendir_ext_io64
#define zzip_dir_open_ext_io zzip_dir_open_ext_io64
#define zzip_plugin_io_t     zzip_plugin_io64_t
#endif

/*
 * all ext_io functions can be called with a default of ext/io == zero/zero
 * which will default to a ".zip" extension and posix io of the system.
 */
typedef struct zzip_plugin_io _zzip_const * zzip_plugin_io_t;

_zzip_export
ZZIP_FILE * zzip_open_shared_io(ZZIP_FILE* stream,
				zzip_char_t* name, int o_flags, int o_modes,
				zzip_strings_t* ext, zzip_plugin_io_t io);

_zzip_export
ZZIP_FILE * zzip_open_ext_io(zzip_char_t* name, int o_flags, int o_modes,
			     zzip_strings_t* ext, zzip_plugin_io_t io);

_zzip_export
ZZIP_DIR *  zzip_opendir_ext_io(zzip_char_t* name, int o_modes,
				zzip_strings_t* ext, zzip_plugin_io_t io);

_zzip_export
ZZIP_FILE * zzip_file_open_ext_io(ZZIP_DIR * dir, 
				  zzip_char_t* name, int flags,
				  zzip_strings_t* ext, zzip_plugin_io_t io);

_zzip_export
ZZIP_DIR *  zzip_dir_open_ext_io(zzip_char_t* filename,
				 zzip_error_t* errcode_p,
				 zzip_strings_t* ext, zzip_plugin_io_t io);

#if defined _ZZIP_WRITE_SOURCE
/* ........................................................................
 * write support is not yet implemented
 * zzip/write.c
 */
#define ZZIP_NO_CREAT 1

ZZIP_DIR*    zzip_dir_creat_ext_io(zzip_char_t* name, int o_mode, 
                                   zzip_strings_t* ext, zzip_plugin_io_t io);
ZZIP_DIR*    zzip_dir_creat(zzip_char_t* name, int o_mode);
int          zzip_file_mkdir(ZZIP_DIR* dir, zzip_char_t* name, int o_mode);
ZZIP_FILE*   zzip_file_creat(ZZIP_DIR* dir, zzip_char_t* name, int o_mode);
zzip_ssize_t zzip_file_write(ZZIP_FILE* file, 
                             const void* ptr, zzip_size_t len);

ZZIP_DIR*    zzip_createdir(zzip_char_t* name, int o_mode);
zzip_ssize_t zzip_write(ZZIP_FILE* file, const void* ptr, zzip_size_t len);
zzip_size_t  zzip_fwrite(const void* ptr, zzip_size_t len, 
                         zzip_size_t multiply, ZZIP_FILE* file);
#ifndef zzip_savefile
#define zzip_savefile 0
#define zzip_savefile_is_null
#endif

#ifdef _ZZIP_NO_INLINE
#define zzip_mkdir(_name_,_mode_) \
        zzip_file_mkdir((zzip_savefile),(_name_),(_mode_))
#define zzip_creat(_name_,_mode_) \
        zzip_file_creat((zzip_savefile),(_name_),(_mode_))
#define zzip_sync() \
      { zzip_closedir((zzip_savefile)); (zzip_savefile) = 0; }
#define zzip_start(_name_,_mode_,_ext_) \
      { if ((zzip_savefile)) zzip_closedir((zzip_savefile)); 
         zzip_savefile = zzip_dir_creat(_name_, _mode_,_ext_); }

#else

_zzip_inline static int         zzip_mkdir(zzip_char_t* name, int o_mode)
{                   return zzip_file_mkdir(zzip_savefile, name, o_mode); }
_zzip_inline static ZZIP_FILE*  zzip_creat(zzip_char_t* name, int o_mode)
{                   return zzip_file_creat(zzip_savefile, name, o_mode); }

#ifndef zzip_savefile_is_null
_zzip_inline static void        zzip_sync(void)
{                           zzip_closedir(zzip_savefile); zzip_savefile = 0; }
_zzip_inline static void        zzip_mkfifo(zzip_char_t* name, int o_mode)
{       if ((zzip_savefile)) zzip_closedir (zzip_savefile);
             zzip_savefile = zzip_createdir(_name_,_mode_); }
#else
_zzip_inline static void        zzip_sync(void) {}
_zzip_inline static void        zzip_mkfifo(zzip_char_t* name, int o_mode) {}
#endif
#endif /* _ZZIP_NO_INLINE */
#endif /* _ZZIP_WRITE_SOURCE */

#ifdef __cplusplus
};
#endif

#endif /* _ZZIPLIB_H */

/* 
 * Local variables:
 * c-file-style: "stroustrup"
 * End:
 */
