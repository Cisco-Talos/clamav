/*
 * Author: 
 *      Guido Draheim <guidod@gmx.de>
 *      Tomi Ollila <Tomi.Ollila@iki.fi>
 *
 * Copyright (c) 1999,2000,2001,2002 Guido Draheim
 *          All rights reserved,
 *          use under the restrictions of the
 *          Lesser GNU General Public License
 *          note the additional license information 
 *          that can be found in COPYING.ZZIP
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <zzip.h>                                         /* exported...*/
#include <zzip-file.h>

#include "strc.h"

#include <sys/types.h>  /* njh@bandsman.co.uk: for icc7.0 */
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>

#include <zzipformat.h>
/*
#include "__debug.h"
*/

#if 0
# if defined ZZIP_HAVE_IO_H
# include <io.h> /* tell */
# else
# define tell(fd) lseek(fd,0,SEEK_CUR)
# endif
#else
#define tells(fd) seeks(fd,0,SEEK_CUR)
#endif

/**
 * the direct function of => zzip_close(fp). it will cleanup the
 * inflate-portion of => zlib and free the structure given.
 * 
 * it is called quite from the error-cleanup parts
 * of the various => _open functions. 
 * 
 * the .refcount is decreased and if zero the fp->dir is closed just as well.
 */
int 
zzip_file_close(ZZIP_FILE * fp)
{
    ZZIP_DIR * dir = fp->dir;
    
    if (fp->method)

        inflateEnd(&fp->d_stream); /* inflateEnd() can be called many times */

    if (fp->buf32k)
    {
        if (dir->cache.buf32k == NULL) dir->cache.buf32k = fp->buf32k;
        else free(fp->buf32k);
    }

    if (dir->currentfp == fp)
        dir->currentfp = NULL;
  
    dir->refcount--;
    /* ease to notice possible dangling reference errors */
    memset(fp, 0, sizeof(*fp)); 

    if (dir->cache.fp == NULL) dir->cache.fp = fp;
    else free(fp);
    
    if (! dir->refcount) return zzip_dir_close(dir); else return 0;
}
  

static int 
zzip_file_saveoffset(ZZIP_FILE * fp)
{
    if (fp)
    {
        int fd = fp->dir->fd;
        zzip_off_t off = fp->io->seeks(fd, 0, SEEK_CUR);
        if (off < 0)
            return -1;

        fp->offset = off;
    }
    return 0;
}


# if !defined strcasecmp && !defined ZZIP_HAVE_STRCASECMP
# define ZZIP_CHECK_BACKSLASH_DIRSEPARATOR 1
# else
# ifndef ZZIP_CHECK_BACKSLASH_DIRSEPARATOR           /* NOTE: also default */
# define ZZIP_CHECK_BACKSLASH_DIRSEPARATOR 0         /* to "NO" on win32 ! */
# endif
# endif

#if ! ZZIP_CHECK_BACKSLASH_DIRSEPARATOR+0
#define dirsep_strrchr(N,C) strrchr(N,C)
#define dirsep_casecmp strcasecmp
#else
#define dirsep_strrchr(N,C) _dirsep_strrchr(N)
#define dirsep_casecmp _dirsep_casecmp
static zzip_char_t*
_dirsep_strrchr (zzip_char_t* name)
{
    char* n = strrchr (name, '/');
    char* m = strrchr (name, '\\');
    if (m && n && m > n) n = m;
    return n;
}
static int
_dirsep_casecmp (zzip_char_t* s1, zzip_char_t* s2)
{
    /* ASCII tolower - including mapping of backslash in normal slash */
    static const char mapping[] = "@abcdefghijklmnopqrstuvwxyz[/]^_";
    int c1, c2;
    while (*s1 && *s2)
    {
	c1 = (int)(unsigned char) *s1;
	c2 = (int)(unsigned char) *s2;
	if ((c1&0xE0) == 0x40) c1 = mapping[c1&0x1f];
	if ((c1&0xE0) == 0x40) c2 = mapping[c2&0x1f];
	if (c1 != c2)
	    return (c1 - c2);
	s1++; s2++;
    }

    return (((int)(unsigned char) *s1) - ((int)(unsigned char) *s2));
}
#endif

static int zzip_inflate_init(ZZIP_FILE *, struct zzip_dir_hdr *);

/**
 * open an => ZZIP_FILE from an already open => ZZIP_DIR handle. Since
 * we have a chance to reuse a cached => buf32k and => ZZIP_FILE memchunk
 * this is the best choice to unpack multiple files.
 * 
 * Note: the zlib supports 2..15 bit windowsize, hence we provide a 32k
 *       memchunk here... just to be safe.
 */
ZZIP_FILE * 
zzip_file_open(ZZIP_DIR * dir, zzip_char_t* name, int o_mode)
{
    zzip_error_t err = 0;
    struct zzip_file * fp = 0;
    struct zzip_dir_hdr * hdr = dir->hdr0;
    int (*cmp)(zzip_char_t*, zzip_char_t*);
 
    cmp = (o_mode & ZZIP_CASELESS)? dirsep_casecmp: strcmp;

    if (! dir || !dir->fd || dir->fd == -1 ) return 0;

    if (o_mode & ZZIP_NOPATHS)
    {
        register zzip_char_t* n = dirsep_strrchr(name, '/');
        if (n)  name = n + 1;
    }

    if (hdr)
    while (1)
    {
        register zzip_char_t* hdr_name = hdr->d_name;
        if (o_mode & ZZIP_NOPATHS)
        {
            register zzip_char_t* n = dirsep_strrchr(hdr_name, '/');
            if (n)  hdr_name = n + 1;
        }

        /*
        HINT4("name='%s', compr=%d, size=%d\n", 
	      hdr->d_name, hdr->d_compr, hdr->d_usize);
	*/

        if (!cmp(hdr_name, name))
        {
            switch (hdr->d_compr)
            {
            case 0: /* store */
            case 8: /* inflate */
                break;
            default:
                { err = ZZIP_UNSUPP_COMPR; goto error; }
            }

            if (dir->cache.fp) 
            {
                fp = dir->cache.fp; dir->cache.fp = NULL;
                /* memset(zfp, 0, sizeof *fp); cleared in zzip_file_close() */
            }else
            {
                if (! (fp = (ZZIP_FILE *)calloc(1, sizeof(*fp))))
                    { err =  ZZIP_OUTOFMEM; goto error; }
            }

            fp->dir = dir;
            fp->io = dir->io;
            dir->refcount++;
        
            if (dir->cache.buf32k) 
              { fp->buf32k = dir->cache.buf32k; dir->cache.buf32k = NULL; }
            else
            {
                if (! (fp->buf32k = (char *)malloc(ZZIP_32K)))
                    { err = ZZIP_OUTOFMEM; goto error; }
            }

            /*
             * In order to support simultaneous open files in one zip archive
             * we'll fix the fd offset when opening new file/changing which
             * file to read...
             */ 

            if (zzip_file_saveoffset(dir->currentfp) < 0)
                { err = ZZIP_DIR_SEEK; goto error; }

            fp->offset = hdr->d_off;
            dir->currentfp = fp;

            if (dir->io->seeks(dir->fd, hdr->d_off, SEEK_SET) < 0)
                { err = ZZIP_DIR_SEEK; goto error; }

            {   /* skip local header - should test tons of other info, 
		 * but trust that those are correct */
                zzip_ssize_t dataoff;
                struct zzip_file_header * p = (void*) fp->buf32k;

		dataoff = dir->io->read(dir->fd, (void*)p, sizeof(*p));
		if (dataoff < (zzip_ssize_t)sizeof(*p))
		{ err = ZZIP_DIR_READ;  goto error; }
                if (! ZZIP_FILE_HEADER_CHECKMAGIC(p)) /* PK\3\4 */
		{ err = ZZIP_CORRUPTED; goto error; }

                dataoff = ZZIP_GET16(p->z_namlen) + ZZIP_GET16(p->z_extras);
              
                if (dir->io->seeks(dir->fd, dataoff, SEEK_CUR) < 0)
                { err = ZZIP_DIR_SEEK; goto error; }

                fp->dataoffset = dir->io->tells(dir->fd);
                fp->usize = hdr->d_usize;
                fp->csize = hdr->d_csize;
            }

            err = zzip_inflate_init (fp, hdr);
            if (err) { goto error; }
                                        
            return fp;
        }else
        {
            if (hdr->d_reclen == 0)
                break;
            hdr = (struct zzip_dir_hdr *)((char *)hdr + hdr->d_reclen);
        }/*cmp name*/
    }/*forever*/
    dir->errcode = ZZIP_ENOENT;         zzip_errno(ZZIP_ENOENT);
    return NULL;
error:
    if (fp) zzip_file_close(fp);
    dir->errcode = err;                 zzip_errno(err);
    return NULL;
}

/**
 *  call => inflateInit and setup fp's iterator variables, 
 *  used by lowlevel => _open functions.
 */
static int 
zzip_inflate_init(ZZIP_FILE * fp, struct zzip_dir_hdr* hdr)
{
    int err;
    fp->method = hdr->d_compr;
    fp->restlen = hdr->d_usize;
    
    if (fp->method)
    {
        memset(&fp->d_stream, 0, sizeof(fp->d_stream));
  
        err = inflateInit2(&fp->d_stream, -MAX_WBITS);
        if (err != Z_OK) { goto error; }

        fp->crestlen = hdr->d_csize;
    }
    return 0;
error:
    if (fp) zzip_file_close(fp);
    return err;
}

/**                                                             
 * This function closes the given ZZIP_FILE handle. 
 *
 * If the ZZIP_FILE wraps a normal stat'fd then it is just that int'fd 
 * that is being closed and the otherwise empty ZZIP_FILE gets freed.
 */
int 
zzip_fclose(ZZIP_FILE * fp)
{
    if (! fp) return 0;
    if (! fp->dir) 
      { int r = fp->io->close(fp->fd); free(fp); return r; } /* stat fd */
    else return zzip_file_close(fp);
}

/** => zzip_fclose
 */
int 
zzip_close(ZZIP_FILE* fp)
{
    return zzip_fclose (fp);
}

/**                                                              
 * This functions read data from zip-contained file.
 *
 * It works like => read(2) and will fill the given buffer with bytes from
 * the opened file. It will return the number of bytes read, so if the => EOF
 * is encountered you will be prompted with the number of bytes actually read.
 * 
 * This is the routines that needs the => buf32k buffer, and it would have
 * need for much more polishing but it does already work quite well.
 * 
 * Note: the 32K buffer is rather big. The original inflate-algorithm
 *       required just that but the latest zlib would work just fine with
 *       a smaller buffer.
 */
zzip_ssize_t 
zzip_file_read(ZZIP_FILE * fp, char * buf, zzip_size_t len)
{
    ZZIP_DIR * dir; 
    zzip_size_t l;
    zzip_ssize_t rv;
    
    if (! fp || ! fp->dir) return 0;

    dir = fp->dir;
    l = fp->restlen > len ? len : fp->restlen;
    if (fp->restlen == 0)
        return 0;

    /*
     * If this is other handle than previous, save current seek pointer
     * and read the file position of `this' handle.
     */
     if (dir->currentfp != fp)
     {
         if (zzip_file_saveoffset(dir->currentfp) < 0 
         || fp->io->seeks(dir->fd, fp->offset, SEEK_SET) < 0)
           { dir->errcode = ZZIP_DIR_SEEK; return -1; }
         else
           { dir->currentfp = fp; }
     }
  
     /* if more methods is to be supported, change this to `switch ()' */
     if (fp->method) /* method != 0   == 8, inflate */
     {
         fp->d_stream.avail_out = l;
         fp->d_stream.next_out = (unsigned char *)buf;

         do {
             int err;
             zzip_size_t startlen;

             if (fp->crestlen > 0 && fp->d_stream.avail_in == 0)
             {
                 zzip_size_t cl = ( fp->crestlen < ZZIP_32K ?
				    fp->crestlen : ZZIP_32K );
             /*  zzip_size_t cl = fp->crestlen > 128 ? 128 : fp->crestlen; */

                 zzip_ssize_t i = fp->io->read(dir->fd, fp->buf32k, cl);
                 if (i <= 0)
                 {
                     dir->errcode = ZZIP_DIR_READ; /* or ZZIP_DIR_READ_EOF ? */
                     return -1;
                 }
                 fp->crestlen -= i;
                 fp->d_stream.avail_in = i;
                 fp->d_stream.next_in = (unsigned char *)fp->buf32k;
             }

             startlen = fp->d_stream.total_out;
             err = inflate(&fp->d_stream, Z_NO_FLUSH);

             if (err == Z_STREAM_END) 
               { fp->restlen = 0; }
             else 
             if (err == Z_OK)
               { fp->restlen -= (fp->d_stream.total_out - startlen); }
             else
               { dir->errcode = err; return -1; }
         } while (fp->restlen && fp->d_stream.avail_out);

         return l - fp->d_stream.avail_out;
     }else
     {   /* method == 0 -- unstore */
         rv = fp->io->read(dir->fd, buf, l);
         if (rv > 0)
             { fp->restlen-= rv; }
         else 
         if (rv < 0)
             { dir->errcode = ZZIP_DIR_READ; }
         return rv;
     }
}  

/**                                                               
 * This function will read(2) data from a real/zipped file.
 *
 * the replacement for => read(2) will fill the given buffer with bytes from
 * the opened file. It will return the number of bytes read, so if the EOF
 * is encountered you will be prompted with the number of bytes actually read.
 * 
 * If the file-handle is wrapping a stat'able file then it will actually just
 * perform a normal => read(2)-call, otherwise => zzip_file_read is called
 * to decompress the data stream and any error is mapped to => errno(3).
 */
zzip_ssize_t
zzip_read(ZZIP_FILE * fp, char * buf, zzip_size_t len)
{
    if (! fp) return 0;
    if (! fp->dir) 
      { return fp->io->read(fp->fd, buf, len); } /* stat fd */
    else
    {   register zzip_ssize_t v;
        v = zzip_file_read(fp, buf, len);
        if (v == -1) { errno = zzip_errno(fp->dir->errcode); }
        return v;
    }
}

/** => zzip_read
 */
zzip_size_t
zzip_fread(void *ptr, zzip_size_t size, zzip_size_t nmemb, ZZIP_FILE *file)
{
    if (! size) size=1;
    return zzip_read (file, ptr, size*nmemb)/size;
}


#define ZZIP_WRONLY             O_WRONLY
#define ZZIP_EXCL               O_EXCL

#if     defined                 O_SYNC
#define ZZIP_SYNC               O_SYNC
#else  
#define ZZIP_SYNC               0
#endif

#if     defined                 O_NONBLOCK
#define ZZIP_NONBLOCK           O_NONBLOCK
#elif   defined                 O_NDELAY
#define ZZIP_NOCTTY             O_NDELAY
#else  
#define ZZIP_NOCTTY             0
#endif

/* ------------------------------------------------------------------- */

/**                                                            
 * This function will => fopen(3) a real/zipped file.
 * 
 * It has some magic functionality builtin - it will first try to open
 * the given <em>filename</em> as a normal file. If it does not
 * exist, the given path to the filename (if any) is split into
 * its directory-part and the file-part. A ".zip" extension is
 * then added to the directory-part to create the name of a
 * zip-archive. That zip-archive (if it exists) is being searched
 * for the file-part, and if found a zzip-handle is returned. 
 * 
 * Note that if the file is found in the normal fs-directory the
 * returned structure is mostly empty and the => zzip_read call will
 * use the libc => read to obtain data. Otherwise a => zzip_file_open 
 * is performed and any error mapped to => errno(3).
 * 
 * unlike the posix-wrapper => zzip_open the mode-argument is
 * a string which allows for more freedom to support the extra
 * zzip modes called ZZIP_CASEINSENSITIVE and ZZIP_IGNOREPATH.
 * Currently, this => zzip_fopen call will convert the following
 * characters in the mode-string into their corrsponding mode-bits: 
 *  <ul><li><code> "r" : O_RDONLY : </code> read-only
 * </li><li><code> "b" : O_BINARY : </code> binary (win32 specific)
 * </li><li><code> "f" : O_NOCTTY : </code> no char device (unix)
 * </li><li><code> "i" : ZZIP_CASELESS : </code> inside zip file
 * </li><li><code> "*" : ZZIP_NOPATHS : </code> inside zip file only
 * </ul> all other modes will be ignored for zip-contained entries
 * but they are transferred for compatibility and portability,
 * including these extra sugar bits:
 *  <ul><li><code> "x" : O_EXCL :</code> fail if file did exist
 * </li><li><code> "s" : O_SYNC :</code> synchronized access
 * </li><li><code> "n" : O_NONBLOCK :</code> nonblocking access
 * </li><li><code> "z#" : compression level :</code> for zlib
 * </li><li><code> "g#" : group access :</code> unix access bits
 * </li><li><code> "u#" : owner access :</code> unix access bits
 * </li><li><code> "o#" : world access :</code> unix access bits
 * </ul>... the access bits are in traditional unix bit format
 * with 7 = read/write/execute, 6 = read/write, 4 = read-only.
 *
 * The default access mode is 0664, and the compression level
 * is ignored since the lib can not yet write zip files, otherwise
 * it would be the initialisation value for the zlib deflateInit
 * where 0 = no-compression, 1 = best-speed, 9 = best-compression.
 */
ZZIP_FILE*
zzip_fopen(zzip_char_t* filename, zzip_char_t* mode)
{
    return zzip_freopen (filename, mode, 0);
}

/** => zzip_fopen
 *
 * This function receives an additional argument pointing to
 * a ZZIP_FILE* being already in use. If this extra argument is
 * null then this function is identical with calling => zzip_fopen
 *
 * Per default, the old file stream is closed and only the internal
 * structures associated with it are kept. These internal structures
 * may be reused for the return value, and this is a lot quicker when
 * the filename matches a zipped file that is incidently in the very
 * same zip arch as the old filename wrapped in the stream struct.
 *
 * That's simply because the zip arch's central directory does not 
 * need to be read again. As an extension for this function, if the 
 * mode-string contains a "q" then the old stream is not closed but
 * left untouched, instead it is only given as a hint that a new
 * file handle may share/copy the zip arch structures of the old file
 * handle if that is possible, i.e when they are in the same zip arch.
 */ 
ZZIP_FILE*
zzip_freopen(zzip_char_t* filename, zzip_char_t* mode, ZZIP_FILE* stream)
{
    int o_flags = 0;
    int o_modes = 0664;
    if (!mode) mode = "rb";

#   ifndef O_BINARY
#   define O_BINARY 0
#   endif
#   ifndef O_NOCTTY
#   define O_NOCTTY 0
#   endif
#   ifndef O_SYNC
#   define O_SYNC 0
#   endif
#   ifndef O_NONBLOCK
#   define O_NONBLOCK 0
#   endif

    for(; *mode; mode++) 
    {
        switch (*mode)
        {
	case '0': case '1': case '2': case '3': case '4': 
	case '5': case '6': case '7': case '8': case '9':
	    continue; /* ignore if not attached to other info */
        case 'r': o_flags |= mode[1] == '+' ? O_RDWR : O_RDONLY; break;
        case 'w': o_flags |= mode[1] == '+' ? O_RDWR : O_WRONLY; 
                  o_flags |= O_TRUNC; break;
        case 'b': o_flags |= O_BINARY; break;
        case 'f': o_flags |= O_NOCTTY; break;
        case 'i': o_modes |= ZZIP_CASELESS; break;
        case '*': o_modes |= ZZIP_NOPATHS; break;
        case 'x': o_flags |= O_EXCL; break;
        case 's': o_flags |= O_SYNC; break;
        case 'n': o_flags |= O_NONBLOCK; break;
	case 'o': o_modes &=~ 07; 
                  o_modes |= ((mode[1] - '0'))&07; continue;
	case 'g': o_modes &=~ 070; 
                  o_modes |= ((mode[1] - '0')<<3)&070; continue;
	case 'u': o_modes &=~ 0700; 
                  o_modes |= ((mode[1] - '0')<<6)&0700; continue;
	case 'q': o_modes |= ZZIP_FACTORY; break;
	case 'z': /* compression level */
	    continue; /* currently ignored, just for write mode */
        }
    }

    {
	ZZIP_FILE* fp = 
	    zzip_open_shared_io (stream, filename, o_flags, o_modes, 0, 0);

	if (! o_modes&ZZIP_FACTORY && stream)
	    zzip_file_close (stream);

	return fp;
    }
}

/**                                                        
 * This function will => open(2) a real/zipped file
 *
 * It has some magic functionality builtin - it will first try to open
 * the given <em>filename</em> as a normal file. If it does not
 * exist, the given path to the filename (if any) is split into
 * its directory-part and the file-part. A ".zip" extension is
 * then added to the directory-part to create the name of a
 * zip-archive. That zip-archive (if it exists) is being searched
 * for the file-part, and if found a zzip-handle is returned. 
 * 
 * Note that if the file is found in the normal fs-directory the
 * returned structure is mostly empty and the => zzip_read call will
 * use the libc => read to obtain data. Otherwise a => zzip_file_open 
 * is performed and any error mapped to => errno(3).
 * 
 * There was a possibility to transfer zziplib-specific openmodes
 * through o_flags but you should please not use them anymore and
 * look into => zzip_open_ext_io to submit them down. This function
 * is shallow in that it just extracts the zzipflags and calls <ul><li><code>
 * zzip_open_ext_io(filename, o_flags, zzipflags|0664, 0, 0) </code></li></ul>
 * you must stop using this extra functionality (not well known
 * anyway) since zzip_open might be later usable to open files
 * for writing in which case the _EXTRAFLAGS will get in conflict.
 *
 * compare with  => open(2) and => zzip_fopen
 */
ZZIP_FILE*
zzip_open(zzip_char_t* filename, int o_flags)
{
    /* backward compatibility */
    int o_modes = 0664;
    if (o_flags & ZZIP_CASEINSENSITIVE) 
    {  o_flags ^= ZZIP_CASEINSENSITIVE; o_modes |= ZZIP_CASELESS; }
    if (o_flags & ZZIP_IGNOREPATH) 
    {  o_flags ^= ZZIP_IGNOREPATH;      o_modes |= ZZIP_NOPATHS; }
    return zzip_open_ext_io(filename, o_flags, o_modes, 0, 0);
}

/* ZZIP_ONLYZIP won't work on platforms with sizeof(int) == 16bit */
#if ZZIP_SIZEOF_INT+0 == 2
#undef ZZIP_ONLYZIP
#endif

/** => zzip_open
 *
 * This function uses explicit ext and io instead of the internal 
 * defaults, setting them to zero is equivalent to => zzip_open
 * 
 * note that the two flag types have been split into an o_flags
 * (for fcntl-like openflags) and o_modes where the latter shall
 * carry the zzip_flags and possibly accessmodes for unix filesystems.
 * Since this version of zziplib can not write zipfiles, it is not
 * yet used for anything else than zzip-specific modeflags.
 */
ZZIP_FILE*
zzip_open_ext_io(zzip_char_t* filename, int o_flags, int o_modes,
                 zzip_strings_t* ext, zzip_plugin_io_t io)
{
    return zzip_open_shared_io (0, filename, o_flags, o_modes, ext, io);
}

/** => zzip_open
 * 
 * This function takes an extra stream argument - if a handle has been
 * then ext/io can be left null and the new stream handle will pick up 
 * the ext/io. This should be used only in specific environment however 
 * since => zzip_file_real does not store any ext-sequence.
 *
 * The benefit for this function comes in when the old file handle
 * was openened from a file within a zip archive. When the new file
 * is in the same zip archive then the internal zzip_dir structures
 * will be shared. It is even quicker, as no check needs to be done
 * anymore trying to guess the zip archive place in the filesystem,
 * here we just check whether the zip archive's filepath is a prefix
 * part of the filename to be opened. 
 *
 * Note that this function is also used by => zzip_freopen that
 * will unshare the old handle, thereby possibly closing the handle.
 */
ZZIP_FILE*
zzip_open_shared_io (ZZIP_FILE* stream,
		     zzip_char_t* filename, int o_flags, int o_modes,
		     zzip_strings_t* ext, zzip_plugin_io_t io)
{
    if (stream && stream->dir)
    {
	if (! ext) ext = stream->dir->fileext;
	if (! io) io = stream->dir->io;
    }
    if (! io) io = zzip_get_default_io ();

    if (o_modes & (ZZIP_PREFERZIP|ZZIP_ONLYZIP)) goto try_zzip;
 try_real:
    /* prefer an existing real file */
    {   
	zzip_plugin_io_t os = (o_modes & ZZIP_ALLOWREAL)
	    ?  zzip_get_default_io () : io;
	int fd = os->open(filename, o_flags); /* io->open */
        if (fd != -1)
        {
            ZZIP_FILE* fp = calloc (1, sizeof(ZZIP_FILE));
            if (!fp) { os->close(fd); return 0; } /* io->close */

            fp->fd = fd; 
            fp->io = os;
            return fp;
        }
        if (o_modes & ZZIP_PREFERZIP) return 0;
    }
 try_zzip:

    /* if the user had it in place of a normal xopen, then
     * we better defend this lib against illegal usage */
    if (o_flags & (O_CREAT|O_WRONLY))     { errno = EINVAL; return 0; }
    if (o_flags & (O_RDWR)) { o_flags ^= O_RDWR; o_flags |= O_RDONLY; }

    /* this is just for backward compatibility -and strictly needed to
     * prepare ourselves for more options and more options later on... */
    /*# if (o_modes & ZZIP_CASELESS) { o_flags |= ZZIP_CASEINSENSITIVE; } */
    /*# if (o_modes & ZZIP_NOPATHS)  { o_flags |= ZZIP_IGNOREPATH; } */
    
    /* see if we can open a file that is a zip file */
    { char basename[PATH_MAX];
      char* p;
      strcpy (basename, filename);

      /* see if we can share the same zip directory */
      if (stream && stream->dir && stream->dir->realname)
      {
	  zzip_size_t len = strlen (stream->dir->realname);
	  if (! memcmp (filename, stream->dir->realname, len) &&
	      filename[len] == '/' && filename[len+1])
	  {
	      ZZIP_FILE* fp = 
		  zzip_file_open (stream->dir, filename+len+1, o_modes);
	      if (! fp) { errno = zzip_errno (stream->dir->errcode); }
	      return fp;
	  }
      }

      /* per each slash in filename, check if it there is a zzip around */
      while ((p = strrchr (basename, '/'))) 
      {
          zzip_error_t e = 0;
          ZZIP_DIR* dir;
          ZZIP_FILE* fp;
          int fd;

          *p = '\0'; /* cut at path separator == possible zipfile basename */
          fd = __zzip_try_open (basename, o_flags|O_RDONLY|O_BINARY, ext, io);
          if (fd == -1) { continue; }
/*    found: */
          /* found zip-file, now try to parse it */
          dir = zzip_dir_fdopen_ext_io(fd, &e, ext, io);
          if (e) { errno = zzip_errno(e); io->close(fd); return 0; }

          /* (p - basename) is the lenghtof zzip_dir part of the filename */
          fp = zzip_file_open(dir, filename + (p - basename) +1, o_modes);
          if (! fp) { errno = zzip_errno(dir->errcode); }
	  else { if (! dir->realname) dir->realname = strdup (basename); }

          zzip_dir_close(dir); 
          /* note: since (fp) is attached that (dir) will survive */
          /* but (dir) is implicitly closed on next zzip_close(fp) */

          return fp;
      } /*again*/

      if (o_modes & ZZIP_PREFERZIP) goto try_real;
      errno = ENOENT; return 0;
    }
}

#if defined ZZIP_LARGEFILE_RENAME && defined EOVERFLOW && defined PIC
#undef zzip_open_shared_io /* zzip_open_shared_io64 */
#undef zzip_open_ext_io    /* zzip_open_ext_io64 */
#undef zzip_opendir_ext_io /* zzip_opendir_ext_io64 */

_zzip_export
ZZIP_FILE * zzip_open_shared_io(ZZIP_FILE* stream,
				zzip_char_t* name, int o_flags, int o_modes,
				zzip_strings_t* ext, zzip_plugin_io_t io)
{
    if (! io) return zzip_open_shared_io64 (stream, name, o_flags, o_modes, 
					    ext, io);
    errno = EOVERFLOW; return NULL;
}

_zzip_export
ZZIP_FILE * zzip_open_ext_io(zzip_char_t* name, int o_flags, int o_modes,
			     zzip_strings_t* ext, zzip_plugin_io_t io)
{
    if (! io) return zzip_open_ext_io64 (name, o_flags, o_modes, ext, io);
    errno = EOVERFLOW; return NULL;
}

_zzip_export
ZZIP_DIR *  zzip_opendir_ext_io(zzip_char_t* name, int o_modes,
				zzip_strings_t* ext, zzip_plugin_io_t io)
{
    if (! io) return zzip_opendir_ext_io64 (name, o_modes, ext, io);
    errno = EOVERFLOW; return NULL;
}

#endif /* ZZIP_LARGEFILE_RENAME && EOVERFLOW && PIC */

/* ------------------------------------------------------------------- */

/**                                                                
 * This function will rewind a real/zipped file. 
 *
 * It seeks to the beginning of this file's data in the zip, 
 * or the beginning of the file for a stat'fd.
 */
int
zzip_rewind(ZZIP_FILE *fp)
{
    ZZIP_DIR *dir;
    int err;

    if (! fp)
        return -1;

    if (! fp->dir) 
    { /* stat fd */
        fp->io->seeks(fp->fd,0,SEEK_SET);
        return 0;
    }
    
    dir = fp->dir;
    /*
     * If this is other handle than previous, save current seek pointer
     */
    if (dir->currentfp != fp)  
    {
        if (zzip_file_saveoffset(dir->currentfp) < 0)
        { dir->errcode = ZZIP_DIR_SEEK; return -1; }
        else
        { dir->currentfp = fp; }
    }
    
    /* seek to beginning of this file */
    if (fp->io->seeks(dir->fd, fp->dataoffset, SEEK_SET) < 0)
        return -1;
    
    /* reset the inflate init stuff */
    fp->restlen = fp->usize;
    fp->offset = fp->dataoffset;
    
    if (fp->method) 
    { /* method == 8, deflate */
        memset(&fp->d_stream, 0, sizeof fp->d_stream);
        err = inflateInit2(&fp->d_stream, -MAX_WBITS);
        if (err != Z_OK) { goto error; }
        
        fp->crestlen = fp->csize;
    }

    return 0;
  
 error:
    if (fp) zzip_file_close(fp);
    return err;
}

/**                                                                  
 * This function will perform a => lseek(2) operation on a real/zipped file
 *
 * It will try to seek to the offset specified by offset, relative to whence, 
 * which is one of SEEK_SET, SEEK_CUR or SEEK_END.
 * 
 * If the file-handle is wrapping a stat'able file then it will actually just
 * perform a normal => lseek(2)-call. Otherwise the relative offset
 * is calculated, negative offsets are transformed into positive ones
 * by rewinding the file, and then data is read until the offset is
 * reached.  This can make the function terribly slow, but this is
 * how gzio implements it, so I'm not sure there is a better way
 * without using the internals of the algorithm.
 */
zzip_off_t
zzip_seek(ZZIP_FILE * fp, zzip_off_t offset, int whence)
{
    zzip_off_t cur_pos, rel_ofs, read_size, ofs;
    ZZIP_DIR *dir;
  
    if (! fp)
        return -1;

    if (! fp->dir) 
    { /* stat fd */
        return fp->io->seeks(fp->fd, offset, whence);
    }

    cur_pos = zzip_tell(fp);

    /* calculate relative offset */
    switch (whence) 
    {
    case SEEK_SET: /* from beginning */
        rel_ofs = offset - cur_pos;
        break;
    case SEEK_CUR: /* from current */
        rel_ofs = offset;
        break;
    case SEEK_END: /* from end */
        rel_ofs = fp->usize + offset - cur_pos;
        break;
    default: /* something wrong */
        return -1;
    }

    if (rel_ofs == 0) 
        return cur_pos; /* don't have to move */

    if (rel_ofs < 0) 
    { /* convert backward into forward */
        if (zzip_rewind(fp) == -1) 
            return -1;

        read_size = cur_pos + rel_ofs;
        cur_pos = 0;
    }else
    { /* amount to read is positive relative offset */
        read_size = rel_ofs;
    }

    if (read_size < 0) /* bad offset, before beginning of file */
        return -1;

    if (read_size + cur_pos > (zzip_off_t)fp->usize) /* bad offset, past EOF */
        return -1;

    if (read_size == 0) /* nothing to read */
        return cur_pos;
  
    dir = fp->dir;
    /*
     * If this is other handle than previous, save current seek pointer
     * and read the file position of `this' handle.
     */
    if (dir->currentfp != fp)  
    {
        if (zzip_file_saveoffset(dir->currentfp) < 0 
            || dir->currentfp->io->seeks(dir->fd, fp->offset, SEEK_SET) < 0)
        { dir->errcode = ZZIP_DIR_SEEK; return -1; }
        else
        { dir->currentfp = fp; }
    }
  
    if (fp->method == 0) 
    { /* unstore, just lseek relatively */
        ofs = fp->io->tells(dir->fd);
        ofs = fp->io->seeks(dir->fd,read_size,SEEK_CUR);
        if (ofs > 0) 
        { /* readjust from beginning of file */
            ofs -= fp->dataoffset;
            fp->restlen = fp->usize - ofs;
        }
        return ofs;
    }else 
    { /* method == 8, inflate */
        char *buf;
        /*FIXME: use a static buffer! */
        buf = (char *)malloc(ZZIP_32K);
        if (! buf) return -1;
        
        while (read_size > 0)  
        {
            zzip_off_t size = ZZIP_32K;
            if (read_size < size/*32K*/) size = read_size;

            size = zzip_file_read(fp, buf, (zzip_size_t)size);
            if (size <= 0) { free(buf); return -1; }
      
            read_size -= size;
        }

        free (buf);
    }

    return zzip_tell(fp);
}

/**                                                                  
 * This function will => tell(2) the current position in a real/zipped file
 *
 * It will return the current offset within the real/zipped file, 
 * measured in uncompressed bytes for the zipped-file case.
 *
 * If the file-handle is wrapping a stat'able file then it will actually just
 * perform a normal => tell(2)-call, otherwise the offset is
 * calculated from the amount of data left and the total uncompressed
 * size;
 */
zzip_off_t
zzip_tell(ZZIP_FILE * fp)
{
    if (! fp)
        return -1;

    if (! fp->dir)  /* stat fd */
        return fp->io->tells(fp->fd);

    /* current uncompressed offset is uncompressed size - data left */
    return (fp->usize - fp->restlen);
}

/* 
 * Local variables:
 * c-file-style: "stroustrup"
 * End:
 */
