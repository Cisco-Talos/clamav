/*
 * this is an internal header file - the structure contains two off_t
 * atleast making it LARGEFILE_SENSITIVE on linux2 and solaris systems
 * whereas about all functions just return a ZZIP_FILE* in zzip/zzip.h
 *
 * and so, this structure should be handled version-specific and
 * subject to change - it had been kept binary-compatible for quite
 * a while now so perhaps some program sources have errnously taken
 * advantage of this file.
 *
 * Author: 
 *      Guido Draheim <guidod@gmx.de>
 *      Tomi Ollila <Tomi.Ollila@tfi.net>
 *
 *      Copyright (c) 1999,2000,2001,2002 Guido Draheim
 *          All rights reserved,
 *          use under the restrictions of the
 *          Lesser GNU General Public License
 *          note the additional license information 
 *          that can be found in COPYING.ZZIP
 */

#ifndef _ZZIP_FILE_H /* zzip-file.h */
#define _ZZIP_FILE_H 1

#ifndef ZZIP_32K
#ifdef __GNUC__
/* include zzip/lib.h beforehand in order to suppress the following warning */
#warning zzip/file.h is an internal header, do not use it freely
#endif
#endif

#include <zzip.h>
#include <zlib.h>

#ifdef ZZIP_HAVE_UNISTD_H
#include <unistd.h>
#else
#include <stdio.h>
# ifdef ZZIP_HAVE_SYS_TYPES_H
# include <sys/types.h>
# endif
#endif

#ifdef ZZIP_HAVE_SYS_PARAM_H
#include <sys/param.h> /* PATH_MAX */
#endif

#ifndef PATH_MAX
# ifdef  MAX_PATH /* windows */
# define PATH_MAX MAX_PATH
# else
# define PATH_MAX 512
# endif
#endif
/*
 * ZZIP_FILE structure... currently no need to unionize, since structure needed
 * for inflate is superset of structure needed for unstore.
 *
 * Don't make this public. Instead, create methods for needed operations.
 */

struct zzip_file
{
  struct zzip_dir* dir; 
  int fd;
  int method;
  zzip_size_t restlen;
  zzip_size_t crestlen;
  zzip_size_t usize;
  zzip_size_t csize;
  /* added dataoffset member - data offset from start of zipfile*/
  zzip_off_t dataoffset;
  char* buf32k;
  zzip_off_t offset; /* offset from the start of zipfile... */
  z_stream d_stream;
  zzip_plugin_io_t io;
};

#endif /* _ZZIP_FILE_H */

