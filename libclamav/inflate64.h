/* 
 * This file contains code from zlib library v.1.2.3 with modifications
 * by aCaB <acab@clamav.net> to allow decompression of deflate64 streams
 * (aka zip method 9). The implementation is heavily inspired by InfoZip
 *  and zlib's inf9back.c
 * 
 * Full copy of the original zlib license follows:
 */

/* zlib.h -- interface of the 'zlib' general purpose compression library
  version 1.2.3, July 18th, 2005

  Copyright (C) 1995-2005 Jean-loup Gailly and Mark Adler

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Jean-loup Gailly        Mark Adler
  jloup@gzip.org          madler@alumni.caltech.edu


  The data format used by the zlib library is described by RFCs (Request for
  Comments) 1950 to 1952 in the files http://www.ietf.org/rfc/rfc1950.txt
  (zlib format), rfc1951.txt (deflate format) and rfc1952.txt (gzip format).
*/

#ifndef __INFLATE64_H
#define __INFLATE64_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "others.h"

#ifndef OF /* function prototypes */
#  ifdef STDC
#    define OF(args)  args
#  else
#    define OF(args)  ()
#  endif
#endif

#ifndef ZEXTERN
#  define ZEXTERN extern
#endif
#ifndef ZEXPORT
#  define ZEXPORT
#endif
#ifndef ZEXPORTVA
#  define ZEXPORTVA
#endif

#ifndef FAR
#  define FAR
#endif

#ifndef MAX_WBITS64
#  define MAX_WBITS64   16 /* 64K window */
#endif

struct internal_state;

typedef struct z_stream64_s {
    uint8_t		*next_in;  /* next input byte */
    unsigned long	total_in;  /* total nb of input bytes read so far */
    unsigned int	avail_in;  /* number of bytes available at next_in */

    unsigned int	avail_out; /* remaining free space at next_out */
    uint8_t		*next_out; /* next output byte should be put there */
    unsigned long	total_out; /* total nb of bytes output so far */

    struct internal_state FAR *state; /* not visible by applications */

    unsigned long   adler;      /* adler32 value of the uncompressed data */
    int     data_type;  /* best guess about the data type: binary or text */
} z_stream64;

typedef z_stream64 FAR *z_stream64p;

ZEXTERN int ZEXPORT inflate64 OF((z_stream64p strm, int flush));
ZEXTERN int ZEXPORT inflate64End OF((z_stream64p strm));
ZEXTERN int ZEXPORT inflate64Init2 OF((z_stream64p strm, int  windowBits));

#endif /* __INFLATE64_H */
