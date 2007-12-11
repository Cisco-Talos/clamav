#ifndef INFLATE64_H
#define INFLATE64_H

#include <stdint.h> /* FIXME */

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
    unsigned int	avail_in;  /* number of bytes available at next_in */
    unsigned long	total_in;  /* total nb of input bytes read so far */

    uint8_t		*next_out; /* next output byte should be put there */
    unsigned int	avail_out; /* remaining free space at next_out */
    unsigned long	total_out; /* total nb of bytes output so far */

    struct internal_state FAR *state; /* not visible by applications */

    int     data_type;  /* best guess about the data type: binary or text */
    unsigned long   adler;      /* adler32 value of the uncompressed data */
} z_stream64;

typedef z_stream64 FAR *z_stream64p;

ZEXTERN int ZEXPORT inflate64 OF((z_stream64p strm, int flush));
ZEXTERN int ZEXPORT inflate64End OF((z_stream64p strm));
ZEXTERN int ZEXPORT inflate64Init2 OF((z_stream64p strm, int  windowBits));

#endif /* INFLATE64_H */
