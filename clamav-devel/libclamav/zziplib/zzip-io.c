/*
 * Author: 
 *	Guido Draheim <guidod@gmx.de>
 *      Mike Nordell <tamlin@algonet.se>
 *
 *	Copyright (c) 2002 Guido Draheim
 * 	    All rights reserved,
 *	    use under the restrictions of the
 *	    Lesser GNU General Public License
 *          note the additional license information 
 *          that can be found in COPYING.ZZIP
 */

#include <zzip.h>
#include <zzip-io.h>

#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#ifdef DEBUG
#include <stdio.h>
#endif

#include <zzip-file.h>
#include <zzipformat.h>

zzip_off_t
zzip_filesize(int fd)
{
  struct stat st;

  if (fstat(fd, &st) < 0)
    return -1;

# ifdef DEBUG 
  if (! st.st_size && st.st_blocks > 1) /* seen on some darwin 10.1 machines */
      fprintf(stderr, "broken fstat(2) ?? st_size=%ld st_blocks=%ld\n", 
	      (long) st.st_size, (long) st.st_blocks);
# endif

  return st.st_size;
}

#if defined ZZIP_WRAPWRAP
int		zzip_wrap_read(int fd, void* p, unsigned int len)
				{ return _zzip_read (fd, p, len); }
zzip_off_t	zzip_wrap_lseek(int fd, zzip_off_t offset, int whence)
				{ return _zzip_lseek (fd, offset, whence); }
#else
#define zzip_wrap_read  _zzip_read
#define zzip_wrap_lseek _zzip_lseek
#endif

static const struct zzip_plugin_io default_io =
{
    &open,
    &close,
    /* (int (*)(int, void*, unsigned)) */
    &zzip_wrap_read,
    /* (zzip_off_t (*)(int, zzip_off_t, int)) */
    &zzip_wrap_lseek,
    &zzip_filesize,
    1
};

/** => zzip_init_io
 * This function returns a zzip_plugin_io_t handle to static defaults
 * wrapping the posix io file functions for actual file access.
 */
zzip_plugin_io_t
zzip_get_default_io()
{
    return &default_io;
}

/**
 * This function initializes the users handler struct to default values 
 * being the posix io functions in default configured environments.
 */
int zzip_init_io(struct zzip_plugin_io* io, int flags)
{
    if (!io) {
        return ZZIP_ERROR;
    }
    memcpy(io, &default_io, sizeof(default_io));
    io->use_mmap = flags;
    return 0;
}

/* 
 * Local variables:
 * c-file-style: "stroustrup"
 * End:
 */
