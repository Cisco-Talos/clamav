/* This file is part of libmspack.
 * (C) 2003-2004 Stuart Caie.
 *
 * libmspack is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License (LGPL) version 2.1
 *
 * For further details, see the file COPYING.LIB distributed with libmspack
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <mspack.h>
#include "others.h"

int mspack_version(int entity) {
  switch (entity) {
  case MSPACK_VER_LIBRARY:
  case MSPACK_VER_SYSTEM:
  case MSPACK_VER_MSCABD:
  case MSPACK_VER_MSCHMD:
    return 1;
  case MSPACK_VER_MSCABC:
  case MSPACK_VER_MSCHMC:
  case MSPACK_VER_MSLITD:
  case MSPACK_VER_MSLITC:
  case MSPACK_VER_MSHLPD:
  case MSPACK_VER_MSHLPC:
  case MSPACK_VER_MSSZDDD:
  case MSPACK_VER_MSSZDDC:
  case MSPACK_VER_MSKWAJD:
  case MSPACK_VER_MSKWAJC:
    return 0;
  }
  return -1;
}

int mspack_sys_selftest_internal(int offt_size) {
  return (sizeof(off_t) == offt_size) ? MSPACK_ERR_OK : MSPACK_ERR_SEEK;
}

/* validates a system structure */
int mspack_valid_system(struct mspack_system *sys) {
  return (sys != NULL) && (sys->open != NULL) && (sys->close != NULL) &&
    (sys->read != NULL) && (sys->write != NULL) && (sys->seek != NULL) &&
    (sys->tell != NULL) && (sys->message != NULL) && (sys->alloc != NULL) &&
    (sys->free != NULL) && (sys->copy != NULL) && (sys->null_ptr == NULL);
}

/* returns the length of a file opened for reading */
int mspack_sys_filelen(struct mspack_system *system,
		       struct mspack_file *file, off_t *length)
{
  off_t current;

  if (!system || !file || !length) return MSPACK_ERR_OPEN;

  /* get current offset */
  current = system->tell(file);

  /* seek to end of file */
  if (system->seek(file, (off_t) 0, MSPACK_SYS_SEEK_END)) {
    return MSPACK_ERR_SEEK;
  }

  /* get offset of end of file */
  *length = system->tell(file);

  /* seek back to original offset */
  if (system->seek(file, current, MSPACK_SYS_SEEK_START)) {
    return MSPACK_ERR_SEEK;
  }

  return MSPACK_ERR_OK;
}



/* definition of mspack_default_system -- if the library is compiled with
 * MSPACK_NO_DEFAULT_SYSTEM, no default system will be provided. Otherwise,
 * an appropriate default system (e.g. the standard C library, or some native
 * API calls)
 */

#ifdef MSPACK_NO_DEFAULT_SYSTEM
struct mspack_system *mspack_default_system = NULL;
#else

/* implementation of mspack_default_system for standard C library */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

struct mspack_file_p {
  FILE *fh;
  const char *name;
  int desc;
};

static struct mspack_file *msp_open(struct mspack_system *this,
				    char *filename, int mode)
{
  struct mspack_file_p *fh;
  char *fmode;

  switch (mode) {
  case MSPACK_SYS_OPEN_READ:   fmode = "rb";  break;
  case MSPACK_SYS_OPEN_WRITE:  fmode = "wb";  break;
  case MSPACK_SYS_OPEN_UPDATE: fmode = "r+b"; break;
  case MSPACK_SYS_OPEN_APPEND: fmode = "ab";  break;
  default: return NULL;
  }

  if ((fh = malloc(sizeof(struct mspack_file_p)))) {
    fh->name = filename;
    fh->desc = 0;
    if ((fh->fh = fopen(filename, fmode))) return (struct mspack_file *) fh;
    free(fh);
  }
  return NULL;
}

static struct mspack_file *msp_dopen(struct mspack_system *this,
				    int desc, int mode)
{
  struct mspack_file_p *fh;
  char *fmode;

  switch (mode) {
  case MSPACK_SYS_OPEN_READ:   fmode = "rb";  break;
  case MSPACK_SYS_OPEN_WRITE:  fmode = "wb";  break;
  case MSPACK_SYS_OPEN_UPDATE: fmode = "r+b"; break;
  case MSPACK_SYS_OPEN_APPEND: fmode = "ab";  break;
  default: return NULL;
  }

  if ((fh = malloc(sizeof(struct mspack_file_p)))) {
    fh->name = "descriptor";
    fh->desc = desc;
    if ((fh->fh = fdopen(desc, fmode))) return (struct mspack_file *) fh;
    free(fh);
  }
  return NULL;
}

static void msp_close(struct mspack_file *file) {
  struct mspack_file_p *this = (struct mspack_file_p *) file;
  if (this) {
    fclose(this->fh);
    free(this);
  }
}

static int msp_read(struct mspack_file *file, void *buffer, int bytes) {
  struct mspack_file_p *this = (struct mspack_file_p *) file;
  if (this) {
    size_t count = fread(buffer, 1, (size_t) bytes, this->fh);
    if (!ferror(this->fh)) return (int) count;
  }
  return -1;
}

static int msp_write(struct mspack_file *file, void *buffer, int bytes) {
  struct mspack_file_p *this = (struct mspack_file_p *) file;
  if (this) {
    size_t count = fwrite(buffer, 1, (size_t) bytes, this->fh);
    if (!ferror(this->fh)) return (int) count;
  }
  return -1;
}

static int msp_seek(struct mspack_file *file, off_t offset, int mode) {
  struct mspack_file_p *this = (struct mspack_file_p *) file;
  if (this) {
    switch (mode) {
    case MSPACK_SYS_SEEK_START: mode = SEEK_SET; break;
    case MSPACK_SYS_SEEK_CUR:   mode = SEEK_CUR; break;
    case MSPACK_SYS_SEEK_END:   mode = SEEK_END; break;
    default: return -1;
    }
#ifdef HAVE_FSEEKO
    return fseeko(this->fh, offset, mode);
#else
    return fseek(this->fh, offset, mode);
#endif
  }
  return -1;
}

static off_t msp_tell(struct mspack_file *file) {
  struct mspack_file_p *this = (struct mspack_file_p *) file;
#ifdef HAVE_FSEEKO
  return (this) ? (off_t) ftello(this->fh) : 0;
#else
  return (this) ? (off_t) ftell(this->fh) : 0;
#endif
}

static void msp_msg(struct mspack_file *file, char *format, ...) {
  va_list ap;
  char buff[512];

  va_start(ap, format);
  vsnprintf(buff, 512, format, ap);
  va_end(ap);
  cli_dbgmsg("libmspack: %s\n", buff);
}

static void *msp_alloc(struct mspack_system *this, size_t bytes) {
#ifdef DEBUG
  /* make uninitialised data obvious */
  char *buf = malloc(bytes + 8);
  if (buf) memset(buf, 0xDC, bytes);
  *((size_t *)buf) = bytes;
  return &buf[8];
#else
  return cli_calloc(bytes, 1);
#endif
}

static void msp_free(void *buffer) {
#ifdef DEBUG
  char *buf = buffer;
  size_t bytes;
  if (buf) {
    buf -= 8;
    bytes = *((size_t *)buf);
    /* make freed data obvious */
    memset(buf, 0xED, bytes);
    free(buf);
  }
#else
  free(buffer);
#endif
}

static void msp_copy(void *src, void *dest, size_t bytes) {
  memcpy(dest, src, bytes);
}

static struct mspack_system msp_system = {
  &msp_open, &msp_dopen, &msp_close, &msp_read,  &msp_write, &msp_seek,
  &msp_tell, &msp_msg, &msp_alloc, &msp_free, &msp_copy, NULL
};

struct mspack_system *mspack_default_system = &msp_system;

#endif
