/* an mspack_system implementation which reads one or more files, and
 * only writes to one file; the file is not actually written to, but
 * an MD5 sum is computed and is available once the written-to file is
 * closed. You can use anything for the written-to filename, NULL is
 * probably the most obvious. The code is not multithreadable.
 */

#include <md5.h>
#include <stdio.h>
#include <stdarg.h>

struct md5_ctx md5_context;
char md5_string[33];

struct mspack_file_p {
    FILE *fh;
};

static struct mspack_file *m_open(struct mspack_system *self, const char *filename, int mode) {
    struct mspack_file_p *fh;
    if (mode != MSPACK_SYS_OPEN_WRITE &&
        mode != MSPACK_SYS_OPEN_READ) return NULL;

    if ((fh = (struct mspack_file_p *) malloc(sizeof(struct mspack_file_p)))) {
        if (mode == MSPACK_SYS_OPEN_WRITE) {
            fh->fh = NULL;
            md5_init_ctx(&md5_context);
            return (struct mspack_file *) fh;
        }
        else {
            if ((fh->fh = fopen(filename, "rb")))
                return (struct mspack_file *) fh;
        }
        /* error - free file handle and return NULL */
        free(fh);
    }
    return NULL;
}

static void m_close(struct mspack_file *file) {
  struct mspack_file_p *self = (struct mspack_file_p *) file;
  if (self) {
      if (self->fh) fclose(self->fh);
      else {
          unsigned char md5[16];
          md5_finish_ctx(&md5_context, (void *) &md5);
          snprintf(md5_string, sizeof(md5_string),
                   "%02x%02x%02x%02x%02x%02x%02x%02x"
                   "%02x%02x%02x%02x%02x%02x%02x%02x",
                   md5[0],  md5[1],  md5[2],  md5[3],
                   md5[4],  md5[5],  md5[6],  md5[7],
                   md5[8],  md5[9],  md5[10], md5[11],
                   md5[12], md5[13], md5[14], md5[15]);
      }
      free(self);
  }
}

static int m_read(struct mspack_file *file, void *buffer, int bytes) {
  struct mspack_file_p *self = (struct mspack_file_p *) file;
  if (self && self->fh && buffer && bytes >= 0) {
      size_t count = fread(buffer, 1, bytes, self->fh);
      if (!ferror(self->fh)) return (int) count;
  }
  return -1;
}

static int m_write(struct mspack_file *file, void *buffer, int bytes) {
    struct mspack_file_p *self = (struct mspack_file_p *) file;
    if (!self || self->fh || !buffer || bytes < 0) return -1;
    md5_process_bytes(buffer, bytes, &md5_context);
    return bytes;
}

static int m_seek(struct mspack_file *file, off_t offset, int mode) {
    struct mspack_file_p *self = (struct mspack_file_p *) file;
    if (self && self->fh) {
        switch (mode) {
        case MSPACK_SYS_SEEK_START: mode = SEEK_SET; break;
        case MSPACK_SYS_SEEK_CUR:   mode = SEEK_CUR; break;
        case MSPACK_SYS_SEEK_END:   mode = SEEK_END; break;
        default: return -1;
        }
#if HAVE_FSEEKO
        return fseeko(self->fh, offset, mode);
#else
        return fseek(self->fh, offset, mode);
#endif
    }
    return -1;
}

static off_t m_tell(struct mspack_file *file) {
    struct mspack_file_p *self = (struct mspack_file_p *) file;
#if HAVE_FSEEKO
    return (self && self->fh) ? (off_t) ftello(self->fh) : 0;
#else
    return (self && self->fh) ? (off_t) ftell(self->fh) : 0;
#endif
}

static void m_msg(struct mspack_file *file, const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
    fputc((int) '\n', stderr);
    fflush(stderr);
}
static void *m_alloc(struct mspack_system *self, size_t bytes) {
    return malloc(bytes);
}
static void m_free(void *buffer) {
    free(buffer);
}
static void m_copy(void *src, void *dest, size_t bytes) {
    memcpy(dest, src, bytes);
}

static struct mspack_system read_files_write_md5 = {
    &m_open, &m_close, &m_read, &m_write, &m_seek,
    &m_tell, &m_msg, &m_alloc, &m_free, &m_copy, NULL
};
