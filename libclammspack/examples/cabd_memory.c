/* An implementation of the mspack_system interface using only memory */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mspack.h>

/* use a pointer to a mem_buf structure as "filenames" */
struct mem_buf {
  void *data;
  size_t length;
};

struct mem_file {
  char *data;
  size_t length, posn;
};

static void *mem_alloc(struct mspack_system *self, size_t bytes) {
  /* put your memory allocator here */
  return malloc(bytes);
}

static void mem_free(void *buffer) {
  /* put your memory deallocator here */
  free(buffer);
}

static void mem_copy(void *src, void *dest, size_t bytes) {
  /* put your own memory copy routine here */
  memcpy(dest, src, bytes);
}

static void mem_msg(struct mem_file *file, const char *format, ...) {
  /* put your own printf-type routine here, or leave it empty */
}

static struct mem_file *mem_open(struct mspack_system *self,
                                 struct mem_buf *fn, int mode)
{
  struct mem_file *fh;
  if (!fn || !fn->data || !fn->length) return NULL;
  if ((fh = (struct mem_file *) mem_alloc(self, sizeof(struct mem_file)))) {
    fh->data   = (char *) fn->data;
    fh->length = fn->length;
    fh->posn   = (mode == MSPACK_SYS_OPEN_APPEND) ? fn->length : 0;
  }
  return fh;
}

static void mem_close(struct mem_file *fh) {
  if (fh) mem_free(fh);
}

static int mem_read(struct mem_file *fh, void *buffer, int bytes) {
  int todo;
  if (!fh || !buffer || bytes < 0) return -1;
  todo = fh->length - fh->posn;
  if (todo > bytes) todo = bytes;
  if (todo > 0) mem_copy(&fh->data[fh->posn], buffer, (size_t) todo);
  fh->posn += todo; return todo;
}

static int mem_write(struct mem_file *fh, void *buffer, int bytes) {
  int todo;
  if (!fh || !buffer || bytes < 0) return -1;
  todo = fh->length - fh->posn;
  if (todo > bytes) todo = bytes;
  if (todo > 0) mem_copy(buffer, &fh->data[fh->posn], (size_t) todo);
  fh->posn += todo; return todo;
}

static int mem_seek(struct mem_file *fh, off_t offset, int mode) {
  if (!fh) return 1;
  switch (mode) {
  case MSPACK_SYS_SEEK_START: break;
  case MSPACK_SYS_SEEK_CUR:   offset += (off_t) fh->posn; break;
  case MSPACK_SYS_SEEK_END:   offset += (off_t) fh->length; break;
  default: return 1;
  }
  if ((offset < 0) || (offset > (off_t) fh->length)) return 1;
  fh->posn = (size_t) offset;
  return 0;
}

static off_t mem_tell(struct mem_file *fh) {
  return (fh) ? (off_t) fh->posn : -1;
}

static struct mspack_system mem_system = {
  (struct mspack_file * (*)(struct mspack_system *, const char *, int)) &mem_open,
  (void (*)(struct mspack_file *)) &mem_close,
  (int (*)(struct mspack_file *, void *, int)) &mem_read, 
  (int (*)(struct mspack_file *, void *, int)) &mem_write,
  (int (*)(struct mspack_file *, off_t, int)) &mem_seek, 
  (off_t (*)(struct mspack_file *)) &mem_tell,
  (void (*)(struct mspack_file *, const char *, ...)) &mem_msg,
  &mem_alloc,
  &mem_free,
  &mem_copy,
  NULL
};

/* example of usage with mscab_decompressor */

/* a simple cabinet */
static unsigned char embedded_cab[] = {
  0x4D,0x53,0x43,0x46,0x00,0x00,0x00,0x00,0xFD,0x00,0x00,0x00,0x00,0x00,0x00,
  0x00,0x2C,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x01,0x01,0x00,0x02,0x00,
  0x00,0x00,0x22,0x06,0x00,0x00,0x5E,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x4D,
  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x6C,0x22,0xBA,0x59,0x20,0x00,
  0x68,0x65,0x6C,0x6C,0x6F,0x2E,0x63,0x00,0x4A,0x00,0x00,0x00,0x4D,0x00,0x00,
  0x00,0x00,0x00,0x6C,0x22,0xE7,0x59,0x20,0x00,0x77,0x65,0x6C,0x63,0x6F,0x6D,
  0x65,0x2E,0x63,0x00,0xBD,0x5A,0xA6,0x30,0x97,0x00,0x97,0x00,0x23,0x69,0x6E,
  0x63,0x6C,0x75,0x64,0x65,0x20,0x3C,0x73,0x74,0x64,0x69,0x6F,0x2E,0x68,0x3E,
  0x0D,0x0A,0x0D,0x0A,0x76,0x6F,0x69,0x64,0x20,0x6D,0x61,0x69,0x6E,0x28,0x76,
  0x6F,0x69,0x64,0x29,0x0D,0x0A,0x7B,0x0D,0x0A,0x20,0x20,0x20,0x20,0x70,0x72,
  0x69,0x6E,0x74,0x66,0x28,0x22,0x48,0x65,0x6C,0x6C,0x6F,0x2C,0x20,0x77,0x6F,
  0x72,0x6C,0x64,0x21,0x5C,0x6E,0x22,0x29,0x3B,0x0D,0x0A,0x7D,0x0D,0x0A,0x23,
  0x69,0x6E,0x63,0x6C,0x75,0x64,0x65,0x20,0x3C,0x73,0x74,0x64,0x69,0x6F,0x2E,
  0x68,0x3E,0x0D,0x0A,0x0D,0x0A,0x76,0x6F,0x69,0x64,0x20,0x6D,0x61,0x69,0x6E,
  0x28,0x76,0x6F,0x69,0x64,0x29,0x0D,0x0A,0x7B,0x0D,0x0A,0x20,0x20,0x20,0x20,
  0x70,0x72,0x69,0x6E,0x74,0x66,0x28,0x22,0x57,0x65,0x6C,0x63,0x6F,0x6D,0x65,
  0x21,0x5C,0x6E,0x22,0x29,0x3B,0x0D,0x0A,0x7D,0x0D,0x0A,0x0D,0x0A
};

int main() {
  struct mscab_decompressor *cabd;
  struct mscabd_cabinet *cab;
  struct mscabd_file *file;
  struct mem_buf source = { &embedded_cab[0], sizeof(embedded_cab) };
  struct mem_buf output;
  int err;

  /* if self-test reveals an error */
  MSPACK_SYS_SELFTEST(err);
  if (err) return 1;

  /* create a cab decompressor using our custom mspack_system interface */
  if ((cabd = mspack_create_cab_decompressor(&mem_system))) {

    /* open a cab file direct from memory */
    if ((cab = cabd->open(cabd, (char *) &source))) {

      /* for all files */
      for (file = cab->files; file; file = file->next) {
        /* fill out our "filename" (memory pointer and length) */
        output.data = (char *) malloc(file->length);
        output.length = file->length;

        /* let cabd extract this file to our memory buffer */
        if (output.data && cabd->extract(cabd, file, (char *) &output)) {
          exit(1);
        }

        /* dump the memory buffer to stdout (for display purposes) */
        printf("Filename: %s\nContents:\n", file->filename);
        fwrite(output.data, 1, output.length, stdout);

        /* free our buffer */
        free(output.data);
      }
      cabd->close(cabd, cab);
    }
    else {
      fprintf(stderr, "can't open cabinet (%d)\n", cabd->last_error(cabd));
    }
    mspack_destroy_cab_decompressor(cabd);
  }
  else {
    fprintf(stderr, "can't make decompressor\n");
  }
  return 0;

}
