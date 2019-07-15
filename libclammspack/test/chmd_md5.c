#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mspack.h>

#include <md5_fh.h>
#include <error.h>

static int sortfunc(const void *a, const void *b) {
  off_t diff = 
    ((* ((struct mschmd_file **) a))->offset) -
    ((* ((struct mschmd_file **) b))->offset);
  return (diff < 0) ? -1 : ((diff > 0) ? 1 : 0);
}

int main(int argc, char *argv[]) {
  struct mschm_decompressor *chmd;
  struct mschmd_header *chm;
  struct mschmd_file *file, **f;
  unsigned int numf, i;
  int err;

  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  MSPACK_SYS_SELFTEST(err);
  if (err) return 0;

  if ((chmd = mspack_create_chm_decompressor(&read_files_write_md5))) {
    for (argv++; *argv; argv++) {
      printf("*** %s\n", *argv);
      if ((chm = chmd->open(chmd, *argv))) {

        /* extract in order of the offset into content section - faster */
        for (numf=0, file=chm->files; file; file = file->next) numf++;
        if ((f = (struct mschmd_file **) calloc(numf, sizeof(struct mschmd_file *)))) {
          for (i=0, file=chm->files; file; file = file->next) f[i++] = file;
          qsort(f, numf, sizeof(struct mschmd_file *), &sortfunc);
          for (i = 0; i < numf; i++) {
            if (chmd->extract(chmd, f[i], NULL)) {
              fprintf(stderr, "%s: extract error on \"%s\": %s\n",
                      *argv, f[i]->filename, ERROR(chmd));
            }
            else {
              printf("%s %s\n", md5_string, f[i]->filename);
            }
          }
          free(f);
        }

        chmd->close(chmd, chm);
      }
      else {
        fprintf(stderr, "%s: can't open -- %s\n", *argv, ERROR(chmd));
      }
    }
    mspack_destroy_chm_decompressor(chmd);
  }
  else {
    fprintf(stderr, "%s: can't make CHM decompressor\n", *argv);
  }
  return 0;
}
