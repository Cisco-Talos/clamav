#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mspack.h>
#include <sys/stat.h>

#include <error.h>

#if HAVE_MKDIR
# if MKDIR_TAKES_ONE_ARG
#  define mkdir(a, b) mkdir(a)
# endif
#else
# if HAVE__MKDIR
#  define mkdir(a, b) _mkdir(a)
# else
#  error "Don't know how to create a directory on this system."
# endif
#endif

mode_t user_umask;

/**
 * Ensures that all directory components in a filepath exist. New directory
 * components are created, if necessary.
 *
 * @param path the filepath to check
 * @return non-zero if all directory components in a filepath exist, zero
 *         if components do not exist and cannot be created
 */
static int ensure_filepath(char *path) {
  struct stat st_buf;
  char *p;
  int ok;

  for (p = &path[1]; *p; p++) {
    if (*p != '/') continue;
    *p = '\0';
    ok = (stat(path, &st_buf) == 0) && S_ISDIR(st_buf.st_mode);
    if (!ok) ok = (mkdir(path, 0777 & ~user_umask) == 0);
    *p = '/';
    if (!ok) return 0;
  }
  return 1;
}

char *create_output_name(char *fname) {
    char *out, *p;
    if ((out = malloc(strlen(fname) + 1))) {
        /* remove leading slashes */
        while (*fname == '/' || *fname == '\\') fname++;
        /* if that removes all characters, just call it "x" */
        strcpy(out, (*fname) ? fname : "x");

        /* change "../" to "xx/" */
        for (p = out; *p; p++) {
            if (p[0] == '.' && p[1] == '.' && (p[2] == '/' || p[2] == '\\')) {
               p[0] = p[1] = 'x';
            }
        }
    }
    return out;
}

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

  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
  user_umask = umask(0); umask(user_umask);

  MSPACK_SYS_SELFTEST(i);
  if (i) return 0;

  if ((chmd = mspack_create_chm_decompressor(NULL))) {
    for (argv++; *argv; argv++) {
      printf("%s\n", *argv);
      if ((chm = chmd->open(chmd, *argv))) {

        /* build an ordered list of files for maximum extraction speed */
        for (numf=0, file=chm->files; file; file = file->next) numf++;
        if ((f = (struct mschmd_file **) calloc(numf, sizeof(struct mschmd_file *)))) {
          for (i=0, file=chm->files; file; file = file->next) f[i++] = file;
          qsort(f, numf, sizeof(struct mschmd_file *), &sortfunc);

          for (i = 0; i < numf; i++) {
            char *outname = create_output_name(f[i]->filename);
            printf("Extracting %s\n", outname);
            ensure_filepath(outname);
            if (chmd->extract(chmd, f[i], outname)) {
              printf("%s: extract error on \"%s\": %s\n",
                     *argv, f[i]->filename, ERROR(chmd));
            }
            free(outname);
          }
          free(f);
        }
        chmd->close(chmd, chm);
      }
      else {
        printf("%s: can't open -- %s\n", *argv, ERROR(chmd));
      }
    }
    mspack_destroy_chm_decompressor(chmd);
  }
  return 0;
}
