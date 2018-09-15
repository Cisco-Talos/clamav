#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mspack.h>
#include <ctype.h>
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

#define FILENAME ".test.chmx"

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

/**
 * Creates a UNIX filename from the internal CAB filename and the given
 * parameters.
 *
 * @param fname  the internal CAB filename.
 * @param dir    a directory path to prepend to the output filename.
 * @param lower  if non-zero, filename should be made lower-case.
 * @param isunix if zero, MS-DOS path seperators are used in the internal
 *               CAB filename. If non-zero, UNIX path seperators are used.
 * @param utf8   if non-zero, the internal CAB filename is encoded in UTF8.
 * @return a freshly allocated and created filename, or NULL if there was
 *         not enough memory.
 * @see unix_path_seperators()
 */
static char *create_output_name(unsigned char *fname, unsigned char *dir,
			 int lower, int isunix, int utf8)
{
  unsigned char *p, *name, c, *fe, sep, slash;
  unsigned int x;

  sep   = (isunix) ? '/'  : '\\'; /* the path-seperator */
  slash = (isunix) ? '\\' : '/';  /* the other slash */

  /* length of filename */
  x = strlen((char *) fname);
  /* UTF8 worst case scenario: tolower() expands all chars from 1 to 3 bytes */
  if (utf8) x *= 3;
  /* length of output directory */
  if (dir) x += strlen((char *) dir);

  if (!(name = (unsigned char *) malloc(x + 2))) {
    fprintf(stderr, "out of memory!\n");
    return NULL;
  }
  
  /* start with blank name */
  *name = '\0';

  /* add output directory if needed */
  if (dir) {
    strcpy((char *) name, (char *) dir);
    strcat((char *) name, "/");
  }

  /* remove leading slashes */
  while (*fname == sep) fname++;

  /* copy from fi->filename to new name, converting MS-DOS slashes to UNIX
   * slashes as we go. Also lowercases characters if needed.
   */
  p = &name[strlen((char *)name)];
  fe = &fname[strlen((char *)fname)];

  if (utf8) {
    /* UTF8 translates two-byte unicode characters into 1, 2 or 3 bytes.
     * %000000000xxxxxxx -> %0xxxxxxx
     * %00000xxxxxyyyyyy -> %110xxxxx %10yyyyyy
     * %xxxxyyyyyyzzzzzz -> %1110xxxx %10yyyyyy %10zzzzzz
     *
     * Therefore, the inverse is as follows:
     * First char:
     *  0x00 - 0x7F = one byte char
     *  0x80 - 0xBF = invalid
     *  0xC0 - 0xDF = 2 byte char (next char only 0x80-0xBF is valid)
     *  0xE0 - 0xEF = 3 byte char (next 2 chars only 0x80-0xBF is valid)
     *  0xF0 - 0xFF = invalid
     */
    do {
      if (fname >= fe) {
	free(name);
	return NULL;
      }

      /* get next UTF8 char */
      if ((c = *fname++) < 0x80) x = c;
      else {
	if ((c >= 0xC0) && (c < 0xE0)) {
	  x = (c & 0x1F) << 6;
	  x |= *fname++ & 0x3F;
	}
	else if ((c >= 0xE0) && (c < 0xF0)) {
	  x = (c & 0xF) << 12;
	  x |= (*fname++ & 0x3F) << 6;
	  x |= *fname++ & 0x3F;
	}
	else x = '?';
      }

      /* whatever is the path seperator -> '/'
       * whatever is the other slash    -> '\\'
       * otherwise, if lower is set, the lowercase version */
      if      (x == sep)   x = '/';
      else if (x == slash) x = '\\';
      else if (lower)      x = (unsigned int) tolower((int) x);

      /* integer back to UTF8 */
      if (x < 0x80) {
	*p++ = (unsigned char) x;
      }
      else if (x < 0x800) {
	*p++ = 0xC0 | (x >> 6);   
	*p++ = 0x80 | (x & 0x3F);
      }
      else {
	*p++ = 0xE0 | (x >> 12);
	*p++ = 0x80 | ((x >> 6) & 0x3F);
	*p++ = 0x80 | (x & 0x3F);
      }
    } while (x);
  }
  else {
    /* regular non-utf8 version */
    do {
      c = *fname++;
      if      (c == sep)   c = '/';
      else if (c == slash) c = '\\';
      else if (lower)      c = (unsigned char) tolower((int) c);
    } while ((*p++ = c));
  }
  return (char *) name;
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
	    char *outname = create_output_name((unsigned char *)f[i]->filename,NULL,0,1,0);
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
