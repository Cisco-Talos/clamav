#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <mspack.h>
#include <system.h>

#define BUF_SIZE (1024*4096)
char buf[BUF_SIZE];

void rip(char *fname, off_t offset, unsigned int length) {
  static unsigned int counter = 1;
   struct stat st_buf;
  char outname[13];
  FILE *in, *out;

  do {
    snprintf(outname, 13, "%08u.cab", counter++);
  } while (stat(outname, &st_buf) == 0);

  printf("ripping %s offset %" LD " length %u to %s\n",
	 fname, offset, length, outname);

  if ((in = fopen(fname, "rb"))) {
#ifdef HAVE_FSEEKO
    if (!fseeko(in, offset, SEEK_SET)) {
#else
    if (!fseek(in, offset, SEEK_SET)) {
#endif
      if ((out = fopen(outname, "wb"))) {
	while (length > 0) {
	  unsigned int run = BUF_SIZE;
	  if (run > length) run = length;
	  if (fread(&buf[0], 1, run, in) != run) {
	    perror(fname);
	    break;
	  }
	  if (fwrite(&buf[0], 1, run, out) != run) {
	    perror(outname);
	    break;
	  }
	  length -= run;
	}
	fclose(out);
      }
      else {
	perror(outname);
      }
    }
    else {
      perror(fname);
    }
    fclose(in);
  }
  else {
    perror(fname);
  }
}

int main(int argc, char *argv[]) {
  struct mscab_decompressor *cabd;
  struct mscabd_cabinet *cab, *c;
  int err;

  MSPACK_SYS_SELFTEST(err);
  if (err) return 0;

  if ((cabd = mspack_create_cab_decompressor(NULL))) {
    for (argv++; *argv; argv++) {
      if ((cab = cabd->search(cabd, *argv))) {
	for (c = cab; c; c = c->next) rip(*argv, c->base_offset, c->length);
	cabd->close(cabd, cab);
      }
    }
    mspack_destroy_cab_decompressor(cabd);
  }
  return 0;
}
