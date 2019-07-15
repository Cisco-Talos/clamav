#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <mspack.h>
#include <system.h>

#if HAVE_FSEEKO
# define fseek fseeko
#endif

#define BUF_SIZE (1024*4096)
char buf[BUF_SIZE];

void rip(char *fname, off_t offset, unsigned int length) {
    static unsigned int counter = 1;
    struct stat st_buf;
    char outname[13];
    FILE *in = NULL, *out = NULL;

    /* find an unused output filename */
    do {
        snprintf(outname, 13, "%08u.cab", counter++);
    } while (stat(outname, &st_buf) == 0);

    printf("ripping %s offset %" LD " length %u to %s\n",
           fname, offset, length, outname);

    if (!(in = fopen(fname, "rb"))) {
        perror(fname);
        goto cleanup;
    }
    if (!(out = fopen(outname, "wb"))) {
        perror(outname);
        goto cleanup;
    }
    if (fseek(in, offset, SEEK_SET)) {
        fprintf(stderr, "%s: can't seek to cab offset %"LD"\n", fname, offset);
        goto cleanup;
    }
    while (length) {
        size_t run = (length > BUF_SIZE) ? BUF_SIZE : length;
        size_t actual = fread(&buf[0], 1, run, in);
        if (actual < run) {
            fprintf(stderr, "%s: file %u bytes shorter than expected\n",
                    fname, length - (unsigned int)(run - actual));
            length = run = actual;
        }
        if (fwrite(&buf[0], 1, run, out) != run) {
            perror(outname);
            break;
        }
        length -= run;
    }

cleanup:
    if (in) fclose(in);
    if (out) fclose(out);
}

int main(int argc, char *argv[]) {
    struct mscab_decompressor *cabd;
    struct mscabd_cabinet *cab, *c;
    int err;

    MSPACK_SYS_SELFTEST(err);
    if (err) return 0;

    if ((cabd = mspack_create_cab_decompressor(NULL))) {
        cabd->set_param(cabd, MSCABD_PARAM_SALVAGE, 1);
        for (argv++; *argv; argv++) {
            if ((cab = cabd->search(cabd, *argv))) {
                for (c = cab; c; c = c->next) {
                    rip(*argv, c->base_offset, c->length);
                }
                cabd->close(cabd, cab);
            }
        }
        mspack_destroy_cab_decompressor(cabd);
    }
    return 0;
}
