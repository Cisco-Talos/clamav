/* acts like Microsoft's EXPAND.EXE */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mspack.h>
#include <error.h>

int main(int argc, char *argv[]) {
    struct msszdd_decompressor *szddd;
    struct mskwaj_decompressor *kwajd;
    int err;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input file> <output file>\n", argv[0]);
        return 1;
    }

    /* exit if self-test reveals an error */
    MSPACK_SYS_SELFTEST(err);
    if (err) return 1;

    szddd = mspack_create_szdd_decompressor(NULL);
    kwajd = mspack_create_kwaj_decompressor(NULL);

    if (szddd && kwajd) {
        err = szddd->decompress(szddd, argv[1], argv[2]);
        /* if not SZDD file, try decompressing as KWAJ */
        if (err == MSPACK_ERR_SIGNATURE) {
            err = kwajd->decompress(kwajd, argv[1], argv[2]);
        }
        if (err != MSPACK_ERR_OK) {
            fprintf(stderr, "%s -> %s: %s\n", argv[1], argv[2], error_msg(err));
        }
    }
    else {
         fprintf(stderr, "can't create SZDD/KWAJ decompressor\n");
         err = 1;
    }

    mspack_destroy_szdd_decompressor(szddd);
    mspack_destroy_kwaj_decompressor(kwajd);
    return err ? 1 : 0;
}
