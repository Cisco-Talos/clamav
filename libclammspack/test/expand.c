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
    struct msszddd_header *szdd;
    struct mskwajd_header *kwaj;
    int err;

    if (argc != 3) {
	fprintf(stderr, "Usage: %s <input file> <output file>\n", argv[0]);
	return 1;
    }

    /* if self-test reveals an error */
    MSPACK_SYS_SELFTEST(err);
    if (err) return 1;

    szddd = mspack_create_szdd_decompressor(NULL);
    kwajd = mspack_create_kwaj_decompressor(NULL);

    if (!szddd || !kwajd) {
	fprintf(stderr, "can't make either SZDD or KWAJ decompressor\n");
	mspack_destroy_szdd_decompressor(szddd);
	mspack_destroy_kwaj_decompressor(kwajd);
	return 1;
    }

    /* open then extract; try SZDD */
    if ((szdd = szddd->open(szddd, argv[1]))) {
	if (szddd->extract(szddd, szdd, argv[2]) != MSPACK_ERR_OK) {
	    fprintf(stderr, "%s: SZDD extract error: %s\n", argv[2], ERROR(szddd));
	}
	szddd->close(szddd, szdd);
    }
    else {
	if (szddd->last_error(szddd) == MSPACK_ERR_SIGNATURE) {
	    /* try KWAJ */
	    if ((kwaj = kwajd->open(kwajd, argv[1]))) {
		if (kwajd->extract(kwajd, kwaj, argv[2]) != MSPACK_ERR_OK) {
		    fprintf(stderr, "%s: KWAJ extract error: %s\n", argv[2], ERROR(kwajd));
		}
		kwajd->close(kwajd, kwaj);
	    }
	    else {
		fprintf(stderr, "%s: KWAJ open error: %s\n", argv[1], ERROR(kwajd));
	    }
	}
	else {
	    fprintf(stderr, "%s: SZDD open error: %s\n", argv[1], ERROR(szddd));
	}
    }

    /* decompress in a single step; try KWAJ */
    if (kwajd->decompress(kwajd, argv[1], argv[2]) != MSPACK_ERR_OK) {
	if (kwajd->last_error(kwajd) == MSPACK_ERR_SIGNATURE) {
	    if (szddd->decompress(szddd, argv[1], argv[2]) != MSPACK_ERR_OK) {
		fprintf(stderr, "%s -> %s: SZDD decompress error: %s\n", argv[1], argv[2], ERROR(szddd));
	    }
	}
	else {
	    fprintf(stderr, "%s -> %s: KWAJ decompress error: %s\n", argv[1], argv[2], ERROR(kwajd));
	}
    }

    mspack_destroy_szdd_decompressor(szddd);
    mspack_destroy_kwaj_decompressor(kwajd);
    return 0;
}
