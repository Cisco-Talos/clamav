#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mspack.h>

#include <error.h>

int main(int argc, char *argv[]) {
    struct msoab_decompressor *oabd;
    int err;

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    MSPACK_SYS_SELFTEST(err);
    if (err) return 0;

    if ((oabd = mspack_create_oab_decompressor(NULL))) {
        if (argc == 3) {
            err = oabd->decompress(oabd, argv[1], argv[2]);
            if (err) fprintf(stderr, "%s -> %s: %s\n", argv[1], argv[2], error_msg(err));
        }
        else if (argc == 4) {
            err = oabd->decompress_incremental(oabd, argv[2], argv[1], argv[3]);
            if (err) fprintf(stderr, "%s + %s -> %s: %s\n", argv[1], argv[2], argv[3], error_msg(err));
        }
        else {
            fprintf(stderr, "Usage: %s <input> <output>\n", *argv);
            fprintf(stderr, "   or  %s <base> <patch> <output>\n", *argv);
        }
        mspack_destroy_oab_decompressor(oabd);
    }
    else {
        fprintf(stderr, "%s: can't make OAB decompressor\n", *argv);
    }
    return 0;
}
