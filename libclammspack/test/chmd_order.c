/* chmd_order: test that extracting a CHM file in different ways works
 * and all give the same results:
 * - extracting files in the order they're listed (generally alphabetical)
 * - extracting files ordered by their content section offset
 * - extracting files using fast_find() to find them
 * - extracting files from two chms at the same time with one decompressor
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mspack.h>

#include <md5_fh.h>
#include <error.h>

struct my_file {
    struct mschmd_file *file;
    struct mschmd_file result;
    char ordered[32], sorted[32], fast_find[32], mixed[32];
};

static int sortfunc(const void *a, const void *b) {
  off_t diff =
    ((struct my_file *) a)->file->offset -
    ((struct my_file *) b)->file->offset;
  return (diff < 0) ? -1 : ((diff > 0) ? 1 : 0);
}

int main(int argc, char *argv[]) {
    struct mschm_decompressor *chmd;
    struct mschmd_header *chm, *chm2;
    struct mschmd_file *file;
    struct my_file *f;
    unsigned int N, i;

    MSPACK_SYS_SELFTEST(i);
    if (i) return 0;

    if ((chmd = mspack_create_chm_decompressor(&read_files_write_md5))) {
        for (argv++; *argv; argv++) {
            printf("%s\n", *argv);

            if ((chm = chmd->open(chmd, *argv))) {
                if ((chm2 = chmd->fast_open(chmd, *argv))) {

                    /* count the number of files, allocate a results structure */
                    for (N=0, file = chm->files; file; file = file->next) N++;
                    if ((f = (struct my_file *) calloc(N, sizeof(struct my_file)))) {
                        
                        /* fill out results structure while doing ordered extraction */
                        for (i = 0, file = chm->files; file; file = file->next, i++) {
                            printf("OX %s\n", file->filename);
                            f[i].file = file;
                            if (chmd->extract(chmd, file, NULL)) {
                                fprintf(stderr, "%s: O extract error on \"%s\": %s\n",
                                        *argv, file->filename, ERROR(chmd));
                                continue;
                            }
                            memcpy(&f[i].ordered[0], md5_string, 32);
                        }

                        /* sort the list into offset order */
                        qsort(f, N, sizeof(struct my_file), &sortfunc);

                        /* extract in offset order */
                        for (i = 0; i < N; i++) {
                            printf("SX %s\n", f[i].file->filename);
                            if (chmd->extract(chmd, f[i].file, NULL)) {
                                fprintf(stderr, "%s: S extract error on \"%s\": %s\n",
                                        *argv, f[i].file->filename, ERROR(chmd));
                                continue;
                            }
                            memcpy(&f[i].sorted[0], md5_string, 32);
                        }

                        /* extract using fast_find */
                        for (i = 0; i < N; i++) {
                            printf("FX %s\n", f[i].file->filename);
                            
                            if (chmd->fast_find(chmd, chm2,
                                f[i].file->filename,
                                &f[i].result, sizeof(struct mschmd_file)))
                            {
                                fprintf(stderr, "%s: find error on \"%s\": %s\n",
                                        *argv, f[i].file->filename, ERROR(chmd));
                                continue;
                            }
                            if (!f[i].result.section) {
                                fprintf(stderr, "%s: can't find file \"%s\"\n",
                                        *argv, f[i].file->filename);
                                continue;
                            }
                            if (chmd->extract(chmd, &f[i].result, NULL)) {
                                fprintf(stderr, "%s: F extract error on \"%s\": %s\n",
                                        *argv, f[i].file->filename, ERROR(chmd));
                                continue;
                            }
                            memcpy(&f[i].fast_find[0], md5_string, 32);
                        }

                        /* extract two chms at once */
                        for (i = 0; i < N; i++) {
                            printf("MX %s\n", f[i].file->filename);
                            chmd->extract(chmd, f[i].file, NULL);
                            if (chmd->extract(chmd, &f[i].result, NULL)) {
                                fprintf(stderr, "%s: M extract error on \"%s\": %s\n",
                                        *argv, f[i].file->filename, ERROR(chmd));
                                continue;
                            }
                            memcpy(&f[i].mixed[0], md5_string, 32);
                        }

                        /* check all the MD5 sums match */
                        for (i = 0; i < N; i++) {
                            if (memcmp(&f[i].ordered, &f[i].sorted,    32) ||
                                memcmp(&f[i].ordered, &f[i].fast_find, 32) ||
                                memcmp(&f[i].ordered, &f[i].mixed,     32))
                             {
                                 fprintf(stderr, "%s: sums mismatch on %s "
                                         "(O=%32.32s,S=%32.32s,F=%32.32s,M=%32.32s)\n",
                                         *argv, f[i].file->filename,
                                         &f[i].ordered[0], &f[i].sorted[0],
                                         &f[i].fast_find[0], &f[i].mixed[0]);
                             }
                        }

                        free(f);
                    }
                    chmd->close(chmd, chm2);
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
