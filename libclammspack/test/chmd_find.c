/* chmd_find: tests fast-find functionality
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mspack.h>

#include <error.h>
#include <system.h>

void find(struct mschm_decompressor *chmd, struct mschmd_header *chm,
          char *archive, char *filename, struct mschmd_file *compare)
{
    struct mschmd_file result;
    if (chmd->fast_find(chmd, chm, filename, &result, sizeof(result))) {
        fprintf(stderr, "%s: find error on \"%s\": %s\n",
                archive, filename, ERROR(chmd));
    }
    else if (!result.section) {
        if (compare) {
            fprintf(stderr, "%s: file \"%s\" not found\n", archive, filename);
        }
        else {
            printf("%s: file \"%s\" not found\n", archive, filename);
        }
    }
    else {
        printf("%s\n", filename);
        printf(" section: %d\n", result.section->id);
        printf(" offset:  %" LD "\n", result.offset);
        printf(" length:  %" LD "\n", result.length);
        if (compare) {
            if (result.section->id != compare->section->id) {
                fprintf(stderr, "%s: found file \"%s\" section is wrong "
                        "(%d vs %d)\n", archive, filename,
                        result.section->id, compare->section->id);
            }

            if (result.offset != compare->offset) {
                fprintf(stderr, "%s: found file \"%s\" offset is wrong "
                        "(%" LD " vs %" LD ")\n", archive, filename,
                        result.offset, compare->offset);
            }

            if (result.length != compare->length) {
                fprintf(stderr, "%s: found file \"%s\" length is wrong "
                        "(%" LD " vs %" LD ")\n", archive, filename,
                        result.length, compare->length);
            }
        }
    }
}

int main(int argc, char *argv[]) {
    struct mschm_decompressor *chmd;
    struct mschmd_header *chm, *chm2;
    unsigned int i;

    if (argc < 2 || argc > 3) {
        printf("Usage: %s <file.chm> [filename to find]\n", argv[0]);
        return 1;
    }

    MSPACK_SYS_SELFTEST(i);
    if (i) return 0;

    if ((chmd = mspack_create_chm_decompressor(NULL))) {
        if ((chm = chmd->fast_open(chmd, argv[1]))) {
            if (argv[2]) {
                find(chmd, chm, argv[1], argv[2], NULL);
            }
            else {
                if ((chm2 = chmd->open(chmd, argv[1]))) {
                    struct mschmd_file *file;
                    for (file = chm2->files; file; file = file->next) {
                        find(chmd, chm, argv[1], file->filename, file);
                    }
                }
                else {
                    printf("%s: can't open -- %s\n", argv[1], ERROR(chmd));
                }
            }
            chmd->close(chmd, chm);
        }
        else {
            printf("%s: can't open -- %s\n", argv[1], ERROR(chmd));
        }
        mspack_destroy_chm_decompressor(chmd);
    }
    return 0;
}
