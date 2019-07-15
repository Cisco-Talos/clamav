#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mspack.h>
#include <sys/stat.h>
#include <dirent.h>

#include <md5_fh.h>
#include <error.h>

/**
 * Matches a cabinet's filename case-insensitively in the filesystem and
 * returns the case-correct form.
 *
 * @param origcab if this is non-NULL, the pathname part of this filename
 *                will be extracted, and the search will be conducted in
 *                that directory.
 * @param cabname the internal CAB filename to search for.
 * @return a copy of the full, case-correct filename of the given cabinet
 *         filename, or NULL if the specified filename does not exist on disk.
 */
static char *find_cabinet_file(char *origcab, char *cabname) {
    struct dirent *entry;
    struct stat st_buf;
    int found = 0, len;
    char *tail, *cab;
    DIR *dir;

    /* ensure we have a cabinet name at all */
    if (!cabname || !cabname[0]) return NULL;

    /* find if there's a directory path in the origcab */
    tail = origcab ? strrchr(origcab, '/') : NULL;
    len = (tail - origcab) + 1;

    /* allocate memory for our copy */
    if (!(cab = (char *) malloc((tail ? len : 2) + strlen(cabname) + 1))) return NULL;

    /* add the directory path from the original cabinet name, or "." */
    if (tail) memcpy(cab, origcab, (size_t) len);
    else      cab[0]='.', cab[1]='/', len=2;
    cab[len] = '\0';

    /* try accessing the cabinet with its current name (case-sensitive) */
    strcpy(&cab[len], cabname);
    if (stat(cab, &st_buf) == 0) {
        found = 1;
    }
    else {
        /* cabinet was not found, look for it in the current dir */
        cab[len] = '\0';
        if ((dir = opendir(cab))) {
            while ((entry = readdir(dir))) {
                if (strcasecmp(cabname, entry->d_name) == 0) {
                    strcat(cab, entry->d_name);
                    found = (stat(cab, &st_buf) == 0);
                    break;
                }
            }
            closedir(dir);
        }
    }

    if (!found || !S_ISREG(st_buf.st_mode)) {
        /* cabinet not found, or not a regular file */
        free(cab);
        cab = NULL;
    }

    return cab;
}


int main(int argc, char *argv[]) {
    struct mscab_decompressor *cabd;
    struct mscabd_cabinet *cab, *c, *c2;
    struct mscabd_file *file;
    char *cabname, *newname;
    int err;

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    /* if self-test reveals an error */
    MSPACK_SYS_SELFTEST(err);
    if (err) return 1;

    if (!(cabd = mspack_create_cab_decompressor(&read_files_write_md5))) {
        fprintf(stderr, "can't make decompressor\n");
        return 1;
    }

    for (argv++; (cabname = *argv); argv++) {
        printf("*** %s\n", cabname);

        if (!(cab = cabd->open(cabd, cabname))) {
            fprintf(stderr, "cab open error: %s\n", ERROR(cabd));
            continue;
        }

        /* prepend any spanning cabinets */
        for (c = cab; c && (c->flags & MSCAB_HDR_PREVCAB); c = c->prevcab) {
            if (!(newname = find_cabinet_file(cabname, c->prevname))) {
                fprintf(stderr, "%s: can't find \"%s\" to prepend\n",
                        cabname, c->prevname);
                break;
            }
            if (!(c2 = cabd->open(cabd, newname))) {
                fprintf(stderr, "%s: error opening \"%s\" for prepend: %s\n",
                        cabname, newname, ERROR(cabd));
                break;
            }
            if (cabd->prepend(cabd, c, c2) != MSPACK_ERR_OK) {
                fprintf(stderr, "%s: error prepending \"%s\": %s\n",
                        cabname, newname, ERROR(cabd));
                break;
            }
        }

        /* append any spanning cabinets */
        for (c = cab; c && (c->flags & MSCAB_HDR_NEXTCAB); c = c->nextcab) {
            if (!(newname = find_cabinet_file(cabname, c->nextname))) {
                fprintf(stderr, "%s: can't find \"%s\" to append\n",
                        cabname, c->nextname);
                break;
            }
            if (!(c2 = cabd->open(cabd, newname))) {
                fprintf(stderr, "%s: error opening \"%s\" for append: %s\n",
                        cabname, newname, ERROR(cabd));
                break;
            }
            if (cabd->append(cabd, c, c2) != MSPACK_ERR_OK) {
                fprintf(stderr, "%s: error appending \"%s\": %s\n",
                        cabname, newname, ERROR(cabd));
                break;
            }
        }

        /* extract files */
        for (file = cab->files; file; file = file->next ) {
            if (cabd->extract(cabd, file, NULL) == MSPACK_ERR_OK) {
                printf("%s  %s\n", md5_string, file->filename);
            }
            else {
                fprintf(stderr, "%s: error extracting \"%s\": %s\n",
                        cabname, file->filename, ERROR(cabd));
            }
        }

        /* free all resources */
        for (c2 = cab->prevcab; c2; c2 = c2->prevcab) free((void*)c2->filename);
        for (c2 = cab->nextcab; c2; c2 = c2->nextcab) free((void*)c2->filename);
        cabd->close(cabd, cab);
    }
    mspack_destroy_cab_decompressor(cabd);
    return 0;
}
