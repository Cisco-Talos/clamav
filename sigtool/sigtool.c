/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *  Copyright (C) 2002-2007 Tomasz Kojm <tkojm@clamav.net>
 *
 *  CDIFF code (C) 2006 Sensory Networks, Inc.
 *
 *  Author: Tomasz Kojm <tkojm@clamav.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <time.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <libgen.h>

#ifndef _WIN32
#include <sys/resource.h>
#endif

// libclamav
#include "clamav.h"
#include "matcher.h"
#include "cvd.h"
#include "dsig.h"
#include "str.h"
#include "ole2_extract.h"
#include "htmlnorm.h"
#include "textnorm.h"
#include "default.h"
#include "fmap.h"
#include "readdb.h"
#include "others.h"
#include "pe.h"
#include "entconv.h"
#include "clamav_rust.h"

// common
#include "output.h"
#include "optparser.h"
#include "misc.h"
#include "tar.h"

#include "vba.h"

#define MAX_DEL_LOOKAHEAD 5000

// global variable for the absolute path of the --cvdcertsdir option
char *g_cvdcertsdir = NULL;

// struct s_info info;
short recursion = 0, bell = 0;
short printinfected = 0, printclean = 1;

static const struct dblist_s {
    const char *ext;
    unsigned int count;
} dblist[] = {

    /* special files */
    {"info", 0},
    {"cfg", 0},
    {"ign", 0},
    {"ign2", 0},
    {"ftm", 0},

    /* databases */
    {"db", 1},
    {"hdb", 1},
    {"hdu", 1},
    {"hsb", 1},
    {"hsu", 1},
    {"mdb", 1},
    {"mdu", 1},
    {"msb", 1},
    {"msu", 1},
    {"ndb", 1},
    {"ndu", 1},
    {"ldb", 1},
    {"ldu", 1},
    {"sdb", 1},
    {"zmd", 1},
    {"rmd", 1},
    {"idb", 0},
    {"fp", 1}, // TODO Should count be 0 here?  We don't count others like this
    {"sfp", 0},
    {"gdb", 1},
    {"pdb", 1},
    {"wdb", 0},
    {"crb", 1},
    {"cdb", 1},
    {"imp", 1},
    // TODO Should we add .ioc, .yar, .yara, and .pwdb so that sigtool will
    // include these sigs in a build (just in case we need this functionality
    // in the future?)

    {NULL, 0}};

static char *getdbname(const char *str, char *dst, int dstlen)
{
    int len = strlen(str);

    if (cli_strbcasestr(str, ".cvd") || cli_strbcasestr(str, ".cld") || cli_strbcasestr(str, ".cud"))
        len -= 4;

    if (dst) {
        strncpy(dst, str, MIN(dstlen - 1, len));
        dst[MIN(dstlen - 1, len)] = 0;
    } else {
        dst = (char *)malloc(len + 1);
        if (!dst)
            return NULL;
        strncpy(dst, str, len - 4);
        dst[MIN(dstlen - 1, len - 4)] = 0;
    }
    return dst;
}

static int hexdump(void)
{
    char buffer[FILEBUFF], *pt;
    int bytes;

    while ((bytes = read(0, buffer, FILEBUFF)) > 0) {
        pt = cli_str2hex(buffer, bytes);
        if (write(1, pt, 2 * bytes) == -1) {
            mprintf(LOGG_ERROR, "hexdump: Can't write to stdout\n");
            free(pt);
            return -1;
        }
        free(pt);
    }

    if (bytes == -1)
        return -1;

    return 0;
}

static int hashpe(const char *filename, unsigned int class, cli_hash_type_t type)
{
    int status = -1;
    STATBUF sb;
    const char *fmptr;
    struct cl_engine *engine       = NULL;
    cli_ctx ctx                    = {0};
    struct cl_scan_options options = {0};
    cl_fmap_t *new_map             = NULL;
    int fd                         = -1;
    cl_error_t ret;

    /* Prepare file */
    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        mprintf(LOGG_ERROR, "hashpe: Can't open file %s!\n", filename);
        goto done;
    }

    lseek(fd, 0, SEEK_SET);
    FSTAT(fd, &sb);

    new_map = fmap_new(fd, 0, sb.st_size, filename, filename);
    if (NULL == new_map) {
        mprintf(LOGG_ERROR, "hashpe: Can't create fmap for open file\n");
        goto done;
    }

    /* build engine */
    if (!(engine = cl_engine_new())) {
        mprintf(LOGG_ERROR, "hashpe: Can't create new engine\n");
        goto done;
    }
    cl_engine_set_num(engine, CL_ENGINE_AC_ONLY, 1);

    if (cli_initroots(engine, 0) != CL_SUCCESS) {
        mprintf(LOGG_ERROR, "hashpe: cli_initroots() failed\n");
        goto done;
    }

    if (cli_add_content_match_pattern(engine->root[0], "test", "deadbeef", 0, 0, 0, "*", NULL, 0) != CL_SUCCESS) {
        mprintf(LOGG_ERROR, "hashpe: Can't parse signature\n");
        goto done;
    }

    if (cl_engine_compile(engine) != CL_SUCCESS) {
        mprintf(LOGG_ERROR, "hashpe: Can't compile engine\n");
        goto done;
    }

    /* prepare context */
    ctx.engine = engine;

    ctx.options        = &options;
    ctx.options->parse = ~0;
    ctx.dconf          = (struct cli_dconf *)engine->dconf;

    ctx.recursion_stack_size = ctx.engine->max_recursion_level;
    ctx.recursion_stack      = calloc(sizeof(cli_scan_layer_t), ctx.recursion_stack_size);
    if (!ctx.recursion_stack) {
        goto done;
    }

    // ctx was memset, so recursion_level starts at 0.
    ctx.recursion_stack[ctx.recursion_level].fmap = new_map;
    ctx.recursion_stack[ctx.recursion_level].type = CL_TYPE_ANY; // ANY for the top level, because we don't yet know the type.
    ctx.recursion_stack[ctx.recursion_level].size = new_map->len;

    ctx.fmap = ctx.recursion_stack[ctx.recursion_level].fmap;

    fmptr = fmap_need_off_once(ctx.fmap, 0, sb.st_size);
    if (!fmptr) {
        mprintf(LOGG_ERROR, "hashpe: fmap_need_off_once failed!\n");
        goto done;
    }

    cl_debug();

    /* Send to PE-specific hasher */
    switch (class) {
        case 1:
            ret = cli_genhash_pe(&ctx, CL_GENHASH_PE_CLASS_SECTION, type, NULL);
            break;
        case 2:
            ret = cli_genhash_pe(&ctx, CL_GENHASH_PE_CLASS_IMPTBL, type, NULL);
            break;
        default:
            mprintf(LOGG_ERROR, "hashpe: unknown classification(%u) for pe hash!\n", class);
            goto done;
    }

    /* THIS MAY BE UNNECESSARY */
    switch (ret) {
        case CL_CLEAN:
            break;
        case CL_VIRUS:
            mprintf(LOGG_DEBUG, "hashpe: CL_VIRUS after cli_genhash_pe()!\n");
            break;
        case CL_BREAK:
            mprintf(LOGG_DEBUG, "hashpe: CL_BREAK after cli_genhash_pe()!\n");
            break;
        case CL_EFORMAT:
            mprintf(LOGG_ERROR, "hashpe: Not a valid PE file!\n");
            break;
        default:
            mprintf(LOGG_ERROR, "hashpe: Other error %d inside cli_genhash_pe.\n", ret);
            break;
    }

    status = 0;

done:
    /* Cleanup */
    if (NULL != new_map) {
        fmap_free(new_map);
    }
    if (NULL != ctx.recursion_stack) {
        if (ctx.recursion_stack[ctx.recursion_level].evidence) {
            evidence_free(ctx.recursion_stack[ctx.recursion_level].evidence);
        }
        free(ctx.recursion_stack);
    }
    if (NULL != engine) {
        cl_engine_free(engine);
    }
    if (-1 != fd) {
        close(fd);
    }
    return status;
}

static int hashsig(const struct optstruct *opts, unsigned int class, cli_hash_type_t type)
{
    char *hash;
    unsigned int i;
    STATBUF sb;

    if (opts->filename) {
        for (i = 0; opts->filename[i]; i++) {
            if (CLAMSTAT(opts->filename[i], &sb) == -1) {
                perror("hashsig");
                mprintf(LOGG_ERROR, "hashsig: Can't access file %s\n", opts->filename[i]);
                return -1;
            } else {
                if ((sb.st_mode & S_IFMT) == S_IFREG) {
                    if ((class == 0) && (hash = cli_hashfile(opts->filename[i], NULL, type))) {
                        mprintf(LOGG_INFO, "%s:%u:%s\n", hash, (unsigned int)sb.st_size, basename(opts->filename[i]));
                        free(hash);
                    } else if ((class > 0) && (hashpe(opts->filename[i], class, type) == 0)) {
                        /* intentionally empty - printed in cli_genhash_pe() */
                    } else {
                        mprintf(LOGG_ERROR, "hashsig: Can't generate hash for %s\n", opts->filename[i]);
                        return -1;
                    }
                }
            }
        }

    } else { /* stream */
        if (class > 0) {
            mprintf(LOGG_ERROR, "hashsig: Can't generate requested hash for input stream\n");
            return -1;
        }
        hash = cli_hashstream(stdin, NULL, type);
        if (!hash) {
            mprintf(LOGG_ERROR, "hashsig: Can't generate hash for input stream\n");
            return -1;
        }
        mprintf(LOGG_INFO, "%s\n", hash);
        free(hash);
    }

    return 0;
}

static int fuzzy_img_file(char *filename)
{
    int status = -1;

    int target_fd                   = -1;
    FFIError *fuzzy_hash_calc_error = NULL;
    uint8_t *mem                    = NULL;

    image_fuzzy_hash_t hash = {0};
    STATBUF st;
    ssize_t bytes_read;

    if ((target_fd = open(filename, O_RDONLY)) == -1) {
        char err[128];
        mprintf(LOGG_ERROR, "%s: Can't open file: %s\n", basename(filename), cli_strerror(errno, err, sizeof(err)));
        goto done;
    }

    if (FSTAT(target_fd, &st)) {
        char err[128];
        mprintf(LOGG_ERROR, "%s: fstat() failed: %s\n", basename(filename), cli_strerror(errno, err, sizeof(err)));
        goto done;
    }

    if (NULL == (mem = malloc((size_t)st.st_size))) {
        mprintf(LOGG_ERROR, "%s: Malloc failed, buffer size: %zu\n", basename(filename), (size_t)st.st_size);
        goto done;
    }

    bytes_read = read(target_fd, mem, (size_t)st.st_size);
    if (bytes_read == -1) {
        char err[128];
        mprintf(LOGG_ERROR, "%s: Failed to read file: %s\n", basename(filename), cli_strerror(errno, err, sizeof(err)));
        goto done;
    }
    if (bytes_read < (ssize_t)st.st_size) {
        mprintf(LOGG_ERROR, "%s: Read fewer bytes than expected. The file may have been modified while attempting to process it.\n", basename(filename));
        goto done;
    }

    if (!fuzzy_hash_calculate_image(mem, (size_t)st.st_size, hash.hash, 8, &fuzzy_hash_calc_error)) {
        mprintf(LOGG_ERROR, "%s: Failed to calculate image fuzzy hash: %s\n",
                basename(filename),
                ffierror_fmt(fuzzy_hash_calc_error));
        goto done;
    }

    char hashstr[17];
    snprintf(hashstr, 17, "%02x%02x%02x%02x%02x%02x%02x%02x",
             hash.hash[0], hash.hash[1], hash.hash[2], hash.hash[3],
             hash.hash[4], hash.hash[5], hash.hash[6], hash.hash[7]);
    mprintf(LOGG_INFO, "%s: %s\n", basename(filename), hashstr);

    status = 0;

done:

    if (NULL != mem) {
        free(mem);
    }

    if (NULL != fuzzy_hash_calc_error) {
        ffierror_free(fuzzy_hash_calc_error);
    }

    if (target_fd != -1) {
        close(target_fd);
    }

    return status;
}

static int fuzzy_img(const struct optstruct *opts)
{
    int status = 0;
    int ret;

    size_t i;

    if (!opts->filename) {
        mprintf(LOGG_ERROR, "You must provide one or more files to generate a hash.");
        status = -1;
        goto done;
    }

    for (i = 0; opts->filename[i]; i++) {
        ret = fuzzy_img_file(opts->filename[i]);
        if (ret != 0) {
            // report failure if any of the files fail
            status = -1;
        }
    }

done:

    return status;
}

static cli_ctx *convenience_ctx(int fd, const char *filepath)
{
    cl_error_t status        = CL_EMEM;
    cli_ctx *ctx             = NULL;
    struct cl_engine *engine = NULL;
    cl_fmap_t *new_map       = NULL;

    /* build engine */
    engine = cl_engine_new();
    if (NULL == engine) {
        printf("convenience_ctx: engine initialization failed\n");
        goto done;
    }

    cl_engine_set_num(engine, CL_ENGINE_AC_ONLY, 1);

    if (cli_initroots(engine, 0) != CL_SUCCESS) {
        printf("convenience_ctx: cli_initroots() failed\n");
        goto done;
    }

    if (cli_add_content_match_pattern(engine->root[0], "test", "deadbeef", 0, 0, 0, "*", NULL, 0) != CL_SUCCESS) {
        printf("convenience_ctx: Can't parse signature\n");
        goto done;
    }

    if (CL_SUCCESS != cl_engine_compile(engine)) {
        printf("convenience_ctx: failed to compile engine.");
        goto done;
    }

    /* fake input fmap */
    new_map = fmap_new(fd, 0, 0, NULL, filepath);
    if (NULL == new_map) {
        printf("convenience_ctx: fmap failed\n");
        goto done;
    }

    /* prepare context */
    ctx = calloc(1, sizeof(cli_ctx));
    if (!ctx) {
        printf("convenience_ctx: ctx allocation failed\n");
        goto done;
    }

    ctx->engine = (const struct cl_engine *)engine;

    ctx->dconf = (struct cli_dconf *)engine->dconf;

    ctx->recursion_stack_size = ctx->engine->max_recursion_level;
    ctx->recursion_stack      = calloc(sizeof(cli_scan_layer_t), ctx->recursion_stack_size);
    if (!ctx->recursion_stack) {
        status = CL_EMEM;
        goto done;
    }

    // ctx was calloc'd, so recursion_level starts at 0.
    ctx->recursion_stack[ctx->recursion_level].fmap = new_map;
    ctx->recursion_stack[ctx->recursion_level].type = CL_TYPE_ANY; // ANY for the top level, because we don't yet know the type.
    ctx->recursion_stack[ctx->recursion_level].size = new_map->len;

    ctx->fmap = ctx->recursion_stack[ctx->recursion_level].fmap;

    ctx->options = calloc(1, sizeof(struct cl_scan_options));
    if (!ctx->options) {
        printf("convenience_ctx: scan options allocation failed\n");
        goto done;
    }
    ctx->options->general |= CL_SCAN_GENERAL_HEURISTICS;
    ctx->options->parse = ~(0);

    status = CL_SUCCESS;

done:
    if (CL_SUCCESS != status) {
        if (NULL != new_map) {
            fmap_free(new_map);
        }
        if (NULL != ctx) {
            if (NULL != ctx->options) {
                free(ctx->options);
            }
            if (NULL != ctx->recursion_stack) {
                if (ctx->recursion_stack[ctx->recursion_level].evidence) {
                    evidence_free(ctx->recursion_stack[ctx->recursion_level].evidence);
                }
                free(ctx->recursion_stack);
            }
            free(ctx);
            ctx = NULL;
        }
        if (NULL != engine) {
            cl_engine_free(engine);
        }
    }

    return ctx;
}

static void destroy_ctx(cli_ctx *ctx)
{
    if (NULL != ctx) {
        if (NULL != ctx->recursion_stack) {
            /* Clean up any fmaps */
            while (ctx->recursion_level > 0) {
                if (NULL != ctx->recursion_stack[ctx->recursion_level].fmap) {
                    fmap_free(ctx->recursion_stack[ctx->recursion_level].fmap);
                    ctx->recursion_stack[ctx->recursion_level].fmap = NULL;
                }
                ctx->recursion_level -= 1;
            }

            if (NULL != ctx->recursion_stack[0].fmap) {
                fmap_free(ctx->recursion_stack[0].fmap);
                ctx->recursion_stack[0].fmap = NULL;
            }

            if (NULL != ctx->recursion_stack[0].evidence) {
                evidence_free(ctx->recursion_stack[0].evidence);
                ctx->recursion_stack[0].evidence = NULL;
            }

            free(ctx->recursion_stack);
            ctx->recursion_stack = NULL;
        }

        if (NULL != ctx->engine) {
            cl_engine_free((struct cl_engine *)ctx->engine);
            ctx->engine = NULL;
        }

        if (NULL != ctx->options) {
            free(ctx->options);
            ctx->options = NULL;
        }

        free(ctx);
    }
}

static int htmlnorm(const struct optstruct *opts)
{
    int fd;
    cli_ctx *ctx = NULL;

    if ((fd = open(optget(opts, "html-normalise")->strarg, O_RDONLY | O_BINARY)) == -1) {
        mprintf(LOGG_ERROR, "htmlnorm: Can't open file %s\n", optget(opts, "html-normalise")->strarg);
        return -1;
    }

    if (NULL != (ctx = convenience_ctx(fd, optget(opts, "html-normalise")->strarg))) {
        html_normalise_map(ctx, ctx->fmap, ".", NULL, NULL);
    } else {
        mprintf(LOGG_ERROR, "fmap failed\n");
    }

    close(fd);

    destroy_ctx(ctx);

    return 0;
}

static int asciinorm(const struct optstruct *opts)
{
    const char *fname;
    unsigned char *norm_buff;
    struct text_norm_state state;
    size_t map_off;
    fmap_t *map;
    int fd, ofd;

    fname = optget(opts, "ascii-normalise")->strarg;
    fd    = open(fname, O_RDONLY | O_BINARY);

    if (fd == -1) {
        mprintf(LOGG_ERROR, "asciinorm: Can't open file %s\n", fname);
        return -1;
    }

    if (!(norm_buff = malloc(ASCII_FILE_BUFF_LENGTH))) {
        mprintf(LOGG_ERROR, "asciinorm: Can't allocate memory\n");
        close(fd);
        return -1;
    }

    if (!(map = fmap_new(fd, 0, 0, fname, fname))) {
        mprintf(LOGG_ERROR, "fmap: Could not map fd %d\n", fd);
        close(fd);
        free(norm_buff);
        return -1;
    }

    if (map->len > MAX_ASCII_FILE_SIZE) {
        mprintf(LOGG_ERROR, "asciinorm: File size of %zu too large\n", map->len);
        close(fd);
        free(norm_buff);
        fmap_free(map);
        return -1;
    }

    ofd = open("./normalised_text", O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR);
    if (ofd == -1) {
        mprintf(LOGG_ERROR, "asciinorm: Can't open file ./normalised_text\n");
        close(fd);
        free(norm_buff);
        fmap_free(map);
        return -1;
    }

    text_normalize_init(&state, norm_buff, ASCII_FILE_BUFF_LENGTH);

    map_off = 0;
    while (map_off != map->len) {
        size_t written;
        if (!(written = text_normalize_map(&state, map, map_off))) break;
        map_off += written;

        if (write(ofd, norm_buff, state.out_pos) == -1) {
            mprintf(LOGG_ERROR, "asciinorm: Can't write to file ./normalised_text\n");
            close(fd);
            close(ofd);
            free(norm_buff);
            fmap_free(map);
            return -1;
        }
        text_normalize_reset(&state);
    }

    close(fd);
    close(ofd);
    free(norm_buff);
    fmap_free(map);
    return 0;
}

static int utf16decode(const struct optstruct *opts)
{
    const char *fname;
    char *newname, buff[512], *decoded;
    int fd1, fd2, bytes;

    fname = optget(opts, "utf16-decode")->strarg;
    if ((fd1 = open(fname, O_RDONLY | O_BINARY)) == -1) {
        mprintf(LOGG_ERROR, "utf16decode: Can't open file %s\n", fname);
        return -1;
    }

    newname = malloc(strlen(fname) + 7);
    if (!newname) {
        mprintf(LOGG_ERROR, "utf16decode: Can't allocate memory\n");
        close(fd1);
        return -1;
    }
    sprintf(newname, "%s.ascii", fname);

    if ((fd2 = open(newname, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR)) < 0) {
        mprintf(LOGG_ERROR, "utf16decode: Can't create file %s\n", newname);
        free(newname);
        close(fd1);
        return -1;
    }

    while ((bytes = read(fd1, buff, sizeof(buff))) > 0) {
        decoded = cli_utf16toascii(buff, bytes);
        if (decoded) {
            if (write(fd2, decoded, strlen(decoded)) == -1) {
                mprintf(LOGG_ERROR, "utf16decode: Can't write to file %s\n", newname);
                free(decoded);
                close(fd1);
                close(fd2);
                unlink(newname);
                free(newname);
                return -1;
            }
            free(decoded);
        }
    }

    free(newname);
    close(fd1);
    close(fd2);

    return 0;
}

static char *sha2_256_file(const char *file, unsigned int *size)
{
    FILE *fh;
    unsigned int i, bytes;
    unsigned char digest[32], buffer[FILEBUFF];
    char *sha;
    void *ctx;

    ctx = cl_hash_init("sha2-256");
    if (!(ctx))
        return NULL;

    if (!(fh = fopen(file, "rb"))) {
        mprintf(LOGG_ERROR, "sha2_256_file: Can't open file %s\n", file);
        cl_hash_destroy(ctx);
        return NULL;
    }
    if (size)
        *size = 0;
    while ((bytes = fread(buffer, 1, sizeof(buffer), fh))) {
        cl_update_hash(ctx, buffer, bytes);
        if (size)
            *size += bytes;
    }
    cl_finish_hash(ctx, digest);
    sha = (char *)malloc(65);
    if (!sha) {
        fclose(fh);
        return NULL;
    }
    for (i = 0; i < 32; i++)
        sprintf(sha + i * 2, "%02x", digest[i]);

    fclose(fh);
    return sha;
}

static int writeinfo(const char *dbname, const char *builder, const char *header, const struct optstruct *opts, char *const *dblist2, unsigned int dblist2cnt)
{
    FILE *fh;
    unsigned int i, bytes;
    char file[4096], *pt, dbfile[4096];
    unsigned char digest[32], buffer[FILEBUFF];
    void *ctx;

    snprintf(file, sizeof(file), "%s.info", dbname);
    if (!access(file, R_OK)) {
        if (unlink(file) == -1) {
            mprintf(LOGG_ERROR, "writeinfo: Can't unlink %s\n", file);
            return -1;
        }
    }

    if (!(fh = fopen(file, "wb+"))) {
        mprintf(LOGG_ERROR, "writeinfo: Can't create file %s\n", file);
        return -1;
    }

    if (fprintf(fh, "%s\n", header) < 0) {
        mprintf(LOGG_ERROR, "writeinfo: Can't write to %s\n", file);
        fclose(fh);
        return -1;
    }

    if (dblist2cnt) {
        for (i = 0; i < dblist2cnt; i++) {
            if (!(pt = sha2_256_file(dblist2[i], &bytes))) {
                mprintf(LOGG_ERROR, "writeinfo: Can't generate SHA2-256 for %s\n", file);
                fclose(fh);
                return -1;
            }
            if (fprintf(fh, "%s:%u:%s\n", dblist2[i], bytes, pt) < 0) {
                mprintf(LOGG_ERROR, "writeinfo: Can't write to info file\n");
                fclose(fh);
                free(pt);
                return -1;
            }
            free(pt);
        }
    }
    if (!dblist2cnt || optget(opts, "hybrid")->enabled) {
        for (i = 0; dblist[i].ext; i++) {
            snprintf(dbfile, sizeof(dbfile), "%s.%s", dbname, dblist[i].ext);
            if (strcmp(dblist[i].ext, "info") && !access(dbfile, R_OK)) {
                if (!(pt = sha2_256_file(dbfile, &bytes))) {
                    mprintf(LOGG_ERROR, "writeinfo: Can't generate SHA2-256 for %s\n", file);
                    fclose(fh);
                    return -1;
                }
                if (fprintf(fh, "%s:%u:%s\n", dbfile, bytes, pt) < 0) {
                    mprintf(LOGG_ERROR, "writeinfo: Can't write to info file\n");
                    fclose(fh);
                    free(pt);
                    return -1;
                }
                free(pt);
            }
        }
    }
    if (!optget(opts, "unsigned")->enabled) {
        rewind(fh);
        ctx = cl_hash_init("sha2-256");
        if (!(ctx)) {
            fclose(fh);
            return -1;
        }

        while ((bytes = fread(buffer, 1, sizeof(buffer), fh)))
            cl_update_hash(ctx, buffer, bytes);
        cl_finish_hash(ctx, digest);
        if (!(pt = cli_getdsig(optget(opts, "server")->strarg, builder, digest, 32, 3))) {
            mprintf(LOGG_ERROR, "writeinfo: Can't get digital signature from remote server\n");
            fclose(fh);
            return -1;
        }
        fprintf(fh, "DSIG:%s\n", pt);
        free(pt);
    }
    fclose(fh);
    return 0;
}

static int diffdirs(const char *old, const char *new, const char *patch);
static int verifydiff(const struct optstruct *opts, const char *diff, const char *cvd, const char *incdir);

static int qcompare(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

char *createTempDir(const struct optstruct *opts);
void removeTempDir(const struct optstruct *opts, char *dir)
{
    if (!optget(opts, "leave-temps")->enabled) {
        cli_rmdirs(dir);
    }
}

/**
 * @brief Determine the name of the sign file based on the target file name.
 *
 * If the target file name ends with '.cvd', '.cud', or '.cld' then the sign file name will be
 * 'name-version.cvd.sign', 'name-version.cud.sign', or 'name-version.cld.sign' respectively.
 *
 * If the target file name does not end with '.cvd', '.cud', or '.cld' then the sign file name will be
 * 'target.sign'.
 *
 * The sign file name will be placed in the same directory as the target file.
 *
 * If the target file is a CVD file, the version number will be extracted from the CVD file.
 *
 * The caller is responsible for freeing the memory allocated for the sign file name.
 *
 * @param target  The target file name.
 * @return char*
 */
static char *get_sign_file_name(char *target)
{
    char *sign_file_name     = NULL;
    char *dir                = NULL;
    FFIError *cvd_open_error = NULL;
    uint32_t cvd_version     = 0;
    char *cvd_name           = NULL;
    cvd_t *cvd               = NULL;
    char *target_dup         = NULL;

    cvd_type cvd_type         = CVD_TYPE_UNKNOWN;
    const char *cvd_extension = NULL;

    // If the target filename ends with '.cvd',
    // the sign file name will be 'name-version.cvd.sign'
    if (cli_strbcasestr(target, ".cvd")) {
        cvd_type      = CVD_TYPE_CVD;
        cvd_extension = "cvd";
    } else if (cli_strbcasestr(target, ".cld")) {
        cvd_type      = CVD_TYPE_CLD;
        cvd_extension = "cld";
    } else if (cli_strbcasestr(target, ".cud")) {
        cvd_type      = CVD_TYPE_CUD;
        cvd_extension = "cud";
    }

    if (cvd_type != CVD_TYPE_UNKNOWN) {
        // Signing a signature archive.  We need to open the CVD file to get the version to use in the .sign file name.
        cvd = cvd_open(target, &cvd_open_error);
        if (NULL == cvd) {
            mprintf(LOGG_ERROR, "get_sign_file_name: Failed to open CVD file '%s': %s\n", target, ffierror_fmt(cvd_open_error));
            goto done;
        }

        cvd_version = cvd_get_version(cvd);
        cvd_name    = cvd_get_name(cvd);

        // get the directory from the target filename
        target_dup = strdup(target);
        if (NULL == target_dup) {
            mprintf(LOGG_ERROR, "get_sign_file_name: Failed to duplicate target filepath.\n");
            goto done;
        }
        dir = dirname(target_dup);
        if (NULL == dir) {
            mprintf(LOGG_ERROR, "get_sign_file_name: Failed to get directory from target filename.\n");
            goto done;
        }

        sign_file_name = calloc(1, strlen(dir) + 1 + strlen(cvd_name) + 1 + (3 * sizeof(uint32_t) + 2) + 1 + strlen(cvd_extension) + strlen(".sign") + 1);
        if (NULL == sign_file_name) {
            mprintf(LOGG_ERROR, "get_sign_file_name: Memory allocation error.\n");
            goto done;
        }

        sprintf(sign_file_name, "%s/%s-%u.%s.sign", dir, cvd_name, cvd_version, cvd_extension);
    } else {
        // sign file name will just be the target filename with an added '.sign' extension
        sign_file_name = malloc(strlen(target) + strlen(".sign") + 1);
        if (NULL == sign_file_name) {
            mprintf(LOGG_ERROR, "get_sign_file_name: Memory allocation error.\n");
            goto done;
        }
        strcpy(sign_file_name, target);
        strcat(sign_file_name, ".sign");
    }

done:

    if (NULL != cvd_name) {
        ffi_cstring_free(cvd_name);
    }
    if (NULL != cvd) {
        cvd_free(cvd);
    }
    if (NULL != target_dup) {
        free(target_dup);
    }
    if (NULL != cvd_open_error) {
        ffierror_free(cvd_open_error);
    }

    return sign_file_name;
}

static int sign(const struct optstruct *opts)
{
    int ret = -1;
    const struct optstruct *opt;

    char *target         = NULL;
    char *sign_file_name = NULL;

    char *signing_key = NULL;

    char **certs       = NULL;
    size_t certs_count = 0;

    bool sign_result          = false;
    FFIError *sign_file_error = NULL;

    bool append = false;

    target = optget(opts, "sign")->strarg;
    if (NULL == target) {
        mprintf(LOGG_ERROR, "sign: No target file specified.\n");
        mprintf(LOGG_ERROR, "To sign a file with sigtool, you must specify a target file and use the --key and --cert options.\n");
        mprintf(LOGG_ERROR, "For example:  sigtool --sign myfile.cvd --key /path/to/private.key --cert /path/to/public.crt --cert /path/to/intermediate.crt --cert /path/to/root-ca.crt\n");
        goto done;
    }

    sign_file_name = get_sign_file_name(target);
    if (NULL == sign_file_name) {
        mprintf(LOGG_ERROR, "sign: Failed to determine sign file name from target: %s\n", target);
        goto done;
    }

    signing_key = optget(opts, "key")->strarg;
    if (NULL == target) {
        mprintf(LOGG_ERROR, "sign: No private key specified.\n");
        mprintf(LOGG_ERROR, "To sign a file with sigtool, you must specify a target file and use the --key and --cert options.\n");
        mprintf(LOGG_ERROR, "For example:  sigtool --sign myfile.cvd --key /path/to/private.key --cert /path/to/public.crt --cert /path/to/intermediate.crt --cert /path/to/root-ca.crt\n");
        goto done;
    }

    opt = optget(opts, "cert");
    if (NULL == opt) {
        mprintf(LOGG_ERROR, "sign: No signing or intermediate certificates specified.\n");
        mprintf(LOGG_ERROR, "To sign a file with sigtool, you must specify a target file and use the --key and --cert options.\n");
        mprintf(LOGG_ERROR, "For example:  sigtool --sign myfile.cvd --key /path/to/private.key --cert /path/to/public.crt --cert /path/to/intermediate.crt --cert /path/to/root-ca.crt\n");
        goto done;
    }

    while (opt) {
        if (!opt->strarg) {
            mprintf(LOGG_ERROR, "sign: The --cert option requires a path value to a signing or intermediate certificate.\n");
            mprintf(LOGG_ERROR, "To sign a file with sigtool, you must specify a target file and use the --key and --cert options.\n");
            mprintf(LOGG_ERROR, "For example:  sigtool --sign myfile.cvd --key /path/to/private.key --cert /path/to/public.crt --cert /path/to/intermediate.crt --cert /path/to/root-ca.crt\n");
            goto done;
        }

        certs_count += 1;

        certs = realloc(certs, certs_count * sizeof(char *));
        if (NULL == certs) {
            mprintf(LOGG_ERROR, "sign: Memory allocation error.\n");
            goto done;
        }

        certs[certs_count - 1] = opt->strarg;

        opt = opt->nextarg;
    }

    if (optget(opts, "append")->enabled) {
        append = true;
    }

    sign_result = codesign_sign_file(
        target,
        sign_file_name,
        signing_key,
        (const char **)certs,
        certs_count,
        append,
        &sign_file_error);

    if (!sign_result) {
        mprintf(LOGG_ERROR, "sign: Failed to sign file '%s': %s\n", target, ffierror_fmt(sign_file_error));
        goto done;
    }

    mprintf(LOGG_INFO, "sign: Successfully signed file '%s', and placed the signature in '%s'\n", target, sign_file_name);
    ret = 0;

done:

    if (NULL != sign_file_name) {
        free(sign_file_name);
    }
    if (NULL != certs) {
        free(certs);
    }
    if (NULL != sign_file_error) {
        ffierror_free(sign_file_error);
    }

    return ret;
}

static int verify(const struct optstruct *opts)
{
    int ret              = -1;
    char *target         = NULL;
    char *sign_file_name = NULL;

    char *signer_name           = NULL;
    bool verify_result          = false;
    FFIError *verify_file_error = NULL;

    void *verifier               = NULL;
    FFIError *new_verifier_error = NULL;

    target = optget(opts, "verify")->strarg;
    if (NULL == target) {
        mprintf(LOGG_ERROR, "verify: No target file specified.\n");
        mprintf(LOGG_ERROR, "To verify a file signed with sigtool, you must specify a target file. "
                            "You may also override the default certificates directory using --cvdcertsdir. "
                            "For example:  sigtool --verify myfile.cvd --cvdcertsdir /path/to/certs/\n");
        goto done;
    }

    sign_file_name = get_sign_file_name(target);
    if (NULL == sign_file_name) {
        mprintf(LOGG_ERROR, "verify: Failed to determine sign file name.\n");
        goto done;
    }

    if (!codesign_verifier_new(g_cvdcertsdir, &verifier, &new_verifier_error)) {
        mprintf(LOGG_ERROR, "verify: Failed to create verifier: %s\n", ffierror_fmt(new_verifier_error));
        goto done;
    }

    verify_result = codesign_verify_file(
        target,
        sign_file_name,
        verifier,
        &signer_name,
        &verify_file_error);
    if (!verify_result) {
        mprintf(LOGG_ERROR, "verify: Failed to verify file '%s': %s\n", target, ffierror_fmt(verify_file_error));
        goto done;
    }

    mprintf(LOGG_INFO, "verify: Successfully verified file '%s' with signature '%s', signed by '%s'\n", target, sign_file_name, signer_name);
    ret = 0;

done:

    if (NULL != signer_name) {
        ffi_cstring_free(signer_name);
    }
    if (NULL != sign_file_name) {
        free(sign_file_name);
    }
    if (NULL != verify_file_error) {
        ffierror_free(verify_file_error);
    }
    if (NULL != verifier) {
        codesign_verifier_free(verifier);
    }
    if (NULL != new_verifier_error) {
        ffierror_free(new_verifier_error);
    }

    return ret;
}

static int build(const struct optstruct *opts)
{
    int ret, bc = 0, hy = 0;
    size_t bytes;
    unsigned int i, sigs = 0, oldsigs = 0, entries = 0, version, real_header, fl, maxentries;
    STATBUF foo;
    unsigned char buffer[FILEBUFF];
    char *tarfile, header[513], smbuff[32], builder[33], *pt, olddb[512];
    char patch[50], broken[57], dbname[32], dbfile[4096];
    const char *newcvd, *localdbdir = NULL;
    struct cl_engine *engine;
    FILE *cvd, *fh;
    gzFile tar;
    time_t timet;
    struct tm *brokent;
    struct cl_cvd *oldcvd;
    char **dblist2          = NULL;
    unsigned int dblist2cnt = 0;
    DIR *dd;
    struct dirent *dent;
    unsigned int dboptions = 0;

#define FREE_LS(x)                   \
    for (i = 0; i < dblist2cnt; i++) \
        free(x[i]);                  \
    free(x);

    if (!optget(opts, "server")->enabled && !optget(opts, "unsigned")->enabled) {
        mprintf(LOGG_ERROR, "build: --server is required for --build\n");
        return -1;
    }

    if (optget(opts, "datadir")->active)
        localdbdir = optget(opts, "datadir")->strarg;

    if (CLAMSTAT("COPYING", &foo) == -1) {
        mprintf(LOGG_ERROR, "build: COPYING file not found in current working directory.\n");
        return -1;
    }

    getdbname(optget(opts, "build")->strarg, dbname, sizeof(dbname));
    if (!strcmp(dbname, "bytecode"))
        bc = 1;

    if (optget(opts, "hybrid")->enabled)
        hy = 1;

    if (!(engine = cl_engine_new())) {
        mprintf(LOGG_ERROR, "build: Can't initialize antivirus engine\n");
        return 50;
    }

    if (NULL != g_cvdcertsdir) {
        if ((ret = cl_engine_set_str(engine, CL_ENGINE_CVDCERTSDIR, g_cvdcertsdir))) {
            logg(LOGG_ERROR, "cli_engine_set_str(CL_ENGINE_CVDCERTSDIR) failed: %s\n", cl_strerror(ret));
            cl_engine_free(engine);
            return -1;
        }
    }

    dboptions = CL_DB_STDOPT | CL_DB_PUA | CL_DB_SIGNED;

    if (optget(opts, "fips-limits")->enabled) {
        dboptions |= CL_DB_FIPS_LIMITS;
    }

    if ((ret = cl_load(".", engine, &sigs, dboptions))) {
        mprintf(LOGG_ERROR, "build: Can't load database: %s\n", cl_strerror(ret));
        cl_engine_free(engine);
        return -1;
    }
    cl_engine_free(engine);

    if (!sigs) {
        mprintf(LOGG_ERROR, "build: There are no signatures in database files\n");
    } else {
        if (bc || hy) {
            if ((dd = opendir(".")) == NULL) {
                mprintf(LOGG_ERROR, "build: Can't open current directory\n");
                return -1;
            }
            while ((dent = readdir(dd))) {
                if (dent->d_ino) {
                    if (cli_strbcasestr(dent->d_name, ".cbc")) {
                        dblist2 = (char **)realloc(dblist2, (dblist2cnt + 1) * sizeof(char *));
                        if (!dblist2) { /* dblist2 leaked but we don't really care */
                            mprintf(LOGG_ERROR, "build: Memory allocation error\n");
                            closedir(dd);
                            return -1;
                        }
                        dblist2[dblist2cnt] = strdup(dent->d_name);
                        if (!dblist2[dblist2cnt]) {
                            FREE_LS(dblist2);
                            mprintf(LOGG_ERROR, "build: Memory allocation error\n");
                            return -1;
                        }
                        dblist2cnt++;
                    }
                }
            }
            closedir(dd);
            entries += dblist2cnt;
            if (dblist2 != NULL) {
                qsort(dblist2, dblist2cnt, sizeof(char *), qcompare);
            }

            if (!access("last.hdb", R_OK)) {
                if (!dblist2cnt) {
                    mprintf(LOGG_ERROR, "build: dblist2 == NULL (no .cbc files?)\n");
                    return -1;
                }
                dblist2 = (char **)realloc(dblist2, (dblist2cnt + 1) * sizeof(char *));
                if (!dblist2) {
                    mprintf(LOGG_ERROR, "build: Memory allocation error\n");
                    return -1;
                }
                dblist2[dblist2cnt] = strdup("last.hdb");
                if (!dblist2[dblist2cnt]) {
                    FREE_LS(dblist2);
                    mprintf(LOGG_ERROR, "build: Memory allocation error\n");
                    return -1;
                }
                dblist2cnt++;
                entries += countlines("last.hdb");
            }
        }
        if (!bc || hy) {
            for (i = 0; dblist[i].ext; i++) {
                snprintf(dbfile, sizeof(dbfile), "%s.%s", dbname, dblist[i].ext);
                if (dblist[i].count && !access(dbfile, R_OK))
                    entries += countlines(dbfile);
            }
        }

        if (entries != sigs)
            mprintf(LOGG_WARNING, "build: Signatures in %s db files: %u, loaded by libclamav: %u\n", dbname, entries, sigs);

        maxentries = optget(opts, "max-bad-sigs")->numarg;

        if (maxentries) {
            if (!entries || (sigs > entries && sigs - entries >= maxentries)) {
                mprintf(LOGG_ERROR, "Bad number of signatures in database files\n");
                FREE_LS(dblist2);
                return -1;
            }
        }
    }

    /* try to read cvd header of current database */
    if (opts->filename) {
        if (cli_strbcasestr(opts->filename[0], ".cvd") || cli_strbcasestr(opts->filename[0], ".cld") || cli_strbcasestr(opts->filename[0], ".cud")) {
            strncpy(olddb, opts->filename[0], sizeof(olddb));
            olddb[sizeof(olddb) - 1] = '\0';
        } else {
            mprintf(LOGG_ERROR, "build: Not a CVD/CLD/CUD file\n");
            FREE_LS(dblist2);
            return -1;
        }

    } else {
        pt = freshdbdir();
        snprintf(olddb, sizeof(olddb), "%s" PATHSEP "%s.cvd", localdbdir ? localdbdir : pt, dbname);
        if (access(olddb, R_OK))
            snprintf(olddb, sizeof(olddb), "%s" PATHSEP "%s.cld", localdbdir ? localdbdir : pt, dbname);
        if (access(olddb, R_OK))
            snprintf(olddb, sizeof(olddb), "%s" PATHSEP "%s.cud", localdbdir ? localdbdir : pt, dbname);
        free(pt);
    }

    if (!(oldcvd = cl_cvdhead(olddb)) && !optget(opts, "unsigned")->enabled) {
        mprintf(LOGG_WARNING, "build: CAN'T READ CVD HEADER OF CURRENT DATABASE %s (wait 3 s)\n", olddb);
        sleep(3);
    }

    if (oldcvd) {
        version = oldcvd->version + 1;
        oldsigs = oldcvd->sigs;
        cl_cvdfree(oldcvd);
    } else if (optget(opts, "cvd-version")->numarg != 0) {
        version = optget(opts, "cvd-version")->numarg;
    } else {
        mprintf(LOGG_INFO, "Version number: ");
        if (scanf("%u", &version) == EOF) {
            mprintf(LOGG_ERROR, "build: scanf() failed\n");
            FREE_LS(dblist2);
            return -1;
        }
    }

    mprintf(LOGG_INFO, "Total sigs: %u\n", sigs);
    if (sigs > oldsigs)
        mprintf(LOGG_INFO, "New sigs: %u\n", sigs - oldsigs);

    strcpy(header, "ClamAV-VDB:");

    /* time */
    time(&timet);
    brokent = localtime(&timet);
    setlocale(LC_TIME, "C");
    strftime(smbuff, sizeof(smbuff), "%d %b %Y %H-%M %z", brokent);
    strcat(header, smbuff);

    /* version */
    sprintf(header + strlen(header), ":%u:", version);

    /* number of signatures */
    sprintf(header + strlen(header), "%u:", sigs);

    /* functionality level */
    fl = (unsigned int)(optget(opts, "flevel")->numarg);
    sprintf(header + strlen(header), "%u:", fl);

    real_header = strlen(header);

    /* add fake MD5 and dsig (for writeinfo) */
    strcat(header, "X:X:");

    if ((pt = getenv("SIGNDUSER"))) {
        strncpy(builder, pt, sizeof(builder));
        builder[sizeof(builder) - 1] = '\0';
    } else {
        mprintf(LOGG_INFO, "Builder name: ");
        if (scanf("%32s", builder) == EOF) {
            mprintf(LOGG_ERROR, "build: Can't get builder name\n");
            free(dblist2);
            return -1;
        }
    }

    /* add builder */
    strcat(header, builder);

    /* add current time */
    sprintf(header + strlen(header), ":" STDu64, (uint64_t)timet);

    if (writeinfo(dbname, builder, header, opts, dblist2, dblist2cnt) == -1) {
        mprintf(LOGG_ERROR, "build: Can't generate info file\n");
        FREE_LS(dblist2);
        return -1;
    }

    header[real_header] = 0;

    if (!(tarfile = cli_gentemp("."))) {
        mprintf(LOGG_ERROR, "build: Can't generate temporary name for tarfile\n");
        FREE_LS(dblist2);
        return -1;
    }

    if ((tar = gzopen(tarfile, "wb9f")) == NULL) {
        mprintf(LOGG_ERROR, "build: Can't open file %s for writing\n", tarfile);
        free(tarfile);
        FREE_LS(dblist2);
        return -1;
    }

    if (tar_addfile(-1, tar, "COPYING") == -1) {
        mprintf(LOGG_ERROR, "build: Can't add COPYING to tar archive\n");
        gzclose(tar);
        unlink(tarfile);
        free(tarfile);
        FREE_LS(dblist2);
        return -1;
    }

    if (bc || hy) {
        if (!hy && tar_addfile(-1, tar, "bytecode.info") == -1) {
            gzclose(tar);
            unlink(tarfile);
            free(tarfile);
            FREE_LS(dblist2);
            return -1;
        }
        for (i = 0; i < dblist2cnt; i++) {
            if (tar_addfile(-1, tar, dblist2[i]) == -1) {
                gzclose(tar);
                unlink(tarfile);
                free(tarfile);
                FREE_LS(dblist2);
                return -1;
            }
        }
    }
    if (!bc || hy) {
        for (i = 0; dblist[i].ext; i++) {
            snprintf(dbfile, sizeof(dbfile), "%s.%s", dbname, dblist[i].ext);
            if (!access(dbfile, R_OK)) {
                if (tar_addfile(-1, tar, dbfile) == -1) {
                    gzclose(tar);
                    unlink(tarfile);
                    free(tarfile);
                    FREE_LS(dblist2);
                    return -1;
                }
            }
        }
    }
    gzclose(tar);
    FREE_LS(dblist2);

    /* MD5 + dsig */
    if (!(fh = fopen(tarfile, "rb"))) {
        mprintf(LOGG_ERROR, "build: Can't open file %s for reading\n", tarfile);
        unlink(tarfile);
        free(tarfile);
        return -1;
    }

    if (!(pt = cli_hashstream(fh, buffer, CLI_HASH_MD5))) {
        mprintf(LOGG_ERROR, "build: Can't generate MD5 checksum for %s\n", tarfile);
        fclose(fh);
        unlink(tarfile);
        free(tarfile);
        return -1;
    }

    // Check if the MD5 starts with 00. If it does, we'll return CL_ELAST_ERROR. The caller may try again for better luck.
    // This is to avoid a bug in hash verification with ClamAV 1.1 -> 1.4. The bug was fixed in 1.5.0.
    // TODO: Remove this workaround when no one is using those versions.
    if (pt[0] == '0' && pt[1] == '0') {
        // print out the pt hash
        mprintf(LOGG_INFO, "The tar.gz MD5 starts with 00, which will fail to verify in ClamAV 1.1 -> 1.4: %s\n", pt);
        fclose(fh);
        unlink(tarfile);
        free(tarfile);
        free(pt);
        return CL_ELAST_ERROR;
    }

    rewind(fh);
    sprintf(header + strlen(header), "%s:", pt);
    free(pt);

    if (!optget(opts, "unsigned")->enabled) {
        if (!(pt = cli_getdsig(optget(opts, "server")->strarg, builder, buffer, 16, 1))) {
            mprintf(LOGG_ERROR, "build: Can't get digital signature from remote server\n");
            fclose(fh);
            unlink(tarfile);
            free(tarfile);
            return -1;
        }
        sprintf(header + strlen(header), "%s:", pt);
        free(pt);
    } else {
        sprintf(header + strlen(header), "X:");
    }

    /* add builder */
    strcat(header, builder);

    /* add current time */
    sprintf(header + strlen(header), ":" STDu64, (uint64_t)timet);

    /* fill up with spaces */
    while (strlen(header) < sizeof(header) - 1)
        strcat(header, " ");

    /* build the final database */
    newcvd = optget(opts, "build")->strarg;
    if (!(cvd = fopen(newcvd, "wb"))) {
        mprintf(LOGG_ERROR, "build: Can't create final database %s\n", newcvd);
        fclose(fh);
        unlink(tarfile);
        free(tarfile);
        return -1;
    }

    if (fwrite(header, 1, 512, cvd) != 512) {
        mprintf(LOGG_ERROR, "build: Can't write to %s\n", newcvd);
        fclose(fh);
        unlink(tarfile);
        free(tarfile);
        fclose(cvd);
        unlink(newcvd);
        return -1;
    }

    while ((bytes = fread(buffer, 1, FILEBUFF, fh)) > 0) {
        if (fwrite(buffer, 1, bytes, cvd) != bytes) {
            mprintf(LOGG_ERROR, "build: Can't write to %s\n", newcvd);
            fclose(fh);
            unlink(tarfile);
            free(tarfile);
            fclose(cvd);
            unlink(newcvd);
            return -1;
        }
    }

    fclose(fh);
    fclose(cvd);

    if (unlink(tarfile) == -1) {
        mprintf(LOGG_WARNING, "build: Can't unlink %s\n", tarfile);
        unlink(tarfile);
        free(tarfile);
        unlink(newcvd);
        return -1;
    }
    free(tarfile);

    mprintf(LOGG_INFO, "Created %s\n", newcvd);

    if (!oldcvd || optget(opts, "no-cdiff")->enabled) {
        mprintf(LOGG_INFO, "Skipping .cdiff creation\n");
        return 0;
    }

    /* generate patch */
    if (!(pt = createTempDir(opts))) {
        return -1;
    }

    if (CL_SUCCESS != cl_cvdunpack_ex(olddb, pt, NULL, CL_DB_UNSIGNED)) {
        mprintf(LOGG_ERROR, "build: Can't unpack CVD file %s\n", olddb);
        removeTempDir(opts, pt);
        free(pt);
        unlink(newcvd);
        return -1;
    }
    strncpy(olddb, pt, sizeof(olddb));
    olddb[sizeof(olddb) - 1] = '\0';
    free(pt);

    if (!(pt = createTempDir(opts))) {
        return -1;
    }

    if (CL_SUCCESS != cl_cvdunpack_ex(newcvd, pt, NULL, CL_DB_UNSIGNED)) {
        mprintf(LOGG_ERROR, "build: Can't unpack CVD file %s\n", newcvd);
        removeTempDir(opts, pt);
        free(pt);
        cli_rmdirs(olddb);
        unlink(newcvd);
        return -1;
    }

    snprintf(patch, sizeof(patch), "%s-%u.script", dbname, version);
    ret = diffdirs(olddb, pt, patch);
    removeTempDir(opts, pt);
    free(pt);

    if (ret == -1) {
        cli_rmdirs(olddb);
        unlink(newcvd);
        return -1;
    }

    ret = verifydiff(opts, patch, NULL, olddb);
    cli_rmdirs(olddb);

    if (ret == -1) {
        snprintf(broken, sizeof(broken), "%s.broken", patch);
        if (rename(patch, broken)) {
            unlink(patch);
            mprintf(LOGG_ERROR, "Generated file is incorrect, removed");
        } else {
            mprintf(LOGG_ERROR, "Generated file is incorrect, renamed to %s\n", broken);
        }
        return ret;
    }

    if (optget(opts, "unsigned")->enabled)
        return 0;

    if (!script2cdiff(patch, builder, optget(opts, "server")->strarg)) {
        ret = -1;
    } else {
        ret = 0;
    }

    return ret;
}

static int unpack(const struct optstruct *opts)
{
    char name[512], *dbdir;
    const char *localdbdir      = NULL;
    const char *certs_directory = NULL;
    uint32_t dboptions          = 0;

    if (optget(opts, "datadir")->active)
        localdbdir = optget(opts, "datadir")->strarg;

    if (optget(opts, "unpack-current")->enabled) {
        dbdir = freshdbdir();
        snprintf(name, sizeof(name), "%s" PATHSEP "%s.cvd", localdbdir ? localdbdir : dbdir, optget(opts, "unpack-current")->strarg);
        if (access(name, R_OK)) {
            snprintf(name, sizeof(name), "%s" PATHSEP "%s.cld", localdbdir ? localdbdir : dbdir, optget(opts, "unpack-current")->strarg);
            if (access(name, R_OK)) {
                mprintf(LOGG_ERROR, "unpack: Couldn't find %s CLD/CVD database in %s\n", optget(opts, "unpack-current")->strarg, localdbdir ? localdbdir : dbdir);
                free(dbdir);
                return -1;
            }
        }
        free(dbdir);

    } else {
        strncpy(name, optget(opts, "unpack")->strarg, sizeof(name));
        name[sizeof(name) - 1] = '\0';
    }

    certs_directory = optget(opts, "cvdcertsdir")->strarg;
    if (NULL == certs_directory) {
        // Check if the CVD_CERTS_DIR environment variable is set
        certs_directory = getenv("CVD_CERTS_DIR");

        // If not, use the default value
        if (NULL == certs_directory) {
            certs_directory = OPT_CERTSDIR;
        }
    }

    if (optget(opts, "fips-limits")->enabled) {
        dboptions |= CL_DB_FIPS_LIMITS;
    }

    if (cl_cvdverify_ex(name, g_cvdcertsdir, dboptions) != CL_SUCCESS) {
        mprintf(LOGG_ERROR, "unpack: %s is not a valid CVD\n", name);
        return -1;
    }

    if (CL_SUCCESS != cl_cvdunpack_ex(name, ".", NULL, CL_DB_UNSIGNED)) {
        mprintf(LOGG_ERROR, "unpack: Can't unpack file %s\n", name);
        return -1;
    }

    return 0;
}

static int cvdinfo(const struct optstruct *opts)
{
    struct cl_cvd *cvd;
    char *pt;
    int ret;
    const char *certs_directory = NULL;
    uint32_t dboptions          = 0;

    pt = optget(opts, "info")->strarg;
    if ((cvd = cl_cvdhead(pt)) == NULL) {
        mprintf(LOGG_ERROR, "cvdinfo: Can't read/parse CVD header of %s\n", pt);
        return -1;
    }
    mprintf(LOGG_INFO, "File: %s\n", pt);

    pt = strchr(cvd->time, '-');
    if (!pt) {
        cl_cvdfree(cvd);
        return -1;
    }
    *pt = ':';
    mprintf(LOGG_INFO, "Build time: %s\n", cvd->time);
    mprintf(LOGG_INFO, "Version: %u\n", cvd->version);
    mprintf(LOGG_INFO, "Signatures: %u\n", cvd->sigs);
    mprintf(LOGG_INFO, "Functionality level: %u\n", cvd->fl);
    mprintf(LOGG_INFO, "Builder: %s\n", cvd->builder);

    pt = optget(opts, "info")->strarg;
    if (cli_strbcasestr(pt, ".cvd")) {
        mprintf(LOGG_INFO, "MD5: %s\n", cvd->md5);
        mprintf(LOGG_INFO, "Digital signature: %s\n", cvd->dsig);
    }
    cl_cvdfree(cvd);

    certs_directory = optget(opts, "cvdcertsdir")->strarg;
    if (NULL == certs_directory) {
        // Check if the CVD_CERTS_DIR environment variable is set
        certs_directory = getenv("CVD_CERTS_DIR");

        // If not, use the default value
        if (NULL == certs_directory) {
            certs_directory = OPT_CERTSDIR;
        }
    }

    if (optget(opts, "fips-limits")->enabled) {
        dboptions |= CL_DB_FIPS_LIMITS;
    }

    if (cli_strbcasestr(pt, ".cud")) {
        mprintf(LOGG_INFO, "Verification: Unsigned container\n");

    } else if ((ret = cl_cvdverify_ex(pt, certs_directory, dboptions))) {
        mprintf(LOGG_ERROR, "cvdinfo: Verification: %s\n", cl_strerror(ret));
        return -1;

    } else {
        mprintf(LOGG_INFO, "Verification OK.\n");
    }

    return 0;
}

static int listdb(const struct optstruct *opts, const char *filename, const regex_t *regex);

static int listdir(const struct optstruct *opts, const char *dirname, const regex_t *regex)
{
    DIR *dd;
    struct dirent *dent;
    char *dbfile;

    if ((dd = opendir(dirname)) == NULL) {
        mprintf(LOGG_ERROR, "listdir: Can't open directory %s\n", dirname);
        return -1;
    }

    while ((dent = readdir(dd))) {
        if (dent->d_ino) {
            if (strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..") &&
                (cli_strbcasestr(dent->d_name, ".db") ||
                 cli_strbcasestr(dent->d_name, ".hdb") ||
                 cli_strbcasestr(dent->d_name, ".hdu") ||
                 cli_strbcasestr(dent->d_name, ".hsb") ||
                 cli_strbcasestr(dent->d_name, ".hsu") ||
                 cli_strbcasestr(dent->d_name, ".mdb") ||
                 cli_strbcasestr(dent->d_name, ".mdu") ||
                 cli_strbcasestr(dent->d_name, ".msb") ||
                 cli_strbcasestr(dent->d_name, ".msu") ||
                 cli_strbcasestr(dent->d_name, ".ndb") ||
                 cli_strbcasestr(dent->d_name, ".ndu") ||
                 cli_strbcasestr(dent->d_name, ".ldb") ||
                 cli_strbcasestr(dent->d_name, ".ldu") ||
                 cli_strbcasestr(dent->d_name, ".sdb") ||
                 cli_strbcasestr(dent->d_name, ".zmd") ||
                 cli_strbcasestr(dent->d_name, ".rmd") ||
                 cli_strbcasestr(dent->d_name, ".cdb") ||
                 cli_strbcasestr(dent->d_name, ".cbc") ||
                 cli_strbcasestr(dent->d_name, ".cld") ||
                 cli_strbcasestr(dent->d_name, ".cvd") ||
                 cli_strbcasestr(dent->d_name, ".crb") ||
                 cli_strbcasestr(dent->d_name, ".imp"))) {

                dbfile = (char *)malloc(strlen(dent->d_name) + strlen(dirname) + 2);
                if (!dbfile) {
                    mprintf(LOGG_ERROR, "listdir: Can't allocate memory for dbfile\n");
                    closedir(dd);
                    return -1;
                }
                sprintf(dbfile, "%s" PATHSEP "%s", dirname, dent->d_name);

                if (listdb(opts, dbfile, regex) == -1) {
                    mprintf(LOGG_ERROR, "listdb: Error listing database %s\n", dbfile);
                    free(dbfile);
                    closedir(dd);
                    return -1;
                }
                free(dbfile);
            }
        }
    }

    closedir(dd);
    return 0;
}

static int listdb(const struct optstruct *opts, const char *filename, const regex_t *regex)
{
    FILE *fh;
    char *buffer, *pt, *start, *dir;
    const char *dbname, *pathsep = PATHSEP;
    unsigned int line = 0;

    if ((fh = fopen(filename, "rb")) == NULL) {
        mprintf(LOGG_ERROR, "listdb: Can't open file %s\n", filename);
        return -1;
    }

    if (!(buffer = (char *)malloc(CLI_DEFAULT_LSIG_BUFSIZE + 1))) {
        mprintf(LOGG_ERROR, "listdb: Can't allocate memory for buffer\n");
        fclose(fh);
        return -1;
    }

    /* check for CVD file */
    if (!fgets(buffer, 12, fh)) {
        mprintf(LOGG_ERROR, "listdb: fgets failed\n");
        free(buffer);
        fclose(fh);
        return -1;
    }
    rewind(fh);

    if (!strncmp(buffer, "ClamAV-VDB:", 11)) {
        free(buffer);
        fclose(fh);

        if (!(dir = createTempDir(opts))) {
            return -1;
        }

        if (CL_SUCCESS != cl_cvdunpack_ex(filename, dir, NULL, CL_DB_UNSIGNED)) {
            mprintf(LOGG_ERROR, "listdb: Can't unpack CVD file %s\n", filename);
            removeTempDir(opts, dir);
            free(dir);
            return -1;
        }

        /* list extracted directory */
        if (listdir(opts, dir, regex) == -1) {
            mprintf(LOGG_ERROR, "listdb: Can't list directory %s\n", filename);
            removeTempDir(opts, dir);
            free(dir);
            return -1;
        }

        removeTempDir(opts, dir);
        free(dir);

        return 0;
    }

    if (!(dbname = strrchr(filename, *pathsep))) {
        mprintf(LOGG_ERROR, "listdb: Invalid filename %s\n", filename);
        fclose(fh);
        free(buffer);
        return -1;
    }
    dbname++;

    if (cli_strbcasestr(filename, ".db")) { /* old style database */

        while (fgets(buffer, CLI_DEFAULT_LSIG_BUFSIZE, fh)) {
            if (regex) {
                cli_chomp(buffer);
                if (!cli_regexec(regex, buffer, 0, NULL, 0))
                    mprintf(LOGG_INFO, "[%s] %s\n", dbname, buffer);
                continue;
            }
            line++;

            if (buffer && buffer[0] == '#')
                continue;

            pt = strchr(buffer, '=');
            if (!pt) {
                mprintf(LOGG_ERROR, "listdb: Malformed pattern line %u (file %s)\n", line, filename);
                fclose(fh);
                free(buffer);
                return -1;
            }

            start = buffer;
            *pt   = 0;

            if ((pt = strstr(start, " (Clam)")))
                *pt = 0;

            mprintf(LOGG_INFO, "%s\n", start);
        }

    } else if (cli_strbcasestr(filename, ".crb")) {
        while (fgets(buffer, CLI_DEFAULT_LSIG_BUFSIZE, fh)) {
            cli_chomp(buffer);

            if (buffer[0] == '#')
                continue;

            if (regex) {
                if (!cli_regexec(regex, buffer, 0, NULL, 0))
                    mprintf(LOGG_INFO, "[%s] %s\n", dbname, buffer);

                continue;
            }
            line++;
            mprintf(LOGG_INFO, "%s\n", buffer);
        }
    } else if (cli_strbcasestr(filename, ".hdb") || cli_strbcasestr(filename, ".hdu") || cli_strbcasestr(filename, ".mdb") || cli_strbcasestr(filename, ".mdu") || cli_strbcasestr(filename, ".hsb") || cli_strbcasestr(filename, ".hsu") || cli_strbcasestr(filename, ".msb") || cli_strbcasestr(filename, ".msu") || cli_strbcasestr(filename, ".imp")) { /* hash database */

        while (fgets(buffer, CLI_DEFAULT_LSIG_BUFSIZE, fh)) {
            cli_chomp(buffer);
            if (regex) {
                if (!cli_regexec(regex, buffer, 0, NULL, 0))
                    mprintf(LOGG_INFO, "[%s] %s\n", dbname, buffer);
                continue;
            }
            line++;

            if (buffer && buffer[0] == '#')
                continue;

            start = cli_strtok(buffer, 2, ":");

            if (!start) {
                mprintf(LOGG_ERROR, "listdb: Malformed pattern line %u (file %s)\n", line, filename);
                fclose(fh);
                free(buffer);
                return -1;
            }

            if ((pt = strstr(start, " (Clam)")))
                *pt = 0;

            mprintf(LOGG_INFO, "%s\n", start);
            free(start);
        }

    } else if (cli_strbcasestr(filename, ".ndb") || cli_strbcasestr(filename, ".ndu") || cli_strbcasestr(filename, ".ldb") || cli_strbcasestr(filename, ".ldu") || cli_strbcasestr(filename, ".sdb") || cli_strbcasestr(filename, ".zmd") || cli_strbcasestr(filename, ".rmd") || cli_strbcasestr(filename, ".cdb")) {

        while (fgets(buffer, CLI_DEFAULT_LSIG_BUFSIZE, fh)) {
            cli_chomp(buffer);
            if (regex) {
                if (!cli_regexec(regex, buffer, 0, NULL, 0))
                    mprintf(LOGG_INFO, "[%s] %s\n", dbname, buffer);
                continue;
            }
            line++;

            if (buffer && buffer[0] == '#')
                continue;

            if (cli_strbcasestr(filename, ".ldb") || cli_strbcasestr(filename, ".ldu"))
                pt = strchr(buffer, ';');
            else
                pt = strchr(buffer, ':');

            if (!pt) {
                mprintf(LOGG_ERROR, "listdb: Malformed pattern line %u (file %s)\n", line, filename);
                fclose(fh);
                free(buffer);
                return -1;
            }
            *pt = 0;

            if ((pt = strstr(buffer, " (Clam)")))
                *pt = 0;

            mprintf(LOGG_INFO, "%s\n", buffer);
        }

    } else if (cli_strbcasestr(filename, ".cbc")) {
        if (fgets(buffer, CLI_DEFAULT_LSIG_BUFSIZE, fh) && fgets(buffer, CLI_DEFAULT_LSIG_BUFSIZE, fh)) {
            pt = strchr(buffer, ';');
            if (!pt) { /* not a real sig */
                fclose(fh);
                free(buffer);
                return 0;
            }
            if (regex) {
                if (!cli_regexec(regex, buffer, 0, NULL, 0)) {
                    mprintf(LOGG_INFO, "[%s BYTECODE] %s", dbname, buffer);
                }
            } else {
                *pt = 0;
                mprintf(LOGG_INFO, "%s\n", buffer);
            }
        }
    }
    fclose(fh);
    free(buffer);
    return 0;
}

static int listsigs(const struct optstruct *opts, int mode)
{
    int ret;
    const char *name;
    char *dbdir;
    STATBUF sb;
    regex_t reg;
    const char *localdbdir = NULL;

    if (optget(opts, "datadir")->active)
        localdbdir = optget(opts, "datadir")->strarg;

    if (mode == 0) {
        name = optget(opts, "list-sigs")->strarg;
        if (access(name, R_OK) && localdbdir)
            name = localdbdir;
        if (CLAMSTAT(name, &sb) == -1) {
            mprintf(LOGG_INFO, "--list-sigs: Can't get status of %s\n", name);
            return -1;
        }

        mprintf_stdout = 1;
        if (S_ISDIR(sb.st_mode)) {
            if (!strcmp(name, OPT_DATADIR)) {
                dbdir = freshdbdir();
                ret   = listdir(opts, localdbdir ? localdbdir : dbdir, NULL);
                free(dbdir);
            } else {
                ret = listdir(opts, name, NULL);
            }
        } else {
            ret = listdb(opts, name, NULL);
        }

    } else {
        if (cli_regcomp(&reg, optget(opts, "find-sigs")->strarg, REG_EXTENDED | REG_NOSUB) != 0) {
            mprintf(LOGG_INFO, "--find-sigs: Can't compile regex\n");
            return -1;
        }
        mprintf_stdout = 1;
        dbdir          = freshdbdir();
        ret            = listdir(opts, localdbdir ? localdbdir : dbdir, &reg);
        free(dbdir);
        cli_regfree(&reg);
    }

    return ret;
}

char *createTempDir(const struct optstruct *opts)
{
    const struct optstruct *opt;
    const char *tempdir = NULL;
    char *ret           = NULL;

    if (opts && ((opt = optget(opts, "tempdir"))->enabled)) {
        tempdir = opt->strarg;
    } else {
        tempdir = cli_gettmpdir();
    }

    ret = (char *)cli_gentemp_with_prefix(tempdir, "sigtool");
    if (NULL == ret) {
        logg(LOGG_ERROR, "Can't create temporary directory name.\n");
        goto done;
    }

    if (mkdir(ret, 0700)) {
        logg(LOGG_ERROR, "Can't create temporary directory for scan: %s.\n", tempdir);
        free((char *)ret);
        ret = NULL;
    }

done:

    return ret;
}

static bool setTempDir(struct cl_engine *engine, const struct optstruct *opts)
{
    bool bRet           = false;
    int ret             = -1;
    const char *tempdir = createTempDir(opts);
    if (NULL == tempdir) {
        goto done;
    }

    if ((ret = cl_engine_set_str(engine, CL_ENGINE_TMPDIR, tempdir))) {
        logg(LOGG_ERROR, "cli_engine_set_str(CL_ENGINE_TMPDIR) failed: %s\n", cl_strerror(ret));
        goto done;
    }

    bRet = true;
done:
    if (tempdir) {
        free((char *)tempdir);
    }
    return bRet;
}

static void scanfile(const char *filename, struct cl_engine *engine, const struct optstruct *opts, struct cl_scan_options *options)
{
    cl_error_t ret           = CL_SUCCESS;
    int fd                   = -1;
    const char *virname      = NULL;
    char *real_filename      = NULL;
    unsigned long int blocks = 0;

    if (NULL == filename || NULL == engine || NULL == opts || NULL == options) {
        logg(LOGG_INFO, "scanfile: Invalid args.\n");
        ret = CL_EARG;
        goto done;
    }

    ret = cli_realpath((const char *)filename, &real_filename);
    if (CL_SUCCESS != ret) {
        logg(LOGG_DEBUG, "Failed to determine real filename of %s.\n", filename);
        logg(LOGG_DEBUG, "Quarantine of the file may fail if file path contains symlinks.\n");
    } else {
        filename = real_filename;
    }

    if ((fd = safe_open(filename, O_RDONLY | O_BINARY)) == -1) {
        logg(LOGG_WARNING, "Can't open file %s: %s\n", filename, strerror(errno));
        goto done;
    }

    if (CL_CLEAN != cl_scandesc_callback(fd, filename, &virname, &blocks, engine, options, NULL)) {
        logg(LOGG_ERROR, "Error parsing '%s'\n", filename);
        goto done;
    }

done:
    if (NULL != real_filename) {
        free(real_filename);
    }
    return;
}

static int vba_callback(const unsigned char *const metaString, const size_t metaStringLen, void *context)
{

    size_t i = 0;

    UNUSEDPARAM(context);

    if (NULL == metaString) {
        return -1;
    }

    for (i = 0; i < metaStringLen; i++) {
#ifndef _WIN32
        if ('\r' == metaString[i]) {
            continue;
        }
#endif
        printf("%c", metaString[i]);
    }
    printf("\n");

    return 0;
}

static int vbadump(const struct optstruct *opts)
{
    int ret = -1;

    struct cl_scan_options options;
    struct cl_engine *engine = NULL;

#ifndef _WIN32
    struct rlimit rlim;
#endif

    const char *filename = NULL;

    /* Initialize scan options struct */
    memset(&options, 0, sizeof(struct cl_scan_options));

    if ((ret = cl_init(CL_INIT_DEFAULT))) {
        logg(LOGG_ERROR, "Can't initialize libclamav: %s\n", cl_strerror(ret));
        ret = 2;
        goto done;
    }

    if (!(engine = cl_engine_new())) {
        logg(LOGG_ERROR, "Can't initialize antivirus engine\n");
        ret = 2;
        goto done;
    }

    cl_engine_set_clcb_vba(engine, vba_callback);

    if (!setTempDir(engine, opts)) {
        ret = 2;
        goto done;
    }

    if ((ret = cl_engine_compile(engine)) != 0) {
        logg(LOGG_ERROR, "Database initialization error: %s\n", cl_strerror(ret));
        ret = 2;
        goto done;
    }

#ifndef _WIN32
    if (getrlimit(RLIMIT_FSIZE, &rlim) == 0) {
        if (rlim.rlim_cur < (rlim_t)cl_engine_get_num(engine, CL_ENGINE_MAX_FILESIZE, NULL))
            logg(LOGG_WARNING, "System limit for file size is lower than engine->maxfilesize\n");
        if (rlim.rlim_cur < (rlim_t)cl_engine_get_num(engine, CL_ENGINE_MAX_SCANSIZE, NULL))
            logg(LOGG_WARNING, "System limit for file size is lower than engine->maxscansize\n");
    } else {
        logg(LOGG_WARNING, "Cannot obtain resource limits for file size\n");
    }
#endif

    options.general |= CL_SCAN_GENERAL_COLLECT_METADATA;

    /* Have the engine unpack everything so that we don't miss anything.  We'll clean it up later. */
    options.parse = ~0;

    /*
     * Need to explicitly set this to always keep temps, since we are scanning extracted ooxml/ole2 files
     * from our scan directory to print all the vba content. Remove it later if leave-temps was not specified.
     */
    cl_engine_set_num(engine, CL_ENGINE_KEEPTMP, 1);
    cl_engine_set_num(engine, CL_ENGINE_TMPDIR_RECURSION, 1);

    filename = optget(opts, "vba")->strarg;
    if (NULL == filename) {
        filename = optget(opts, "vba-hex")->strarg;
    }
    scanfile(filename, engine, opts, &options);

    removeTempDir(opts, engine->tmpdir);

    ret = 0;
done:

    /* free the engine */
    cl_engine_free(engine);

    return ret;
}

static int comparesha(const char *diff)
{
    char info[32], buff[FILEBUFF], *sha, *pt, *name;
    const char *tokens[3];
    FILE *fh;
    int ret = 0, tokens_count;

    name = strdup(diff);
    if (!name) {
        mprintf(LOGG_ERROR, "verifydiff: strdup() failed\n");
        return -1;
    }
    if (!(pt = strrchr(name, '-')) || !isdigit(pt[1])) {
        mprintf(LOGG_ERROR, "verifydiff: Invalid diff name\n");
        free(name);
        return -1;
    }
    *pt = 0;
    if ((pt = strrchr(name, *PATHSEP)))
        pt++;
    else
        pt = name;

    snprintf(info, sizeof(info), "%s.info", pt);
    free(name);

    if (!(fh = fopen(info, "rb"))) {
        mprintf(LOGG_ERROR, "verifydiff: Can't open %s\n", info);
        return -1;
    }

    if (!fgets(buff, sizeof(buff), fh) || strncmp(buff, "ClamAV-VDB", 10)) {
        mprintf(LOGG_ERROR, "verifydiff: Incorrect info file %s\n", info);
        fclose(fh);
        return -1;
    }

    while (fgets(buff, sizeof(buff), fh)) {
        cli_chomp(buff);
        tokens_count = cli_strtokenize(buff, ':', 3, tokens);
        if (tokens_count != 3) {
            if (!strcmp(tokens[0], "DSIG"))
                continue;
            mprintf(LOGG_ERROR, "verifydiff: Incorrect format of %s\n", info);
            ret = -1;
            break;
        }
        if (!(sha = sha2_256_file(tokens[0], NULL))) {
            mprintf(LOGG_ERROR, "verifydiff: Can't generate SHA2-256 for %s\n", buff);
            ret = -1;
            break;
        }
        if (strcmp(sha, tokens[2])) {
            mprintf(LOGG_ERROR, "verifydiff: %s has incorrect checksum\n", buff);
            ret = -1;
            free(sha);
            break;
        }
        free(sha);
    }

    fclose(fh);
    return ret;
}

static int rundiff(const struct optstruct *opts)
{
    int ret;
    unsigned short mode;
    const char *diff;
    FFIError *cdiff_apply_error = NULL;

    void *verifier               = NULL;
    FFIError *new_verifier_error = NULL;

    diff = optget(opts, "run-cdiff")->strarg;
    if (strstr(diff, ".cdiff")) {
        mode = 1;
    } else if (strstr(diff, ".script")) {
        mode = 0;
    } else {
        mprintf(LOGG_ERROR, "rundiff: Incorrect file name (no .cdiff/.script extension)\n");
        return -1;
    }

    if (!codesign_verifier_new(g_cvdcertsdir, &verifier, &new_verifier_error)) {
        cli_errmsg("rundiff: Failed to create a new code-signature verifier: %s\n", ffierror_fmt(new_verifier_error));
        ret = -1;
        goto done;
    }

    if (!cdiff_apply(
            diff,
            verifier,
            mode,
            &cdiff_apply_error)) {

        mprintf(LOGG_ERROR, "rundiff: Error applying '%s': %s\n",
                diff, ffierror_fmt(cdiff_apply_error));
        ret = -1;
        goto done;
    }

    // success. compare the SHA2-256 checksums of the files
    ret = comparesha(diff);

done:

    if (NULL != verifier) {
        codesign_verifier_free(verifier);
    }
    if (NULL != new_verifier_error) {
        ffierror_free(new_verifier_error);
    }
    if (NULL != cdiff_apply_error) {
        ffierror_free(cdiff_apply_error);
    }

    return ret;
}

static int maxlinelen(const char *file)
{
    int fd, bytes, n = 0, nmax = 0, i;
    char buff[512];

    if ((fd = open(file, O_RDONLY | O_BINARY)) == -1) {
        mprintf(LOGG_ERROR, "maxlinelen: Can't open file %s\n", file);
        return -1;
    }

    while ((bytes = read(fd, buff, 512)) > 0) {
        for (i = 0; i < bytes; i++, ++n) {
            if (buff[i] == '\n') {
                if (n > nmax)
                    nmax = n;
                n = 0;
            }
        }
    }

    if (bytes == -1) {
        mprintf(LOGG_ERROR, "maxlinelen: Can't read file %s\n", file);
        close(fd);
        return -1;
    }

    close(fd);
    return nmax + 1;
}

static int compare(const char *oldpath, const char *newpath, FILE *diff)
{
    FILE *old, *new;
    char *obuff, *nbuff, *tbuff, *pt, *omd5, *nmd5;
    unsigned int oline = 0, tline, found, i, badxchg = 0;
    int l1 = 0, l2;
    long opos;

    if (!access(oldpath, R_OK) && (omd5 = cli_hashfile(oldpath, NULL, CLI_HASH_MD5))) {
        if (!(nmd5 = cli_hashfile(newpath, NULL, CLI_HASH_MD5))) {
            mprintf(LOGG_ERROR, "compare: Can't get MD5 checksum of %s\n", newpath);
            free(omd5);
            return -1;
        }
        if (!strcmp(omd5, nmd5)) {
            free(omd5);
            free(nmd5);
            return 0;
        }
        free(omd5);
        free(nmd5);
        l1 = maxlinelen(oldpath);
    }

    l2 = maxlinelen(newpath);
    if (l1 == -1 || l2 == -1)
        return -1;
    l1 = MAX(l1, l2) + 1;

    obuff = malloc(l1);
    if (!obuff) {
        mprintf(LOGG_ERROR, "compare: Can't allocate memory for 'obuff'\n");
        return -1;
    }
    nbuff = malloc(l1);
    if (!nbuff) {
        mprintf(LOGG_ERROR, "compare: Can't allocate memory for 'nbuff'\n");
        free(obuff);
        return -1;
    }
    tbuff = malloc(l1);
    if (!tbuff) {
        mprintf(LOGG_ERROR, "compare: Can't allocate memory for 'tbuff'\n");
        free(obuff);
        free(nbuff);
        return -1;
    }

    if (l1 > CLI_DEFAULT_LSIG_BUFSIZE)
        fprintf(diff, "#LSIZE %u\n", l1 + 32);

    fprintf(diff, "OPEN %s\n", newpath);

    if (!(new = fopen(newpath, "rb"))) {
        mprintf(LOGG_ERROR, "compare: Can't open file %s for reading\n", newpath);
        free(obuff);
        free(nbuff);
        free(tbuff);
        return -1;
    }
    old = fopen(oldpath, "rb");

    while (fgets(nbuff, l1, new)) {
        i = strlen(nbuff);
        if (i >= 2 && (nbuff[i - 1] == '\r' || (nbuff[i - 1] == '\n' && nbuff[i - 2] == '\r'))) {
            mprintf(LOGG_ERROR, "compare: New %s file contains lines terminated with CRLF or CR\n", newpath);
            if (old)
                fclose(old);
            fclose(new);
            free(obuff);
            free(nbuff);
            free(tbuff);
            return -1;
        }
        cli_chomp(nbuff);
        if (!old) {
            fprintf(diff, "ADD %s\n", nbuff);
        } else {
            if (fgets(obuff, l1, old)) {
                oline++;
                cli_chomp(obuff);
                if (!strcmp(nbuff, obuff)) {
                    continue;
                } else {
                    tline = 0;
                    found = 0;
                    opos  = ftell(old);
                    while (fgets(tbuff, l1, old)) {
                        tline++;
                        cli_chomp(tbuff);

                        if (tline > MAX_DEL_LOOKAHEAD)
                            break;

                        if (!strcmp(tbuff, nbuff)) {
                            found = 1;
                            break;
                        }
                    }
                    fseek(old, opos, SEEK_SET);

                    if (found) {
                        strncpy(tbuff, obuff, l1);
                        tbuff[l1 - 1] = '\0';
                        for (i = 0; i < tline; i++) {
                            tbuff[MIN(16, l1 - 1)] = 0;
                            if ((pt = strchr(tbuff, ' ')))
                                *pt = 0;
                            fprintf(diff, "DEL %u %s\n", oline + i, tbuff);
                            if (!fgets(tbuff, l1, old))
                                break;
                        }
                        oline += tline;

                    } else {
                        if (!*obuff || *obuff == ' ') {
                            badxchg = 1;
                            break;
                        }
                        obuff[MIN(16, l1 - 1)] = 0;
                        if ((pt = strchr(obuff, ' ')))
                            *pt = 0;
                        fprintf(diff, "XCHG %u %s %s\n", oline, obuff, nbuff);
                    }
                }
            } else {
                fclose(old);
                old = NULL;
                fprintf(diff, "ADD %s\n", nbuff);
            }
        }
    }

    if (old) {
        if (!badxchg) {
            while (fgets(obuff, l1, old)) {
                oline++;
                cli_chomp(obuff);
                obuff[MIN(16, l1 - 1)] = 0;
                if ((pt = strchr(obuff, ' ')))
                    *pt = 0;
                fprintf(diff, "DEL %u %s\n", oline, obuff);
            }
        }
        fclose(old);
    }
    fprintf(diff, "CLOSE\n");
    free(obuff);
    free(tbuff);
    if (badxchg) {
        fprintf(diff, "UNLINK %s\n", newpath);
        fprintf(diff, "OPEN %s\n", newpath);
        rewind(new);
        while (fgets(nbuff, l1, new)) {
            cli_chomp(nbuff);
            fprintf(diff, "ADD %s\n", nbuff);
        }
        fprintf(diff, "CLOSE\n");
    }
    free(nbuff);
    fclose(new);
    return 0;
}

static int compareone(const struct optstruct *opts)
{
    if (!opts->filename) {
        mprintf(LOGG_ERROR, "makediff: --compare requires two arguments\n");
        return -1;
    }
    return compare(optget(opts, "compare")->strarg, opts->filename[0], stdout);
}

static int dircopy(const char *src, const char *dest)
{
    DIR *dd;
    struct dirent *dent;
    STATBUF sb;
    char spath[512], dpath[512];

    if (CLAMSTAT(dest, &sb) == -1) {
        if (mkdir(dest, 0755)) {
            /* mprintf(LOGG_ERROR, "dircopy: Can't create temporary directory %s\n", dest); */
            return -1;
        }
    }

    if ((dd = opendir(src)) == NULL) {
        /* mprintf(LOGG_ERROR, "dircopy: Can't open directory %s\n", src); */
        return -1;
    }

    while ((dent = readdir(dd))) {
        if (dent->d_ino) {
            if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
                continue;

            snprintf(spath, sizeof(spath), "%s" PATHSEP "%s", src, dent->d_name);
            snprintf(dpath, sizeof(dpath), "%s" PATHSEP "%s", dest, dent->d_name);

            if (filecopy(spath, dpath) == -1) {
                /* mprintf(LOGG_ERROR, "dircopy: Can't copy %s to %s\n", spath, dpath); */
                cli_rmdirs(dest);
                closedir(dd);
                return -1;
            }
        }
    }

    closedir(dd);
    return 0;
}

static int verifydiff(const struct optstruct *opts, const char *diff, const char *cvd, const char *incdir)
{
    char *tempdir = NULL;
    char cwd[512];
    int ret = -1;
    unsigned short mode;
    FFIError *cdiff_apply_error = NULL;

    void *verifier               = NULL;
    FFIError *new_verifier_error = NULL;

    bool created_temp_dir = false;

    cl_error_t cl_ret;

    char *real_diff = NULL;

    if (strstr(diff, ".cdiff")) {
        mode = 1;
    } else if (strstr(diff, ".script")) {
        mode = 0;
    } else {
        mprintf(LOGG_ERROR, "verifydiff: Incorrect file name (no .cdiff/.script extension)\n");
        goto done;
    }

    if (!(tempdir = createTempDir(opts))) {
        goto done;
    }
    created_temp_dir = true;

    if (cvd) {
        if (CL_SUCCESS != cl_cvdunpack_ex(cvd, tempdir, NULL, CL_DB_UNSIGNED)) {
            mprintf(LOGG_ERROR, "verifydiff: Can't unpack CVD file %s\n", cvd);
            goto done;
        }
    } else {
        if (dircopy(incdir, tempdir) == -1) {
            mprintf(LOGG_ERROR, "verifydiff: Can't copy dir %s to %s\n", incdir, tempdir);
            goto done;
        }
    }

    if (!getcwd(cwd, sizeof(cwd))) {
        mprintf(LOGG_ERROR, "verifydiff: getcwd() failed\n");
        goto done;
    }

    cl_ret = cli_realpath((const char *)diff, &real_diff);
    if (CL_SUCCESS != cl_ret) {
        mprintf(LOGG_ERROR, "verifydiff: Failed to determine real filename of %s: %s\n", diff, cl_strerror(cl_ret));
        goto done;
    }

    diff = real_diff;

    if (chdir(tempdir) == -1) {
        mprintf(LOGG_ERROR, "verifydiff: Can't chdir to %s\n", tempdir);
        goto done;
    }

    if (!codesign_verifier_new(g_cvdcertsdir, &verifier, &new_verifier_error)) {
        cli_errmsg("verifydiff: Failed to create a new code-signature verifier: %s\n", ffierror_fmt(new_verifier_error));
        ret = -1;
        goto done;
    }

    if (!cdiff_apply(
            diff,
            verifier,
            mode,
            &cdiff_apply_error)) {
        mprintf(LOGG_ERROR, "verifydiff: Can't apply %s: %s\n", diff, ffierror_fmt(cdiff_apply_error));
        if (chdir(cwd) == -1) {
            mprintf(LOGG_WARNING, "verifydiff: Can't chdir to %s\n", cwd);
        }
        goto done;
    }

    ret = comparesha(diff);

    if (chdir(cwd) == -1) {
        mprintf(LOGG_WARNING, "verifydiff: Can't chdir to %s\n", cwd);
    }

    if (0 == ret) {
        if (cvd) {
            mprintf(LOGG_INFO, "Verification: %s correctly applies to %s\n", diff, cvd);
        } else {
            mprintf(LOGG_INFO, "Verification: %s correctly applies to the previous version\n", diff);
        }
    }

done:
    if (created_temp_dir) {
        removeTempDir(opts, tempdir);
    }
    if (NULL != tempdir) {
        free(tempdir);
    }
    if (NULL != cdiff_apply_error) {
        ffierror_free(cdiff_apply_error);
    }
    if (NULL != real_diff) {
        free(real_diff);
    }
    if (NULL != verifier) {
        codesign_verifier_free(verifier);
    }
    if (NULL != new_verifier_error) {
        ffierror_free(new_verifier_error);
    }

    return ret;
}

/**
 * @brief Match a given "signature" in the file fd and return the offset.
 *
 * The "signature" may be a subsignature to include things like a PCRE special
 * subsignature.
 *
 * @param sig
 * @param offset
 * @param fd
 */
static void matchsig(char *sig, const char *offset, int fd)
{
    struct cli_ac_result *acres = NULL, *res;
    STATBUF sb;
    unsigned int matches           = 0;
    struct cl_engine *engine       = NULL;
    cli_ctx ctx                    = {0};
    struct cl_scan_options options = {0};
    cl_fmap_t *new_map             = NULL;
    struct cli_lsig_tdb tdb        = {0};

    mprintf(LOGG_INFO, "SUBSIG: %s\n", sig);

    /* Prepare file */
    lseek(fd, 0, SEEK_SET);
    FSTAT(fd, &sb);

    new_map = fmap_new(fd, 0, sb.st_size, NULL, NULL);
    if (NULL == new_map) {
        goto done;
    }

    /* build engine */
    if (!(engine = cl_engine_new())) {
        mprintf(LOGG_ERROR, "matchsig: Can't create new engine\n");
        goto done;
    }
    cl_engine_set_num(engine, CL_ENGINE_AC_ONLY, 1);

    if (cli_initroots(engine, 0) != CL_SUCCESS) {
        mprintf(LOGG_ERROR, "matchsig: cli_initroots() failed\n");
        goto done;
    }

    if (readdb_parse_ldb_subsignature(engine->root[0], "test", sig, "*", NULL, 0, 0, 1, &tdb) != CL_SUCCESS) {
        mprintf(LOGG_ERROR, "matchsig: Can't parse signature\n");
        goto done;
    }

    if (cl_engine_compile(engine) != CL_SUCCESS) {
        mprintf(LOGG_ERROR, "matchsig: Can't compile engine\n");
        goto done;
    }

    ctx.engine = engine;

    ctx.options        = &options;
    ctx.options->parse = ~0;
    ctx.dconf          = (struct cli_dconf *)engine->dconf;

    ctx.recursion_stack_size = ctx.engine->max_recursion_level;
    ctx.recursion_stack      = calloc(sizeof(cli_scan_layer_t), ctx.recursion_stack_size);
    if (!ctx.recursion_stack) {
        goto done;
    }

    // ctx was memset, so recursion_level starts at 0.
    ctx.recursion_stack[ctx.recursion_level].fmap = new_map;
    ctx.recursion_stack[ctx.recursion_level].type = CL_TYPE_ANY; // ANY for the top level, because we don't yet know the type.
    ctx.recursion_stack[ctx.recursion_level].size = new_map->len;

    ctx.fmap = ctx.recursion_stack[ctx.recursion_level].fmap;

    (void)cli_scan_fmap(&ctx, CL_TYPE_ANY, false, NULL, AC_SCAN_VIR, &acres);

    res = acres;
    while (res) {
        matches++;
        res = res->next;
    }

    if (matches) {
        /* TODO: check offsets automatically */
        mprintf(LOGG_INFO, "MATCH: ** YES%s ** (%u %s:", offset ? "/CHECK OFFSET" : "", matches, matches > 1 ? "matches at offsets" : "match at offset");
        res = acres;
        while (res) {
            mprintf(LOGG_INFO, " %u", (unsigned int)res->offset);
            res = res->next;
        }
        mprintf(LOGG_INFO, ")\n");
    } else {
        mprintf(LOGG_INFO, "MATCH: ** NO **\n");
    }

done:
    /* Cleanup */
    while (acres) {
        res   = acres;
        acres = acres->next;
        free(res);
    }
    if (NULL != new_map) {
        fmap_free(new_map);
    }
    if (NULL != ctx.recursion_stack) {
        if (ctx.recursion_stack[ctx.recursion_level].evidence) {
            evidence_free(ctx.recursion_stack[ctx.recursion_level].evidence);
        }
        free(ctx.recursion_stack);
    }
    if (NULL != engine) {
        cl_engine_free(engine);
    }
}

static char *decodehexstr(const char *hex, unsigned int *dlen)
{
    uint16_t *str16;
    char *decoded;
    unsigned int i, p = 0, wildcard = 0, len = strlen(hex) / 2;

    str16 = cli_hex2ui(hex);
    if (!str16)
        return NULL;

    for (i = 0; i < len; i++)
        if (str16[i] & CLI_MATCH_WILDCARD)
            wildcard++;

    decoded = calloc(len + 1 + wildcard * 32, sizeof(char));
    if (!decoded) {
        free(str16);
        mprintf(LOGG_ERROR, "decodehexstr: Can't allocate memory for decoded\n");
        return NULL;
    }

    for (i = 0; i < len; i++) {
        if (str16[i] & CLI_MATCH_WILDCARD) {
            switch (str16[i] & CLI_MATCH_WILDCARD) {
                case CLI_MATCH_IGNORE:
                    p += sprintf(decoded + p, "{WILDCARD_IGNORE}");
                    break;

                case CLI_MATCH_NIBBLE_HIGH:
                    p += sprintf(decoded + p, "{WILDCARD_NIBBLE_HIGH:0x%x}", str16[i] & 0x00f0);
                    break;

                case CLI_MATCH_NIBBLE_LOW:
                    p += sprintf(decoded + p, "{WILDCARD_NIBBLE_LOW:0x%x}", str16[i] & 0x000f);
                    break;

                default:
                    mprintf(LOGG_ERROR, "decodehexstr: Unknown wildcard (0x%x@%u)\n", str16[i] & CLI_MATCH_WILDCARD, i);
                    free(decoded);
                    free(str16);
                    return NULL;
            }
        } else {
            decoded[p] = str16[i];
            p++;
        }
    }

    if (dlen)
        *dlen = p;
    free(str16);
    return decoded;
}

inline static char *get_paren_end(char *hexstr)
{
    char *pt;
    int level = 0;

    pt = hexstr;
    while (*pt != '\0') {
        if (*pt == '(') {
            level++;
        } else if (*pt == ')') {
            if (!level)
                return pt;
            level--;
        }
        pt++;
    }
    return NULL;
}

static char *decodehexspecial(const char *hex, unsigned int *dlen)
{
    char *pt, *start, *hexcpy, *decoded, *h, *e, *c, op, lop;
    unsigned int len = 0, hlen, negative;
    int level;
    char *buff;

    hexcpy = NULL;
    buff   = NULL;

    hexcpy = strdup(hex);
    if (!hexcpy) {
        mprintf(LOGG_ERROR, "decodehexspecial: strdup(hex) failed\n");
        return NULL;
    }
    pt = strchr(hexcpy, '(');
    if (!pt) {
        free(hexcpy);
        return decodehexstr(hex, dlen);
    } else {
        buff = calloc(strlen(hex) + 512, sizeof(char));
        if (!buff) {
            mprintf(LOGG_ERROR, "decodehexspecial: Can't allocate memory for buff\n");
            free(hexcpy);
            return NULL;
        }
        start = hexcpy;
        do {
            negative = 0;
            *pt++    = 0;
            if (!start) {
                mprintf(LOGG_ERROR, "decodehexspecial: Unexpected EOL\n");
                free(hexcpy);
                free(buff);
                return NULL;
            }
            if (pt >= hexcpy + 2) {
                if (pt[-2] == '!') {
                    negative = 1;
                    pt[-2]   = 0;
                }
            }
            if (!(decoded = decodehexstr(start, &hlen))) {
                mprintf(LOGG_ERROR, "Decoding failed (1): %s\n", pt);
                free(hexcpy);
                free(buff);
                return NULL;
            }
            memcpy(&buff[len], decoded, hlen);
            len += hlen;
            free(decoded);

            if (!(start = get_paren_end(pt))) {
                mprintf(LOGG_ERROR, "decodehexspecial: Missing closing parenthesis\n");
                free(hexcpy);
                free(buff);
                return NULL;
            }

            *start++ = 0;
            if (!strlen(pt)) {
                mprintf(LOGG_ERROR, "decodehexspecial: Empty block\n");
                free(hexcpy);
                free(buff);
                return NULL;
            }

            if (!strcmp(pt, "B")) {
                if (!*start) {
                    if (negative)
                        len += sprintf(buff + len, "{NOT_BOUNDARY_RIGHT}");
                    else
                        len += sprintf(buff + len, "{BOUNDARY_RIGHT}");
                    continue;
                } else if (pt - 1 == hexcpy) {
                    if (negative)
                        len += sprintf(buff + len, "{NOT_BOUNDARY_LEFT}");
                    else
                        len += sprintf(buff + len, "{BOUNDARY_LEFT}");
                    continue;
                }
            } else if (!strcmp(pt, "L")) {
                if (!*start) {
                    if (negative)
                        len += sprintf(buff + len, "{NOT_LINE_MARKER_RIGHT}");
                    else
                        len += sprintf(buff + len, "{LINE_MARKER_RIGHT}");
                    continue;
                } else if (pt - 1 == hexcpy) {
                    if (negative)
                        len += sprintf(buff + len, "{NOT_LINE_MARKER_LEFT}");
                    else
                        len += sprintf(buff + len, "{LINE_MARKER_LEFT}");
                    continue;
                }
            } else if (!strcmp(pt, "W")) {
                if (!*start) {
                    if (negative)
                        len += sprintf(buff + len, "{NOT_WORD_MARKER_RIGHT}");
                    else
                        len += sprintf(buff + len, "{WORD_MARKER_RIGHT}");
                    continue;
                } else if (pt - 1 == hexcpy) {
                    if (negative)
                        len += sprintf(buff + len, "{NOT_WORD_MARKER_LEFT}");
                    else
                        len += sprintf(buff + len, "{WORD_MARKER_LEFT}");
                    continue;
                }
            } else {
                if (!strlen(pt)) {
                    mprintf(LOGG_ERROR, "decodehexspecial: Empty block\n");
                    free(hexcpy);
                    free(buff);
                    return NULL;
                }

                /* TODO: analyze string alternative for typing */
                if (negative)
                    len += sprintf(buff + len, "{EXCLUDING_STRING_ALTERNATIVE:");
                else
                    len += sprintf(buff + len, "{STRING_ALTERNATIVE:");

                level = 0;
                h = e = pt;
                op    = '\0';
                while ((level >= 0) && (e = strpbrk(h, "()|"))) {
                    lop = op;
                    op  = *e;

                    *e++ = 0;
                    if (op != '(' && lop != ')' && !strlen(h)) {
                        mprintf(LOGG_ERROR, "decodehexspecial: Empty string alternative block\n");
                        free(hexcpy);
                        free(buff);
                        return NULL;
                    }

                    // mprintf(LOGG_INFO, "decodehexspecial: %s\n", h);
                    if (!(c = cli_hex2str(h))) {
                        mprintf(LOGG_ERROR, "Decoding failed (3): %s\n", h);
                        free(hexcpy);
                        free(buff);
                        return NULL;
                    }
                    memcpy(&buff[len], c, strlen(h) / 2);
                    len += strlen(h) / 2;
                    free(c);

                    switch (op) {
                        case '(':
                            level++;
                            negative = 0;
                            if (e >= pt + 2) {
                                if (e[-2] == '!') {
                                    negative = 1;
                                    e[-2]    = 0;
                                }
                            }

                            if (negative)
                                len += sprintf(buff + len, "{EXCLUDING_STRING_ALTERNATIVE:");
                            else
                                len += sprintf(buff + len, "{STRING_ALTERNATIVE:");

                            break;
                        case ')':
                            level--;
                            buff[len++] = '}';

                            break;
                        case '|':
                            buff[len++] = '|';

                            break;
                        default:;
                    }

                    h = e;
                }
                if (!(c = cli_hex2str(h))) {
                    mprintf(LOGG_ERROR, "Decoding failed (4): %s\n", h);
                    free(hexcpy);
                    free(buff);
                    return NULL;
                }
                memcpy(&buff[len], c, strlen(h) / 2);
                len += strlen(h) / 2;
                free(c);

                buff[len++] = '}';
                if (level != 0) {
                    mprintf(LOGG_ERROR, "decodehexspecial: Invalid string alternative nesting\n");
                    free(hexcpy);
                    free(buff);
                    return NULL;
                }
            }
        } while ((pt = strchr(start, '(')));

        if (start) {
            if (!(decoded = decodehexstr(start, &hlen))) {
                mprintf(LOGG_ERROR, "Decoding failed (2)\n");
                free(buff);
                free(hexcpy);
                return NULL;
            }
            memcpy(&buff[len], decoded, hlen);
            len += hlen;
            free(decoded);
        }
    }
    free(hexcpy);
    if (dlen)
        *dlen = len;
    return buff;
}

static int decodehex(const char *hexsig)
{
    char *pt, *hexcpy, *start, *n, *decoded, *wild;
    int asterisk = 0;
    unsigned int i, j, hexlen, dlen, parts = 0;
    int mindist = 0, maxdist = 0, error = 0;
    ssize_t bytes_written;

    hexlen = strlen(hexsig);
    if ((wild = strchr(hexsig, '/'))) {
        /* ^offset:trigger-logic/regex/options$ */
        char *trigger, *regex, *regex_end, *cflags;
        size_t tlen = wild - hexsig, rlen = 0, clen;

        /* check for trigger */
        if (!tlen) {
            mprintf(LOGG_ERROR, "pcre without logical trigger\n");
            return -1;
        }

        /* locate end of regex for options start, locate options length */
        if ((regex_end = strchr(wild + 1, '/')) == NULL) {
            mprintf(LOGG_ERROR, "missing regex expression terminator /\n");
            return -1;
        }

        /* gotta make sure we treat escaped slashes */
        for (i = tlen + 1; i < hexlen; i++) {
            if (hexsig[i] == '/' && hexsig[i - 1] != '\\') {
                rlen = i - tlen - 1;
                break;
            }
        }
        if (i == hexlen) {
            mprintf(LOGG_ERROR, "missing regex expression terminator /\n");
            return -1;
        }

        clen = hexlen - tlen - rlen - 2; /* 2 from regex boundaries '/' */

        /* get the trigger statement */
        trigger = calloc(tlen + 1, sizeof(char));
        if (!trigger) {
            mprintf(LOGG_ERROR, "cannot allocate memory for trigger string\n");
            return -1;
        }
        strncpy(trigger, hexsig, tlen);
        trigger[tlen] = '\0';

        /* get the regex expression */
        regex = calloc(rlen + 1, sizeof(char));
        if (!regex) {
            mprintf(LOGG_ERROR, "cannot allocate memory for regex expression\n");
            free(trigger);
            return -1;
        }
        strncpy(regex, hexsig + tlen + 1, rlen);
        regex[rlen] = '\0';

        /* get the compile flags */
        if (clen) {
            cflags = calloc(clen + 1, sizeof(char));
            if (!cflags) {
                mprintf(LOGG_ERROR, "cannot allocate memory for compile flags\n");
                free(trigger);
                free(regex);
                return -1;
            }
            strncpy(cflags, hexsig + tlen + rlen + 2, clen);
            cflags[clen] = '\0';
        } else {
            cflags = NULL;
        }

        /* print components of regex subsig */
        mprintf(LOGG_INFO, "     +-> TRIGGER: %s\n", trigger);
        mprintf(LOGG_INFO, "     +-> REGEX: %s\n", regex);
        mprintf(LOGG_INFO, "     +-> CFLAGS: %s\n", cflags != NULL ? cflags : "null");

        free(trigger);
        free(regex);
        if (cflags)
            free(cflags);

        return 0;
    } else if (strchr(hexsig, '{') || strchr(hexsig, '[')) {
        if (!(hexcpy = strdup(hexsig)))
            return -1;

        for (i = 0; i < hexlen; i++)
            if (hexsig[i] == '{' || hexsig[i] == '[' || hexsig[i] == '*')
                parts++;

        if (parts)
            parts++;

        start = pt = hexcpy;
        for (i = 1; i <= parts; i++) {
            if (i != parts) {
                for (j = 0; j < strlen(start); j++) {
                    if (start[j] == '{' || start[j] == '[') {
                        asterisk = 0;
                        pt       = start + j;
                        break;
                    }
                    if (start[j] == '*') {
                        asterisk = 1;
                        pt       = start + j;
                        break;
                    }
                }
                *pt++ = 0;
            }

            if (mindist && maxdist) {
                if (mindist == maxdist)
                    mprintf(LOGG_INFO, "{WILDCARD_ANY_STRING(LENGTH==%u)}", mindist);
                else
                    mprintf(LOGG_INFO, "{WILDCARD_ANY_STRING(LENGTH>=%u&&<=%u)}", mindist, maxdist);
            } else if (mindist)
                mprintf(LOGG_INFO, "{WILDCARD_ANY_STRING(LENGTH>=%u)}", mindist);
            else if (maxdist)
                mprintf(LOGG_INFO, "{WILDCARD_ANY_STRING(LENGTH<=%u)}", maxdist);

            if (!(decoded = decodehexspecial(start, &dlen))) {
                mprintf(LOGG_ERROR, "Decoding failed\n");
                free(hexcpy);
                return -1;
            }
            bytes_written = write(1, decoded, dlen);
            if (bytes_written != dlen) {
                mprintf(LOGG_WARNING, "Failed to print all decoded bytes\n");
            }
            free(decoded);

            if (i == parts)
                break;

            if (asterisk)
                mprintf(LOGG_INFO, "{WILDCARD_ANY_STRING}");

            mindist = maxdist = 0;

            if (asterisk) {
                start = pt;
                continue;
            }

            if (!(start = strchr(pt, '}')) && !(start = strchr(pt, ']'))) {
                error = 1;
                break;
            }
            *start++ = 0;

            if (!pt) {
                error = 1;
                break;
            }

            if (!strchr(pt, '-')) {
                if (!cli_isnumber(pt) || (mindist = maxdist = atoi(pt)) < 0) {
                    error = 1;
                    break;
                }
            } else {
                if ((n = cli_strtok(pt, 0, "-"))) {
                    if (!cli_isnumber(n) || (mindist = atoi(n)) < 0) {
                        error = 1;
                        free(n);
                        break;
                    }
                    free(n);
                }

                if ((n = cli_strtok(pt, 1, "-"))) {
                    if (!cli_isnumber(n) || (maxdist = atoi(n)) < 0) {
                        error = 1;
                        free(n);
                        break;
                    }
                    free(n);
                }

                if ((n = cli_strtok(pt, 2, "-"))) { /* strict check */
                    error = 1;
                    free(n);
                    break;
                }
            }
        }

        free(hexcpy);
        if (error)
            return -1;

    } else if (strchr(hexsig, '*')) {
        for (i = 0; i < hexlen; i++)
            if (hexsig[i] == '*')
                parts++;

        if (parts)
            parts++;

        for (i = 1; i <= parts; i++) {
            if ((pt = cli_strtok(hexsig, i - 1, "*")) == NULL) {
                mprintf(LOGG_ERROR, "Can't extract part %u of partial signature\n", i);
                return -1;
            }
            if (!(decoded = decodehexspecial(pt, &dlen))) {
                mprintf(LOGG_ERROR, "Decoding failed\n");
                free(pt);
                return -1;
            }
            bytes_written = write(1, decoded, dlen);
            if (bytes_written != dlen) {
                mprintf(LOGG_WARNING, "Failed to print all decoded bytes\n");
            }
            free(decoded);
            if (i < parts)
                mprintf(LOGG_INFO, "{WILDCARD_ANY_STRING}");
            free(pt);
        }

    } else {
        if (!(decoded = decodehexspecial(hexsig, &dlen))) {
            mprintf(LOGG_ERROR, "Decoding failed\n");
            return -1;
        }
        bytes_written = write(1, decoded, dlen);
        if (bytes_written != dlen) {
            mprintf(LOGG_WARNING, "Failed to print all decoded bytes\n");
        }
        free(decoded);
    }

    mprintf(LOGG_INFO, "\n");
    return 0;
}

static int decodesigmod(const char *sigmod)
{
    size_t i;

    for (i = 0; i < strlen(sigmod); i++) {
        mprintf(LOGG_INFO, " ");

        switch (sigmod[i]) {
            case 'i':
                mprintf(LOGG_INFO, "NOCASE");
                break;
            case 'f':
                mprintf(LOGG_INFO, "FULLWORD");
                break;
            case 'w':
                mprintf(LOGG_INFO, "WIDE");
                break;
            case 'a':
                mprintf(LOGG_INFO, "ASCII");
                break;
            default:
                mprintf(LOGG_INFO, "UNKNOWN");
                return -1;
        }
    }

    mprintf(LOGG_INFO, "\n");
    return 0;
}

static int decodecdb(char **tokens)
{
    int sz = 0;
    char *range[2];

    if (!tokens)
        return -1;

    mprintf(LOGG_INFO, "VIRUS NAME: %s\n", tokens[0]);
    mprintf(LOGG_INFO, "CONTAINER TYPE: %s\n", (strcmp(tokens[1], "*") ? tokens[1] : "ANY"));
    mprintf(LOGG_INFO, "CONTAINER SIZE: ");
    if (!cli_isnumber(tokens[2])) {
        if (!strcmp(tokens[2], "*")) {
            mprintf(LOGG_INFO, "ANY\n");

        } else if (strchr(tokens[2], '-')) {
            sz = cli_strtokenize(tokens[2], '-', 2, (const char **)range);
            if (sz != 2 || !cli_isnumber(range[0]) || !cli_isnumber(range[1])) {
                mprintf(LOGG_ERROR, "decodesig: Invalid container size range\n");
                return -1;
            }
            mprintf(LOGG_INFO, "WITHIN RANGE %s to %s\n", range[0], range[1]);

        } else {
            mprintf(LOGG_ERROR, "decodesig: Invalid container size\n");
            return -1;
        }
    } else {
        mprintf(LOGG_INFO, "%s\n", tokens[2]);
    }
    mprintf(LOGG_INFO, "FILENAME REGEX: %s\n", tokens[3]);
    mprintf(LOGG_INFO, "COMPRESSED FILESIZE: ");
    if (!cli_isnumber(tokens[4])) {
        if (!strcmp(tokens[4], "*")) {
            mprintf(LOGG_INFO, "ANY\n");

        } else if (strchr(tokens[4], '-')) {
            sz = cli_strtokenize(tokens[4], '-', 2, (const char **)range);
            if (sz != 2 || !cli_isnumber(range[0]) || !cli_isnumber(range[1])) {
                mprintf(LOGG_ERROR, "decodesig: Invalid container size range\n");
                return -1;
            }
            mprintf(LOGG_INFO, "WITHIN RANGE %s to %s\n", range[0], range[1]);

        } else {
            mprintf(LOGG_ERROR, "decodesig: Invalid compressed filesize\n");
            return -1;
        }
    } else {
        mprintf(LOGG_INFO, "%s\n", tokens[4]);
    }
    mprintf(LOGG_INFO, "UNCOMPRESSED FILESIZE: ");
    if (!cli_isnumber(tokens[5])) {
        if (!strcmp(tokens[5], "*")) {
            mprintf(LOGG_INFO, "ANY\n");

        } else if (strchr(tokens[5], '-')) {
            sz = cli_strtokenize(tokens[5], '-', 2, (const char **)range);
            if (sz != 2 || !cli_isnumber(range[0]) || !cli_isnumber(range[1])) {
                mprintf(LOGG_ERROR, "decodesig: Invalid container size range\n");
                return -1;
            }
            mprintf(LOGG_INFO, "WITHIN RANGE %s to %s\n", range[0], range[1]);

        } else {
            mprintf(LOGG_ERROR, "decodesig: Invalid uncompressed filesize\n");
            return -1;
        }
    } else {
        mprintf(LOGG_INFO, "%s\n", tokens[5]);
    }

    mprintf(LOGG_INFO, "ENCRYPTION: ");
    if (!cli_isnumber(tokens[6])) {
        if (!strcmp(tokens[6], "*")) {
            mprintf(LOGG_INFO, "IGNORED\n");
        } else {
            mprintf(LOGG_ERROR, "decodesig: Invalid encryption flag\n");
            return -1;
        }
    } else {
        mprintf(LOGG_INFO, "%s\n", (atoi(tokens[6]) ? "YES" : "NO"));
    }

    mprintf(LOGG_INFO, "FILE POSITION: ");
    if (!cli_isnumber(tokens[7])) {
        if (!strcmp(tokens[7], "*")) {
            mprintf(LOGG_INFO, "ANY\n");

        } else if (strchr(tokens[7], '-')) {
            sz = cli_strtokenize(tokens[7], '-', 2, (const char **)range);
            if (sz != 2 || !cli_isnumber(range[0]) || !cli_isnumber(range[1])) {
                mprintf(LOGG_ERROR, "decodesig: Invalid container size range\n");
                return -1;
            }
            mprintf(LOGG_INFO, "WITHIN RANGE %s to %s\n", range[0], range[1]);

        } else {
            mprintf(LOGG_ERROR, "decodesig: Invalid file position\n");
            return -1;
        }
    } else {
        mprintf(LOGG_INFO, "%s\n", tokens[7]);
    }

    if (!strcmp(tokens[1], "CL_TYPE_ZIP") || !strcmp(tokens[1], "CL_TYPE_RAR")) {
        if (!strcmp(tokens[8], "*")) {
            mprintf(LOGG_INFO, "CRC SUM: ANY\n");
        } else {

            errno = 0;
            sz    = (int)strtol(tokens[8], NULL, 16);
            if (!sz && errno) {
                mprintf(LOGG_ERROR, "decodesig: Invalid cyclic redundancy check sum\n");
                return -1;
            } else {
                mprintf(LOGG_INFO, "CRC SUM: %d\n", sz);
            }
        }
    }

    return 0;
}

static int decodeftm(char **tokens, int tokens_count)
{
    mprintf(LOGG_INFO, "FILE TYPE NAME: %s\n", tokens[3]);
    mprintf(LOGG_INFO, "FILE SIGNATURE TYPE: %s\n", tokens[0]);
    mprintf(LOGG_INFO, "FILE MAGIC OFFSET: %s\n", tokens[1]);
    mprintf(LOGG_INFO, "FILE MAGIC HEX: %s\n", tokens[2]);
    mprintf(LOGG_INFO, "FILE MAGIC DECODED:\n");
    decodehex(tokens[2]);
    mprintf(LOGG_INFO, "FILE TYPE REQUIRED: %s\n", tokens[4]);
    mprintf(LOGG_INFO, "FILE TYPE DETECTED: %s\n", tokens[5]);
    if (tokens_count == 7)
        mprintf(LOGG_INFO, "FTM FLEVEL: >=%s\n", tokens[6]);
    else if (tokens_count == 8)
        mprintf(LOGG_INFO, "FTM FLEVEL: %s..%s\n", tokens[6], tokens[7]);
    return 0;
}

static int decodesig(char *sig, int fd)
{
    char *pt;
    char *tokens[68], *subtokens[4], *subhex;
    int tokens_count, subtokens_count, subsigs, i, bc = 0;

    if (*sig == '[') {
        if (!(pt = strchr(sig, ']'))) {
            mprintf(LOGG_ERROR, "decodesig: Invalid input\n");
            return -1;
        }
        sig = &pt[2];
    }

    if (strchr(sig, ';')) { /* lsig */
        tokens_count = cli_ldbtokenize(sig, ';', 67 + 1, (const char **)tokens, 2);
        if (tokens_count < 4) {
            mprintf(LOGG_ERROR, "decodesig: Invalid or not supported signature format\n");
            return -1;
        }
        mprintf(LOGG_INFO, "VIRUS NAME: %s\n", tokens[0]);
        if (strlen(tokens[0]) && strstr(tokens[0], ".{") && tokens[0][strlen(tokens[0]) - 1] == '}')
            bc = 1;
        mprintf(LOGG_INFO, "TDB: %s\n", tokens[1]);
        mprintf(LOGG_INFO, "LOGICAL EXPRESSION: %s\n", tokens[2]);
        subsigs = cli_ac_chklsig(tokens[2], tokens[2] + strlen(tokens[2]), NULL, NULL, NULL, 1);
        if (subsigs == -1) {
            mprintf(LOGG_ERROR, "decodesig: Broken logical expression\n");
            return -1;
        }
        subsigs++;
        if (subsigs > 64) {
            mprintf(LOGG_ERROR, "decodesig: Too many subsignatures\n");
            return -1;
        }
        if (!bc && subsigs != tokens_count - 3) {
            mprintf(LOGG_ERROR, "decodesig: The number of subsignatures (==%u) doesn't match the IDs in the logical expression (==%u)\n", tokens_count - 3, subsigs);
            return -1;
        }
        for (i = 0; i < tokens_count - 3; i++) {
            if (i >= subsigs)
                mprintf(LOGG_INFO, " * BYTECODE SUBSIG\n");
            else
                mprintf(LOGG_INFO, " * SUBSIG ID %d\n", i);

            subtokens_count = cli_ldbtokenize(tokens[3 + i], ':', 4, (const char **)subtokens, 0);
            if (!subtokens_count) {
                mprintf(LOGG_ERROR, "decodesig: Invalid or not supported subsignature format\n");
                return -1;
            }
            if ((subtokens_count % 2) == 0)
                mprintf(LOGG_INFO, " +-> OFFSET: %s\n", subtokens[0]);
            else
                mprintf(LOGG_INFO, " +-> OFFSET: ANY\n");

            if (subtokens_count == 3) {
                mprintf(LOGG_INFO, " +-> SIGMOD:");
                decodesigmod(subtokens[2]);
            } else if (subtokens_count == 4) {
                mprintf(LOGG_INFO, " +-> SIGMOD:");
                decodesigmod(subtokens[3]);
            } else {
                mprintf(LOGG_INFO, " +-> SIGMOD: NONE\n");
            }

            subhex = (subtokens_count % 2) ? subtokens[0] : subtokens[1];
            if (fd == -1) {
                mprintf(LOGG_INFO, " +-> DECODED SUBSIGNATURE:\n");
                decodehex(subhex);
            } else {
                mprintf(LOGG_INFO, " +-> ");
                matchsig(subhex, subhex, fd);
            }
        }
    } else if (strchr(sig, ':')) { /* ndb or cdb or ftm*/
        tokens_count = cli_strtokenize(sig, ':', 12 + 1, (const char **)tokens);

        if (tokens_count > 9 && tokens_count < 13) { /* cdb*/
            return decodecdb(tokens);
        }

        if (tokens_count > 5 && tokens_count < 9) { /* ftm */
            long ftmsigtype;
            char *end;
            ftmsigtype = strtol(tokens[0], &end, 10);
            if (end == tokens[0] + 1 && (ftmsigtype == 0 || ftmsigtype == 1 || ftmsigtype == 4))
                return decodeftm(tokens, tokens_count);
        }

        if (tokens_count < 4 || tokens_count > 6) {
            mprintf(LOGG_ERROR, "decodesig: Invalid or not supported signature format\n");
            mprintf(LOGG_INFO, "TOKENS COUNT: %u\n", tokens_count);
            return -1;
        }
        mprintf(LOGG_INFO, "VIRUS NAME: %s\n", tokens[0]);
        if (tokens_count == 5)
            mprintf(LOGG_INFO, "FUNCTIONALITY LEVEL: >=%s\n", tokens[4]);
        else if (tokens_count == 6)
            mprintf(LOGG_INFO, "FUNCTIONALITY LEVEL: %s..%s\n", tokens[4], tokens[5]);

        if (!cli_isnumber(tokens[1])) {
            mprintf(LOGG_ERROR, "decodesig: Invalid target type\n");
            return -1;
        }
        mprintf(LOGG_INFO, "TARGET TYPE: ");
        switch (atoi(tokens[1])) {
            case 0:
                mprintf(LOGG_INFO, "ANY FILE\n");
                break;
            case 1:
                mprintf(LOGG_INFO, "PE\n");
                break;
            case 2:
                mprintf(LOGG_INFO, "OLE2\n");
                break;
            case 3:
                mprintf(LOGG_INFO, "HTML\n");
                break;
            case 4:
                mprintf(LOGG_INFO, "MAIL\n");
                break;
            case 5:
                mprintf(LOGG_INFO, "GRAPHICS\n");
                break;
            case 6:
                mprintf(LOGG_INFO, "ELF\n");
                break;
            case 7:
                mprintf(LOGG_INFO, "NORMALIZED ASCII TEXT\n");
                break;
            case 8:
                mprintf(LOGG_INFO, "DISASM DATA\n");
                break;
            case 9:
                mprintf(LOGG_INFO, "MACHO\n");
                break;
            case 10:
                mprintf(LOGG_INFO, "PDF\n");
                break;
            case 11:
                mprintf(LOGG_INFO, "FLASH\n");
                break;
            case 12:
                mprintf(LOGG_INFO, "JAVA CLASS\n");
                break;
            default:
                mprintf(LOGG_ERROR, "decodesig: Invalid target type\n");
                return -1;
        }
        mprintf(LOGG_INFO, "OFFSET: %s\n", tokens[2]);
        if (fd == -1) {
            mprintf(LOGG_INFO, "DECODED SIGNATURE:\n");
            decodehex(tokens[3]);
        } else {
            matchsig(tokens[3], strcmp(tokens[2], "*") ? tokens[2] : NULL, fd);
        }
    } else if ((pt = strchr(sig, '='))) {
        *pt++ = 0;
        mprintf(LOGG_INFO, "VIRUS NAME: %s\n", sig);
        if (fd == -1) {
            mprintf(LOGG_INFO, "DECODED SIGNATURE:\n");
            decodehex(pt);
        } else {
            matchsig(pt, NULL, fd);
        }
    } else {
        mprintf(LOGG_INFO, "decodesig: Not supported signature format\n");
        return -1;
    }

    return 0;
}

static int decodesigs(void)
{
    char buffer[32769];

    fflush(stdin);
    while (fgets(buffer, sizeof(buffer), stdin)) {
        cli_chomp(buffer);
        if (!strlen(buffer))
            break;
        if (decodesig(buffer, -1) == -1)
            return -1;
    }
    return 0;
}

static int testsigs(const struct optstruct *opts)
{
    char buffer[32769];
    FILE *sigs;
    int ret = 0, fd;

    if (!opts->filename) {
        mprintf(LOGG_ERROR, "--test-sigs requires two arguments\n");
        return -1;
    }

    sigs = fopen(optget(opts, "test-sigs")->strarg, "rb");
    if (!sigs) {
        mprintf(LOGG_ERROR, "testsigs: Can't open file %s\n", optget(opts, "test-sigs")->strarg);
        return -1;
    }

    fd = open(opts->filename[0], O_RDONLY | O_BINARY);
    if (fd == -1) {
        mprintf(LOGG_ERROR, "testsigs: Can't open file %s\n", optget(opts, "test-sigs")->strarg);
        fclose(sigs);
        return -1;
    }

    while (fgets(buffer, sizeof(buffer), sigs)) {
        cli_chomp(buffer);
        if (!strlen(buffer))
            break;
        if (decodesig(buffer, fd) == -1) {
            ret = -1;
            break;
        }
    }

    close(fd);
    fclose(sigs);
    return ret;
}

static int diffdirs(const char *old, const char *new, const char *patch)
{
    FILE *diff;
    DIR *dd;
    struct dirent *dent;
    char cwd[512], path[1024];

    if (!getcwd(cwd, sizeof(cwd))) {
        mprintf(LOGG_ERROR, "diffdirs: getcwd() failed\n");
        return -1;
    }

    if (!(diff = fopen(patch, "wb"))) {
        mprintf(LOGG_ERROR, "diffdirs: Can't open %s for writing\n", patch);
        return -1;
    }

    if (chdir(new) == -1) {
        mprintf(LOGG_ERROR, "diffdirs: Can't chdir to %s\n", new);
        fclose(diff);
        return -1;
    }

    if ((dd = opendir(new)) == NULL) {
        mprintf(LOGG_ERROR, "diffdirs: Can't open directory %s\n", new);
        fclose(diff);
        return -1;
    }

    while ((dent = readdir(dd))) {
        if (dent->d_ino) {
            if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
                continue;

            snprintf(path, sizeof(path), "%s" PATHSEP "%s", old, dent->d_name);
            if (compare(path, dent->d_name, diff) == -1) {
                if (chdir(cwd) == -1)
                    mprintf(LOGG_WARNING, "diffdirs: Can't chdir to %s\n", cwd);
                fclose(diff);
                unlink(patch);
                closedir(dd);
                return -1;
            }
        }
    }
    closedir(dd);

    /* check for removed files */
    if ((dd = opendir(old)) == NULL) {
        mprintf(LOGG_ERROR, "diffdirs: Can't open directory %s\n", old);
        fclose(diff);
        return -1;
    }

    while ((dent = readdir(dd))) {
        if (dent->d_ino) {
            if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
                continue;

            snprintf(path, sizeof(path), "%s" PATHSEP "%s", new, dent->d_name);
            if (access(path, R_OK))
                fprintf(diff, "UNLINK %s\n", dent->d_name);
        }
    }
    closedir(dd);

    fclose(diff);
    mprintf(LOGG_INFO, "Generated diff file %s\n", patch);
    if (chdir(cwd) == -1)
        mprintf(LOGG_WARNING, "diffdirs: Can't chdir to %s\n", cwd);

    return 0;
}

static int makediff(const struct optstruct *opts)
{
    char *odir, *ndir, name[PATH_MAX], broken[PATH_MAX + 8], dbname[PATH_MAX];
    struct cl_cvd *cvd;
    unsigned int oldver, newver;
    int ret;

    if (!opts->filename) {
        mprintf(LOGG_ERROR, "makediff: --diff requires two arguments\n");
        return -1;
    }

    if (!(cvd = cl_cvdhead(opts->filename[0]))) {
        mprintf(LOGG_ERROR, "makediff: Can't read CVD header from %s\n", opts->filename[0]);
        return -1;
    }
    newver = cvd->version;
    cl_cvdfree(cvd);

    if (!(cvd = cl_cvdhead(optget(opts, "diff")->strarg))) {
        mprintf(LOGG_ERROR, "makediff: Can't read CVD header from %s\n", optget(opts, "diff")->strarg);
        return -1;
    }
    oldver = cvd->version;
    cl_cvdfree(cvd);

    if (oldver + 1 != newver) {
        mprintf(LOGG_ERROR, "makediff: The old CVD must be %u\n", newver - 1);
        return -1;
    }

    if (!(odir = createTempDir(opts))) {
        return -1;
    }

    if (CL_SUCCESS != cl_cvdunpack_ex(optget(opts, "diff")->strarg, odir, NULL, CL_DB_UNSIGNED)) {
        mprintf(LOGG_ERROR, "makediff: Can't unpack CVD file %s\n", optget(opts, "diff")->strarg);
        removeTempDir(opts, odir);
        free(odir);
        return -1;
    }

    if (!(ndir = createTempDir(opts))) {
        return -1;
    }

    if (CL_SUCCESS != cl_cvdunpack_ex(opts->filename[0], ndir, NULL, CL_DB_UNSIGNED)) {
        mprintf(LOGG_ERROR, "makediff: Can't unpack CVD file %s\n", opts->filename[0]);
        removeTempDir(opts, odir);
        removeTempDir(opts, ndir);
        free(odir);
        free(ndir);
        return -1;
    }

    snprintf(name, sizeof(name), "%s-%u.script", getdbname(opts->filename[0], dbname, sizeof(dbname)), newver);
    ret = diffdirs(odir, ndir, name);

    removeTempDir(opts, odir);
    removeTempDir(opts, ndir);
    free(odir);
    free(ndir);

    if (ret == -1)
        return -1;

    if (verifydiff(opts, name, optget(opts, "diff")->strarg, NULL) == -1) {
        snprintf(broken, sizeof(broken), "%s.broken", name);
        if (rename(name, broken)) {
            unlink(name);
            mprintf(LOGG_ERROR, "Generated file is incorrect, removed");
        } else {
            mprintf(LOGG_ERROR, "Generated file is incorrect, renamed to %s\n", broken);
        }
        return -1;
    }

    return 0;
}

static int dumpcerts(const struct optstruct *opts)
{
    int status     = -1;
    char *filename = NULL;
    STATBUF sb;
    struct cl_engine *engine       = NULL;
    cli_ctx ctx                    = {0};
    struct cl_scan_options options = {0};
    int fd                         = -1;
    cl_fmap_t *new_map             = NULL;
    cl_error_t ret;

    logg_file = NULL;

    filename = optget(opts, "print-certs")->strarg;
    if (!filename) {
        mprintf(LOGG_ERROR, "dumpcerts: No filename!\n");
        goto done;
    }

    /* Prepare file */
    fd = open(filename, O_RDONLY | O_BINARY);
    if (fd < 0) {
        mprintf(LOGG_ERROR, "dumpcerts: Can't open file %s!\n", filename);
        goto done;
    }

    lseek(fd, 0, SEEK_SET);
    FSTAT(fd, &sb);

    new_map = fmap_new(fd, 0, sb.st_size, filename, filename);
    if (NULL == new_map) {
        mprintf(LOGG_ERROR, "dumpcerts: Can't create fmap for open file\n");
        goto done;
    }

    /* build engine */
    if (!(engine = cl_engine_new())) {
        mprintf(LOGG_ERROR, "dumpcerts: Can't create new engine\n");
        goto done;
    }
    cl_engine_set_num(engine, CL_ENGINE_AC_ONLY, 1);

    if (cli_initroots(engine, 0) != CL_SUCCESS) {
        mprintf(LOGG_ERROR, "dumpcerts: cli_initroots() failed\n");
        goto done;
    }

    if (cli_add_content_match_pattern(engine->root[0], "test", "deadbeef", 0, 0, 0, "*", NULL, 0) != CL_SUCCESS) {
        mprintf(LOGG_ERROR, "dumpcerts: Can't parse signature\n");
        goto done;
    }

    if (cl_engine_compile(engine) != CL_SUCCESS) {
        mprintf(LOGG_ERROR, "dumpcerts: Can't compile engine\n");
        goto done;
    }

    cl_engine_set_num(engine, CL_ENGINE_PE_DUMPCERTS, 1);
    cl_debug();

    /* prepare context */
    ctx.engine = engine;

    ctx.options        = &options;
    ctx.options->parse = ~0;
    ctx.dconf          = (struct cli_dconf *)engine->dconf;

    ctx.recursion_stack_size = ctx.engine->max_recursion_level;
    ctx.recursion_stack      = calloc(sizeof(cli_scan_layer_t), ctx.recursion_stack_size);
    if (!ctx.recursion_stack) {
        goto done;
    }

    // ctx was memset, so recursion_level starts at 0.
    ctx.recursion_stack[ctx.recursion_level].fmap = new_map;
    ctx.recursion_stack[ctx.recursion_level].type = CL_TYPE_ANY; // ANY for the top level, because we don't yet know the type.
    ctx.recursion_stack[ctx.recursion_level].size = new_map->len;

    ctx.fmap = ctx.recursion_stack[ctx.recursion_level].fmap;

    ret = cli_check_auth_header(&ctx, NULL);

    switch (ret) {
        case CL_VERIFIED:
        case CL_VIRUS:
            // These shouldn't happen, since sigtool doesn't load in any sigs
            break;
        case CL_EVERIFY:
            // The Authenticode header was parsed successfully but there were
            // no applicable trust/block rules
            break;
        case CL_BREAK:
            mprintf(LOGG_DEBUG, "dumpcerts: No Authenticode signature detected\n");
            break;
        case CL_EFORMAT:
            mprintf(LOGG_ERROR, "dumpcerts: An error occurred when parsing the file\n");
            break;
        default:
            mprintf(LOGG_ERROR, "dumpcerts: Other error %d inside cli_check_auth_header.\n", ret);
            break;
    }

    status = 0;

done:
    /* Cleanup */
    if (NULL != new_map) {
        fmap_free(new_map);
    }
    if (NULL != ctx.recursion_stack) {
        if (ctx.recursion_stack[ctx.recursion_level].evidence) {
            evidence_free(ctx.recursion_stack[ctx.recursion_level].evidence);
        }
        free(ctx.recursion_stack);
    }
    if (NULL != engine) {
        cl_engine_free(engine);
    }
    if (-1 != fd) {
        close(fd);
    }
    return status;
}

static void help(void)
{
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "                      Clam AntiVirus: Signature Tool %s\n", get_version());
    mprintf(LOGG_INFO, "           By The ClamAV Team: https://www.clamav.net/about.html#credits\n");
    mprintf(LOGG_INFO, "           (C) 2025 Cisco Systems, Inc.\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    sigtool [options]\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    --help                 -h              Show this help\n");
    mprintf(LOGG_INFO, "    --version              -V              Print version number and exit\n");
    mprintf(LOGG_INFO, "    --quiet                                Be quiet, output only error messages\n");
    mprintf(LOGG_INFO, "    --debug                                Enable debug messages\n");
    mprintf(LOGG_INFO, "    --stdout                               Write to stdout instead of stderr. Does not affect 'debug' messages.\n");
    mprintf(LOGG_INFO, "    --tempdir=DIRECTORY                    Create temporary files in DIRECTORY\n");
    mprintf(LOGG_INFO, "    --leave-temps[=yes/no(*)]              Do not remove temporary files\n");
    mprintf(LOGG_INFO, "    --datadir=DIR                          Use DIR as default database directory\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "  Commands for working with signatures:\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    --list-sigs[=FILE]     -l[FILE]        List signature names\n");
    mprintf(LOGG_INFO, "    --find-sigs=REGEX      -fREGEX         Find signatures matching REGEX\n");
    mprintf(LOGG_INFO, "    --decode-sigs                          Decode signatures from stdin\n");
    mprintf(LOGG_INFO, "    --test-sigs=DATABASE TARGET_FILE       Test signatures from DATABASE against \n");
    mprintf(LOGG_INFO, "                                           TARGET_FILE\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "  Commands to generate signatures:\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    --md5 [FILES]                          Generate MD5 hash from stdin\n");
    mprintf(LOGG_INFO, "                                           or MD5 sigs for FILES\n");
    mprintf(LOGG_INFO, "    --sha1 [FILES]                         Generate SHA1 hash from stdin\n");
    mprintf(LOGG_INFO, "                                           or SHA1 sigs for FILES\n");
    mprintf(LOGG_INFO, "    --sha2-256 [FILES]                     Generate SHA2-256 hash from stdin\n");
    mprintf(LOGG_INFO, "                                           or SHA2-256 sigs for FILES\n");
    mprintf(LOGG_INFO, "    --mdb [FILES]                          Generate .mdb (section hash) sigs\n");
    mprintf(LOGG_INFO, "    --imp [FILES]                          Generate .imp (import table hash) sigs\n");
    mprintf(LOGG_INFO, "    --fuzzy-img FILE(S)                    Generate image fuzzy hash for each file\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "  Commands to normalize files, so you can write more generic signatures:\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    --html-normalise=FILE                  Create normalised parts of HTML file\n");
    mprintf(LOGG_INFO, "    --ascii-normalise=FILE                 Create normalised text file from ascii source\n");
    mprintf(LOGG_INFO, "    --utf16-decode=FILE                    Decode UTF16 encoded files\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "  Assorted commands to aid file analysis:\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    --vba=FILE                             Extract VBA/Word6 macro code\n");
    mprintf(LOGG_INFO, "    --vba-hex=FILE                         Extract Word6 macro code with hex values\n");
    mprintf(LOGG_INFO, "    --print-certs=FILE                     Print Authenticode details from a PE\n");
    mprintf(LOGG_INFO, "    --hex-dump                             Convert data from stdin to a hex\n");
    mprintf(LOGG_INFO, "                                           string and print it on stdout\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "  Commands for working with CVD signature database archives:\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    --info=FILE            -i FILE         Print CVD database archive information\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    --build=NAME [cvd] -b NAME             Build a CVD file.\n");
    mprintf(LOGG_INFO, "                                           The following options augment --build.\n");
    mprintf(LOGG_INFO, "    --max-bad-sigs=NUMBER                  Maximum number of mismatched signatures\n");
    mprintf(LOGG_INFO, "                                           When building a CVD. Default: 3000\n");
    mprintf(LOGG_INFO, "    --flevel=FLEVEL                        Specify a custom flevel.\n");
    mprintf(LOGG_INFO, "                                           Default: %u\n", cl_retflevel());
    mprintf(LOGG_INFO, "    --cvd-version=NUMBER                   Specify the version number to use for\n");
    mprintf(LOGG_INFO, "                                           the build. Default is to use the value+1\n");
    mprintf(LOGG_INFO, "                                           from the current CVD in --datadir.\n");
    mprintf(LOGG_INFO, "                                           If no datafile is found the default\n");
    mprintf(LOGG_INFO, "                                           behaviour is to prompt for a version\n");
    mprintf(LOGG_INFO, "                                           number, this switch will prevent the\n");
    mprintf(LOGG_INFO, "                                           prompt.  NOTE: If a CVD is found in the\n");
    mprintf(LOGG_INFO, "                                           --datadir its version+1 is used and\n");
    mprintf(LOGG_INFO, "                                           this value is ignored.\n");
    mprintf(LOGG_INFO, "    --no-cdiff                             Don't generate .cdiff file.\n");
    mprintf(LOGG_INFO, "                                           If not specified, --build will try to\n");
    mprintf(LOGG_INFO, "                                           create a cdiff by comparing with the\n");
    mprintf(LOGG_INFO, "                                           current CVD in --datadir\n");
    mprintf(LOGG_INFO, "                                           If no datafile is found the default\n");
    mprintf(LOGG_INFO, "                                           behaviour is to skip making a CDIFF.\n");
    mprintf(LOGG_INFO, "    --hybrid                               Create a hybrid (standard and bytecode)\n");
    mprintf(LOGG_INFO, "                                           database file\n");
    mprintf(LOGG_INFO, "    --unsigned                             Create unsigned database file (.cud)\n");
    mprintf(LOGG_INFO, "    --server=ADDR                          ClamAV Signing Service address\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    --unpack=FILE          -u FILE         Unpack a CVD/CLD file\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    --unpack-current=SHORTNAME             Unpack local CVD/CLD into cwd\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    --fips-limits                          Enforce FIPS-like limits on using hash algorithms for\n");
    mprintf(LOGG_INFO, "                                           cryptographic purposes. Will disable MD5 & SHA1\n");
    mprintf(LOGG_INFO, "                                           FP sigs and will require '.sign' files to verify CVD\n");
    mprintf(LOGG_INFO, "                                           authenticity.\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "  Commands for working with CDIFF patch files:\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    --diff=OLD NEW         -d OLD NEW      Create diff for OLD and NEW CVDs\n");
    mprintf(LOGG_INFO, "    --compare=OLD NEW      -c OLD NEW      Show diff between OLD and NEW files in\n");
    mprintf(LOGG_INFO, "                                           cdiff format\n");
    mprintf(LOGG_INFO, "    --run-cdiff=FILE       -r FILE         Execute update script FILE in cwd\n");
    mprintf(LOGG_INFO, "    --verify-cdiff=DIFF CVD/CLD            Verify DIFF against CVD/CLD\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "  Commands creating and verifying .sign detached digital signatures:\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    --sign FILE                            Sign a file.\n");
    mprintf(LOGG_INFO, "                                           The resulting .sign file name will\n");
    mprintf(LOGG_INFO, "                                           be in the form: dbname-version.cvd.sign\n");
    mprintf(LOGG_INFO, "                                           or FILE.sign for non-CVD targets.\n");
    mprintf(LOGG_INFO, "                                           It will be created next to the target file.\n");
    mprintf(LOGG_INFO, "                                           If a .sign file already exists, then the\n");
    mprintf(LOGG_INFO, "                                           new signature will be appended to file.\n");
    mprintf(LOGG_INFO, "    --key /path/to/private.key             Specify a signing key.\n");
    mprintf(LOGG_INFO, "    --cert /path/to/private.key            Specify a signing cert.\n");
    mprintf(LOGG_INFO, "                                           May be used more than once to add\n");
    mprintf(LOGG_INFO, "                                           intermediate and root certificates.\n");
    mprintf(LOGG_INFO, "    --append                               Use to add a signature line to an existing .sign file.\n");
    mprintf(LOGG_INFO, "                                           Otherwise an existing .sign file will be overwritten.\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    --verify FILE                          Find and verify a detached digital\n");
    mprintf(LOGG_INFO, "                                           signature for the given file.\n");
    mprintf(LOGG_INFO, "                                           The digital signature file name must\n");
    mprintf(LOGG_INFO, "                                           be in the form: dbname-version.cvd.sign\n");
    mprintf(LOGG_INFO, "                                           or FILE.sign for non-CVD targets.\n");
    mprintf(LOGG_INFO, "                                           It must be found next to the target file.\n");
    mprintf(LOGG_INFO, "    --cvdcertsdir DIRECTORY                Specify a directory containing the root\n");
    mprintf(LOGG_INFO, "                                           CA cert needed to verify the signature.\n");
    mprintf(LOGG_INFO, "                                           If not provided, then sigtool will look in the default directory.n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "Environment Variables:\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    SIGNDUSER                              The username to authenticate with the signing server when building a\n");
    mprintf(LOGG_INFO, "                                           signed CVD database.\n");
    mprintf(LOGG_INFO, "    SIGNDPASS                              The password to authenticate with the signing server when building a\n");
    mprintf(LOGG_INFO, "                                           signed CVD database.\n");
    mprintf(LOGG_INFO, "    CVD_CERTS_DIR                          Specify a directory containing the root CA cert needed\n");
    mprintf(LOGG_INFO, "                                           to verify detached CVD digital signatures.\n");
    mprintf(LOGG_INFO, "                                           If not provided, then sigtool will look in the default directory.\n");
    mprintf(LOGG_INFO, "\n");

    return;
}

int main(int argc, char **argv)
{
    int ret;
    struct optstruct *opts;
    STATBUF sb;

    const char *cvdcertsdir = NULL;
    STATBUF statbuf;

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    if (check_flevel())
        exit(1);

    if ((ret = cl_init(CL_INIT_DEFAULT)) != CL_SUCCESS) {
        mprintf(LOGG_ERROR, "Can't initialize libclamav: %s\n", cl_strerror(ret));
        return -1;
    }
    ret = 1;

    /* Rust logging initialization */
    if (!clrs_log_init()) {
        cli_dbgmsg("Unexpected problem occurred while setting up rust logging... continuing without rust logging. \
                    Please submit an issue to https://github.com/Cisco-Talos/clamav");
    }

    opts = optparse(NULL, argc, argv, 1, OPT_SIGTOOL, 0, NULL);
    if (!opts) {
        mprintf(LOGG_ERROR, "Can't parse command line options\n");
        return 1;
    }

    if (optget(opts, "quiet")->enabled)
        mprintf_quiet = 1;

    if (optget(opts, "stdout")->enabled)
        mprintf_stdout = 1;

    if (optget(opts, "debug")->enabled)
        cl_debug();

    if (optget(opts, "version")->enabled) {
        print_version(NULL);
        optfree(opts);
        return 0;
    }

    if (optget(opts, "help")->enabled) {
        optfree(opts);
        help();
        return 0;
    }

    // Evaluate the absolute path for cvdcertsdir in case we change directories later.
    cvdcertsdir = optget(opts, "cvdcertsdir")->strarg;
    if (NULL == cvdcertsdir) {
        // If not set, check the environment variable.
        cvdcertsdir = getenv("CVD_CERTS_DIR");
        if (NULL == cvdcertsdir) {
            // If not set, use the default path.
            cvdcertsdir = OPT_CERTSDIR;
        }
    }

    // Command line option must override the engine defaults
    // (which would've used the env var or hardcoded path)
    if (LSTAT(cvdcertsdir, &statbuf) == -1) {
        logg(LOGG_ERROR,
             "ClamAV CA certificates directory is missing: %s"
             " - It should have been provided as a part of installation.\n",
             cvdcertsdir);
        return -1;
    }

    // Convert certs dir to real path.
    ret = cli_realpath((const char *)cvdcertsdir, &g_cvdcertsdir);
    if (CL_SUCCESS != ret) {
        logg(LOGG_ERROR, "Failed to determine absolute path of '%s' for the CVD certs directory.\n", cvdcertsdir);
        return -1;
    }

    if (optget(opts, "hex-dump")->enabled)
        ret = hexdump();
    else if (optget(opts, "md5")->enabled)
        ret = hashsig(opts, 0, CLI_HASH_MD5);
    else if (optget(opts, "sha1")->enabled)
        ret = hashsig(opts, 0, CLI_HASH_SHA1);
    else if (optget(opts, "sha2-256")->enabled || optget(opts, "sha256")->enabled)
        ret = hashsig(opts, 0, CLI_HASH_SHA2_256);
    else if (optget(opts, "mdb")->enabled)
        ret = hashsig(opts, 1, CLI_HASH_MD5);
    else if (optget(opts, "imp")->enabled)
        ret = hashsig(opts, 2, CLI_HASH_MD5);
    else if (optget(opts, "fuzzy-img")->enabled)
        ret = fuzzy_img(opts);
    else if (optget(opts, "html-normalise")->enabled)
        ret = htmlnorm(opts);
    else if (optget(opts, "ascii-normalise")->enabled)
        ret = asciinorm(opts);
    else if (optget(opts, "utf16-decode")->enabled)
        ret = utf16decode(opts);
    else if (optget(opts, "build")->enabled) {
        ret = build(opts);
        if (ret == CL_ELAST_ERROR) {
            // build() returns CL_ELAST_ERROR the hash starts with 00. This will fail to verify with ClamAV 1.1 -> 1.4.
            // Retry the build again to get new hashes.
            mprintf(LOGG_WARNING, "Retrying the build for a chance at a better hash.\n");
            ret = build(opts);
        }
    } else if (optget(opts, "sign")->enabled)
        ret = sign(opts);
    else if (optget(opts, "verify")->enabled)
        ret = verify(opts);
    else if (optget(opts, "unpack")->enabled)
        ret = unpack(opts);
    else if (optget(opts, "unpack-current")->enabled)
        ret = unpack(opts);
    else if (optget(opts, "info")->enabled)
        ret = cvdinfo(opts);
    else if (optget(opts, "list-sigs")->active)
        ret = listsigs(opts, 0);
    else if (optget(opts, "find-sigs")->active)
        ret = listsigs(opts, 1);
    else if (optget(opts, "decode-sigs")->active)
        ret = decodesigs();
    else if (optget(opts, "test-sigs")->enabled)
        ret = testsigs(opts);
    else if (optget(opts, "vba")->enabled || optget(opts, "vba-hex")->enabled)
        ret = vbadump(opts);
    else if (optget(opts, "diff")->enabled)
        ret = makediff(opts);
    else if (optget(opts, "compare")->enabled)
        ret = compareone(opts);
    else if (optget(opts, "print-certs")->enabled)
        ret = dumpcerts(opts);
    else if (optget(opts, "run-cdiff")->enabled)
        ret = rundiff(opts);
    else if (optget(opts, "verify-cdiff")->enabled) {
        if (!opts->filename) {
            mprintf(LOGG_ERROR, "--verify-cdiff requires two arguments\n");
            ret = -1;
        } else {
            if (CLAMSTAT(opts->filename[0], &sb) == -1) {
                mprintf(LOGG_INFO, "--verify-cdiff: Can't get status of %s\n", opts->filename[0]);
                ret = -1;
            } else {
                if (S_ISDIR(sb.st_mode))
                    ret = verifydiff(opts, optget(opts, "verify-cdiff")->strarg, NULL, opts->filename[0]);
                else
                    ret = verifydiff(opts, optget(opts, "verify-cdiff")->strarg, opts->filename[0], NULL);
            }
        }
    } else
        help();

    optfree(opts);

    return ret ? 1 : 0;
}
