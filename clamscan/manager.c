/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
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
 *
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#include <dirent.h>
#ifndef _WIN32
#include <sys/wait.h>
#include <utime.h>
#include <sys/time.h>
#include <sys/resource.h>
#endif
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <math.h>

// libclamav
#include "clamav.h"
#include "others.h"
#include "matcher-ac.h"
#include "matcher-pcre.h"
#include "str.h"
#include "readdb.h"
#include "default.h"

// common
#include "optparser.h"
#include "actions.h"
#include "output.h"
#include "misc.h"

#include "manager.h"
#include "global.h"

#ifdef _WIN32 /* scan memory */
#include "scanmem.h"
#endif

#ifdef C_LINUX
dev_t procdev;
#endif

#ifdef _WIN32
/* FIXME: If possible, handle users correctly */
static int checkaccess(const char *path, const char *username, int mode)
{
    return !access(path, mode);
}
#else
static int checkaccess(const char *path, const char *username, int mode)
{
    struct passwd *user;
    int ret = 0, status;

    if (!geteuid()) {
        if ((user = getpwnam(username)) == NULL) {
            return -1;
        }

        switch (fork()) {
            case -1:
                return -2;
            case 0:
                if (setgid(user->pw_gid)) {
                    fprintf(stderr, "ERROR: setgid(%d) failed.\n", (int)user->pw_gid);
                    exit(0);
                }

                if (setuid(user->pw_uid)) {
                    fprintf(stderr, "ERROR: setuid(%d) failed.\n", (int)user->pw_uid);
                    exit(0);
                }

                if (access(path, mode))
                    exit(0);
                else
                    exit(1);
            default:
                wait(&status);
                if (WIFEXITED(status) && WEXITSTATUS(status) == 1)
                    ret = 1;
        }
    } else {
        if (!access(path, mode))
            ret = 1;
    }

    return ret;
}
#endif

struct metachain {
    char **chains;
    size_t lastadd;
    size_t lastvir;
    size_t level;
    size_t nchains;
};

struct clamscan_cb_data {
    struct metachain *chain;
    const char *filename;
};

static cl_error_t pre(int fd, const char *type, void *context)
{
    struct metachain *c;
    struct clamscan_cb_data *d;

    UNUSEDPARAM(fd);
    UNUSEDPARAM(type);

    if (!(context))
        return CL_CLEAN;
    d = (struct clamscan_cb_data *)context;
    c = d->chain;
    if (c == NULL)
        return CL_CLEAN;

    c->level++;

    return CL_CLEAN;
}

static int print_chain(struct metachain *c, char *str, size_t len)
{
    size_t i;
    size_t na = 0;

    for (i = 0; i < c->nchains - 1; i++) {
        size_t n = strlen(c->chains[i]);

        if (na)
            str[na++] = '!';

        if (n + na + 2 > len)
            break;

        memcpy(str + na, c->chains[i], n);
        na += n;
    }

    str[na]      = '\0';
    str[len - 1] = '\0';

    return i == c->nchains - 1 ? 0 : 1;
}

static cl_error_t post(int fd, int result, const char *alert_name, void *context)
{
    struct clamscan_cb_data *d = context;
    struct metachain *c        = NULL;
    char str[128];

    UNUSEDPARAM(fd);
    UNUSEDPARAM(result);

    if (d != NULL)
        c = d->chain;

    if (c && c->nchains) {
        print_chain(c, str, sizeof(str));

        if (c->level == c->lastadd && !alert_name)
            free(c->chains[--c->nchains]);

        if (alert_name && !c->lastvir)
            c->lastvir = c->level;
    }

    if (c)
        c->level--;

    return CL_CLEAN;
}

static cl_error_t meta(const char *container_type, unsigned long fsize_container, const char *filename,
                       unsigned long fsize_real, int is_encrypted, unsigned int filepos_container, void *context)
{
    char prev[128];
    struct metachain *c;
    struct clamscan_cb_data *d;
    const char *type;
    size_t n;
    char *chain;
    char **chains;
    int toolong;

    UNUSEDPARAM(fsize_container);
    UNUSEDPARAM(fsize_real);
    UNUSEDPARAM(is_encrypted);
    UNUSEDPARAM(filepos_container);

    if (!(context))
        return CL_CLEAN;
    d = (struct clamscan_cb_data *)context;

    c    = d->chain;
    type = (strncmp(container_type, "CL_TYPE_", 8) == 0 ? container_type + 8 : container_type);
    n    = strlen(type) + strlen(filename) + 2;

    if (!c)
        return CL_CLEAN;

    chain = malloc(n);

    if (!chain)
        return CL_CLEAN;

    if (!strcmp(type, "ANY"))
        snprintf(chain, n, "%s", filename);
    else
        snprintf(chain, n, "%s:%s", type, filename);

    if (c->lastadd != c->level) {
        n = c->nchains + 1;

        chains = realloc(c->chains, n * sizeof(*chains));
        if (!chains) {
            free(chain);
            return CL_CLEAN;
        }

        c->chains  = chains;
        c->nchains = n;
        c->lastadd = c->level;
    } else {
        if (c->nchains > 0)
            free(c->chains[c->nchains - 1]);
    }

    if (c->nchains > 0) {
        c->chains[c->nchains - 1] = chain;
        toolong                   = print_chain(c, prev, sizeof(prev));
        logg(LOGG_DEBUG, "Scanning %s%s!%s\n", prev, toolong ? "..." : "", chain);
    } else {
        free(chain);
    }

    return CL_CLEAN;
}

static void clamscan_virus_found_cb(int fd, const char *alert_name, void *context)
{
    struct clamscan_cb_data *data = (struct clamscan_cb_data *)context;
    const char *filename;

    UNUSEDPARAM(fd);

    if (data == NULL)
        return;
    if (data->filename != NULL)
        filename = data->filename;
    else
        filename = "(filename not set)";
    logg(LOGG_INFO, "%s: %s FOUND\n", filename, alert_name);
    return;
}

static void scanfile(const char *filename, struct cl_engine *engine, const struct optstruct *opts, struct cl_scan_options *options)
{
    cl_error_t ret = CL_SUCCESS;
    int fd         = -1;
    int included   = 0;
    unsigned i;
    const struct optstruct *opt;
    cl_verdict_t verdict   = CL_VERDICT_NOTHING_FOUND;
    const char *alert_name = NULL;
    STATBUF sb;
    struct metachain chain       = {0};
    struct clamscan_cb_data data = {0};
    const char *hash_hint        = NULL;
    char **hash_out              = NULL;
    char *hash                   = NULL;
    const char *hash_alg         = NULL;
    const char *file_type_hint   = NULL;
    char **file_type_out         = NULL;
    char *file_type              = NULL;

    char *real_filename = NULL;

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

    if ((opt = optget(opts, "exclude"))->enabled) {
        while (opt) {
            if (match_regex(filename, opt->strarg) == 1) {
                if (!printinfected)
                    logg(LOGG_INFO, "%s: Excluded\n", filename);

                goto done;
            }

            opt = opt->nextarg;
        }
    }

    if ((opt = optget(opts, "include"))->enabled) {
        included = 0;

        while (opt) {
            if (match_regex(filename, opt->strarg) == 1) {
                included = 1;
                break;
            }

            opt = opt->nextarg;
        }

        if (!included) {
            if (!printinfected)
                logg(LOGG_INFO, "%s: Excluded\n", filename);

            goto done;
        }
    }

    /* argh, don't scan /proc files */
    if (CLAMSTAT(filename, &sb) != -1) {
#ifdef C_LINUX
        if (procdev && sb.st_dev == procdev) {
            if (!printinfected)
                logg(LOGG_INFO, "%s: Excluded (/proc)\n", filename);

            goto done;
        }
#endif
        if (!sb.st_size) {
            if (!printinfected)
                logg(LOGG_INFO, "%s: Empty file\n", filename);

            goto done;
        }

        info.bytes_read += sb.st_size;
    }

#ifndef _WIN32
    if (geteuid()) {
        if (checkaccess(filename, NULL, R_OK) != 1) {
            if (!printinfected)
                logg(LOGG_INFO, "%s: Access denied\n", filename);

            info.errors++;
            goto done;
        }
    }
#endif

    memset(&chain, 0, sizeof(chain));
    if (optget(opts, "archive-verbose")->enabled) {
        chain.chains = malloc(sizeof(char **));
        if (chain.chains) {
            chain.chains[0] = strdup(filename);
            if (!chain.chains[0]) {
                logg(LOGG_INFO, "Unable to allocate memory in scanfile()\n");
                info.errors++;
                goto done;
            }
            chain.nchains = 1;
        }
    }

    if ((opt = optget(opts, "hash-alg"))->enabled) {
        hash_alg = opt->strarg;
    }
    if ((opt = optget(opts, "hash-hint"))->enabled) {
        hash_hint = opt->strarg;
    }
    if ((opt = optget(opts, "log-hash"))->enabled) {
        hash_out = &hash;
    }
    if ((opt = optget(opts, "file-type-hint"))->enabled) {
        file_type_hint = opt->strarg;
    }
    if ((opt = optget(opts, "log-file-type"))->enabled) {
        file_type_out = &file_type;
    }

    logg(LOGG_DEBUG, "Scanning %s\n", filename);

    if ((fd = safe_open(filename, O_RDONLY | O_BINARY)) == -1) {
        logg(LOGG_WARNING, "Can't open file %s: %s\n", filename, strerror(errno));
        info.errors++;
        goto done;
    }

    data.chain    = &chain;
    data.filename = filename;

    ret = cl_scandesc_ex(
        fd,
        filename,
        &verdict,
        &alert_name,
        &info.bytes_scanned,
        engine, options,
        &data,
        hash_hint,
        hash_out,
        hash_alg,
        file_type_hint,
        file_type_out);

    switch (verdict) {
        case CL_VERDICT_NOTHING_FOUND: {
            if (CL_SUCCESS == ret) {
                if (!printinfected && printclean) {
                    mprintf(LOGG_INFO, "%s: OK\n", filename);
                }
                info.files++;
            } else {
                if (!printinfected)
                    logg(LOGG_INFO, "%s: %s ERROR\n", filename, cl_strerror(ret));

                info.errors++;
            }
        } break;

        case CL_VERDICT_TRUSTED: {
            // TODO: Option to print "TRUSTED" verdict instead of "OK"?
            if (!printinfected && printclean) {
                mprintf(LOGG_INFO, "%s: OK\n", filename);
            }
            info.files++;
        } break;

        case CL_VERDICT_STRONG_INDICATOR:
        case CL_VERDICT_POTENTIALLY_UNWANTED: {
            if (optget(opts, "archive-verbose")->enabled) {
                if (chain.nchains > 1) {
                    char str[128];
                    int toolong = print_chain(&chain, str, sizeof(str));

                    logg(LOGG_INFO, "%s%s!(%llu)%s: %s FOUND\n", str, toolong ? "..." : "", (long long unsigned)(chain.lastvir - 1), chain.chains[chain.nchains - 1], alert_name);
                } else if (chain.lastvir) {
                    logg(LOGG_INFO, "%s!(%llu): %s FOUND\n", filename, (long long unsigned)(chain.lastvir - 1), alert_name);
                }
            }
            info.files++;
            info.ifiles++;

            if (bell) {
                fprintf(stderr, "\007");
            }
        } break;
    }

    if (NULL != hash) {
        if (hash_alg == NULL) {
            // libclamav defaults to sha2-256
            hash_alg = "sha2-256";
        }
        logg(LOGG_INFO, "%s FileHash: %s (%s)\n", filename, hash, hash_alg);
    }

    if (NULL != file_type) {
        logg(LOGG_INFO, "%s FileType: %s\n", filename, file_type);
    }

done:
    /*
     * Run the action callback if the file was infected.
     */
    if (((verdict == CL_VERDICT_STRONG_INDICATOR) || (verdict == CL_VERDICT_POTENTIALLY_UNWANTED)) && action) {
        action(filename);
    }

    if (NULL != hash) {
        free(hash);
    }
    if (NULL != file_type) {
        free(file_type);
    }
    if (NULL != chain.chains) {
        for (i = 0; i < chain.nchains; i++) {
            free(chain.chains[i]);
        }
        free(chain.chains);
    }
    if (fd != -1) {
        close(fd);
    }
    if (NULL != real_filename) {
        free(real_filename);
    }

    return;
}

static void scandirs(const char *dirname, struct cl_engine *engine, const struct optstruct *opts, struct cl_scan_options *options, unsigned int depth, dev_t dev)
{
    DIR *dd;
    struct dirent *dent;
    STATBUF sb;
    char *fname;
    int included;
    const struct optstruct *opt;
    unsigned int dirlnk, filelnk;

    if ((opt = optget(opts, "exclude-dir"))->enabled) {
        while (opt) {
            if (match_regex(dirname, opt->strarg) == 1) {
                if (!printinfected)
                    logg(LOGG_INFO, "%s: Excluded\n", dirname);

                return;
            }

            opt = opt->nextarg;
        }
    }

    if ((opt = optget(opts, "include-dir"))->enabled) {
        included = 0;
        while (opt) {
            if (match_regex(dirname, opt->strarg) == 1) {
                included = 1;
                break;
            }

            opt = opt->nextarg;
        }

        if (!included) {
            if (!printinfected)
                logg(LOGG_INFO, "%s: Excluded\n", dirname);

            return;
        }
    }

    if (depth > (unsigned int)optget(opts, "max-dir-recursion")->numarg)
        return;

    dirlnk  = optget(opts, "follow-dir-symlinks")->numarg;
    filelnk = optget(opts, "follow-file-symlinks")->numarg;

    if ((dd = opendir(dirname)) != NULL) {
        info.dirs++;
        depth++;
        while ((dent = readdir(dd))) {
            if (dent->d_ino) {
                if (strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
                    /* build the full name */
                    fname = malloc(strlen(dirname) + strlen(dent->d_name) + 2);
                    if (fname == NULL) { /* oops, malloc() failed, print warning and return */
                        logg(LOGG_ERROR, "scandirs: Memory allocation failed for fname\n");
                        break;
                    }

                    if (!strcmp(dirname, PATHSEP))
                        sprintf(fname, PATHSEP "%s", dent->d_name);
                    else
                        sprintf(fname, "%s" PATHSEP "%s", dirname, dent->d_name);

                    /* stat the file */
                    if (LSTAT(fname, &sb) != -1) {
                        if (!optget(opts, "cross-fs")->enabled) {
                            if (sb.st_dev != dev) {
                                if (!printinfected)
                                    logg(LOGG_INFO, "%s: Excluded\n", fname);

                                free(fname);
                                continue;
                            }
                        }
                        if (S_ISLNK(sb.st_mode)) {
                            if (dirlnk != 2 && filelnk != 2) {
                                if (!printinfected)
                                    logg(LOGG_INFO, "%s: Symbolic link\n", fname);
                            } else if (CLAMSTAT(fname, &sb) != -1) {
                                if (S_ISREG(sb.st_mode) && filelnk == 2) {
                                    scanfile(fname, engine, opts, options);
                                } else if (S_ISDIR(sb.st_mode) && dirlnk == 2) {
                                    if (recursion)
                                        scandirs(fname, engine, opts, options, depth, dev);
                                } else {
                                    if (!printinfected)
                                        logg(LOGG_INFO, "%s: Symbolic link\n", fname);
                                }
                            }
                        } else if (S_ISREG(sb.st_mode)) {
                            scanfile(fname, engine, opts, options);
                        } else if (S_ISDIR(sb.st_mode) && recursion) {
                            scandirs(fname, engine, opts, options, depth, dev);
                        }
                    }

                    free(fname);
                }
            }
        }
        closedir(dd);
    } else {
        if (!printinfected)
            logg(LOGG_INFO, "%s: Can't open directory.\n", dirname);

        info.errors++;
    }
}

static int scanstdin(const struct cl_engine *engine, const struct optstruct *opts, struct cl_scan_options *options)
{
    cl_error_t ret;

    size_t fsize           = 0;
    cl_verdict_t verdict   = CL_VERDICT_NOTHING_FOUND;
    const char *alert_name = NULL;
    const char *tmpdir     = NULL;
    char *filename, buff[FILEBUFF];
    size_t bread;
    FILE *fs;
    struct clamscan_cb_data data;
    const struct optstruct *opt;
    const char *hash_hint      = NULL;
    char **hash_out            = NULL;
    char *hash                 = NULL;
    const char *hash_alg       = NULL;
    const char *file_type_hint = NULL;
    char **file_type_out       = NULL;
    char *file_type            = NULL;

    tmpdir = cl_engine_get_str(engine, CL_ENGINE_TMPDIR, NULL);
    if (NULL == tmpdir) {
        tmpdir = cli_gettmpdir();
    }

    if (access(tmpdir, R_OK | W_OK) == -1) {
        logg(LOGG_ERROR, "Can't write to temporary directory\n");
        return 2;
    }

    if (!(filename = cli_gentemp(tmpdir))) {
        logg(LOGG_ERROR, "Can't generate tempfile name\n");
        return 2;
    }

    if (!(fs = fopen(filename, "wb"))) {
        logg(LOGG_ERROR, "Can't open %s for writing\n", filename);
        free(filename);
        return 2;
    }

    while ((bread = fread(buff, 1, FILEBUFF, stdin))) {
        fsize += bread;
        if (fwrite(buff, 1, bread, fs) < bread) {
            logg(LOGG_ERROR, "Can't write to %s\n", filename);
            free(filename);
            fclose(fs);
            return 2;
        }
    }

    fclose(fs);

    if ((opt = optget(opts, "hash-alg"))->enabled) {
        hash_alg = opt->strarg;
    }
    if ((opt = optget(opts, "hash-hint"))->enabled) {
        hash_hint = opt->strarg;
    }
    if ((opt = optget(opts, "log-hash"))->enabled) {
        hash_out = &hash;
    }
    if ((opt = optget(opts, "file-type-hint"))->enabled) {
        file_type_hint = opt->strarg;
    }
    if ((opt = optget(opts, "log-file-type"))->enabled) {
        file_type_out = &file_type;
    }

    logg(LOGG_DEBUG, "Scanning %s\n", filename);

    info.files++;
    info.bytes_read += fsize;

    data.filename = "stdin";
    data.chain    = NULL;

    ret = cl_scanfile_ex(
        filename,
        &verdict,
        &alert_name,
        &info.bytes_scanned,
        engine,
        options,
        &data,
        hash_hint,
        hash_out,
        hash_alg,
        file_type_hint,
        file_type_out);

    switch (verdict) {
        case CL_VERDICT_NOTHING_FOUND: {
            if (CL_SUCCESS == ret) {
                if (!printinfected) {
                    mprintf(LOGG_INFO, "stdin: OK\n");
                }
                info.files++;
            } else {
                if (!printinfected) {
                    logg(LOGG_INFO, "stdin: %s ERROR\n", cl_strerror(ret));
                }
                info.errors++;
            }
        } break;

        case CL_VERDICT_TRUSTED: {
            // TODO: Option to print "TRUSTED" verdict instead of "OK"?
            if (!printinfected) {
                mprintf(LOGG_INFO, "stdin: OK\n");
            }
        } break;

        case CL_VERDICT_STRONG_INDICATOR:
        case CL_VERDICT_POTENTIALLY_UNWANTED: {
            info.ifiles++;

            if (bell) {
                fprintf(stderr, "\007");
            }
        } break;
    }

    if (NULL != hash) {
        if (hash_alg == NULL) {
            // libclamav defaults to sha2-256
            hash_alg = "sha2-256";
        }
        logg(LOGG_INFO, "%s FileHash: %s (%s)\n", filename, hash, hash_alg);
    }

    if (NULL != file_type) {
        logg(LOGG_INFO, "%s FileType: %s\n", filename, file_type);
    }

    if (NULL != hash) {
        free(hash);
    }

    if (NULL != file_type) {
        free(file_type);
    }

    unlink(filename);
    free(filename);
    return ret;
}

struct sigload_progress {
    time_t startTime;
    time_t lastRunTime;
    uint8_t bComplete;
};

struct engine_compile_progress {
    time_t startTime;
    time_t lastRunTime;
    uint8_t bComplete;
};

struct engine_free_progress {
    time_t startTime;
    time_t lastRunTime;
    uint8_t bComplete;
};

static void print_time(time_t seconds)
{
    if (seconds >= 3600) {
        fprintf(stdout, "%2lldh %02lldm", (long long)seconds / 3600, ((long long)seconds % 3600) / 60);
    } else if (seconds >= 60) {
        fprintf(stdout, "%2lldm %02llds", (long long)seconds / 60, (long long)seconds % 60);
    } else {
        fprintf(stdout, "%3llds", (long long)seconds);
    }
}

static void print_num_sigs(size_t sigs, int bPad)
{
    if (sigs >= (1000 * 1000)) {
        const char *format = bPad ? "%7.02fM" : "%.02fM";
        double megasigs    = sigs / (double)(1000 * 1000);
        fprintf(stdout, format, megasigs);
    } else if (sigs >= 1000) {
        const char *format = bPad ? "%7.02fK" : "%.02fK";
        double kilosigs    = sigs / (double)(1000);
        fprintf(stdout, format, kilosigs);
    } else {
        const char *format = bPad ? "%8zu" : "%zu";
        fprintf(stdout, format, sigs);
    }
}

/**
 * @brief Progress callback for sig-load
 *
 * @param total_items   Total number of items
 * @param now_completed Number of items completed
 * @param context       Opaque application provided data; This maps to sigload_progress
 */
static cl_error_t sigload_callback(size_t total_items, size_t now_completed, void *context)
{
    time_t curtime = 0;
    time_t remtime = 0;

    struct sigload_progress *sigloadProgress = (struct sigload_progress *)context;

    uint32_t i             = 0;
    uint32_t totalNumDots  = 25;
    uint32_t numDots       = 0;
    double fraction_loaded = 0.0;

    if ((total_items <= 0) || (sigloadProgress->bComplete)) {
        return CL_SUCCESS;
    }

    fraction_loaded = (double)now_completed / (double)total_items;
    numDots         = round(fraction_loaded * totalNumDots);

    if (0 == sigloadProgress->startTime) {
        sigloadProgress->startTime = time(0);
    }
    curtime = time(0) - sigloadProgress->startTime;

    sigloadProgress->lastRunTime = curtime;

#ifndef _WIN32
    fprintf(stdout, "\e[?7l");
#endif
    if (fraction_loaded <= 0.0) {
        fprintf(stdout, "Loading:   ");
        print_time(curtime);
        fprintf(stdout, "               ");
    } else {
        remtime = (curtime / fraction_loaded) - curtime;
        fprintf(stdout, "Loading:   ");
        print_time(curtime);
        fprintf(stdout, ", ETA: ");
        print_time(remtime);
        fprintf(stdout, " ");
    }

    fprintf(stdout, "[");
    if (numDots > 0) {
        if (numDots > 1) {
            for (i = 0; i < numDots - 1; i++) {
                fprintf(stdout, "=");
            }
        }
        fprintf(stdout, ">");
        i++;
    }
    for (; i < totalNumDots; i++) {
        fprintf(stdout, " ");
    }

    fprintf(stdout, "] ");

    print_num_sigs(now_completed, 1);
    fprintf(stdout, "/");
    print_num_sigs(total_items, 0);
    fprintf(stdout, " sigs    ");

    if (now_completed < total_items) {
        fprintf(stdout, "\r");
    } else {
        fprintf(stdout, "\n");
        sigloadProgress->bComplete = 1;
    }
#ifndef _WIN32
    fprintf(stdout, "\e[?7h");
#endif
    fflush(stdout);

    return CL_SUCCESS;
}

/**
 * @brief Progress callback for sig-load
 *
 * @param total_items   Total number of items
 * @param now_completed Number of items completed
 * @param context       Opaque application provided data; This maps to engine_compile_progress
 */
static cl_error_t engine_compile_callback(size_t total_items, size_t now_completed, void *context)
{
    time_t curtime = 0;
    time_t remtime = 0;

    struct engine_compile_progress *engineCompileProgress = (struct engine_compile_progress *)context;

    uint32_t i               = 0;
    uint32_t totalNumDots    = 25;
    uint32_t numDots         = 0;
    double fraction_compiled = 0.0;

    if ((total_items <= 0) || (engineCompileProgress->bComplete)) {
        return CL_SUCCESS;
    }

    fraction_compiled = (double)now_completed / (double)total_items;
    numDots           = round(fraction_compiled * totalNumDots);

    if (0 == engineCompileProgress->startTime) {
        engineCompileProgress->startTime = time(0);
    }
    curtime = time(0) - engineCompileProgress->startTime;

    engineCompileProgress->lastRunTime = curtime;

#ifndef _WIN32
    fprintf(stdout, "\e[?7l");
#endif
    if (fraction_compiled <= 0.0) {
        fprintf(stdout, "Compiling: ");
        print_time(curtime);
        fprintf(stdout, "               ");
    } else {
        remtime = (curtime / fraction_compiled) - curtime;
        fprintf(stdout, "Compiling: ");
        print_time(curtime);
        fprintf(stdout, ", ETA: ");
        print_time(remtime);
        fprintf(stdout, " ");
    }

    fprintf(stdout, "[");
    if (numDots > 0) {
        if (numDots > 1) {
            for (i = 0; i < numDots - 1; i++) {
                fprintf(stdout, "=");
            }
        }
        fprintf(stdout, ">");
        i++;
    }
    for (; i < totalNumDots; i++) {
        fprintf(stdout, " ");
    }

    fprintf(stdout, "] ");

    print_num_sigs(now_completed, 1);
    fprintf(stdout, "/");
    print_num_sigs(total_items, 0);
    fprintf(stdout, " tasks ");

    if (now_completed < total_items) {
        fprintf(stdout, "\r");
    } else {
        fprintf(stdout, "\n");
        engineCompileProgress->bComplete = 1;
    }
#ifndef _WIN32
    fprintf(stdout, "\e[?7h");
#endif
    fflush(stdout);

    return CL_SUCCESS;
}

#ifdef ENABLE_ENGINE_FREE_PROGRESSBAR
/**
 * @brief Progress callback for sig-load
 *
 * @param total_items   Total number of items
 * @param now_completed Number of items completed
 * @param context       Opaque application provided data; This maps to engine_free_progress
 */
static cl_error_t engine_free_callback(size_t total_items, size_t now_completed, void *context)
{
    time_t curtime = 0;

    struct engine_free_progress *engineFreeProgress = (struct engine_free_progress *)context;

    uint32_t i            = 0;
    uint32_t totalNumDots = 10;
    uint32_t numDots      = 0;
    double fraction_freed = 0.0;

    if ((total_items <= 0) || (engineFreeProgress->bComplete)) {
        return CL_SUCCESS;
    }

    fraction_freed = (double)now_completed / (double)total_items;
    numDots        = round(fraction_freed * totalNumDots);

    if (0 == engineFreeProgress->startTime) {
        engineFreeProgress->startTime = time(0);
    }
    curtime = time(0) - engineFreeProgress->startTime;

    engineFreeProgress->lastRunTime = curtime;

#ifndef _WIN32
    fprintf(stdout, "\e[?7l");
#endif
    fprintf(stdout, "Unloading");

    if (numDots > 0) {
        if (numDots > 1) {
            for (i = 0; i < numDots - 1; i++) {
                fprintf(stdout, ".");
            }
        }
        i++;
    }
    for (; i < totalNumDots; i++) {
        fprintf(stdout, " ");
    }

    fprintf(stdout, " ");

    print_num_sigs(now_completed, 1);
    fprintf(stdout, "/");
    print_num_sigs(total_items, 0);
    fprintf(stdout, " tasks ");

    if (now_completed < total_items) {
        fprintf(stdout, "\r");
    } else {
        fprintf(stdout, "\n");
        engineFreeProgress->bComplete = 1;
    }
#ifndef _WIN32
    fprintf(stdout, "\e[?7h");
#endif
    fflush(stdout);

    return CL_SUCCESS;
}
#endif

#ifdef _WIN32
static int scan_memory(struct cl_engine *engine, const struct optstruct *opts, struct cl_scan_options *options)
{
    int ret = 0;
    struct mem_info minfo;

    minfo.d             = 0;
    minfo.files         = info.files;
    minfo.ifiles        = info.ifiles;
    minfo.bytes_scanned = info.bytes_scanned;
    minfo.engine        = engine;
    minfo.opts          = opts;
    minfo.options       = options;
    ret                 = scanmem(&minfo);

    info.files         = minfo.files;
    info.ifiles        = minfo.ifiles;
    info.bytes_scanned = minfo.bytes_scanned;

    return ret;
}
#endif

/**
 * @brief Scan the files from the --file-list option, or scan the files listed as individual arguments.
 *
 * If the user uses both --file-list <LISTFILE> AND one or more files, then clam will only
 * scan the files listed in the LISTFILE and emit a warning about not scanning the other file parameters.
 *
 * @param opts
 * @param options
 * @return int
 */
static int scan_files(struct cl_engine *engine, const struct optstruct *opts, struct cl_scan_options *options,
                      unsigned int dirlnk, unsigned int filelnk)
{
    int ret = 0;
    const char *filename;
    char *file;
    STATBUF sb;

    if (optget(opts, "file-list")->enabled && opts->filename) {
        logg(LOGG_WARNING, "Only scanning files from --file-list (files passed at cmdline are ignored)\n");
    }

#ifdef _WIN32
    /* scan first memory if requested */
    if (optget(opts, "memory")->enabled) {
        ret = scan_memory(engine, opts, options);
    }
#endif

    while ((filename = filelist(opts, &ret)) && (file = strdup(filename))) {
        if (!strcmp(file, "-")) {
            /* scan data from stdin */
            ret = scanstdin(engine, opts, options);
        } else if (LSTAT(file, &sb) == -1) {
            /* Can't access the file */
            perror(file);
            logg(LOGG_WARNING, "%s: Can't access file\n", file);
            ret = 2;
        } else {
            /* Can access the file. Now have to identify what type of file it is */
            int i;
            for (i = strlen(file) - 1; i > 0; i--) {
                if (file[i] == *PATHSEP) {
                    file[i] = 0;
                } else {
                    break;
                }
            }

            if (S_ISLNK(sb.st_mode)) {
                /* found a link */
                if (dirlnk == 0 && filelnk == 0) {
                    /* don't follow links */
                    if (!printinfected) {
                        logg(LOGG_INFO, "%s: Symbolic link\n", file);
                    }
                } else if (CLAMSTAT(file, &sb) != -1) {
                    /* maybe follow links */
                    if (S_ISREG(sb.st_mode) && filelnk) {
                        /* follow file links */
                        scanfile(file, engine, opts, options);
                    } else if (S_ISDIR(sb.st_mode) && dirlnk) {
                        /* follow directory links */
                        scandirs(file, engine, opts, options, 1, sb.st_dev);
                    } else {
                        if (!printinfected) {
                            logg(LOGG_INFO, "%s: Symbolic link\n", file);
                        }
                    }
                }
            } else if (S_ISREG(sb.st_mode)) {
                /* Found a file, scan it. */
                scanfile(file, engine, opts, options);
            } else if (S_ISDIR(sb.st_mode)) {
                /* Found a directory, scan it. */
                scandirs(file, engine, opts, options, 1, sb.st_dev);
            } else {
                logg(LOGG_WARNING, "%s: Not supported file type\n", file);
                ret = 2;
            }
        }

        free(file);
    }

    return ret;
}

int scanmanager(const struct optstruct *opts)
{
    int ret = 0;
    int i;
    struct cl_scan_options options;
    unsigned int dboptions = 0, dirlnk = 1, filelnk = 1;
    struct cl_engine *engine = NULL;
    STATBUF sb;
    char *pua_cats = NULL;
    const struct optstruct *opt;
#ifndef _WIN32
    struct rlimit rlim;
#endif
    struct sigload_progress sigload_progress_ctx               = {0};
    struct engine_compile_progress engine_compile_progress_ctx = {0};
#ifdef ENABLE_ENGINE_FREE_PROGRESSBAR
    struct engine_free_progress engine_free_progress_ctx = {0};
#endif

    char *cvdcertsdir = NULL;
    STATBUF statbuf;

    /* Initialize scan options struct */
    memset(&options, 0, sizeof(struct cl_scan_options));

    dirlnk = optget(opts, "follow-dir-symlinks")->numarg;
    if (dirlnk > 2) {
        logg(LOGG_ERROR, "--follow-dir-symlinks: Invalid argument\n");
        ret = 2;
        goto done;
    }

    filelnk = optget(opts, "follow-file-symlinks")->numarg;
    if (filelnk > 2) {
        logg(LOGG_ERROR, "--follow-file-symlinks: Invalid argument\n");
        ret = 2;
        goto done;
    }

    if (optget(opts, "yara-rules")->enabled) {
        char *p = optget(opts, "yara-rules")->strarg;
        if (strcmp(p, "yes")) {
            if (!strcmp(p, "only"))
                dboptions |= CL_DB_YARA_ONLY;
            else if (!strcmp(p, "no"))
                dboptions |= CL_DB_YARA_EXCLUDE;
        }
    }

    if (optget(opts, "phishing-sigs")->enabled)
        dboptions |= CL_DB_PHISHING;

    if (optget(opts, "official-db-only")->enabled)
        dboptions |= CL_DB_OFFICIAL_ONLY;

    if (optget(opts, "phishing-scan-urls")->enabled)
        dboptions |= CL_DB_PHISHING_URLS;

    if (optget(opts, "bytecode")->enabled)
        dboptions |= CL_DB_BYTECODE;

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

    cl_engine_set_clcb_virus_found(engine, clamscan_virus_found_cb);

    if (isatty(fileno(stdout)) &&
        !optget(opts, "debug")->enabled &&
        !optget(opts, "quiet")->enabled &&
        !optget(opts, "infected")->enabled &&
        !optget(opts, "no-summary")->enabled) {
        /* set progress callbacks */
        cl_engine_set_clcb_sigload_progress(engine, sigload_callback, &sigload_progress_ctx);
        cl_engine_set_clcb_engine_compile_progress(engine, engine_compile_callback, &engine_compile_progress_ctx);
#ifdef ENABLE_ENGINE_FREE_PROGRESSBAR
        cl_engine_set_clcb_engine_free_progress(engine, engine_free_callback, &engine_free_progress_ctx);
#endif
    }

    if ((opt = optget(opts, "cache-size"))->enabled)
        cl_engine_set_num(engine, CL_ENGINE_CACHE_SIZE, opt->numarg);
    if (optget(opts, "disable-cache")->enabled)
        cl_engine_set_num(engine, CL_ENGINE_DISABLE_CACHE, 1);

    if (optget(opts, "detect-pua")->enabled) {
        dboptions |= CL_DB_PUA;
        if ((opt = optget(opts, "exclude-pua"))->enabled) {
            dboptions |= CL_DB_PUA_EXCLUDE;
            i = 0;
            while (opt) {
                if (!(pua_cats = realloc(pua_cats, i + strlen(opt->strarg) + 3))) {
                    logg(LOGG_ERROR, "Can't allocate memory for pua_cats\n");

                    ret = 2;
                    goto done;
                }

                sprintf(pua_cats + i, ".%s", opt->strarg);
                i += strlen(opt->strarg) + 1;
                pua_cats[i] = 0;

                opt = opt->nextarg;
            }
            pua_cats[i]     = '.';
            pua_cats[i + 1] = 0;
        }

        if ((opt = optget(opts, "include-pua"))->enabled) {
            if (pua_cats) {
                logg(LOGG_ERROR, "--exclude-pua and --include-pua cannot be used at the same time\n");

                free(pua_cats);
                ret = 2;
                goto done;
            }

            dboptions |= CL_DB_PUA_INCLUDE;
            i = 0;
            while (opt) {
                if (!(pua_cats = realloc(pua_cats, i + strlen(opt->strarg) + 3))) {
                    logg(LOGG_ERROR, "Can't allocate memory for pua_cats\n");
                    ret = 2;
                    goto done;
                }

                sprintf(pua_cats + i, ".%s", opt->strarg);
                i += strlen(opt->strarg) + 1;
                pua_cats[i] = 0;

                opt = opt->nextarg;
            }

            pua_cats[i]     = '.';
            pua_cats[i + 1] = 0;
        }

        if (pua_cats) {
            if ((ret = cl_engine_set_str(engine, CL_ENGINE_PUA_CATEGORIES, pua_cats))) {
                logg(LOGG_ERROR, "cli_engine_set_str(CL_ENGINE_PUA_CATEGORIES) failed: %s\n", cl_strerror(ret));

                free(pua_cats);
                ret = 2;
                goto done;
            }

            free(pua_cats);
        }
    }

    if (optget(opts, "dev-ac-only")->enabled)
        cl_engine_set_num(engine, CL_ENGINE_AC_ONLY, 1);

    if (optget(opts, "dev-ac-depth")->enabled)
        cl_engine_set_num(engine, CL_ENGINE_AC_MAXDEPTH, optget(opts, "dev-ac-depth")->numarg);

    if (optget(opts, "leave-temps")->enabled) {
        /* Set the engine to keep temporary files */
        cl_engine_set_num(engine, CL_ENGINE_KEEPTMP, 1);
        /* Also set the engine to create temporary directory structure */
        cl_engine_set_num(engine, CL_ENGINE_TMPDIR_RECURSION, 1);
    }

    if (optget(opts, "force-to-disk")->enabled)
        cl_engine_set_num(engine, CL_ENGINE_FORCETODISK, 1);

    if (optget(opts, "bytecode-unsigned")->enabled)
        dboptions |= CL_DB_BYTECODE_UNSIGNED;

    if ((opt = optget(opts, "bytecode-timeout"))->enabled)
        cl_engine_set_num(engine, CL_ENGINE_BYTECODE_TIMEOUT, opt->numarg);

    if (optget(opts, "nocerts")->enabled)
        cl_engine_set_num(engine, CL_ENGINE_DISABLE_PE_CERTS, 1);

    if (optget(opts, "dumpcerts")->enabled)
        cl_engine_set_num(engine, CL_ENGINE_PE_DUMPCERTS, 1);

    if ((opt = optget(opts, "bytecode-mode"))->enabled) {
        enum bytecode_mode mode;

        if (!strcmp(opt->strarg, "ForceJIT"))
            mode = CL_BYTECODE_MODE_JIT;
        else if (!strcmp(opt->strarg, "ForceInterpreter"))
            mode = CL_BYTECODE_MODE_INTERPRETER;
        else if (!strcmp(opt->strarg, "Test"))
            mode = CL_BYTECODE_MODE_TEST;
        else
            mode = CL_BYTECODE_MODE_AUTO;

        cl_engine_set_num(engine, CL_ENGINE_BYTECODE_MODE, mode);
    }

    if ((opt = optget(opts, "statistics"))->enabled) {
        while (opt) {
            if (!strcasecmp(opt->strarg, "bytecode")) {
                dboptions |= CL_DB_BYTECODE_STATS;
            } else if (!strcasecmp(opt->strarg, "pcre")) {
                dboptions |= CL_DB_PCRE_STATS;
            }
            opt = opt->nextarg;
        }
    }

    if (optget(opts, "fips-limits")->enabled) {
        dboptions |= CL_DB_FIPS_LIMITS;
        cl_engine_set_num(engine, CL_ENGINE_FIPS_LIMITS, 1);
    }

    if (optget(opts, "gen-json")->enabled) {
        options.general |= CL_SCAN_GENERAL_COLLECT_METADATA;
    }

    if (optget(opts, "json-store-html-uris")->enabled) {
        options.general |= CL_SCAN_GENERAL_STORE_HTML_URIS;
    }

    if (optget(opts, "json-store-pdf-uris")->enabled) {
        options.general |= CL_SCAN_GENERAL_STORE_PDF_URIS;
    }

    if (optget(opts, "json-store-extra-hashes")->enabled) {
        options.general |= CL_SCAN_GENERAL_STORE_EXTRA_HASHES;
    }

    if ((opt = optget(opts, "tempdir"))->enabled) {
        if ((ret = cl_engine_set_str(engine, CL_ENGINE_TMPDIR, opt->strarg))) {
            logg(LOGG_ERROR, "cli_engine_set_str(CL_ENGINE_TMPDIR) failed: %s\n", cl_strerror(ret));

            ret = 2;
            goto done;
        }
    }

    cvdcertsdir = optget(opts, "cvdcertsdir")->strarg;
    if (NULL != cvdcertsdir) {
        // Command line option must override the engine defaults
        // (which would've used the env var or hardcoded path)
        if (LSTAT(cvdcertsdir, &statbuf) == -1) {
            logg(LOGG_ERROR,
                 "ClamAV CA certificates directory is missing: %s"
                 " - It should have been provided as a part of installation.\n",
                 cvdcertsdir);
            ret = 2;
            goto done;
        }

        if ((ret = cl_engine_set_str(engine, CL_ENGINE_CVDCERTSDIR, cvdcertsdir))) {
            logg(LOGG_ERROR, "cli_engine_set_str(CL_ENGINE_CVDCERTSDIR) failed: %s\n", cl_strerror(ret));
            ret = 2;
            goto done;
        }
    }

    if ((opt = optget(opts, "database"))->active) {
        while (opt) {
            if (optget(opts, "fail-if-cvd-older-than")->enabled) {
                if (LSTAT(opt->strarg, &sb) == -1) {
                    logg(LOGG_ERROR, "Can't access database directory/file: %s\n", opt->strarg);
                    ret = 2;
                    goto done;
                }
                if (!S_ISDIR(sb.st_mode) && !CLI_DBEXT_SIGNATURE(opt->strarg)) {
                    opt = opt->nextarg;
                    continue;
                }
                if (check_if_cvd_outdated(opt->strarg, optget(opts, "fail-if-cvd-older-than")->numarg) != CL_SUCCESS) {
                    ret = 2;
                    goto done;
                }
            }

            if ((ret = cl_load(opt->strarg, engine, &info.sigs, dboptions))) {
                logg(LOGG_ERROR, "%s\n", cl_strerror(ret));

                ret = 2;
                goto done;
            }

            opt = opt->nextarg;
        }
    } else {
        char *dbdir = freshdbdir();

        if (optget(opts, "fail-if-cvd-older-than")->enabled) {
            if (check_if_cvd_outdated(dbdir, optget(opts, "fail-if-cvd-older-than")->numarg) != CL_SUCCESS) {
                ret = 2;
                goto done;
            }
        }

        if ((ret = cl_load(dbdir, engine, &info.sigs, dboptions))) {
            logg(LOGG_ERROR, "%s\n", cl_strerror(ret));

            free(dbdir);
            ret = 2;
            goto done;
        }

        free(dbdir);
    }

    /* pcre engine limits - required for cl_engine_compile */
    if ((opt = optget(opts, "pcre-match-limit"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_PCRE_MATCH_LIMIT, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(CL_ENGINE_PCRE_MATCH_LIMIT) failed: %s\n", cl_strerror(ret));
            ret = 2;
            goto done;
        }
    }

    if ((opt = optget(opts, "pcre-recmatch-limit"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_PCRE_RECMATCH_LIMIT, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(CL_ENGINE_PCRE_RECMATCH_LIMIT) failed: %s\n", cl_strerror(ret));
            ret = 2;
            goto done;
        }
    }

    if ((ret = cl_engine_compile(engine)) != 0) {
        logg(LOGG_ERROR, "Database initialization error: %s\n", cl_strerror(ret));
        ret = 2;
        goto done;
    }

    if (isatty(fileno(stdout)) &&
        !optget(opts, "debug")->enabled &&
        !optget(opts, "quiet")->enabled &&
        !optget(opts, "infected")->enabled &&
        !optget(opts, "no-summary")->enabled) {
        /* For a space after the progress bars */
        logg(LOGG_INFO, "\n");
    }

    if (optget(opts, "archive-verbose")->enabled) {
        cl_engine_set_clcb_meta(engine, meta);
        cl_engine_set_clcb_pre_cache(engine, pre);
        cl_engine_set_clcb_post_scan(engine, post);
    }

    /* set limits */

    /* TODO: Remove deprecated option in a future feature release */
    if ((opt = optget(opts, "timelimit"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_SCANTIME, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(CL_ENGINE_MAX_SCANTIME) failed: %s\n", cl_strerror(ret));
            ret = 2;
            goto done;
        }
    }
    if ((opt = optget(opts, "max-scantime"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_SCANTIME, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(CL_ENGINE_MAX_SCANTIME) failed: %s\n", cl_strerror(ret));
            ret = 2;
            goto done;
        }
    }

    if ((opt = optget(opts, "max-scansize"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_SCANSIZE, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(CL_ENGINE_MAX_SCANSIZE) failed: %s\n", cl_strerror(ret));
            ret = 2;
            goto done;
        }
    }

    if ((opt = optget(opts, "max-filesize"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_FILESIZE, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(CL_ENGINE_MAX_FILESIZE) failed: %s\n", cl_strerror(ret));
            ret = 2;
            goto done;
        }
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

    if ((opt = optget(opts, "max-files"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_FILES, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(CL_ENGINE_MAX_FILES) failed: %s\n", cl_strerror(ret));
            ret = 2;
            goto done;
        }
    }

    if ((opt = optget(opts, "max-recursion"))->active) {
        uint32_t opt_value = opt->numarg;
        if ((0 == opt_value) || (opt_value > CLI_MAX_MAXRECLEVEL)) {
            logg(LOGG_ERROR, "max-recursion set to %u, but  cannot be larger than %u, and cannot be 0.\n",
                 opt_value, CLI_MAX_MAXRECLEVEL);
            ret = 2;
            goto done;
        }
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_RECURSION, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(CL_ENGINE_MAX_RECURSION) failed: %s\n", cl_strerror(ret));
            ret = 2;
            goto done;
        }
    }

    /* Engine max sizes */

    if ((opt = optget(opts, "max-embeddedpe"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_EMBEDDEDPE, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(CL_ENGINE_MAX_EMBEDDEDPE) failed: %s\n", cl_strerror(ret));
            ret = 2;
            goto done;
        }
    }

    if ((opt = optget(opts, "max-htmlnormalize"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_HTMLNORMALIZE, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(CL_ENGINE_MAX_HTMLNORMALIZE) failed: %s\n", cl_strerror(ret));
            ret = 2;
            goto done;
        }
    }

    if ((opt = optget(opts, "max-htmlnotags"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_HTMLNOTAGS, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(CL_ENGINE_MAX_HTMLNOTAGS) failed: %s\n", cl_strerror(ret));
            ret = 2;
            goto done;
        }
    }

    if ((opt = optget(opts, "max-scriptnormalize"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_SCRIPTNORMALIZE, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(CL_ENGINE_MAX_SCRIPTNORMALIZE) failed: %s\n", cl_strerror(ret));
            ret = 2;
            goto done;
        }
    }

    if ((opt = optget(opts, "max-ziptypercg"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_ZIPTYPERCG, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(CL_ENGINE_MAX_ZIPTYPERCG) failed: %s\n", cl_strerror(ret));
            ret = 2;
            goto done;
        }
    }

    if ((opt = optget(opts, "max-partitions"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_PARTITIONS, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(CL_ENGINE_MAX_PARTITIONS) failed: %s\n", cl_strerror(ret));
            ret = 2;
            goto done;
        }
    }

    if ((opt = optget(opts, "max-iconspe"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_ICONSPE, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(CL_ENGINE_MAX_ICONSPE) failed: %s\n", cl_strerror(ret));
            ret = 2;
            goto done;
        }
    }

    if ((opt = optget(opts, "max-rechwp3"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_MAX_RECHWP3, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(CL_ENGINE_MAX_RECHWP3) failed: %s\n", cl_strerror(ret));
            ret = 2;
            goto done;
        }
    }

    if ((opt = optget(opts, "pcre-max-filesize"))->active) {
        if ((ret = cl_engine_set_num(engine, CL_ENGINE_PCRE_MAX_FILESIZE, opt->numarg))) {
            logg(LOGG_ERROR, "cli_engine_set_num(CL_ENGINE_PCRE_MAX_FILESIZE) failed: %s\n", cl_strerror(ret));
            ret = 2;
            goto done;
        }
    }

    /* set scan options */
    if (optget(opts, "allmatch")->enabled) {
        options.general |= CL_SCAN_GENERAL_ALLMATCHES;
    }

    /* TODO: Remove deprecated option in a future feature release */
    if ((optget(opts, "phishing-ssl")->enabled) ||
        (optget(opts, "alert-phishing-ssl")->enabled))
        options.heuristic |= CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH;

    /* TODO: Remove deprecated option in a future feature release */
    if ((optget(opts, "phishing-cloak")->enabled) ||
        (optget(opts, "alert-phishing-cloak")->enabled))
        options.heuristic |= CL_SCAN_HEURISTIC_PHISHING_CLOAK;

    /* TODO: Remove deprecated option in a future feature release */
    if ((optget(opts, "partition-intersection")->enabled) ||
        (optget(opts, "alert-partition-intersection")->enabled))
        options.heuristic |= CL_SCAN_HEURISTIC_PARTITION_INTXN;

    if (optget(opts, "heuristic-scan-precedence")->enabled)
        options.general |= CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE;

    if (optget(opts, "scan-archive")->enabled)
        options.parse |= CL_SCAN_PARSE_ARCHIVE;

    /* TODO: Remove deprecated option in a future feature release */
    if ((optget(opts, "detect-broken")->enabled) ||
        (optget(opts, "alert-broken")->enabled)) {
        options.heuristic |= CL_SCAN_HEURISTIC_BROKEN;
    }

    if (optget(opts, "alert-broken-media")->enabled) {
        options.heuristic |= CL_SCAN_HEURISTIC_BROKEN_MEDIA;
    }

    /* TODO: Remove deprecated option in a future feature release */
    if ((optget(opts, "block-encrypted")->enabled) ||
        (optget(opts, "alert-encrypted")->enabled)) {
        options.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE;
        options.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_DOC;
    }

    if (optget(opts, "alert-encrypted-archive")->enabled)
        options.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE;

    if (optget(opts, "alert-encrypted-doc")->enabled)
        options.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_DOC;

    /* TODO: Remove deprecated option in a future feature release */
    if ((optget(opts, "block-macros")->enabled) ||
        (optget(opts, "alert-macros")->enabled)) {
        options.heuristic |= CL_SCAN_HEURISTIC_MACROS;
    }

    if (optget(opts, "scan-pe")->enabled)
        options.parse |= CL_SCAN_PARSE_PE;

    if (optget(opts, "scan-elf")->enabled)
        options.parse |= CL_SCAN_PARSE_ELF;

    if (optget(opts, "scan-ole2")->enabled)
        options.parse |= CL_SCAN_PARSE_OLE2;

    if (optget(opts, "scan-pdf")->enabled)
        options.parse |= CL_SCAN_PARSE_PDF;

    if (optget(opts, "scan-swf")->enabled)
        options.parse |= CL_SCAN_PARSE_SWF;

    if (optget(opts, "scan-html")->enabled && optget(opts, "normalize")->enabled)
        options.parse |= CL_SCAN_PARSE_HTML;

    if (optget(opts, "scan-mail")->enabled)
        options.parse |= CL_SCAN_PARSE_MAIL;

    if (optget(opts, "scan-xmldocs")->enabled)
        options.parse |= CL_SCAN_PARSE_XMLDOCS;

    if (optget(opts, "scan-hwp3")->enabled)
        options.parse |= CL_SCAN_PARSE_HWP3;

    if (optget(opts, "scan-onenote")->enabled)
        options.parse |= CL_SCAN_PARSE_ONENOTE;

    if (optget(opts, "scan-image")->enabled)
        options.parse |= CL_SCAN_PARSE_IMAGE;

    if (optget(opts, "scan-image-fuzzy-hash")->enabled)
        options.parse |= CL_SCAN_PARSE_IMAGE_FUZZY_HASH;

    /* TODO: Remove deprecated option in a future feature release */
    if ((optget(opts, "algorithmic-detection")->enabled) && /* && used due to default-yes for both options */
        (optget(opts, "heuristic-alerts")->enabled)) {
        options.general |= CL_SCAN_GENERAL_HEURISTICS;
    }

    /* TODO: Remove deprecated option in a future feature release */
    if ((optget(opts, "block-max")->enabled) ||
        (optget(opts, "alert-exceeds-max")->enabled)) {
        options.heuristic |= CL_SCAN_HEURISTIC_EXCEEDS_MAX;
    }

    if (optget(opts, "dev-performance")->enabled)
        options.dev |= CL_SCAN_DEV_COLLECT_PERFORMANCE_INFO;

    if (optget(opts, "detect-structured")->enabled) {
        options.heuristic |= CL_SCAN_HEURISTIC_STRUCTURED;

        if ((opt = optget(opts, "structured-ssn-format"))->enabled) {
            switch (opt->numarg) {
                case 0:
                    options.heuristic |= CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL;
                    break;
                case 1:
                    options.heuristic |= CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED;
                    break;
                case 2:
                    options.heuristic |= (CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL | CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED);
                    break;
                default:
                    logg(LOGG_ERROR, "Invalid argument for --structured-ssn-format\n");
                    ret = 2;
                    goto done;
            }
        } else {
            options.heuristic |= CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL;
        }

        if ((opt = optget(opts, "structured-ssn-count"))->active) {
            if ((ret = cl_engine_set_num(engine, CL_ENGINE_MIN_SSN_COUNT, opt->numarg))) {
                logg(LOGG_ERROR, "cli_engine_set_num(CL_ENGINE_MIN_SSN_COUNT) failed: %s\n", cl_strerror(ret));
                ret = 2;
                goto done;
            }
        }

        if ((opt = optget(opts, "structured-cc-count"))->active) {
            if ((ret = cl_engine_set_num(engine, CL_ENGINE_MIN_CC_COUNT, opt->numarg))) {
                logg(LOGG_ERROR, "cli_engine_set_num(CL_ENGINE_MIN_CC_COUNT) failed: %s\n", cl_strerror(ret));
                ret = 2;
                goto done;
            }
        }

        if ((opt = optget(opts, "structured-cc-mode"))->active) {
            switch (opt->numarg) {
                case 0:
                    break;
                case 1:
                    options.heuristic |= CL_SCAN_HEURISTIC_STRUCTURED_CC;
                    break;
                default:
                    logg(LOGG_ERROR, "Invalid argument for --structured-cc-mode\n");
                    ret = 2;
                    goto done;
            }
        }
    } else {
        options.heuristic &= ~CL_SCAN_HEURISTIC_STRUCTURED;
    }

#ifdef C_LINUX
    procdev = (dev_t)0;
    if (CLAMSTAT("/proc", &sb) != -1 && !sb.st_size) {
        procdev = sb.st_dev;
    }
#endif

    if (optget(opts, "file-list")->enabled || opts->filename) {
        /* scan the files listed in the --file-list, or it that's not specified, then
         * scan the list of file arguments (including data from stdin, if `-` specified) */
        ret = scan_files(engine, opts, &options, dirlnk, filelnk);

#ifdef _WIN32
    } else if (optget(opts, "memory")->enabled) {
        /* scan only memory */
        ret = scan_memory(engine, opts, &options);

#endif
    } else {
        /* No list of files provided to scan, and no request to scan memory,
         * so just scan the current directory. */
        char cwd[1024];

        /* Get the current working directory.
         * we need full path for some reasons (eg. archive handling) */
        if (!getcwd(cwd, sizeof(cwd))) {
            logg(LOGG_ERROR, "Can't get absolute pathname of current working directory\n");
            ret = 2;
        } else {
            CLAMSTAT(cwd, &sb);
            scandirs(cwd, engine, opts, &options, 1, sb.st_dev);
        }
    }

    if ((opt = optget(opts, "statistics"))->enabled) {
        while (opt) {
            if (!strcasecmp(opt->strarg, "bytecode")) {
                cli_sigperf_print();
                cli_sigperf_events_destroy();
            } else if (!strcasecmp(opt->strarg, "pcre")) {
                cli_pcre_perf_print();
                cli_pcre_perf_events_destroy();
            }

            opt = opt->nextarg;
        }
    }

done:
    /* free the engine */
    cl_engine_free(engine);

    /* overwrite return code - infection takes priority */
    if (info.ifiles)
        ret = 1;
    else if (info.errors)
        ret = 2;

    return ret;
}
