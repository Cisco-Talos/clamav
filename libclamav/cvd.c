/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
 *
 *  Summary: Code to parse Clamav CVD database format.
 *
 *  Acknowledgements: ClamAV untar code is based on a public domain minitar utility
 *                    by Charles G. Waldman.
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
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include "zlib.h"
#include <time.h>
#include <errno.h>
#include <openssl/crypto.h>

#include "clamav.h"
#include "clamav_rust.h"
#include "others.h"
#include "dsig.h"
#include "str.h"
#include "cvd.h"
#include "readdb.h"
#include "default.h"

#define TAR_BLOCKSIZE 512

static void cli_tgzload_cleanup(int comp, struct cli_dbio *dbio, int fdd)
{
    UNUSEDPARAM(fdd);
    cli_dbgmsg("in cli_tgzload_cleanup()\n");
    if (comp) {
        gzclose(dbio->gzs);
        dbio->gzs = NULL;
    } else {
        fclose(dbio->fs);
        dbio->fs = NULL;
    }
    if (dbio->buf != NULL) {
        free(dbio->buf);
        dbio->buf = NULL;
    }

    if (dbio->hashctx) {
        cl_hash_destroy(dbio->hashctx);
        dbio->hashctx = NULL;
    }
}

static int cli_tgzload(cvd_t *cvd, struct cl_engine *engine, unsigned int *signo, unsigned int options, struct cli_dbio *dbio, struct cli_dbinfo *dbinfo, void *sign_verifier)
{
    char osize[13], name[101];
    char block[TAR_BLOCKSIZE];
    int nread, fdd, ret;
    unsigned int type, size, pad, compr = 1;
    off_t off;
    struct cli_dbinfo *db;
    char hash[32];
    int fd = -1;
#ifdef _WIN32
    HANDLE hFile;
#endif

    cli_dbgmsg("in cli_tgzload()\n");

#ifdef _WIN32
    // For windows, first get the file handle from the cvd_t object
    hFile = cvd_get_file_handle(cvd);
    if (hFile == INVALID_HANDLE_VALUE) {
        return CL_EOPEN;
    }

    // Then get the file descriptor from the file handle
    fd = _open_osfhandle((intptr_t)hFile, _O_RDONLY);
    if (fd == -1) {
        return CL_EOPEN;
    }
#else
    // For non-windows, get the file descriptor directly from the cvd_t object
    fd = cvd_get_file_descriptor(cvd);
    if (fd == -1) {
        return CL_EOPEN;
    }
#endif

    if (lseek(fd, 512, SEEK_SET) < 0) {
        return CL_ESEEK;
    }

    if (cli_readn(fd, block, 7) != 7)
        return CL_EFORMAT; /* truncated file? */

    if (!strncmp(block, "COPYING", 7))
        compr = 0;

    if (lseek(fd, 512, SEEK_SET) < 0) {
        return CL_ESEEK;
    }

    if ((fdd = dup(fd)) == -1) {
        cli_errmsg("cli_tgzload: Can't duplicate descriptor %d\n", fd);
        return CL_EDUP;
    }

    if (compr) {
        if ((dbio->gzs = gzdopen(fdd, "rb")) == NULL) {
            cli_errmsg("cli_tgzload: Can't gzdopen() descriptor %d, errno = %d\n", fdd, errno);
            if (fdd > -1)
                close(fdd);
            return CL_EOPEN;
        }
        dbio->fs = NULL;
    } else {
        if ((dbio->fs = fdopen(fdd, "rb")) == NULL) {
            cli_errmsg("cli_tgzload: Can't fdopen() descriptor %d, errno = %d\n", fdd, errno);
            if (fdd > -1)
                close(fdd);
            return CL_EOPEN;
        }
        dbio->gzs = NULL;
    }

    dbio->bufsize = CLI_DEFAULT_DBIO_BUFSIZE;
    dbio->buf     = malloc(dbio->bufsize);
    if (!dbio->buf) {
        cli_errmsg("cli_tgzload: Can't allocate memory for dbio->buf\n");
        cli_tgzload_cleanup(compr, dbio, fdd);
        return CL_EMALFDB;
    }
    dbio->bufpt  = NULL;
    dbio->usebuf = 1;
    dbio->readpt = dbio->buf;

    while (1) {

        if (compr)
            nread = gzread(dbio->gzs, block, TAR_BLOCKSIZE);
        else
            nread = fread(block, 1, TAR_BLOCKSIZE, dbio->fs);

        if (!nread)
            break;

        if (nread != TAR_BLOCKSIZE) {
            cli_errmsg("cli_tgzload: Incomplete block read\n");
            cli_tgzload_cleanup(compr, dbio, fdd);
            return CL_EMALFDB;
        }

        if (block[0] == '\0') /* We're done */
            break;

        strncpy(name, block, 100);
        name[100] = '\0';

        if (strchr(name, '/')) {
            cli_errmsg("cli_tgzload: Slash separators are not allowed in CVD\n");
            cli_tgzload_cleanup(compr, dbio, fdd);
            return CL_EMALFDB;
        }

        type = block[156];

        switch (type) {
            case '0':
            case '\0':
                break;
            case '5':
                cli_errmsg("cli_tgzload: Directories are not supported in CVD\n");
                cli_tgzload_cleanup(compr, dbio, fdd);
                return CL_EMALFDB;
            default:
                cli_errmsg("cli_tgzload: Unknown type flag '%c'\n", type);
                cli_tgzload_cleanup(compr, dbio, fdd);
                return CL_EMALFDB;
        }

        strncpy(osize, block + 124, 12);
        osize[12] = '\0';

        if ((sscanf(osize, "%o", &size)) == 0) {
            cli_errmsg("cli_tgzload: Invalid size in header\n");
            cli_tgzload_cleanup(compr, dbio, fdd);
            return CL_EMALFDB;
        }
        dbio->size     = size;
        dbio->readsize = dbio->size < dbio->bufsize ? dbio->size : dbio->bufsize - 1;
        dbio->bufpt    = NULL;
        dbio->readpt   = dbio->buf;
        if (!(dbio->hashctx)) {
            dbio->hashctx = cl_hash_init("sha2-256");
            if (!(dbio->hashctx)) {
                cli_tgzload_cleanup(compr, dbio, fdd);
                return CL_EMALFDB;
            }
        }
        dbio->bread = 0;

        /* cli_dbgmsg("cli_tgzload: Loading %s, size: %u\n", name, size); */
        if (compr)
            off = (off_t)gzseek(dbio->gzs, 0, SEEK_CUR);
        else
            off = ftell(dbio->fs);

        if ((!dbinfo && cli_strbcasestr(name, ".info")) || (dbinfo && CLI_DBEXT(name))) {
            ret = cli_load(name, engine, signo, options, dbio, sign_verifier);
            if (ret) {
                cli_errmsg("cli_tgzload: Can't load %s\n", name);
                cli_tgzload_cleanup(compr, dbio, fdd);
                return CL_EMALFDB;
            }
            if (!dbinfo) {
                cli_tgzload_cleanup(compr, dbio, fdd);
                return CL_SUCCESS;
            } else {
                db = dbinfo;
                while (db && strcmp(db->name, name))
                    db = db->next;
                if (!db) {
                    cli_errmsg("cli_tgzload: File %s not found in .info\n", name);
                    cli_tgzload_cleanup(compr, dbio, fdd);
                    return CL_EMALFDB;
                }
                if (dbio->bread) {
                    if (db->size != dbio->bread) {
                        cli_errmsg("cli_tgzload: File %s not correctly loaded\n", name);
                        cli_tgzload_cleanup(compr, dbio, fdd);
                        return CL_EMALFDB;
                    }
                    cl_finish_hash(dbio->hashctx, hash);
                    dbio->hashctx = cl_hash_init("sha2-256");
                    if (!(dbio->hashctx)) {
                        cli_tgzload_cleanup(compr, dbio, fdd);
                        return CL_EMALFDB;
                    }
                    if (memcmp(db->hash, hash, 32)) {
                        cli_errmsg("cli_tgzload: Invalid checksum for file %s\n", name);
                        cli_tgzload_cleanup(compr, dbio, fdd);
                        return CL_EMALFDB;
                    }
                }
            }
        }
        pad = size % TAR_BLOCKSIZE ? (TAR_BLOCKSIZE - (size % TAR_BLOCKSIZE)) : 0;
        if (compr) {
            if (off == gzseek(dbio->gzs, 0, SEEK_CUR))
                gzseek(dbio->gzs, size + pad, SEEK_CUR);
            else if (pad)
                gzseek(dbio->gzs, pad, SEEK_CUR);
        } else {
            if (off == ftell(dbio->fs))
                fseek(dbio->fs, size + pad, SEEK_CUR);
            else if (pad)
                fseek(dbio->fs, pad, SEEK_CUR);
        }
    }

    cli_tgzload_cleanup(compr, dbio, fdd);
    return CL_SUCCESS;
}

struct cl_cvd *cl_cvdparse(const char *head)
{
    struct cl_cvd *cvd;
    char *pt;

    if (strncmp(head, "ClamAV-VDB:", 11)) {
        cli_errmsg("cli_cvdparse: Not a CVD file\n");
        return NULL;
    }

    if (!(cvd = (struct cl_cvd *)malloc(sizeof(struct cl_cvd)))) {
        cli_errmsg("cl_cvdparse: Can't allocate memory for cvd\n");
        return NULL;
    }

    if (!(cvd->time = cli_strtok(head, 1, ":"))) {
        cli_errmsg("cli_cvdparse: Can't parse the creation time\n");
        free(cvd);
        return NULL;
    }

    if (!(pt = cli_strtok(head, 2, ":"))) {
        cli_errmsg("cli_cvdparse: Can't parse the version number\n");
        free(cvd->time);
        free(cvd);
        return NULL;
    }
    cvd->version = atoi(pt);
    free(pt);

    if (!(pt = cli_strtok(head, 3, ":"))) {
        cli_errmsg("cli_cvdparse: Can't parse the number of signatures\n");
        free(cvd->time);
        free(cvd);
        return NULL;
    }
    cvd->sigs = atoi(pt);
    free(pt);

    if (!(pt = cli_strtok(head, 4, ":"))) {
        cli_errmsg("cli_cvdparse: Can't parse the functionality level\n");
        free(cvd->time);
        free(cvd);
        return NULL;
    }
    cvd->fl = atoi(pt);
    free(pt);

    if (!(cvd->md5 = cli_strtok(head, 5, ":"))) {
        cli_errmsg("cli_cvdparse: Can't parse the MD5 checksum\n");
        free(cvd->time);
        free(cvd);
        return NULL;
    }

    if (!(cvd->dsig = cli_strtok(head, 6, ":"))) {
        cli_errmsg("cli_cvdparse: Can't parse the digital signature\n");
        free(cvd->time);
        free(cvd->md5);
        free(cvd);
        return NULL;
    }

    if (!(cvd->builder = cli_strtok(head, 7, ":"))) {
        cli_errmsg("cli_cvdparse: Can't parse the builder name\n");
        free(cvd->time);
        free(cvd->md5);
        free(cvd->dsig);
        free(cvd);
        return NULL;
    }

    if ((pt = cli_strtok(head, 8, ":"))) {
        cvd->stime = atoi(pt);
        free(pt);
    } else {
        cli_dbgmsg("cli_cvdparse: No creation time in seconds (old file format)\n");
        cvd->stime = 0;
    }

    return cvd;
}

struct cl_cvd *cl_cvdhead(const char *file)
{
    FILE *fs;
    char head[513], *pt;
    int i;
    unsigned int bread;

    if ((fs = fopen(file, "rb")) == NULL) {
        cli_errmsg("cl_cvdhead: Can't open file %s\n", file);
        return NULL;
    }

    if (!(bread = fread(head, 1, 512, fs))) {
        cli_errmsg("cl_cvdhead: Can't read CVD header in %s\n", file);
        fclose(fs);
        return NULL;
    }

    fclose(fs);

    head[bread] = 0;
    if ((pt = strpbrk(head, "\n\r")))
        *pt = 0;

    for (i = bread - 1; i > 0 && (head[i] == ' ' || head[i] == '\n' || head[i] == '\r'); head[i] = 0, i--) {
        continue;
    }

    return cl_cvdparse(head);
}

void cl_cvdfree(struct cl_cvd *cvd)
{
    free(cvd->time);
    free(cvd->md5);
    free(cvd->dsig);
    free(cvd->builder);
    free(cvd);
}

cl_error_t cl_cvdverify(const char *file)
{
    return cl_cvdverify_ex(file, NULL, 0);
}

cl_error_t cl_cvdverify_ex(const char *file, const char *certs_directory, uint32_t dboptions)
{
    struct cl_engine *engine = NULL;
    cl_error_t ret;
    cvd_type dbtype              = CVD_TYPE_UNKNOWN;
    void *verifier               = NULL;
    FFIError *new_verifier_error = NULL;

    if (!(engine = cl_engine_new())) {
        cli_errmsg("cl_cvdverify: Can't create new engine\n");
        ret = CL_EMEM;
        goto done;
    }
    engine->cb_stats_submit = NULL; /* Don't submit stats if we're just verifying a CVD */

    if (!!cli_strbcasestr(file, ".cvd")) {
        dbtype = CVD_TYPE_CVD;
    } else if (!!cli_strbcasestr(file, ".cld")) {
        dbtype = CVD_TYPE_CLD;
    } else if (!!cli_strbcasestr(file, ".cud")) {
        dbtype = CVD_TYPE_CUD;
    } else {
        cli_errmsg("cl_cvdverify: File is not a CVD, CLD, or CUD: %s\n", file);
        ret = CL_ECVD;
        goto done;
    }

    if (NULL != certs_directory) {
        ret = cl_engine_set_str(engine, CL_ENGINE_CVDCERTSDIR, certs_directory);
        if (CL_SUCCESS != ret) {
            cli_errmsg("cl_cvdverify: Failed to set engine certs directory\n");
            goto done;
        }

        if (!codesign_verifier_new(engine->certs_directory, &verifier, &new_verifier_error)) {
            cli_errmsg("cl_cvdverify: Failed to create a new code-signature verifier: %s\n", ffierror_fmt(new_verifier_error));
            ret = CL_EVERIFY;
            goto done;
        }
    }

    ret = cli_cvdload(engine, NULL, dboptions | CL_DB_STDOPT | CL_DB_PUA, dbtype, file, verifier, true);

done:
    if (NULL != engine) {
        cl_engine_free(engine);
    }
    if (NULL != verifier) {
        codesign_verifier_free(verifier);
    }
    if (NULL != new_verifier_error) {
        ffierror_free(new_verifier_error);
    }

    return ret;
}

cl_error_t cli_cvdload(
    struct cl_engine *engine,
    unsigned int *signo,
    uint32_t options,
    cvd_type dbtype,
    const char *filename,
    void *sign_verifier,
    bool chkonly)
{
    cl_error_t status = CL_ECVD;
    cl_error_t ret;
    time_t s_time;
    struct cli_dbio dbio;
    struct cli_dbinfo *dbinfo  = NULL;
    char *dupname              = NULL;
    cvd_t *cvd                 = NULL;
    cvd_t *dupcvd              = NULL;
    FFIError *cvd_open_error   = NULL;
    FFIError *cvd_verify_error = NULL;
    char *signer_name          = NULL;
    bool disable_legacy_dsig   = false;

    dbio.hashctx = NULL;

    cli_dbgmsg("in cli_cvdload()\n");

    disable_legacy_dsig = (options & CL_DB_FIPS_LIMITS) || (engine->engine_options & ENGINE_OPTIONS_FIPS_LIMITS);

    /* Open the cvd and read the header */
    cvd = cvd_open(filename, &cvd_open_error);
    if (!cvd) {
        cli_errmsg("cli_cvdload: Can't open CVD file %s: %s\n", filename, ffierror_fmt(cvd_open_error));
        goto done;
    }

    /* For actual .cvd files, verify the digital signature. */
    if (dbtype == CVD_TYPE_CVD) {
        if (!cvd_verify(
                cvd,
                sign_verifier,
                disable_legacy_dsig,
                &signer_name,
                &cvd_verify_error)) {
            cli_errmsg("cli_cvdload: Can't verify CVD file %s: %s\n", filename, ffierror_fmt(cvd_verify_error));
            status = CL_EVERIFY;
            goto done;
        }
    }

    /* For .cvd files, check if there is a .cld of the same name.
       Reminder, .cld's are patched .cvd's so that would be a duplicate.
       Because it shouldn't happen, we treat it as an error. */
    if (dbtype == CVD_TYPE_CVD) {
        /* check for duplicate db */
        dupname = cli_safer_strdup(filename);
        if (!dupname) {
            status = CL_EMEM;
            goto done;
        }

        dupname[strlen(dupname) - 2] = (dbtype == CVD_TYPE_CLD ? 'v' : 'l');

        dupcvd = cvd_open(dupname, &cvd_open_error);
        if (dupcvd) {
            if (cvd_get_version(dupcvd) > cvd_get_version(cvd)) {
                cli_warnmsg("Detected duplicate databases %s and %s. The %s database is older and will not be loaded, you should manually remove it from the database directory.\n", filename, dupname, filename);
                status = CL_SUCCESS;
                goto done;
            } else if ((cvd_get_version(dupcvd) == cvd_get_version(cvd)) &&
                       dbtype == CVD_TYPE_CVD) {
                cli_warnmsg("Detected duplicate databases %s and %s, please manually remove one of them\n", filename, dupname);
                status = CL_SUCCESS;
                goto done;
            }
        } else {
            // If the .cld file doesn't exist, it's not an error.
            if (NULL != cvd_open_error) {
                ffierror_free(cvd_open_error);
                cvd_open_error = NULL;
            }
        }
    }

    if (strstr(filename, "daily.")) {
        time(&s_time);
        if (cvd_get_time_creation(cvd) > (uint64_t)s_time) {
            if (cvd_get_time_creation(cvd) - (unsigned int)s_time > 3600) {
                cli_warnmsg("******************************************************\n");
                cli_warnmsg("***      Virus database timestamp in the future!   ***\n");
                cli_warnmsg("***  Please check the timezone and clock settings  ***\n");
                cli_warnmsg("******************************************************\n");
            }
        } else if ((unsigned int)s_time - cvd_get_time_creation(cvd) > 604800) {
            cli_warnmsg("**************************************************\n");
            cli_warnmsg("***  The virus database is older than 7 days!  ***\n");
            cli_warnmsg("***   Please update it as soon as possible.    ***\n");
            cli_warnmsg("**************************************************\n");
        }
        engine->dbversion[0] = cvd_get_version(cvd);
        engine->dbversion[1] = cvd_get_time_creation(cvd);
    }

    if (cvd_get_min_flevel(cvd) > cl_retflevel()) {
        cli_warnmsg("*******************************************************************\n");
        cli_warnmsg("***  This version of the ClamAV engine is outdated.             ***\n");
        cli_warnmsg("***   Read https://docs.clamav.net/manual/Installing.html       ***\n");
        cli_warnmsg("*******************************************************************\n");
    }

    dbio.chkonly = 0;
    if (dbtype == CVD_TYPE_CUD) {
        ret = cli_tgzload(cvd, engine, signo, options | CL_DB_UNSIGNED, &dbio, NULL, sign_verifier);
    } else {
        ret = cli_tgzload(cvd, engine, signo, options | CL_DB_OFFICIAL, &dbio, NULL, sign_verifier);
    }
    if (ret != CL_SUCCESS) {
        status = ret;
        goto done;
    }

    dbinfo = engine->dbinfo;
    if (!dbinfo ||
        !dbinfo->cvd ||
        ((uint32_t)dbinfo->cvd->version != cvd_get_version(cvd)) ||
        ((uint32_t)dbinfo->cvd->sigs != cvd_get_num_sigs(cvd)) ||
        ((uint32_t)dbinfo->cvd->fl != cvd_get_min_flevel(cvd)) ||
        ((uint64_t)dbinfo->cvd->stime != cvd_get_time_creation(cvd))) {

        cli_errmsg("cli_cvdload: Corrupted CVD header\n");
        status = CL_EMALFDB;
        goto done;
    }
    dbinfo = engine->dbinfo ? engine->dbinfo->next : NULL;
    if (!dbinfo) {
        cli_errmsg("cli_cvdload: dbinfo error\n");
        status = CL_EMALFDB;
        goto done;
    }

    dbio.chkonly = chkonly;
    if (dbtype == CVD_TYPE_CUD) {
        options |= CL_DB_UNSIGNED;
    } else {
        options |= CL_DB_SIGNED | CL_DB_OFFICIAL;
    }

    status = cli_tgzload(cvd, engine, signo, options, &dbio, dbinfo, sign_verifier);

done:

    while (engine->dbinfo) {
        dbinfo         = engine->dbinfo;
        engine->dbinfo = dbinfo->next;
        MPOOL_FREE(engine->mempool, dbinfo->name);
        MPOOL_FREE(engine->mempool, dbinfo->hash);
        if (dbinfo->cvd)
            cl_cvdfree(dbinfo->cvd);
        MPOOL_FREE(engine->mempool, dbinfo);
    }

    if (NULL != signer_name) {
        ffi_cstring_free(signer_name);
    }
    free(dupname);
    if (NULL != cvd) {
        cvd_free(cvd);
    }
    if (NULL != dupcvd) {
        cvd_free(dupcvd);
    }
    if (NULL != cvd_open_error) {
        ffierror_free(cvd_open_error);
    }
    if (NULL != cvd_verify_error) {
        ffierror_free(cvd_verify_error);
    }

    return status;
}

cl_error_t cli_cvdverify(
    const char *file,
    bool disable_legacy_dsig,
    void *verifier)
{
    cl_error_t status          = CL_SUCCESS;
    cvd_t *cvd                 = NULL;
    FFIError *cvd_open_error   = NULL;
    FFIError *cvd_verify_error = NULL;
    char *signer_name          = NULL;

    cvd = cvd_open(file, &cvd_open_error);
    if (!cvd) {
        cli_errmsg("Can't open CVD file %s: %s\n", file, ffierror_fmt(cvd_open_error));
        return CL_EOPEN;
    }

    if (!cvd_verify(cvd, verifier, disable_legacy_dsig, &signer_name, &cvd_verify_error)) {
        cli_errmsg("CVD verification failed: %s\n", ffierror_fmt(cvd_verify_error));
        status = CL_EVERIFY;
        goto done;
    }

done:

    if (NULL != signer_name) {
        ffi_cstring_free(signer_name);
    }
    if (NULL != cvd) {
        cvd_free(cvd);
    }
    if (NULL != cvd_open_error) {
        ffierror_free(cvd_open_error);
    }
    if (NULL != cvd_verify_error) {
        ffierror_free(cvd_verify_error);
    }

    return status;
}

cl_error_t cli_cvdunpack_and_verify(
    const char *file,
    const char *dir,
    bool dont_verify,
    bool disable_legacy_dsig,
    void *verifier)
{
    cl_error_t status          = CL_SUCCESS;
    cvd_t *cvd                 = NULL;
    FFIError *cvd_open_error   = NULL;
    FFIError *cvd_verify_error = NULL;
    FFIError *cvd_unpack_error = NULL;
    char *signer_name          = NULL;

    cvd = cvd_open(file, &cvd_open_error);
    if (!cvd) {
        cli_errmsg("Can't open CVD file %s: %s\n", file, ffierror_fmt(cvd_open_error));
        return CL_EOPEN;
    }

    if (!dont_verify) {
        if (!cvd_verify(cvd, verifier, disable_legacy_dsig, &signer_name, &cvd_verify_error)) {
            cli_errmsg("CVD verification failed: %s\n", ffierror_fmt(cvd_verify_error));
            status = CL_EVERIFY;
            goto done;
        }
    }

    if (!cvd_unpack(cvd, dir, &cvd_unpack_error)) {
        cli_errmsg("CVD unpacking failed: %s\n", ffierror_fmt(cvd_unpack_error));
        status = CL_EUNPACK;
        goto done;
    }

done:

    if (NULL != signer_name) {
        ffi_cstring_free(signer_name);
    }
    if (NULL != cvd) {
        cvd_free(cvd);
    }
    if (NULL != cvd_open_error) {
        ffierror_free(cvd_open_error);
    }
    if (NULL != cvd_verify_error) {
        ffierror_free(cvd_verify_error);
    }
    if (NULL != cvd_unpack_error) {
        ffierror_free(cvd_unpack_error);
    }

    return status;
}

cl_error_t cl_cvdunpack_ex(const char *file, const char *dir, const char *certs_directory, uint32_t dboptions)
{
    cl_error_t status            = CL_SUCCESS;
    cvd_t *cvd                   = NULL;
    FFIError *cvd_open_error     = NULL;
    FFIError *new_verifier_error = NULL;
    FFIError *cvd_unpack_error   = NULL;
    char *signer_name            = NULL;
    void *verifier               = NULL;

    cvd = cvd_open(file, &cvd_open_error);
    if (!cvd) {
        cli_errmsg("Can't open CVD file %s: %s\n", file, ffierror_fmt(cvd_open_error));
        return CL_EOPEN;
    }

    if (dboptions & CL_DB_UNSIGNED) {
        // Just unpack the CVD file and don´t verify the digital signature.
        if (!cvd_unpack(cvd, dir, &cvd_unpack_error)) {
            cli_errmsg("CVD unpacking failed: %s\n", ffierror_fmt(cvd_unpack_error));
            status = CL_EUNPACK;
            goto done;
        }
    } else {
        // Verify the CVD file and then unpack it.
        bool disable_legacy_dsig = false;

        // The certs directory is optional.
        // If not provided, then we can't validate external signatures and will have to rely
        // on the internal MD5-based RSA signature.
        if (NULL != certs_directory) {
            if (!codesign_verifier_new(certs_directory, &verifier, &new_verifier_error)) {
                cli_errmsg("Failed to create a new code-signature verifier: %s\n", ffierror_fmt(new_verifier_error));
                status = CL_EUNPACK;
                goto done;
            }
        }

#if OPENSSL_VERSION_MAJOR >= 3
        disable_legacy_dsig = (dboptions & CL_DB_FIPS_LIMITS) || EVP_default_properties_is_fips_enabled(NULL);
#else
        disable_legacy_dsig = (dboptions & CL_DB_FIPS_LIMITS) || FIPS_mode();
#endif

        status = cli_cvdunpack_and_verify(file, dir, false, disable_legacy_dsig, verifier);
        if (status != CL_SUCCESS) {
            goto done;
        }
    }

done:

    if (NULL != signer_name) {
        ffi_cstring_free(signer_name);
    }
    if (NULL != cvd) {
        cvd_free(cvd);
    }
    if (NULL != cvd_open_error) {
        ffierror_free(cvd_open_error);
    }
    if (NULL != new_verifier_error) {
        ffierror_free(new_verifier_error);
    }
    if (NULL != cvd_unpack_error) {
        ffierror_free(cvd_unpack_error);
    }
    if (NULL != verifier) {
        codesign_verifier_free(verifier);
    }

    return status;
}

cl_error_t cl_cvdunpack(const char *file, const char *dir, bool dont_verify)
{
    cl_error_t status          = CL_SUCCESS;
    cvd_t *cvd                 = NULL;
    FFIError *cvd_open_error   = NULL;
    FFIError *cvd_verify_error = NULL;
    FFIError *cvd_unpack_error = NULL;
    char *signer_name          = NULL;
    bool disable_legacy_dsig   = false;

    cvd = cvd_open(file, &cvd_open_error);
    if (!cvd) {
        cli_errmsg("Can't open CVD file %s: %s\n", file, ffierror_fmt(cvd_open_error));
        return CL_EOPEN;
    }

#if OPENSSL_VERSION_MAJOR >= 3
    disable_legacy_dsig = EVP_default_properties_is_fips_enabled(NULL);
#else
    disable_legacy_dsig = FIPS_mode();
#endif

    if (!dont_verify) {
        if (!cvd_verify(cvd, NULL, disable_legacy_dsig, &signer_name, &cvd_verify_error)) {
            cli_errmsg("CVD verification failed: %s\n", ffierror_fmt(cvd_verify_error));
            status = CL_EVERIFY;
            goto done;
        }
    }

    if (!cvd_unpack(cvd, dir, &cvd_unpack_error)) {
        cli_errmsg("CVD unpacking failed: %s\n", ffierror_fmt(cvd_unpack_error));
        status = CL_EUNPACK;
        goto done;
    }

done:

    if (NULL != signer_name) {
        ffi_cstring_free(signer_name);
    }
    if (NULL != cvd) {
        cvd_free(cvd);
    }
    if (NULL != cvd_open_error) {
        ffierror_free(cvd_open_error);
    }
    if (NULL != cvd_verify_error) {
        ffierror_free(cvd_verify_error);
    }
    if (NULL != cvd_unpack_error) {
        ffierror_free(cvd_unpack_error);
    }

    return status;
}

static cl_error_t cvdgetfileage(const char *path, time_t *age_seconds)
{
    time_t s_time;
    cl_error_t status        = CL_EOPEN;
    cvd_t *cvd               = NULL;
    FFIError *cvd_open_error = NULL;

    cvd = cvd_open(path, &cvd_open_error);
    if (!cvd) {
        cli_errmsg("Can't open CVD file %s: %s\n", path, ffierror_fmt(cvd_open_error));
        goto done;
    }

    time(&s_time);

    if (cvd_get_time_creation(cvd) > (uint64_t)s_time) {
        *age_seconds = 0;
    } else {
        *age_seconds = (uint64_t)s_time - cvd_get_time_creation(cvd);
    }

    status = CL_SUCCESS;

done:
    if (NULL != cvd) {
        cvd_free(cvd);
    }
    if (NULL != cvd_open_error) {
        ffierror_free(cvd_open_error);
    }

    return status;
}

cl_error_t cl_cvdgetage(const char *path, time_t *age_seconds)
{
    STATBUF statbuf;
    struct dirent *dent;
    size_t path_len;
    bool ends_with_sep = false;
    DIR *dd            = NULL;
    bool first_age_set = true;
    cl_error_t status  = CL_SUCCESS;

    if (CLAMSTAT(path, &statbuf) == -1) {
        cli_errmsg("cl_cvdgetage: Can't get status of: %s\n", path);
        status = CL_ESTAT;
        goto done;
    }

    if (!S_ISDIR(statbuf.st_mode)) {
        status = cvdgetfileage(path, age_seconds);
        goto done;
    }

    if ((dd = opendir(path)) == NULL) {
        cli_errmsg("cl_cvdgetage: Can't open directory %s\n", path);
        status = CL_EOPEN;
        goto done;
    }

    path_len = strlen(path);

    if (path_len >= strlen(PATHSEP)) {
        if (strcmp(path + path_len - strlen(PATHSEP), PATHSEP) == 0) {
            cli_dbgmsg("cl_cvdgetage: path ends with separator\n");
            ends_with_sep = true;
        }
    }

    while ((dent = readdir(dd))) {
        char fname[1024] = {0};
        time_t file_age;

        if (!dent->d_ino)
            continue;

        if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
            continue;

        if (!CLI_DBEXT_SIGNATURE(dent->d_name))
            continue;

        if (ends_with_sep)
            snprintf(fname, sizeof(fname) - 1, "%s%s", path, dent->d_name);
        else
            snprintf(fname, sizeof(fname) - 1, "%s" PATHSEP "%s", path, dent->d_name);

        if ((status = cvdgetfileage(fname, &file_age)) != CL_SUCCESS) {
            cli_errmsg("cl_cvdgetage: cvdgetfileage() failed for %s\n", fname);
            goto done;
        }

        if (first_age_set) {
            first_age_set = false;
            *age_seconds  = file_age;
        } else {
            *age_seconds = MIN(file_age, *age_seconds);
        }
    }

done:
    if (dd)
        closedir(dd);

    return status;
}
