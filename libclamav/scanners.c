/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifndef _WIN32
#include <sys/time.h>
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <fcntl.h>
#include <dirent.h>
#ifdef HAVE_SYS_TIMES_H
#include <sys/times.h>
#endif

#define DCONF_ARCH ctx->dconf->archive
#define DCONF_DOC ctx->dconf->doc
#define DCONF_MAIL ctx->dconf->mail
#define DCONF_OTHER ctx->dconf->other

#include "clamav.h"
#include "others.h"
#include "dconf.h"
#include "scanners.h"
#include "matcher-ac.h"
#include "matcher-bm.h"
#include "matcher.h"
#include "ole2_extract.h"
#include "vba_extract.h"
#include "msexpand.h"
#include "mbox.h"
#include "libmspack.h"
#include "pe.h"
#include "elf.h"
#include "filetypes.h"
#include "htmlnorm.h"
#include "untar.h"
#include "special.h"
#include "binhex.h"
/* #include "uuencode.h" */
#include "tnef.h"
#include "sis.h"
#include "pdf.h"
#include "str.h"
#include "rtf.h"
#include "libclamunrar_iface/unrar_iface.h"
#include "unarj.h"
#include "nsis/nulsft.h"
#include "autoit.h"
#include "textnorm.h"
#include <zlib.h>
#include "unzip.h"
#include "dlp.h"
#include "default.h"
#include "cpio.h"
#include "macho.h"
#include "ishield.h"
#include "7z_iface.h"
#include "fmap.h"
#include "cache.h"
#include "events.h"
#include "swf.h"
#include "jpeg.h"
#include "png.h"
#include "iso9660.h"
#include "dmg.h"
#include "xar.h"
#include "hfsplus.h"
#include "xz_iface.h"
#include "mbr.h"
#include "gpt.h"
#include "apm.h"
#include "ooxml.h"
#include "xdp.h"
#include "json_api.h"
#include "msxml.h"
#include "tiff.h"
#include "hwp.h"
#include "msdoc.h"

#ifdef HAVE_BZLIB_H
#include <bzlib.h>
#endif

#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
#include <limits.h>
#include <stddef.h>
#endif

#include <fcntl.h>
#include <string.h>

static int cli_scanfile(const char *filename, cli_ctx *ctx);

static int cli_scandir(const char *dirname, cli_ctx *ctx)
{
    DIR *dd;
    struct dirent *dent;
#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
    union {
        struct dirent d;
        char b[offsetof(struct dirent, d_name) + NAME_MAX + 1];
    } result;
#endif
    STATBUF statbuf;
    char *fname;
    unsigned int viruses_found = 0;

    if ((dd = opendir(dirname)) != NULL)
    {
#ifdef HAVE_READDIR_R_3
        while (!readdir_r(dd, &result.d, &dent) && dent)
        {
#elif defined(HAVE_READDIR_R_2)
        while ((dent = (struct dirent *)readdir_r(dd, &result.d)))
        {
#else
        while ((dent = readdir(dd)))
        {
#endif
            if (dent->d_ino)
            {
                if (strcmp(dent->d_name, ".") && strcmp(dent->d_name, ".."))
                {
                    /* build the full name */
                    fname = cli_malloc(strlen(dirname) + strlen(dent->d_name) + 2);
                    if (!fname)
                    {
                        closedir(dd);
                        cli_dbgmsg("cli_scandir: Unable to allocate memory for filename\n");
                        return CL_EMEM;
                    }

                    sprintf(fname, "%s" PATHSEP "%s", dirname, dent->d_name);

                    /* stat the file */
                    if (LSTAT(fname, &statbuf) != -1)
                    {
                        if (S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode))
                        {
                            if (cli_scandir(fname, ctx) == CL_VIRUS)
                            {
                                free(fname);

                                if (SCAN_ALLMATCHES)
                                {
                                    viruses_found++;
                                    continue;
                                }

                                closedir(dd);
                                return CL_VIRUS;
                            }
                        }
                        else
                        {
                            if (S_ISREG(statbuf.st_mode))
                            {
                                if (cli_scanfile(fname, ctx) == CL_VIRUS)
                                {
                                    free(fname);

                                    if (SCAN_ALLMATCHES)
                                    {
                                        viruses_found++;
                                        continue;
                                    }

                                    closedir(dd);
                                    return CL_VIRUS;
                                }
                            }
                        }
                    }
                    free(fname);
                }
            }
        }
    }
    else
    {
        cli_dbgmsg("cli_scandir: Can't open directory %s.\n", dirname);
        return CL_EOPEN;
    }

    closedir(dd);
    if (SCAN_ALLMATCHES && viruses_found)
        return CL_VIRUS;
    return CL_CLEAN;
}

/**
 * @brief  Scan the metadata using cli_matchmeta()
 *
 * @param metadata  unrar metadata structure
 * @param ctx       scanning context structure
 * @param files
 * @return cl_error_t  Returns CL_CLEAN if nothing found, CL_VIRUS if something found, CL_EUNPACK if encrypted.
 */
static cl_error_t cli_unrar_scanmetadata(unrar_metadata_t* metadata, cli_ctx* ctx, unsigned int files)
{
    cl_error_t status = CL_CLEAN;

    cli_dbgmsg("RAR: %s, crc32: 0x%x, encrypted: %u, compressed: %u, normal: %u, method: %u, ratio: %u\n",
        metadata->filename, metadata->crc, metadata->encrypted, (unsigned int)metadata->pack_size,
        (unsigned int)metadata->unpack_size, metadata->method,
        metadata->pack_size ? (unsigned int)(metadata->unpack_size / metadata->pack_size) : 0);

    if (CL_VIRUS == cli_matchmeta(ctx, metadata->filename, metadata->pack_size, metadata->unpack_size, metadata->encrypted, files, metadata->crc, NULL)) {
        status = CL_VIRUS;
    } else if (SCAN_HEURISTIC_ENCRYPTED_ARCHIVE && metadata->encrypted) {
        cli_dbgmsg("RAR: Encrypted files found in archive.\n");
        status = CL_EUNPACK;
    }

    return status;
}

static cl_error_t cli_scanrar(const char *filepath, int desc, cli_ctx* ctx)
{
    cl_error_t status = CL_EPARSE;
    cl_unrar_error_t unrar_ret = UNRAR_ERR;

    char* extract_dir = NULL; /* temp dir to write extracted files to */
    unsigned int file_count = 0;
    unsigned int viruses_found = 0;

    uint32_t nEncryptedFilesFound = 0;
    uint32_t nTooLargeFilesFound = 0;

    void * hArchive = NULL;

    char * comment = NULL;
    uint32_t comment_size = 0;

    unrar_metadata_t metadata;
    char * filename_base = NULL;
    char * extract_fullpath = NULL;
    char * comment_fullpath = NULL;

    if (filepath == NULL || ctx == NULL) {
        cli_dbgmsg("RAR: Invalid arguments!\n");
        return CL_EARG;
    }

    cli_dbgmsg("in scanrar()\n");

    /* Zero out the metadata struct before we read the header */
    memset(&metadata, 0, sizeof(unrar_metadata_t));

    /* Determine file basename */
    if (CL_SUCCESS != cli_basename(filepath, strlen(filepath), &filename_base)) {
        status = CL_EARG;
        goto done;
    }

    /* generate the temporary directory for extracted files. */
    if (!(extract_dir = cli_gentemp_with_prefix(ctx->engine->tmpdir, filename_base))) {
        status = CL_EMEM;
        goto done;
    }
    if (mkdir(extract_dir, 0700)) {
        cli_dbgmsg("RAR: Can't create temporary directory for extracted files %s\n", extract_dir);
        status = CL_ETMPDIR;
        goto done;
    }

    /*
     * Open the archive.
     */
    if (UNRAR_OK != (unrar_ret = cli_unrar_open(filepath, &hArchive, &comment, &comment_size, cli_debug_flag))) {
        if (unrar_ret == UNRAR_ENCRYPTED) {
            cli_dbgmsg("RAR: Encrypted main header\n");
            status = CL_EUNPACK;
            goto done;
        }
        if (unrar_ret == UNRAR_EMEM) {
            status = CL_EMEM;
            goto done;
        } else if (unrar_ret == UNRAR_EOPEN) {
            status = CL_EOPEN;
            goto done;
        } else {
            status = CL_EFORMAT;
            goto done;
        }
    }

    /* If the archive header had a comment, write it to the comment dir. */
    if ((comment != NULL) && (comment_size > 0)) {
        int comment_fd = -1;
        if (!(comment_fullpath = cli_gentemp_with_prefix(extract_dir, "comments"))) {
            status = CL_EMEM;
            goto done;
        }

        comment_fd = open(comment_fullpath, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0600);
        if (comment_fd < 0) {
            cli_dbgmsg("RAR: ERROR: Failed to open output file\n");
        } else {
            cli_dbgmsg("RAR: Writing the archive comment to temp file: %s\n", comment_fullpath);
            if (0 == write(comment_fd, comment, comment_size)) {
                cli_dbgmsg("RAR: ERROR: Failed to write to output file\n");
            } else {
                close(comment_fd);
                comment_fd = -1;

                /* Scan the comment file */
                status = cli_scanfile(comment_fullpath, ctx);

                /* Delete the tempfile if not --leave-temps */
                if (!ctx->engine->keeptmp)
                    if (cli_unlink(comment_fullpath))
                        cli_dbgmsg("RAR: Failed to unlink the extracted comment file: %s\n", comment_fullpath);

                if ((status == CL_VIRUS) && SCAN_ALLMATCHES) {
                    status = CL_CLEAN;
                    viruses_found++;
                }
                if ((status == CL_VIRUS) || (status == CL_BREAK)) {
                    goto done;
                }
            }
        }
    }

    /*
     * Read & scan each file header.
     * Extract & scan each file.
     *
     * Skip files if they will exceed max filesize or max scansize.
     * Count the number of encrypted file headers and encrypted files.
     *  - Alert if there are encrypted files,
     *      if the Heuristic for encrypted archives is enabled,
     *      and if we have not detected a signature match.
     */
    do {
        status = CL_CLEAN;

        /* Zero out the metadata struct before we read the header */
        memset(&metadata, 0, sizeof(unrar_metadata_t));

        /*
         * Get the header information for the next file in the archive.
         */
        unrar_ret = cli_unrar_peek_file_header(hArchive, &metadata);
        if (unrar_ret != UNRAR_OK) {
            if (unrar_ret == UNRAR_ENCRYPTED) {
                /* Found an encrypted file header, must skip. */
                cli_dbgmsg("RAR: Encrypted file header, unable to reading file metadata and file contents. Skipping file...\n");
                nEncryptedFilesFound += 1;

                if (UNRAR_OK != cli_unrar_skip_file(hArchive)) {
                    /* Failed to skip!  Break extraction loop. */
                    cli_dbgmsg("RAR: Failed to skip file. RAR archive extraction has failed.\n");
                    break;
                }
            } else if (unrar_ret == UNRAR_BREAK) {
                /* No more files. Break extraction loop. */
                cli_dbgmsg("RAR: No more files in archive.\n");
                break;
            } else {
                /* Memory error or some other error reading the header info. */
                cli_dbgmsg("RAR: Error (%u) reading file header!\n", unrar_ret);
                break;
            }
        }
        else {
            file_count += 1;

            /*
            * Scan the metadata for the file in question since the content was clean, or we're running in all-match.
            */
            status = cli_unrar_scanmetadata(&metadata, ctx, file_count);
            if ((status == CL_VIRUS) && SCAN_ALLMATCHES) {
                status = CL_CLEAN;
                viruses_found++;
            }
            if ((status == CL_VIRUS) || (status == CL_BREAK)) {
                break;
            }

            /* Check if we've already exceeded the scan limit */
            if (cli_checklimits("RAR", ctx, 0, 0, 0))
                break;

            if (metadata.is_dir) {
                /* Entry is a directory. Skip. */
                cli_dbgmsg("RAR: Found directory. Skipping to next file.\n");

                if (UNRAR_OK != cli_unrar_skip_file(hArchive)) {
                    /* Failed to skip!  Break extraction loop. */
                    cli_dbgmsg("RAR: Failed to skip directory. RAR archive extraction has failed.\n");
                    break;
                }
            } else if (cli_checklimits("RAR", ctx, metadata.unpack_size, 0, 0)) {
                /* File size exceeds maxfilesize, must skip extraction.
                * Although we may be able to scan the metadata */
                nTooLargeFilesFound += 1;

                cli_dbgmsg("RAR: Next file is too large (%" PRIu64 " bytes); it would exceed max scansize.  Skipping to next file.\n", metadata.unpack_size);

                if (UNRAR_OK != cli_unrar_skip_file(hArchive)) {
                    /* Failed to skip!  Break extraction loop. */
                    cli_dbgmsg("RAR: Failed to skip file. RAR archive extraction has failed.\n");
                    break;
                }
            } else if (metadata.encrypted != 0) {
                /* Found an encrypted file, must skip. */
                cli_dbgmsg("RAR: Encrypted file, unable to extract file contents. Skipping file...\n");
                nEncryptedFilesFound += 1;

                if (UNRAR_OK != cli_unrar_skip_file(hArchive)) {
                    /* Failed to skip!  Break extraction loop. */
                    cli_dbgmsg("RAR: Failed to skip file. RAR archive extraction has failed.\n");
                    break;
                }
            } else {
                /*
                 * Extract the file...
                 */
                extract_fullpath = cli_gentemp(extract_dir);
                if (NULL == extract_fullpath) {
                    cli_dbgmsg("RAR: Memory error allocating filename for extracted file.");
                    status = CL_EMEM;
                    break;
                }
                cli_dbgmsg("RAR: Extracting file: %s to %s\n", metadata.filename, extract_fullpath);

                unrar_ret = cli_unrar_extract_file(hArchive, extract_fullpath, NULL);
                if (unrar_ret != UNRAR_OK) {
                    /*
                     * Some other error extracting the file
                     */
                    cli_dbgmsg("RAR: Error extracting file: %s\n", metadata.filename);

                    /* TODO:
                     *   may need to manually skip the file depending on what, specifically, cli_unrar_extract_file() returned.
                     */
                } else {
                    /* File should be extracted...
                     * ... scan the extracted file.
                     */
                    cli_dbgmsg("RAR: Extraction complete.  Scanning now...\n");
                    status = cli_scanfile(extract_fullpath, ctx);
                    if (status == CL_EOPEN) {
                        cli_dbgmsg("RAR: File not found, Extraction failed!\n");
                        status = CL_CLEAN;
                    } else {
                        /* Delete the tempfile if not --leave-temps */
                        if (!ctx->engine->keeptmp)
                            if (cli_unlink(extract_fullpath))
                                cli_dbgmsg("RAR: Failed to unlink the extracted file: %s\n", extract_fullpath);

                        if (status == CL_VIRUS) {
                            cli_dbgmsg("RAR: infected with %s\n", cli_get_last_virus(ctx));
                            status = CL_VIRUS;
                            viruses_found++;
                        }
                    }
                }

                /* Free up that the filepath */
                if (NULL != extract_fullpath) {
                    free(extract_fullpath);
                    extract_fullpath = NULL;
                }
            }
        }

        if (status == CL_VIRUS) {
            if (SCAN_ALLMATCHES)
                status = CL_SUCCESS;
            else
                break;
        }

        if (ctx->engine->maxscansize && ctx->scansize >= ctx->engine->maxscansize) {
            status = CL_CLEAN;
            break;
        }

        /*
         * TODO: Free up any malloced metadata...
         */
        if (metadata.filename != NULL) {
            free(metadata.filename);
            metadata.filename = NULL;
        }

    } while (status == CL_CLEAN);

    if (status == CL_BREAK)
        status = CL_CLEAN;

done:
    if (NULL != comment) {
        free(comment);
        comment = NULL;
    }

    if (NULL != comment_fullpath) {
        if (!ctx->engine->keeptmp) {
            cli_rmdirs(comment_fullpath);
        }
        free(comment_fullpath);
        comment_fullpath = NULL;
    }

    if (NULL != hArchive) {
        cli_unrar_close(hArchive);
        hArchive = NULL;
    }

    if (NULL != filename_base) {
        free(filename_base);
        filename_base = NULL;
    }

    if (metadata.filename != NULL) {
        free(metadata.filename);
        metadata.filename = NULL;
    }

    if (NULL != extract_fullpath) {
        free(extract_fullpath);
        extract_fullpath = NULL;
    }

    if (NULL != extract_dir) {
        if (!ctx->engine->keeptmp) {
            cli_rmdirs(extract_dir);
        }
        free(extract_dir);
        extract_dir = NULL;
    }

    /* If return value was a failure due to encryption, scan the un-extracted archive just in case... */
    if ((CL_VIRUS != status) && ((CL_EUNPACK == status) || (nEncryptedFilesFound > 0))) {
        status = cli_scandesc(desc, ctx, 0, 0, NULL, AC_SCAN_VIR, NULL);

        /* If no virus, and user requests enabled the Heuristic for encrypted archives... */
        if ((status != CL_VIRUS) && SCAN_HEURISTIC_ENCRYPTED_ARCHIVE) {
            if (CL_VIRUS == cli_append_virus(ctx, "Heuristics.Encrypted.RAR")) {
                status = CL_VIRUS;
            }
        }
        if (status != CL_VIRUS) {
            status = CL_CLEAN;
        }
    }

    cli_dbgmsg("RAR: Exit code: %d\n", status);

    if (SCAN_ALLMATCHES && viruses_found)
        status = CL_VIRUS;

    return status;
}

static int cli_scanarj(cli_ctx *ctx, off_t sfx_offset)
{
    int ret = CL_CLEAN, rc, file = 0;
    arj_metadata_t metadata;
    char *dir;
    int virus_found = 0;

    cli_dbgmsg("in cli_scanarj()\n");

    memset(&metadata, 0, sizeof(arj_metadata_t));

    /* generate the temporary directory */
    if (!(dir = cli_gentemp(ctx->engine->tmpdir)))
        return CL_EMEM;

    if (mkdir(dir, 0700))
    {
        cli_dbgmsg("ARJ: Can't create temporary directory %s\n", dir);
        free(dir);
        return CL_ETMPDIR;
    }

    ret = cli_unarj_open(*ctx->fmap, dir, &metadata, sfx_offset);
    if (ret != CL_SUCCESS)
    {
        if (!ctx->engine->keeptmp)
            cli_rmdirs(dir);
        free(dir);
        cli_dbgmsg("ARJ: Error: %s\n", cl_strerror(ret));
        return ret;
    }

    do
    {
        metadata.filename = NULL;
        ret = cli_unarj_prepare_file(dir, &metadata);
        if (ret != CL_SUCCESS)
        {
            cli_dbgmsg("ARJ: cli_unarj_prepare_file Error: %s\n", cl_strerror(ret));
            break;
        }
        file++;
        if (cli_matchmeta(ctx, metadata.filename, metadata.comp_size, metadata.orig_size, metadata.encrypted, file, 0, NULL) == CL_VIRUS)
        {
            if (!SCAN_ALLMATCHES)
            {
                cli_rmdirs(dir);
                free(dir);
                return CL_VIRUS;
            }
            virus_found = 1;
            ret = CL_SUCCESS;
        }

        if ((ret = cli_checklimits("ARJ", ctx, metadata.orig_size, metadata.comp_size, 0)) != CL_CLEAN)
        {
            ret = CL_SUCCESS;
            if (metadata.filename)
                free(metadata.filename);
            continue;
        }
        ret = cli_unarj_extract_file(dir, &metadata);
        if (ret != CL_SUCCESS)
        {
            cli_dbgmsg("ARJ: cli_unarj_extract_file Error: %s\n", cl_strerror(ret));
        }
        if (metadata.ofd >= 0)
        {
            if (lseek(metadata.ofd, 0, SEEK_SET) == -1)
            {
                cli_dbgmsg("ARJ: call to lseek() failed\n");
            }
            rc = cli_magic_scandesc(metadata.ofd, NULL, ctx);
            close(metadata.ofd);
            if (rc == CL_VIRUS)
            {
                cli_dbgmsg("ARJ: infected with %s\n", cli_get_last_virus(ctx));
                if (!SCAN_ALLMATCHES)
                {
                    ret = CL_VIRUS;
                    if (metadata.filename)
                    {
                        free(metadata.filename);
                        metadata.filename = NULL;
                    }
                    break;
                }
                virus_found = 1;
                ret = CL_SUCCESS;
            }
        }
        if (metadata.filename)
        {
            free(metadata.filename);
            metadata.filename = NULL;
        }

    } while (ret == CL_SUCCESS);

    if (!ctx->engine->keeptmp)
        cli_rmdirs(dir);

    free(dir);
    if (metadata.filename)
    {
        free(metadata.filename);
    }

    if (virus_found != 0)
        ret = CL_VIRUS;
    cli_dbgmsg("ARJ: Exit code: %d\n", ret);
    if (ret == CL_BREAK)
        ret = CL_CLEAN;

    return ret;
}

static int cli_scangzip_with_zib_from_the_80s(cli_ctx *ctx, unsigned char *buff)
{
    int fd, ret, outsize = 0, bytes;
    fmap_t *map = *ctx->fmap;
    char *tmpname;
    gzFile gz;

    ret = fmap_fd(map);
    if (ret < 0)
        return CL_EDUP;
    fd = dup(ret);
    if (fd < 0)
        return CL_EDUP;

    if (!(gz = gzdopen(fd, "rb")))
    {
        close(fd);
        return CL_EOPEN;
    }

    if ((ret = cli_gentempfd(ctx->engine->tmpdir, &tmpname, &fd)) != CL_SUCCESS)
    {
        cli_dbgmsg("GZip: Can't generate temporary file.\n");
        gzclose(gz);
        close(fd);
        return ret;
    }

    while ((bytes = gzread(gz, buff, FILEBUFF)) > 0)
    {
        outsize += bytes;
        if (cli_checklimits("GZip", ctx, outsize, 0, 0) != CL_CLEAN)
            break;
        if (cli_writen(fd, buff, bytes) != bytes)
        {
            close(fd);
            gzclose(gz);
            if (cli_unlink(tmpname))
            {
                free(tmpname);
                return CL_EUNLINK;
            }
            free(tmpname);
            return CL_EWRITE;
        }
    }

    gzclose(gz);

    if ((ret = cli_magic_scandesc(fd, tmpname, ctx)) == CL_VIRUS)
    {
        cli_dbgmsg("GZip: Infected with %s\n", cli_get_last_virus(ctx));
        close(fd);
        if (!ctx->engine->keeptmp)
        {
            if (cli_unlink(tmpname))
            {
                free(tmpname);
                return CL_EUNLINK;
            }
        }
        free(tmpname);
        return CL_VIRUS;
    }
    close(fd);
    if (!ctx->engine->keeptmp)
        if (cli_unlink(tmpname))
            ret = CL_EUNLINK;
    free(tmpname);
    return ret;
}

static int cli_scangzip(cli_ctx *ctx)
{
    int fd, ret = CL_CLEAN;
    unsigned char buff[FILEBUFF];
    char *tmpname;
    z_stream z;
    size_t at = 0, outsize = 0;
    fmap_t *map = *ctx->fmap;

    cli_dbgmsg("in cli_scangzip()\n");

    memset(&z, 0, sizeof(z));
    if ((ret = inflateInit2(&z, MAX_WBITS + 16)) != Z_OK)
    {
        cli_dbgmsg("GZip: InflateInit failed: %d\n", ret);
        return cli_scangzip_with_zib_from_the_80s(ctx, buff);
    }

    if ((ret = cli_gentempfd(ctx->engine->tmpdir, &tmpname, &fd)) != CL_SUCCESS)
    {
        cli_dbgmsg("GZip: Can't generate temporary file.\n");
        inflateEnd(&z);
        return ret;
    }

    while (at < map->len)
    {
        unsigned int bytes = MIN(map->len - at, map->pgsz);
        if (!(z.next_in = (void *)fmap_need_off_once(map, at, bytes)))
        {
            cli_dbgmsg("GZip: Can't read %u bytes @ %lu.\n", bytes, (long unsigned)at);
            inflateEnd(&z);
            close(fd);
            if (cli_unlink(tmpname))
            {
                free(tmpname);
                return CL_EUNLINK;
            }
            free(tmpname);
            return CL_EREAD;
        }
        at += bytes;
        z.avail_in = bytes;
        do
        {
            int inf;
            z.avail_out = sizeof(buff);
            z.next_out = buff;
            inf = inflate(&z, Z_NO_FLUSH);
            if (inf != Z_OK && inf != Z_STREAM_END && inf != Z_BUF_ERROR)
            {
                if (sizeof(buff) == z.avail_out)
                {
                    cli_dbgmsg("GZip: Bad stream, nothing in output buffer.\n");
                    at = map->len;
                    break;
                }
                else
                {
                    cli_dbgmsg("GZip: Bad stream, data in output buffer.\n");
                    /* no break yet, flush extracted bytes to file */
                }
            }
            if (cli_writen(fd, buff, sizeof(buff) - z.avail_out) < 0)
            {
                inflateEnd(&z);
                close(fd);
                if (cli_unlink(tmpname))
                {
                    free(tmpname);
                    return CL_EUNLINK;
                }
                free(tmpname);
                return CL_EWRITE;
            }
            outsize += sizeof(buff) - z.avail_out;
            if (cli_checklimits("GZip", ctx, outsize, 0, 0) != CL_CLEAN)
            {
                at = map->len;
                break;
            }
            if (inf == Z_STREAM_END)
            {
                at -= z.avail_in;
                inflateReset(&z);
                break;
            }
            else if (inf != Z_OK && inf != Z_BUF_ERROR)
            {
                at = map->len;
                break;
            }
        } while (z.avail_out == 0);
    }

    inflateEnd(&z);

    if ((ret = cli_magic_scandesc(fd, tmpname, ctx)) == CL_VIRUS)
    {
        cli_dbgmsg("GZip: Infected with %s\n", cli_get_last_virus(ctx));
        close(fd);
        if (!ctx->engine->keeptmp)
        {
            if (cli_unlink(tmpname))
            {
                free(tmpname);
                return CL_EUNLINK;
            }
        }
        free(tmpname);
        return CL_VIRUS;
    }
    close(fd);
    if (!ctx->engine->keeptmp)
        if (cli_unlink(tmpname))
            ret = CL_EUNLINK;
    free(tmpname);
    return ret;
}

#ifndef HAVE_BZLIB_H
static int cli_scanbzip(cli_ctx *ctx)
{
    cli_warnmsg("cli_scanbzip: bzip2 support not compiled in\n");
    return CL_CLEAN;
}

#else

#ifdef NOBZ2PREFIX
#define BZ2_bzDecompressInit bzDecompressInit
#define BZ2_bzDecompress bzDecompress
#define BZ2_bzDecompressEnd bzDecompressEnd
#endif

static int cli_scanbzip(cli_ctx *ctx)
{
    int ret = CL_CLEAN, fd, rc;
    unsigned long int size = 0;
    char *tmpname;
    bz_stream strm;
    size_t off = 0;
    size_t avail;
    char buf[FILEBUFF];

    memset(&strm, 0, sizeof(strm));
    strm.next_out = buf;
    strm.avail_out = sizeof(buf);
    rc = BZ2_bzDecompressInit(&strm, 0, 0);
    if (BZ_OK != rc)
    {
        cli_dbgmsg("Bzip: DecompressInit failed: %d\n", rc);
        return CL_EOPEN;
    }

    if ((ret = cli_gentempfd(ctx->engine->tmpdir, &tmpname, &fd)))
    {
        cli_dbgmsg("Bzip: Can't generate temporary file.\n");
        BZ2_bzDecompressEnd(&strm);
        return ret;
    }

    do
    {
        if (!strm.avail_in)
        {
            strm.next_in = (void *)fmap_need_off_once_len(*ctx->fmap, off, FILEBUFF, &avail);
            strm.avail_in = avail;
            off += avail;
            if (!strm.avail_in)
            {
                cli_dbgmsg("Bzip: premature end of compressed stream\n");
                break;
            }
        }

        rc = BZ2_bzDecompress(&strm);
        if (BZ_OK != rc && BZ_STREAM_END != rc)
        {
            cli_dbgmsg("Bzip: decompress error: %d\n", rc);
            break;
        }

        if (!strm.avail_out || BZ_STREAM_END == rc)
        {

            size += sizeof(buf) - strm.avail_out;

            if (cli_writen(fd, buf, sizeof(buf) - strm.avail_out) != sizeof(buf) - strm.avail_out)
            {
                cli_dbgmsg("Bzip: Can't write to file.\n");
                BZ2_bzDecompressEnd(&strm);
                close(fd);
                if (!ctx->engine->keeptmp)
                {
                    if (cli_unlink(tmpname))
                    {
                        free(tmpname);
                        return CL_EUNLINK;
                    }
                }
                free(tmpname);
                return CL_EWRITE;
            }

            if (cli_checklimits("Bzip", ctx, size, 0, 0) != CL_CLEAN)
                break;

            strm.next_out = buf;
            strm.avail_out = sizeof(buf);
        }
    } while (BZ_STREAM_END != rc);

    BZ2_bzDecompressEnd(&strm);

    if ((ret = cli_magic_scandesc(fd, tmpname, ctx)) == CL_VIRUS)
    {
        cli_dbgmsg("Bzip: Infected with %s\n", cli_get_last_virus(ctx));
        close(fd);
        if (!ctx->engine->keeptmp)
        {
            if (cli_unlink(tmpname))
            {
                ret = CL_EUNLINK;
                free(tmpname);
                return ret;
            }
        }
        free(tmpname);
        return CL_VIRUS;
    }
    close(fd);
    if (!ctx->engine->keeptmp)
        if (cli_unlink(tmpname))
            ret = CL_EUNLINK;
    free(tmpname);

    return ret;
}
#endif

static int cli_scanxz(cli_ctx *ctx)
{
    int ret = CL_CLEAN, fd, rc;
    unsigned long int size = 0;
    char *tmpname;
    struct CLI_XZ strm;
    size_t off = 0;
    size_t avail;
    unsigned char *buf;

    buf = cli_malloc(CLI_XZ_OBUF_SIZE);
    if (buf == NULL)
    {
        cli_errmsg("cli_scanxz: nomemory for decompress buffer.\n");
        return CL_EMEM;
    }
    memset(&strm, 0x00, sizeof(struct CLI_XZ));
    strm.next_out = buf;
    strm.avail_out = CLI_XZ_OBUF_SIZE;
    rc = cli_XzInit(&strm);
    if (rc != XZ_RESULT_OK)
    {
        cli_errmsg("cli_scanxz: DecompressInit failed: %i\n", rc);
        free(buf);
        return CL_EOPEN;
    }

    if ((ret = cli_gentempfd(ctx->engine->tmpdir, &tmpname, &fd)))
    {
        cli_errmsg("cli_scanxz: Can't generate temporary file.\n");
        cli_XzShutdown(&strm);
        free(buf);
        return ret;
    }
    cli_dbgmsg("cli_scanxz: decompressing to file %s\n", tmpname);

    do
    {
        /* set up input buffer */
        if (!strm.avail_in)
        {
            strm.next_in = (void *)fmap_need_off_once_len(*ctx->fmap, off, CLI_XZ_IBUF_SIZE, &avail);
            strm.avail_in = avail;
            off += avail;
            if (!strm.avail_in)
            {
                cli_errmsg("cli_scanxz: premature end of compressed stream\n");
                ret = CL_EFORMAT;
                goto xz_exit;
            }
        }

        /* xz decompress a chunk */
        rc = cli_XzDecode(&strm);
        if (XZ_RESULT_OK != rc && XZ_STREAM_END != rc)
        {
            if (rc == XZ_DIC_HEURISTIC)
            {
                ret = cli_append_virus(ctx, "Heuristics.XZ.DicSizeLimit");
                goto xz_exit;
            }
            cli_errmsg("cli_scanxz: decompress error: %d\n", rc);
            ret = CL_EFORMAT;
            goto xz_exit;
        }
        //cli_dbgmsg("cli_scanxz: xz decompressed %li of %li available bytes\n",
        //           avail - strm.avail_in, avail);

        /* write decompress buffer */
        if (!strm.avail_out || rc == XZ_STREAM_END)
        {
            size_t towrite = CLI_XZ_OBUF_SIZE - strm.avail_out;
            size += towrite;

            //cli_dbgmsg("Writing %li bytes to XZ decompress temp file(%li byte total)\n",
            //           towrite, size);

            if ((size_t)cli_writen(fd, buf, towrite) != towrite)
            {
                cli_errmsg("cli_scanxz: Can't write to file.\n");
                ret = CL_EWRITE;
                goto xz_exit;
            }
            if (cli_checklimits("cli_scanxz", ctx, size, 0, 0) != CL_CLEAN)
            {
                cli_warnmsg("cli_scanxz: decompress file size exceeds limits - "
                            "only scanning %li bytes\n",
                            size);
                break;
            }
            strm.next_out = buf;
            strm.avail_out = CLI_XZ_OBUF_SIZE;
        }
    } while (XZ_STREAM_END != rc);

    /* scan decompressed file */
    if ((ret = cli_magic_scandesc(fd, tmpname, ctx)) == CL_VIRUS)
    {
        cli_dbgmsg("cli_scanxz: Infected with %s\n", cli_get_last_virus(ctx));
    }

xz_exit:
    cli_XzShutdown(&strm);
    close(fd);
    if (!ctx->engine->keeptmp)
        if (cli_unlink(tmpname) && ret == CL_CLEAN)
            ret = CL_EUNLINK;
    free(tmpname);
    free(buf);
    return ret;
}

static int cli_scanszdd(cli_ctx *ctx)
{
    int ofd, ret;
    char *tmpname;

    cli_dbgmsg("in cli_scanszdd()\n");

    if ((ret = cli_gentempfd(ctx->engine->tmpdir, &tmpname, &ofd)))
    {
        cli_dbgmsg("MSEXPAND: Can't generate temporary file/descriptor\n");
        return ret;
    }

    ret = cli_msexpand(ctx, ofd);

    if (ret != CL_SUCCESS)
    { /* CL_VIRUS or some error */
        close(ofd);
        if (!ctx->engine->keeptmp)
            if (cli_unlink(tmpname))
                ret = CL_EUNLINK;
        free(tmpname);
        return ret;
    }

    cli_dbgmsg("MSEXPAND: Decompressed into %s\n", tmpname);
    ret = cli_magic_scandesc(ofd, tmpname, ctx);
    close(ofd);
    if (!ctx->engine->keeptmp)
        if (cli_unlink(tmpname))
            ret = CL_EUNLINK;
    free(tmpname);

    return ret;
}

static int vba_scandata(const unsigned char *data, unsigned int len, cli_ctx *ctx)
{
    struct cli_matcher *groot = ctx->engine->root[0];
    struct cli_matcher *troot = ctx->engine->root[2];
    struct cli_ac_data gmdata, tmdata;
    struct cli_ac_data *mdata[2];
    int ret;
    unsigned int viruses_found = 0;

    if ((ret = cli_ac_initdata(&tmdata, troot->ac_partsigs, troot->ac_lsigs, troot->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN)))
        return ret;

    if ((ret = cli_ac_initdata(&gmdata, groot->ac_partsigs, groot->ac_lsigs, groot->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN)))
    {
        cli_ac_freedata(&tmdata);
        return ret;
    }
    mdata[0] = &tmdata;
    mdata[1] = &gmdata;

    ret = cli_scanbuff(data, len, 0, ctx, CL_TYPE_MSOLE2, mdata);
    if (ret == CL_VIRUS)
        viruses_found++;

    if (ret == CL_CLEAN || (ret == CL_VIRUS && SCAN_ALLMATCHES))
    {
        fmap_t *map = *ctx->fmap;
        *ctx->fmap = cl_fmap_open_memory(data, len);
        if (*ctx->fmap == NULL)
            return CL_EMEM;
        ret = cli_exp_eval(ctx, troot, &tmdata, NULL, NULL);
        if (ret == CL_VIRUS)
            viruses_found++;

        if (ret == CL_CLEAN || (ret == CL_VIRUS && SCAN_ALLMATCHES))
            ret = cli_exp_eval(ctx, groot, &gmdata, NULL, NULL);
        funmap(*ctx->fmap);
        *ctx->fmap = map;
    }
    cli_ac_freedata(&tmdata);
    cli_ac_freedata(&gmdata);

    return (ret != CL_CLEAN) ? ret : viruses_found ? CL_VIRUS : CL_CLEAN;
}

static int cli_vba_scandir(const char *dirname, cli_ctx *ctx, struct uniq *U)
{
    cl_error_t ret = CL_CLEAN;
    int i, j, fd, data_len, hasmacros = 0;
    vba_project_t *vba_project;
    DIR *dd;
    struct dirent *dent;
#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
    union {
        struct dirent d;
        char b[offsetof(struct dirent, d_name) + NAME_MAX + 1];
    } result;
#endif
    STATBUF statbuf;
    char *fullname, vbaname[1024];
    unsigned char *data;
    char *hash;
    uint32_t hashcnt           = 0;
    unsigned int viruses_found = 0;

    cli_dbgmsg("VBADir: %s\n", dirname);
    if (CL_SUCCESS != (ret = uniq_get(U, "_vba_project", 12, NULL, &hashcnt))) {
        cli_dbgmsg("VBADir: uniq_get('_vba_project') failed with ret code (%d)!\n", ret);
        return ret;
    }
    while (hashcnt) {
        if (!(vba_project = (vba_project_t *)cli_vba_readdir(dirname, U, hashcnt))) {
            hashcnt--;
            continue;
        }

        for (i = 0; i < vba_project->count; i++)
        {
            for (j = 1; (unsigned int)j <= vba_project->colls[i]; j++)
            {
                snprintf(vbaname, 1024, "%s" PATHSEP "%s_%u", vba_project->dir, vba_project->name[i], j);
                vbaname[sizeof(vbaname) - 1] = '\0';
                fd = open(vbaname, O_RDONLY | O_BINARY);
                if (fd == -1) {
                    continue;
                }
                cli_dbgmsg("VBADir: Decompress VBA project '%s_%u'\n", vba_project->name[i], j);
                data = (unsigned char *)cli_vba_inflate(fd, vba_project->offset[i], &data_len);
                close(fd);
                hasmacros++;
                if (!data)
                {
                    cli_dbgmsg("VBADir: WARNING: VBA project '%s_%u' decompressed to NULL\n", vba_project->name[i], j);
                }
                else
                {
                    /* cli_dbgmsg("Project content:\n%s", data); */
                    if (ctx->scanned)
                        *ctx->scanned += data_len / CL_COUNT_PRECISION;
                    if (ctx->engine->keeptmp)
                    {
                        char *tempfile;
                        int of;

                        if ((ret = cli_gentempfd(ctx->engine->tmpdir, &tempfile, &of)) != CL_SUCCESS)
                        {
                            cli_warnmsg("VBADir: WARNING: VBA project '%s_%u' cannot be dumped to file\n", vba_project->name[i], j);
                            return ret;
                        }
                        if (cli_writen(of, data, data_len) != data_len)
                        {
                            cli_warnmsg("VBADir: WARNING: VBA project '%s_%u' failed to write to file\n", vba_project->name[i], j);
                            close(of);
                            free(tempfile);
                            return CL_EWRITE;
                        }

                        cli_dbgmsg("VBADir: VBA project '%s_%u' dumped to %s\n", vba_project->name[i], j, tempfile);
                        free(tempfile);
                    }

                    if (vba_scandata(data, data_len, ctx) == CL_VIRUS)
                    {
                        if (SCAN_ALLMATCHES)
                            viruses_found++;
                        else
                        {
                            free(data);
                            ret = CL_VIRUS;
                            break;
                        }
                    }
                    free(data);
                }
            }
        }

        cli_free_vba_project(vba_project);
        vba_project = NULL;

        if (ret == CL_VIRUS && !SCAN_ALLMATCHES)
            break;

        hashcnt--;
    }

    if (ret == CL_CLEAN || (ret == CL_VIRUS && SCAN_ALLMATCHES)) {
        if (CL_SUCCESS != (ret = uniq_get(U, "powerpoint document", 19, &hash, &hashcnt))) {
            cli_dbgmsg("VBADir: uniq_get('powerpoint document') failed with ret code (%d)!\n", ret);
            return ret;
        }
        while (hashcnt) {
            snprintf(vbaname, 1024, "%s" PATHSEP "%s_%u", dirname, hash, hashcnt);
            vbaname[sizeof(vbaname) - 1] = '\0';
            fd = open(vbaname, O_RDONLY | O_BINARY);
            if (fd == -1) {
                hashcnt--;
                continue;
            }
            if ((fullname = cli_ppt_vba_read(fd, ctx))) {
                if (cli_scandir(fullname, ctx) == CL_VIRUS) {
                    ret = CL_VIRUS;
                    viruses_found++;
                }
                if (!ctx->engine->keeptmp)
                    cli_rmdirs(fullname);
                free(fullname);
            }
            close(fd);
            hashcnt--;
        }
    }

    if (ret == CL_CLEAN || (ret == CL_VIRUS && SCAN_ALLMATCHES)) {
        if (CL_SUCCESS != (ret = uniq_get(U, "worddocument", 12, &hash, &hashcnt))) {
            cli_dbgmsg("VBADir: uniq_get('worddocument') failed with ret code (%d)!\n", ret);
            return ret;
        }
        while (hashcnt) {
            snprintf(vbaname, sizeof(vbaname), "%s" PATHSEP "%s_%u", dirname, hash, hashcnt);
            vbaname[sizeof(vbaname) - 1] = '\0';
            fd = open(vbaname, O_RDONLY | O_BINARY);
            if (fd == -1) {
                hashcnt--;
                continue;
            }

            if (!(vba_project = (vba_project_t *)cli_wm_readdir(fd)))
            {
                close(fd);
                hashcnt--;
                continue;
            }

            for (i = 0; i < vba_project->count; i++)
            {
                cli_dbgmsg("VBADir: Decompress WM project macro:%d key:%d length:%d\n", i, vba_project->key[i], vba_project->length[i]);
                data = (unsigned char *)cli_wm_decrypt_macro(fd, vba_project->offset[i], vba_project->length[i], vba_project->key[i]);
                if (!data)
                {
                    cli_dbgmsg("VBADir: WARNING: WM project '%s' macro %d decrypted to NULL\n", vba_project->name[i], i);
                }
                else
                {
                    cli_dbgmsg("Project content:\n%s", data);
                    if (ctx->scanned)
                        *ctx->scanned += vba_project->length[i] / CL_COUNT_PRECISION;
                    if (vba_scandata(data, vba_project->length[i], ctx) == CL_VIRUS)
                    {
                        if (SCAN_ALLMATCHES)
                            viruses_found++;
                        else
                        {
                            free(data);
                            ret = CL_VIRUS;
                            break;
                        }
                    }
                    free(data);
                }
            }

            close(fd);
            cli_free_vba_project(vba_project);
            vba_project = NULL;

            if (ret == CL_VIRUS) {
                if (SCAN_ALLMATCHES)
                    viruses_found++;
                else
                    break;
            }
            hashcnt--;
        }
    }

    if (ret != CL_CLEAN && !(ret == CL_VIRUS && SCAN_ALLMATCHES))
        return ret;

#if HAVE_JSON
    /* JSON Output Summary Information */
    if (SCAN_COLLECT_METADATA && (ctx->wrkproperty != NULL)) {
        if (CL_SUCCESS != (ret = uniq_get(U, "_5_summaryinformation", 21, &hash, &hashcnt))) {
            cli_dbgmsg("VBADir: uniq_get('_5_summaryinformation') failed with ret code (%d)!\n", ret);
            return ret;
        }
        while (hashcnt) {
            snprintf(vbaname, sizeof(vbaname), "%s" PATHSEP "%s_%u", dirname, hash, hashcnt);
            vbaname[sizeof(vbaname) - 1] = '\0';

            fd = open(vbaname, O_RDONLY | O_BINARY);
            if (fd >= 0)
            {
                cli_dbgmsg("VBADir: detected a '_5_summaryinformation' stream\n");
                /* JSONOLE2 - what to do if something breaks? */
                cli_ole2_summary_json(ctx, fd, 0);
                close(fd);
            }
            hashcnt--;
        }

        if (CL_SUCCESS != (ret = uniq_get(U, "_5_documentsummaryinformation", 29, &hash, &hashcnt))) {
            cli_dbgmsg("VBADir: uniq_get('_5_documentsummaryinformation') failed with ret code (%d)!\n", ret);
            return ret;
        }
        while (hashcnt) {
            snprintf(vbaname, sizeof(vbaname), "%s" PATHSEP "%s_%u", dirname, hash, hashcnt);
            vbaname[sizeof(vbaname) - 1] = '\0';

            fd = open(vbaname, O_RDONLY | O_BINARY);
            if (fd >= 0)
            {
                cli_dbgmsg("VBADir: detected a '_5_documentsummaryinformation' stream\n");
                /* JSONOLE2 - what to do if something breaks? */
                cli_ole2_summary_json(ctx, fd, 1);
                close(fd);
            }
            hashcnt--;
        }
    }
#endif

    /* Check directory for embedded OLE objects */
    if (CL_SUCCESS != (ret = uniq_get(U, "_1_ole10native", 14, &hash, &hashcnt))) {
        cli_dbgmsg("VBADir: uniq_get('_1_ole10native') failed with ret code (%d)!\n", ret);
        return ret;
    }
    while (hashcnt) {
        snprintf(vbaname, sizeof(vbaname), "%s" PATHSEP "%s_%u", dirname, hash, hashcnt);
        vbaname[sizeof(vbaname) - 1] = '\0';

        fd = open(vbaname, O_RDONLY | O_BINARY);
        if (fd >= 0)
        {
            ret = cli_scan_ole10(fd, ctx);
            close(fd);
            if (ret != CL_CLEAN && !(ret == CL_VIRUS && SCAN_ALLMATCHES))
                return ret;
        }
        hashcnt--;
    }

    /* ACAB: since we now hash filenames and handle collisions we
     * could avoid recursion by removing the block below and by
     * flattening the paths in ole2_walk_property_tree (case 1) */

    if ((dd = opendir(dirname)) != NULL)
    {
#ifdef HAVE_READDIR_R_3
        while (!readdir_r(dd, &result.d, &dent) && dent)
        {
#elif defined(HAVE_READDIR_R_2)
        while ((dent = (struct dirent *)readdir_r(dd, &result.d)))
        {
#else
        while ((dent = readdir(dd)))
        {
#endif
            if (dent->d_ino)
            {
                if (strcmp(dent->d_name, ".") && strcmp(dent->d_name, ".."))
                {
                    /* build the full name */
                    fullname = cli_malloc(strlen(dirname) + strlen(dent->d_name) + 2);
                    if (!fullname)
                    {
                        cli_dbgmsg("cli_vba_scandir: Unable to allocate memory for fullname\n");
                        ret = CL_EMEM;
                        break;
                    }
                    sprintf(fullname, "%s" PATHSEP "%s", dirname, dent->d_name);

                    /* stat the file */
                    if (LSTAT(fullname, &statbuf) != -1)
                    {
                        if (S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode))
                            if (cli_vba_scandir(fullname, ctx, U) == CL_VIRUS)
                            {
                                if (SCAN_ALLMATCHES)
                                    viruses_found++;
                                else
                                {
                                    ret = CL_VIRUS;
                                    free(fullname);
                                    break;
                                }
                            }
                    }
                    free(fullname);
                }
            }
        }
    }
    else
    {
        cli_dbgmsg("VBADir: Can't open directory %s.\n", dirname);
        return CL_EOPEN;
    }

    closedir(dd);
#if HAVE_JSON
    if (hasmacros && SCAN_COLLECT_METADATA && (ctx->wrkproperty != NULL))
        cli_jsonbool(ctx->wrkproperty, "HasMacros", 1);
#endif
    if (SCAN_HEURISTIC_MACROS && hasmacros)
    {
        ret = cli_append_virus(ctx, "Heuristics.OLE2.ContainsMacros");
        if (ret == CL_VIRUS)
            viruses_found++;
    }
    if (SCAN_ALLMATCHES && viruses_found)
        return CL_VIRUS;
    return ret;
}

static int cli_scanhtml(cli_ctx *ctx)
{
    char *tempname, fullname[1024];
    int ret = CL_CLEAN, fd;
    fmap_t *map = *ctx->fmap;
    unsigned int viruses_found = 0;
    uint64_t curr_len = map->len;

    cli_dbgmsg("in cli_scanhtml()\n");

    /* CL_ENGINE_MAX_HTMLNORMALIZE */
    if (curr_len > ctx->engine->maxhtmlnormalize)
    {
        cli_dbgmsg("cli_scanhtml: exiting (file larger than MaxHTMLNormalize)\n");
        return CL_CLEAN;
    }

    if (!(tempname = cli_gentemp(ctx->engine->tmpdir)))
        return CL_EMEM;

    if (mkdir(tempname, 0700))
    {
        cli_errmsg("cli_scanhtml: Can't create temporary directory %s\n", tempname);
        free(tempname);
        return CL_ETMPDIR;
    }

    cli_dbgmsg("cli_scanhtml: using tempdir %s\n", tempname);

    html_normalise_map(map, tempname, NULL, ctx->dconf);
    snprintf(fullname, 1024, "%s" PATHSEP "nocomment.html", tempname);
    fd = open(fullname, O_RDONLY | O_BINARY);
    if (fd >= 0)
    {
        if ((ret = cli_scandesc(fd, ctx, CL_TYPE_HTML, 0, NULL, AC_SCAN_VIR, NULL)) == CL_VIRUS)
            viruses_found++;
        close(fd);
    }

    if (ret == CL_CLEAN || (ret == CL_VIRUS && SCAN_ALLMATCHES))
    {
        /* CL_ENGINE_MAX_HTMLNOTAGS */
        curr_len = map->len;
        if (curr_len > ctx->engine->maxhtmlnotags)
        {
            /* we're not interested in scanning large files in notags form */
            /* TODO: don't even create notags if file is over limit */
            cli_dbgmsg("cli_scanhtml: skipping notags (normalized size over MaxHTMLNoTags)\n");
        }
        else
        {
            snprintf(fullname, 1024, "%s" PATHSEP "notags.html", tempname);
            fd = open(fullname, O_RDONLY | O_BINARY);
            if (fd >= 0)
            {
                if ((ret = cli_scandesc(fd, ctx, CL_TYPE_HTML, 0, NULL, AC_SCAN_VIR, NULL)) == CL_VIRUS)
                    viruses_found++;
                close(fd);
            }
        }
    }

    if (ret == CL_CLEAN || (ret == CL_VIRUS && SCAN_ALLMATCHES))
    {
        snprintf(fullname, 1024, "%s" PATHSEP "javascript", tempname);
        fd = open(fullname, O_RDONLY | O_BINARY);
        if (fd >= 0)
        {
            if ((ret = cli_scandesc(fd, ctx, CL_TYPE_HTML, 0, NULL, AC_SCAN_VIR, NULL)) == CL_VIRUS)
                viruses_found++;
            if (ret == CL_CLEAN || (ret == CL_VIRUS && SCAN_ALLMATCHES))
            {
                if ((ret = cli_scandesc(fd, ctx, CL_TYPE_TEXT_ASCII, 0, NULL, AC_SCAN_VIR, NULL)) == CL_VIRUS)
                    viruses_found++;
            }
            close(fd);
        }
    }

    if (ret == CL_CLEAN || (ret == CL_VIRUS && SCAN_ALLMATCHES))
    {
        snprintf(fullname, 1024, "%s" PATHSEP "rfc2397", tempname);
        ret = cli_scandir(fullname, ctx);
    }

    if (!ctx->engine->keeptmp)
        cli_rmdirs(tempname);

    free(tempname);
    if (SCAN_ALLMATCHES && viruses_found)
        return CL_VIRUS;
    return ret;
}

static int cli_scanscript(cli_ctx *ctx)
{
    const unsigned char *buff;
    unsigned char *normalized;
    struct text_norm_state state;
    char *tmpname = NULL;
    int ofd = -1, ret;
    struct cli_matcher *troot;
    uint32_t maxpatlen, offset = 0;
    struct cli_matcher *groot;
    struct cli_ac_data gmdata, tmdata;
    struct cli_ac_data *mdata[2];
    fmap_t *map;
    size_t at = 0;
    unsigned int viruses_found = 0;
    uint64_t curr_len;
    struct cli_target_info info;

    if (!ctx || !ctx->engine->root)
        return CL_ENULLARG;

    map = *ctx->fmap;
    curr_len = map->len;
    groot = ctx->engine->root[0];
    troot = ctx->engine->root[7];
    maxpatlen = troot ? troot->maxpatlen : 0;

    cli_dbgmsg("in cli_scanscript()\n");

    /* CL_ENGINE_MAX_SCRIPTNORMALIZE */
    if (curr_len > ctx->engine->maxscriptnormalize)
    {
        cli_dbgmsg("cli_scanscript: exiting (file larger than MaxScriptSize)\n");
        return CL_CLEAN;
    }

    if (!(normalized = cli_malloc(SCANBUFF + maxpatlen)))
    {
        cli_dbgmsg("cli_scanscript: Unable to malloc %u bytes\n", SCANBUFF);
        return CL_EMEM;
    }
    text_normalize_init(&state, normalized, SCANBUFF + maxpatlen);

    if ((ret = cli_ac_initdata(&tmdata, troot ? troot->ac_partsigs : 0, troot ? troot->ac_lsigs : 0, troot ? troot->ac_reloff_num : 0, CLI_DEFAULT_AC_TRACKLEN)))
    {
        free(normalized);
        return ret;
    }

    if ((ret = cli_ac_initdata(&gmdata, groot->ac_partsigs, groot->ac_lsigs, groot->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN)))
    {
        cli_ac_freedata(&tmdata);
        free(normalized);
        return ret;
    }

    /* dump to disk only if explicitly asked to
     * or if necessary to check relative offsets,
     * otherwise we can process just in-memory */
    if (ctx->engine->keeptmp || (troot && (troot->ac_reloff_num > 0 || troot->linked_bcs)))
    {
        if ((ret = cli_gentempfd(ctx->engine->tmpdir, &tmpname, &ofd)))
        {
            cli_dbgmsg("cli_scanscript: Can't generate temporary file/descriptor\n");
            goto done;
        }
        if (ctx->engine->keeptmp)
            cli_dbgmsg("cli_scanscript: saving normalized file to %s\n", tmpname);
    }

    mdata[0] = &tmdata;
    mdata[1] = &gmdata;

    /* If there's a relative offset in troot or triggered bytecodes, normalize to file.*/
    if (troot && (troot->ac_reloff_num > 0 || troot->linked_bcs))
    {
        size_t map_off = 0;
        while (map_off < map->len)
        {
            size_t written;
            if (!(written = text_normalize_map(&state, map, map_off)))
                break;
            map_off += written;

            if (write(ofd, state.out, state.out_pos) == -1)
            {
                cli_errmsg("cli_scanscript: can't write to file %s\n", tmpname);
                ret = CL_EWRITE;
                goto done;
            }
            text_normalize_reset(&state);
        }

        /* Temporarily store the normalized file map in the context. */
        *ctx->fmap = fmap(ofd, 0, 0);
        if (!(*ctx->fmap))
        {
            cli_dbgmsg("cli_scanscript: could not map file %s\n", tmpname);
        }
        else
        {

            /* scan map */
            ret = cli_fmap_scandesc(ctx, CL_TYPE_TEXT_ASCII, 0, NULL, AC_SCAN_VIR, NULL, NULL);
            if (ret == CL_VIRUS)
            {
                viruses_found++;
            }
            funmap(*ctx->fmap);
        }
        *ctx->fmap = map;
    }
    else
    {
        /* Since the above is moderately costly all in all,
         * do the old stuff if there's no relative offsets. */

        if (troot)
        {
            cli_targetinfo(&info, 7, map);
            ret = cli_ac_caloff(troot, &tmdata, &info);
            if (ret)
                goto done;
        }

        while (1)
        {
            size_t len = MIN(map->pgsz, map->len - at);
            buff = fmap_need_off_once(map, at, len);
            at += len;
            if (!buff || !len || state.out_pos + len > state.out_len)
            {
                /* flush if error/EOF, or too little buffer space left */
                if ((ofd != -1) && (write(ofd, state.out, state.out_pos) == -1))
                {
                    cli_errmsg("cli_scanscript: can't write to file %s\n", tmpname);
                    close(ofd);
                    ofd = -1;
                    /* we can continue to scan in memory */
                }
                /* when we flush the buffer also scan */
                if (cli_scanbuff(state.out, state.out_pos, offset, ctx, CL_TYPE_TEXT_ASCII, mdata) == CL_VIRUS)
                {
                    if (SCAN_ALLMATCHES)
                        viruses_found++;
                    else
                    {
                        ret = CL_VIRUS;
                        break;
                    }
                }
                if (ctx->scanned)
                    *ctx->scanned += state.out_pos / CL_COUNT_PRECISION;
                offset += state.out_pos;
                /* carry over maxpatlen from previous buffer */
                if (state.out_pos > maxpatlen)
                    memmove(state.out, state.out + state.out_pos - maxpatlen, maxpatlen);
                text_normalize_reset(&state);
                state.out_pos = maxpatlen;
            }
            if (!len)
                break;
            if (!buff || text_normalize_buffer(&state, buff, len) != len)
            {
                cli_dbgmsg("cli_scanscript: short read during normalizing\n");
            }
        }
    }

    if (ret != CL_VIRUS || SCAN_ALLMATCHES)
    {
        if ((ret = cli_exp_eval(ctx, troot, &tmdata, NULL, NULL)) == CL_VIRUS)
            viruses_found++;
        if (ret != CL_VIRUS || SCAN_ALLMATCHES)
            if ((ret = cli_exp_eval(ctx, groot, &gmdata, NULL, NULL)) == CL_VIRUS)
                viruses_found++;
    }

done:
    free(normalized);
    cli_ac_freedata(&tmdata);
    cli_ac_freedata(&gmdata);

    if (ofd != -1)
        close(ofd);
    if (tmpname != NULL)
    {
        if (!ctx->engine->keeptmp)
            cli_unlink(tmpname);
        free(tmpname);
    }

    if (viruses_found)
        return CL_VIRUS;

    return ret;
}

static int cli_scanhtml_utf16(cli_ctx *ctx)
{
    char *tempname, *decoded;
    const char *buff;
    int ret = CL_CLEAN, fd, bytes;
    size_t at = 0;
    fmap_t *map = *ctx->fmap;

    cli_dbgmsg("in cli_scanhtml_utf16()\n");

    if (!(tempname = cli_gentemp(ctx->engine->tmpdir)))
        return CL_EMEM;

    if ((fd = open(tempname, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, S_IRWXU)) < 0)
    {
        cli_errmsg("cli_scanhtml_utf16: Can't create file %s\n", tempname);
        free(tempname);
        return CL_EOPEN;
    }

    cli_dbgmsg("cli_scanhtml_utf16: using tempfile %s\n", tempname);

    while (at < map->len)
    {
        bytes = MIN(map->len - at, map->pgsz * 16);
        if (!(buff = fmap_need_off_once(map, at, bytes)))
        {
            close(fd);
            cli_unlink(tempname);
            free(tempname);
            return CL_EREAD;
        }
        at += bytes;
        decoded = cli_utf16toascii(buff, bytes);
        if (decoded)
        {
            if (write(fd, decoded, bytes / 2) == -1)
            {
                cli_errmsg("cli_scanhtml_utf16: Can't write to file %s\n", tempname);
                free(decoded);
                close(fd);
                cli_unlink(tempname);
                free(tempname);
                return CL_EWRITE;
            }
            free(decoded);
        }
    }

    *ctx->fmap = fmap(fd, 0, 0);
    if (*ctx->fmap)
    {
        ret = cli_scanhtml(ctx);
        funmap(*ctx->fmap);
    }
    else
        cli_errmsg("cli_scanhtml_utf16: fmap of %s failed\n", tempname);

    *ctx->fmap = map;
    close(fd);

    if (!ctx->engine->keeptmp)
    {
        if (cli_unlink(tempname))
            ret = CL_EUNLINK;
    }
    else
        cli_dbgmsg("cli_scanhtml_utf16: Decoded HTML data saved in %s\n", tempname);
    free(tempname);

    return ret;
}

static int cli_scanole2(cli_ctx *ctx)
{
    char *dir;
    int ret = CL_CLEAN;
    struct uniq *vba = NULL;

    cli_dbgmsg("in cli_scanole2()\n");

    if (ctx->engine->maxreclevel && ctx->recursion >= ctx->engine->maxreclevel)
        return CL_EMAXREC;

    /* generate the temporary directory */
    if (!(dir = cli_gentemp(ctx->engine->tmpdir)))
        return CL_EMEM;

    if (mkdir(dir, 0700))
    {
        cli_dbgmsg("OLE2: Can't create temporary directory %s\n", dir);
        free(dir);
        return CL_ETMPDIR;
    }

    ret = cli_ole2_extract(dir, ctx, &vba);
    if (ret != CL_CLEAN && ret != CL_VIRUS)
    {
        cli_dbgmsg("OLE2: %s\n", cl_strerror(ret));
        if (!ctx->engine->keeptmp)
            cli_rmdirs(dir);
        free(dir);
        return ret;
    }

    if (vba)
    {
        ctx->recursion++;

        ret = cli_vba_scandir(dir, ctx, vba);
        uniq_free(vba);
        if (ret != CL_VIRUS)
            if (cli_scandir(dir, ctx) == CL_VIRUS)
                ret = CL_VIRUS;
        ctx->recursion--;
    }

    if (!ctx->engine->keeptmp)
        cli_rmdirs(dir);
    free(dir);
    return ret;
}

static int cli_scantar(cli_ctx *ctx, unsigned int posix)
{
    char *dir;
    int ret = CL_CLEAN;

    cli_dbgmsg("in cli_scantar()\n");

    /* generate temporary directory */
    if (!(dir = cli_gentemp(ctx->engine->tmpdir)))
        return CL_EMEM;

    if (mkdir(dir, 0700))
    {
        cli_errmsg("Tar: Can't create temporary directory %s\n", dir);
        free(dir);
        return CL_ETMPDIR;
    }

    ret = cli_untar(dir, posix, ctx);

    if (!ctx->engine->keeptmp)
        cli_rmdirs(dir);

    free(dir);
    return ret;
}

static int cli_scanscrenc(cli_ctx *ctx)
{
    char *tempname;
    int ret = CL_CLEAN;

    cli_dbgmsg("in cli_scanscrenc()\n");

    if (!(tempname = cli_gentemp(ctx->engine->tmpdir)))
        return CL_EMEM;

    if (mkdir(tempname, 0700))
    {
        cli_dbgmsg("CHM: Can't create temporary directory %s\n", tempname);
        free(tempname);
        return CL_ETMPDIR;
    }

    if (html_screnc_decode(*ctx->fmap, tempname))
        ret = cli_scandir(tempname, ctx);

    if (!ctx->engine->keeptmp)
        cli_rmdirs(tempname);

    free(tempname);
    return ret;
}

static int cli_scanriff(cli_ctx *ctx)
{
    int ret = CL_CLEAN;

    if (cli_check_riff_exploit(ctx) == 2)
        ret = cli_append_virus(ctx, "Heuristics.Exploit.W32.MS05-002");

    return ret;
}

static int cli_scanjpeg(cli_ctx *ctx)
{
    int ret = CL_CLEAN;

    if (cli_check_jpeg_exploit(ctx, 0) == 1)
        ret = cli_append_virus(ctx, "Heuristics.Exploit.W32.MS04-028");

    return ret;
}

static int cli_scancryptff(cli_ctx *ctx)
{
    int ret = CL_CLEAN, ndesc;
    unsigned int i;
    const unsigned char *src;
    unsigned char *dest = NULL;
    char *tempfile;
    size_t pos;
    size_t bread;

    /* Skip the CryptFF file header */
    pos = 0x10;

    if ((dest = (unsigned char *)cli_malloc(FILEBUFF)) == NULL)
    {
        cli_dbgmsg("CryptFF: Can't allocate memory\n");
        return CL_EMEM;
    }

    if (!(tempfile = cli_gentemp(ctx->engine->tmpdir)))
    {
        free(dest);
        return CL_EMEM;
    }

    if ((ndesc = open(tempfile, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, S_IRWXU)) < 0)
    {
        cli_errmsg("CryptFF: Can't create file %s\n", tempfile);
        free(dest);
        free(tempfile);
        return CL_ECREAT;
    }

    for (; (src = fmap_need_off_once_len(*ctx->fmap, pos, FILEBUFF, &bread)) && bread; pos += bread)
    {
        for (i = 0; i < bread; i++)
            dest[i] = src[i] ^ (unsigned char)0xff;
        if (cli_writen(ndesc, dest, bread) == -1)
        {
            cli_dbgmsg("CryptFF: Can't write to descriptor %d\n", ndesc);
            free(dest);
            close(ndesc);
            free(tempfile);
            return CL_EWRITE;
        }
    }

    free(dest);

    cli_dbgmsg("CryptFF: Scanning decrypted data\n");

    if ((ret = cli_magic_scandesc(ndesc, tempfile, ctx)) == CL_VIRUS)
        cli_dbgmsg("CryptFF: Infected with %s\n", cli_get_last_virus(ctx));

    close(ndesc);

    if (ctx->engine->keeptmp)
        cli_dbgmsg("CryptFF: Decompressed data saved in %s\n", tempfile);
    else if (cli_unlink(tempfile))
        ret = CL_EUNLINK;

    free(tempfile);
    return ret;
}

static int cli_scanpdf(cli_ctx *ctx, off_t offset)
{
    int ret;
    char *dir = cli_gentemp(ctx->engine->tmpdir);

    if (!dir)
        return CL_EMEM;

    if (mkdir(dir, 0700))
    {
        cli_dbgmsg("Can't create temporary directory for PDF file %s\n", dir);
        free(dir);
        return CL_ETMPDIR;
    }

    ret = cli_pdf(dir, ctx, offset);

    if (!ctx->engine->keeptmp)
        cli_rmdirs(dir);

    free(dir);
    return ret;
}

static int cli_scantnef(cli_ctx *ctx)
{
    int ret;
    char *dir = cli_gentemp(ctx->engine->tmpdir);

    if (!dir)
        return CL_EMEM;

    if (mkdir(dir, 0700))
    {
        cli_dbgmsg("Can't create temporary directory for tnef file %s\n", dir);
        free(dir);
        return CL_ETMPDIR;
    }

    ret = cli_tnef(dir, ctx);

    if (ret == CL_CLEAN)
        ret = cli_scandir(dir, ctx);

    if (!ctx->engine->keeptmp)
        cli_rmdirs(dir);

    free(dir);
    return ret;
}

static int cli_scanuuencoded(cli_ctx *ctx)
{
    int ret;
    char *dir = cli_gentemp(ctx->engine->tmpdir);

    if (!dir)
        return CL_EMEM;

    if (mkdir(dir, 0700))
    {
        cli_dbgmsg("Can't create temporary directory for uuencoded file %s\n", dir);
        free(dir);
        return CL_ETMPDIR;
    }

    ret = cli_uuencode(dir, *ctx->fmap);

    if (ret == CL_CLEAN)
        ret = cli_scandir(dir, ctx);

    if (!ctx->engine->keeptmp)
        cli_rmdirs(dir);

    free(dir);
    return ret;
}

static int cli_scanmail(cli_ctx *ctx)
{
    char *dir;
    int ret;
    unsigned int viruses_found = 0;

    cli_dbgmsg("Starting cli_scanmail(), recursion = %u\n", ctx->recursion);

    /* generate the temporary directory */
    if (!(dir = cli_gentemp(ctx->engine->tmpdir)))
        return CL_EMEM;

    if (mkdir(dir, 0700))
    {
        cli_dbgmsg("Mail: Can't create temporary directory %s\n", dir);
        free(dir);
        return CL_ETMPDIR;
    }

    /*
     * Extract the attachments into the temporary directory
     */
    if ((ret = cli_mbox(dir, ctx)))
    {
        if (ret == CL_VIRUS && SCAN_ALLMATCHES)
            viruses_found++;
        else
        {
            if (!ctx->engine->keeptmp)
                cli_rmdirs(dir);
            free(dir);
            return ret;
        }
    }

    ret = cli_scandir(dir, ctx);

    if (!ctx->engine->keeptmp)
        cli_rmdirs(dir);

    free(dir);
    if (viruses_found)
        return CL_VIRUS;
    return ret;
}

static int cli_scan_structured(cli_ctx *ctx)
{
    char buf[8192];
    int result = 0;
    unsigned int cc_count = 0;
    unsigned int ssn_count = 0;
    int done = 0;
    fmap_t *map;
    size_t pos = 0;
    int (*ccfunc)(const unsigned char *buffer, int length);
    int (*ssnfunc)(const unsigned char *buffer, int length);
    unsigned int viruses_found = 0;

    if (ctx == NULL)
        return CL_ENULLARG;

    map = *ctx->fmap;

    if (ctx->engine->min_cc_count == 1)
        ccfunc = dlp_has_cc;
    else
        ccfunc = dlp_get_cc_count;

    switch (SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL | SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED)
    {
    case (CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL | CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED):
        if (ctx->engine->min_ssn_count == 1)
            ssnfunc = dlp_has_ssn;
        else
            ssnfunc = dlp_get_ssn_count;
        break;

    case CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL:
        if (ctx->engine->min_ssn_count == 1)
            ssnfunc = dlp_has_normal_ssn;
        else
            ssnfunc = dlp_get_normal_ssn_count;
        break;

    case CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED:
        if (ctx->engine->min_ssn_count == 1)
            ssnfunc = dlp_has_stripped_ssn;
        else
            ssnfunc = dlp_get_stripped_ssn_count;
        break;

    default:
        ssnfunc = NULL;
    }

    while (!done && ((result = fmap_readn(map, buf, pos, 8191)) > 0))
    {
        pos += result;
        if ((cc_count += ccfunc((const unsigned char *)buf, result)) >= ctx->engine->min_cc_count)
        {
            done = 1;
        }

        if (ssnfunc && ((ssn_count += ssnfunc((const unsigned char *)buf, result)) >= ctx->engine->min_ssn_count))
        {
            done = 1;
        }
    }

    if (cc_count != 0 && cc_count >= ctx->engine->min_cc_count)
    {
        cli_dbgmsg("cli_scan_structured: %u credit card numbers detected\n", cc_count);
        if (CL_VIRUS == cli_append_virus(ctx, "Heuristics.Structured.CreditCardNumber"))
        {
            if (SCAN_ALLMATCHES)
            {
                viruses_found++;
            }
            else
            {
                return CL_VIRUS;
            }
        }
    }

    if (ssn_count != 0 && ssn_count >= ctx->engine->min_ssn_count)
    {
        cli_dbgmsg("cli_scan_structured: %u social security numbers detected\n", ssn_count);
        if (CL_VIRUS == cli_append_virus(ctx, "Heuristics.Structured.SSN"))
        {
            if (SCAN_ALLMATCHES)
            {
                viruses_found++;
            }
            else
            {
                return CL_VIRUS;
            }
        }
    }

    if (viruses_found)
        return CL_VIRUS;
    return CL_CLEAN;
}

static int cli_scanembpe(cli_ctx *ctx, off_t offset)
{
    int fd, bytes, ret = CL_CLEAN;
    unsigned long int size = 0, todo;
    const char *buff;
    char *tmpname;
    fmap_t *map = *ctx->fmap;
    unsigned int corrupted_input;

    tmpname = cli_gentemp(ctx->engine->tmpdir);
    if (!tmpname)
        return CL_EMEM;

    if ((fd = open(tmpname, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, S_IRWXU)) < 0)
    {
        cli_errmsg("cli_scanembpe: Can't create file %s\n", tmpname);
        free(tmpname);
        return CL_ECREAT;
    }

    todo = map->len - offset;
    while (1)
    {
        bytes = MIN(todo, map->pgsz);
        if (!bytes)
            break;

        if (!(buff = fmap_need_off_once(map, offset + size, bytes)))
        {
            close(fd);
            if (!ctx->engine->keeptmp)
            {
                if (cli_unlink(tmpname))
                {
                    free(tmpname);
                    return CL_EUNLINK;
                }
            }
            free(tmpname);
            return CL_EREAD;
        }
        size += bytes;
        todo -= bytes;

        if (cli_checklimits("cli_scanembpe", ctx, size, 0, 0) != CL_CLEAN)
            break;

        if (cli_writen(fd, buff, bytes) != bytes)
        {
            cli_dbgmsg("cli_scanembpe: Can't write to temporary file\n");
            close(fd);
            if (!ctx->engine->keeptmp)
            {
                if (cli_unlink(tmpname))
                {
                    free(tmpname);
                    return CL_EUNLINK;
                }
            }
            free(tmpname);
            return CL_EWRITE;
        }
    }

    ctx->recursion++;
    corrupted_input = ctx->corrupted_input;
    ctx->corrupted_input = 1;
    ret = cli_magic_scandesc(fd, tmpname, ctx);
    ctx->corrupted_input = corrupted_input;
    if (ret == CL_VIRUS)
    {
        cli_dbgmsg("cli_scanembpe: Infected with %s\n", cli_get_last_virus(ctx));
        close(fd);
        if (!ctx->engine->keeptmp)
        {
            if (cli_unlink(tmpname))
            {
                free(tmpname);
                return CL_EUNLINK;
            }
        }
        free(tmpname);
        return CL_VIRUS;
    }
    ctx->recursion--;

    close(fd);
    if (!ctx->engine->keeptmp)
    {
        if (cli_unlink(tmpname))
        {
            free(tmpname);
            return CL_EUNLINK;
        }
    }
    free(tmpname);

    /* intentionally ignore possible errors from cli_magic_scandesc */
    return CL_CLEAN;
}

#if defined(_WIN32) || defined(C_LINUX) || defined(C_DARWIN)
#define PERF_MEASURE
#endif

#ifdef PERF_MEASURE

static struct
{
    enum perfev id;
    const char *name;
    enum ev_type type;
} perf_events[] = {
    {PERFT_SCAN, "full scan", ev_time},
    {PERFT_PRECB, "prescan cb", ev_time},
    {PERFT_POSTCB, "postscan cb", ev_time},
    {PERFT_CACHE, "cache", ev_time},
    {PERFT_FT, "filetype", ev_time},
    {PERFT_CONTAINER, "container", ev_time},
    {PERFT_SCRIPT, "script", ev_time},
    {PERFT_PE, "pe", ev_time},
    {PERFT_RAW, "raw", ev_time},
    {PERFT_RAWTYPENO, "raw container", ev_time},
    {PERFT_MAP, "map", ev_time},
    {PERFT_BYTECODE, "bytecode", ev_time},
    {PERFT_KTIME, "kernel", ev_int},
    {PERFT_UTIME, "user", ev_int}};

static void get_thread_times(uint64_t *kt, uint64_t *ut)
{
#ifdef _WIN32
    FILETIME c, e, k, u;
    ULARGE_INTEGER kl, ul;
    if (!GetThreadTimes(GetCurrentThread(), &c, &e, &k, &u))
    {
        *kt = *ut = 0;
        return;
    }
    kl.LowPart = k.dwLowDateTime;
    kl.HighPart = k.dwHighDateTime;
    ul.LowPart = u.dwLowDateTime;
    ul.HighPart = u.dwHighDateTime;
    *kt = kl.QuadPart / 10;
    *ut = ul.QuadPart / 10;
#else
    struct tms tbuf;
    if (times(&tbuf) != -1)
    {
        clock_t tck = sysconf(_SC_CLK_TCK);
        *kt = ((uint64_t)1000000) * tbuf.tms_stime / tck;
        *ut = ((uint64_t)1000000) * tbuf.tms_utime / tck;
    }
    else
    {
        *kt = *ut = 0;
    }
#endif
}

static inline void perf_init(cli_ctx *ctx)
{
    uint64_t kt, ut;
    unsigned i;

    if (!SCAN_DEV_COLLECT_PERF_INFO)
        return;

    ctx->perf = cli_events_new(PERFT_LAST);
    for (i = 0; i < sizeof(perf_events) / sizeof(perf_events[0]); i++)
    {
        if (cli_event_define(ctx->perf, perf_events[i].id, perf_events[i].name,
                             perf_events[i].type, multiple_sum) == -1)
            continue;
    }
    cli_event_time_start(ctx->perf, PERFT_SCAN);
    get_thread_times(&kt, &ut);
    cli_event_int(ctx->perf, PERFT_KTIME, -kt);
    cli_event_int(ctx->perf, PERFT_UTIME, -ut);
}

static inline void perf_done(cli_ctx *ctx)
{
    char timestr[512];
    char *p;
    unsigned i;
    uint64_t kt, ut;
    char *pend;
    cli_events_t *perf = ctx->perf;

    if (!perf)
        return;

    p = timestr;
    pend = timestr + sizeof(timestr) - 1;
    *pend = 0;

    cli_event_time_stop(perf, PERFT_SCAN);
    get_thread_times(&kt, &ut);
    cli_event_int(perf, PERFT_KTIME, kt);
    cli_event_int(perf, PERFT_UTIME, ut);

    for (i = 0; i < sizeof(perf_events) / sizeof(perf_events[0]); i++)
    {
        union ev_val val;
        unsigned count;

        cli_event_get(perf, perf_events[i].id, &val, &count);
        if (p < pend)
            p += snprintf(p, pend - p, "%s: %d.%03ums, ", perf_events[i].name,
                          (signed)(val.v_int / 1000),
                          (unsigned)(val.v_int % 1000));
    }
    *p = 0;
    cli_infomsg(ctx, "performance: %s\n", timestr);

    cli_events_free(perf);
    ctx->perf = NULL;
}

static inline void perf_start(cli_ctx *ctx, int id)
{
    cli_event_time_start(ctx->perf, id);
}

static inline void perf_stop(cli_ctx *ctx, int id)
{
    cli_event_time_stop(ctx->perf, id);
}

static inline void perf_nested_start(cli_ctx *ctx, int id, int nestedid)
{
    cli_event_time_nested_start(ctx->perf, id, nestedid);
}

static inline void perf_nested_stop(cli_ctx *ctx, int id, int nestedid)
{
    cli_event_time_nested_stop(ctx->perf, id, nestedid);
}

#else
static inline void perf_init(cli_ctx *ctx)
{
    UNUSEDPARAM(ctx);
}
static inline void perf_start(cli_ctx *ctx, int id)
{
    UNUSEDPARAM(ctx);
    UNUSEDPARAM(id);
}
static inline void perf_stop(cli_ctx *ctx, int id)
{
    UNUSEDPARAM(ctx);
    UNUSEDPARAM(id);
}
static inline void perf_nested_start(cli_ctx *ctx, int id, int nestedid)
{
    UNUSEDPARAM(ctx);
    UNUSEDPARAM(id);
    UNUSEDPARAM(nestedid);
}
static inline void perf_nested_stop(cli_ctx *ctx, int id, int nestedid)
{
    UNUSEDPARAM(ctx);
    UNUSEDPARAM(id);
    UNUSEDPARAM(nestedid);
}
static inline void perf_done(cli_ctx *ctx) { UNUSEDPARAM(ctx); }
#endif

static int cli_scanraw(cli_ctx *ctx, cli_file_t type, uint8_t typercg, cli_file_t *dettype, unsigned char *refhash)
{
    int ret = CL_CLEAN, nret = CL_CLEAN;
    struct cli_matched_type *ftoffset = NULL, *fpt;
    struct cli_exe_info peinfo;
    unsigned int acmode = AC_SCAN_VIR, break_loop = 0;
    fmap_t *map = *ctx->fmap;

    if (ctx->engine->maxreclevel && ctx->recursion >= ctx->engine->maxreclevel)
    {
        cli_check_blockmax(ctx, CL_EMAXREC);
        return CL_EMAXREC;
    }

    perf_start(ctx, PERFT_RAW);
    if (typercg)
        acmode |= AC_SCAN_FT;

    ret = cli_fmap_scandesc(ctx, type == CL_TYPE_TEXT_ASCII ? 0 : type, 0, &ftoffset, acmode, NULL, refhash);
    perf_stop(ctx, PERFT_RAW);

    if (ret >= CL_TYPENO)
    {
        perf_nested_start(ctx, PERFT_RAWTYPENO, PERFT_SCAN);
        ctx->recursion++;
        fpt = ftoffset;

        while (fpt)
        {
            /* set current level as container AFTER recursing */
            cli_set_container(ctx, fpt->type, map->len);
            if (fpt->offset)
                switch (fpt->type)
                {
                case CL_TYPE_MHTML:
                    if (SCAN_PARSE_MAIL && (DCONF_MAIL & MAIL_CONF_MBOX))
                    {
                        cli_dbgmsg("MHTML signature found at %u\n", (unsigned int)fpt->offset);
                        nret = ret = cli_scanmail(ctx);
                    }
                    break;

                case CL_TYPE_XDP:
                    if (SCAN_PARSE_PDF && (DCONF_DOC & DOC_CONF_PDF))
                    {
                        cli_dbgmsg("XDP signature found at %u\n", (unsigned int)fpt->offset);
                        nret = ret = cli_scanxdp(ctx);
                    }
                    break;
                case CL_TYPE_XML_WORD:
                    if (SCAN_PARSE_XMLDOCS && (DCONF_DOC & DOC_CONF_MSXML))
                    {
                        cli_dbgmsg("XML-WORD signature found at %u\n", (unsigned int)fpt->offset);
                        nret = ret = cli_scanmsxml(ctx);
                    }
                    break;
                case CL_TYPE_XML_XL:
                    if (SCAN_PARSE_XMLDOCS && (DCONF_DOC & DOC_CONF_MSXML))
                    {
                        cli_dbgmsg("XML-XL signature found at %u\n", (unsigned int)fpt->offset);
                        nret = ret = cli_scanmsxml(ctx);
                    }
                    break;
                case CL_TYPE_XML_HWP:
                    if (SCAN_PARSE_XMLDOCS && (DCONF_DOC & DOC_CONF_HWP))
                    {
                        cli_dbgmsg("XML-HWP signature found at %u\n", (unsigned int)fpt->offset);
                        nret = ret = cli_scanhwpml(ctx);
                    }
                    break;
                case CL_TYPE_RARSFX:
                    if (type != CL_TYPE_RAR && have_rar && SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_RAR))
                    {
                        const char *filepath = NULL;
                        int fd = -1;

                        char *tmpname = NULL;
                        int tmpfd = -1;
                        size_t csize = map->len - fpt->offset; /* not precise */

                        cli_set_container(ctx, CL_TYPE_RAR, csize);
                        cli_dbgmsg("RAR/RAR-SFX signature found at %u\n", (unsigned int)fpt->offset);

#ifdef _WIN32
                        if ((fpt->offset != 0) || (SCAN_UNPRIVILEGED)|| (NULL == ctx->sub_filepath) || (0 != _access_s(ctx->sub_filepath, R_OK))) {
#else
                        if ((fpt->offset != 0) || (SCAN_UNPRIVILEGED) || (NULL == ctx->sub_filepath) || (0 != access(ctx->sub_filepath, R_OK))) {
#endif
                            /*
                             * If map is not file-backed, or offset is not at the start of the file...
                             * ...have to dump to file for scanrar.
                             */
                            nret = fmap_dump_to_file(map, ctx->sub_filepath, ctx->engine->tmpdir, &tmpname, &tmpfd, fpt->offset, fpt->offset + csize);
                            if (nret != CL_SUCCESS) {
                                cli_dbgmsg("cli_scanraw: failed to generate temporary file.\n");
                                ret = nret;
                                break_loop = 1;
                                break;
                            }
                            filepath = tmpname;
                            fd = tmpfd;
                        } else {
                            /* Use the original file and file descriptor. */
                            filepath = ctx->sub_filepath;
                            fd = fmap_fd(map);
                        }

                        /* scan file */
                        nret = cli_scanrar(filepath, fd, ctx);

                        if ((NULL == tmpname) && (CL_EOPEN == nret)) {
                            /*
                             * Failed to open the file using the original filename.
                             * Try writing the file descriptor to a temp file and try again.
                             */
                            nret = fmap_dump_to_file(map, ctx->sub_filepath, ctx->engine->tmpdir, &tmpname, &tmpfd, fpt->offset, fpt->offset + csize);
                            if (nret != CL_SUCCESS) {
                                cli_dbgmsg("cli_scanraw: failed to generate temporary file.\n");
                                ret = nret;
                                break_loop = 1;
                                break;
                            }
                            filepath = tmpname;
                            fd = tmpfd;

                            /* try to scan again */
                            nret = cli_scanrar(filepath, fd, ctx);
                        }

                        if (tmpfd != -1)
                        {
                            /* If dumped tempfile, need to cleanup */
                            close(tmpfd);
                            if (!ctx->engine->keeptmp) {
                                if (cli_unlink(tmpname)) {
                                    ret = nret = CL_EUNLINK;
                                    break_loop = 1;
                                }
                            }
                        }

                        if (tmpname != NULL) {
                            free(tmpname);
                        }
                    }
                    break;

                case CL_TYPE_ZIPSFX:
                    if (type != CL_TYPE_ZIP && SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ZIP))
                    {
                        size_t csize = map->len - fpt->offset; /* not precise */
                        cli_set_container(ctx, CL_TYPE_ZIP, csize);
                        cli_dbgmsg("ZIP/ZIP-SFX signature found at %u\n", (unsigned int)fpt->offset);
                        nret = cli_unzip_single(ctx, fpt->offset);
                    }
                    break;

                case CL_TYPE_CABSFX:
                    if (type != CL_TYPE_MSCAB && SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_CAB))
                    {
                        size_t csize = map->len - fpt->offset; /* not precise */
                        cli_set_container(ctx, CL_TYPE_MSCAB, csize);
                        cli_dbgmsg("CAB/CAB-SFX signature found at %u\n", (unsigned int)fpt->offset);
                        nret = cli_scanmscab(ctx, fpt->offset);
                    }
                    break;

                case CL_TYPE_ARJSFX:
                    if (type != CL_TYPE_ARJ && SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ARJ))
                    {
                        size_t csize = map->len - fpt->offset; /* not precise */
                        cli_set_container(ctx, CL_TYPE_ARJ, csize);
                        cli_dbgmsg("ARJ-SFX signature found at %u\n", (unsigned int)fpt->offset);
                        nret = cli_scanarj(ctx, fpt->offset);
                    }
                    break;

                case CL_TYPE_7ZSFX:
                    if (type != CL_TYPE_7Z && SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_7Z))
                    {
                        size_t csize = map->len - fpt->offset; /* not precise */
                        cli_set_container(ctx, CL_TYPE_7Z, csize);
                        cli_dbgmsg("7Zip-SFX signature found at %u\n", (unsigned int)fpt->offset);
                        nret = cli_7unz(ctx, fpt->offset);
                    }
                    break;

                case CL_TYPE_ISO9660:
                    if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ISO9660))
                    {
                        size_t csize = map->len - fpt->offset; /* not precise */
                        cli_set_container(ctx, CL_TYPE_ISO9660, csize);
                        cli_dbgmsg("ISO9660 signature found at %u\n", (unsigned int)fpt->offset);
                        nret = cli_scaniso(ctx, fpt->offset);
                    }
                    break;

                case CL_TYPE_NULSFT:
                    if (SCAN_PARSE_ARCHIVE && type == CL_TYPE_MSEXE && (DCONF_ARCH & ARCH_CONF_NSIS) &&
                        fpt->offset > 4)
                    {
                        size_t csize = map->len - fpt->offset; /* not precise */
                        cli_set_container(ctx, CL_TYPE_NULSFT, csize);
                        cli_dbgmsg("NSIS signature found at %u\n", (unsigned int)fpt->offset - 4);
                        nret = cli_scannulsft(ctx, fpt->offset - 4);
                    }
                    break;

                case CL_TYPE_AUTOIT:
                    if (SCAN_PARSE_ARCHIVE && type == CL_TYPE_MSEXE && (DCONF_ARCH & ARCH_CONF_AUTOIT))
                    {
                        size_t csize = map->len - fpt->offset; /* not precise */
                        cli_set_container(ctx, CL_TYPE_AUTOIT, csize);
                        cli_dbgmsg("AUTOIT signature found at %u\n", (unsigned int)fpt->offset);
                        nret = cli_scanautoit(ctx, fpt->offset + 23);
                    }
                    break;

                case CL_TYPE_ISHIELD_MSI:
                    if (SCAN_PARSE_ARCHIVE && type == CL_TYPE_MSEXE && (DCONF_ARCH & ARCH_CONF_ISHIELD))
                    {
                        size_t csize = map->len - fpt->offset; /* not precise */
                        cli_set_container(ctx, CL_TYPE_AUTOIT, csize);
                        cli_dbgmsg("ISHIELD-MSI signature found at %u\n", (unsigned int)fpt->offset);
                        nret = cli_scanishield_msi(ctx, fpt->offset + 14);
                    }
                    break;

                case CL_TYPE_DMG:
                    if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_DMG))
                    {
                        cli_dbgmsg("DMG signature found at %u\n", (unsigned int)fpt->offset);
                        nret = cli_scandmg(ctx);
                    }
                    break;

                case CL_TYPE_MBR:
                    if (SCAN_PARSE_ARCHIVE)
                    {
                        int iret = cli_mbr_check2(ctx, 0);
                        if ((iret == CL_TYPE_GPT) && (DCONF_ARCH & ARCH_CONF_GPT))
                        {
                            cli_dbgmsg("Recognized GUID Partition Table file\n");
                            cli_set_container(ctx, CL_TYPE_GPT, map->len);
                            cli_dbgmsg("GPT signature found at %u\n", (unsigned int)fpt->offset);
                            nret = cli_scangpt(ctx, 0);
                        }
                        else if ((iret == CL_CLEAN) && (DCONF_ARCH & ARCH_CONF_MBR))
                        {
                            cli_dbgmsg("MBR signature found at %u\n", (unsigned int)fpt->offset);
                            nret = cli_scanmbr(ctx, 0);
                        }
                    }
                    break;

                case CL_TYPE_PDF:
                    if (type != CL_TYPE_PDF && SCAN_PARSE_PDF && (DCONF_DOC & DOC_CONF_PDF))
                    {
                        size_t csize = map->len - fpt->offset; /* not precise */
                        cli_set_container(ctx, CL_TYPE_PDF, csize);
                        cli_dbgmsg("PDF signature found at %u\n", (unsigned int)fpt->offset);
                        nret = cli_scanpdf(ctx, fpt->offset);
                    }
                    break;

                case CL_TYPE_MSEXE:
                    if (SCAN_PARSE_PE && (type == CL_TYPE_MSEXE || type == CL_TYPE_ZIP || type == CL_TYPE_MSOLE2) && ctx->dconf->pe)
                    {
                        uint64_t curr_len = map->len;
                        size_t csize = map->len - fpt->offset; /* not precise */
                        /* CL_ENGINE_MAX_EMBEDDED_PE */
                        if (curr_len > ctx->engine->maxembeddedpe)
                        {
                            cli_dbgmsg("cli_scanraw: MaxEmbeddedPE exceeded\n");
                            break;
                        }
                        cli_set_container(ctx, CL_TYPE_MSEXE, csize);
                        memset(&peinfo, 0, sizeof(struct cli_exe_info));
                        peinfo.offset = fpt->offset;
                        if (cli_peheader(map, &peinfo) == 0)
                        {
                            cli_dbgmsg("*** Detected embedded PE file at %u ***\n",
                                       (unsigned int)fpt->offset);
                            if (peinfo.section)
                                free(peinfo.section);
                            cli_hashset_destroy(&peinfo.vinfo);

                            nret = cli_scanembpe(ctx, fpt->offset);
                            break_loop = 1; /* we can stop here and other
                                             * embedded executables will
                                             * be found recursively
                                             * through the above call
                                             */
                        }
                    }
                    break;

                default:
                    cli_warnmsg("cli_scanraw: Type %u not handled in fpt loop\n", fpt->type);
                }

            if (nret == CL_VIRUS || break_loop)
                break;

            fpt = fpt->next;
        }

        if (nret != CL_VIRUS)
            switch (ret)
            {
            case CL_TYPE_HTML:
                /* bb#11196 - autoit script file misclassified as HTML */
                if (cli_get_container_intermediate(ctx, -2) == CL_TYPE_AUTOIT)
                {
                    ret = CL_TYPE_TEXT_ASCII;
                }
                else if (SCAN_PARSE_HTML && (type == CL_TYPE_TEXT_ASCII || type == CL_TYPE_GRAPHICS) &&
                         (DCONF_DOC & DOC_CONF_HTML))
                {
                    *dettype = CL_TYPE_HTML;
                    nret = cli_scanhtml(ctx);
                }
                break;

            case CL_TYPE_MAIL:
                cli_set_container(ctx, CL_TYPE_MAIL, map->len);
                if (SCAN_PARSE_MAIL && type == CL_TYPE_TEXT_ASCII && (DCONF_MAIL & MAIL_CONF_MBOX))
                {
                    *dettype = CL_TYPE_MAIL;
                    nret = cli_scanmail(ctx);
                }
                break;

            default:
                break;
            }
        perf_nested_stop(ctx, PERFT_RAWTYPENO, PERFT_SCAN);
        ctx->recursion--;
        ret = nret;
    }

    while (ftoffset)
    {
        fpt = ftoffset;
        ftoffset = ftoffset->next;
        free(fpt);
    }

    if (ret == CL_VIRUS)
        cli_dbgmsg("%s found\n", cli_get_last_virus(ctx));

    return ret;
}

static void emax_reached(cli_ctx *ctx)
{
    fmap_t **ctx_fmap = ctx->fmap;
    if (!ctx_fmap)
        return;
    while (*ctx_fmap)
    {
        fmap_t *map = *ctx_fmap;
        map->dont_cache_flag = 1;
        ctx_fmap--;
    }
    cli_dbgmsg("emax_reached: marked parents as non cacheable\n");
}

#define LINESTR(x) #x
#define LINESTR2(x) LINESTR(x)
#define __AT__ " at line " LINESTR2(__LINE__)

#define early_ret_from_magicscan(retcode)                                                         \
    do                                                                                            \
    {                                                                                             \
        cli_dbgmsg("cli_magic_scandesc: returning %d %s (no post, no cache)\n", retcode, __AT__); \
        return retcode;                                                                           \
    } while (0)

static int magic_scandesc_cleanup(cli_ctx *ctx, cli_file_t type, unsigned char *hash, size_t hashed_size, int cache_clean, int retcode, void *parent_property)
{
    int cb_retcode;
#if HAVE_JSON
    ctx->wrkproperty = (struct json_object *)(parent_property);
#else
    UNUSEDPARAM(parent_property);
#endif

    UNUSEDPARAM(type);

    if (retcode == CL_CLEAN && ctx->found_possibly_unwanted)
    {
        cli_virus_found_cb(ctx);
        cb_retcode = CL_VIRUS;
    }
    else
    {
        if (retcode == CL_CLEAN && ctx->num_viruses != 0)
            cb_retcode = CL_VIRUS;
        else
            cb_retcode = retcode;
    }

    cli_dbgmsg("cli_magic_scandesc: returning %d %s\n", retcode, __AT__);
    if (ctx->engine->cb_post_scan)
    {
        const char *virusname = NULL;
        perf_start(ctx, PERFT_POSTCB);
        if (cb_retcode == CL_VIRUS)
            virusname = cli_get_last_virus(ctx);
        switch (ctx->engine->cb_post_scan(fmap_fd(*ctx->fmap), cb_retcode, virusname, ctx->cb_ctx))
        {
        case CL_BREAK:
            cli_dbgmsg("cli_magic_scandesc: file whitelisted by post_scan callback\n");
            perf_stop(ctx, PERFT_POSTCB);
            return CL_CLEAN;
        case CL_VIRUS:
            cli_dbgmsg("cli_magic_scandesc: file blacklisted by post_scan callback\n");
            cli_append_virus(ctx, "Detected.By.Callback");
            perf_stop(ctx, PERFT_POSTCB);
            if (retcode != CL_VIRUS)
                return cli_checkfp(hash, hashed_size, ctx);
            return CL_VIRUS;
        case CL_CLEAN:
            break;
        default:
            cli_warnmsg("cli_magic_scandesc: ignoring bad return code from post_scan callback\n");
        }
        perf_stop(ctx, PERFT_POSTCB);
    }
    if (cb_retcode == CL_CLEAN && cache_clean)
    {
        perf_start(ctx, PERFT_CACHE);
        if (!(SCAN_COLLECT_METADATA))
            cache_add(hash, hashed_size, ctx);
        perf_stop(ctx, PERFT_CACHE);
    }
    if (retcode == CL_VIRUS && SCAN_ALLMATCHES)
        return CL_CLEAN;
    return retcode;
}

static int dispatch_prescan(clcb_pre_scan cb, cli_ctx *ctx, const char *filetype, bitset_t *old_hook_lsig_matches, void *parent_property, unsigned char *hash, size_t hashed_size, int *run_cleanup)
{
    int res = CL_CLEAN;

    UNUSEDPARAM(parent_property);
    UNUSEDPARAM(hash);
    UNUSEDPARAM(hashed_size);

    *run_cleanup = 0;

    if (cb)
    {
        perf_start(ctx, PERFT_PRECB);
        switch (cb(fmap_fd(*ctx->fmap), filetype, ctx->cb_ctx))
        {
        case CL_BREAK:
            cli_dbgmsg("cli_magic_scandesc: file whitelisted by callback\n");
            perf_stop(ctx, PERFT_PRECB);
            ctx->hook_lsig_matches = old_hook_lsig_matches;
            /* returns CL_CLEAN */
            *run_cleanup = 1;
            break;
        case CL_VIRUS:
            cli_dbgmsg("cli_magic_scandesc: file blacklisted by callback\n");
            cli_append_virus(ctx, "Detected.By.Callback");
            perf_stop(ctx, PERFT_PRECB);
            ctx->hook_lsig_matches = old_hook_lsig_matches;
            *run_cleanup = 1;
            res = CL_VIRUS;
            break;
        case CL_CLEAN:
            break;
        default:
            cli_warnmsg("cli_magic_scandesc: ignoring bad return code from callback\n");
        }

        perf_stop(ctx, PERFT_PRECB);
    }

    return res;
}

static int magic_scandesc(cli_ctx *ctx, cli_file_t type)
{
    int ret = CL_CLEAN;
    cli_file_t dettype = 0;
    uint8_t typercg = 1;
    size_t hashed_size;
    unsigned char hash[16] = {'\0'};
    bitset_t *old_hook_lsig_matches;
    const char *filetype;
    int cache_clean = 0, res;
    int run_cleanup = 0;
#if HAVE_JSON
    struct json_object *parent_property = NULL;
#else
    void *parent_property = NULL;
#endif

    if (!ctx->engine)
    {
        cli_errmsg("CRITICAL: engine == NULL\n");
        early_ret_from_magicscan(CL_ENULLARG);
    }

    if (!(ctx->engine->dboptions & CL_DB_COMPILED))
    {
        cli_errmsg("CRITICAL: engine not compiled\n");
        early_ret_from_magicscan(CL_EMALFDB);
    }

    if (ctx->engine->maxreclevel && ctx->recursion > ctx->engine->maxreclevel)
    {
        cli_dbgmsg("cli_magic_scandesc: Archive recursion limit exceeded (%u, max: %u)\n", ctx->recursion, ctx->engine->maxreclevel);
        emax_reached(ctx);
        cli_check_blockmax(ctx, CL_EMAXREC);
        early_ret_from_magicscan(CL_CLEAN);
    }

    if (cli_updatelimits(ctx, (*ctx->fmap)->len) != CL_CLEAN)
    {
        emax_reached(ctx);
        early_ret_from_magicscan(CL_CLEAN);
    }
    old_hook_lsig_matches = ctx->hook_lsig_matches;
    if (type == CL_TYPE_PART_ANY)
    {
        typercg = 0;
    }

    perf_start(ctx, PERFT_FT);
    if ((type == CL_TYPE_ANY) || type == CL_TYPE_PART_ANY)
    {
        type = cli_filetype2(*ctx->fmap, ctx->engine, type);
    }
    perf_stop(ctx, PERFT_FT);
    if (type == CL_TYPE_ERROR)
    {
        cli_dbgmsg("cli_magic_scandesc: cli_filetype2 returned CL_TYPE_ERROR\n");
        early_ret_from_magicscan(CL_EREAD);
    }
    filetype = cli_ftname(type);

#if HAVE_JSON
    if (SCAN_COLLECT_METADATA)
    {
        json_object *arrobj;

        if (NULL == ctx->properties)
        {
            if (type == CL_TYPE_PDF || /* file types we collect properties about */
                type == CL_TYPE_MSOLE2 ||
                type == CL_TYPE_MSEXE ||
                //type == CL_TYPE_ZIP ||
                type == CL_TYPE_OOXML_WORD ||
                type == CL_TYPE_OOXML_PPT ||
                type == CL_TYPE_OOXML_XL ||
                type == CL_TYPE_XML_WORD ||
                type == CL_TYPE_XML_XL ||
                type == CL_TYPE_HWP3 ||
                type == CL_TYPE_XML_HWP ||
                type == CL_TYPE_HWPOLE2 ||
                type == CL_TYPE_OOXML_HWP ||
                type == CL_TYPE_MHTML)
            {
                ctx->properties = json_object_new_object();
                if (NULL == ctx->properties)
                {
                    cli_errmsg("magic_scandesc: no memory for json properties object\n");
                    early_ret_from_magicscan(CL_EMEM);
                }
                ctx->wrkproperty = ctx->properties;
                ret = cli_jsonstr(ctx->properties, "Magic", "CLAMJSONv0");
                if (ret != CL_SUCCESS)
                {
                    early_ret_from_magicscan(ret);
                }
                ret = cli_jsonstr(ctx->properties, "RootFileType", filetype);
                if (ret != CL_SUCCESS)
                {
                    early_ret_from_magicscan(ret);
                }
            }
            else
            { /* turn off property collection flag for file types we don't care about */
                ctx->options->general &= ~CL_SCAN_GENERAL_COLLECT_METADATA;
            }
        }
        else
        {
            parent_property = ctx->wrkproperty;
            if (!json_object_object_get_ex(parent_property, "ContainedObjects", &arrobj))
            {
                arrobj = json_object_new_array();
                if (NULL == arrobj)
                {
                    cli_errmsg("magic_scandesc: no memory for json properties object\n");
                    early_ret_from_magicscan(CL_EMEM);
                }
                json_object_object_add(parent_property, "ContainedObjects", arrobj);
            }
            ctx->wrkproperty = json_object_new_object();
            if (NULL == ctx->wrkproperty)
            {
                cli_errmsg("magic_scandesc: no memory for json properties object\n");
                early_ret_from_magicscan(CL_EMEM);
            }
            json_object_array_add(arrobj, ctx->wrkproperty);
        }
    }

    if (SCAN_COLLECT_METADATA)
    { /* separated for cases json is not tracked */
        ret = cli_jsonstr(ctx->wrkproperty, "FileType", filetype);
        if (ret != CL_SUCCESS)
        {
            early_ret_from_magicscan(ret);
        }
        ret = cli_jsonint(ctx->wrkproperty, "FileSize", (*ctx->fmap)->len);
        if (ret != CL_SUCCESS)
        {
            early_ret_from_magicscan(ret);
        }
    }
#endif

    hashed_size = 0;
    ret = dispatch_prescan(ctx->engine->cb_pre_cache, ctx, filetype, old_hook_lsig_matches, parent_property, hash, hashed_size, &run_cleanup);
    if (run_cleanup)
    {
        if (ret == CL_VIRUS)
            return magic_scandesc_cleanup(ctx, type, hash, hashed_size, cache_clean, cli_checkfp(hash, hashed_size, ctx), parent_property);
        else
            return magic_scandesc_cleanup(ctx, type, hash, hashed_size, cache_clean, CL_CLEAN, parent_property);
    }

    perf_start(ctx, PERFT_CACHE);
    if (!(SCAN_COLLECT_METADATA))
        res = cache_check(hash, ctx);
    else
        res = CL_VIRUS;

#if HAVE_JSON
    if (SCAN_COLLECT_METADATA /* ctx.options->general & CL_SCAN_GENERAL_COLLECT_METADATA && ctx->wrkproperty != NULL */)
    {
        char hashstr[33];
        ret = cache_get_MD5(hash, ctx);
        if (ret != CL_SUCCESS)
        {
            early_ret_from_magicscan(ret);
        }
        snprintf(hashstr, 33, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                 hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
                 hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15]);

        ret = cli_jsonstr(ctx->wrkproperty, "FileMD5", hashstr);
        if (ctx->engine->engine_options & ENGINE_OPTIONS_DISABLE_CACHE)
            memset(hash, 0, sizeof(hash));
        if (ret != CL_SUCCESS)
        {
            early_ret_from_magicscan(ret);
        }
    }
#endif

    if (res != CL_VIRUS)
    {
        perf_stop(ctx, PERFT_CACHE);
#if HAVE_JSON
        ctx->wrkproperty = parent_property;
#endif
        early_ret_from_magicscan(res);
    }

    perf_stop(ctx, PERFT_CACHE);
    hashed_size = (*ctx->fmap)->len;
    memcpy((*ctx->fmap)->maphash, hash, 16);
    ctx->hook_lsig_matches = NULL;

    if (!((ctx->options->general & ~CL_SCAN_GENERAL_ALLMATCHES) || (ctx->options->parse) || (ctx->options->heuristic) || (ctx->options->mail) || (ctx->options->dev)) || (ctx->recursion == ctx->engine->maxreclevel))
    { /* raw mode (stdin, etc.) or last level of recursion */
        if (ctx->recursion == ctx->engine->maxreclevel)
        {
            cli_check_blockmax(ctx, CL_EMAXREC);
            cli_dbgmsg("cli_magic_scandesc: Hit recursion limit, only scanning raw file\n");
        }
        else
            cli_dbgmsg("Raw mode: No support for special files\n");

        ret = dispatch_prescan(ctx->engine->cb_pre_scan, ctx, filetype, old_hook_lsig_matches, parent_property, hash, hashed_size, &run_cleanup);
        if (run_cleanup)
        {
            if (ret == CL_VIRUS)
                return magic_scandesc_cleanup(ctx, type, hash, hashed_size, cache_clean, cli_checkfp(hash, hashed_size, ctx), parent_property);
            else
                return magic_scandesc_cleanup(ctx, type, hash, hashed_size, cache_clean, ret, parent_property);
        }
        /* ret_from_magicscan can be used below here*/
        if ((ret = cli_fmap_scandesc(ctx, 0, 0, NULL, AC_SCAN_VIR, NULL, hash)) == CL_VIRUS)
            cli_dbgmsg("%s found in descriptor %d\n", cli_get_last_virus(ctx), fmap_fd(*ctx->fmap));
        else if (ret == CL_CLEAN)
        {
            if (ctx->recursion != ctx->engine->maxreclevel)
                cache_clean = 1; /* Only cache if limits are not reached */
            else
                emax_reached(ctx);
        }

        ctx->hook_lsig_matches = old_hook_lsig_matches;
        return magic_scandesc_cleanup(ctx, type, hash, hashed_size, cache_clean, ret, parent_property);
    }

    ret = dispatch_prescan(ctx->engine->cb_pre_scan, ctx, filetype, old_hook_lsig_matches, parent_property, hash, hashed_size, &run_cleanup);
    if (run_cleanup)
    {
        if (ret == CL_VIRUS)
            return magic_scandesc_cleanup(ctx, type, hash, hashed_size, cache_clean, cli_checkfp(hash, hashed_size, ctx), parent_property);
        else
            return magic_scandesc_cleanup(ctx, type, hash, hashed_size, cache_clean, ret, parent_property);
    }
/* ret_from_magicscan can be used below here*/

#ifdef HAVE__INTERNAL__SHA_COLLECT
    if (!ctx->sha_collect && type == CL_TYPE_MSEXE)
        ctx->sha_collect = 1;
#endif

    ctx->hook_lsig_matches = cli_bitset_init();
    if (!ctx->hook_lsig_matches)
    {
        ctx->hook_lsig_matches = old_hook_lsig_matches;
        return magic_scandesc_cleanup(ctx, type, hash, hashed_size, cache_clean, CL_EMEM, parent_property);
    }

    if (type != CL_TYPE_IGNORED && ctx->engine->sdb)
    {
        if ((ret = cli_scanraw(ctx, type, 0, &dettype, (ctx->engine->engine_options & ENGINE_OPTIONS_DISABLE_CACHE) ? NULL : hash)) == CL_VIRUS)
        {
            ret = cli_checkfp(hash, hashed_size, ctx);
            cli_bitset_free(ctx->hook_lsig_matches);
            ctx->hook_lsig_matches = old_hook_lsig_matches;
            return magic_scandesc_cleanup(ctx, type, hash, hashed_size, cache_clean, ret, parent_property);
        }
    }

    ctx->recursion++;
    perf_nested_start(ctx, PERFT_CONTAINER, PERFT_SCAN);
    /* set current level as container AFTER recursing */
    cli_set_container(ctx, type, (*ctx->fmap)->len);
    switch (type)
    {
    case CL_TYPE_IGNORED:
        break;

    case CL_TYPE_HWP3:
        if (SCAN_PARSE_HWP3 && (DCONF_DOC & DOC_CONF_HWP))
            ret = cli_scanhwp3(ctx);
        break;

    case CL_TYPE_HWPOLE2:
        if (SCAN_PARSE_OLE2 && (DCONF_ARCH & ARCH_CONF_OLE2))
            ret = cli_scanhwpole2(ctx);
        break;

    case CL_TYPE_XML_WORD:
        if (SCAN_PARSE_XMLDOCS && (DCONF_DOC & DOC_CONF_MSXML))
            ret = cli_scanmsxml(ctx);
        break;

    case CL_TYPE_XML_XL:
        if (SCAN_PARSE_XMLDOCS && (DCONF_DOC & DOC_CONF_MSXML))
            ret = cli_scanmsxml(ctx);
        break;

    case CL_TYPE_XML_HWP:
        if (SCAN_PARSE_XMLDOCS && (DCONF_DOC & DOC_CONF_HWP))
            ret = cli_scanhwpml(ctx);
        break;

    case CL_TYPE_XDP:
        if (SCAN_PARSE_PDF && (DCONF_DOC & DOC_CONF_PDF))
            ret = cli_scanxdp(ctx);
        break;

    case CL_TYPE_RAR:
        if (have_rar && SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_RAR)) {
            const char *filepath = NULL;
            int fd = -1;

            char *tmpname = NULL;
            int tmpfd = -1;

#ifdef _WIN32
            if ((SCAN_UNPRIVILEGED) || (NULL == ctx->sub_filepath) || (0 != _access_s(ctx->sub_filepath, R_OK))) {
#else
            if ((SCAN_UNPRIVILEGED) || (NULL == ctx->sub_filepath) || (0 != access(ctx->sub_filepath, R_OK))) {
#endif
                /* If map is not file-backed have to dump to file for scanrar. */
                ret = fmap_dump_to_file(*ctx->fmap, ctx->sub_filepath, ctx->engine->tmpdir, &tmpname, &tmpfd, 0, SIZE_MAX);
                if (ret != CL_SUCCESS) {
                    cli_dbgmsg("magic_scandesc: failed to generate temporary file.\n");
                    break;
                }
                filepath = tmpname;
                fd = tmpfd;
            } else {
                /* Use the original file and file descriptor. */
                filepath = ctx->sub_filepath;
                fd = fmap_fd(*ctx->fmap);
            }

            /* scan file */
            ret = cli_scanrar(filepath, fd, ctx);

            if ((NULL == tmpname) && (CL_EOPEN == ret)) {
                /*
                 * Failed to open the file using the original filename.
                 * Try writing the file descriptor to a temp file and try again.
                 */
                ret = fmap_dump_to_file(*ctx->fmap, ctx->sub_filepath, ctx->engine->tmpdir, &tmpname, &tmpfd, 0, SIZE_MAX);
                if (ret != CL_SUCCESS) {
                    cli_dbgmsg("cli_scanraw: failed to generate temporary file.\n");
                    break;
                }
                filepath = tmpname;
                fd = tmpfd;

                /* try to scan again */
                ret = cli_scanrar(filepath, fd, ctx);
            }

            if (tmpfd != -1) {
                /* If dumped tempfile, need to cleanup */
                close(tmpfd);
                if (!ctx->engine->keeptmp) {
                    if (cli_unlink(tmpname)) {
                        ret = CL_EUNLINK;
                    }
                }
            }

            if (tmpname != NULL) {
                free(tmpname);
            }
        }
        break;

    case CL_TYPE_OOXML_WORD:
    case CL_TYPE_OOXML_PPT:
    case CL_TYPE_OOXML_XL:
    case CL_TYPE_OOXML_HWP:
#if HAVE_JSON
        if (SCAN_PARSE_XMLDOCS && (DCONF_DOC & DOC_CONF_OOXML))
        {
            if (SCAN_COLLECT_METADATA && (ctx->wrkproperty != NULL))
            {
                ret = cli_process_ooxml(ctx, type);

                if (ret == CL_EMEM || ret == CL_ENULLARG)
                {
                    /* critical error */
                    break;
                }
                else if (ret != CL_SUCCESS)
                {
                    /*
             * non-critical return => allow for the CL_TYPE_ZIP scan to occur
             * cli_process_ooxml other possible returns:
             *   CL_ETIMEOUT, CL_EMAXSIZE, CL_EMAXFILES, CL_EPARSE,
             *   CL_EFORMAT, CL_BREAK, CL_ESTAT
             */
                    ret = CL_SUCCESS;
                }
            }
        }
#endif
    case CL_TYPE_ZIP:
        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ZIP))
            ret = cli_unzip(ctx);
        break;

    case CL_TYPE_GZ:
        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_GZ))
            ret = cli_scangzip(ctx);
        break;

    case CL_TYPE_BZ:
        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_BZ))
            ret = cli_scanbzip(ctx);
        break;

    case CL_TYPE_XZ:
        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_XZ))
            ret = cli_scanxz(ctx);
        break;

    case CL_TYPE_GPT:
        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_GPT))
            ret = cli_scangpt(ctx, 0);
        break;

    case CL_TYPE_APM:
        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_APM))
            ret = cli_scanapm(ctx);
        break;

    case CL_TYPE_ARJ:
        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ARJ))
            ret = cli_scanarj(ctx, 0);
        break;

    case CL_TYPE_NULSFT:
        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_NSIS))
            ret = cli_scannulsft(ctx, 0);
        break;

    case CL_TYPE_AUTOIT:
        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_AUTOIT))
            ret = cli_scanautoit(ctx, 23);
        break;

    case CL_TYPE_MSSZDD:
        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_SZDD))
            ret = cli_scanszdd(ctx);
        break;

    case CL_TYPE_MSCAB:
        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_CAB))
            ret = cli_scanmscab(ctx, 0);
        break;

    case CL_TYPE_HTML:
        if (SCAN_PARSE_HTML && (DCONF_DOC & DOC_CONF_HTML))
            ret = cli_scanhtml(ctx);
        break;

    case CL_TYPE_HTML_UTF16:
        if (SCAN_PARSE_HTML && (DCONF_DOC & DOC_CONF_HTML))
            ret = cli_scanhtml_utf16(ctx);
        break;

    case CL_TYPE_SCRIPT:
        if ((DCONF_DOC & DOC_CONF_SCRIPT) && dettype != CL_TYPE_HTML)
            ret = cli_scanscript(ctx);
        break;

    case CL_TYPE_SWF:
        if (SCAN_PARSE_SWF && (DCONF_DOC & DOC_CONF_SWF))
            ret = cli_scanswf(ctx);
        break;

    case CL_TYPE_RTF:
        if (SCAN_PARSE_ARCHIVE && (DCONF_DOC & DOC_CONF_RTF))
            ret = cli_scanrtf(ctx);
        break;

    case CL_TYPE_MAIL:
        if (SCAN_PARSE_MAIL && (DCONF_MAIL & MAIL_CONF_MBOX))
            ret = cli_scanmail(ctx);
        break;

    case CL_TYPE_MHTML:
        if (SCAN_PARSE_MAIL && (DCONF_MAIL & MAIL_CONF_MBOX))
            ret = cli_scanmail(ctx);
        break;

    case CL_TYPE_TNEF:
        if (SCAN_PARSE_MAIL && (DCONF_MAIL & MAIL_CONF_TNEF))
            ret = cli_scantnef(ctx);
        break;

    case CL_TYPE_UUENCODED:
        if (DCONF_OTHER & OTHER_CONF_UUENC)
            ret = cli_scanuuencoded(ctx);
        break;

    case CL_TYPE_MSCHM:
        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_CHM))
            ret = cli_scanmschm(ctx);
        break;

    case CL_TYPE_MSOLE2:
        if (SCAN_PARSE_OLE2 && (DCONF_ARCH & ARCH_CONF_OLE2))
            ret = cli_scanole2(ctx);
        break;

    case CL_TYPE_7Z:
        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_7Z))
            ret = cli_7unz(ctx, 0);
        break;

    case CL_TYPE_POSIX_TAR:
        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_TAR))
            ret = cli_scantar(ctx, 1);
        break;

    case CL_TYPE_OLD_TAR:
        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_TAR))
            ret = cli_scantar(ctx, 0);
        break;

    case CL_TYPE_CPIO_OLD:
        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_CPIO))
            ret = cli_scancpio_old(ctx);
        break;

    case CL_TYPE_CPIO_ODC:
        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_CPIO))
            ret = cli_scancpio_odc(ctx);
        break;

    case CL_TYPE_CPIO_NEWC:
        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_CPIO))
            ret = cli_scancpio_newc(ctx, 0);
        break;

    case CL_TYPE_CPIO_CRC:
        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_CPIO))
            ret = cli_scancpio_newc(ctx, 1);
        break;

    case CL_TYPE_BINHEX:
        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_BINHEX))
            ret = cli_binhex(ctx);
        break;

    case CL_TYPE_SCRENC:
        if (DCONF_OTHER & OTHER_CONF_SCRENC)
            ret = cli_scanscrenc(ctx);
        break;

    case CL_TYPE_RIFF:
        if (SCAN_HEURISTICS && (DCONF_OTHER & OTHER_CONF_RIFF))
            ret = cli_scanriff(ctx);
        break;

    case CL_TYPE_GRAPHICS:
        if (SCAN_HEURISTICS && (DCONF_OTHER & OTHER_CONF_JPEG))
            ret = cli_scanjpeg(ctx);

        if (ctx->img_validate && SCAN_HEURISTICS && ret != CL_VIRUS)
            ret = cli_parsejpeg(ctx);

        if (ctx->img_validate && SCAN_HEURISTICS && ret != CL_VIRUS && ret != CL_EPARSE)
            ret = cli_parsepng(ctx);

        if (ctx->img_validate && SCAN_HEURISTICS && ret != CL_VIRUS && ret != CL_EPARSE)
            ret = cli_parsegif(ctx);

        if (ctx->img_validate && SCAN_HEURISTICS && ret != CL_VIRUS && ret != CL_EPARSE)
            ret = cli_parsetiff(ctx);

        break;

    case CL_TYPE_PDF: /* FIXMELIMITS: pdf should be an archive! */
        if (SCAN_PARSE_PDF && (DCONF_DOC & DOC_CONF_PDF))
            ret = cli_scanpdf(ctx, 0);
        break;

    case CL_TYPE_CRYPTFF:
        if (DCONF_OTHER & OTHER_CONF_CRYPTFF)
            ret = cli_scancryptff(ctx);
        break;

    case CL_TYPE_ELF:
        if (SCAN_PARSE_ELF && ctx->dconf->elf)
            ret = cli_scanelf(ctx);
        break;

    case CL_TYPE_MACHO:
        if (ctx->dconf->macho)
            ret = cli_scanmacho(ctx, NULL);
        break;

    case CL_TYPE_MACHO_UNIBIN:
        if (ctx->dconf->macho)
            ret = cli_scanmacho_unibin(ctx);
        break;

    case CL_TYPE_SIS:
        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_SIS))
            ret = cli_scansis(ctx);
        break;

    case CL_TYPE_XAR:
        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_XAR))
            ret = cli_scanxar(ctx);
        break;

    case CL_TYPE_PART_HFSPLUS:
        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_HFSPLUS))
            ret = cli_scanhfsplus(ctx);
        break;

    case CL_TYPE_BINARY_DATA:
    case CL_TYPE_TEXT_UTF16BE:
        if (SCAN_HEURISTICS && (DCONF_OTHER & OTHER_CONF_MYDOOMLOG))
            ret = cli_check_mydoom_log(ctx);
        break;

    case CL_TYPE_TEXT_ASCII:
        if (SCAN_HEURISTIC_STRUCTURED && (DCONF_OTHER & OTHER_CONF_DLP))
            /* TODO: consider calling this from cli_scanscript() for
         * a normalised text
         */

            ret = cli_scan_structured(ctx);
        break;

    default:
        break;
    }
    perf_nested_stop(ctx, PERFT_CONTAINER, PERFT_SCAN);
    ctx->recursion--;

    if (ret == CL_VIRUS && !SCAN_ALLMATCHES)
    {
        cli_bitset_free(ctx->hook_lsig_matches);
        ctx->hook_lsig_matches = old_hook_lsig_matches;
        return magic_scandesc_cleanup(ctx, type, hash, hashed_size, cache_clean, ret, parent_property);
    }

    if (type == CL_TYPE_ZIP && SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ZIP))
    {
        /* CL_ENGINE_MAX_ZIPTYPERCG */
        uint64_t curr_len = (*ctx->fmap)->len;
        if (curr_len > ctx->engine->maxziptypercg)
        {
            cli_dbgmsg("cli_magic_scandesc: Not checking for embedded PEs (zip file > MaxZipTypeRcg)\n");
            typercg = 0;
        }
    }

    /* CL_TYPE_HTML: raw HTML files are not scanned, unless safety measure activated via DCONF */
    if (type != CL_TYPE_IGNORED && (type != CL_TYPE_HTML || !(SCAN_PARSE_HTML) || !(DCONF_DOC & DOC_CONF_HTML_SKIPRAW)) && !ctx->engine->sdb)
    {
        res = cli_scanraw(ctx, type, typercg, &dettype, (ctx->engine->engine_options & ENGINE_OPTIONS_DISABLE_CACHE) ? NULL : hash);
        if (res != CL_CLEAN)
        {
            switch (res)
            {
            /* List of scan halts, runtime errors only! */
            case CL_EUNLINK:
            case CL_ESTAT:
            case CL_ESEEK:
            case CL_EWRITE:
            case CL_EDUP:
            case CL_ETMPFILE:
            case CL_ETMPDIR:
            case CL_EMEM:
                cli_dbgmsg("Descriptor[%d]: cli_scanraw error %s\n", fmap_fd(*ctx->fmap), cl_strerror(res));
                cli_bitset_free(ctx->hook_lsig_matches);
                ctx->hook_lsig_matches = old_hook_lsig_matches;
                return magic_scandesc_cleanup(ctx, type, hash, hashed_size, cache_clean, res, parent_property);
            /* CL_VIRUS = malware found, check FP and report */
            case CL_VIRUS:
                ret = res;
                if (SCAN_ALLMATCHES)
                    break;
                cli_bitset_free(ctx->hook_lsig_matches);
                ctx->hook_lsig_matches = old_hook_lsig_matches;
                return magic_scandesc_cleanup(ctx, type, hash, hashed_size, cache_clean, ret, parent_property);
            /* The CL_ETIMEOUT "MAX" condition should set exceeds max flag and exit out quietly. */
            case CL_ETIMEOUT:
                cli_check_blockmax(ctx, ret);
                cli_bitset_free(ctx->hook_lsig_matches);
                ctx->hook_lsig_matches = old_hook_lsig_matches;
                cli_dbgmsg("Descriptor[%d]: Stopping after cli_scanraw reached %s\n",
                            fmap_fd(*ctx->fmap), cl_strerror(res));
                return magic_scandesc_cleanup(ctx, type, hash, hashed_size, cache_clean, CL_CLEAN, parent_property);
            /* All other "MAX" conditions should still fully scan the current file */
            case CL_EMAXREC:
            case CL_EMAXSIZE:
            case CL_EMAXFILES:
                ret = res;
                cli_dbgmsg("Descriptor[%d]: Continuing after cli_scanraw reached %s\n",
                           fmap_fd(*ctx->fmap), cl_strerror(res));
                break;
            /* Other errors must not block further scans below
         * This specifically includes CL_EFORMAT & CL_EREAD & CL_EUNPACK
         * Malformed/truncated files could report as any of these three.
         */
            default:
                ret = res;
                cli_dbgmsg("Descriptor[%d]: Continuing after cli_scanraw error %s\n",
                           fmap_fd(*ctx->fmap), cl_strerror(res));
            }
        }
    }

    ctx->recursion++;
    switch (type)
    {
    /* bytecode hooks triggered by a lsig must be a hook
     * called from one of the functions here */
    case CL_TYPE_TEXT_ASCII:
    case CL_TYPE_TEXT_UTF16BE:
    case CL_TYPE_TEXT_UTF16LE:
    case CL_TYPE_TEXT_UTF8:
        perf_nested_start(ctx, PERFT_SCRIPT, PERFT_SCAN);
        if ((DCONF_DOC & DOC_CONF_SCRIPT) && dettype != CL_TYPE_HTML && (ret != CL_VIRUS || SCAN_ALLMATCHES) && SCAN_PARSE_HTML)
            ret = cli_scanscript(ctx);
        if (SCAN_PARSE_MAIL && (DCONF_MAIL & MAIL_CONF_MBOX) && ret != CL_VIRUS && (cli_get_container(ctx, -1) == CL_TYPE_MAIL || dettype == CL_TYPE_MAIL))
        {
            ret = cli_fmap_scandesc(ctx, CL_TYPE_MAIL, 0, NULL, AC_SCAN_VIR, NULL, NULL);
        }
        perf_nested_stop(ctx, PERFT_SCRIPT, PERFT_SCAN);
        break;
    /* Due to performance reasons all executables were first scanned
     * in raw mode. Now we will try to unpack them
     */
    case CL_TYPE_MSEXE:
        perf_nested_start(ctx, PERFT_PE, PERFT_SCAN);
        if (SCAN_PARSE_PE && ctx->dconf->pe)
        {
            unsigned int corrupted_input = ctx->corrupted_input;
            ret = cli_scanpe(ctx);
            ctx->corrupted_input = corrupted_input;
        }
        perf_nested_stop(ctx, PERFT_PE, PERFT_SCAN);
        break;
    case CL_TYPE_BINARY_DATA:
        ret = cli_fmap_scandesc(ctx, CL_TYPE_OTHER, 0, NULL, AC_SCAN_VIR, NULL, NULL);
        break;
    default:
        break;
    }

    ctx->recursion--;
    cli_bitset_free(ctx->hook_lsig_matches);
    ctx->hook_lsig_matches = old_hook_lsig_matches;

    switch (ret)
    {
    /* Limits exceeded */
    case CL_ETIMEOUT:
    case CL_EMAXREC:
    case CL_EMAXSIZE:
    case CL_EMAXFILES:
        cli_check_blockmax(ctx, ret);
    /* Malformed file cases */
    case CL_EFORMAT:
    case CL_EREAD:
    case CL_EUNPACK:
        cli_dbgmsg("Descriptor[%d]: %s\n", fmap_fd(*ctx->fmap), cl_strerror(ret));
#if HAVE_JSON
        ctx->wrkproperty = parent_property;
#endif
        return magic_scandesc_cleanup(ctx, type, hash, hashed_size, cache_clean, CL_CLEAN, parent_property);
    case CL_CLEAN:
        cache_clean = 1;
#if HAVE_JSON
        ctx->wrkproperty = parent_property;
#endif
        return magic_scandesc_cleanup(ctx, type, hash, hashed_size, cache_clean, CL_CLEAN, parent_property);
    default:
        return magic_scandesc_cleanup(ctx, type, hash, hashed_size, cache_clean, ret, parent_property);
    }
}

static cl_error_t cli_base_scandesc(int desc, const char *filepath, cli_ctx *ctx, cli_file_t type)
{
    STATBUF sb;
    cl_error_t status = CL_CLEAN;
    cl_error_t ret    = CL_CLEAN;

    if (!ctx) {
        return CL_EARG;
    }

    const char *parent_filepath = ctx->sub_filepath;
    ctx->sub_filepath = filepath;

#ifdef HAVE__INTERNAL__SHA_COLLECT
    if (ctx->sha_collect > 0)
        ctx->sha_collect = 0;
#endif
    cli_dbgmsg("in cli_magic_scandesc (reclevel: %u/%u)\n", ctx->recursion, ctx->engine->maxreclevel);
    if (FSTAT(desc, &sb) == -1)
    {
        cli_errmsg("magic_scandesc: Can't fstat descriptor %d\n", desc);

        status = CL_ESTAT;
        cli_dbgmsg("cli_magic_scandesc: returning %d %s (no post, no cache)\n", status, __AT__);
        goto done;
    }
    if (sb.st_size <= 5)
    {
        cli_dbgmsg("Small data (%u bytes)\n", (unsigned int)sb.st_size);

        status = CL_CLEAN;
        cli_dbgmsg("cli_magic_scandesc: returning %d %s (no post, no cache)\n", status, __AT__);
        goto done;
    }

    ctx->fmap++;
    perf_start(ctx, PERFT_MAP);
    if (!(*ctx->fmap = fmap(desc, 0, sb.st_size)))
    {
        cli_errmsg("CRITICAL: fmap() failed\n");
        ctx->fmap--;
        perf_stop(ctx, PERFT_MAP);

        status = CL_EMEM;
        cli_dbgmsg("cli_magic_scandesc: returning %d %s (no post, no cache)\n", status, __AT__);
        goto done;
    }
    perf_stop(ctx, PERFT_MAP);

    status = magic_scandesc(ctx, type);

    funmap(*ctx->fmap);
    ctx->fmap--;

done:
    ctx->sub_filepath = parent_filepath;

    return status;
}

int cli_magic_scandesc(int desc, const char *filepath, cli_ctx *ctx)
{
    return cli_base_scandesc(desc, filepath, ctx, CL_TYPE_ANY);
}

/* Have to keep partition typing separate */
int cli_partition_scandesc(int desc, const char *filepath, cli_ctx *ctx)
{
    return cli_base_scandesc(desc, filepath, ctx, CL_TYPE_PART_ANY);
}

int cli_magic_scandesc_type(cli_ctx *ctx, cli_file_t type)
{
    return magic_scandesc(ctx, type);
}

int cl_scandesc(int desc, const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, struct cl_scan_options* scanoptions)
{
    return cl_scandesc_callback(desc, filename, virname, scanned, engine, scanoptions, NULL);
}

/* For map scans that may be forced to disk */
int cli_map_scan(cl_fmap_t *map, off_t offset, size_t length, cli_ctx *ctx, cli_file_t type)
{
    off_t old_off = map->nested_offset;
    size_t old_len = map->len;
    int ret = CL_CLEAN;

    cli_dbgmsg("cli_map_scan: [%ld, +%lu)\n",
               (long)offset, (unsigned long)length);
    if (offset < 0 || (size_t)offset >= old_len)
    {
        cli_dbgmsg("Invalid offset: %ld\n", (long)offset);
        return CL_CLEAN;
    }

    if (ctx->engine->engine_options & ENGINE_OPTIONS_FORCE_TO_DISK)
    {
        /* if this is forced to disk, then need to write the nested map and scan it */
        const uint8_t *mapdata = NULL;
        char *tempfile = NULL;
        int fd = -1;
        size_t nread = 0;

        /* Then check length */
        if (!length)
            length = old_len - offset;
        if (length > old_len - offset)
        {
            cli_dbgmsg("cli_map_scan: Data truncated: %lu -> %lu\n",
                       (unsigned long)length, (unsigned long)(old_len - offset));
            length = old_len - offset;
        }
        if (length <= 5)
        {
            cli_dbgmsg("cli_map_scan: Small data (%u bytes)\n", (unsigned int)length);
            return CL_CLEAN;
        }
        if (!CLI_ISCONTAINED(old_off, old_len, old_off + offset, length))
        {
            cli_dbgmsg("cli_map_scan: map error occurred [%ld, %zu]\n",
                       (long)old_off, old_len);
            return CL_CLEAN;
        }

        /* Length checked, now get map */
        mapdata = fmap_need_off_once_len(map, offset, length, &nread);
        if (!mapdata || (nread != length))
        {
            cli_errmsg("cli_map_scan: could not map sub-file\n");
            return CL_EMAP;
        }

        ret = cli_gentempfd(ctx->engine->tmpdir, &tempfile, &fd);
        if (ret != CL_SUCCESS)
        {
            return ret;
        }

        cli_dbgmsg("cli_map_scan: writing nested map content to temp file %s\n", tempfile);
        if (cli_writen(fd, mapdata, length) < 0)
        {
            cli_errmsg("cli_map_scan: cli_writen error writing subdoc temporary file.\n");
            ret = CL_EWRITE;
        }

        /* scan the temp file */
        ret = cli_base_scandesc(fd, tempfile, ctx, type);

        /* remove the temp file, if needed */
        if (fd >= 0)
        {
            close(fd);
        }
        if (!ctx->engine->keeptmp)
        {
            if (cli_unlink(tempfile))
            {
                cli_errmsg("cli_map_scan: error unlinking tempfile %s\n", tempfile);
                ret = CL_EUNLINK;
            }
        }
        free(tempfile);
    }
    else
    {
        /* Not forced to disk, use nested map */
        ret = cli_map_scandesc(map, offset, length, ctx, type);
    }
    return ret;
}

/* For map scans that are not forced to disk */
int cli_map_scandesc(cl_fmap_t *map, off_t offset, size_t length, cli_ctx *ctx, cli_file_t type)
{
    off_t old_off = map->nested_offset;
    size_t old_len = map->len;
    size_t old_real_len = map->real_len;
    int ret = CL_CLEAN;

    cli_dbgmsg("cli_map_scandesc: [%ld, +%lu), [%ld, +%lu)\n",
               (long)old_off, (unsigned long)old_len,
               (long)offset, (unsigned long)length);
    if (offset < 0 || (size_t)offset >= old_len)
    {
        cli_dbgmsg("Invalid offset: %ld\n", (long)offset);
        return CL_CLEAN;
    }

    if (!length)
        length = old_len - offset;
    if (length > old_len - offset)
    {
        cli_dbgmsg("Data truncated: %zu -> %zu\n",
                length, old_len - (size_t)offset);
        length = old_len - (size_t)offset;
    }

    if (length <= 5)
    {
        cli_dbgmsg("Small data (%u bytes)\n", (unsigned int)length);
        return CL_CLEAN;
    }
    ctx->fmap++;
    *ctx->fmap = map;
    /* can't change offset because then we'd have to discard/move cached
     * data, instead use another offset to reuse the already cached data */
    map->nested_offset += offset;
    map->len = length;
    map->real_len = map->nested_offset + length;
    if (CLI_ISCONTAINED(old_off, old_len, map->nested_offset, map->len))
    {
        ret = magic_scandesc(ctx, type);
    }
    else
    {
        long long len1, len2;
        len1 = old_off + old_len;
        len2 = map->nested_offset + map->len;
        cli_warnmsg("internal map error: %lu, %llu; %lu, %llu\n", (long unsigned)old_off,
                    (long long unsigned)len1, (long unsigned)map->offset, (long long unsigned)len2);
    }

    ctx->fmap--;
    map->nested_offset = old_off;
    map->len = old_len;
    map->real_len = old_real_len;
    return ret;
}

int cli_mem_scandesc(const void *buffer, size_t length, cli_ctx *ctx)
{
    int ret;
    fmap_t *map = cl_fmap_open_memory(buffer, length);
    if (!map)
    {
        return CL_EMAP;
    }
    ret = cli_map_scan(map, 0, length, ctx, CL_TYPE_ANY);
    cl_fmap_close(map);
    return ret;
}

/**
 * @brief   The main function to initiate a scan, that may be invoked with a file descriptor or a file map.
 *
 * @param desc              File descriptor of an open file. The caller must provide this or the map.
 * @param map               File map. The caller must provide this or the desc.
 * @param filepath          (optional, recommended) filepath of the open file descriptor or file map.
 * @param[out] virname      Will be set to a statically allocated (i.e. needs not be freed) signature name if the scan matches against a signature.
 * @param[out] scanned      The number of bytes scanned.
 * @param engine            The scanning engine.
 * @param scanoptions       Scanning options.
 * @param[in/out] context   An opaque context structure allowing the caller to record details about the sample being scanned.
 * @return int              CL_CLEAN, CL_VIRUS, or an error code if an error occured during the scan.
 */
static cl_error_t scan_common(int desc, cl_fmap_t *map, const char * filepath, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, struct cl_scan_options *scanoptions, void *context)
{
    cli_ctx ctx;
    int rc;
    STATBUF sb;

    /* We have a limit of around 2.17GB (INT_MAX - 2). Enforce it here. */
    if (map != NULL)
    {
        if ((size_t)(map->real_len) > (size_t)(INT_MAX - 2))
            return CL_CLEAN;
    }
    else
    {
        if (FSTAT(desc, &sb))
            return CL_ESTAT;

        if ((size_t)(sb.st_size) > (size_t)(INT_MAX - 2))
            return CL_CLEAN;
    }

    memset(&ctx, '\0', sizeof(cli_ctx));
    ctx.engine = engine;
    ctx.virname = virname;
    ctx.scanned = scanned;
    ctx.options = malloc(sizeof(struct cl_scan_options));
    memcpy(ctx.options, scanoptions, sizeof(struct cl_scan_options));
    ctx.found_possibly_unwanted = 0;
    ctx.containers = cli_calloc(sizeof(cli_ctx_container), ctx.engine->maxreclevel + 2);
    if (!ctx.containers)
        return CL_EMEM;
    cli_set_container(&ctx, CL_TYPE_ANY, 0);
    ctx.dconf = (struct cli_dconf *)engine->dconf;
    ctx.cb_ctx = context;
    ctx.fmap = cli_calloc(sizeof(fmap_t *), ctx.engine->maxreclevel + 2);
    if (!ctx.fmap)
        return CL_EMEM;
    if (!(ctx.hook_lsig_matches = cli_bitset_init()))
    {
        free(ctx.fmap);
        return CL_EMEM;
    }
    perf_init(&ctx);

    if (ctx.engine->maxscantime != 0)
    {
        if (gettimeofday(&ctx.time_limit, NULL) == 0)
        {
            uint32_t secs = ctx.engine->maxscantime / 1000;
            uint32_t usecs = (ctx.engine->maxscantime % 1000) * 1000;
            ctx.time_limit.tv_sec += secs;
            ctx.time_limit.tv_usec += usecs;
            if (ctx.time_limit.tv_usec >= 1000000)
            {
                ctx.time_limit.tv_usec -= 1000000;
                ctx.time_limit.tv_sec++;
            }
        }
        else
        {
            char buf[64];
            cli_dbgmsg("scan_common: gettimeofday error: %s\n", cli_strerror(errno, buf, 64));
        }
    }

    if (filepath != NULL)
    {
        ctx.target_filepath = strdup(filepath);
    }

    cli_logg_setup(&ctx);
    rc = map ? cli_map_scandesc(map, 0, map->len, &ctx, CL_TYPE_ANY)
             : cli_magic_scandesc(desc, ctx.target_filepath, &ctx);

#if HAVE_JSON
    if (ctx.options->general & CL_SCAN_GENERAL_COLLECT_METADATA && (ctx.properties != NULL))
    {
        json_object *jobj;
        const char *jstring;

        /* set value of unique root object tag */
        if (json_object_object_get_ex(ctx.properties, "FileType", &jobj))
        {
            enum json_type type;
            const char *jstr;

            type = json_object_get_type(jobj);
            if (type == json_type_string)
            {
                jstr = json_object_get_string(jobj);
                cli_jsonstr(ctx.properties, "RootFileType", jstr);
            }
        }

        /* serialize json properties to string */
        jstring = json_object_to_json_string(ctx.properties);
        if (NULL == jstring)
        {
            cli_errmsg("scan_common: no memory for json serialization.\n");
            rc = CL_EMEM;
        }
        else
        {
            int ret = CL_SUCCESS;
            struct cli_matcher *iroot = ctx.engine->root[13];
            cli_dbgmsg("%s\n", jstring);

            if (rc != CL_VIRUS)
            {
                /* run bytecode preclass hook; generate fmap if needed for running hook */
                struct cli_bc_ctx *bc_ctx = cli_bytecode_context_alloc();
                if (!bc_ctx)
                {
                    cli_errmsg("scan_common: can't allocate memory for bc_ctx\n");
                    rc = CL_EMEM;
                }
                else
                {
                    fmap_t *pc_map = map;

                    if (!pc_map)
                    {
                        perf_start(&ctx, PERFT_MAP);
                        if (!(pc_map = fmap(desc, 0, sb.st_size)))
                        {
                            perf_stop(&ctx, PERFT_MAP);
                            rc = CL_EMEM;
                        }
                        perf_stop(&ctx, PERFT_MAP);
                    }

                    if (pc_map)
                    {
                        cli_bytecode_context_setctx(bc_ctx, &ctx);
                        rc = cli_bytecode_runhook(&ctx, ctx.engine, bc_ctx, BC_PRECLASS, pc_map);
                        cli_bytecode_context_destroy(bc_ctx);

                        if (!map)
                            funmap(pc_map);
                    }
                }

                /* backwards compatibility: scan the json string unless a virus was detected */
                if (rc != CL_VIRUS && (iroot->ac_lsigs
                                    || iroot->ac_patterns
#ifdef HAVE_PCRE
                                    || iroot->pcre_metas
#endif
                ))
                {
                    cli_dbgmsg("scan_common: running deprecated preclass bytecodes for target type 13\n");
                    ctx.options->general &= ~CL_SCAN_GENERAL_COLLECT_METADATA;
                    rc = cli_mem_scandesc(jstring, strlen(jstring), &ctx);
                }
            }

            /* Invoke file props callback */
            if (ctx.engine->cb_file_props != NULL)
            {
                ret = ctx.engine->cb_file_props(jstring, rc, ctx.cb_ctx);
                if (ret != CL_SUCCESS)
                    rc = ret;
            }

            /* keeptmp file processing for file properties json string */
            if (ctx.engine->keeptmp)
            {
                int fd = -1;
                char *tmpname = NULL;
                if ((ret = cli_gentempfd(ctx.engine->tmpdir, &tmpname, &fd)) != CL_SUCCESS)
                {
                    cli_dbgmsg("scan_common: Can't create json properties file, ret = %i.\n", ret);
                }
                else
                {
                    if (cli_writen(fd, jstring, strlen(jstring)) < 0)
                        cli_dbgmsg("scan_common: cli_writen error writing json properties file.\n");
                    else
                        cli_dbgmsg("json written to: %s\n", tmpname);
                }
                if (fd != -1)
                    close(fd);
                if (NULL != tmpname)
                    free(tmpname);
            }
        }
        cli_json_delobj(ctx.properties); /* frees all json memory */
#if 0
        // test code  - to be deleted
        if (cli_checktimelimit(&ctx) != CL_SUCCESS) {
            cli_errmsg("scan_common: timeout!\n");
            rc = CL_ETIMEOUT;
        }
#endif
    }
#endif

    if (rc == CL_CLEAN)
    {
        if ((ctx.found_possibly_unwanted) ||
            ((ctx.num_viruses != 0) &&
               ((ctx.options->general & CL_SCAN_GENERAL_ALLMATCHES) ||
                (ctx.options->heuristic & CL_SCAN_HEURISTIC_EXCEEDS_MAX))
            ))
            rc = CL_VIRUS;
    }

    if (NULL != ctx.target_filepath) {
        free(ctx.target_filepath);
    }
    free(ctx.containers);
    cli_bitset_free(ctx.hook_lsig_matches);
    free(ctx.fmap);
    free(ctx.options);
    cli_logg_unsetup();
    perf_done(&ctx);
    return rc;
}

int cl_scandesc_callback(int desc, const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, struct cl_scan_options *scanoptions, void *context)
{
    return scan_common(desc, NULL, filename, virname, scanned, engine, scanoptions, context);
}

int cl_scanmap_callback(cl_fmap_t *map, const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, struct cl_scan_options *scanoptions, void *context)
{
    return scan_common(-1, map, filename, virname, scanned, engine, scanoptions, context);
}

int cli_found_possibly_unwanted(cli_ctx *ctx)
{
    if (cli_get_last_virus(ctx))
    {
        cli_dbgmsg("found Possibly Unwanted: %s\n", cli_get_last_virus(ctx));
        if (SCAN_HEURISTIC_PRECEDENCE)
        {
            /* we found a heuristic match, don't scan further,
         * but consider it a virus. */
            cli_dbgmsg("cli_found_possibly_unwanted: CL_VIRUS\n");
            return CL_VIRUS;
        }
        /* heuristic scan isn't taking precedence, keep scanning.
     * If this is part of an archive, and
     * we find a real malware we report that instead of the
     * heuristic match */
        ctx->found_possibly_unwanted = 1;
    }
    else
    {
        cli_warnmsg("cli_found_possibly_unwanted called, but virname is not set\n");
    }
    emax_reached(ctx);
    return CL_CLEAN;
}

static int cli_scanfile(const char *filename, cli_ctx *ctx)
{
    int fd, ret;

    /* internal version of cl_scanfile with arec/mrec preserved */
    if ((fd = safe_open(filename, O_RDONLY | O_BINARY)) == -1)
        return CL_EOPEN;

    ret = cli_magic_scandesc(fd, filename, ctx);

    close(fd);
    return ret;
}

int cl_scanfile(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, struct cl_scan_options* scanoptions)
{
    return cl_scanfile_callback(filename, virname, scanned, engine, scanoptions, NULL);
}

int cl_scanfile_callback(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, struct cl_scan_options* scanoptions, void *context)
{
    int fd, ret;
    const char *fname = cli_to_utf8_maybe_alloc(filename);

    if (!fname)
        return CL_EARG;

    if ((fd = safe_open(fname, O_RDONLY | O_BINARY)) == -1)
        return CL_EOPEN;

    if (fname != filename)
        free((char *)fname);

    ret = cl_scandesc_callback(fd, filename, virname, scanned, engine, scanoptions, context);
    close(fd);

    return ret;
}

/*
Local Variables:
   c-basic-offset: 4
End:
*/
