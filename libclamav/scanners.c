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
#include <stdbool.h>
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

#include <zlib.h>

#include "clamav_rust.h"
#include "clamav.h"
#include "others.h"
#include "dconf.h"
#include "scanners.h"
#include "matcher-ac.h"
#include "matcher-bm.h"
#include "matcher.h"
#include "ole2_extract.h"
#include "vba_extract.h"
#include "xlm_extract.h"
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
#include "entconv.h"
#include "rtf.h"
#include "unarj.h"
#include "nsis/nulsft.h"
#include "autoit.h"
#include "textnorm.h"
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
#include "gif.h"
#include "png.h"
#include "iso9660.h"
#include "udf.h"
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
#include "execs.h"
#include "egg.h"

// libclamunrar_iface
#include "unrar_iface.h"

#include <bzlib.h>

#include <fcntl.h>
#include <string.h>

cl_error_t cli_magic_scan_dir(const char *dir, cli_ctx *ctx, uint32_t attributes)
{
    cl_error_t status = CL_SUCCESS;
    DIR *dd           = NULL;
    struct dirent *dent;
    STATBUF statbuf;
    char *fname = NULL;

    if ((dd = opendir(dir)) != NULL) {
        while ((dent = readdir(dd))) {
            if (dent->d_ino) {
                if (strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
                    /* build the full name */
                    fname = malloc(strlen(dir) + strlen(dent->d_name) + 2);
                    if (!fname) {
                        cli_dbgmsg("cli_magic_scan_dir: Unable to allocate memory for filename\n");
                        status = CL_EMEM;
                        goto done;
                    }

                    sprintf(fname, "%s" PATHSEP "%s", dir, dent->d_name);

                    /* stat the file */
                    if (LSTAT(fname, &statbuf) != -1) {
                        if (S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode)) {
                            status = cli_magic_scan_dir(fname, ctx, attributes);
                            if (CL_SUCCESS != status) {
                                goto done;
                            }
                        } else {
                            if (S_ISREG(statbuf.st_mode)) {
                                status = cli_magic_scan_file(fname, ctx, dent->d_name, attributes);
                                if (CL_SUCCESS != status) {
                                    goto done;
                                }
                            }
                        }
                    }
                    free(fname);
                    fname = NULL;
                }
            }
        }
    } else {
        cli_dbgmsg("cli_magic_scan_dir: Can't open directory %s.\n", dir);
        status = CL_EOPEN;
        goto done;
    }

done:
    if (NULL != dd) {
        closedir(dd);
    }
    if (NULL != fname) {
        free(fname);
    }

    return status;
}

/**
 * @brief  Scan the metadata using cli_matchmeta()
 *
 * @param metadata  unrar metadata structure
 * @param ctx       scanning context structure
 * @param files
 * @return cl_error_t  Returns CL_SUCCESS if nothing found, CL_VIRUS if something found, CL_EUNPACK if encrypted.
 */
static cl_error_t cli_unrar_scanmetadata(unrar_metadata_t *metadata, cli_ctx *ctx, unsigned int files)
{
    cl_error_t status = CL_SUCCESS;

    cli_dbgmsg("RAR: %s, crc32: 0x%x, encrypted: %u, compressed: %u, normal: %u, method: %u, ratio: %u\n",
               metadata->filename, metadata->crc, metadata->encrypted, (unsigned int)metadata->pack_size,
               (unsigned int)metadata->unpack_size, metadata->method,
               metadata->pack_size ? (unsigned int)(metadata->unpack_size / metadata->pack_size) : 0);

    if (CL_VIRUS == cli_matchmeta(ctx, metadata->filename, metadata->pack_size, metadata->unpack_size, metadata->encrypted, files, metadata->crc)) {
        status = CL_VIRUS;
    } else if (SCAN_HEURISTIC_ENCRYPTED_ARCHIVE && metadata->encrypted) {
        cli_dbgmsg("RAR: Encrypted files found in archive.\n");
        status = CL_EUNPACK;
    }

    return status;
}

static cl_error_t cli_scanrar_file(const char *filepath, int desc, cli_ctx *ctx)
{
    cl_error_t status          = CL_EPARSE;
    cl_unrar_error_t unrar_ret = UNRAR_ERR;

    unsigned int file_count = 0;

    uint32_t nEncryptedFilesFound = 0;

    void *hArchive = NULL;

    char *comment         = NULL;
    uint32_t comment_size = 0;

    unrar_metadata_t metadata;
    char *filename_base    = NULL;
    char *extract_fullpath = NULL;
    char *comment_fullpath = NULL;

    UNUSEDPARAM(desc);

    if (filepath == NULL || ctx == NULL) {
        cli_dbgmsg("RAR: Invalid arguments!\n");
        return CL_EARG;
    }

    cli_dbgmsg("in scanrar()\n");

    /* Zero out the metadata struct before we read the header */
    memset(&metadata, 0, sizeof(unrar_metadata_t));

    /*
     * Open the archive.
     */
    if (UNRAR_OK != (unrar_ret = cli_unrar_open(filepath, &hArchive, &comment, &comment_size, cli_debug_flag))) {
        if (unrar_ret == UNRAR_ENCRYPTED) {
            cli_dbgmsg("RAR: Encrypted main header\n");
            status = CL_SUCCESS;
            nEncryptedFilesFound += 1;
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

        if (ctx->engine->keeptmp) {
            int comment_fd = -1;
            if (!(comment_fullpath = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, "comments"))) {
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
                }
                close(comment_fd);
            }
        }

        /* Scan the comment */
        status = cli_magic_scan_buff(comment, comment_size, ctx, NULL, LAYER_ATTRIBUTES_NONE);
        if (status != CL_SUCCESS) {
            goto done;
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
        status = CL_SUCCESS;

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
        } else {
            file_count += 1;

            /*
             * Scan the metadata for the file in question since the content was clean, or we're running in all-match.
             */
            status = cli_unrar_scanmetadata(&metadata, ctx, file_count);
            if (status == CL_EUNPACK) {
                nEncryptedFilesFound += 1;
            } else if (status != CL_SUCCESS) {
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
                if (0 != metadata.filename[0]) {
                    (void)cli_basename(metadata.filename, strlen(metadata.filename), &filename_base, true /* posix_support_backslash_pathsep */);
                }

                if (!(ctx->engine->keeptmp) ||
                    (NULL == filename_base)) {
                    extract_fullpath = cli_gentemp(ctx->this_layer_tmpdir);
                } else {
                    extract_fullpath = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, filename_base);
                }
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
                    /*
                     * File should be extracted...
                     * ... make sure we have read permissions to the file.
                     */
                    if (0 != access(extract_fullpath, R_OK)) {
                        cli_dbgmsg("RAR: Don't have read permissions, attempting to change file permissions to make it readable..\n");
#ifdef _WIN32
                        if (0 != _chmod(extract_fullpath, _S_IREAD)) {
#else
                        if (0 != chmod(extract_fullpath, S_IRUSR | S_IRGRP)) {
#endif
                            cli_dbgmsg("RAR: Failed to change permission bits so the extracted file is readable..\n");
                        }
                    }

                    /*
                     * ... scan the extracted file.
                     */
                    cli_dbgmsg("RAR: Extraction complete.  Scanning now...\n");
                    status = cli_magic_scan_file(extract_fullpath, ctx, filename_base, LAYER_ATTRIBUTES_NONE);
                    if (status == CL_EOPEN) {
                        cli_dbgmsg("RAR: File not found, Extraction failed!\n");

                        // Don't abort the scan just because one file failed to extract.
                        status = CL_SUCCESS;
                    } else {
                        /* Delete the tempfile if not --leave-temps */
                        if (!ctx->engine->keeptmp) {
                            if (cli_unlink(extract_fullpath)) {
                                cli_dbgmsg("RAR: Failed to unlink the extracted file: %s\n", extract_fullpath);
                            }
                        }

                        if (status != CL_SUCCESS) {
                            // Bail out if "virus" and also if exceeded scan maximums, etc.
                            goto done;
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

        /*
         * Free up any malloced metadata...
         */
        if (NULL != filename_base) {
            free(filename_base);
            filename_base = NULL;
        }

    } while (status == CL_SUCCESS);

    if (status == CL_BREAK) {
        status = CL_SUCCESS;
    }

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

    if (NULL != extract_fullpath) {
        free(extract_fullpath);
        extract_fullpath = NULL;
    }

    if ((CL_VIRUS != status) && (nEncryptedFilesFound > 0)) {
        /* If user requests enabled the Heuristic for encrypted archives... */
        if (SCAN_HEURISTIC_ENCRYPTED_ARCHIVE) {
            if (CL_VIRUS == cli_append_potentially_unwanted(ctx, "Heuristics.Encrypted.RAR")) {
                status = CL_VIRUS;
            }
        }
    }

    cli_dbgmsg("RAR: Exit code: %d\n", status);

    return status;
}

static cl_error_t cli_scanrar(cli_ctx *ctx)
{
    cl_error_t status = CL_SUCCESS;

    const char *filepath = NULL;
    int fd               = -1;

    char *tmpname = NULL;
    int tmpfd     = -1;

    if ((SCAN_UNPRIVILEGED) ||
        (NULL == ctx->fmap->path) ||
        (0 != access(ctx->fmap->path, R_OK)) ||
        (ctx->fmap->nested_offset > 0) || (ctx->fmap->len < ctx->fmap->real_len)) {

        /* If map is not file-backed have to dump to file for scanrar. */
        status = fmap_dump_to_file(ctx->fmap, ctx->fmap->path, ctx->this_layer_tmpdir, &tmpname, &tmpfd, 0, SIZE_MAX);
        if (status != CL_SUCCESS) {
            cli_dbgmsg("cli_magic_scan: failed to generate temporary file.\n");
            goto done;
        }
        filepath = tmpname;
        fd       = tmpfd;
    } else {
        /* Use the original file and file descriptor. */
        filepath = ctx->fmap->path;
        fd       = fmap_fd(ctx->fmap);
    }

    /* scan file */
    status = cli_scanrar_file(filepath, fd, ctx);

    if ((NULL == tmpname) && (CL_EOPEN == status)) {
        /*
         * Failed to open the file using the original filename.
         * Try writing the file descriptor to a temp file and try again.
         */
        status = fmap_dump_to_file(ctx->fmap, ctx->fmap->path, ctx->this_layer_tmpdir, &tmpname, &tmpfd, 0, SIZE_MAX);
        if (status != CL_SUCCESS) {
            cli_dbgmsg("cli_magic_scan: failed to generate temporary file.\n");
            goto done;
        }
        filepath = tmpname;
        fd       = tmpfd;

        /* try to scan again */
        status = cli_scanrar_file(filepath, fd, ctx);
    }

done:
    if (tmpfd != -1) {
        /* If dumped tempfile, need to cleanup */
        close(tmpfd);
        if (!ctx->engine->keeptmp) {
            if (cli_unlink(tmpname)) {
                status = CL_EUNLINK;
            }
        }
    }

    if (tmpname != NULL) {
        free(tmpname);
    }
    return status;
}

/**
 * @brief  Scan the metadata using cli_matchmeta()
 *
 * @param metadata  egg metadata structure
 * @param ctx       scanning context structure
 * @param files     number of files
 * @return cl_error_t  Returns CL_SUCCESS if nothing found, CL_VIRUS if something found, CL_EUNPACK if encrypted.
 */
static cl_error_t cli_egg_scanmetadata(cl_egg_metadata *metadata, cli_ctx *ctx, unsigned int files)
{
    cl_error_t status = CL_SUCCESS;

    cli_dbgmsg("EGG: %s, encrypted: %u, compressed: %u, normal: %u, ratio: %u\n",
               metadata->filename, metadata->encrypted, (unsigned int)metadata->pack_size,
               (unsigned int)metadata->unpack_size,
               metadata->pack_size ? (unsigned int)(metadata->unpack_size / metadata->pack_size) : 0);

    if (CL_VIRUS == cli_matchmeta(ctx, metadata->filename, metadata->pack_size, metadata->unpack_size, metadata->encrypted, files, 0)) {
        status = CL_VIRUS;
    } else if (SCAN_HEURISTIC_ENCRYPTED_ARCHIVE && metadata->encrypted) {
        cli_dbgmsg("EGG: Encrypted files found in archive.\n");
        status = CL_EUNPACK;
    }

    return status;
}

static cl_error_t cli_scanegg(cli_ctx *ctx)
{
    cl_error_t status = CL_SUCCESS;
    cl_error_t egg_ret;

    unsigned int file_count = 0;

    uint32_t nEncryptedFilesFound = 0;

    void *hArchive = NULL;

    char **comments    = NULL;
    uint32_t nComments = 0;

    cl_egg_metadata metadata;
    char *filename_base    = NULL;
    char *extract_fullpath = NULL;
    char *comment_fullpath = NULL;

    char *extract_filename    = NULL;
    char *extract_buffer      = NULL;
    size_t extract_buffer_len = 0;

    if (ctx == NULL) {
        cli_dbgmsg("EGG: Invalid arguments!\n");
        return CL_EARG;
    }

    cli_dbgmsg("in scanegg()\n");

    /* Zero out the metadata struct before we read the header */
    memset(&metadata, 0, sizeof(cl_egg_metadata));

    /*
     * Open the archive.
     */
    if (CL_SUCCESS != (egg_ret = cli_egg_open(ctx->fmap, &hArchive, &comments, &nComments))) {
        if (egg_ret == CL_EUNPACK) {
            cli_dbgmsg("EGG: Encrypted main header\n");
            nEncryptedFilesFound += 1;
            status = CL_SUCCESS;
            goto done;
        }
        if (egg_ret == CL_EMEM) {
            status = CL_EMEM;
            goto done;
        } else {
            status = CL_EFORMAT;
            goto done;
        }
    }

    /* If the archive header had a comment, write it to the comment dir. */
    if (comments != NULL) {
        uint32_t i;
        for (i = 0; i < nComments; i++) {
            /*
             * Drop the comment to a temp file, if requested
             */
            if (ctx->engine->keeptmp) {
                int comment_fd   = -1;
                size_t prefixLen = strlen("comments_") + 5;
                char *prefix     = (char *)malloc(prefixLen + 1);

                snprintf(prefix, prefixLen, "comments_%u", i);
                prefix[prefixLen] = '\0';

                if (!(comment_fullpath = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, prefix))) {
                    free(prefix);
                    status = CL_EMEM;
                    goto done;
                }
                free(prefix);

                comment_fd = open(comment_fullpath, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0600);
                if (comment_fd < 0) {
                    cli_dbgmsg("EGG: ERROR: Failed to open output file\n");
                } else {
                    cli_dbgmsg("EGG: Writing the archive comment to temp file: %s\n", comment_fullpath);
                    if (0 == write(comment_fd, comments[i], nComments)) {
                        cli_dbgmsg("EGG: ERROR: Failed to write to output file\n");
                    }
                    close(comment_fd);
                }
                free(comment_fullpath);
                comment_fullpath = NULL;
            }

            /*
             * Scan the comment.
             */
            status = cli_magic_scan_buff(comments[i], strlen(comments[i]), ctx, NULL, LAYER_ATTRIBUTES_NONE);
            if (status != CL_SUCCESS) {
                goto done;
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
        status = CL_SUCCESS;

        /* Zero out the metadata struct before we read the header */
        memset(&metadata, 0, sizeof(cl_egg_metadata));

        /*
         * Get the header information for the next file in the archive.
         */
        egg_ret = cli_egg_peek_file_header(hArchive, &metadata);
        if (egg_ret != CL_SUCCESS) {
            if (egg_ret == CL_EUNPACK) {
                /* Found an encrypted file header, must skip. */
                cli_dbgmsg("EGG: Encrypted file header, unable to reading file metadata and file contents. Skipping file...\n");
                nEncryptedFilesFound += 1;

                if (CL_SUCCESS != cli_egg_skip_file(hArchive)) {
                    /* Failed to skip!  Break extraction loop. */
                    cli_dbgmsg("EGG: Failed to skip file. EGG archive extraction has failed.\n");
                    break;
                }
            } else if (egg_ret == CL_BREAK) {
                /* No more files. Break extraction loop. */
                cli_dbgmsg("EGG: No more files in archive.\n");
                break;
            } else {
                /* Memory error or some other error reading the header info. */
                cli_dbgmsg("EGG: Error (%u) reading file header!\n", egg_ret);
                break;
            }
        } else {
            file_count += 1;

            /*
             * Scan the metadata for the file in question since the content was clean, or we're running in all-match.
             */
            status = cli_egg_scanmetadata(&metadata, ctx, file_count);
            if (status == CL_EUNPACK) {
                nEncryptedFilesFound += 1;
            } else if (status != CL_SUCCESS) {
                break;
            }

            /* Check if we've already exceeded the scan limit */
            if (cli_checklimits("EGG", ctx, 0, 0, 0))
                break;

            if (metadata.is_dir) {
                /* Entry is a directory. Skip. */
                cli_dbgmsg("EGG: Found directory. Skipping to next file.\n");

                if (CL_SUCCESS != cli_egg_skip_file(hArchive)) {
                    /* Failed to skip!  Break extraction loop. */
                    cli_dbgmsg("EGG: Failed to skip directory. EGG archive extraction has failed.\n");
                    break;
                }
            } else if (cli_checklimits("EGG", ctx, metadata.unpack_size, 0, 0)) {
                /* File size exceeds maxfilesize, must skip extraction.
                 * Although we may be able to scan the metadata */

                cli_dbgmsg("EGG: Next file is too large (%" PRIu64 " bytes); it would exceed max scansize.  Skipping to next file.\n", metadata.unpack_size);

                if (CL_SUCCESS != cli_egg_skip_file(hArchive)) {
                    /* Failed to skip!  Break extraction loop. */
                    cli_dbgmsg("EGG: Failed to skip file. EGG archive extraction has failed.\n");
                    break;
                }
            } else if (metadata.encrypted != 0) {
                /* Found an encrypted file, must skip. */
                cli_dbgmsg("EGG: Encrypted file, unable to extract file contents. Skipping file...\n");
                nEncryptedFilesFound += 1;

                if (CL_SUCCESS != cli_egg_skip_file(hArchive)) {
                    /* Failed to skip!  Break extraction loop. */
                    cli_dbgmsg("EGG: Failed to skip file. EGG archive extraction has failed.\n");
                    break;
                }
            } else {
                /*
                 * Extract the file...
                 */

                cli_dbgmsg("EGG: Extracting file: %s\n", metadata.filename);

                egg_ret = cli_egg_extract_file(hArchive, (const char **)&extract_filename, (const char **)&extract_buffer, &extract_buffer_len);
                if (egg_ret != CL_SUCCESS) {
                    /*
                     * Some other error extracting the file
                     */
                    cli_dbgmsg("EGG: Error extracting file: %s\n", metadata.filename);
                } else if (!extract_buffer || 0 == extract_buffer_len) {
                    /*
                     * Empty file. Skip.
                     */
                    cli_dbgmsg("EGG: Skipping empty file: %s\n", metadata.filename);

                    if (NULL != extract_filename) {
                        free(extract_filename);
                        extract_filename = NULL;
                    }
                    if (NULL != extract_buffer) {
                        free(extract_buffer);
                        extract_buffer = NULL;
                    }
                } else {
                    /*
                     * Drop to a temp file, if requested.
                     */
                    if (NULL != metadata.filename) {
                        (void)cli_basename(metadata.filename, strlen(metadata.filename), &filename_base, true /* posix_support_backslash_pathsep */);
                    }

                    if (ctx->engine->keeptmp) {
                        int extracted_fd = -1;
                        if (NULL == filename_base) {
                            extract_fullpath = cli_gentemp(ctx->this_layer_tmpdir);
                        } else {
                            extract_fullpath = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, filename_base);
                        }
                        if (NULL == extract_fullpath) {
                            cli_dbgmsg("EGG: Memory error allocating filename for extracted file.");
                            status = CL_EMEM;
                            break;
                        }

                        extracted_fd = open(extract_fullpath, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0600);
                        if (extracted_fd < 0) {
                            cli_dbgmsg("EGG: ERROR: Failed to open output file\n");
                        } else {
                            cli_dbgmsg("EGG: Writing the extracted file contents to temp file: %s\n", extract_fullpath);
                            if (0 == write(extracted_fd, extract_buffer, extract_buffer_len)) {
                                cli_dbgmsg("EGG: ERROR: Failed to write to output file\n");
                            } else {
                                close(extracted_fd);
                                extracted_fd = -1;
                            }
                        }
                    }

                    /*
                     * Scan the extracted file...
                     */
                    cli_dbgmsg("EGG: Extraction complete.  Scanning now...\n");
                    status = cli_magic_scan_buff(extract_buffer, extract_buffer_len, ctx, filename_base, LAYER_ATTRIBUTES_NONE);
                    if (status != CL_SUCCESS) {
                        goto done;
                    }

                    if (NULL != filename_base) {
                        free(filename_base);
                        filename_base = NULL;
                    }
                    if (NULL != extract_filename) {
                        free(extract_filename);
                        extract_filename = NULL;
                    }
                    if (NULL != extract_buffer) {
                        free(extract_buffer);
                        extract_buffer = NULL;
                    }
                }

                /* Free up that the filepath */
                if (NULL != extract_fullpath) {
                    free(extract_fullpath);
                    extract_fullpath = NULL;
                }
            }
        }

        if (ctx->engine->maxscansize && ctx->scansize >= ctx->engine->maxscansize) {
            status = CL_SUCCESS;
            break;
        }

        /*
         * TODO: Free up any malloced metadata...
         */
        if (metadata.filename != NULL) {
            free(metadata.filename);
            metadata.filename = NULL;
        }

    } while (status == CL_SUCCESS);

    if (status == CL_BREAK) {
        status = CL_SUCCESS;
    }

done:

    if (NULL != extract_filename) {
        free(extract_filename);
        extract_filename = NULL;
    }

    if (NULL != extract_buffer) {
        free(extract_buffer);
        extract_buffer = NULL;
    }

    if (NULL != comment_fullpath) {
        free(comment_fullpath);
        comment_fullpath = NULL;
    }

    if (NULL != hArchive) {
        cli_egg_close(hArchive);
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

    if ((CL_VIRUS != status) && (nEncryptedFilesFound > 0)) {
        /* If user requests enabled the Heuristic for encrypted archives... */
        if (SCAN_HEURISTIC_ENCRYPTED_ARCHIVE) {
            if (CL_VIRUS == cli_append_potentially_unwanted(ctx, "Heuristics.Encrypted.EGG")) {
                status = CL_VIRUS;
            }
        }
    }

    cli_dbgmsg("EGG: Exit code: %d\n", status);

    return status;
}

static cl_error_t cli_scanarj(cli_ctx *ctx)
{
    cl_error_t ret = CL_SUCCESS;
    int file       = 0;
    arj_metadata_t metadata;
    char *dir = NULL;

    cli_dbgmsg("in cli_scanarj()\n");

    memset(&metadata, 0, sizeof(arj_metadata_t));

    /* generate the temporary directory */
    if (!(dir = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, "arj-tmp")))
        return CL_EMEM;

    if (mkdir(dir, 0700)) {
        cli_dbgmsg("ARJ: Can't create temporary directory %s\n", dir);
        free(dir);
        return CL_ETMPDIR;
    }

    ret = cli_unarj_open(ctx->fmap, dir, &metadata);
    if (ret != CL_SUCCESS) {
        if (!ctx->engine->keeptmp)
            cli_rmdirs(dir);
        free(dir);
        cli_dbgmsg("ARJ: Error: %s\n", cl_strerror(ret));
        return ret;
    }

    do {
        metadata.filename = NULL;

        ret = cli_unarj_prepare_file(&metadata);
        if (ret != CL_SUCCESS) {
            cli_dbgmsg("ARJ: cli_unarj_prepare_file Error: %s\n", cl_strerror(ret));
            break;
        }

        file++;

        if (CL_VIRUS == cli_matchmeta(ctx, metadata.filename, metadata.comp_size, metadata.orig_size, metadata.encrypted, file, 0)) {
            cli_rmdirs(dir);
            free(dir);
            return CL_VIRUS;
        }

        if ((ret = cli_checklimits("ARJ", ctx, metadata.orig_size, metadata.comp_size, 0)) != CL_SUCCESS) {
            ret = CL_SUCCESS;
            if (metadata.filename)
                free(metadata.filename);
            continue;
        }

        ret = cli_unarj_extract_file(dir, &metadata);
        if (ret != CL_SUCCESS) {
            cli_dbgmsg("ARJ: cli_unarj_extract_file Error: %s\n", cl_strerror(ret));
        }

        if (metadata.ofd >= 0) {
            if (lseek(metadata.ofd, 0, SEEK_SET) == -1) {
                cli_dbgmsg("ARJ: call to lseek() failed\n");
            }

            ret = cli_magic_scan_desc(metadata.ofd, NULL, ctx, metadata.filename, LAYER_ATTRIBUTES_NONE);
            close(metadata.ofd);
            if (ret != CL_SUCCESS) {
                break;
            }
        }

        if (metadata.filename) {
            free(metadata.filename);
            metadata.filename = NULL;
        }

    } while (ret == CL_SUCCESS);

    if (!ctx->engine->keeptmp) {
        cli_rmdirs(dir);
    }

    if (NULL != dir) {
        free(dir);
    }

    if (metadata.filename) {
        free(metadata.filename);
    }

    cli_dbgmsg("ARJ: Exit code: %d\n", ret);

    if (ret == CL_BREAK) {
        ret = CL_SUCCESS;
    }

    return ret;
}

static cl_error_t cli_scangzip_with_zib_from_the_80s(cli_ctx *ctx, unsigned char *buff)
{
    int fd;
    cl_error_t ret;
    size_t outsize = 0;
    int bytes;
    fmap_t *map = ctx->fmap;
    char *tmpname;
    gzFile gz;

    ret = fmap_fd(map);
    if (ret < 0)
        return CL_EDUP;
    fd = dup(ret);
    if (fd < 0)
        return CL_EDUP;

    if (!(gz = gzdopen(fd, "rb"))) {
        close(fd);
        return CL_EOPEN;
    }

    if ((ret = cli_gentempfd(ctx->this_layer_tmpdir, &tmpname, &fd)) != CL_SUCCESS) {
        cli_dbgmsg("GZip: Can't generate temporary file.\n");
        gzclose(gz);
        close(fd);
        return ret;
    }

    while ((bytes = gzread(gz, buff, FILEBUFF)) > 0) {
        outsize += bytes;
        if (cli_checklimits("GZip", ctx, outsize, 0, 0) != CL_SUCCESS)
            break;
        if (cli_writen(fd, buff, (size_t)bytes) != (size_t)bytes) {
            close(fd);
            gzclose(gz);
            if (cli_unlink(tmpname)) {
                free(tmpname);
                return CL_EUNLINK;
            }
            free(tmpname);
            return CL_EWRITE;
        }
    }

    gzclose(gz);

    if (CL_SUCCESS != (ret = cli_magic_scan_desc(fd, tmpname, ctx, NULL, LAYER_ATTRIBUTES_NONE))) {
        close(fd);
        if (!ctx->engine->keeptmp) {
            (void)cli_unlink(tmpname);
        }
        free(tmpname);
        return ret;
    }
    close(fd);
    if (!ctx->engine->keeptmp) {
        if (cli_unlink(tmpname)) {
            ret = CL_EUNLINK;
        }
    }
    free(tmpname);
    return ret;
}

static cl_error_t cli_scangzip(cli_ctx *ctx)
{
    int fd;
    cl_error_t ret = CL_SUCCESS;
    unsigned char buff[FILEBUFF];
    char *tmpname;
    z_stream z;
    size_t at = 0, outsize = 0;
    fmap_t *map = ctx->fmap;

    cli_dbgmsg("in cli_scangzip()\n");

    memset(&z, 0, sizeof(z));
    if ((ret = inflateInit2(&z, MAX_WBITS + 16)) != Z_OK) {
        cli_dbgmsg("GZip: InflateInit failed: %d\n", ret);
        return cli_scangzip_with_zib_from_the_80s(ctx, buff);
    }

    if ((ret = cli_gentempfd(ctx->this_layer_tmpdir, &tmpname, &fd)) != CL_SUCCESS) {
        cli_dbgmsg("GZip: Can't generate temporary file.\n");
        inflateEnd(&z);
        return ret;
    }

    while (at < map->len) {
        unsigned int bytes = MIN(map->len - at, map->pgsz);
        if (!(z.next_in = (void *)fmap_need_off_once(map, at, bytes))) {
            cli_dbgmsg("GZip: Can't read %u bytes @ %lu.\n", bytes, (long unsigned)at);
            inflateEnd(&z);
            close(fd);
            if (cli_unlink(tmpname)) {
                free(tmpname);
                return CL_EUNLINK;
            }
            free(tmpname);
            return CL_EREAD;
        }
        at += bytes;
        z.avail_in = bytes;
        do {
            int inf;
            z.avail_out = sizeof(buff);
            z.next_out  = buff;
            inf         = inflate(&z, Z_NO_FLUSH);
            if (inf != Z_OK && inf != Z_STREAM_END && inf != Z_BUF_ERROR) {
                if (sizeof(buff) == z.avail_out) {
                    cli_dbgmsg("GZip: Bad stream, nothing in output buffer.\n");
                    at = map->len;
                    break;
                } else {
                    cli_dbgmsg("GZip: Bad stream, data in output buffer.\n");
                    /* no break yet, flush extracted bytes to file */
                }
            }
            if (cli_writen(fd, buff, sizeof(buff) - z.avail_out) == (size_t)-1) {
                inflateEnd(&z);
                close(fd);
                if (cli_unlink(tmpname)) {
                    free(tmpname);
                    return CL_EUNLINK;
                }
                free(tmpname);
                return CL_EWRITE;
            }
            outsize += sizeof(buff) - z.avail_out;
            if (cli_checklimits("GZip", ctx, outsize, 0, 0) != CL_SUCCESS) {
                at = map->len;
                break;
            }
            if (inf == Z_STREAM_END) {
                at -= z.avail_in;
                inflateReset(&z);
                break;
            } else if (inf != Z_OK && inf != Z_BUF_ERROR) {
                at = map->len;
                break;
            }
        } while (z.avail_out == 0);
    }

    inflateEnd(&z);

    if (CL_SUCCESS != (ret = cli_magic_scan_desc(fd, tmpname, ctx, NULL, LAYER_ATTRIBUTES_NONE))) {
        close(fd);
        if (!ctx->engine->keeptmp) {
            if (cli_unlink(tmpname)) {
                free(tmpname);
                return CL_EUNLINK;
            }
        }
        free(tmpname);
        return ret;
    }
    close(fd);
    if (!ctx->engine->keeptmp)
        if (cli_unlink(tmpname))
            ret = CL_EUNLINK;
    free(tmpname);

    return ret;
}

#ifdef NOBZ2PREFIX
#define BZ2_bzDecompressInit bzDecompressInit
#define BZ2_bzDecompress bzDecompress
#define BZ2_bzDecompressEnd bzDecompressEnd
#endif

static cl_error_t cli_scanbzip(cli_ctx *ctx)
{
    cl_error_t ret = CL_SUCCESS;
    int fd, rc;
    uint64_t size = 0;
    char *tmpname;
    bz_stream strm;
    size_t off = 0;
    size_t avail;
    char buf[FILEBUFF];

    memset(&strm, 0, sizeof(strm));
    strm.next_out  = buf;
    strm.avail_out = sizeof(buf);
    rc             = BZ2_bzDecompressInit(&strm, 0, 0);
    if (BZ_OK != rc) {
        cli_dbgmsg("Bzip: DecompressInit failed: %d\n", rc);
        return CL_EOPEN;
    }

    if ((ret = cli_gentempfd(ctx->this_layer_tmpdir, &tmpname, &fd))) {
        cli_dbgmsg("Bzip: Can't generate temporary file.\n");
        BZ2_bzDecompressEnd(&strm);
        return ret;
    }

    do {
        if (!strm.avail_in) {
            strm.next_in  = (void *)fmap_need_off_once_len(ctx->fmap, off, FILEBUFF, &avail);
            strm.avail_in = avail;
            off += avail;
            if (!strm.avail_in) {
                cli_dbgmsg("Bzip: premature end of compressed stream\n");
                break;
            }
        }

        rc = BZ2_bzDecompress(&strm);
        if (BZ_OK != rc && BZ_STREAM_END != rc) {
            cli_dbgmsg("Bzip: decompress error: %d\n", rc);
            break;
        }

        if (!strm.avail_out || BZ_STREAM_END == rc) {

            size += sizeof(buf) - strm.avail_out;

            if (cli_writen(fd, buf, sizeof(buf) - strm.avail_out) != sizeof(buf) - strm.avail_out) {
                cli_dbgmsg("Bzip: Can't write to file.\n");
                BZ2_bzDecompressEnd(&strm);
                close(fd);
                if (!ctx->engine->keeptmp) {
                    if (cli_unlink(tmpname)) {
                        free(tmpname);
                        return CL_EUNLINK;
                    }
                }
                free(tmpname);
                return CL_EWRITE;
            }

            if (cli_checklimits("Bzip", ctx, size, 0, 0) != CL_SUCCESS)
                break;

            strm.next_out  = buf;
            strm.avail_out = sizeof(buf);
        }
    } while (BZ_STREAM_END != rc);

    BZ2_bzDecompressEnd(&strm);

    if (CL_SUCCESS != (ret = cli_magic_scan_desc(fd, tmpname, ctx, NULL, LAYER_ATTRIBUTES_NONE))) {
        close(fd);
        if (!ctx->engine->keeptmp) {
            if (cli_unlink(tmpname)) {
                free(tmpname);
                return CL_EUNLINK;
            }
        }
        free(tmpname);
        return ret;
    }
    close(fd);
    if (!ctx->engine->keeptmp)
        if (cli_unlink(tmpname))
            ret = CL_EUNLINK;
    free(tmpname);

    return ret;
}

static cl_error_t cli_scanxz(cli_ctx *ctx)
{
    cl_error_t ret = CL_SUCCESS;
    int fd, rc;
    unsigned long int size = 0;
    char *tmpname;
    struct CLI_XZ strm;
    size_t off = 0;
    size_t avail;
    unsigned char *buf;

    buf = malloc(CLI_XZ_OBUF_SIZE);
    if (buf == NULL) {
        cli_errmsg("cli_scanxz: nomemory for decompress buffer.\n");
        return CL_EMEM;
    }
    memset(&strm, 0x00, sizeof(struct CLI_XZ));
    strm.next_out  = buf;
    strm.avail_out = CLI_XZ_OBUF_SIZE;
    rc             = cli_XzInit(&strm);
    if (rc != XZ_RESULT_OK) {
        cli_errmsg("cli_scanxz: DecompressInit failed: %i\n", rc);
        free(buf);
        return CL_EOPEN;
    }

    if ((ret = cli_gentempfd(ctx->this_layer_tmpdir, &tmpname, &fd))) {
        cli_errmsg("cli_scanxz: Can't generate temporary file.\n");
        cli_XzShutdown(&strm);
        free(buf);
        return ret;
    }
    cli_dbgmsg("cli_scanxz: decompressing to file %s\n", tmpname);

    do {
        /* set up input buffer */
        if (!strm.avail_in) {
            strm.next_in  = (void *)fmap_need_off_once_len(ctx->fmap, off, CLI_XZ_IBUF_SIZE, &avail);
            strm.avail_in = avail;
            off += avail;
            if (!strm.avail_in) {
                cli_errmsg("cli_scanxz: premature end of compressed stream\n");
                ret = CL_EFORMAT;
                goto xz_exit;
            }
        }

        /* xz decompress a chunk */
        rc = cli_XzDecode(&strm);
        if (XZ_RESULT_OK != rc && XZ_STREAM_END != rc) {
            cli_dbgmsg("cli_scanxz: decompress error: %d\n", rc);
            ret = CL_EMEM;
            goto xz_exit;
        }
        // cli_dbgmsg("cli_scanxz: xz decompressed %li of %li available bytes\n",
        //            avail - strm.avail_in, avail);

        /* write decompress buffer */
        if (!strm.avail_out || rc == XZ_STREAM_END) {
            size_t towrite = CLI_XZ_OBUF_SIZE - strm.avail_out;
            size += towrite;

            // cli_dbgmsg("Writing %li bytes to XZ decompress temp file(%li byte total)\n",
            //            towrite, size);

            if (cli_writen(fd, buf, towrite) != towrite) {
                cli_errmsg("cli_scanxz: Can't write to file.\n");
                ret = CL_EWRITE;
                goto xz_exit;
            }
            if (cli_checklimits("cli_scanxz", ctx, size, 0, 0) != CL_SUCCESS) {
                cli_warnmsg("cli_scanxz: decompress file size exceeds limits - "
                            "only scanning %li bytes\n",
                            size);
                break;
            }
            strm.next_out  = buf;
            strm.avail_out = CLI_XZ_OBUF_SIZE;
        }
    } while (XZ_STREAM_END != rc);

    /* scan decompressed file */
    ret = cli_magic_scan_desc(fd, tmpname, ctx, NULL, LAYER_ATTRIBUTES_NONE);

xz_exit:
    cli_XzShutdown(&strm);
    close(fd);
    if (!ctx->engine->keeptmp) {
        if (cli_unlink(tmpname) && ret == CL_SUCCESS) {
            ret = CL_EUNLINK;
        }
    }
    free(tmpname);
    free(buf);
    return ret;
}

static cl_error_t cli_scanszdd(cli_ctx *ctx)
{
    int ofd;
    cl_error_t ret;
    char *tmpname;

    cli_dbgmsg("in cli_scanszdd()\n");

    if ((ret = cli_gentempfd(ctx->this_layer_tmpdir, &tmpname, &ofd))) {
        cli_dbgmsg("MSEXPAND: Can't generate temporary file/descriptor\n");
        return ret;
    }

    ret = cli_msexpand(ctx, ofd);

    if (ret != CL_SUCCESS) { /* CL_VIRUS or some error */
        close(ofd);
        if (!ctx->engine->keeptmp)
            if (cli_unlink(tmpname))
                ret = CL_EUNLINK;
        free(tmpname);
        return ret;
    }

    cli_dbgmsg("MSEXPAND: Decompressed into %s\n", tmpname);
    ret = cli_magic_scan_desc(ofd, tmpname, ctx, NULL, LAYER_ATTRIBUTES_NONE);
    close(ofd);
    if (!ctx->engine->keeptmp)
        if (cli_unlink(tmpname))
            ret = CL_EUNLINK;
    free(tmpname);

    return ret;
}

static cl_error_t vba_scandata(const unsigned char *data, size_t len, cli_ctx *ctx)
{
    cl_error_t ret                      = CL_SUCCESS;
    struct cli_matcher *generic_ac_root = ctx->engine->root[0];
    struct cli_matcher *target_ac_root  = ctx->engine->root[2];
    struct cli_ac_data gmdata, tmdata;
    bool gmdata_initialized = false;
    bool tmdata_initialized = false;
    struct cli_ac_data *mdata[2];
    bool must_pop_stack = false;

    cl_fmap_t *new_map = NULL;

    if ((ret = cli_ac_initdata(&tmdata, target_ac_root->ac_partsigs, target_ac_root->ac_lsigs, target_ac_root->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN))) {
        goto done;
    }
    tmdata_initialized = true;

    if ((ret = cli_ac_initdata(&gmdata, generic_ac_root->ac_partsigs, generic_ac_root->ac_lsigs, generic_ac_root->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN))) {
        goto done;
    }
    gmdata_initialized = true;

    mdata[0] = &tmdata;
    mdata[1] = &gmdata;

    ret = cli_scan_buff(data, len, 0, ctx, CL_TYPE_MSOLE2, mdata);
    if (CL_SUCCESS != ret) {
        goto done;
    }

    /*
     * Evaluate logical & yara rules given the new matches to see if anything alerts.
     */
    new_map = fmap_open_memory(data, len, NULL);
    if (new_map == NULL) {
        cli_dbgmsg("Failed to create fmap for evaluating logical/yara rules after call to cli_scan_buff()\n");
        ret = CL_EMEM;
        goto done;
    }

    ret = cli_recursion_stack_push(ctx, new_map, CL_TYPE_MSOLE2, true, LAYER_ATTRIBUTES_NONE); /* Perform exp_eval with child fmap */
    if (CL_SUCCESS != ret) {
        cli_dbgmsg("Failed to scan fmap.\n");
        goto done;
    }

    must_pop_stack = true;

    ret = cli_exp_eval(ctx, target_ac_root, &tmdata, NULL);
    if (CL_SUCCESS != ret) {
        goto done;
    }

    ret = cli_exp_eval(ctx, generic_ac_root, &gmdata, NULL);

done:

    if (must_pop_stack) {
        (void)cli_recursion_stack_pop(ctx); /* Restore the parent fmap */
    }

    if (NULL != new_map) {
        fmap_free(new_map);
    }

    if (tmdata_initialized) {
        cli_ac_freedata(&tmdata);
    }

    if (gmdata_initialized) {
        cli_ac_freedata(&gmdata);
    }

    return ret;
}

/**
 * Find a file in a directory tree.
 * \param filename Name of the file to find
 * \param dir Directory path where to find the file
 * \param A pointer to the string to store the result into
 * \param Size of the string to store the result in
 */
cl_error_t find_file(const char *filename, const char *dir, char *result, size_t result_size)
{
    DIR *dd;
    struct dirent *dent;
    char fullname[PATH_MAX];
    cl_error_t ret;
    size_t len;
    STATBUF statbuf;

    if (!result) {
        return CL_ENULLARG;
    }

    if ((dd = opendir(dir)) != NULL) {
        while ((dent = readdir(dd))) {
            if (dent->d_ino) {
                if (strcmp(dent->d_name, ".") != 0 && strcmp(dent->d_name, "..") != 0) {

                    snprintf(fullname, sizeof(fullname), "%s" PATHSEP "%s", dir, dent->d_name);
                    fullname[sizeof(fullname) - 1] = '\0';

                    /* stat the file */
                    if (LSTAT(fullname, &statbuf) != -1) {
                        if (S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode)) {
                            ret = find_file(filename, fullname, result, result_size);
                            if (ret == CL_SUCCESS) {
                                closedir(dd);
                                return ret;
                            }
                        } else if (S_ISREG(statbuf.st_mode)) {
                            if (strcmp(dent->d_name, filename) == 0) {
                                len = MIN(strlen(dir) + 1, result_size);
                                memcpy(result, dir, len);
                                result[len - 1] = '\0';
                                closedir(dd);
                                return CL_SUCCESS;
                            }
                        }
                    }
                }
            }
        }
        closedir(dd);
    }

    return CL_EOPEN;
}

/**
 * Scan an OLE directory for a VBA project.
 * Contrary to cli_ole2_tempdir_scan_vba, this function uses the dir file to locate VBA modules.
 */
static cl_error_t cli_ole2_tempdir_scan_vba_new(const char *dir, cli_ctx *ctx, struct uniq *U, int *has_macros)
{
    cl_error_t ret   = CL_SUCCESS;
    uint32_t hashcnt = 0;
    char *hash       = NULL;
    char path[PATH_MAX];
    char filename[PATH_MAX];
    int tempfd     = -1;
    char *tempfile = NULL;

    if (CL_SUCCESS != (ret = uniq_get(U, "dir", 3, &hash, &hashcnt))) {
        cli_dbgmsg("cli_ole2_tempdir_scan_vba_new: uniq_get('dir') failed with ret code (%d)!\n", ret);
        return ret;
    }

    while (hashcnt) {
        // Find the directory containing the extracted dir file. This is complicated
        // because ClamAV doesn't use the file names from the OLE file, but temporary names,
        // and we have neither the complete path of the dir file in the OLE container,
        // nor the mapping of the temporary directory names to their OLE names.
        snprintf(filename, sizeof(filename), "%s_%u", hash, hashcnt);
        filename[sizeof(filename) - 1] = '\0';

        if (CL_SUCCESS == find_file(filename, dir, path, sizeof(path))) {
            cli_dbgmsg("cli_ole2_tempdir_scan_vba_new: Found dir file: %s\n", path);
            if ((ret = cli_vba_readdir_new(ctx, path, U, hash, hashcnt, &tempfd, has_macros, &tempfile)) != CL_SUCCESS) {
                // FIXME: Since we only know the stream name of the OLE2 stream, but not its path inside the
                //        OLE2 archive, we don't know if we have the right file. The only thing we can do is
                //        iterate all of them until one succeeds.
                cli_dbgmsg("cli_ole2_tempdir_scan_vba_new: Failed to read dir from %s, trying others (error: %s (%d))\n", path, cl_strerror(ret), (int)ret);

                if (tempfile) {
                    if (!ctx->engine->keeptmp) {
                        remove(tempfile);
                    }
                    free(tempfile);
                    tempfile = NULL;
                }

                ret = CL_SUCCESS;
                hashcnt--;
                continue;
            }

            if (*has_macros && SCAN_COLLECT_METADATA && (ctx->this_layer_metadata_json != NULL)) {
                cli_jsonbool(ctx->this_layer_metadata_json, "HasMacros", 1);
                json_object *macro_languages = cli_jsonarray(ctx->this_layer_metadata_json, "MacroLanguages");
                if (macro_languages) {
                    cli_jsonstr(macro_languages, NULL, "VBA");
                } else {
                    cli_dbgmsg("[cli_ole2_tempdir_scan_vba_new] Failed to add \"VBA\" entry to MacroLanguages JSON array\n");
                }
            }

            if (SCAN_HEURISTIC_MACROS && *has_macros) {
                ret = cli_append_potentially_unwanted(ctx, "Heuristics.OLE2.ContainsMacros.VBA");
                if (ret == CL_VIRUS) {
                    goto done;
                }
            }

            /*
             * Now rewind the extracted vba-project output FD and scan it!
             */
            if (lseek(tempfd, 0, SEEK_SET) != 0) {
                cli_dbgmsg("cli_ole2_tempdir_scan_vba_new: Failed to seek to beginning of temporary VBA project file\n");
                ret = CL_ESEEK;
                goto done;
            }

            ret = cli_scan_desc(tempfd, ctx, CL_TYPE_SCRIPT, false, NULL, AC_SCAN_VIR, NULL, "extracted-vba-project", tempfile, LAYER_ATTRIBUTES_NONE);
            if (CL_SUCCESS != ret) {
                goto done;
            }

            close(tempfd);
            tempfd = -1;

            if (tempfile) {
                if (!ctx->engine->keeptmp) {
                    remove(tempfile);
                }
                free(tempfile);
                tempfile = NULL;
            }
        }

        hashcnt--;
    }

done:
    if (tempfd != -1) {
        close(tempfd);
        tempfd = -1;
    }

    if (tempfile) {
        if (!ctx->engine->keeptmp) {
            remove(tempfile);
        }
        free(tempfile);
        tempfile = NULL;
    }

    return ret;
}

/**
 * @brief find the summary information files and write out the meta to the JSON.
 *
 * @param dir   The directory containing ole2 temp files
 * @param ctx       The scan context
 * @param U         The unique structure indicating while files exist in the directory
 * @return cl_error_t
 */
static cl_error_t cli_ole2_tempdir_scan_summary(const char *dir, cli_ctx *ctx, struct uniq *U)
{
    cl_error_t status = CL_SUCCESS;
    cl_error_t ret;
    char summary_filename[1024];
    char *hash;
    uint32_t hashcnt = 0;

    if (CL_SUCCESS != (ret = uniq_get(U, "_5_summaryinformation", 21, &hash, &hashcnt))) {
        cli_dbgmsg("cli_ole2_tempdir_scan_summary: uniq_get('_5_summaryinformation') failed with ret code (%d)!\n", ret);
        status = ret;
        goto done;
    }
    while (hashcnt) {
        int fd = -1;

        snprintf(summary_filename, sizeof(summary_filename), "%s" PATHSEP "%s_%u", dir, hash, hashcnt);
        summary_filename[sizeof(summary_filename) - 1] = '\0';

        fd = open(summary_filename, O_RDONLY | O_BINARY);
        if (fd >= 0) {
            cli_dbgmsg("cli_ole2_tempdir_scan_summary: detected a '_5_summaryinformation' stream\n");
            /* JSONOLE2 - what to do if something breaks? */
            cli_ole2_summary_json(ctx, fd, 0, summary_filename);
            close(fd);
        }
        hashcnt--;
    }

    if (CL_SUCCESS != (ret = uniq_get(U, "_5_documentsummaryinformation", 29, &hash, &hashcnt))) {
        cli_dbgmsg("cli_ole2_tempdir_scan_summary: uniq_get('_5_documentsummaryinformation') failed with ret code (%d)!\n", ret);
        status = ret;
        goto done;
    }
    while (hashcnt) {
        int fd = -1;

        snprintf(summary_filename, sizeof(summary_filename), "%s" PATHSEP "%s_%u", dir, hash, hashcnt);
        summary_filename[sizeof(summary_filename) - 1] = '\0';

        fd = open(summary_filename, O_RDONLY | O_BINARY);
        if (fd >= 0) {
            cli_dbgmsg("cli_ole2_tempdir_scan_summary: detected a '_5_documentsummaryinformation' stream\n");
            /* JSONOLE2 - what to do if something breaks? */
            cli_ole2_summary_json(ctx, fd, 1, summary_filename);
            close(fd);
        }
        hashcnt--;
    }

done:

    return status;
}

/**
 * @brief Check the ole2 temp directory for embedded OLE objects
 *
 * @param dir   The ole2 temp directory
 * @param ctx       The scan context
 * @param U         The uniq structure which recors what files are in the temp directory
 * @return cl_error_t
 */
static cl_error_t cli_ole2_tempdir_scan_embedded_ole10(const char *dir, cli_ctx *ctx, struct uniq *U)
{
    cl_error_t status = CL_SUCCESS;
    cl_error_t ret;
    char ole10_filename[1024];
    char *hash;
    uint32_t hashcnt = 0;

    int fd = -1;

    /* Check directory for embedded OLE objects */
    if (CL_SUCCESS != (ret = uniq_get(U, "_1_ole10native", 14, &hash, &hashcnt))) {
        cli_dbgmsg("cli_ole2_tempdir_scan_embedded_ole10: uniq_get('_1_ole10native') failed with ret code (%d)!\n", ret);
        status = ret;
        goto done;
    }
    while (hashcnt) {
        snprintf(ole10_filename, sizeof(ole10_filename), "%s" PATHSEP "%s_%u", dir, hash, hashcnt);
        ole10_filename[sizeof(ole10_filename) - 1] = '\0';

        fd = open(ole10_filename, O_RDONLY | O_BINARY);
        if (fd < 0) {
            hashcnt--;
            continue;
        }

        ret = cli_scan_ole10(fd, ctx);
        if (CL_SUCCESS != ret) {
            status = ret;
            goto done;
        }

        close(fd);
        fd = -1;

        hashcnt--;
    }

done:

    if (fd >= 0) {
        close(fd);
    }

    return status;
}

static cl_error_t cli_ole2_tempdir_scan_vba(const char *dir, cli_ctx *ctx, struct uniq *U, int *has_macros)
{
    cl_error_t status = CL_SUCCESS;
    cl_error_t ret;
    int i, j;
    size_t data_len;
    vba_project_t *vba_project = NULL;
    char *fullname             = NULL;
    char vbaname[1024];
    unsigned char *data = NULL;
    char *hash;
    uint32_t hashcnt = 0;

    int fd = -1;

    int proj_contents_fd      = -1;
    char *proj_contents_fname = NULL;

    if (CL_SUCCESS != (status = uniq_get(U, "_vba_project", 12, NULL, &hashcnt))) {
        cli_dbgmsg("cli_ole2_tempdir_scan_vba: uniq_get('_vba_project') failed with ret code (%d)!\n", status);
        goto done;
    }
    while (hashcnt) {
        if (!(vba_project = (vba_project_t *)cli_vba_readdir(dir, U, hashcnt))) {
            hashcnt--;
            continue;
        }

        for (i = 0; i < vba_project->count; i++) {
            for (j = 1; (unsigned int)j <= vba_project->colls[i]; j++) {
                snprintf(vbaname, 1024, "%s" PATHSEP "%s_%u", vba_project->dir, vba_project->name[i], j);
                vbaname[sizeof(vbaname) - 1] = '\0';

                fd = open(vbaname, O_RDONLY | O_BINARY);
                if (fd == -1) {
                    continue;
                }

                cli_dbgmsg("cli_ole2_tempdir_scan_vba: Decompress VBA project '%s_%u'\n", vba_project->name[i], j);

                data = (unsigned char *)cli_vba_inflate(fd, vba_project->offset[i], &data_len);

                close(fd);
                fd = -1;

                *has_macros = *has_macros + 1;

                if (NULL != data) {
                    /* cli_dbgmsg("Project content:\n%s", data); */
                    if (ctx->scanned)
                        *ctx->scanned += data_len;
                    if (ctx->engine->keeptmp) {
                        if (CL_SUCCESS != (status = cli_gentempfd(ctx->this_layer_tmpdir, &proj_contents_fname, &proj_contents_fd))) {
                            cli_warnmsg("WARNING: VBA project '%s_%u' cannot be dumped to file\n", vba_project->name[i], j);
                            goto done;
                        }

                        if (cli_writen(proj_contents_fd, data, data_len) != data_len) {
                            cli_warnmsg("WARNING: VBA project '%s_%u' failed to write to file\n", vba_project->name[i], j);
                            status = CL_EWRITE;
                            goto done;
                        }

                        close(proj_contents_fd);
                        proj_contents_fd = -1;

                        cli_dbgmsg("cli_ole2_tempdir_scan_vba: VBA project '%s_%u' dumped to %s\n", vba_project->name[i], j, proj_contents_fname);

                        free(proj_contents_fname);
                        proj_contents_fname = NULL;
                    }

                    status = vba_scandata(data, data_len, ctx);
                    if (CL_SUCCESS != status) {
                        goto done;
                    }

                    free(data);
                    data = NULL;
                }
            }
        }

        cli_free_vba_project(vba_project);
        vba_project = NULL;

        hashcnt--;
    }

    if (CL_SUCCESS != (status = uniq_get(U, "powerpoint document", 19, &hash, &hashcnt))) {
        cli_dbgmsg("cli_ole2_tempdir_scan_vba: uniq_get('powerpoint document') failed with ret code (%d)!\n", status);
        goto done;
    }
    while (hashcnt) {
        snprintf(vbaname, 1024, "%s" PATHSEP "%s_%u", dir, hash, hashcnt);
        vbaname[sizeof(vbaname) - 1] = '\0';

        fd = open(vbaname, O_RDONLY | O_BINARY);
        if (fd == -1) {
            hashcnt--;
            continue;
        }

        fullname = cli_ppt_vba_read(fd, ctx);
        if (NULL != fullname) {
            status = cli_magic_scan_dir(fullname, ctx, LAYER_ATTRIBUTES_NONE);
            if (CL_SUCCESS != status) {
                goto done;
            }

            if (!ctx->engine->keeptmp) {
                cli_rmdirs(fullname);
            }
            free(fullname);
            fullname = NULL;
        }

        close(fd);
        fd = -1;

        hashcnt--;
    }

    if (CL_SUCCESS != (status = uniq_get(U, "worddocument", 12, &hash, &hashcnt))) {
        cli_dbgmsg("cli_ole2_tempdir_scan_vba: uniq_get('worddocument') failed with ret code (%d)!\n", status);
        goto done;
    }
    while (hashcnt) {
        snprintf(vbaname, sizeof(vbaname), "%s" PATHSEP "%s_%u", dir, hash, hashcnt);
        vbaname[sizeof(vbaname) - 1] = '\0';

        fd = open(vbaname, O_RDONLY | O_BINARY);
        if (fd == -1) {
            hashcnt--;
            continue;
        }

        if (!(vba_project = (vba_project_t *)cli_wm_readdir(fd))) {
            close(fd);
            fd = -1;
            hashcnt--;
            continue;
        }

        for (i = 0; i < vba_project->count; i++) {
            cli_dbgmsg("cli_ole2_tempdir_scan_vba: Decompress WM project macro:%d key:%d length:%d\n", i, vba_project->key[i], vba_project->length[i]);

            data = (unsigned char *)cli_wm_decrypt_macro(fd, vba_project->offset[i], vba_project->length[i], vba_project->key[i]);
            if (!data) {
                cli_dbgmsg("cli_ole2_tempdir_scan_vba: WARNING: WM project '%s' macro %d decrypted to NULL\n", vba_project->name[i], i);
            } else {
                cli_dbgmsg("cli_ole2_tempdir_scan_vba: Project content:\n%s", data);

                if (ctx->scanned) {
                    *ctx->scanned += vba_project->length[i];
                }

                status = vba_scandata(data, vba_project->length[i], ctx);
                if (CL_SUCCESS != status) {
                    goto done;
                }

                free(data);
                data = NULL;
            }
        }

        close(fd);
        fd = -1;

        cli_free_vba_project(vba_project);
        vba_project = NULL;

        hashcnt--;
    }

done:

    if (*has_macros) {
        if (SCAN_COLLECT_METADATA && (ctx->this_layer_metadata_json != NULL)) {
            cli_jsonbool(ctx->this_layer_metadata_json, "HasMacros", 1);
            json_object *macro_languages = cli_jsonarray(ctx->this_layer_metadata_json, "MacroLanguages");
            if (macro_languages) {
                cli_jsonstr(macro_languages, NULL, "VBA");
            } else {
                cli_dbgmsg("cli_ole2_tempdir_scan_vba: Failed to add \"VBA\" entry to MacroLanguages JSON array\n");
            }
        }

        if (SCAN_HEURISTIC_MACROS) {
            ret = cli_append_potentially_unwanted(ctx, "Heuristics.OLE2.ContainsMacros.VBA");
            if (ret == CL_VIRUS) {
                status = ret;
            }
        }
    }

    if (proj_contents_fd >= 0) {
        close(proj_contents_fd);
    }
    if (NULL != proj_contents_fname) {
        free(proj_contents_fname);
    }

    if (NULL != vba_project) {
        cli_free_vba_project(vba_project);
    }

    if (NULL != data) {
        free(data);
    }

    if (NULL != fullname) {
        if (!ctx->engine->keeptmp) {
            (void)cli_rmdirs(fullname);
        }

        free(fullname);
    }

    if (fd >= 0) {
        close(fd);
    }

    return status;
}

static cl_error_t cli_ole2_tempdir_scan_for_xlm_and_images(const char *dir, cli_ctx *ctx, struct uniq *U)
{
    cl_error_t ret      = CL_SUCCESS;
    char *hash          = NULL;
    uint32_t hashcnt    = 0;
    char STR_WORKBOOK[] = "workbook";
    char STR_BOOK[]     = "book";

    if (CL_SUCCESS != (ret = uniq_get(U, STR_WORKBOOK, sizeof(STR_WORKBOOK) - 1, &hash, &hashcnt))) {
        if (CL_SUCCESS != (ret = uniq_get(U, STR_BOOK, sizeof(STR_BOOK) - 1, &hash, &hashcnt))) {
            cli_dbgmsg("cli_ole2_tempdir_scan_for_xlm_and_images: uniq_get('%s') failed with ret code (%d)!\n", STR_BOOK, ret);
            goto done;
        }
    }

    for (; hashcnt > 0; hashcnt--) {
        if (CL_SUCCESS != (ret = cli_extract_xlm_macros_and_images(dir, ctx, hash, hashcnt))) {
            switch (ret) {
                case CL_VIRUS:
                case CL_EMEM:
                    goto done;
                default:
                    cli_dbgmsg("cli_ole2_tempdir_scan_for_xlm_and_images: An error occurred when parsing XLM BIFF temp file, skipping to next file.\n");
            }
        }
    }

done:
    return ret;
}

const char *const HTML_URIS_JSON_KEY = "URIs";
/* https://www.iana.org/assignments/uri-schemes/uri-schemes.xhtml  */
const char *URI_LIST[] = {
    "aaa://",
    "aaas://",
    "about://",
    "acap://",
    "acct://",
    "acd://",
    "acr://",
    "adiumxtra://",
    "adt://",
    "afp://",
    "afs://",
    "aim://",
    "amss://",
    "android://",
    "appdata://",
    "apt://",
    "ar://",
    "ark://",
    "at://",
    "attachment://",
    "aw://",
    "barion://",
    "bb://",
    "beshare://",
    "bitcoin://",
    "bitcoincash://",
    "blob://",
    "bolo://",
    "brid://",
    "browserext://",
    "cabal://",
    "calculator://",
    "callto://",
    "cap://",
    "cast://",
    "casts://",
    "chrome://",
    "chrome-extension://",
    "cid://",
    "coap://",
    "coap+tcp://",
    "coap+ws://",
    "coaps://",
    "coaps+tcp://",
    "coaps+ws://",
    "com-eventbrite-attendee://",
    "content://",
    "content-type://",
    "crid://",
    "cstr://",
    "cvs://",
    "dab://",
    "dat://",
    "data://",
    "dav://",
    "dhttp://",
    "diaspora://",
    "dict://",
    "did://",
    "dis://",
    "dlna-playcontainer://",
    "dlna-playsingle://",
    "dns://",
    "dntp://",
    "doi://",
    "dpp://",
    "drm://",
    "drop://",
    "dtmi://",
    "dtn://",
    "dvb://",
    "dvx://",
    "dweb://",
    "ed2k://",
    "eid://",
    "elsi://",
    "embedded://",
    "ens://",
    "ethereum://",
    "example://",
    "facetime://",
    "fax://",
    "feed://",
    "feedready://",
    "fido://",
    "file://",
    "filesystem://",
    "finger://",
    "first-run-pen-experience://",
    "fish://",
    "fm://",
    "ftp://",
    "fuchsia-pkg://",
    "geo://",
    "gg://",
    "git://",
    "gitoid://",
    "gizmoproject://",
    "go://",
    "gopher://",
    "graph://",
    "grd://",
    "gtalk://",
    "h323://",
    "ham://",
    "hcap://",
    "hcp://",
    "hs20://",
    "http://",
    "https://",
    "hxxp://",
    "hxxps://",
    "hydrazone://",
    "hyper://",
    "iax://",
    "icap://",
    "icon://",
    "im://",
    "imap://",
    "info://",
    "iotdisco://",
    "ipfs://",
    "ipn://",
    "ipns://",
    "ipp://",
    "ipps://",
    "irc://",
    "irc6://",
    "ircs://",
    "iris://",
    "iris.beep://",
    "iris.lwz://",
    "iris.xpc://",
    "iris.xpcs://",
    "isostore://",
    "itms://",
    "jabber://",
    "jar://",
    "jms://",
    "keyparc://",
    "lastfm://",
    "lbry://",
    "ldap://",
    "ldaps://",
    "leaptofrogans://",
    "lid://",
    "lorawan://",
    "lpa://",
    "lvlt://",
    "machineProvisioningProgressReporter://",
    "magnet://",
    "mailserver://",
    "mailto://",
    "maps://",
    "market://",
    "matrix://",
    "message://",
    "microsoft.windows.camera://",
    "microsoft.windows.camera.multipicker://",
    "microsoft.windows.camera.picker://",
    "mid://",
    "mms://",
    "modem://",
    "mongodb://",
    "moz://",
    "ms-access://",
    "ms-appinstaller://",
    "ms-browser-extension://",
    "ms-calculator://",
    "ms-drive-to://",
    "ms-enrollment://",
    "ms-excel://",
    "ms-eyecontrolspeech://",
    "ms-gamebarservices://",
    "ms-gamingoverlay://",
    "ms-getoffice://",
    "ms-help://",
    "ms-infopath://",
    "ms-inputapp://",
    "ms-launchremotedesktop://",
    "ms-lockscreencomponent-config://",
    "ms-media-stream-id://",
    "ms-meetnow://",
    "ms-mixedrealitycapture://",
    "ms-mobileplans://",
    "ms-newsandinterests://",
    "ms-officeapp://",
    "ms-people://",
    "ms-project://",
    "ms-powerpoint://",
    "ms-publisher://",
    "ms-recall://",
    "ms-remotedesktop://",
    "ms-remotedesktop-launch://",
    "ms-restoretabcompanion://",
    "ms-screenclip://",
    "ms-screensketch://",
    "ms-search://",
    "ms-search-repair://",
    "ms-secondary-screen-controller://",
    "ms-secondary-screen-setup://",
    "ms-settings://",
    "ms-settings-airplanemode://",
    "ms-settings-bluetooth://",
    "ms-settings-camera://",
    "ms-settings-cellular://",
    "ms-settings-cloudstorage://",
    "ms-settings-connectabledevices://",
    "ms-settings-displays-topology://",
    "ms-settings-emailandaccounts://",
    "ms-settings-language://",
    "ms-settings-location://",
    "ms-settings-lock://",
    "ms-settings-nfctransactions://",
    "ms-settings-notifications://",
    "ms-settings-power://",
    "ms-settings-privacy://",
    "ms-settings-proximity://",
    "ms-settings-screenrotation://",
    "ms-settings-wifi://",
    "ms-settings-workplace://",
    "ms-spd://",
    "ms-stickers://",
    "ms-sttoverlay://",
    "ms-transit-to://",
    "ms-useractivityset://",
    "ms-virtualtouchpad://",
    "ms-visio://",
    "ms-walk-to://",
    "ms-whiteboard://",
    "ms-whiteboard-cmd://",
    "ms-word://",
    "msnim://",
    "msrp://",
    "msrps://",
    "mss://",
    "mt://",
    "mtqp://",
    "mumble://",
    "mupdate://",
    "mvn://",
    "mvrp://",
    "mvrps://",
    "news://",
    "nfs://",
    "ni://",
    "nih://",
    "nntp://",
    "notes://",
    "num://",
    "ocf://",
    "oid://",
    "onenote://",
    "onenote-cmd://",
    "opaquelocktoken://",
    "openid://",
    "openpgp4fpr://",
    "otpauth://",
    "p1://",
    "pack://",
    "palm://",
    "paparazzi://",
    "payment://",
    "payto://",
    "pkcs11://",
    "platform://",
    "pop://",
    "pres://",
    "prospero://",
    "proxy://",
    "pwid://",
    "psyc://",
    "pttp://",
    "qb://",
    "query://",
    "quic-transport://",
    "redis://",
    "rediss://",
    "reload://",
    "res://",
    "resource://",
    "rmi://",
    "rsync://",
    "rtmfp://",
    "rtmp://",
    "rtsp://",
    "rtsps://",
    "rtspu://",
    "sarif://",
    "secondlife://",
    "secret-token://",
    "service://",
    "session://",
    "sftp://",
    "sgn://",
    "shc://",
    "shttp://",
    "sieve://",
    "simpleledger://",
    "simplex://",
    "sip://",
    "sips://",
    "skype://",
    "smb://",
    "smp://",
    "sms://",
    "smtp://",
    "snews://",
    "snmp://",
    "soap.beep://",
    "soap.beeps://",
    "soldat://",
    "spiffe://",
    "spotify://",
    "ssb://",
    "ssh://",
    "starknet://",
    "steam://",
    "stun://",
    "stuns://",
    "submit://",
    "svn://",
    "swh://",
    "swid://",
    "swidpath://",
    "tag://",
    "taler://",
    "teamspeak://",
    "tel://",
    "teliaeid://",
    "telnet://",
    "tftp://",
    "things://",
    "thismessage://",
    "tip://",
    "tn3270://",
    "tool://",
    "turn://",
    "turns://",
    "tv://",
    "udp://",
    "unreal://",
    "upt://",
    "urn://",
    "ut2004://",
    "uuid-in-package://",
    "v-event://",
    "vemmi://",
    "ventrilo://",
    "ves://",
    "videotex://",
    "vnc://",
    "view-source://",
    "vscode://",
    "vscode-insiders://",
    "vsls://",
    "w3://",
    "wais://",
    "web3://",
    "wcr://",
    "webcal://",
    "web+ap://",
    "wifi://",
    "wpid://",
    "ws://",
    "wss://",
    "wtai://",
    "wyciwyg://",
    "xcon://",
    "xcon-userid://",
    "xfire://",
    "xmlrpc.beep://",
    "xmlrpc.beeps://",
    "xmpp://",
    "xftp://",
    "xrcp://",
    "xri://",
    "ymsgr://",
    "z39.50://",
    "z39.50r://",
    "z39.50s://"};

static bool is_url(const char *const str, size_t str_len)
{
    bool bRet = false;
    size_t i;

    for (i = 0; i < sizeof(URI_LIST) / sizeof(URI_LIST[0]); i++) {
        if (str && (str_len > strlen(URI_LIST[i])) && (0 == strncasecmp(str, URI_LIST[i], strlen(URI_LIST[i])))) {
            bRet = true;
            goto done;
        }
    }
done:
    return bRet;
}

static void save_urls(cli_ctx *ctx, tag_arguments_t *hrefs, form_data_t *form_data)
{
    int i            = 0;
    json_object *ary = NULL;

    if (NULL == hrefs) {
        return;
    }

    if (!(SCAN_STORE_HTML_URIS && SCAN_COLLECT_METADATA && (ctx->this_layer_metadata_json != NULL))) {
        return;
    }

    /*Add hrefs*/
    for (i = 0; i < hrefs->count; i++) {
        if (is_url((const char *)hrefs->value[i], strlen((const char *)hrefs->value[i]))) {
            if (NULL == ary) {
                ary = cli_jsonarray(ctx->this_layer_metadata_json, HTML_URIS_JSON_KEY);
                if (!ary) {
                    cli_dbgmsg("[cli_scanhtml] Failed to add \"%s\" entry JSON array\n", HTML_URIS_JSON_KEY);
                    return;
                }
            }
            cli_jsonstr(ary, NULL, (const char *)hrefs->value[i]);
        }
    }

    /*Add form_data*/
    for (i = 0; i < (int)form_data->count; i++) {
        if (is_url((const char *)form_data->urls[i], strlen((const char *)form_data->urls[i]))) {
            if (NULL == ary) {
                ary = cli_jsonarray(ctx->this_layer_metadata_json, HTML_URIS_JSON_KEY);
                if (!ary) {
                    cli_dbgmsg("[cli_scanhtml] Failed to add \"%s\" entry JSON array\n", HTML_URIS_JSON_KEY);
                    return;
                }
            }
            cli_jsonstr(ary, NULL, (const char *)form_data->urls[i]);
        }
    }
}

static cl_error_t cli_scanhtml(cli_ctx *ctx)
{
    cl_error_t status = CL_SUCCESS;
    char *tempname    = NULL;
    char fullname[1024];
    int fd            = -1;
    fmap_t *map       = ctx->fmap;
    uint64_t curr_len = map->len;

    cli_dbgmsg("in cli_scanhtml()\n");

    /* CL_ENGINE_MAX_HTMLNORMALIZE */
    if (curr_len > ctx->engine->maxhtmlnormalize) {
        cli_dbgmsg("cli_scanhtml: exiting (file larger than MaxHTMLNormalize)\n");
        status = CL_SUCCESS;
        goto done;
    }

    if (NULL == (tempname = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, "html-tmp"))) {
        status = CL_EMEM;
        goto done;
    }

    if (mkdir(tempname, 0700)) {
        cli_errmsg("cli_scanhtml: Can't create temporary directory %s\n", tempname);
        status = CL_ETMPDIR;
        goto done;
    }

    cli_dbgmsg("cli_scanhtml: using tempdir %s\n", tempname);

    /* Output JSON Summary Information */
    if (SCAN_STORE_HTML_URIS && SCAN_COLLECT_METADATA && (ctx->this_layer_metadata_json != NULL)) {
        tag_arguments_t hrefs = {0};
        hrefs.scanContents    = 1;
        form_data_t form_data = {0};
        (void)html_normalise_map_form_data(ctx, map, tempname, &hrefs, ctx->dconf, &form_data);
        save_urls(ctx, &hrefs, &form_data);
        html_tag_arg_free(&hrefs);
        html_form_data_tag_free(&form_data);
    } else {
        (void)html_normalise_map(ctx, map, tempname, NULL, ctx->dconf);
    }

    snprintf(fullname, 1024, "%s" PATHSEP "nocomment.html", tempname);
    fd = open(fullname, O_RDONLY | O_BINARY);
    if (fd >= 0) {
        // nocomment.html file exists, so lets scan it.

        status = cli_scan_desc(fd, ctx, CL_TYPE_HTML, false, NULL, AC_SCAN_VIR, NULL, "no-comment", fullname, LAYER_ATTRIBUTES_NORMALIZED);
        if (CL_SUCCESS != status) {
            goto done;
        }

        close(fd);
        fd = -1;
    }

    /* CL_ENGINE_MAX_HTMLNOTAGS */
    curr_len = map->len;
    if (curr_len > ctx->engine->maxhtmlnotags) {
        /* we're not interested in scanning large files in notags form */
        /* TODO: don't even create notags if file is over limit */
        cli_dbgmsg("cli_scanhtml: skipping notags (normalized size over MaxHTMLNoTags)\n");
    } else {
        snprintf(fullname, 1024, "%s" PATHSEP "notags.html", tempname);

        fd = open(fullname, O_RDONLY | O_BINARY);
        if (fd >= 0) {
            // notags.html file exists, so lets scan it.

            status = cli_scan_desc(fd, ctx, CL_TYPE_HTML, false, NULL, AC_SCAN_VIR, NULL, "no-tags", fullname, LAYER_ATTRIBUTES_NORMALIZED);
            if (CL_SUCCESS != status) {
                goto done;
            }

            close(fd);
            fd = -1;
        }
    }

    snprintf(fullname, 1024, "%s" PATHSEP "javascript", tempname);
    fd = open(fullname, O_RDONLY | O_BINARY);
    if (fd >= 0) {
        // javascript file exists, so lets scan it (twice, as different types).

        status = cli_scan_desc(fd, ctx, CL_TYPE_HTML, false, NULL, AC_SCAN_VIR, NULL, "javascript-as-html", fullname, LAYER_ATTRIBUTES_NORMALIZED);
        if (CL_SUCCESS != status) {
            goto done;
        }

        status = cli_scan_desc(fd, ctx, CL_TYPE_TEXT_ASCII, false, NULL, AC_SCAN_VIR, NULL, "javascript-as-text-ascii", fullname, LAYER_ATTRIBUTES_NORMALIZED);
        if (CL_SUCCESS != status) {
            goto done;
        }

        close(fd);
        fd = -1;
    }

    snprintf(fullname, 1024, "%s" PATHSEP "rfc2397", tempname);

    status = cli_magic_scan_dir(fullname, ctx, LAYER_ATTRIBUTES_NORMALIZED);
    if (CL_EOPEN == status) {
        /* If the directory doesn't exist, that's fine */
        status = CL_SUCCESS;
    } else {
        goto done;
    }

done:
    if (fd >= 0) {
        close(fd);
    }
    if (NULL != tempname) {
        if (!ctx->engine->keeptmp) {
            cli_rmdirs(tempname);
        }
        free(tempname);
    }

    return status;
}

static cl_error_t cli_scanscript(cli_ctx *ctx)
{
    cl_error_t ret = CL_SUCCESS;
    const unsigned char *buff;
    unsigned char *normalized = NULL;
    struct text_norm_state state;
    char *tmpname = NULL;
    int ofd       = -1;
    struct cli_matcher *target_ac_root;
    uint32_t maxpatlen, offset = 0;
    struct cli_matcher *generic_ac_root;
    struct cli_ac_data gmdata, tmdata;
    int gmdata_initialized = 0;
    int tmdata_initialized = 0;
    struct cli_ac_data *mdata[2];
    cl_fmap_t *new_map = NULL;
    fmap_t *map;
    size_t at = 0;
    uint64_t curr_len;
    struct cli_target_info info;

    if (!ctx || !ctx->engine->root)
        return CL_ENULLARG;

    map             = ctx->fmap;
    curr_len        = map->len;
    generic_ac_root = ctx->engine->root[0];
    target_ac_root  = ctx->engine->root[7];
    maxpatlen       = target_ac_root ? target_ac_root->maxpatlen : 0;

    // Initialize info so it's safe to pass to destroy later
    cli_targetinfo_init(&info);

    cli_dbgmsg("in cli_scanscript()\n");

    /* CL_ENGINE_MAX_SCRIPTNORMALIZE */
    if (curr_len > ctx->engine->maxscriptnormalize) {
        cli_dbgmsg("cli_scanscript: exiting (file larger than MaxScriptSize)\n");
        ret = CL_SUCCESS;
        goto done;
    }

    if (!(normalized = malloc(SCANBUFF + maxpatlen))) {
        cli_dbgmsg("cli_scanscript: Unable to malloc %u bytes\n", SCANBUFF);
        ret = CL_EMEM;
        goto done;
    }
    text_normalize_init(&state, normalized, SCANBUFF + maxpatlen);

    if ((ret = cli_ac_initdata(&tmdata, target_ac_root ? target_ac_root->ac_partsigs : 0, target_ac_root ? target_ac_root->ac_lsigs : 0, target_ac_root ? target_ac_root->ac_reloff_num : 0, CLI_DEFAULT_AC_TRACKLEN))) {
        goto done;
    }
    tmdata_initialized = 1;

    if ((ret = cli_ac_initdata(&gmdata, generic_ac_root->ac_partsigs, generic_ac_root->ac_lsigs, generic_ac_root->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN))) {
        goto done;
    }
    gmdata_initialized = 1;

    /* dump to disk only if explicitly asked to
     * or if necessary to check relative offsets,
     * otherwise we can process just in-memory */
    if (ctx->engine->keeptmp || (target_ac_root && (target_ac_root->ac_reloff_num > 0 || target_ac_root->linked_bcs))) {
        if ((ret = cli_gentempfd(ctx->this_layer_tmpdir, &tmpname, &ofd))) {
            cli_dbgmsg("cli_scanscript: Can't generate temporary file/descriptor\n");
            goto done;
        }
        if (ctx->engine->keeptmp)
            cli_dbgmsg("cli_scanscript: saving normalized file to %s\n", tmpname);
    }

    mdata[0] = &tmdata;
    mdata[1] = &gmdata;

    /* If there's a relative offset in target_ac_root or triggered bytecodes, normalize to file.*/
    if (target_ac_root && (target_ac_root->ac_reloff_num > 0 || target_ac_root->linked_bcs)) {
        size_t map_off = 0;
        while (map_off < map->len) {
            size_t written;
            if (!(written = text_normalize_map(&state, map, map_off)))
                break;
            map_off += written;

            if (write(ofd, state.out, state.out_pos) == -1) {
                cli_errmsg("cli_scanscript: can't write to file %s\n", tmpname);
                ret = CL_EWRITE;
                goto done;
            }
            text_normalize_reset(&state);
        }

        /* Temporarily store the normalized file map in the context. */
        new_map = fmap_new(ofd, 0, 0, NULL, tmpname);
        if (new_map == NULL) {
            cli_dbgmsg("cli_scanscript: could not map file %s\n", tmpname);
            goto done;
        }

        /* Perform cli_scan_fmap with child fmap */
        ret = cli_recursion_stack_push(ctx, new_map, CL_TYPE_TEXT_ASCII, true, LAYER_ATTRIBUTES_NORMALIZED);
        if (CL_SUCCESS != ret) {
            cli_dbgmsg("Failed to scan fmap.\n");
            goto done;
        }

        /* scan map */
        ret = cli_scan_fmap(ctx, CL_TYPE_TEXT_ASCII, false, NULL, AC_SCAN_VIR, NULL);

        (void)cli_recursion_stack_pop(ctx); /* Restore the parent fmap */

        if (CL_SUCCESS != ret) {
            goto done;
        }

    } else {
        /* Since the above is moderately costly all in all,
         * do the old stuff if there's no relative offsets. */

        if (target_ac_root) {
            cli_targetinfo(&info, 7, ctx);
            ret = cli_ac_caloff(target_ac_root, &tmdata, &info);
            if (ret)
                goto done;
        }

        while (1) {
            size_t len = MIN(map->pgsz, map->len - at);
            buff       = fmap_need_off_once(map, at, len);
            at += len;
            if (!buff || !len || state.out_pos + len > state.out_len) {
                /* flush if error/EOF, or too little buffer space left */
                if ((ofd != -1) && (write(ofd, state.out, state.out_pos) == -1)) {
                    cli_errmsg("cli_scanscript: can't write to file %s\n", tmpname);
                    close(ofd);
                    ofd = -1;
                    /* we can continue to scan in memory */
                }
                /* when we flush the buffer also scan */
                ret = cli_scan_buff(state.out, state.out_pos, offset, ctx, CL_TYPE_TEXT_ASCII, mdata);
                if (CL_SUCCESS != ret) {
                    goto done;
                }

                if (ctx->scanned)
                    *ctx->scanned += state.out_pos;
                offset += state.out_pos;

                /* carry over maxpatlen from previous buffer */
                if (state.out_pos > maxpatlen)
                    memmove(state.out, state.out + state.out_pos - maxpatlen, maxpatlen);
                text_normalize_reset(&state);
                state.out_pos = maxpatlen;
            }
            if (!len)
                break;
            if (!buff || text_normalize_buffer(&state, buff, len) != len) {
                cli_dbgmsg("cli_scanscript: short read during normalizing\n");
            }
        }
    }

    ret = cli_exp_eval(ctx, target_ac_root, &tmdata, NULL);
    if (CL_SUCCESS != ret) {
        goto done;
    }

    ret = cli_exp_eval(ctx, generic_ac_root, &gmdata, NULL);
    if (CL_SUCCESS != ret) {
        goto done;
    }

done:
    if (NULL != new_map) {
        fmap_free(new_map);
    }

    cli_targetinfo_destroy(&info);

    if (NULL != normalized) {
        free(normalized);
    }

    if (tmdata_initialized) {
        cli_ac_freedata(&tmdata);
    }

    if (gmdata_initialized) {
        cli_ac_freedata(&gmdata);
    }

    if (ofd != -1) {
        close(ofd);
    }

    if (tmpname != NULL) {
        if (!ctx->engine->keeptmp) {
            (void)cli_unlink(tmpname);
        }
        free(tmpname);
    }

    return ret;
}

static cl_error_t cli_scanhtml_utf16(cli_ctx *ctx)
{
    cl_error_t status = CL_ERROR;
    char *tempname    = NULL;
    char *decoded     = NULL;
    const char *buff;
    int fd = -1;
    int bytes;
    size_t at       = 0;
    fmap_t *new_map = NULL;

    cli_dbgmsg("in cli_scanhtml_utf16()\n");

    if (!(tempname = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, "html-utf16-tmp"))) {
        status = CL_EMEM;
        goto done;
    }

    if ((fd = open(tempname, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR)) < 0) {
        cli_errmsg("cli_scanhtml_utf16: Can't create file %s\n", tempname);
        status = CL_EOPEN;
        goto done;
    }

    cli_dbgmsg("cli_scanhtml_utf16: using tempfile %s\n", tempname);

    while (at < ctx->fmap->len) {
        bytes = MIN(ctx->fmap->len - at, ctx->fmap->pgsz * 16);
        if (!(buff = fmap_need_off_once(ctx->fmap, at, bytes))) {
            status = CL_EREAD;
            goto done;
        }
        at += bytes;
        decoded = cli_utf16toascii(buff, bytes);
        if (decoded) {
            if (write(fd, decoded, bytes / 2) == -1) {
                cli_errmsg("cli_scanhtml_utf16: Can't write to file %s\n", tempname);
                status = CL_EWRITE;
                goto done;
            }
            free(decoded);
            decoded = NULL;
        }
    }

    new_map = fmap_new(fd, 0, 0, NULL, tempname);
    if (NULL == new_map) {
        cli_errmsg("cli_scanhtml_utf16: failed to create fmap for ascii HTML file decoded from utf16: %s\n.", tempname);
        status = CL_EMEM;
        goto done;
    }

    /* Perform exp_eval with child fmap */
    status = cli_recursion_stack_push(ctx, new_map, CL_TYPE_HTML, true, LAYER_ATTRIBUTES_NORMALIZED);
    if (CL_SUCCESS != status) {
        cli_dbgmsg("Failed to scan fmap.\n");
        goto done;
    }

    status = cli_scanhtml(ctx);

    (void)cli_recursion_stack_pop(ctx); /* Restore the parent fmap */

    if (CL_SUCCESS != status) {
        goto done;
    }

done:
    if (NULL != new_map) {
        fmap_free(new_map);
    }
    if (-1 != fd) {
        close(fd);
    }

    if (NULL != decoded) {
        free(decoded);
    }

    if (NULL != tempname) {
        if (!ctx->engine->keeptmp) {
            (void)cli_unlink(tempname);
        } else {
            cli_dbgmsg("cli_scanhtml_utf16: Decoded HTML data saved in %s\n", tempname);
        }

        free(tempname);
    }

    return status;
}

static cl_error_t cli_ole2_scan_tempdir(
    cli_ctx *ctx,
    const char *dir,
    struct uniq *files,
    int has_vba,
    int has_xlm,
    int has_image)
{
    cl_error_t status = CL_SUCCESS;
    DIR *dd           = NULL;
    int has_macros    = 0;

    struct dirent *dent;
    STATBUF statbuf;
    char *subdirectory = NULL;

    cli_dbgmsg("cli_ole2_scan_tempdir: %s\n", dir);

    /* Output JSON Summary Information */
    if (SCAN_COLLECT_METADATA && (ctx->this_layer_metadata_json != NULL)) {
        (void)cli_ole2_tempdir_scan_summary(dir, ctx, files);
    }

    status = cli_ole2_tempdir_scan_embedded_ole10(dir, ctx, files);
    if (CL_SUCCESS != status) {
        goto done;
    }

    if (has_vba) {
        status = cli_ole2_tempdir_scan_vba(dir, ctx, files, &has_macros);
        if (CL_SUCCESS != status) {
            goto done;
        }

        status = cli_ole2_tempdir_scan_vba_new(dir, ctx, files, &has_macros);
        if (CL_SUCCESS != status) {
            goto done;
        }
    }

    if (has_xlm) {
        if (SCAN_HEURISTIC_MACROS) {
            status = cli_append_potentially_unwanted(ctx, "Heuristics.OLE2.ContainsMacros.XLM");
            if (CL_SUCCESS != status) {
                goto done;
            }
        }
    }

    if (has_xlm || has_image) {
        /* TODO: Consider moving image extraction to handler_enum and
         * removing the has_image and found_image stuff. */
        status = cli_ole2_tempdir_scan_for_xlm_and_images(dir, ctx, files);
        if (CL_SUCCESS != status) {
            goto done;
        }
    }

    if (has_xlm || has_vba) {
        status = cli_magic_scan_dir(dir, ctx, LAYER_ATTRIBUTES_NONE);
        if (CL_SUCCESS != status) {
            goto done;
        }
    }

    /* ACAB: since we now hash filenames and handle collisions we
     * could avoid recursion by removing the block below and by
     * flattening the paths in ole2_walk_property_tree (case 1) */

    if ((dd = opendir(dir)) != NULL) {
        while ((dent = readdir(dd))) {
            if (dent->d_ino) {
                if (strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
                    /* build the full name */
                    subdirectory = malloc(strlen(dir) + strlen(dent->d_name) + 2);
                    if (!subdirectory) {
                        cli_dbgmsg("cli_ole2_tempdir_scan_vba: Unable to allocate memory for subdirectory path\n");
                        status = CL_EMEM;
                        break;
                    }
                    sprintf(subdirectory, "%s" PATHSEP "%s", dir, dent->d_name);

                    /* stat the file */
                    if (LSTAT(subdirectory, &statbuf) != -1) {
                        if (S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode)) {
                            /*
                             * Process subdirectory
                             */
                            status = cli_ole2_scan_tempdir(
                                ctx,
                                subdirectory,
                                files,
                                has_vba,
                                has_xlm,
                                has_image);
                            if (CL_SUCCESS != status) {
                                goto done;
                            }
                        }
                    }
                    free(subdirectory);
                    subdirectory = NULL;
                }
            }
        }
    } else {
        cli_dbgmsg("VBADir: Can't open directory %s.\n", dir);
        status = CL_EOPEN;
        goto done;
    }

done:
    if (NULL != dd) {
        closedir(dd);
    }
    if (NULL != subdirectory) {
        free(subdirectory);
    }

    return status;
}

static cl_error_t cli_scanole2(cli_ctx *ctx)
{
    char *dir          = NULL;
    cl_error_t ret     = CL_SUCCESS;
    struct uniq *files = NULL;
    int has_vba        = 0;
    int has_xlm        = 0;
    int has_image      = 0;

    cli_dbgmsg("in cli_scanole2()\n");

    /* generate the temporary directory */
    if (NULL == (dir = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, "ole2-tmp"))) {
        ret = CL_EMEM;
        goto done;
    }

    if (mkdir(dir, 0700)) {
        cli_dbgmsg("OLE2: Can't create temporary directory %s\n", dir);
        free(dir);
        dir = NULL;
        ret = CL_ETMPDIR;
        goto done;
    }

    ret = cli_ole2_extract(dir, ctx, &files, &has_vba, &has_xlm, &has_image);
    if (CL_SUCCESS != ret) {
        goto done;
    }

    if (files) {
        /*
         * Files containing the document summary, any VBA or XLM macros, or
         * images were previously extracted from an ole2 file.
         * This happens if cli_ole2_extract() executes the handler_writer()
         * because XLM, VBA, or images were found.
         * So now we need to process them.
         *
         * TODO: consider maybe processes all that stuff in memory instead of
         * writing everything to temp files?
         */
        ret = cli_ole2_scan_tempdir(
            ctx,
            dir,
            files,
            has_vba,
            has_xlm,
            has_image);
    }

done:
    if (files) {
        uniq_free(files);
    }

    if (NULL != dir) {
        if (!ctx->engine->keeptmp) {
            cli_rmdirs(dir);
        }
        free(dir);
    }

    return ret;
}

static cl_error_t cli_scantar(cli_ctx *ctx, unsigned int posix)
{
    char *dir;
    cl_error_t ret = CL_SUCCESS;

    cli_dbgmsg("in cli_scantar()\n");

    /* generate temporary directory */
    if (!(dir = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, "tar-tmp")))
        return CL_EMEM;

    if (mkdir(dir, 0700)) {
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

static cl_error_t cli_scanscrenc(cli_ctx *ctx)
{
    char *tempname;
    cl_error_t ret = CL_SUCCESS;

    cli_dbgmsg("in cli_scanscrenc()\n");

    if (!(tempname = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, "screnc-tmp")))
        return CL_EMEM;

    if (mkdir(tempname, 0700)) {
        cli_dbgmsg("CHM: Can't create temporary directory %s\n", tempname);
        free(tempname);
        return CL_ETMPDIR;
    }

    if (html_screnc_decode(ctx->fmap, tempname))
        ret = cli_magic_scan_dir(tempname, ctx, LAYER_ATTRIBUTES_NONE);

    if (!ctx->engine->keeptmp)
        cli_rmdirs(tempname);

    free(tempname);
    return ret;
}

static cl_error_t cli_scanriff(cli_ctx *ctx)
{
    cl_error_t ret = CL_SUCCESS;

    if (cli_check_riff_exploit(ctx) == 2)
        ret = cli_append_potentially_unwanted(ctx, "Heuristics.Exploit.W32.MS05-002");

    return ret;
}

static cl_error_t cli_scancryptff(cli_ctx *ctx)
{
    cl_error_t ret = CL_SUCCESS, ndesc;
    unsigned int i;
    const unsigned char *src;
    unsigned char *dest = NULL;
    char *tempfile;
    size_t pos;
    size_t bread;

    /* Skip the CryptFF file header */
    pos = 0x10;

    if ((dest = (unsigned char *)malloc(FILEBUFF)) == NULL) {
        cli_dbgmsg("CryptFF: Can't allocate memory\n");
        return CL_EMEM;
    }

    if (!(tempfile = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, "cryptff"))) {
        free(dest);
        return CL_EMEM;
    }

    if ((ndesc = open(tempfile, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR)) < 0) {
        cli_errmsg("CryptFF: Can't create file %s\n", tempfile);
        free(dest);
        free(tempfile);
        return CL_ECREAT;
    }

    for (; (src = fmap_need_off_once_len(ctx->fmap, pos, FILEBUFF, &bread)) && bread; pos += bread) {
        for (i = 0; i < bread; i++)
            dest[i] = src[i] ^ (unsigned char)0xff;
        if (cli_writen(ndesc, dest, bread) == (size_t)-1) {
            cli_dbgmsg("CryptFF: Can't write to descriptor %d\n", ndesc);
            free(dest);
            close(ndesc);
            free(tempfile);
            return CL_EWRITE;
        }
    }

    free(dest);

    cli_dbgmsg("CryptFF: Scanning decrypted data\n");

    ret = cli_magic_scan_desc(ndesc, tempfile, ctx, NULL, LAYER_ATTRIBUTES_NONE);

    close(ndesc);

    if (ctx->engine->keeptmp) {
        cli_dbgmsg("CryptFF: Decompressed data saved in %s\n", tempfile);
    } else {
        if (CL_SUCCESS != cli_unlink(tempfile)) {
            ret = CL_EUNLINK;
        }
    }

    free(tempfile);
    return ret;
}

static cl_error_t cli_scanpdf(cli_ctx *ctx, off_t offset)
{
    cl_error_t ret;
    char *dir = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, "pdf-tmp");

    if (!dir)
        return CL_EMEM;

    if (mkdir(dir, 0700)) {
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

static cl_error_t cli_scantnef(cli_ctx *ctx)
{
    cl_error_t ret;
    char *dir = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, "tnef-tmp");

    if (!dir)
        return CL_EMEM;

    if (mkdir(dir, 0700)) {
        cli_dbgmsg("Can't create temporary directory for tnef file %s\n", dir);
        free(dir);
        return CL_ETMPDIR;
    }

    ret = cli_tnef(dir, ctx);

    if (ret == CL_SUCCESS)
        ret = cli_magic_scan_dir(dir, ctx, LAYER_ATTRIBUTES_NONE);

    if (!ctx->engine->keeptmp)
        cli_rmdirs(dir);

    free(dir);
    return ret;
}

static cl_error_t cli_scanuuencoded(cli_ctx *ctx)
{
    cl_error_t ret;
    char *dir = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, "uuencoded-tmp");

    if (!dir)
        return CL_EMEM;

    if (mkdir(dir, 0700)) {
        cli_dbgmsg("Can't create temporary directory for uuencoded file %s\n", dir);
        free(dir);
        return CL_ETMPDIR;
    }

    ret = cli_uuencode(dir, ctx->fmap);

    if (ret == CL_SUCCESS)
        ret = cli_magic_scan_dir(dir, ctx, LAYER_ATTRIBUTES_NONE);

    if (!ctx->engine->keeptmp)
        cli_rmdirs(dir);

    free(dir);
    return ret;
}

static cl_error_t cli_scanmail(cli_ctx *ctx)
{
    char *dir = NULL;
    cl_error_t ret;

    cli_dbgmsg("Starting cli_scanmail()\n");

    /* generate the temporary directory */
    if (NULL == (dir = cli_gentemp_with_prefix(ctx->this_layer_tmpdir, "mail-tmp"))) {
        ret = CL_EMEM;
        goto done;
    }

    if (mkdir(dir, 0700)) {
        cli_dbgmsg("Mail: Can't create temporary directory %s\n", dir);
        ret = CL_ETMPDIR;
        goto done;
    }

    /*
     * Extract the attachments into the temporary directory
     */
    ret = cli_mbox(dir, ctx);
    if (CL_SUCCESS != ret) {
        goto done;
    }

    ret = cli_magic_scan_dir(dir, ctx, LAYER_ATTRIBUTES_NONE);
    if (CL_SUCCESS != ret) {
        goto done;
    }

done:
    if (NULL != dir) {
        if (!ctx->engine->keeptmp) {
            cli_rmdirs(dir);
        }

        free(dir);
    }

    return ret;
}

static cl_error_t cli_scan_structured(cli_ctx *ctx)
{
    char buf[8192];
    size_t result          = 0;
    unsigned int cc_count  = 0;
    unsigned int ssn_count = 0;
    bool done              = false;
    fmap_t *map;
    size_t pos = 0;
    int (*ccfunc)(const unsigned char *buffer, size_t length, int cc_only);
    int (*ssnfunc)(const unsigned char *buffer, size_t length);

    if (ctx == NULL)
        return CL_ENULLARG;

    map = ctx->fmap;

    if (ctx->engine->min_cc_count == 1)
        ccfunc = dlp_has_cc;
    else
        ccfunc = dlp_get_cc_count;

    switch (SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL | SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED) {
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

    while (!done && ((result = fmap_readn(map, buf, pos, 8191)) > 0) && (result != (size_t)-1)) {
        pos += result;
        if ((cc_count += ccfunc((const unsigned char *)buf, result,
                                (ctx->options->heuristic & CL_SCAN_HEURISTIC_STRUCTURED_CC) ? 1 : 0)) >= ctx->engine->min_cc_count) {
            done = true;
        }

        if (ssnfunc && ((ssn_count += ssnfunc((const unsigned char *)buf, result)) >= ctx->engine->min_ssn_count)) {
            done = true;
        }
    }

    if (cc_count != 0 && cc_count >= ctx->engine->min_cc_count) {
        cli_dbgmsg("cli_scan_structured: %u credit card numbers detected\n", cc_count);
        if (CL_VIRUS == cli_append_potentially_unwanted(ctx, "Heuristics.Structured.CreditCardNumber")) {
            return CL_VIRUS;
        }
    }

    if (ssn_count != 0 && ssn_count >= ctx->engine->min_ssn_count) {
        cli_dbgmsg("cli_scan_structured: %u social security numbers detected\n", ssn_count);
        if (CL_VIRUS == cli_append_potentially_unwanted(ctx, "Heuristics.Structured.SSN")) {
            return CL_VIRUS;
        }
    }

    return CL_SUCCESS;
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
    if (!GetThreadTimes(GetCurrentThread(), &c, &e, &k, &u)) {
        *kt = *ut = 0;
        return;
    }
    kl.LowPart  = k.dwLowDateTime;
    kl.HighPart = k.dwHighDateTime;
    ul.LowPart  = u.dwLowDateTime;
    ul.HighPart = u.dwHighDateTime;
    *kt         = kl.QuadPart / 10;
    *ut         = ul.QuadPart / 10;
#else
    struct tms tbuf;
    if (times(&tbuf) != ((clock_t)-1)) {
        clock_t tck = sysconf(_SC_CLK_TCK);
        *kt         = ((uint64_t)1000000) * tbuf.tms_stime / tck;
        *ut         = ((uint64_t)1000000) * tbuf.tms_utime / tck;
    } else {
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
    for (i = 0; i < sizeof(perf_events) / sizeof(perf_events[0]); i++) {
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

    p     = timestr;
    pend  = timestr + sizeof(timestr) - 1;
    *pend = 0;

    cli_event_time_stop(perf, PERFT_SCAN);
    get_thread_times(&kt, &ut);
    cli_event_int(perf, PERFT_KTIME, kt);
    cli_event_int(perf, PERFT_UTIME, ut);

    for (i = 0; i < sizeof(perf_events) / sizeof(perf_events[0]); i++) {
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
static inline void perf_done(cli_ctx *ctx)
{
    UNUSEDPARAM(ctx);
}
#endif

/**
 * @brief Perform raw scan of current fmap.
 *
 * @param ctx           Current scan context.
 * @param type          File type
 * @param typercg       Enable type recognition (file typing scan results).
 *                      If 0, will be a regular ac-mode scan.
 * @param[out] dettype  If typercg enabled and scan detects HTML or MAIL types,
 *                      will output HTML or MAIL types after performing HTML/MAIL scans
 * @return cl_error_t
 */
static cl_error_t scanraw(cli_ctx *ctx, cli_file_t type, uint8_t typercg, cli_file_t *dettype)
{
    cl_error_t ret = CL_SUCCESS, nret = CL_SUCCESS;
    struct cli_matched_type *ftoffset = NULL, *fpt;
    unsigned int acmode               = AC_SCAN_VIR;

    cli_file_t found_type;

    if ((typercg) &&
        // Omit embedded files or file types already identified via this process.
        (!(ctx->recursion_stack[ctx->recursion_level].attributes & LAYER_ATTRIBUTES_EMBEDDED)) &&
        // Omit GZ files because they can contain portions of original files like zip file entries that cause invalid extractions and lots of warnings. Decompress first, then scan!
        (type != CL_TYPE_GZ) &&
        // We should also omit bzips, but DMG's may be detected in bzips.
        //(type != CL_TYPE_BZ) &&
        // Omit CPIO_OLD files because it's an image format that we can extract and scan manually.
        (type != CL_TYPE_CPIO_OLD) &&
        // Omit ZIP files because it'll detect each zip file entry as SFXZIP, which is a waste. We'll extract it and then scan.
        (type != CL_TYPE_ZIP) &&
        // Omit OOXML because they are ZIP-based and file-type scanning will double-extract their contents.
        (type != CL_TYPE_OOXML_WORD) &&
        (type != CL_TYPE_OOXML_PPT) &&
        (type != CL_TYPE_OOXML_XL) &&
        (type != CL_TYPE_OOXML_HWP) &&
        // Omit OLD TAR files because it's a raw archive format that we can extract and scan manually.
        (type != CL_TYPE_OLD_TAR) &&
        // Omit POSIX TAR files because it's a raw archive format that we can extract and scan manually.
        (type != CL_TYPE_POSIX_TAR) &&
        // Omit TNEF files because TNEF message attachments are raw / not compressed. Document and ZIP attachments would be likely to have double-extraction issues.
        (type != CL_TYPE_TNEF)) {
        /*
         * Enable file type recognition scan mode if requested, except for some problematic types (above).
         */
        acmode |= AC_SCAN_FT;
    } else {
        cli_dbgmsg("scanraw: embedded type recognition disabled or not applicable for type %s %s\n",
                   cli_ftname(type),
                   (ctx->recursion_stack[ctx->recursion_level].attributes & LAYER_ATTRIBUTES_EMBEDDED) ? "(embedded layer)" : "");
    }

    perf_start(ctx, PERFT_RAW);
    ret = cli_scan_fmap(ctx, type == CL_TYPE_TEXT_ASCII ? CL_TYPE_ANY : type, false, &ftoffset, acmode, NULL);
    perf_stop(ctx, PERFT_RAW);

    // In allmatch-mode, ret will never be CL_VIRUS, so ret may be used exclusively for file type detection and for terminal errors.
    // When not in allmatch-mode, it's more important to return right away if ret is CL_VIRUS, so we don't care if file type matches were found.
    if (ret >= CL_TYPENO) {
        size_t last_offset = 0;

        // Matched 1+ file type signatures. Handle them.
        found_type = (cli_file_t)ret;

        perf_nested_start(ctx, PERFT_RAWTYPENO, PERFT_SCAN);

        fpt = ftoffset;

        while (fpt) {
            if ((fpt->offset > 0) &&
                // Only handle each offset once to prevent duplicate processing like if two signatures are found at the same offset.
                ((size_t)fpt->offset > last_offset)) {

                bool type_has_been_handled = true;
                bool ancestor_was_embedded = false;
                size_t i;

                last_offset = (size_t)fpt->offset;

                /*
                 * First, use "embedded type recognition" to identify a file's actual type.
                 * (a.k.a. not embedded files, but file type detection corrections)
                 *
                 * Do this at all fmap layers. Though we should only reassign the types
                 * if the current type makes sense for the reassignment.
                 */
                switch (fpt->type) {
                    case CL_TYPE_MHTML:
                        if (SCAN_PARSE_MAIL && (DCONF_MAIL & MAIL_CONF_MBOX)) {
                            if ((ctx->recursion_stack[ctx->recursion_level].type >= CL_TYPE_TEXT_ASCII) &&
                                (ctx->recursion_stack[ctx->recursion_level].type <= CL_TYPE_BINARY_DATA)) {
                                // HTML files may contain special characters and could be
                                // misidentified as BINARY_DATA by cli_compare_ftm_file()

                                // Reassign type of current layer based on what we discovered
                                if (CL_SUCCESS != (ret = cli_recursion_stack_change_type(ctx, fpt->type, true))) {
                                    cli_dbgmsg("Call to cli_recursion_stack_change_type() returned %s \n", cl_strerror(ret));
                                    type_has_been_handled = false;
                                } else {
                                    cli_dbgmsg("MHTML signature found at %u\n", (unsigned int)fpt->offset);
                                    nret = ret = cli_scanmail(ctx);
                                }
                            }
                        }
                        break;

                    case CL_TYPE_XDP:
                        if (SCAN_PARSE_PDF && (DCONF_DOC & DOC_CONF_PDF)) {
                            if ((ctx->recursion_stack[ctx->recursion_level].type >= CL_TYPE_TEXT_ASCII) &&
                                (ctx->recursion_stack[ctx->recursion_level].type <= CL_TYPE_BINARY_DATA)) {
                                // XML files may contain special characters and could be
                                // misidentified as BINARY_DATA by cli_compare_ftm_file()

                                // Reassign type of current layer based on what we discovered
                                if (CL_SUCCESS != (ret = cli_recursion_stack_change_type(ctx, fpt->type, true))) {
                                    cli_dbgmsg("Call to cli_recursion_stack_change_type() returned %s \n", cl_strerror(ret));
                                    type_has_been_handled = false;
                                } else {
                                    cli_dbgmsg("XDP signature found at %u\n", (unsigned int)fpt->offset);
                                    nret = ret = cli_scanxdp(ctx);
                                }
                            }
                        }
                        break;

                    case CL_TYPE_XML_WORD:
                        if (SCAN_PARSE_XMLDOCS && (DCONF_DOC & DOC_CONF_MSXML)) {
                            if ((ctx->recursion_stack[ctx->recursion_level].type >= CL_TYPE_TEXT_ASCII) &&
                                (ctx->recursion_stack[ctx->recursion_level].type <= CL_TYPE_BINARY_DATA)) {
                                // XML files may contain special characters and could be
                                // misidentified as BINARY_DATA by cli_compare_ftm_file()

                                // Reassign type of current layer based on what we discovered
                                if (CL_SUCCESS != (ret = cli_recursion_stack_change_type(ctx, fpt->type, true))) {
                                    cli_dbgmsg("Call to cli_recursion_stack_change_type() returned %s \n", cl_strerror(ret));
                                    type_has_been_handled = false;
                                } else {
                                    cli_dbgmsg("XML-WORD signature found at %u\n", (unsigned int)fpt->offset);
                                    nret = ret = cli_scanmsxml(ctx);
                                }
                            }
                        }
                        break;
                    case CL_TYPE_XML_XL:
                        if (SCAN_PARSE_XMLDOCS && (DCONF_DOC & DOC_CONF_MSXML)) {
                            if ((ctx->recursion_stack[ctx->recursion_level].type >= CL_TYPE_TEXT_ASCII) &&
                                (ctx->recursion_stack[ctx->recursion_level].type <= CL_TYPE_BINARY_DATA)) {
                                // XML files may contain special characters and could be
                                // misidentified as BINARY_DATA by cli_compare_ftm_file()

                                // Reassign type of current layer based on what we discovered
                                if (CL_SUCCESS != (ret = cli_recursion_stack_change_type(ctx, fpt->type, true))) {
                                    cli_dbgmsg("Call to cli_recursion_stack_change_type() returned %s \n", cl_strerror(ret));
                                    type_has_been_handled = false;
                                } else {
                                    cli_dbgmsg("XML-XL signature found at %u\n", (unsigned int)fpt->offset);
                                    nret = ret = cli_scanmsxml(ctx);
                                }
                            }
                        }
                        break;
                    case CL_TYPE_XML_HWP:
                        if (SCAN_PARSE_XMLDOCS && (DCONF_DOC & DOC_CONF_HWP)) {
                            if ((ctx->recursion_stack[ctx->recursion_level].type >= CL_TYPE_TEXT_ASCII) &&
                                (ctx->recursion_stack[ctx->recursion_level].type <= CL_TYPE_BINARY_DATA)) {
                                // XML files may contain special characters and could be
                                // misidentified as BINARY_DATA by cli_compare_ftm_file()

                                // Reassign type of current layer based on what we discovered
                                if (CL_SUCCESS != (ret = cli_recursion_stack_change_type(ctx, fpt->type, true))) {
                                    cli_dbgmsg("Call to cli_recursion_stack_change_type() returned %s \n", cl_strerror(ret));
                                    type_has_been_handled = false;
                                } else {
                                    cli_dbgmsg("XML-HWP signature found at %u\n", (unsigned int)fpt->offset);
                                    nret = ret = cli_scanhwpml(ctx);
                                }
                            }
                        }
                        break;

                    case CL_TYPE_DMG:
                        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_DMG)) {
                            // TODO: determine all types that DMG may start with
                            // if ((ctx->recursion_stack[ctx->recursion_level].type == CL_TYPE_BZIP2) || ...))
                            {
                                // Reassign type of current layer based on what we discovered
                                if (CL_SUCCESS != (ret = cli_recursion_stack_change_type(ctx, fpt->type, true))) {
                                    cli_dbgmsg("Call to cli_recursion_stack_change_type() returned %s \n", cl_strerror(ret));
                                    type_has_been_handled = false;
                                } else {
                                    cli_dbgmsg("DMG signature found at %u\n", (unsigned int)fpt->offset);
                                    nret = cli_scandmg(ctx);
                                }
                            }
                        }
                        break;

                    case CL_TYPE_ISO9660:
                        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ISO9660)) {
                            // TODO: determine all types that ISO9660 may start with
                            // if ((ctx->recursion_stack[ctx->recursion_level].type == CL_TYPE_ANY) || ...))
                            {
                                // Reassign type of current layer based on what we discovered
                                if (CL_SUCCESS != (ret = cli_recursion_stack_change_type(ctx, fpt->type, true))) {
                                    cli_dbgmsg("Call to cli_recursion_stack_change_type() returned %s \n", cl_strerror(ret));
                                    type_has_been_handled = false;
                                } else {
                                    cli_dbgmsg("ISO signature found at %u\n", (unsigned int)fpt->offset);
                                    nret = cli_scaniso(ctx, fpt->offset);
                                }
                            }
                        }
                        break;

                    case CL_TYPE_UDF:
                        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_UDF)) {
                            {
                                // Reassign type of current layer based on what we discovered
                                if (CL_SUCCESS != (ret = cli_recursion_stack_change_type(ctx, fpt->type, true))) {
                                    cli_dbgmsg("Call to cli_recursion_stack_change_type() returned %s \n", cl_strerror(ret));
                                    type_has_been_handled = false;
                                } else {
                                    cli_dbgmsg("UDF signature found at %u\n", (unsigned int)fpt->offset);
                                    nret = cli_scanudf(ctx, fpt->offset);
                                }
                            }
                        }
                        break;

                    case CL_TYPE_MBR:
                        if (SCAN_PARSE_ARCHIVE) {
                            // TODO: determine all types that GPT or MBR may start with
                            // if ((ctx->recursion_stack[ctx->recursion_level].type == CL_TYPE_???) ||  ...))
                            {
                                // First check if actually a GPT, not MBR.
                                cl_error_t iret = cli_mbr_check2(ctx, 0);

                                if ((iret == CL_TYPE_GPT) && (DCONF_ARCH & ARCH_CONF_GPT)) {
                                    // Reassign type of current layer based on what we discovered
                                    if (CL_SUCCESS != (ret = cli_recursion_stack_change_type(ctx, CL_TYPE_GPT, true))) {
                                        cli_dbgmsg("Call to cli_recursion_stack_change_type() returned %s \n", cl_strerror(ret));
                                        type_has_been_handled = false;
                                    } else {
                                        cli_dbgmsg("Recognized GUID Partition Table file\n");
                                        cli_dbgmsg("GPT signature found at %u\n", (unsigned int)fpt->offset);
                                        nret = cli_scangpt(ctx, 0);
                                    }
                                } else if ((iret == CL_SUCCESS) && (DCONF_ARCH & ARCH_CONF_MBR)) {
                                    // Reassign type of current layer based on what we discovered
                                    if (CL_SUCCESS != (ret = cli_recursion_stack_change_type(ctx, CL_TYPE_MBR, true))) {
                                        cli_dbgmsg("Call to cli_recursion_stack_change_type() returned %s \n", cl_strerror(ret));
                                        type_has_been_handled = false;
                                    } else {
                                        cli_dbgmsg("MBR signature found at %u\n", (unsigned int)fpt->offset);
                                        nret = cli_scanmbr(ctx, 0);
                                    }
                                }
                            }
                        }
                        break;

                    default:
                        type_has_been_handled = false;
                }

                if ((CL_EMEM == nret) || ctx->abort_scan) {
                    break;
                }

                /*
                 * Next, check for actual embedded files.
                 */
                if (false == type_has_been_handled) {
                    cli_dbgmsg("%s signature found at %u\n", cli_ftname(fpt->type), (unsigned int)fpt->offset);

                    type_has_been_handled = true;

                    switch (fpt->type) {
                        case CL_TYPE_RARSFX:
                            if ((have_rar && SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_RAR)) &&
                                (type != CL_TYPE_RAR)) {
                                // TODO: Add header validity check to prevent false positives from being scanned.
                                nret = cli_magic_scan_nested_fmap_type(
                                    ctx->fmap,
                                    fpt->offset,
                                    ctx->fmap->len - fpt->offset,
                                    ctx,
                                    CL_TYPE_RAR,
                                    NULL,
                                    LAYER_ATTRIBUTES_EMBEDDED);
                            }
                            break;

                        case CL_TYPE_EGGSFX:
                            if ((SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_EGG)) &&
                                (type != CL_TYPE_EGG)) {
                                // TODO: Add header validity check to prevent false positives from being scanned.
                                nret = cli_magic_scan_nested_fmap_type(
                                    ctx->fmap,
                                    fpt->offset,
                                    ctx->fmap->len - fpt->offset,
                                    ctx,
                                    CL_TYPE_EGG,
                                    NULL,
                                    LAYER_ATTRIBUTES_EMBEDDED);
                            }
                            break;

                        case CL_TYPE_ZIPSFX:
                            if ((SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ZIP)) &&
                                (type != CL_TYPE_ZIP) &&
                                /* OOXML are ZIP-based. */
                                (type != CL_TYPE_OOXML_WORD) &&
                                (type != CL_TYPE_OOXML_PPT) &&
                                (type != CL_TYPE_OOXML_XL) &&
                                (type != CL_TYPE_OOXML_HWP)) {
                                // Header validity check to prevent false positives from being scanned.
                                size_t zip_size = 0;

                                ret = cli_unzip_single_header_check(ctx, fpt->offset, &zip_size);
                                if (ret != CL_SUCCESS) {
                                    cli_dbgmsg("ZIP single header check failed: %s (%d)\n", cl_strerror(ret), ret);
                                    break;
                                }

                                // Increment last_offset to ignore any file type matches that occured within this legitimate archive.
                                last_offset += zip_size - 1; // Note: size is definitely > 0 because header_check succeeded.

                                nret = cli_magic_scan_nested_fmap_type(
                                    ctx->fmap,
                                    fpt->offset,
                                    zip_size,
                                    ctx,
                                    CL_TYPE_ZIP,
                                    NULL,
                                    LAYER_ATTRIBUTES_EMBEDDED);
                            }
                            break;

                        case CL_TYPE_CABSFX:
                            if ((SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_CAB)) &&
                                (type != CL_TYPE_MSCAB)) {
                                // Header validity check to prevent false positives from being scanned.
                                size_t cab_size = 0;
                                ret             = cli_mscab_header_check(ctx, fpt->offset, &cab_size);
                                if (ret != CL_SUCCESS) {
                                    cli_dbgmsg("CAB header check failed: %s (%d)\n", cl_strerror(ret), ret);
                                    break;
                                }

                                // Increment last_offset to ignore any file type matches that occured within this legitimate archive.
                                last_offset += cab_size - 1; // Note: size is definitely > 0 because header_check succeeded.

                                nret = cli_magic_scan_nested_fmap_type(
                                    ctx->fmap,
                                    fpt->offset,
                                    cab_size,
                                    ctx,
                                    CL_TYPE_MSCAB,
                                    NULL,
                                    LAYER_ATTRIBUTES_EMBEDDED);
                            }
                            break;

                        case CL_TYPE_ARJSFX:
                            if ((SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ARJ)) &&
                                (type != CL_TYPE_ARJ)) {
                                // Header validity check to prevent false positives from being scanned.
                                size_t arj_size = 0;

                                ret = cli_unarj_header_check(ctx, fpt->offset, &arj_size);
                                if (ret != CL_SUCCESS) {
                                    cli_dbgmsg("ARJ header check failed: %s (%d)\n", cl_strerror(ret), ret);
                                    break;
                                }

                                // Increment last_offset to ignore any file type matches that occured within this legitimate archive.
                                last_offset += arj_size - 1; // Note: size is definitely > 0 because header_check succeeded.

                                nret = cli_magic_scan_nested_fmap_type(
                                    ctx->fmap,
                                    fpt->offset,
                                    arj_size,
                                    ctx,
                                    CL_TYPE_ARJ,
                                    NULL,
                                    LAYER_ATTRIBUTES_EMBEDDED);
                            }
                            break;

                        case CL_TYPE_7ZSFX:
                            if ((SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_7Z)) &&
                                (type != CL_TYPE_7Z)) {
                                // TODO: Add header validity check to prevent false positives from being scanned.
                                nret = cli_magic_scan_nested_fmap_type(
                                    ctx->fmap,
                                    fpt->offset,
                                    ctx->fmap->len - fpt->offset,
                                    ctx,
                                    CL_TYPE_7Z,
                                    NULL,
                                    LAYER_ATTRIBUTES_EMBEDDED);
                            }
                            break;

                        case CL_TYPE_NULSFT:
                            // Note: CL_TYPE_NULSFT is special, because the file actually starts 4 bytes before the start of the signature match
                            if ((SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_NSIS)) &&
                                (type == CL_TYPE_MSEXE && fpt->offset > 4)) {
                                // TODO: Add header validity check to prevent false positives from being scanned.
                                nret = cli_magic_scan_nested_fmap_type(
                                    ctx->fmap,
                                    fpt->offset - 4,
                                    ctx->fmap->len - (fpt->offset - 4),
                                    ctx,
                                    CL_TYPE_NULSFT,
                                    NULL,
                                    LAYER_ATTRIBUTES_EMBEDDED);
                            }
                            break;

                        case CL_TYPE_AUTOIT:
                            if ((SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_AUTOIT)) &&
                                (type == CL_TYPE_MSEXE)) {
                                // TODO: Add header validity check to prevent false positives from being scanned.
                                nret = cli_magic_scan_nested_fmap_type(
                                    ctx->fmap,
                                    fpt->offset,
                                    ctx->fmap->len - fpt->offset,
                                    ctx,
                                    CL_TYPE_AUTOIT,
                                    NULL,
                                    LAYER_ATTRIBUTES_EMBEDDED);
                            }
                            break;

                        case CL_TYPE_ISHIELD_MSI:
                            if ((SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ISHIELD)) &&
                                (type == CL_TYPE_MSEXE)) {
                                // TODO: Add header validity check to prevent false positives from being scanned.
                                nret = cli_magic_scan_nested_fmap_type(
                                    ctx->fmap,
                                    fpt->offset,
                                    ctx->fmap->len - fpt->offset,
                                    ctx,
                                    CL_TYPE_ISHIELD_MSI,
                                    NULL,
                                    LAYER_ATTRIBUTES_EMBEDDED);
                            }
                            break;

                        case CL_TYPE_PDF:
                            if ((SCAN_PARSE_PDF && (DCONF_DOC & DOC_CONF_PDF)) &&
                                (type != CL_TYPE_PDF)) {
                                // TODO: Add header validity check to prevent false positives from being scanned.
                                nret = cli_magic_scan_nested_fmap_type(
                                    ctx->fmap,
                                    fpt->offset,
                                    ctx->fmap->len - fpt->offset,
                                    ctx,
                                    CL_TYPE_PDF,
                                    NULL,
                                    LAYER_ATTRIBUTES_EMBEDDED);
                            }
                            break;

                        case CL_TYPE_MSEXE:
                            if (SCAN_PARSE_PE && ctx->dconf->pe &&
                                (type == CL_TYPE_MSEXE || type == CL_TYPE_ZIP || type == CL_TYPE_MSOLE2)) {
                                struct cli_exe_info peinfo;

                                if ((uint64_t)(ctx->fmap->len - fpt->offset) > ctx->engine->maxembeddedpe) {
                                    cli_dbgmsg("scanraw: MaxEmbeddedPE exceeded\n");
                                    break;
                                }

                                cli_exe_info_init(&peinfo, fpt->offset);

                                // Header validity check to prevent false positives from being scanned.
                                ret = cli_peheader(ctx, &peinfo, CLI_PEHEADER_OPT_NONE);

                                // peinfo memory may have been allocated and must be freed even if it failed.
                                cli_exe_info_destroy(&peinfo);

                                if (CL_SUCCESS != ret) {
                                    cli_dbgmsg("Header check for MSEXE detection failed, probably not actually an embedded PE file.\n");
                                    break;
                                }

                                cli_dbgmsg("*** Detected embedded PE file at %u ***\n", (unsigned int)fpt->offset);

                                // Setting ctx->corrupted_input will prevent the PE parser from reporting "broken executable" for unpacked/reconstructed files that may not be 100% to spec.
                                // In here we're just carrying the corrupted_input flag from parent to child, in case the parent's flag was set.
                                unsigned int corrupted_input = ctx->corrupted_input;

                                ctx->corrupted_input = 1;

                                nret = cli_magic_scan_nested_fmap_type(
                                    ctx->fmap,
                                    fpt->offset,
                                    // Sadly, there is no way from the PE header to determine the length of the PE file.
                                    // So we just pass the remaining length of the fmap.
                                    ctx->fmap->len - fpt->offset,
                                    ctx,
                                    CL_TYPE_MSEXE,
                                    NULL,
                                    LAYER_ATTRIBUTES_EMBEDDED);

                                ctx->corrupted_input = corrupted_input;
                            }
                            break;

                        default:
                            type_has_been_handled = false;
                            cli_dbgmsg("scanraw: Type %u not handled in fpt loop\n", fpt->type);
                    }

                } // end check for embedded files

            } // end if (fpt->offset > 0)

            if ((nret == CL_EMEM) ||
                (ctx->abort_scan)) {
                break;
            }

            fpt = fpt->next;
        } // end while (fpt) loop

        if (!((nret == CL_EMEM) || (ctx->abort_scan))) {
            /*
             * Now run the other file type parsers that may rely on file type
             * recognition to determine the actual file type.
             */
            switch (found_type) {
                case CL_TYPE_HTML:
                    if (cli_recursion_stack_get_type(ctx, -2) == CL_TYPE_AUTOIT) {
                        /* bb#11196 - autoit script file misclassified as HTML */
                        ret = CL_TYPE_TEXT_ASCII;
                    } else if (SCAN_PARSE_HTML &&
                               (type == CL_TYPE_TEXT_ASCII ||
                                type == CL_TYPE_GIF) && /* Scan GIFs for embedded HTML/Javascript */
                               (DCONF_DOC & DOC_CONF_HTML)) {
                        *dettype = CL_TYPE_HTML;
                        if (CL_SUCCESS != (ret = cli_recursion_stack_change_type(ctx, CL_TYPE_HTML, true))) {
                            cli_dbgmsg("Call to cli_recursion_stack_change_type() returned %s \n", cl_strerror(ret));
                        } else {
                            nret = cli_scanhtml(ctx);
                        }
                    }
                    break;

                case CL_TYPE_MAIL:
                    if (SCAN_PARSE_MAIL && type == CL_TYPE_TEXT_ASCII && (DCONF_MAIL & MAIL_CONF_MBOX)) {
                        *dettype = CL_TYPE_MAIL;
                        if (CL_SUCCESS != (ret = cli_recursion_stack_change_type(ctx, CL_TYPE_MAIL, true))) {
                            cli_dbgmsg("Call to cli_recursion_stack_change_type() returned %s \n", cl_strerror(ret));
                        } else {
                            nret = cli_scanmail(ctx);
                        }
                    }
                    break;

                default:
                    break;
            }
        }

        perf_nested_stop(ctx, PERFT_RAWTYPENO, PERFT_SCAN);
        ret = nret;
    } // end if (ret >= CL_TYPENO)

    while (ftoffset) {
        fpt      = ftoffset;
        ftoffset = ftoffset->next;
        free(fpt);
    }

    return ret;
}

void emax_reached(cli_ctx *ctx)
{
    int32_t stack_index;

    if (NULL == ctx || NULL == ctx->recursion_stack) {
        return;
    }

    stack_index = (int32_t)ctx->recursion_level;

    while (stack_index >= 0) {
        fmap_t *map = ctx->recursion_stack[stack_index].fmap;

        if (NULL != map) {
            map->dont_cache_flag = true;
        }

        stack_index -= 1;
    }

    cli_dbgmsg("emax_reached: marked parents as non cacheable\n");
}

#define LINESTR(x) #x
#define LINESTR2(x) LINESTR(x)
#define __AT__ " at line " LINESTR2(__LINE__)

/**
 * @brief Provide the following to the calling application for each embedded file:
 *  - name of parent file
 *  - size of parent file
 *  - name of current file
 *  - size of current file
 *  - pointer to the current file data
 *
 * @param cb
 * @param ctx
 * @param filetype
 * @return cl_error_t
 */
static cl_error_t dispatch_file_inspection_callback(clcb_file_inspection cb, cli_ctx *ctx, const char *filetype)
{
    cl_error_t status = CL_SUCCESS;
    cl_error_t append_ret;

    int fd              = -1;
    uint32_t fmap_index = ctx->recursion_level; /* index of current file */

    cl_fmap_t *fmap         = NULL;
    const char *file_name   = NULL;
    size_t file_size        = 0;
    const char *file_buffer = NULL;
    const char **ancestors  = NULL;

    size_t parent_file_size = 0;

    if (NULL == cb) {
        // Callback is not set.
        goto done;
    }

    fmap = ctx->recursion_stack[fmap_index].fmap;
    fd   = fmap_fd(fmap);

    CLI_MAX_CALLOC_OR_GOTO_DONE(ancestors, ctx->recursion_level + 1, sizeof(char *), status = CL_EMEM);

    file_name   = fmap->name;
    file_buffer = fmap_need_off_once_len(fmap, 0, fmap->len, &file_size);

    while (fmap_index > 0) {
        cl_fmap_t *previous_fmap;

        fmap_index -= 1;
        previous_fmap = ctx->recursion_stack[fmap_index].fmap;

        if (ctx->recursion_level > 0 && (fmap_index == ctx->recursion_level - 1)) {
            parent_file_size = previous_fmap->len;
        }

        ancestors[fmap_index] = previous_fmap->name;
    }

    perf_start(ctx, PERFT_INSPECT);
    status = cb(fd, filetype, ancestors, parent_file_size, file_name, file_size, file_buffer,
                ctx->recursion_level, ctx->recursion_stack[ctx->recursion_level].attributes, ctx->cb_ctx);
    perf_stop(ctx, PERFT_INSPECT);

    switch (status) {
        case CL_BREAK:
            cli_dbgmsg("dispatch_file_inspection_callback: file trusted by callback\n");

            // Remove any evidence for this layer and set the verdict to trusted.
            (void)cli_trust_this_layer(ctx, "legacy file-inspection application callback");

            break;
        case CL_VIRUS:
            cli_dbgmsg("dispatch_file_inspection_callback: file blocked by callback\n");
            append_ret = cli_append_virus(ctx, "Detected.By.Callback.Inspection");
            if (append_ret == CL_VIRUS) {
                status = CL_VIRUS;
            }
            break;
        case CL_SUCCESS:
            // No action requested by callback. Keep scanning.
            break;
        default:
            status = CL_SUCCESS;
            cli_warnmsg("dispatch_file_inspection_callback: ignoring bad return code from callback\n");
    }

done:

    CLI_FREE_AND_SET_NULL(ancestors);
    return status;
}

static cl_error_t dispatch_prescan_callback(clcb_pre_scan cb, cli_ctx *ctx, const char *filetype, bool pre_cache)
{
    cl_error_t status = CL_SUCCESS;
    cl_error_t append_ret;

    if (cb) {
        perf_start(ctx, PERFT_PRECB);
        status = cb(fmap_fd(ctx->fmap), filetype, ctx->cb_ctx);
        perf_stop(ctx, PERFT_PRECB);

        switch (status) {
            case CL_BREAK: {
                const char *source = pre_cache ? "legacy pre-cache application callback"
                                               : "legacy pre-scan application callback";

                cli_dbgmsg("dispatch_prescan_callback: file allowed by callback\n");

                // Remove any evidence for this layer and set the verdict to trusted.
                (void)cli_trust_this_layer(ctx, source);

                status = CL_VERIFIED;
            } break;
            case CL_VIRUS: {
                const char *alert_name = pre_cache ? "Detected.By.Callback.PreCache"
                                                   : "Detected.By.Callback.PreScan";

                cli_dbgmsg("dispatch_prescan_callback: file blocked by callback\n");

                append_ret = cli_append_virus(ctx, alert_name);
                if (append_ret == CL_VIRUS) {
                    status = CL_VIRUS;
                }
            } break;
            case CL_SUCCESS:
                // No action requested by callback. Keep scanning.
                break;
            default:
                status = CL_SUCCESS;
                cli_warnmsg("dispatch_prescan_callback: ignoring bad return code from callback\n");
        }
    }

    return status;
}

static cl_error_t calculate_fuzzy_image_hash(cli_ctx *ctx, cli_file_t type)
{
    cl_error_t status       = CL_EPARSE;
    const uint8_t *offset   = NULL;
    image_fuzzy_hash_t hash = {0};
    json_object *header     = NULL;

    FFIError *fuzzy_hash_calc_error = NULL;

    offset = fmap_need_off(ctx->fmap, 0, ctx->fmap->real_len);

    if (SCAN_COLLECT_METADATA && (NULL != ctx->this_layer_metadata_json)) {
        if (NULL == (header = cli_jsonobj(ctx->this_layer_metadata_json, "ImageFuzzyHash"))) {
            cli_errmsg("Failed to allocate ImageFuzzyHash JSON object\n");
            status = CL_EMEM;
            goto done;
        }
    }

    if (!fuzzy_hash_calculate_image(offset, ctx->fmap->real_len, hash.hash, 8, &fuzzy_hash_calc_error)) {
        cli_dbgmsg("Failed to calculate image fuzzy hash for %s: %s\n",
                   cli_ftname(type),
                   ffierror_fmt(fuzzy_hash_calc_error));

        if (SCAN_COLLECT_METADATA && (NULL != header)) {
            (void)cli_jsonstr(header, "Error", ffierror_fmt(fuzzy_hash_calc_error));
        }

        goto done;
    }

    if (SCAN_COLLECT_METADATA && (NULL != header)) {
        char hashstr[17];
        snprintf(hashstr, 17, "%02x%02x%02x%02x%02x%02x%02x%02x",
                 hash.hash[0], hash.hash[1], hash.hash[2], hash.hash[3],
                 hash.hash[4], hash.hash[5], hash.hash[6], hash.hash[7]);
        (void)cli_jsonstr(header, "Hash", hashstr);
    }

    ctx->recursion_stack[ctx->recursion_level].image_fuzzy_hash            = hash;
    ctx->recursion_stack[ctx->recursion_level].calculated_image_fuzzy_hash = true;

    status = CL_SUCCESS;

done:
    if (NULL != fuzzy_hash_calc_error) {
        ffierror_free(fuzzy_hash_calc_error);
    }
    return status;
}

/**
 * @brief A unified list of reasons why a scan result inside the magic_scan function
 *        should goto done instead of continuing to parse/scan this layer.
 *
 * These are not reasons why the scan should abort entirely. For that, just check ctx->abort_scan.
 *
 * @param ctx        The scan context.
 * @param result_in  The result to compare.
 * @param result_out The result that magic_scan should return.
 * @return true      We found a reason to goto done.
 * @return false     The scan must go on.
 */
static inline bool result_should_goto_done(cli_ctx *ctx, cl_error_t result_in, cl_error_t *result_out)
{
    bool halt_scan = false;

    if (NULL == ctx || NULL == result_out) {
        cli_dbgmsg("Invalid arguments for file scan result check.\n");
        halt_scan = true;
        goto done;
    }

    if (NULL != ctx && ctx->abort_scan) {
        // ensure abort_scan is respected
        halt_scan = true;
    }

    switch (result_in) {
        /*
         * Reasons to halt the scan and report the error up to the caller/user.
         */

        // A virus result means we should halt the scan.
        // We do not return CL_VIRUS in allmatch-mode until the very end.
        case CL_VIRUS:

        // Each of these error codes considered terminal and will halt the scan.
        case CL_EUNLINK:
        case CL_ESTAT:
        case CL_ESEEK:
        case CL_EWRITE:
        case CL_EDUP:
        case CL_ETMPFILE:
        case CL_ETMPDIR:
        case CL_EMEM:
            cli_dbgmsg("Descriptor[%d]: halting after file scan because: %s\n", fmap_fd(ctx->fmap), cl_strerror(result_in));
            halt_scan   = true;
            *result_out = result_in;
            break;

        /*
         * Reasons to halt the scan but report a successful scan.
         */

        // Exceeding the time limit should definitely halt the scan.
        // But unless the user enabled alert-exceeds-max, we don't want to complain about it.
        case CL_ETIMEOUT:

        // If the file was determined to be trusted, then we can stop scanning this layer. (Ex: EXE with a valid Authenticode sig.)
        // Convert CL_VERIFIED to CL_SUCCESS because we don't want to propagate the CL_VERIFIED return code up to the caller.
        // If we didn't, a trusted file could cause a larger archive containing non-trustworthy files to be trusted.
        case CL_VERIFIED:
            cli_dbgmsg("Descriptor[%d]: halting after file scan because: %s\n", fmap_fd(ctx->fmap), cl_strerror(result_in));
            halt_scan   = true;
            *result_out = CL_SUCCESS;
            break;

        /*
         * All other results must not halt the scan.
         */

        // Nothing to do.
        case CL_SUCCESS:

        // Unless ctx->abort_scan was set, all these "MAX" conditions should finish scanning as much as is allowed.
        // That is, the can may still be blocked from recursing into the next layer, or scanning new files or large files.
        case CL_EMAXREC:
        case CL_EMAXSIZE:
        case CL_EMAXFILES:

        // The following are explicitly listed here so you think twice before putting them in the scan-halt list, above.
        // Malformed/truncated files could report as any of these three, and that's fine.
        // See commit 087e7fc3fa923e5d6a6fd2efe8df852a36256b5b for additional details.
        case CL_EFORMAT:
        case CL_EPARSE:
        case CL_EREAD:
        case CL_EUNPACK:

        default:
            cli_dbgmsg("Descriptor[%d]: Continuing after file scan resulted with: %s\n",
                       fmap_fd(ctx->fmap), cl_strerror(result_in));
            *result_out = CL_SUCCESS;
    }

done:
    return halt_scan;
}

cl_error_t cli_magic_scan(cli_ctx *ctx, cli_file_t type)
{
    cl_error_t status = CL_SUCCESS;
    cl_error_t ret;

    cl_error_t cache_check_result      = CL_VIRUS;
    cl_verdict_t verdict_at_this_level = CL_VERDICT_NOTHING_FOUND;

    bool cache_enabled              = true;
    cli_file_t dettype              = CL_TYPE_ANY;
    uint8_t typercg                 = 1;
    bitset_t *old_hook_lsig_matches = NULL;
    const char *filetype;

    if (!ctx->engine) {
        cli_errmsg("CRITICAL: engine == NULL\n");
        status = CL_ENULLARG;
        goto early_ret;
    }

    if (!(ctx->engine->dboptions & CL_DB_COMPILED)) {
        cli_errmsg("CRITICAL: engine not compiled\n");
        status = CL_EMALFDB;
        goto early_ret;
    }

    if (ctx->fmap->len <= 5) {
        status = CL_SUCCESS;
        cli_dbgmsg("cli_magic_scan: File is too small (%zu bytes), ignoring.\n", ctx->fmap->len);
        goto early_ret;
    }

    if (cli_updatelimits(ctx, ctx->fmap->len) != CL_SUCCESS) {
        emax_reached(ctx);
        status = CL_SUCCESS;
        cli_dbgmsg("cli_magic_scan: returning %d %s (no post, no cache)\n", status, __AT__);
        goto early_ret;
    }

    if (type == CL_TYPE_PART_ANY) {
        typercg = 0;
    }

    /*
     * Determine if caching is enabled.
     * The application may have specifically disabled caching. Also, if the application never loaded any signatures,
     * then the cache will be NULL and caching will also be disabled.
     */
    if ((ctx->engine->engine_options & ENGINE_OPTIONS_DISABLE_CACHE) ||
        (ctx->engine->cache == NULL)) {
        cache_enabled = false;
    }

    /*
     * Perform file typing from the start of the file.
     */
    perf_start(ctx, PERFT_FT);
    if ((type == CL_TYPE_ANY) || type == CL_TYPE_PART_ANY) {
        type = cli_determine_fmap_type(ctx, type);
    }
    perf_stop(ctx, PERFT_FT);
    if (type == CL_TYPE_ERROR) {
        status = CL_EREAD;
        cli_dbgmsg("cli_magic_scan: cli_determine_fmap_type returned CL_TYPE_ERROR\n");
        cli_dbgmsg("cli_magic_scan: returning %d %s (no post, no cache)\n", status, __AT__);
        goto early_ret;
    }
    filetype = cli_ftname(type);

    /* set current layer to the type we found */
    ret = cli_recursion_stack_change_type(ctx, type, true /* ? */);
    if (CL_SUCCESS != ret) {
        cli_dbgmsg("cli_magic_scan: cli_recursion_stack_change_type returned %d\n", ret);
        // We must go to done here (and not early_ret), because `ret` needs to be tidied up before returning.
        status = ret;
        goto done;
    }

    /*
     * Run the pre_hash callback.
     */
    ret = cli_dispatch_scan_callback(ctx, CL_SCAN_CALLBACK_PRE_HASH);
    if (CL_SUCCESS != ret) {
        status = ret;
        goto done;
    }

    /*
     * Run the deprecated pre_cache callback.
     */
    ret = dispatch_prescan_callback(ctx->engine->cb_pre_cache, ctx, filetype, true /* pre_cache */);
    if (CL_VERIFIED == ret || CL_VIRUS == ret) {
        status = ret;
        goto done;
    }

    /*
     * Run the deprecated file_inspection callback.
     */
    ret = dispatch_file_inspection_callback(ctx->engine->cb_file_inspection, ctx, filetype);
    if (CL_SUCCESS != ret) {
        status = ret;
        goto done;
    }

    /*
     * Record the file hash(es) in the JSON metadata before we do the cache check.
     */
    if (SCAN_COLLECT_METADATA) {
        uint8_t *hash = NULL;
        char hash_string[SHA256_HASH_SIZE * 2 + 1];
        bool need_hash[CLI_HASH_AVAIL_TYPES] = {false};
        cli_hash_type_t hash_type;

        need_hash[CLI_HASH_SHA2_256] = true;
        if (SCAN_COLLECT_METADATA && SCAN_STORE_EXTRA_HASHES) {
            need_hash[CLI_HASH_MD5]  = true;
            need_hash[CLI_HASH_SHA1] = true;
        }

        /* Set fmap to need hash later if required.
         * This is an optimization so we can calculate all needed hashes in one pass. */
        for (hash_type = CLI_HASH_MD5; hash_type < CLI_HASH_AVAIL_TYPES; hash_type++) {
            if (need_hash[hash_type]) {
                ret = fmap_will_need_hash_later(ctx->fmap, hash_type);
                if (CL_SUCCESS != ret) {
                    cli_dbgmsg("cli_magic_scan: Failed to set fmap to need the %s hash later\n", cli_hash_name(hash_type));
                    status = ret;
                    goto done;
                }
            }
        }

        for (hash_type = CLI_HASH_MD5; hash_type < CLI_HASH_AVAIL_TYPES; hash_type++) {
            if (need_hash[hash_type]) {
                size_t i;
                size_t hash_len = cli_hash_len(hash_type);

                /* If we need a hash, we will calculate it now */
                ret = fmap_get_hash(ctx->fmap, &hash, hash_type);
                if (CL_SUCCESS != ret || hash == NULL) {
                    cli_dbgmsg("cli_magic_scan: Failed to get a hash for the current fmap.\n");
                    // It may be that the file was truncated between the time we started the scan and the time we got the hash.
                    // Not a reason to print an error message.
                    status = CL_SUCCESS;
                    goto done;
                }

                /* Convert hash to string */
                for (i = 0; i < hash_len; i++) {
                    sprintf(hash_string + i * 2, "%02x", hash[i]);
                }
                hash_string[hash_len * 2] = 0;

                ret = cli_jsonstr(ctx->this_layer_metadata_json, cli_hash_name(hash_type), hash_string);
                if (ret != CL_SUCCESS) {
                    cli_dbgmsg("cli_magic_scan: Failed to store the %s hash in the metadata JSON.\n", cli_hash_name(hash_type));
                    status = ret;
                    goto done;
                }
            }
        }
    }

    /*
     * Check if we've already scanned this file before.
     */
    if (cache_enabled) {
        perf_start(ctx, PERFT_CACHE);
        cache_check_result = clean_cache_check(ctx);
        perf_stop(ctx, PERFT_CACHE);
    }

    if (cache_enabled && (cache_check_result != CL_VIRUS)) {
        status = CL_SUCCESS;
        cli_dbgmsg("cli_magic_scan: returning %d %s (no post, no cache)\n", status, __AT__);
        // We can go to early_ret here, because we know status is CL_SUCCESS, and we obviously add to the cache.
        // This does mean, however, that we do not run the post-scan callback for layers that are cached.
        goto early_ret;
    }

    /* Save off the hook_lsig_matches */
    old_hook_lsig_matches  = ctx->hook_lsig_matches;
    ctx->hook_lsig_matches = NULL;

    /*
     * Run the pre_scan callback.
     */
    ret = cli_dispatch_scan_callback(ctx, CL_SCAN_CALLBACK_PRE_SCAN);
    if (CL_SUCCESS != ret) {
        status = ret;
        goto done;
    }

    /*
     * Run the deprecated pre_scan callback.
     */
    ret = dispatch_prescan_callback(ctx->engine->cb_pre_scan, ctx, filetype, false /* pre_cache */);
    if (CL_VERIFIED == ret || CL_VIRUS == ret) {
        status = ret;
        goto done;
    }

    // If none of the scan options are enabled, then we can skip parsing and just do a raw pattern match.
    // For this check, we don't care if the CL_SCAN_GENERAL_ALLMATCHES option is enabled, hence the `~`.
    if (!((ctx->options->general & ~CL_SCAN_GENERAL_ALLMATCHES) || (ctx->options->parse) || (ctx->options->heuristic) || (ctx->options->mail) || (ctx->options->dev))) {
        status = cli_scan_fmap(ctx, CL_TYPE_ANY, false, NULL, AC_SCAN_VIR, NULL);
        // It doesn't matter what was returned, always go to the end after this. Raw mode! No parsing files!
        goto done;
    }

    // We already saved the hook_lsig_matches (above)
    // The ctx one is NULL at present.
    ctx->hook_lsig_matches = cli_bitset_init();
    if (NULL == ctx->hook_lsig_matches) {
        status = CL_EMEM;
        goto done;
    }

    if (type != CL_TYPE_IGNORED && ctx->engine->sdb) {
        /*
         * If self protection mechanism enabled, do the scanraw() scan first
         * before extracting with a file type parser.
         */
        cli_dbgmsg("cli_magic_scan: Performing raw scan to pattern match\n");

        ret = scanraw(ctx, type, 0, &dettype);

        // Evaluate the result from the scan to see if it end the scan of this layer early,
        // and to decid if we should propagate an error or not.
        if (result_should_goto_done(ctx, ret, &status)) {
            goto done;
        }
    }

    /*
     * Run the file type parsers that we normally use before the raw scan.
     */
    perf_nested_start(ctx, PERFT_CONTAINER, PERFT_SCAN);
    switch (type) {
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
        case CL_TYPE_RARSFX:
            if (have_rar && SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_RAR))
                ret = cli_scanrar(ctx);
            break;

        case CL_TYPE_EGG:
        case CL_TYPE_EGGSFX:
            if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_EGG))
                ret = cli_scanegg(ctx);
            break;

        case CL_TYPE_ONENOTE:
            if (SCAN_PARSE_ONENOTE && (DCONF_ARCH & DOC_CONF_ONENOTE))
                ret = scan_onenote(ctx);
            break;

        case CL_TYPE_ALZ:
            if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ALZ)) {
                ret = cli_scanalz(ctx);
            }
            break;

        case CL_TYPE_LHA_LZH:
            if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_LHA_LZH))
                ret = scan_lha_lzh(ctx);
            break;

        case CL_TYPE_OOXML_WORD:
        case CL_TYPE_OOXML_PPT:
        case CL_TYPE_OOXML_XL:
        case CL_TYPE_OOXML_HWP:
            if (SCAN_PARSE_XMLDOCS && (DCONF_DOC & DOC_CONF_OOXML)) {
                if (SCAN_COLLECT_METADATA && (ctx->this_layer_metadata_json != NULL)) {
                    ret = cli_process_ooxml(ctx, type);

                    if (ret == CL_EMEM || ret == CL_ENULLARG) {
                        /* critical error */
                        break;
                    } else if (ret != CL_SUCCESS) {
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

            /* Extract the OOXML contents */
            if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ZIP))
                ret = cli_unzip(ctx);
            break;

        case CL_TYPE_ZIP:
            if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ZIP)) {
                if (ctx->recursion_stack[ctx->recursion_level].attributes & LAYER_ATTRIBUTES_EMBEDDED) {
                    /* If this is an embedded ZIP found by scanraw() with file type detection,
                     * then we only extract a single zip entry. */
                    ret = cli_unzip_single(ctx, 0);
                } else {
                    ret = cli_unzip(ctx);
                }
            }
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
                ret = cli_scanarj(ctx);
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

        case CL_TYPE_GRAPHICS: {
            if (SCAN_PARSE_IMAGE) {
                /*
                 * This case is for unhandled graphics types such as BMP, JPEG 2000, etc.
                 *
                 * Note: JPEG 2000 is a very different format from JPEG, JPEG/JFIF, JPEG/Exif, JPEG/SPIFF (1994, 1997)
                 * JPEG 2000 is not handled by cli_parsejpeg.
                 */

                if (SCAN_PARSE_IMAGE_FUZZY_HASH && (DCONF_OTHER & OTHER_CONF_IMAGE_FUZZY_HASH)) {
                    // It's okay if it fails to calculate the fuzzy hash.
                    (void)calculate_fuzzy_image_hash(ctx, type);
                }
            }
            break;
        }

        case CL_TYPE_GIF: {
            if (SCAN_PARSE_IMAGE && (DCONF_OTHER & OTHER_CONF_GIF)) {
                if (SCAN_HEURISTICS && SCAN_HEURISTIC_BROKEN_MEDIA) {
                    /*
                     * Parse GIF files, checking for exploits and other file format issues.
                     */
                    ret = cli_parsegif(ctx);
                    if (CL_SUCCESS != ret) {
                        // do not calculate the fuzzy image hash if parsing failed, or a heuristic alert occurred.
                        break;
                    }
                }

                if (SCAN_PARSE_IMAGE_FUZZY_HASH && (DCONF_OTHER & OTHER_CONF_IMAGE_FUZZY_HASH)) {
                    // It's okay if it fails to calculate the fuzzy hash.
                    (void)calculate_fuzzy_image_hash(ctx, type);
                }
            }
            break;
        }

        case CL_TYPE_PNG: {
            if (SCAN_PARSE_IMAGE && (DCONF_OTHER & OTHER_CONF_PNG)) {
                if (SCAN_HEURISTICS && SCAN_HEURISTIC_BROKEN_MEDIA) {
                    /*
                     * Parse PNG files, checking for exploits and other file format issues.
                     */
                    ret = cli_parsepng(ctx); /* PNG parser detects a couple CVE's as well as Broken.Media */
                    if (CL_SUCCESS != ret) {
                        // do not calculate the fuzzy image hash if parsing failed, or a heuristic alert occurred.
                        break;
                    }
                }

                if (SCAN_PARSE_IMAGE_FUZZY_HASH && (DCONF_OTHER & OTHER_CONF_IMAGE_FUZZY_HASH)) {
                    // It's okay if it fails to calculate the fuzzy hash.
                    (void)calculate_fuzzy_image_hash(ctx, type);
                }
            }
            break;
        }

        case CL_TYPE_JPEG: {
            if (SCAN_PARSE_IMAGE && (DCONF_OTHER & OTHER_CONF_JPEG)) {
                if (SCAN_HEURISTICS && SCAN_HEURISTIC_BROKEN_MEDIA) {
                    /*
                     * Parse JPEG files, checking for exploits and other file format issues.
                     *
                     * Note: JPEG 2000 is a very different format from JPEG, JPEG/JFIF, JPEG/Exif, JPEG/SPIFF (1994, 1997)
                     * JPEG 2000 is not checked by cli_parsejpeg.
                     */
                    ret = cli_parsejpeg(ctx); /* JPG parser detects MS04-028 exploits as well as Broken.Media */
                    if (CL_SUCCESS != ret) {
                        // do not calculate the fuzzy image hash if parsing failed, or a heuristic alert occurred.
                        break;
                    }
                }

                if (SCAN_PARSE_IMAGE_FUZZY_HASH && (DCONF_OTHER & OTHER_CONF_IMAGE_FUZZY_HASH)) {
                    // It's okay if it fails to calculate the fuzzy hash.
                    (void)calculate_fuzzy_image_hash(ctx, type);
                }
            }
            break;
        }

        case CL_TYPE_TIFF: {
            if (SCAN_PARSE_IMAGE && (DCONF_OTHER & OTHER_CONF_TIFF)) {
                if (SCAN_HEURISTICS && SCAN_HEURISTIC_BROKEN_MEDIA) {
                    /*
                     * Parse TIFF files, checking for exploits and other file format issues.
                     */
                    ret = cli_parsetiff(ctx);
                    if (CL_SUCCESS != ret) {
                        // do not calculate the fuzzy image hash if parsing failed, or a heuristic alert occurred.
                        break;
                    }
                }

                if (SCAN_PARSE_IMAGE_FUZZY_HASH && (DCONF_OTHER & OTHER_CONF_IMAGE_FUZZY_HASH)) {
                    // It's okay if it fails to calculate the fuzzy hash.
                    (void)calculate_fuzzy_image_hash(ctx, type);
                }
            }
            break;
        }

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

        case CL_TYPE_ISHIELD_MSI:
            if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ISHIELD))
                ret = cli_scanishield_msi(ctx, 14);
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

    // Evaluate the result from the parsers to see if it end the scan of this layer early,
    // and to decide if we should propagate an error or not.
    if (result_should_goto_done(ctx, ret, &status)) {
        goto done;
    }

    /*
     * Perform the raw scan, which may include file type recognition signatures.
     */

    /* Disable type recognition for the raw scan for zip files larger than maxziptypercg */
    if (type == CL_TYPE_ZIP && SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ZIP)) {
        /* CL_ENGINE_MAX_ZIPTYPERCG */
        uint64_t curr_len = ctx->fmap->len;
        if (curr_len > ctx->engine->maxziptypercg) {
            cli_dbgmsg("cli_magic_scan: Not checking for embedded PEs (zip file > MaxZipTypeRcg)\n");
            typercg = 0;
        }
    }

    /*
     * Perform pattern matching for malware detections AND embedded file type recognition.
     * Embedded file type recognition may re-assign the current file as a new type, or
     * it may detect embedded files. E.g. ZIP entries in a PE file (i.e. self-extracting ZIP).
     */
    if ((type != CL_TYPE_IGNORED) &&
        /* CL_TYPE_HTML: raw HTML files are not scanned, unless safety measure activated via DCONF */
        (type != CL_TYPE_HTML || !(SCAN_PARSE_HTML) || !(DCONF_DOC & DOC_CONF_HTML_SKIPRAW)) &&
        (!ctx->engine->sdb)) {

        cli_dbgmsg("cli_magic_scan: Performing raw scan to pattern match and/or detect embedded files\n");

        ret = scanraw(ctx, type, typercg, &dettype);

        // Evaluate the result from the scan to see if it end the scan of this layer early,
        // and to decid if we should propagate an error or not.
        if (result_should_goto_done(ctx, ret, &status)) {
            goto done;
        }
    }

    /*
     * Now run the rest of the file type parsers.
     */
    switch (type) {
        /* bytecode hooks triggered by a lsig must be a hook
         * called from one of the functions here */
        case CL_TYPE_TEXT_ASCII:
        case CL_TYPE_TEXT_UTF16BE:
        case CL_TYPE_TEXT_UTF16LE:
        case CL_TYPE_TEXT_UTF8:
            perf_nested_start(ctx, PERFT_SCRIPT, PERFT_SCAN);
            if ((dettype != CL_TYPE_HTML) &&
                SCAN_PARSE_HTML && (DCONF_DOC & DOC_CONF_SCRIPT) && (ret != CL_VIRUS)) {
                ret = cli_scanscript(ctx);
            }
            if (((dettype == CL_TYPE_MAIL) || (cli_recursion_stack_get_type(ctx, -1) == CL_TYPE_MAIL)) &&
                SCAN_PARSE_MAIL && (DCONF_MAIL & MAIL_CONF_MBOX) && (ret != CL_VIRUS)) {

                ret = cli_scan_fmap(ctx, CL_TYPE_MAIL, false, NULL, AC_SCAN_VIR, NULL);
            }
            perf_nested_stop(ctx, PERFT_SCRIPT, PERFT_SCAN);
            break;

        /* Due to performance reasons all executables were first scanned
         * in raw mode. Now we will try to unpack them
         */
        case CL_TYPE_MSEXE:
            perf_nested_start(ctx, PERFT_PE, PERFT_SCAN);
            if (SCAN_PARSE_PE && ctx->dconf->pe) {
                // Setting ctx->corrupted_input will prevent the PE parser from reporting "broken executable" for unpacked/reconstructed files that may not be 100% to spec.
                // In here we're just carrying the corrupted_input flag from parent to child, in case the parent's flag was set.
                unsigned int corrupted_input = ctx->corrupted_input;
                ret                          = cli_scanpe(ctx);
                ctx->corrupted_input         = corrupted_input;
            }
            perf_nested_stop(ctx, PERFT_PE, PERFT_SCAN);
            break;

        case CL_TYPE_ELF:
            perf_nested_start(ctx, PERFT_ELF, PERFT_SCAN);
            ret = cli_unpackelf(ctx);
            perf_nested_stop(ctx, PERFT_ELF, PERFT_SCAN);
            break;

        case CL_TYPE_MACHO:
        case CL_TYPE_MACHO_UNIBIN:
            perf_nested_start(ctx, PERFT_MACHO, PERFT_SCAN);
            ret = cli_unpackmacho(ctx);
            perf_nested_stop(ctx, PERFT_MACHO, PERFT_SCAN);
            break;

        case CL_TYPE_AI_MODEL:
        case CL_TYPE_PYTHON_COMPILED:
        case CL_TYPE_BINARY_DATA:
            ret = cli_scan_fmap(ctx, CL_TYPE_OTHER, false, NULL, AC_SCAN_VIR, NULL);
            break;

        case CL_TYPE_PDF: /* FIXMELIMITS: pdf should be an archive! */
            if (SCAN_PARSE_PDF && (DCONF_DOC & DOC_CONF_PDF)) {
                ret = cli_scanpdf(ctx, 0);
            }
            break;

        default:
            break;
    }

    // Evaluate the result from the parsers to see if it end the scan of this layer early,
    // and to decide if we should propagate an error or not.
    if (result_should_goto_done(ctx, ret, &status)) {
        goto done;
    }

done:

    /*
     * Run the post_scan callback.
     */
    ret = cli_dispatch_scan_callback(ctx, CL_SCAN_CALLBACK_POST_SCAN);
    if (CL_SUCCESS != ret) {
        cli_dbgmsg("cli_magic_scan: POST_SCAN callback returned %d\n", ret);
        status = ret;
    }

    // Filter the result from the parsers so we don't propagate non-fatal errors.
    // And to convert CL_VERIFIED -> CL_SUCCESS
    (void)result_should_goto_done(ctx, status, &status);

    /*
     * Run the deprecated post-scan callback (if one exists) and provide the verdict for this layer.
     */
    cli_dbgmsg("cli_magic_scan: returning %d %s\n", status, __AT__);
    if (ctx->engine->cb_post_scan) {
        cl_error_t callback_ret;
        cl_error_t append_ret;
        const char *virusname = NULL;

        // Get the last signature that matched (if any).
        if (0 < evidence_num_alerts(ctx->this_layer_evidence)) {
            virusname = cli_get_last_virus(ctx);
        }

        perf_start(ctx, PERFT_POSTCB);
        callback_ret = ctx->engine->cb_post_scan(fmap_fd(ctx->fmap), verdict_at_this_level, virusname, ctx->cb_ctx);
        perf_stop(ctx, PERFT_POSTCB);

        switch (callback_ret) {
            case CL_BREAK:
                cli_dbgmsg("cli_magic_scan: file allowed by post_scan callback\n");

                // Remove any evidence for this layer and set the verdict to trusted.
                (void)cli_trust_this_layer(ctx, "legacy post-scan application callback");

                // status = CL_SUCCESS; // Do override the status here.
                //  If status == CL_VIRUS, we'll fix when we look at the verdict.
                break;
            case CL_VIRUS:
                cli_dbgmsg("cli_magic_scan: file blocked by post_scan callback\n");
                append_ret = cli_append_virus(ctx, "Detected.By.Callback");
                if (append_ret == CL_VIRUS) {
                    status = CL_VIRUS;
                }
                break;
            case CL_SUCCESS:
                // No action requested by callback. Keep scanning.
                break;
            default:
                // status = CL_SUCCESS; // Do override the status here, just log a warning.
                cli_warnmsg("cli_magic_scan: ignoring bad return code from post_scan callback\n");
        }
    }

    /*
     * Check the verdict for this layer.
     * If the verdict is CL_VERDICT_TRUSTED, remove any evidence for this layer and clear CL_VIRUS status (if set)
     * Otherwise, we'll update the verdict based on the evidence.
     */
    if (CL_VERDICT_TRUSTED == ctx->recursion_stack[ctx->recursion_level].verdict) {
        /* Remove any alerts for this layer. */
        if (NULL != ctx->recursion_stack[ctx->recursion_level].evidence) {
            evidence_free(ctx->recursion_stack[ctx->recursion_level].evidence);
            ctx->recursion_stack[ctx->recursion_level].evidence = NULL;
            ctx->this_layer_evidence                            = NULL;
        }
        if (CL_VIRUS == status) {
            status = CL_SUCCESS; // If we have a CL_VERDICT_TRUSTED, we should not return CL_VIRUS.
        }
    } else {
        /*
         * Update the verdict for this layer based on the scan results.
         * If the verdict is CL_VERDICT_TRUSTED, then we don't change it.
         */
        if (0 < evidence_num_indicators_type(ctx->this_layer_evidence, IndicatorType_Strong)) {
            ctx->recursion_stack[ctx->recursion_level].verdict = CL_VERDICT_STRONG_INDICATOR;
        } else if (0 < evidence_num_indicators_type(ctx->this_layer_evidence, IndicatorType_PotentiallyUnwanted)) {
            ctx->recursion_stack[ctx->recursion_level].verdict = CL_VERDICT_POTENTIALLY_UNWANTED;
        }
    }

    /*
     * If the verdict for this layer is "clean", we can cache it.
     *
     * Note: clean_cache_add() will check the fmap->dont_cache_flag,
     * so this may not actually cache if we exceeded limits earlier.
     * It will also check if caching is disabled.
     */
    if ((CL_VERDICT_TRUSTED == ctx->recursion_stack[ctx->recursion_level].verdict) ||
        (CL_VERDICT_NOTHING_FOUND == ctx->recursion_stack[ctx->recursion_level].verdict)) {
        // Also verify we have no weak indicators before adding to the clean cache.
        // Weak indicators may be used in the future to match a strong indicator.
        if (evidence_num_indicators_type(ctx->this_layer_evidence, IndicatorType_Weak) == 0) {
            perf_start(ctx, PERFT_CACHE);
            clean_cache_add(ctx);
            perf_stop(ctx, PERFT_CACHE);
        }
    }

early_ret:

    if (old_hook_lsig_matches) {
        /* We need to restore the old hook_lsig_matches */
        cli_bitset_free(ctx->hook_lsig_matches); // safe to call, even if NULL
        ctx->hook_lsig_matches = old_hook_lsig_matches;
    }

    return status;
}

cl_error_t cli_magic_scan_desc_type(int desc, const char *filepath, cli_ctx *ctx, cli_file_t type,
                                    const char *name, uint32_t attributes)
{
    STATBUF sb;
    cl_error_t status = CL_SUCCESS;
    fmap_t *new_map   = NULL;

    if (!ctx) {
        return CL_EARG;
    }

    cli_dbgmsg("in cli_magic_scan_desc_type (recursion_level: %u/%u)\n", ctx->recursion_level, ctx->engine->max_recursion_level);

    if (FSTAT(desc, &sb) == -1) {
        cli_errmsg("cli_magic_scan_desc_type: Can't fstat descriptor %d\n", desc);
        status = CL_ESTAT;
        goto done;
    }
    if (sb.st_size <= 5) {
        cli_dbgmsg("cli_magic_scan_desc_type: Small data (%u bytes)\n", (unsigned int)sb.st_size);
        status = CL_SUCCESS;
        goto done;
    }

    perf_start(ctx, PERFT_MAP);
    new_map = fmap_new(desc, 0, sb.st_size, name, filepath);
    perf_stop(ctx, PERFT_MAP);
    if (NULL == new_map) {
        cli_errmsg("cli_magic_scan_desc_type: CRITICAL: fmap_new() failed\n");
        status = CL_EMEM;
        goto done;
    }

    status = cli_recursion_stack_push(ctx, new_map, type, true, attributes); /* Perform scan with child fmap */
    if (CL_SUCCESS != status) {
        cli_dbgmsg("Failed to scan fmap.\n");
        goto done;
    }

    status = cli_magic_scan(ctx, type);

    (void)cli_recursion_stack_pop(ctx); /* Restore the parent fmap */

done:
    if (NULL != new_map) {
        fmap_free(new_map);
    }

    return status;
}

cl_error_t cli_magic_scan_desc(int desc, const char *filepath, cli_ctx *ctx, const char *name, uint32_t attributes)
{
    return cli_magic_scan_desc_type(desc, filepath, ctx, CL_TYPE_ANY, name, attributes);
}

/**
 * @brief   Scan an offset/length into a file map.
 *
 * Magic-scan some portion of an existing fmap.
 *
 * @param map       File map.
 * @param offset    Offset into file map.
 * @param length    Length from offset.
 * @param ctx       Scanning context structure.
 * @param type      CL_TYPE of data to be scanned.
 * @param name      (optional) Original name of the file (to set fmap name metadata)
 * @return int      CL_SUCCESS, or an error code.
 */
static cl_error_t magic_scan_nested_fmap_type(cl_fmap_t *map, size_t offset, size_t length, cli_ctx *ctx,
                                              cli_file_t type, const char *name, uint32_t attributes)
{
    cl_error_t status = CL_SUCCESS;
    fmap_t *new_map   = NULL;

    cli_dbgmsg("magic_scan_nested_fmap_type: [0, +%zu), [%zu, +%zu)\n",
               map->len, offset, length);

    if (offset >= map->len) {
        cli_dbgmsg("magic_scan_nested_fmap_type: Invalid offset: %zu\n", offset);
        goto done;
    }

    if (!length)
        length = map->len - offset;

    if (length > map->len - offset) {
        cli_dbgmsg("magic_scan_nested_fmap_type: Data truncated: %zu -> %zu\n",
                   length, map->len - offset);
        length = map->len - offset;
    }

    if (length <= 5) {
        cli_dbgmsg("magic_scan_nested_fmap_type: Small data (%zu bytes)\n", length);
        goto done;
    }

    new_map = fmap_duplicate(map, offset, length, name);
    if (NULL == new_map) {
        cli_dbgmsg("magic_scan_nested_fmap_type: Failed to duplicate fmap for scan of fmap subsection\n");
        goto done;
    }

    status = cli_recursion_stack_push(ctx, new_map, type, false, attributes); /* Perform scan with child fmap */
    if (CL_SUCCESS != status) {
        cli_dbgmsg("magic_scan_nested_fmap_type: Failed to add map to recursion stack for magic scan.\n");
        goto done;
    }

    status = cli_magic_scan(ctx, type);

    (void)cli_recursion_stack_pop(ctx); /* Restore the parent fmap */

done:
    if (NULL != new_map) {
        free_duplicate_fmap(new_map); /* This fmap is just a duplicate. */
    }

    return status;
}

/* For map scans that may be forced to disk */
cl_error_t cli_magic_scan_nested_fmap_type(cl_fmap_t *map, size_t offset, size_t length, cli_ctx *ctx,
                                           cli_file_t type, const char *name, uint32_t attributes)
{
    cl_error_t ret = CL_SUCCESS;

    cli_dbgmsg("cli_magic_scan_nested_fmap_type: [%zu, +%zu)\n", offset, length);
    if (offset >= map->len) {
        cli_dbgmsg("Invalid offset: %zu\n", offset);
        return CL_SUCCESS;
    }

    if (ctx->engine->engine_options & ENGINE_OPTIONS_FORCE_TO_DISK) {
        /*
         * Force to disk!
         *
         * Write the offset + length section of the fmap to disk, and scan it.
         */
        const uint8_t *mapdata = NULL;
        char *tempfile         = NULL;
        int fd                 = -1;
        size_t nread           = 0;

        /* Then check length */
        if (!length) {
            /* Caller didn't specify len, use rest of the map */
            length = map->len - offset;
        }
        if (length > map->len - offset) {
            cli_dbgmsg("cli_magic_scan_nested_fmap_type: Data truncated: %zu -> %zu\n", length, map->len - offset);
            length = map->len - offset;
        }
        if (length <= 5) {
            cli_dbgmsg("cli_magic_scan_nested_fmap_type: Small data (%u bytes)\n", (unsigned int)length);
            return CL_SUCCESS;
        }
        if (!CLI_ISCONTAINED_0_TO(map->len, offset, length)) {
            cli_dbgmsg("cli_magic_scan_nested_fmap_type: map error occurred [%zu, %zu] not within [0, %zu]\n", offset, length, map->len);
            return CL_SUCCESS;
        }

        /* Length checked, now get map */
        mapdata = fmap_need_off_once_len(map, offset, length, &nread);
        if (!mapdata || (nread != length)) {
            cli_errmsg("cli_magic_scan_nested_fmap_type: could not map sub-file\n");
            return CL_EMAP;
        }

        ret = cli_gentempfd(ctx->this_layer_tmpdir, &tempfile, &fd);
        if (ret != CL_SUCCESS) {
            return ret;
        }

        cli_dbgmsg("cli_magic_scan_nested_fmap_type: writing nested map content to temp file %s\n", tempfile);
        if (cli_writen(fd, mapdata, length) == (size_t)-1) {
            cli_errmsg("cli_magic_scan_nested_fmap_type: cli_writen error writing subdoc temporary file.\n");
            ret = CL_EWRITE;
        }

        /* scan the temp file */
        ret = cli_magic_scan_desc_type(fd, tempfile, ctx, type, name, attributes);

        /* remove the temp file, if needed */
        if (fd >= 0) {
            close(fd);
        }
        if (!ctx->engine->keeptmp) {
            if (cli_unlink(tempfile)) {
                cli_errmsg("cli_magic_scan_nested_fmap_type: error unlinking tempfile %s\n", tempfile);
                ret = CL_EUNLINK;
            }
        }
        free(tempfile);
    } else {
        /*
         * Not forced to disk.
         *
         * Just use nested map by scanning given fmap at offset + length.
         */
        ret = magic_scan_nested_fmap_type(map, offset, length, ctx, type, name, attributes);
    }
    return ret;
}

cl_error_t cli_magic_scan_buff(const void *buffer, size_t length, cli_ctx *ctx, const char *name, uint32_t attributes)
{
    cl_error_t ret;
    fmap_t *map = NULL;

    map = fmap_open_memory(buffer, length, name);
    if (!map) {
        return CL_EMAP;
    }

    ret = cli_magic_scan_nested_fmap_type(map, 0, length, ctx, CL_TYPE_ANY, name, attributes);

    fmap_free(map);

    return ret;
}

/**
 * @brief   The main function to initiate a scan of an fmap.
 *
 * @param map                 File map.
 * @param filepath            (optional, recommended) filepath of the open file descriptor or file map.
 * @param[out] verdict_out    A pointer to a cl_verdict_t that will be set to the scan verdict.
 *                            You should check the verdict even if the function returns an error.
 * @param[out] last_alert_out Will be set to a statically allocated (i.e. needs not be freed) signature name if the scan matches against a signature.
 * @param[out] scanned_out    (Optional) The number of bytes scanned.
 * @param engine              The scanning engine.
 * @param scanoptions         Scanning options.
 * @param[in,out] context     (Optional) An application-defined context struct, opaque to libclamav.
 *                            May be used within your callback functions.
 * @param hash_hint           (Optional) A NULL terminated string of the file hash so that
 *                            libclamav does not need to calculate it.
 * @param[out] hash_out       (Optional) A NULL terminated string of the file hash.
 *                            The caller is responsible for freeing this string.
 * @param hash_alg            The hashing algorithm used for either `hash_hint` or `hash_out`.
 *                            Supported algorithms are "md5", "sha1", "sha2-256".
 *                            Required only if you provide a `hash_hint` or want to receive a `hash_out`.
 * @param file_type_hint      (Optional) A NULL terminated string of the file type hint.
 *                            E.g. "pe", "elf", "zip", etc.
 *                            You may also use ClamAV type names such as "CL_TYPE_PE".
 *                            ClamAV will ignore the hint if it is not familiar with the specified type.
 * @param file_type_out       (Optional) A NULL terminated string of the file type
 *                            of the top layer as determined by ClamAV.
 *                            Will take the form of the standard ClamAV file type format. E.g. "CL_TYPE_PE".
 *                            The caller is responsible for freeing this string.
 * @return cl_error_t         CL_SUCCESS if no error occured.
 *                            Otherwise a CL_E* error code.
 *                            Does NOT return CL_VIRUS for a signature match. Check the `verdict_out` parameter instead.
 */
static cl_error_t scan_common(
    cl_fmap_t *map,
    const char *filepath,
    cl_verdict_t *verdict_out,
    const char **last_alert_out,
    uint64_t *scanned_out,
    const struct cl_engine *engine,
    struct cl_scan_options *scanoptions,
    void *context,
    const char *hash_hint,
    char **hash_out,
    const char *hash_alg,
    const char *file_type_hint,
    char **file_type_out)
{
    cl_error_t status = CL_SUCCESS;
    cl_error_t ret;

    cli_ctx ctx = {0};

    bool logg_initialized = false;

    char *target_basename = NULL;
    char *new_temp_prefix = NULL;
    size_t new_temp_prefix_len;
    char *new_temp_path = NULL;

    time_t current_time;
    struct tm tm_struct;

    size_t num_potentially_unwanted_indicators = 0;

    // The default type is SHA2-256.
    cli_hash_type_t requested_hash_type = CLI_HASH_SHA2_256;
    // The type of the file being scanned.
    cli_file_t file_type = CL_TYPE_ANY;

    if (NULL == map || NULL == scanoptions || NULL == verdict_out || NULL == last_alert_out || NULL == engine) {
        return CL_ENULLARG;
    }

    /* Initialize output variables */
    *verdict_out    = CL_VERDICT_NOTHING_FOUND;
    *last_alert_out = NULL;

    // If the caller provided a file type hint, we make a best effort to use it.
    if (file_type_hint) {
        file_type = cli_ftcode_human_friendly(file_type_hint);
        if (CL_TYPE_ERROR == file_type) {
            cli_dbgmsg("scan_common: Unsupported file type hint: %s. Will treat it as unknown (CL_TYPE_ANY)\n", file_type_hint);
            file_type = CL_TYPE_ANY;
        }
    }

    if (NULL != hash_out) {
        *hash_out = NULL;
    }

    if (NULL != hash_alg) {
        // Set the fmap hash for the given algorithm.
        if (3 == strlen(hash_alg) && (0 == strncmp(hash_alg, "md5", 3) || (0 == strncmp(hash_alg, "MD5", 3)))) {
            requested_hash_type = CLI_HASH_MD5;
        } else if (4 == strlen(hash_alg) && (0 == strncmp(hash_alg, "sha1", 4) || (0 == strncmp(hash_alg, "SHA1", 4)))) {
            requested_hash_type = CLI_HASH_SHA1;
        } else if ((8 == strlen(hash_alg) && (0 == strncmp(hash_alg, "sha2-256", 8) || (0 == strncmp(hash_alg, "SHA2-256", 8)))) ||
                   (6 == strlen(hash_alg) && (0 == strncmp(hash_alg, "sha256", 6) || (0 == strncmp(hash_alg, "SHA256", 6))))) {
            requested_hash_type = CLI_HASH_SHA2_256;
        } else {
            cli_errmsg("scan_common: Unsupported hash algorithm: %s\n", hash_alg);
            status = CL_EARG;
            goto done;
        }
    }

    // If hash_hint is provided, we need to check if the hash_alg is valid.
    if (NULL != hash_hint) {
        uint8_t hash[CLI_HASHLEN_MAX] = {0};
        size_t hash_string_len        = strlen(hash_hint);

        if (hash_string_len != cli_hash_len(requested_hash_type) * 2) {
            cli_errmsg("scan_common: hash_hint provided, but its length (%zu) does not match the expected length for %s (%zu).\n",
                       hash_string_len, hash_alg, cli_hash_len(requested_hash_type) * 2);
            status = CL_EARG;
            goto done;
        }

        // Convert the hash_hint string to a binary hash.
        ret = cli_hexstr_to_bytes(hash_hint, hash_string_len, hash);
        if (ret != CL_SUCCESS) {
            cli_errmsg("scan_common: hash_hint provided, but it is not a valid hex string.\n");
            status = CL_EARG;
            goto done;
        }
        // Set the fmap hash for the given algorithm.
        if (CL_SUCCESS != fmap_set_hash(map, hash, requested_hash_type)) {
            cli_errmsg("scan_common: Failed to set fmap hash for %s.\n", hash_alg);
            status = CL_EARG;
            goto done;
        }

        cli_dbgmsg("scan_common: recorded %s hash hint: %s\n", cli_hash_name(requested_hash_type), hash_hint);
    }

    ctx.engine  = engine;
    ctx.scanned = scanned_out;
    CLI_MALLOC_OR_GOTO_DONE(ctx.options, sizeof(struct cl_scan_options), status = CL_EMEM);

    memcpy(ctx.options, scanoptions, sizeof(struct cl_scan_options));

    ctx.dconf  = (struct cli_dconf *)engine->dconf;
    ctx.cb_ctx = context;

    if (!(ctx.hook_lsig_matches = cli_bitset_init())) {
        status = CL_EMEM;
        goto done;
    }

    ctx.recursion_stack_size = ctx.engine->max_recursion_level;
    ctx.recursion_stack      = calloc(sizeof(cli_scan_layer_t), ctx.recursion_stack_size);
    if (!ctx.recursion_stack) {
        status = CL_EMEM;
        goto done;
    }

    // ctx was memset, so recursion_level starts at 0.
    ctx.recursion_stack[ctx.recursion_level].fmap = map;
    ctx.recursion_stack[ctx.recursion_level].size = map->len;
    ctx.recursion_stack[ctx.recursion_level].type = CL_TYPE_ANY;
    ctx.fmap                                      = ctx.recursion_stack[ctx.recursion_level].fmap;

    perf_init(&ctx);

    if (ctx.engine->maxscantime != 0) {
        if (gettimeofday(&ctx.time_limit, NULL) == 0) {
            uint32_t secs  = ctx.engine->maxscantime / 1000;
            uint32_t usecs = (ctx.engine->maxscantime % 1000) * 1000;
            ctx.time_limit.tv_sec += secs;
            ctx.time_limit.tv_usec += usecs;
            if (ctx.time_limit.tv_usec >= 1000000) {
                ctx.time_limit.tv_usec -= 1000000;
                ctx.time_limit.tv_sec++;
            }
        } else {
            char buf[64];
            cli_dbgmsg("scan_common: gettimeofday error: %s\n", cli_strerror(errno, buf, 64));
        }
    }

    if (filepath != NULL) {
        ctx.target_filepath = strdup(filepath);
    }

    /*
     * Create a tmp sub-directory for the temp files generated by this scan.
     *
     * If keeptmp (LeaveTemporaryFiles / --leave-temps) is enabled, we'll include the
     *   basename in the tmp directory.
     * If keeptmp is not enabled, we'll just call it "scantemp".
     */
    current_time = time(NULL);

#ifdef _WIN32
    if (0 != localtime_s(&tm_struct, &current_time)) {
#else
    if (!localtime_r(&current_time, &tm_struct)) {
#endif
        cli_errmsg("scan_common: Failed to get local time.\n");
        status = CL_ESTAT;
        goto done;
    }

    if ((ctx.engine->engine_options & ENGINE_OPTIONS_TMPDIR_RECURSION)) {
        if ((ctx.engine->keeptmp) &&
            (NULL != ctx.target_filepath) &&
            (CL_SUCCESS == cli_basename(ctx.target_filepath, strlen(ctx.target_filepath), &target_basename, true /* posix_support_backslash_pathsep */))) {
            /* Include the basename in the temp directory */
            new_temp_prefix_len = strlen("YYYYMMDD_HHMMSS-") + strlen(target_basename);
            new_temp_prefix     = cli_max_calloc(1, new_temp_prefix_len + 1);
            if (!new_temp_prefix) {
                cli_errmsg("scan_common: Failed to allocate memory for temp directory name.\n");
                status = CL_EMEM;
                goto done;
            }
            strftime(new_temp_prefix, new_temp_prefix_len + 1, "%Y%m%d_%H%M%S-", &tm_struct);
            strcpy(new_temp_prefix + strlen("YYYYMMDD_HHMMSS-"), target_basename);
        } else {
            /* Just use date */
            new_temp_prefix_len = strlen("YYYYMMDD_HHMMSS-scantemp");
            new_temp_prefix     = cli_max_calloc(1, new_temp_prefix_len + 1);
            if (!new_temp_prefix) {
                cli_errmsg("scan_common: Failed to allocate memory for temp directory name.\n");
                status = CL_EMEM;
                goto done;
            }
            strftime(new_temp_prefix, new_temp_prefix_len + 1, "%Y%m%d_%H%M%S-scantemp", &tm_struct);
        }

        /* Place the new temp sub-directory within the configured temp directory */
        new_temp_path = cli_gentemp_with_prefix(ctx.engine->tmpdir, new_temp_prefix);
        free(new_temp_prefix);
        if (NULL == new_temp_path) {
            cli_errmsg("scan_common: Failed to generate temp directory name.\n");
            status = CL_EMEM;
            goto done;
        }

        ctx.recursion_stack[ctx.recursion_level].tmpdir = new_temp_path;
        ctx.this_layer_tmpdir                           = new_temp_path;

        if (mkdir(ctx.this_layer_tmpdir, 0700)) {
            cli_errmsg("Can't create temporary directory for scan: %s.\n", ctx.this_layer_tmpdir);
            status = CL_EACCES;
            goto done;
        }
    } else {
        /*
         * Use the configured temp directory.
         * Making a unique subdirectory per scan is slower, and particularly slow on Windows.
         */
        ctx.recursion_stack[ctx.recursion_level].tmpdir = ctx.engine->tmpdir;
        ctx.this_layer_tmpdir                           = ctx.engine->tmpdir;
    }

    cli_logg_setup(&ctx);
    logg_initialized = true;

    // Assign a unique object_id to the new container.
    ctx.recursion_stack[ctx.recursion_level].object_id = ctx.object_count;
    ctx.object_count++;

    if (ctx.options->general & CL_SCAN_GENERAL_COLLECT_METADATA) {
        ctx.metadata_json = json_object_new_object();
        if (NULL == ctx.metadata_json) {
            cli_errmsg("scan_common: no memory for json properties object\n");
            status = CL_EMEM;
            goto done;
        }
        /* Set the convenience pointer to the current properties object */
        ctx.recursion_stack[ctx.recursion_level].metadata_json = ctx.metadata_json;
        ctx.this_layer_metadata_json                           = ctx.metadata_json;

        status = cli_jsonstr(ctx.metadata_json, "Magic", "CLAMJSONv0");
        if (status != CL_SUCCESS) {
            cli_errmsg("scan_common: error setting Magic property in metadata.json\n");
            goto done;
        }
        if (ctx.fmap->name) {
            status = cli_jsonstr(ctx.metadata_json, "FileName", ctx.fmap->name);
            if (status != CL_SUCCESS) {
                cli_errmsg("scan_common: error setting FileName property in metadata.json\n");
                goto done;
            }
        }
        if (ctx.fmap->path) {
            status = cli_jsonstr(ctx.metadata_json, "FilePath", ctx.fmap->path);
            if (status != CL_SUCCESS) {
                cli_errmsg("scan_common: error setting FilePath property in metadata.json\n");
                goto done;
            }
        }
        status = cli_jsonuint64(ctx.metadata_json, "FileSize", (uint64_t)ctx.fmap->len);
        if (status != CL_SUCCESS) {
            cli_errmsg("scan_common: error setting FileSize property in metadata.json\n");
            goto done;
        }
        status = cli_jsonuint64(ctx.metadata_json, "ObjectID", (uint64_t)ctx.recursion_stack[ctx.recursion_level].object_id);
        if (status != CL_SUCCESS) {
            cli_errmsg("scan_common: error setting ObjectID property in metadata.json\n");
            goto done;
        }
    }

    /*
     * DO THE SCAN!
     */
    status = cli_magic_scan(&ctx, file_type);

    if (ctx.options->general & CL_SCAN_GENERAL_COLLECT_METADATA && (ctx.metadata_json != NULL)) {
        json_object *jobj;
        const char *jstring;

        /* set value of unique root object tag */
        if (json_object_object_get_ex(ctx.metadata_json, "FileType", &jobj)) {
            enum json_type type;
            const char *jstr;

            type = json_object_get_type(jobj);
            if (type == json_type_string) {
                jstr = json_object_get_string(jobj);
                cli_jsonstr(ctx.metadata_json, "RootFileType", jstr);
            }
        }

        /* serialize json properties to string */
#ifdef JSON_C_TO_STRING_NOSLASHESCAPE
        jstring = json_object_to_json_string_ext(ctx.metadata_json, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE);
#else
        jstring = json_object_to_json_string_ext(ctx.metadata_json, JSON_C_TO_STRING_PRETTY);
#endif
        if (NULL == jstring) {
            cli_errmsg("scan_common: no memory for json serialization.\n");
            status = CL_EMEM;
            goto done;
        }

        cli_dbgmsg("%s\n", jstring);

        if (status != CL_VIRUS) {
            /*
             * Run bytecode preclass hook.
             */
            struct cli_matcher *iroot = ctx.engine->root[13];

            struct cli_bc_ctx *bc_ctx = cli_bytecode_context_alloc();
            if (!bc_ctx) {
                cli_errmsg("scan_common: can't allocate memory for bc_ctx\n");
                status = CL_EMEM;
            } else {
                cli_bytecode_context_setctx(bc_ctx, &ctx);
                status = cli_bytecode_runhook(&ctx, ctx.engine, bc_ctx, BC_PRECLASS, map);
                cli_bytecode_context_destroy(bc_ctx);
            }

            /* backwards compatibility: scan the json string unless a virus was detected */
            if (status != CL_VIRUS && (iroot->ac_lsigs || iroot->ac_patterns || iroot->pcre_metas)) {
                cli_dbgmsg("scan_common: running deprecated preclass bytecodes for target type 13\n");
                ctx.options->general &= ~CL_SCAN_GENERAL_COLLECT_METADATA;
                status = cli_magic_scan_buff(jstring, strlen(jstring), &ctx, NULL, LAYER_ATTRIBUTES_NONE);
            }
        }

        /*
         * Invoke file props callback.
         */
        if (ctx.engine->cb_file_props != NULL) {
            ret = ctx.engine->cb_file_props(jstring, status, ctx.cb_ctx);
            if (ret != CL_SUCCESS) {
                status = ret;
            }
        }

        /*
         * Write the file properties metadata JSON to metadata.json if keeptmp is enabled and temp-dir recursion is enabled.
         * At present, the `metadata.json` filename is hardcoded, and cannot be written to a directory containing temp files from other scans.
         */
        if ((ctx.engine->keeptmp) &&
            (ctx.engine->engine_options & ENGINE_OPTIONS_TMPDIR_RECURSION)) {

            int fd        = -1;
            char *tmpname = NULL;

            if ((ret = cli_newfilepathfd(ctx.this_layer_tmpdir, "metadata.json", &tmpname, &fd)) != CL_SUCCESS) {
                cli_dbgmsg("scan_common: Can't create json properties file, ret = %i.\n", ret);
            } else {
                if ((size_t)-1 == cli_writen(fd, jstring, strlen(jstring))) {
                    cli_dbgmsg("scan_common: cli_writen error writing json properties file.\n");
                } else {
                    cli_dbgmsg("json written to: %s\n", tmpname);
                }
            }
            if (fd != -1) {
                close(fd);
            }
            if (NULL != tmpname) {
                free(tmpname);
            }
        }
    }

    // If any alerts occurred, set the output pointer to the "latest" alert signature name.
    if (0 < evidence_num_alerts(ctx.this_layer_evidence)) {
        *last_alert_out = cli_get_last_virus_str(&ctx);
    }

    *verdict_out = ctx.recursion_stack[ctx.recursion_level].verdict;

    /*
     * Report PUA alerts here.
     */
    num_potentially_unwanted_indicators = evidence_num_indicators_type(
        ctx.this_layer_evidence,
        IndicatorType_PotentiallyUnwanted);
    if (0 != num_potentially_unwanted_indicators) {
        // We have "potentially unwanted" indicators that would not have been reported yet.
        // We may wish to report them now, ... depending ....

        if (ctx.options->general & CL_SCAN_GENERAL_ALLMATCHES) {
            // We're in allmatch mode, so report all "potentially unwanted" matches now.

            size_t i;

            for (i = 0; i < num_potentially_unwanted_indicators; i++) {
                const char *pua_alert = evidence_get_indicator(
                    ctx.this_layer_evidence,
                    IndicatorType_PotentiallyUnwanted,
                    i,
                    NULL, // Don't need to get the depth here.
                    NULL  // Don't need to get the object ID here.
                );

                if (NULL != pua_alert) {
                    // We don't know exactly which layer the alert happened at.
                    // There's a decent chance it wasn't at this layer, and in that case we wouldn't
                    // even have access to that file anymore (it's gone!). So we'll pass back -1 for the
                    // file descriptor rather than using `cli_virus_found_cb() which would pass back
                    // The top level file descriptor.
                    if (ctx.engine->cb_virus_found) {
                        ctx.engine->cb_virus_found(
                            -1,
                            pua_alert,
                            ctx.cb_ctx);
                    }
                }
            }

        } else {
            // Not allmatch mode. Only want to report one thing...
            if (0 == evidence_num_indicators_type(ctx.this_layer_evidence, IndicatorType_Strong)) {
                // And it looks like we haven't reported anything else, so report the last "potentially unwanted" one.
                // cli_get_last_virus() will do that, grabbing the last alerting indicator of any type.
                cl_error_t callback_ret = CL_SUCCESS;

                while ((CL_SUCCESS == callback_ret) &&
                       (0 < evidence_num_indicators_type(ctx.this_layer_evidence, IndicatorType_PotentiallyUnwanted))) {
                    callback_ret = cli_virus_found_cb(
                        &ctx,
                        cli_get_last_virus(&ctx),
                        IndicatorType_PotentiallyUnwanted);
                    // If the callback returned CL_SUCCESS then it will have also removed the indicator from evidence
                    // And we must loop around and report the next one.
                }
            }
        }
    }

    /*
     * If the caller requested a hash, we need to get it from the fmap.
     */
    if (NULL != hash_out) {
        // Allocate a buffer for the hash
        size_t hash_len   = cli_hash_len(requested_hash_type);
        char *hash_string = malloc(hash_len * 2 + 1); // +1 for the null terminator
        if (NULL == hash_string) {
            cli_errmsg("scan_common: no memory for hash string buffer\n");
            status = CL_EMEM;
        } else {
            // Get the hash from the fmap.
            uint8_t *hash = NULL;
            ret           = fmap_get_hash(map, &hash, requested_hash_type);
            if (CL_SUCCESS != ret || hash == NULL) {
                cli_errmsg("scan_common: fmap_get_hash failed: %d\n", ret);
                status = ret;
            } else {
                // Convert hash to string.
                size_t i;
                for (i = 0; i < hash_len; i++) {
                    sprintf(hash_string + i * 2, "%02x", hash[i]);
                }
                hash_string[hash_len * 2] = 0;

                *hash_out = hash_string;
            }
        }
    }

    /*
     * If the caller requested a file type, we need to get it from the fmap.
     */
    if (NULL != file_type_out) {
        const char *ftname = cli_ftname(ctx.recursion_stack[ctx.recursion_level].type);
        if ((NULL == ftname) ||
            (strcmp(ftname, "CL_TYPE_ANY") == 0)) {
            cli_dbgmsg("scan_common: unknown file type.\n");
            // Default to CL_TYPE_BINARY_DATA if we never determined the type.
            *file_type_out = cli_safer_strdup("CL_TYPE_BINARY_DATA");
        } else {
            // Set the output pointer to the file type name.
            *file_type_out = cli_safer_strdup(ftname);
        }
    }

done:

    if (logg_initialized) {
        cli_logg_unsetup();
    }

    if (NULL != ctx.metadata_json) {
        cli_json_delobj(ctx.metadata_json);
    }

    if ((NULL != ctx.engine) &&
        (ctx.engine->engine_options & ENGINE_OPTIONS_TMPDIR_RECURSION) &&
        (NULL != ctx.this_layer_tmpdir)) {

        if (!ctx.engine->keeptmp) {
            (void)cli_rmdirs(ctx.this_layer_tmpdir);
        }
        free(ctx.this_layer_tmpdir);
    } else {
        // If we didn't create a temp directory, we don't need to free it,
        // and have to trust that all temp files were cleaned up by their respective modules.
    }

    if (NULL != target_basename) {
        free(target_basename);
    }

    if (NULL != ctx.target_filepath) {
        free(ctx.target_filepath);
    }

    if (NULL != ctx.perf) {
        perf_done(&ctx);
    }

    if (NULL != ctx.hook_lsig_matches) {
        cli_bitset_free(ctx.hook_lsig_matches);
    }

    if (NULL != ctx.recursion_stack) {
        if (NULL != ctx.recursion_stack[ctx.recursion_level].evidence) {
            evidence_free(ctx.recursion_stack[ctx.recursion_level].evidence);
        }

        free(ctx.recursion_stack);
    }

    if (NULL != ctx.options) {
        free(ctx.options);
    }

    return status;
}

cl_error_t cl_scandesc(
    int desc,
    const char *filename,
    const char **virname,
    unsigned long int *scanned,
    const struct cl_engine *engine,
    struct cl_scan_options *scanoptions)
{
    cl_error_t status;
    uint64_t scanned_out;
    cl_verdict_t verdict_out = CL_VERDICT_NOTHING_FOUND;

    status = cl_scandesc_ex(
        desc,
        filename,
        &verdict_out,
        virname,
        &scanned_out,
        engine,
        scanoptions,
        NULL,  // void *context,
        NULL,  // const char *hash_hint,
        NULL,  // char **hash_out,
        NULL,  // const char *hash_alg,
        NULL,  // const char *file_type_hint,
        NULL); // char **file_type_out);

    if (NULL != scanned) {
        if ((SIZEOF_LONG == 4) &&
            (scanned_out / CL_COUNT_PRECISION > UINT32_MAX)) {
            cli_warnmsg("cl_scanfile_callback: scanned_out exceeds UINT32_MAX, setting to UINT32_MAX\n");
            *scanned = UINT32_MAX;
        } else {
            *scanned = (unsigned long int)(scanned_out / CL_COUNT_PRECISION);
        }
    }

    if (verdict_out == CL_VERDICT_STRONG_INDICATOR || verdict_out == CL_VERDICT_POTENTIALLY_UNWANTED) {
        // Reporting "CL_VIRUS" is more important than reporting an error,
        // because... unfortunately we can only do one with this API.
        status = CL_VIRUS;
    }

    return status;
}

cl_error_t cl_scandesc_callback(
    int desc,
    const char *filename,
    const char **virname,
    unsigned long int *scanned,
    const struct cl_engine *engine,
    struct cl_scan_options *scanoptions,
    void *context)
{
    cl_error_t status;
    uint64_t scanned_bytes;
    cl_verdict_t verdict_out = CL_VERDICT_NOTHING_FOUND;

    status = cl_scandesc_ex(
        desc,
        filename,
        &verdict_out,
        virname,
        &scanned_bytes,
        engine,
        scanoptions,
        context,
        NULL,  // const char *hash_hint,
        NULL,  // char **hash_out,
        NULL,  // const char *hash_alg,
        NULL,  // const char *file_type_hint,
        NULL); // char **file_type_out);

    if (NULL != scanned) {
        if ((SIZEOF_LONG == 4) &&
            (scanned_bytes / CL_COUNT_PRECISION > UINT32_MAX)) {
            cli_warnmsg("cl_scanfile_callback: scanned_bytes exceeds UINT32_MAX, setting to UINT32_MAX\n");
            *scanned = UINT32_MAX;
        } else {
            *scanned = (unsigned long int)(scanned_bytes / CL_COUNT_PRECISION);
        }
    }

    if (verdict_out == CL_VERDICT_STRONG_INDICATOR || verdict_out == CL_VERDICT_POTENTIALLY_UNWANTED) {
        // Reporting "CL_VIRUS" is more important than reporting an error,
        // because... unfortunately we can only do one with this API.
        status = CL_VIRUS;
    }

    return status;
}

cl_error_t cl_scandesc_ex(
    int desc,
    const char *filename,
    cl_verdict_t *verdict_out,
    const char **last_alert_out,
    uint64_t *scanned_out,
    const struct cl_engine *engine,
    struct cl_scan_options *scanoptions,
    void *context,
    const char *hash_hint,
    char **hash_out,
    const char *hash_alg,
    const char *file_type_hint,
    char **file_type_out)
{
    cl_error_t status = CL_SUCCESS;
    cl_fmap_t *map    = NULL;
    STATBUF sb;
    char *filename_base = NULL;

    if (FSTAT(desc, &sb) == -1) {
        cli_errmsg("cl_scandesc_callback: Can't fstat descriptor %d\n", desc);
        status = CL_ESTAT;
        goto done;
    }
    if (sb.st_size <= 5) {
        cli_dbgmsg("cl_scandesc_callback: File too small (" STDu64 " bytes), ignoring\n", (uint64_t)sb.st_size);
        status = CL_SUCCESS;
        goto done;
    }
    if ((engine->maxfilesize > 0) && ((uint64_t)sb.st_size > engine->maxfilesize)) {
        cli_dbgmsg("cl_scandesc_callback: File too large (" STDu64 " bytes), ignoring\n", (uint64_t)sb.st_size);
        if (scanoptions->heuristic & CL_SCAN_HEURISTIC_EXCEEDS_MAX) {
            if (engine->cb_virus_found) {
                engine->cb_virus_found(desc, "Heuristics.Limits.Exceeded.MaxFileSize", context);
                if (last_alert_out) {
                    *last_alert_out = "Heuristics.Limits.Exceeded.MaxFileSize";
                }
            }
            status = CL_VIRUS;
        } else {
            status = CL_SUCCESS;
        }
        goto done;
    }

    if (NULL != filename) {
        (void)cli_basename(filename, strlen(filename), &filename_base, true /* posix_support_backslash_pathsep */);
    }

    if (NULL == (map = fmap_new(desc, 0, sb.st_size, filename_base, filename))) {
        cli_errmsg("CRITICAL: fmap_new() failed\n");
        status = CL_EMEM;
        goto done;
    }

    status = scan_common(
        map,
        filename,
        verdict_out,
        last_alert_out,
        scanned_out,
        engine,
        scanoptions,
        context,
        hash_hint,
        hash_out,
        hash_alg,
        file_type_hint,
        file_type_out);

done:
    if (NULL != map) {
        fmap_free(map);
    }
    if (NULL != filename_base) {
        free(filename_base);
    }

    return status;
}

cl_error_t cl_scanmap_callback(
    cl_fmap_t *map,
    const char *filename,
    const char **virname,
    unsigned long int *scanned,
    const struct cl_engine *engine,
    struct cl_scan_options *scanoptions,
    void *context)
{
    cl_error_t status;
    uint64_t scanned_bytes;
    cl_verdict_t verdict_out = CL_VERDICT_NOTHING_FOUND;

    status = cl_scanmap_ex(
        map,
        filename,
        &verdict_out,
        virname,
        &scanned_bytes,
        engine,
        scanoptions,
        context,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);

    if (NULL != scanned) {
        if ((SIZEOF_LONG == 4) &&
            (scanned_bytes / CL_COUNT_PRECISION > UINT32_MAX)) {
            cli_warnmsg("cl_scanfile_callback: scanned_bytes exceeds UINT32_MAX, setting to UINT32_MAX\n");
            *scanned = UINT32_MAX;
        } else {
            *scanned = (unsigned long int)(scanned_bytes / CL_COUNT_PRECISION);
        }
    }

    if (verdict_out == CL_VERDICT_STRONG_INDICATOR || verdict_out == CL_VERDICT_POTENTIALLY_UNWANTED) {
        // Reporting "CL_VIRUS" is more important than reporting an error,
        // because... unfortunately we can only do one with this API.
        status = CL_VIRUS;
    }

    return status;
}

cl_error_t cl_scanmap_ex(
    cl_fmap_t *map,
    const char *filename,
    cl_verdict_t *verdict_out,
    const char **last_alert_out,
    uint64_t *scanned_out,
    const struct cl_engine *engine,
    struct cl_scan_options *scanoptions,
    void *context,
    const char *hash_hint,
    char **hash_out,
    const char *hash_alg,
    const char *file_type_hint,
    char **file_type_out)
{
    if ((engine->maxfilesize > 0) && (map->len > engine->maxfilesize)) {
        cli_dbgmsg("cl_scandesc_callback: File too large (%zu bytes), ignoring\n", map->len);
        if (scanoptions->heuristic & CL_SCAN_HEURISTIC_EXCEEDS_MAX) {
            if (engine->cb_virus_found) {
                engine->cb_virus_found(fmap_fd(map), "Heuristics.Limits.Exceeded.MaxFileSize", context);
                if (last_alert_out) {
                    *last_alert_out = "Heuristics.Limits.Exceeded.MaxFileSize";
                }
            }
            return CL_VIRUS;
        }
        return CL_SUCCESS;
    }

    if (NULL != filename && map->name == NULL) {
        // Use the provided name for the fmap name if one wasn't already set.
        (void)cli_basename(filename, strlen(filename), &map->name, true /* posix_support_backslash_pathsep */);
    }

    return scan_common(
        map,
        filename,
        verdict_out,
        last_alert_out,
        scanned_out,
        engine,
        scanoptions,
        context,
        hash_hint,
        hash_out,
        hash_alg,
        file_type_hint,
        file_type_out);
}

cl_error_t cli_magic_scan_file(const char *filename, cli_ctx *ctx, const char *original_name, uint32_t attributes)
{
    int fd         = -1;
    cl_error_t ret = CL_EOPEN;

    /* internal version of cl_scanfile with arec/mrec preserved */
    fd = safe_open(filename, O_RDONLY | O_BINARY);
    if (fd < 0) {
        goto done;
    }

    ret = cli_magic_scan_desc(fd, filename, ctx, original_name, attributes);

done:
    if (fd >= 0) {
        close(fd);
    }

    return ret;
}

cl_error_t cl_scanfile(
    const char *filename,
    const char **virname,
    unsigned long int *scanned,
    const struct cl_engine *engine,
    struct cl_scan_options *scanoptions)
{
    cl_error_t status;
    uint64_t scanned_bytes;
    cl_verdict_t verdict_out = CL_VERDICT_NOTHING_FOUND;

    status = cl_scanfile_ex(
        filename,
        &verdict_out,
        virname,
        &scanned_bytes,
        engine,
        scanoptions,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);

    if (NULL != scanned) {
        if (SIZEOF_LONG == 4 && scanned_bytes > UINT32_MAX) {
            cli_warnmsg("cl_scanfile_callback: scanned_bytes exceeds UINT32_MAX, setting to UINT32_MAX\n");
            *scanned = UINT32_MAX;
        } else {
            *scanned = (unsigned long int)scanned_bytes;
        }
    }

    if (verdict_out == CL_VERDICT_STRONG_INDICATOR || verdict_out == CL_VERDICT_POTENTIALLY_UNWANTED) {
        // Reporting "CL_VIRUS" is more important than reporting an error,
        // because... unfortunately we can only do one with this API.
        status = CL_VIRUS;
    }

    return status;
}

cl_error_t cl_scanfile_callback(
    const char *filename,
    const char **virname,
    unsigned long int *scanned,
    const struct cl_engine *engine,
    struct cl_scan_options *scanoptions,
    void *context)
{
    cl_error_t status;
    uint64_t scanned_out;
    cl_verdict_t verdict_out = CL_VERDICT_NOTHING_FOUND;

    status = cl_scanfile_ex(
        filename,
        &verdict_out,
        virname,
        &scanned_out,
        engine,
        scanoptions,
        context,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);

    if (NULL != scanned) {
        if (SIZEOF_LONG == 4 && scanned_out > UINT32_MAX) {
            cli_warnmsg("cl_scanfile_callback: scanned_out exceeds UINT32_MAX, setting to UINT32_MAX\n");
            *scanned = UINT32_MAX;
        } else {
            *scanned = (unsigned long int)scanned_out;
        }
    }

    if (verdict_out == CL_VERDICT_STRONG_INDICATOR || verdict_out == CL_VERDICT_POTENTIALLY_UNWANTED) {
        // Reporting "CL_VIRUS" is more important than reporting an error,
        // because... unfortunately we can only do one with this API.
        status = CL_VIRUS;
    }

    return status;
}

cl_error_t cl_scanfile_ex(
    const char *filename,
    cl_verdict_t *verdict_out,
    const char **last_alert_out,
    uint64_t *scanned_out,
    const struct cl_engine *engine,
    struct cl_scan_options *scanoptions,
    void *context,
    const char *hash_hint,
    char **hash_out,
    const char *hash_alg,
    const char *file_type_hint,
    char **file_type_out)
{
    int fd;
    cl_error_t ret;
    const char *fname = cli_to_utf8_maybe_alloc(filename);

    if (!fname)
        return CL_EARG;

    if ((fd = safe_open(fname, O_RDONLY | O_BINARY)) == -1) {
        if (errno == EACCES) {
            return CL_EACCES;
        } else {
            return CL_EOPEN;
        }
    }

    if (fname != filename)
        free((char *)fname);

    ret = cl_scandesc_ex(
        fd,
        filename,
        verdict_out,
        last_alert_out,
        scanned_out,
        engine,
        scanoptions,
        context,
        hash_hint,
        hash_out,
        hash_alg,
        file_type_hint,
        file_type_out);

    close(fd);

    return ret;
}

/*
Local Variables:
   c-basic-offset: 4
End:
*/
