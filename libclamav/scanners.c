/*
 *  Copyright (C) 2013-2023 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#ifdef HAVE_BZLIB_H
#include <bzlib.h>
#endif

#include <fcntl.h>
#include <string.h>

cl_error_t cli_magic_scan_dir(const char *dir, cli_ctx *ctx, uint32_t attributes)
{
    cl_error_t status = CL_CLEAN;
    DIR *dd           = NULL;
    struct dirent *dent;
    STATBUF statbuf;
    char *fname = NULL;

    if ((dd = opendir(dir)) != NULL) {
        while ((dent = readdir(dd))) {
            if (dent->d_ino) {
                if (strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
                    /* build the full name */
                    fname = cli_malloc(strlen(dir) + strlen(dent->d_name) + 2);
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
 * @return cl_error_t  Returns CL_CLEAN if nothing found, CL_VIRUS if something found, CL_EUNPACK if encrypted.
 */
static cl_error_t cli_unrar_scanmetadata(unrar_metadata_t *metadata, cli_ctx *ctx, unsigned int files)
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

static cl_error_t cli_scanrar_file(const char *filepath, int desc, cli_ctx *ctx)
{
    cl_error_t status          = CL_EPARSE;
    cl_unrar_error_t unrar_ret = UNRAR_ERR;

    unsigned int file_count = 0;

    uint32_t nEncryptedFilesFound = 0;
    uint32_t nTooLargeFilesFound  = 0;

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
            if (!(comment_fullpath = cli_gentemp_with_prefix(ctx->sub_tmpdir, "comments"))) {
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
                if (NULL != metadata.filename) {
                    (void)cli_basename(metadata.filename, strlen(metadata.filename), &filename_base);
                }

                if (!(ctx->engine->keeptmp) ||
                    (NULL == filename_base)) {
                    extract_fullpath = cli_gentemp(ctx->sub_tmpdir);
                } else {
                    extract_fullpath = cli_gentemp_with_prefix(ctx->sub_tmpdir, filename_base);
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
#ifdef _WIN32
                    if (0 != _access_s(extract_fullpath, R_OK)) {
#else
                    if (0 != access(extract_fullpath, R_OK)) {
#endif
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
        if (metadata.filename != NULL) {
            free(metadata.filename);
            metadata.filename = NULL;
        }
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

#ifdef _WIN32
    if ((SCAN_UNPRIVILEGED) || (NULL == ctx->sub_filepath) || (0 != _access_s(ctx->sub_filepath, R_OK))) {
#else
    if ((SCAN_UNPRIVILEGED) || (NULL == ctx->sub_filepath) || (0 != access(ctx->sub_filepath, R_OK))) {
#endif
        /* If map is not file-backed have to dump to file for scanrar. */
        status = fmap_dump_to_file(ctx->fmap, ctx->sub_filepath, ctx->sub_tmpdir, &tmpname, &tmpfd, 0, SIZE_MAX);
        if (status != CL_SUCCESS) {
            cli_dbgmsg("cli_magic_scan: failed to generate temporary file.\n");
            goto done;
        }
        filepath = tmpname;
        fd       = tmpfd;
    } else {
        /* Use the original file and file descriptor. */
        filepath = ctx->sub_filepath;
        fd       = fmap_fd(ctx->fmap);
    }

    /* scan file */
    status = cli_scanrar_file(filepath, fd, ctx);

    if ((NULL == tmpname) && (CL_EOPEN == status)) {
        /*
         * Failed to open the file using the original filename.
         * Try writing the file descriptor to a temp file and try again.
         */
        status = fmap_dump_to_file(ctx->fmap, ctx->sub_filepath, ctx->sub_tmpdir, &tmpname, &tmpfd, 0, SIZE_MAX);
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
 * @return cl_error_t  Returns CL_CLEAN if nothing found, CL_VIRUS if something found, CL_EUNPACK if encrypted.
 */
static cl_error_t cli_egg_scanmetadata(cl_egg_metadata *metadata, cli_ctx *ctx, unsigned int files)
{
    cl_error_t status = CL_CLEAN;

    cli_dbgmsg("EGG: %s, encrypted: %u, compressed: %u, normal: %u, ratio: %u\n",
               metadata->filename, metadata->encrypted, (unsigned int)metadata->pack_size,
               (unsigned int)metadata->unpack_size,
               metadata->pack_size ? (unsigned int)(metadata->unpack_size / metadata->pack_size) : 0);

    if (CL_VIRUS == cli_matchmeta(ctx, metadata->filename, metadata->pack_size, metadata->unpack_size, metadata->encrypted, files, 0, NULL)) {
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
    uint32_t nTooLargeFilesFound  = 0;

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

                if (!(comment_fullpath = cli_gentemp_with_prefix(ctx->sub_tmpdir, prefix))) {
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
        status = CL_CLEAN;

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
                nTooLargeFilesFound += 1;

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
                        (void)cli_basename(metadata.filename, strlen(metadata.filename), &filename_base);
                    }

                    if (ctx->engine->keeptmp) {
                        int extracted_fd = -1;
                        if (NULL == filename_base) {
                            extract_fullpath = cli_gentemp(ctx->sub_tmpdir);
                        } else {
                            extract_fullpath = cli_gentemp_with_prefix(ctx->sub_tmpdir, filename_base);
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

    if (status == CL_BREAK) {
        status = CL_CLEAN;
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
    cl_error_t ret = CL_CLEAN;
    int file       = 0;
    arj_metadata_t metadata;
    char *dir = NULL;

    cli_dbgmsg("in cli_scanarj()\n");

    memset(&metadata, 0, sizeof(arj_metadata_t));

    /* generate the temporary directory */
    if (!(dir = cli_gentemp_with_prefix(ctx->sub_tmpdir, "arj-tmp")))
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

        ret = cli_unarj_prepare_file(dir, &metadata);
        if (ret != CL_SUCCESS) {
            cli_dbgmsg("ARJ: cli_unarj_prepare_file Error: %s\n", cl_strerror(ret));
            break;
        }

        file++;

        if (CL_VIRUS == cli_matchmeta(ctx, metadata.filename, metadata.comp_size, metadata.orig_size, metadata.encrypted, file, 0, NULL)) {
            cli_rmdirs(dir);
            free(dir);
            return CL_VIRUS;
        }

        if ((ret = cli_checklimits("ARJ", ctx, metadata.orig_size, metadata.comp_size, 0)) != CL_CLEAN) {
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

    if ((ret = cli_gentempfd(ctx->sub_tmpdir, &tmpname, &fd)) != CL_SUCCESS) {
        cli_dbgmsg("GZip: Can't generate temporary file.\n");
        gzclose(gz);
        close(fd);
        return ret;
    }

    while ((bytes = gzread(gz, buff, FILEBUFF)) > 0) {
        outsize += bytes;
        if (cli_checklimits("GZip", ctx, outsize, 0, 0) != CL_CLEAN)
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
    cl_error_t ret = CL_CLEAN;
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

    if ((ret = cli_gentempfd(ctx->sub_tmpdir, &tmpname, &fd)) != CL_SUCCESS) {
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
            if (cli_checklimits("GZip", ctx, outsize, 0, 0) != CL_CLEAN) {
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

#ifndef HAVE_BZLIB_H
static cl_error_t cli_scanbzip(cli_ctx *ctx)
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

static cl_error_t cli_scanbzip(cli_ctx *ctx)
{
    cl_error_t ret = CL_CLEAN;
    int fd, rc;
    uint64_t size = 0;
    char *tmpname;
    bz_stream strm;
    size_t off = 0;
    size_t avail;
    char buf[FILEBUFF];

    memset(&strm, 0, sizeof(strm));
    strm.next_out = buf;
    strm.avail_out = sizeof(buf);
    rc = BZ2_bzDecompressInit(&strm, 0, 0);
    if (BZ_OK != rc) {
        cli_dbgmsg("Bzip: DecompressInit failed: %d\n", rc);
        return CL_EOPEN;
    }

    if ((ret = cli_gentempfd(ctx->sub_tmpdir, &tmpname, &fd))) {
        cli_dbgmsg("Bzip: Can't generate temporary file.\n");
        BZ2_bzDecompressEnd(&strm);
        return ret;
    }

    do {
        if (!strm.avail_in) {
            strm.next_in = (void *)fmap_need_off_once_len(ctx->fmap, off, FILEBUFF, &avail);
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

            if (cli_checklimits("Bzip", ctx, size, 0, 0) != CL_CLEAN)
                break;

            strm.next_out = buf;
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
#endif

static cl_error_t cli_scanxz(cli_ctx *ctx)
{
    cl_error_t ret = CL_CLEAN;
    int fd, rc;
    unsigned long int size = 0;
    char *tmpname;
    struct CLI_XZ strm;
    size_t off = 0;
    size_t avail;
    unsigned char *buf;

    buf = cli_malloc(CLI_XZ_OBUF_SIZE);
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

    if ((ret = cli_gentempfd(ctx->sub_tmpdir, &tmpname, &fd))) {
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
            if (rc == XZ_DIC_HEURISTIC) {
                ret = cli_append_potentially_unwanted(ctx, "Heuristics.XZ.DicSizeLimit");
                goto xz_exit;
            }
            cli_errmsg("cli_scanxz: decompress error: %d\n", rc);
            ret = CL_EFORMAT;
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
            if (cli_checklimits("cli_scanxz", ctx, size, 0, 0) != CL_CLEAN) {
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
        if (cli_unlink(tmpname) && ret == CL_CLEAN) {
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

    if ((ret = cli_gentempfd(ctx->sub_tmpdir, &tmpname, &ofd))) {
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

    ret = cli_exp_eval(ctx, target_ac_root, &tmdata, NULL, NULL);
    if (CL_SUCCESS != ret) {
        goto done;
    }

    ret = cli_exp_eval(ctx, generic_ac_root, &gmdata, NULL, NULL);

done:

    if (must_pop_stack) {
        (void)cli_recursion_stack_pop(ctx); /* Restore the parent fmap */
    }

    if (NULL != new_map) {
        funmap(new_map);
    }

    if (tmdata_initialized) {
        cli_ac_freedata(&tmdata);
    }

    if (gmdata_initialized) {
        cli_ac_freedata(&gmdata);
    }

    return ret;
}

#define min(x, y) ((x) < (y) ? (x) : (y))

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
                                len = min(strlen(dir) + 1, result_size);
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
                ret = CL_SUCCESS;
                hashcnt--;
                continue;
            }

#if HAVE_JSON
            if (*has_macros && SCAN_COLLECT_METADATA && (ctx->wrkproperty != NULL)) {
                cli_jsonbool(ctx->wrkproperty, "HasMacros", 1);
                json_object *macro_languages = cli_jsonarray(ctx->wrkproperty, "MacroLanguages");
                if (macro_languages) {
                    cli_jsonstr(macro_languages, NULL, "VBA");
                } else {
                    cli_dbgmsg("[cli_ole2_tempdir_scan_vba_new] Failed to add \"VBA\" entry to MacroLanguages JSON array\n");
                }
            }
#endif
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

            ret = cli_scan_desc(tempfd, ctx, CL_TYPE_SCRIPT, false, NULL, AC_SCAN_VIR, NULL, NULL, LAYER_ATTRIBUTES_NONE);
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
    cl_error_t status = CL_CLEAN;
    cl_error_t ret;
    char summary_filename[1024];
    char *hash;
    uint32_t hashcnt = 0;

#if HAVE_JSON
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
            cli_ole2_summary_json(ctx, fd, 0);
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
            cli_ole2_summary_json(ctx, fd, 1);
            close(fd);
        }
        hashcnt--;
    }
#endif

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
    cl_error_t status = CL_CLEAN;
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
    vba_project_t *vba_project;
    char *fullname = NULL;
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
                        *ctx->scanned += data_len / CL_COUNT_PRECISION;
                    if (ctx->engine->keeptmp) {
                        if (CL_SUCCESS != (status = cli_gentempfd(ctx->sub_tmpdir, &proj_contents_fname, &proj_contents_fd))) {
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
                    *ctx->scanned += vba_project->length[i] / CL_COUNT_PRECISION;
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
#if HAVE_JSON
        if (SCAN_COLLECT_METADATA && (ctx->wrkproperty != NULL)) {
            cli_jsonbool(ctx->wrkproperty, "HasMacros", 1);
            json_object *macro_languages = cli_jsonarray(ctx->wrkproperty, "MacroLanguages");
            if (macro_languages) {
                cli_jsonstr(macro_languages, NULL, "VBA");
            } else {
                cli_dbgmsg("cli_ole2_tempdir_scan_vba: Failed to add \"VBA\" entry to MacroLanguages JSON array\n");
            }
        }
#endif

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
    cl_error_t ret      = CL_CLEAN;
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
                    cli_dbgmsg("cli_ole2_tempdir_scan_for_xlm_and_images: An error occured when parsing XLM BIFF temp file, skipping to next file.\n");
            }
        }
    }

done:
    return ret;
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

    if (NULL == (tempname = cli_gentemp_with_prefix(ctx->sub_tmpdir, "html-tmp"))) {
        status = CL_EMEM;
        goto done;
    }

    if (mkdir(tempname, 0700)) {
        cli_errmsg("cli_scanhtml: Can't create temporary directory %s\n", tempname);
        status = CL_ETMPDIR;
        goto done;
    }

    cli_dbgmsg("cli_scanhtml: using tempdir %s\n", tempname);

    (void)html_normalise_map(ctx, map, tempname, NULL, ctx->dconf);

    snprintf(fullname, 1024, "%s" PATHSEP "nocomment.html", tempname);
    fd = open(fullname, O_RDONLY | O_BINARY);
    if (fd >= 0) {
        // nocomment.html file exists, so lets scan it.

        status = cli_scan_desc(fd, ctx, CL_TYPE_HTML, false, NULL, AC_SCAN_VIR, NULL, NULL, LAYER_ATTRIBUTES_NORMALIZED);
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

            status = cli_scan_desc(fd, ctx, CL_TYPE_HTML, false, NULL, AC_SCAN_VIR, NULL, NULL, LAYER_ATTRIBUTES_NORMALIZED);
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

        status = cli_scan_desc(fd, ctx, CL_TYPE_HTML, false, NULL, AC_SCAN_VIR, NULL, NULL, LAYER_ATTRIBUTES_NORMALIZED);
        if (CL_SUCCESS != status) {
            goto done;
        }

        status = cli_scan_desc(fd, ctx, CL_TYPE_TEXT_ASCII, false, NULL, AC_SCAN_VIR, NULL, NULL, LAYER_ATTRIBUTES_NORMALIZED);
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
        ret = CL_CLEAN;
        goto done;
    }

    if (!(normalized = cli_malloc(SCANBUFF + maxpatlen))) {
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
        if ((ret = cli_gentempfd(ctx->sub_tmpdir, &tmpname, &ofd))) {
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
        new_map = fmap(ofd, 0, 0, NULL);
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
        ret = cli_scan_fmap(ctx, CL_TYPE_TEXT_ASCII, false, NULL, AC_SCAN_VIR, NULL, NULL);

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
            if (!buff || text_normalize_buffer(&state, buff, len) != len) {
                cli_dbgmsg("cli_scanscript: short read during normalizing\n");
            }
        }
    }

    ret = cli_exp_eval(ctx, target_ac_root, &tmdata, NULL, NULL);
    if (CL_SUCCESS != ret) {
        goto done;
    }

    ret = cli_exp_eval(ctx, generic_ac_root, &gmdata, NULL, NULL);
    if (CL_SUCCESS != ret) {
        goto done;
    }

done:
    if (NULL != new_map) {
        funmap(new_map);
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

    if (!(tempname = cli_gentemp_with_prefix(ctx->sub_tmpdir, "html-utf16-tmp"))) {
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

    new_map = fmap(fd, 0, 0, NULL);
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
        funmap(new_map);
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
    cl_error_t status = CL_CLEAN;
    DIR *dd           = NULL;
    int has_macros    = 0;

    struct dirent *dent;
    STATBUF statbuf;
    char *subdirectory = NULL;

    cli_dbgmsg("cli_ole2_scan_tempdir: %s\n", dir);

    /* Output JSON Summary Information */
    if (SCAN_COLLECT_METADATA && (ctx->wrkproperty != NULL)) {
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
                    subdirectory = cli_malloc(strlen(dir) + strlen(dent->d_name) + 2);
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
    cl_error_t ret     = CL_CLEAN;
    struct uniq *files = NULL;
    int has_vba        = 0;
    int has_xlm        = 0;
    int has_image      = 0;

    cli_dbgmsg("in cli_scanole2()\n");

    /* generate the temporary directory */
    if (NULL == (dir = cli_gentemp_with_prefix(ctx->sub_tmpdir, "ole2-tmp"))) {
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
    cl_error_t ret = CL_CLEAN;

    cli_dbgmsg("in cli_scantar()\n");

    /* generate temporary directory */
    if (!(dir = cli_gentemp_with_prefix(ctx->sub_tmpdir, "tar-tmp")))
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
    cl_error_t ret = CL_CLEAN;

    cli_dbgmsg("in cli_scanscrenc()\n");

    if (!(tempname = cli_gentemp_with_prefix(ctx->sub_tmpdir, "screnc-tmp")))
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
    cl_error_t ret = CL_CLEAN;

    if (cli_check_riff_exploit(ctx) == 2)
        ret = cli_append_potentially_unwanted(ctx, "Heuristics.Exploit.W32.MS05-002");

    return ret;
}

static cl_error_t cli_scancryptff(cli_ctx *ctx)
{
    cl_error_t ret = CL_CLEAN, ndesc;
    unsigned int i;
    const unsigned char *src;
    unsigned char *dest = NULL;
    char *tempfile;
    size_t pos;
    size_t bread;

    /* Skip the CryptFF file header */
    pos = 0x10;

    if ((dest = (unsigned char *)cli_malloc(FILEBUFF)) == NULL) {
        cli_dbgmsg("CryptFF: Can't allocate memory\n");
        return CL_EMEM;
    }

    if (!(tempfile = cli_gentemp_with_prefix(ctx->sub_tmpdir, "cryptff"))) {
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
    char *dir = cli_gentemp_with_prefix(ctx->sub_tmpdir, "pdf-tmp");

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
    char *dir = cli_gentemp_with_prefix(ctx->sub_tmpdir, "tnef-tmp");

    if (!dir)
        return CL_EMEM;

    if (mkdir(dir, 0700)) {
        cli_dbgmsg("Can't create temporary directory for tnef file %s\n", dir);
        free(dir);
        return CL_ETMPDIR;
    }

    ret = cli_tnef(dir, ctx);

    if (ret == CL_CLEAN)
        ret = cli_magic_scan_dir(dir, ctx, LAYER_ATTRIBUTES_NONE);

    if (!ctx->engine->keeptmp)
        cli_rmdirs(dir);

    free(dir);
    return ret;
}

static cl_error_t cli_scanuuencoded(cli_ctx *ctx)
{
    cl_error_t ret;
    char *dir = cli_gentemp_with_prefix(ctx->sub_tmpdir, "uuencoded-tmp");

    if (!dir)
        return CL_EMEM;

    if (mkdir(dir, 0700)) {
        cli_dbgmsg("Can't create temporary directory for uuencoded file %s\n", dir);
        free(dir);
        return CL_ETMPDIR;
    }

    ret = cli_uuencode(dir, ctx->fmap);

    if (ret == CL_CLEAN)
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
    if (NULL == (dir = cli_gentemp_with_prefix(ctx->sub_tmpdir, "mail-tmp"))) {
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

    return CL_CLEAN;
}

static cl_error_t cli_scanembpe(cli_ctx *ctx, off_t offset)
{
    cl_error_t ret = CL_CLEAN;
    int fd;
    size_t bytes;
    size_t size = 0;
    size_t todo;
    const char *buff;
    char *tmpname;
    fmap_t *map = ctx->fmap;
    unsigned int corrupted_input;

    tmpname = cli_gentemp_with_prefix(ctx->sub_tmpdir, "embedded-pe");
    if (!tmpname)
        return CL_EMEM;

    if ((fd = open(tmpname, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR)) < 0) {
        cli_errmsg("cli_scanembpe: Can't create file %s\n", tmpname);
        free(tmpname);
        return CL_ECREAT;
    }

    todo = map->len - offset;
    while (1) {
        bytes = MIN(todo, map->pgsz);
        if (!bytes)
            break;

        if (!(buff = fmap_need_off_once(map, offset + size, bytes))) {
            close(fd);
            if (!ctx->engine->keeptmp) {
                if (cli_unlink(tmpname)) {
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

        if (cli_writen(fd, buff, bytes) != bytes) {
            cli_dbgmsg("cli_scanembpe: Can't write to temporary file\n");
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
    }

    // Setting ctx->corrupted_input will prevent the PE parser from reporting "broken executable" for unpacked/reconstructed files that may not be 100% to spec.
    corrupted_input      = ctx->corrupted_input;
    ctx->corrupted_input = 1;
    ret                  = cli_magic_scan_desc(fd, tmpname, ctx, NULL, LAYER_ATTRIBUTES_NONE);
    ctx->corrupted_input = corrupted_input;
    if (ret != CL_SUCCESS) {
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
    if (!ctx->engine->keeptmp) {
        if (cli_unlink(tmpname)) {
            free(tmpname);
            return CL_EUNLINK;
        }
    }
    free(tmpname);

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
 * @param refhash       Hash of current fmap
 * @return cl_error_t
 */
static cl_error_t scanraw(cli_ctx *ctx, cli_file_t type, uint8_t typercg, cli_file_t *dettype, unsigned char *refhash)
{
    cl_error_t ret = CL_CLEAN, nret = CL_CLEAN;
    struct cli_matched_type *ftoffset = NULL, *fpt;
    struct cli_exe_info peinfo;
    unsigned int acmode = AC_SCAN_VIR, break_loop = 0;

    cli_file_t found_type;

#if HAVE_JSON
    struct json_object *parent_property = NULL;
#else
    void *parent_property = NULL;
#endif

    if ((typercg) &&
        // We should also omit bzips, but DMG's may be detected in bzips. (type != CL_TYPE_BZ) &&        /* Omit BZ files because they can contain portions of original files like zip file entries that cause invalid extractions and lots of warnings. Decompress first, then scan! */
        (type != CL_TYPE_GZ) &&        /* Omit GZ files because they can contain portions of original files like zip file entries that cause invalid extractions and lots of warnings. Decompress first, then scan! */
        (type != CL_TYPE_CPIO_OLD) &&  /* Omit CPIO_OLD files because it's an image format that we can extract and scan manually. */
        (type != CL_TYPE_ZIP) &&       /* Omit ZIP files because it'll detect each zip file entry as SFXZIP, which is a waste. We'll extract it and then scan. */
        (type != CL_TYPE_ZIPSFX) &&    /* Omit SFX archive types from being checked for embedded content. They should only be parsed for contained files. Those contained files could be EXE's with more SFX, but that's the nature of containers. */
        (type != CL_TYPE_ARJSFX) &&    /* " */
        (type != CL_TYPE_RARSFX) &&    /* " */
        (type != CL_TYPE_EGGSFX) &&    /* " */
        (type != CL_TYPE_CABSFX) &&    /* " */
        (type != CL_TYPE_7ZSFX) &&     /* " */
        (type != CL_TYPE_OLD_TAR) &&   /* Omit OLD TAR files because it's a raw archive format that we can extract and scan manually. */
        (type != CL_TYPE_POSIX_TAR)) { /* Omit POSIX TAR files because it's a raw archive format that we can extract and scan manually. */
        /*
         * Enable file type recognition scan mode if requested, except for some some problematic types (above).
         */
        acmode |= AC_SCAN_FT;
    }

    perf_start(ctx, PERFT_RAW);
    ret = cli_scan_fmap(ctx, type == CL_TYPE_TEXT_ASCII ? CL_TYPE_ANY : type, false, &ftoffset, acmode, NULL, refhash);
    perf_stop(ctx, PERFT_RAW);

    // In allmatch-mode, ret will never be CL_VIRUS, so ret may be used exlusively for file type detection and for terminal errors.
    // When not in allmatch-mode, it's more important to return right away if ret is CL_VIRUS, so we don't care if file type matches were found.
    if (ret >= CL_TYPENO) {
        // Matched 1+ file type signatures. Handle them.
        found_type = (cli_file_t)ret;

        perf_nested_start(ctx, PERFT_RAWTYPENO, PERFT_SCAN);

        fpt = ftoffset;

        while (fpt) {
            if (fpt->offset > 0) {
                bool type_has_been_handled = true;

#if HAVE_JSON
                /*
                 * Add embedded file to metadata JSON.
                 */
                if (SCAN_COLLECT_METADATA && ctx->wrkproperty) {
                    json_object *arrobj;

                    parent_property = ctx->wrkproperty;
                    if (!json_object_object_get_ex(parent_property, "EmbeddedObjects", &arrobj)) {
                        arrobj = json_object_new_array();
                        if (NULL == arrobj) {
                            cli_errmsg("scanraw: no memory for json properties object\n");
                            nret = CL_EMEM;
                            break;
                        }
                        json_object_object_add(parent_property, "EmbeddedObjects", arrobj);
                    }
                    ctx->wrkproperty = json_object_new_object();
                    if (NULL == ctx->wrkproperty) {
                        cli_errmsg("scanraw: no memory for json properties object\n");
                        nret = CL_EMEM;
                        break;
                    }
                    json_object_array_add(arrobj, ctx->wrkproperty);

                    ret = cli_jsonstr(ctx->wrkproperty, "FileType", cli_ftname(fpt->type));
                    if (ret != CL_SUCCESS) {
                        cli_errmsg("scanraw: failed to add string to json object\n");
                        nret = CL_EMEM;
                        break;
                    }

                    ret = cli_jsonint64(ctx->wrkproperty, "Offset", (int64_t)fpt->offset);
                    if (ret != CL_SUCCESS) {
                        cli_errmsg("scanraw: failed to add int to json object\n");
                        nret = CL_EMEM;
                        break;
                    }
                }
#endif
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
                                cli_recursion_stack_change_type(ctx, fpt->type);

                                cli_dbgmsg("MHTML signature found at %u\n", (unsigned int)fpt->offset);
                                nret = ret = cli_scanmail(ctx);
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
                                cli_recursion_stack_change_type(ctx, fpt->type);

                                cli_dbgmsg("XDP signature found at %u\n", (unsigned int)fpt->offset);
                                nret = ret = cli_scanxdp(ctx);
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
                                cli_recursion_stack_change_type(ctx, fpt->type);

                                cli_dbgmsg("XML-WORD signature found at %u\n", (unsigned int)fpt->offset);
                                nret = ret = cli_scanmsxml(ctx);
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
                                cli_recursion_stack_change_type(ctx, fpt->type);

                                cli_dbgmsg("XML-XL signature found at %u\n", (unsigned int)fpt->offset);
                                nret = ret = cli_scanmsxml(ctx);
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
                                cli_recursion_stack_change_type(ctx, fpt->type);

                                cli_dbgmsg("XML-HWP signature found at %u\n", (unsigned int)fpt->offset);
                                nret = ret = cli_scanhwpml(ctx);
                            }
                        }
                        break;

                    case CL_TYPE_DMG:
                        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_DMG)) {
                            // TODO: determine all types that DMG may start with
                            // if ((ctx->recursion_stack[ctx->recursion_level].type == CL_TYPE_BZIP2) || ...))
                            {
                                // Reassign type of current layer based on what we discovered
                                cli_recursion_stack_change_type(ctx, fpt->type);

                                cli_dbgmsg("DMG signature found at %u\n", (unsigned int)fpt->offset);
                                nret = cli_scandmg(ctx);
                            }
                        }
                        break;

                    case CL_TYPE_ISO9660:
                        if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ISO9660)) {
                            // TODO: determine all types that ISO9660 may start with
                            // if ((ctx->recursion_stack[ctx->recursion_level].type == CL_TYPE_ANY) || ...))
                            {
                                // Reassign type of current layer based on what we discovered
                                cli_recursion_stack_change_type(ctx, fpt->type);

                                cli_dbgmsg("DMG signature found at %u\n", (unsigned int)fpt->offset);
                                nret = cli_scaniso(ctx, fpt->offset);
                            }
                        }
                        break;

                    case CL_TYPE_MBR:
                        if (SCAN_PARSE_ARCHIVE) {
                            // TODO: determine all types that GPT or MBR may start with
                            // if ((ctx->recursion_stack[ctx->recursion_level].type == CL_TYPE_???) ||  ...))
                            {
                                // First check if actually a GPT, not MBR.
                                int iret = cli_mbr_check2(ctx, 0);

                                if ((iret == CL_TYPE_GPT) && (DCONF_ARCH & ARCH_CONF_GPT)) {
                                    // Reassign type of current layer based on what we discovered
                                    cli_recursion_stack_change_type(ctx, CL_TYPE_GPT);

                                    cli_dbgmsg("Recognized GUID Partition Table file\n");
                                    cli_dbgmsg("GPT signature found at %u\n", (unsigned int)fpt->offset);
                                    nret = cli_scangpt(ctx, 0);
                                } else if ((iret == CL_CLEAN) && (DCONF_ARCH & ARCH_CONF_MBR)) {
                                    // Reassign type of current layer based on what we discovered
                                    cli_recursion_stack_change_type(ctx, CL_TYPE_MBR);

                                    cli_dbgmsg("MBR signature found at %u\n", (unsigned int)fpt->offset);
                                    nret = cli_scanmbr(ctx, 0);
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
                if ((ctx->recursion_stack[ctx->recursion_level].recursion_level_buffer_fmap == 0) &&
                    (false == type_has_been_handled)) {

                    fmap_t *new_map = NULL;

                    /*
                     * Only do this though if we're at the top fmap layer of a buffer.
                     *
                     * This restriction will prevent detecting the same embedded content
                     * more than once when recursing with embedded file type recognition
                     * deeper within the same buffer.
                     */
                    cli_dbgmsg("%s signature found at %u\n", cli_ftname(fpt->type), (unsigned int)fpt->offset);

                    type_has_been_handled = true;

                    switch (fpt->type) {
                        case CL_TYPE_RARSFX:
                            if (type != CL_TYPE_RAR && have_rar && SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_RAR)) {

                                /// TODO: This is extremely expensive because it has to hash the fpt->offset -> len!
                                /// We need to find a way to not hash every time!!!!
                                new_map = fmap_duplicate(ctx->fmap, fpt->offset, ctx->fmap->len - fpt->offset, NULL);
                                if (NULL == new_map) {
                                    ret = nret = CL_EMEM;
                                    cli_dbgmsg("scanraw: Failed to duplicate fmap to scan embedded file.\n");
                                    break;
                                }

                                /* Perform scan with child fmap */
                                nret = cli_recursion_stack_push(ctx, new_map, CL_TYPE_RAR, false, LAYER_ATTRIBUTES_NONE);
                                if (CL_SUCCESS != nret) {
                                    ret = nret;
                                    cli_dbgmsg("scanraw: Failed to add map to recursion stack to scan embedded file.\n");
                                    break;
                                }

                                nret = cli_scanrar(ctx);

                                (void)cli_recursion_stack_pop(ctx);
                            }
                            break;

                        case CL_TYPE_EGGSFX:
                            if (type != CL_TYPE_EGG && SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_EGG)) {

                                new_map = fmap_duplicate(ctx->fmap, fpt->offset, ctx->fmap->len - fpt->offset, NULL);
                                if (NULL == new_map) {
                                    ret = nret = CL_EMEM;
                                    cli_dbgmsg("scanraw: Failed to duplicate fmap to scan embedded file.\n");
                                    break;
                                }

                                /* Perform scan with child fmap */
                                nret = cli_recursion_stack_push(ctx, new_map, CL_TYPE_EGG, false, LAYER_ATTRIBUTES_NONE);
                                if (CL_SUCCESS != nret) {
                                    ret = nret;
                                    cli_dbgmsg("scanraw: Failed to add map to recursion stack to scan embedded file.\n");
                                    break;
                                }

                                nret = cli_scanegg(ctx);

                                (void)cli_recursion_stack_pop(ctx);
                            }
                            break;

                        case CL_TYPE_ZIPSFX:
                            if (type != CL_TYPE_ZIP && SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ZIP)) {

                                new_map = fmap_duplicate(ctx->fmap, fpt->offset, ctx->fmap->len - fpt->offset, NULL);
                                if (NULL == new_map) {
                                    ret = nret = CL_EMEM;
                                    cli_dbgmsg("scanraw: Failed to duplicate fmap to scan embedded file.\n");
                                    break;
                                }

                                /* Perform scan with child fmap */
                                nret = cli_recursion_stack_push(ctx, new_map, CL_TYPE_ZIP, false, LAYER_ATTRIBUTES_NONE);
                                if (CL_SUCCESS != nret) {
                                    ret = nret;
                                    cli_dbgmsg("scanraw: Failed to add map to recursion stack to scan embedded file.\n");
                                    break;
                                }

                                nret = cli_unzip_single(ctx, 0);

                                (void)cli_recursion_stack_pop(ctx);
                            }
                            break;

                        case CL_TYPE_CABSFX:
                            if (type != CL_TYPE_MSCAB && SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_CAB)) {

                                new_map = fmap_duplicate(ctx->fmap, fpt->offset, ctx->fmap->len - fpt->offset, NULL);
                                if (NULL == new_map) {
                                    ret = nret = CL_EMEM;
                                    cli_dbgmsg("scanraw: Failed to duplicate fmap to scan embedded file.\n");
                                    break;
                                }

                                /* Perform scan with child fmap */
                                nret = cli_recursion_stack_push(ctx, new_map, CL_TYPE_MSCAB, false, LAYER_ATTRIBUTES_NONE);
                                if (CL_SUCCESS != nret) {
                                    ret = nret;
                                    cli_dbgmsg("scanraw: Failed to add map to recursion stack to scan embedded file.\n");
                                    break;
                                }

                                nret = cli_scanmscab(ctx, 0);

                                (void)cli_recursion_stack_pop(ctx);
                            }
                            break;

                        case CL_TYPE_ARJSFX:
                            if (type != CL_TYPE_ARJ && SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ARJ)) {

                                new_map = fmap_duplicate(ctx->fmap, fpt->offset, ctx->fmap->len - fpt->offset, NULL);
                                if (NULL == new_map) {
                                    ret = nret = CL_EMEM;
                                    cli_dbgmsg("scanraw: Failed to duplicate fmap to scan embedded file.\n");
                                    break;
                                }

                                /* Perform scan with child fmap */
                                nret = cli_recursion_stack_push(ctx, new_map, CL_TYPE_ARJ, false, LAYER_ATTRIBUTES_NONE);
                                if (CL_SUCCESS != nret) {
                                    ret = nret;
                                    cli_dbgmsg("scanraw: Failed to add map to recursion stack to scan embedded file.\n");
                                    break;
                                }

                                nret = cli_scanarj(ctx);

                                (void)cli_recursion_stack_pop(ctx);
                            }
                            break;

                        case CL_TYPE_7ZSFX:
                            if (type != CL_TYPE_7Z && SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_7Z)) {

                                new_map = fmap_duplicate(ctx->fmap, fpt->offset, ctx->fmap->len - fpt->offset, NULL);
                                if (NULL == new_map) {
                                    ret = nret = CL_EMEM;
                                    cli_dbgmsg("scanraw: Failed to duplicate fmap to scan embedded file.\n");
                                    break;
                                }

                                /* Perform scan with child fmap */
                                nret = cli_recursion_stack_push(ctx, new_map, CL_TYPE_7Z, false, LAYER_ATTRIBUTES_NONE);
                                if (CL_SUCCESS != nret) {
                                    ret = nret;
                                    cli_dbgmsg("scanraw: Failed to add map to recursion stack to scan embedded file.\n");
                                    break;
                                }

                                nret = cli_7unz(ctx, 0);

                                (void)cli_recursion_stack_pop(ctx);
                            }
                            break;

                        case CL_TYPE_NULSFT:
                            if (SCAN_PARSE_ARCHIVE && type == CL_TYPE_MSEXE && (DCONF_ARCH & ARCH_CONF_NSIS) && fpt->offset > 4) {
                                // Note: CL_TYPE_NULSFT is special, because the file actually starts 4 bytes before the start of the signature match
                                new_map = fmap_duplicate(ctx->fmap, fpt->offset - 4, ctx->fmap->len - (fpt->offset - 4), NULL);
                                if (NULL == new_map) {
                                    ret = nret = CL_EMEM;
                                    cli_dbgmsg("scanraw: Failed to duplicate fmap to scan embedded file.\n");
                                    break;
                                }

                                /* Perform scan with child fmap */
                                nret = cli_recursion_stack_push(ctx, new_map, CL_TYPE_NULSFT, false, LAYER_ATTRIBUTES_NONE);
                                if (CL_SUCCESS != nret) {
                                    ret = nret;
                                    cli_dbgmsg("scanraw: Failed to add map to recursion stack to scan embedded file.\n");
                                    break;
                                }

                                nret = cli_scannulsft(ctx, 0);

                                (void)cli_recursion_stack_pop(ctx);
                            }
                            break;

                        case CL_TYPE_AUTOIT:
                            if (SCAN_PARSE_ARCHIVE && type == CL_TYPE_MSEXE && (DCONF_ARCH & ARCH_CONF_AUTOIT)) {

                                new_map = fmap_duplicate(ctx->fmap, fpt->offset, ctx->fmap->len - fpt->offset, NULL);
                                if (NULL == new_map) {
                                    ret = nret = CL_EMEM;
                                    cli_dbgmsg("scanraw: Failed to duplicate fmap to scan embedded file.\n");
                                    break;
                                }

                                /* Perform scan with child fmap */
                                nret = cli_recursion_stack_push(ctx, new_map, CL_TYPE_AUTOIT, false, LAYER_ATTRIBUTES_NONE);
                                if (CL_SUCCESS != nret) {
                                    ret = nret;
                                    cli_dbgmsg("scanraw: Failed to add map to recursion stack to scan embedded file.\n");
                                    break;
                                }

                                nret = cli_scanautoit(ctx, 23);

                                (void)cli_recursion_stack_pop(ctx);
                            }
                            break;

                        case CL_TYPE_ISHIELD_MSI:
                            if (SCAN_PARSE_ARCHIVE && type == CL_TYPE_MSEXE && (DCONF_ARCH & ARCH_CONF_ISHIELD)) {

                                new_map = fmap_duplicate(ctx->fmap, fpt->offset, ctx->fmap->len - fpt->offset, NULL);
                                if (NULL == new_map) {
                                    ret = nret = CL_EMEM;
                                    cli_dbgmsg("scanraw: Failed to duplicate fmap to scan embedded file.\n");
                                    break;
                                }

                                /* Perform scan with child fmap */
                                nret = cli_recursion_stack_push(ctx, new_map, CL_TYPE_ISHIELD_MSI, false, LAYER_ATTRIBUTES_NONE);
                                if (CL_SUCCESS != nret) {
                                    ret = nret;
                                    cli_dbgmsg("scanraw: Failed to add map to recursion stack to scan embedded file.\n");
                                    break;
                                }

                                nret = cli_scanishield_msi(ctx, 14);

                                (void)cli_recursion_stack_pop(ctx);
                            }
                            break;

                        case CL_TYPE_PDF:
                            if (type != CL_TYPE_PDF && SCAN_PARSE_PDF && (DCONF_DOC & DOC_CONF_PDF)) {

                                new_map = fmap_duplicate(ctx->fmap, fpt->offset, ctx->fmap->len - fpt->offset, NULL);
                                if (NULL == new_map) {
                                    ret = nret = CL_EMEM;
                                    cli_dbgmsg("scanraw: Failed to duplicate fmap to scan embedded file.\n");
                                    break;
                                }

                                /* Perform scan with child fmap */
                                nret = cli_recursion_stack_push(ctx, new_map, CL_TYPE_PDF, false, LAYER_ATTRIBUTES_NONE);
                                if (CL_SUCCESS != nret) {
                                    ret = nret;
                                    cli_dbgmsg("scanraw: Failed to add map to recursion stack to scan embedded file.\n");
                                    break;
                                }

                                nret = cli_scanpdf(ctx, 0);

                                (void)cli_recursion_stack_pop(ctx);
                            }
                            break;

                        case CL_TYPE_MSEXE:
                            if (SCAN_PARSE_PE && (type == CL_TYPE_MSEXE || type == CL_TYPE_ZIP || type == CL_TYPE_MSOLE2) && ctx->dconf->pe) {

                                if ((uint64_t)(ctx->fmap->len - fpt->offset) > ctx->engine->maxembeddedpe) {
                                    cli_dbgmsg("scanraw: MaxEmbeddedPE exceeded\n");
                                    break;
                                }

                                new_map = fmap_duplicate(ctx->fmap, fpt->offset, ctx->fmap->len - fpt->offset, NULL);
                                if (NULL == new_map) {
                                    ret = nret = CL_EMEM;
                                    cli_dbgmsg("scanraw: Failed to duplicate fmap to scan embedded file.\n");
                                    break;
                                }

                                /* Perform scan with child fmap */
                                nret = cli_recursion_stack_push(ctx, new_map, CL_TYPE_MSEXE, false, LAYER_ATTRIBUTES_NONE);
                                if (CL_SUCCESS != nret) {
                                    ret = nret;
                                    cli_dbgmsg("scanraw: Failed to add map to recursion stack to scan embedded file.\n");
                                    break;
                                }
                                // IMPORTANT: Must not break or return before cli_recursion_stack_pop!

                                cli_exe_info_init(&peinfo, 0);

                                // TODO We could probably substitute in a quicker
                                // method of determining whether a PE file exists
                                // at this offset.
                                if (cli_peheader(ctx->fmap, &peinfo, CLI_PEHEADER_OPT_NONE, NULL) != 0) {
                                    cli_dbgmsg("Header check for MSEXE detection failed, probably not actually an embedded PE file.\n");

                                    /* Despite failing, peinfo memory may have been allocated and must be freed. */
                                    cli_exe_info_destroy(&peinfo);

                                } else {
                                    cli_dbgmsg("*** Detected embedded PE file at %u ***\n", (unsigned int)fpt->offset);

                                    /* Immediately free up peinfo allocated memory, prior to any recursion */
                                    cli_exe_info_destroy(&peinfo);

                                    nret       = cli_scanembpe(ctx, 0);
                                    break_loop = 1; /* we can stop here and other
                                                     * embedded executables will
                                                     * be found recursively
                                                     * through the above call
                                                     */

                                    // TODO This method of embedded PE extraction
                                    // is kinda gross in that:
                                    //   - if you have an executable that contains
                                    //     20 other exes, the bytes associated with
                                    //     the last exe will have been included in
                                    //     hash computations and things 20 times
                                    //     (as overlay data to the previously
                                    //     extracted exes).
                                    //   - if you have a signed embedded exe, it
                                    //     will fail to validate after extraction
                                    //     bc it has overlay data, which is a
                                    //     violation of the Authenticode spec.
                                    //   - this method of extraction is subject to
                                    //     the recursion limit, which is fairly
                                    //     low by default (I think 16)
                                    //
                                    // It'd be awesome if we could compute the PE
                                    // size from the PE header and just extract
                                    // that.
                                }

                                (void)cli_recursion_stack_pop(ctx);
                            }
                            break;

                        default:
                            type_has_been_handled = false;
                            cli_dbgmsg("scanraw: Type %u not handled in fpt loop\n", fpt->type);
                    }

                    if (NULL != new_map) {
                        free_duplicate_fmap(new_map);
                    }
                } // end check for embedded files
            }     // end if (fpt->offset > 0)

            if ((nret == CL_EMEM) ||
                (ctx->abort_scan) ||
                (break_loop)) {
                break;
            }

            fpt = fpt->next;

#if HAVE_JSON
            if (NULL != parent_property) {
                ctx->wrkproperty = (struct json_object *)(parent_property);
                parent_property  = NULL;
            }
#endif
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
                        cli_recursion_stack_change_type(ctx, CL_TYPE_HTML);
                        nret = cli_scanhtml(ctx);
                    }
                    break;

                case CL_TYPE_MAIL:
                    if (SCAN_PARSE_MAIL && type == CL_TYPE_TEXT_ASCII && (DCONF_MAIL & MAIL_CONF_MBOX)) {
                        *dettype = CL_TYPE_MAIL;
                        cli_recursion_stack_change_type(ctx, CL_TYPE_MAIL);
                        nret = cli_scanmail(ctx);
                    }
                    break;

                default:
                    break;
            }
        }

        perf_nested_stop(ctx, PERFT_RAWTYPENO, PERFT_SCAN);
        ret = nret;
    } // end if (ret >= CL_TYPENO)

#if HAVE_JSON
    if (NULL != parent_property) {
        ctx->wrkproperty = (struct json_object *)(parent_property);
    }
#endif

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
 * @param old_hook_lsig_matches
 * @param parent_property
 * @param run_cleanup
 * @return cl_error_t
 */
static cl_error_t dispatch_file_inspection_callback(clcb_file_inspection cb, cli_ctx *ctx, const char *filetype)
{
    cl_error_t status = CL_CLEAN;

    int fd            = -1;
    size_t fmap_index = ctx->recursion_level; /* index of current file */

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

    CLI_CALLOC(ancestors, ctx->recursion_level + 1, sizeof(char *), status = CL_EMEM);

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
            cli_dbgmsg("dispatch_file_inspection_callback: scan cancelled by callback\n");
            status = CL_BREAK;
            break;
        case CL_VIRUS:
            cli_dbgmsg("dispatch_file_inspection_callback: file blocked by callback\n");
            cli_append_virus(ctx, "Detected.By.Callback.Inspection");
            status = CL_VIRUS;
            break;
        case CL_CLEAN:
            break;
        default:
            status = CL_CLEAN;
            cli_warnmsg("dispatch_file_inspection_callback: ignoring bad return code from callback\n");
    }

done:

    FREE(ancestors);
    return status;
}

static cl_error_t dispatch_prescan_callback(clcb_pre_scan cb, cli_ctx *ctx, const char *filetype)
{
    cl_error_t status = CL_CLEAN;

    if (cb) {
        perf_start(ctx, PERFT_PRECB);
        status = cb(fmap_fd(ctx->fmap), filetype, ctx->cb_ctx);
        perf_stop(ctx, PERFT_PRECB);

        switch (status) {
            case CL_BREAK:
                cli_dbgmsg("dispatch_prescan_callback: file allowed by callback\n");
                status = CL_VERIFIED;
                break;
            case CL_VIRUS:
                cli_dbgmsg("dispatch_prescan_callback: file blocked by callback\n");
                status = cli_append_virus(ctx, "Detected.By.Callback");
                break;
            case CL_CLEAN:
                break;
            default:
                status = CL_CLEAN;
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

    if (SCAN_COLLECT_METADATA && (NULL != ctx->wrkproperty)) {
        if (NULL == (header = cli_jsonobj(ctx->wrkproperty, "ImageFuzzyHash"))) {
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

        // Exceeding the time limit should definitly halt the scan.
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
    cl_error_t ret = CL_CLEAN;
    cl_error_t cache_check_result;
    cl_error_t verdict_at_this_level;
    cli_file_t dettype              = 0;
    uint8_t typercg                 = 1;
    size_t hashed_size              = 0;
    unsigned char *hash             = NULL;
    bitset_t *old_hook_lsig_matches = NULL;
    const char *filetype;

#if HAVE_JSON
    struct json_object *parent_property = NULL;
#else
    void *parent_property = NULL;
#endif

    char *old_temp_path = NULL;
    char *new_temp_path = NULL;

    if (!ctx->engine) {
        cli_errmsg("CRITICAL: engine == NULL\n");
        ret = CL_ENULLARG;
        goto early_ret;
    }

    if (!(ctx->engine->dboptions & CL_DB_COMPILED)) {
        cli_errmsg("CRITICAL: engine not compiled\n");
        ret = CL_EMALFDB;
        goto early_ret;
    }

    if (ctx->fmap->len <= 5) {
        cli_dbgmsg("cli_magic_scan: File is too too small (%zu bytes), ignoring.\n", ctx->fmap->len);
        ret = CL_CLEAN;
        goto early_ret;
    }

    if (cli_updatelimits(ctx, ctx->fmap->len) != CL_CLEAN) {
        emax_reached(ctx);
        ret = CL_CLEAN;
        cli_dbgmsg("cli_magic_scan: returning %d %s (no post, no cache)\n", ret, __AT__);
        goto early_ret;
    }

    if (ctx->engine->keeptmp) {
        char *fmap_basename = NULL;
        /*
         * Keep-temp enabled, so create a sub-directory to provide extraction directory recursion.
         */
        if ((NULL != ctx->fmap->name) &&
            (CL_SUCCESS == cli_basename(ctx->fmap->name, strlen(ctx->fmap->name), &fmap_basename))) {
            /*
             * The fmap has a name, lets include it in the new sub-directory.
             */
            new_temp_path = cli_gentemp_with_prefix(ctx->sub_tmpdir, fmap_basename);
            free(fmap_basename);
            if (NULL == new_temp_path) {
                cli_errmsg("cli_magic_scan: Failed to generate temp directory name.\n");
                ret = CL_EMEM;
                goto early_ret;
            }
        } else {
            /*
             * The fmap has no name or we failed to get the basename.
             */
            new_temp_path = cli_gentemp(ctx->sub_tmpdir);
            if (NULL == new_temp_path) {
                cli_errmsg("cli_magic_scan: Failed to generate temp directory name.\n");
                ret = CL_EMEM;
                goto early_ret;
            }
        }

        old_temp_path   = ctx->sub_tmpdir;
        ctx->sub_tmpdir = new_temp_path;

        if (mkdir(ctx->sub_tmpdir, 0700)) {
            cli_errmsg("cli_magic_scan: Can't create tmp sub-directory for scan: %s.\n", ctx->sub_tmpdir);
            ret = CL_EACCES;
            goto early_ret;
        }
    }

    if (type == CL_TYPE_PART_ANY) {
        typercg = 0;
    }

    /*
     * Perform file typing from the start of the file.
     */
    perf_start(ctx, PERFT_FT);
    if ((type == CL_TYPE_ANY) || type == CL_TYPE_PART_ANY) {
        type = cli_determine_fmap_type(ctx->fmap, ctx->engine, type);
    }
    perf_stop(ctx, PERFT_FT);
    if (type == CL_TYPE_ERROR) {
        cli_dbgmsg("cli_magic_scan: cli_determine_fmap_type returned CL_TYPE_ERROR\n");
        ret = CL_EREAD;
        cli_dbgmsg("cli_magic_scan: returning %d %s (no post, no cache)\n", ret, __AT__);
        goto early_ret;
    }
    filetype = cli_ftname(type);

    /* set current layer to the type we found */
    cli_recursion_stack_change_type(ctx, type);

#if HAVE_JSON
    if (SCAN_COLLECT_METADATA) {
        /*
         * Create JSON object to record metadata during the scan.
         */
        if (NULL == ctx->properties) {
            ctx->properties = json_object_new_object();
            if (NULL == ctx->properties) {
                cli_errmsg("cli_magic_scan: no memory for json properties object\n");
                ret = CL_EMEM;
                cli_dbgmsg("cli_magic_scan: returning %d %s (no post, no cache)\n", ret, __AT__);
                goto early_ret;
            }
            ctx->wrkproperty = ctx->properties;

            ret = cli_jsonstr(ctx->properties, "Magic", "CLAMJSONv0");
            if (ret != CL_SUCCESS) {
                cli_dbgmsg("cli_magic_scan: returning %d %s (no post, no cache)\n", ret, __AT__);
                goto early_ret;
            }
            ret = cli_jsonstr(ctx->properties, "RootFileType", filetype);
            if (ret != CL_SUCCESS) {
                cli_dbgmsg("cli_magic_scan: returning %d %s (no post, no cache)\n", ret, __AT__);
                goto early_ret;
            }

        } else {
            json_object *arrobj;

            parent_property = ctx->wrkproperty;
            if (!json_object_object_get_ex(parent_property, "ContainedObjects", &arrobj)) {
                arrobj = json_object_new_array();
                if (NULL == arrobj) {
                    cli_errmsg("cli_magic_scan: no memory for json properties object\n");
                    ret = CL_EMEM;
                    cli_dbgmsg("cli_magic_scan: returning %d %s (no post, no cache)\n", ret, __AT__);
                    goto early_ret;
                }
                json_object_object_add(parent_property, "ContainedObjects", arrobj);
            }
            ctx->wrkproperty = json_object_new_object();
            if (NULL == ctx->wrkproperty) {
                cli_errmsg("cli_magic_scan: no memory for json properties object\n");
                ret = CL_EMEM;
                cli_dbgmsg("cli_magic_scan: returning %d %s (no post, no cache)\n", ret, __AT__);
                goto early_ret;
            }
            json_object_array_add(arrobj, ctx->wrkproperty);
        }

        if (ctx->fmap->name) {
            ret = cli_jsonstr(ctx->wrkproperty, "FileName", ctx->fmap->name);
            if (ret != CL_SUCCESS) {
                cli_dbgmsg("cli_magic_scan: returning %d %s (no post, no cache)\n", ret, __AT__);
                goto early_ret;
            }
        }
        if (ctx->sub_filepath) {
            ret = cli_jsonstr(ctx->wrkproperty, "FilePath", ctx->sub_filepath);
            if (ret != CL_SUCCESS) {
                cli_dbgmsg("cli_magic_scan: returning %d %s (no post, no cache)\n", ret, __AT__);
                goto early_ret;
            }
        }
        ret = cli_jsonstr(ctx->wrkproperty, "FileType", filetype);
        if (ret != CL_SUCCESS) {
            cli_dbgmsg("cli_magic_scan: returning %d %s (no post, no cache)\n", ret, __AT__);
            goto early_ret;
        }
        ret = cli_jsonint(ctx->wrkproperty, "FileSize", ctx->fmap->len);
        if (ret != CL_SUCCESS) {
            cli_dbgmsg("cli_magic_scan: returning %d %s (no post, no cache)\n", ret, __AT__);
            goto early_ret;
        }
    }
#endif

    /*
     * Run the pre_scan callback.
     */
    ret = dispatch_prescan_callback(ctx->engine->cb_pre_cache, ctx, filetype);
    if (CL_VERIFIED == ret || CL_VIRUS == ret) {
        goto done;
    }

    /*
     * Get the maphash
     */
    if (CL_SUCCESS != fmap_get_hash(ctx->fmap, &hash, CLI_HASH_MD5)) {
        cli_dbgmsg("cli_magic_scan: Failed to get a hash for the current fmap.\n");

        // It may be that the file was truncated between the time we started the scan and the time we got the hash.
        // Not a reason to print an error message.
        ret = CL_SUCCESS;
        goto done;
    }
    hashed_size = ctx->fmap->len;

    ret = dispatch_file_inspection_callback(ctx->engine->cb_file_inspection, ctx, filetype);
    if (CL_CLEAN != ret) {
        if (ret == CL_VIRUS) {
            ret = cli_check_fp(ctx, NULL);
        } else {
            ret = CL_CLEAN;
        }
        goto done;
    }

    /*
     * Check if we've already scanned this file before.
     */
    perf_start(ctx, PERFT_CACHE);
    cache_check_result = clean_cache_check(hash, hashed_size, ctx);
    perf_stop(ctx, PERFT_CACHE);

#if HAVE_JSON
    if (SCAN_COLLECT_METADATA) {
        char hashstr[CLI_HASHLEN_MD5 * 2 + 1];
        snprintf(hashstr, CLI_HASHLEN_MD5 * 2 + 1, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                 hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7],
                 hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15]);

        ret = cli_jsonstr(ctx->wrkproperty, "FileMD5", hashstr);
        if (ctx->engine->engine_options & ENGINE_OPTIONS_DISABLE_CACHE) {
            memset(hash, 0, CLI_HASHLEN_MD5);
        }
        if (ret != CL_SUCCESS) {
            cli_dbgmsg("cli_magic_scan: returning %d %s (no post, no cache)\n", ret, __AT__);
            goto early_ret;
        }
    }
#endif

    if (cache_check_result != CL_VIRUS) {
        cli_dbgmsg("cli_magic_scan: returning %d %s (no post, no cache)\n", ret, __AT__);
        ret = CL_SUCCESS;
        goto early_ret;
    }

    old_hook_lsig_matches  = ctx->hook_lsig_matches;
    ctx->hook_lsig_matches = NULL;

    /*
     * Run the pre_scan callback.
     */
    ret = dispatch_prescan_callback(ctx->engine->cb_pre_scan, ctx, filetype);
    if (CL_VERIFIED == ret || CL_VIRUS == ret) {
        goto done;
    }

    // If none of the scan options are enabled, then we can skip parsing and just do a raw pattern match.
    // For this check, we don't care if the CL_SCAN_GENERAL_ALLMATCHES option is enabled, hence the `~`.
    if (!((ctx->options->general & ~CL_SCAN_GENERAL_ALLMATCHES) || (ctx->options->parse) || (ctx->options->heuristic) || (ctx->options->mail) || (ctx->options->dev))) {
        /*
         * Scanning in raw mode (stdin, etc.)
         */
        ret = cli_scan_fmap(ctx, CL_TYPE_ANY, false, NULL, AC_SCAN_VIR, NULL, hash);
        // It doesn't matter what was returned, always go to the end after this. Raw mode! No parsing files!
        goto done;
    }

#ifdef HAVE__INTERNAL__SHA_COLLECT
    if (!ctx->sha_collect && type == CL_TYPE_MSEXE)
        ctx->sha_collect = 1;
#endif

    // We already saved the hook_lsig_matches (above)
    // The ctx one is NULL at present.
    ctx->hook_lsig_matches = cli_bitset_init();
    if (NULL == ctx->hook_lsig_matches) {
        ret = CL_EMEM;
        goto done;
    }

    if (type != CL_TYPE_IGNORED && ctx->engine->sdb) {
        /*
         * If self protection mechanism enabled, do the scanraw() scan first
         * before extracting with a file type parser.
         */
        ret = scanraw(ctx, type, 0, &dettype, (ctx->engine->engine_options & ENGINE_OPTIONS_DISABLE_CACHE) ? NULL : hash);

        // Evaluate the result from the scan to see if it end the scan of this layer early,
        // and to decid if we should propagate an error or not.
        if (result_should_goto_done(ctx, ret, &ret)) {
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
            if (have_rar && SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_RAR))
                ret = cli_scanrar(ctx);
            break;

        case CL_TYPE_EGG:
            if (SCAN_PARSE_ARCHIVE && (DCONF_ARCH & ARCH_CONF_EGG))
                ret = cli_scanegg(ctx);
            break;

        case CL_TYPE_OOXML_WORD:
        case CL_TYPE_OOXML_PPT:
        case CL_TYPE_OOXML_XL:
        case CL_TYPE_OOXML_HWP:
#if HAVE_JSON
            if (SCAN_PARSE_XMLDOCS && (DCONF_DOC & DOC_CONF_OOXML)) {
                if (SCAN_COLLECT_METADATA && (ctx->wrkproperty != NULL)) {
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
#endif
            /* fall-through */
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
            /*
             * This case is for unhandled graphics types such as BMP, JPEG 2000, etc.
             *
             * Note: JPEG 2000 is a very different format from JPEG, JPEG/JFIF, JPEG/Exif, JPEG/SPIFF (1994, 1997)
             * JPEG 2000 is not handled by cli_scanjpeg or cli_parsejpeg.
             */

            // It's okay if it fails to calculate the fuzzy hash.
            (void)calculate_fuzzy_image_hash(ctx, type);

            break;
        }

        case CL_TYPE_GIF: {
            if (SCAN_HEURISTICS && SCAN_HEURISTIC_BROKEN_MEDIA && (DCONF_OTHER & OTHER_CONF_GIF)) {
                ret = cli_parsegif(ctx);
            }

            if (CL_SUCCESS != ret) {
                // do not calculate the fuzzy image hash if parsing failed, or a heuristic alert occured.
                break;
            }

            // It's okay if it fails to calculate the fuzzy hash.
            (void)calculate_fuzzy_image_hash(ctx, type);

            break;
        }

        case CL_TYPE_PNG: {
            if (SCAN_HEURISTICS && (DCONF_OTHER & OTHER_CONF_PNG)) {
                ret = cli_parsepng(ctx); /* PNG parser detects a couple CVE's as well as Broken.Media */
            }

            if (CL_SUCCESS != ret) {
                // do not calculate the fuzzy image hash if parsing failed, or a heuristic alert occured.
                break;
            }

            // It's okay if it fails to calculate the fuzzy hash.
            (void)calculate_fuzzy_image_hash(ctx, type);

            break;
        }

        case CL_TYPE_JPEG: {
            if (SCAN_HEURISTICS && (DCONF_OTHER & OTHER_CONF_JPEG)) {
                ret = cli_parsejpeg(ctx); /* JPG parser detects MS04-028 exploits as well as Broken.Media */
            }

            if (CL_SUCCESS != ret) {
                // do not calculate the fuzzy image hash if parsing failed, or a heuristic alert occured.
                break;
            }

            // It's okay if it fails to calculate the fuzzy hash.
            (void)calculate_fuzzy_image_hash(ctx, type);

            break;
        }

        case CL_TYPE_TIFF: {
            if (SCAN_HEURISTICS && SCAN_HEURISTIC_BROKEN_MEDIA && (DCONF_OTHER & OTHER_CONF_TIFF) && ret != CL_VIRUS) {
                ret = cli_parsetiff(ctx);
            }

            if (CL_SUCCESS != ret) {
                // do not calculate the fuzzy image hash if parsing failed, or a heuristic alert occured.
                break;
            }

            // It's okay if it fails to calculate the fuzzy hash.
            (void)calculate_fuzzy_image_hash(ctx, type);

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

    // Evaluate the result from the parsers to see if it end the scan of this layer early,
    // and to decid if we should propagate an error or not.
    if (result_should_goto_done(ctx, ret, &ret)) {
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

    /* CL_TYPE_HTML: raw HTML files are not scanned, unless safety measure activated via DCONF */
    if (type != CL_TYPE_IGNORED && (type != CL_TYPE_HTML || !(SCAN_PARSE_HTML) || !(DCONF_DOC & DOC_CONF_HTML_SKIPRAW)) && !ctx->engine->sdb) {
        ret = scanraw(ctx, type, typercg, &dettype, (ctx->engine->engine_options & ENGINE_OPTIONS_DISABLE_CACHE) ? NULL : hash);

        // Evaluate the result from the scan to see if it end the scan of this layer early,
        // and to decid if we should propagate an error or not.
        if (result_should_goto_done(ctx, ret, &ret)) {
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
                ret = cli_scan_fmap(ctx, CL_TYPE_MAIL, false, NULL, AC_SCAN_VIR, NULL, NULL);
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

        case CL_TYPE_BINARY_DATA:
            ret = cli_scan_fmap(ctx, CL_TYPE_OTHER, false, NULL, AC_SCAN_VIR, NULL, NULL);
            break;

        case CL_TYPE_PDF: /* FIXMELIMITS: pdf should be an archive! */
            if (SCAN_PARSE_PDF && (DCONF_DOC & DOC_CONF_PDF))
                ret = cli_scanpdf(ctx, 0);
            break;

        default:
            break;
    }

done:
    // Filter the result from the parsers so we don't propagate non-fatal errors.
    // And to convert CL_VERIFIED -> CL_CLEAN
    (void)result_should_goto_done(ctx, ret, &ret);

    if (old_hook_lsig_matches) {
        /* We need to restore the old hook_lsig_matches */
        cli_bitset_free(ctx->hook_lsig_matches); // safe to call, even if NULL
        ctx->hook_lsig_matches = old_hook_lsig_matches;
    }

#if HAVE_JSON
    ctx->wrkproperty = (struct json_object *)(parent_property);
#endif

    /*
     * Determine if there was an alert for this layer (or its children).
     */
    if ((evidence_num_alerts(ctx->evidence) > 0)) {
        // TODO: Bug here.
        //       If there was a PUA match in a previous file in a zip, all subsequent files will
        //       think they have a match.
        //       In allmatch mode, this affects strong sigs too, not just PUA sigs.
        //       The only way to solve this is to keep track of the # of alerts for each layer,
        //       including only children layers and propagating the evidence up to the parent layer
        //       only at the end, after the cache_add.
        verdict_at_this_level = CL_VIRUS;
    } else {
        verdict_at_this_level = ret;
    }

    /*
     * Run the post-scan callback (if one exists) and provide the verdict for this layer.
     */
    cli_dbgmsg("cli_magic_scan: returning %d %s\n", ret, __AT__);
    if (ctx->engine->cb_post_scan) {
        cl_error_t callback_ret;
        const char *virusname = NULL;

        // Get the last signature that matched (if any).
        if (verdict_at_this_level == CL_VIRUS) {
            virusname = cli_get_last_virus(ctx);
        }

        perf_start(ctx, PERFT_POSTCB);
        callback_ret = ctx->engine->cb_post_scan(fmap_fd(ctx->fmap), verdict_at_this_level, virusname, ctx->cb_ctx);
        perf_stop(ctx, PERFT_POSTCB);

        switch (callback_ret) {
            case CL_BREAK:
                cli_dbgmsg("cli_magic_scan: file allowed by post_scan callback\n");
                ret = CL_CLEAN;
                break;
            case CL_VIRUS:
                cli_dbgmsg("cli_magic_scan: file blocked by post_scan callback\n");
                callback_ret = cli_append_virus(ctx, "Detected.By.Callback");
                if (callback_ret == CL_VIRUS) {
                    ret = CL_VIRUS;
                }
                break;
            case CL_CLEAN:
                break;
            default:
                ret = CL_CLEAN;
                cli_warnmsg("cli_magic_scan: ignoring bad return code from post_scan callback\n");
        }
    }

    /*
     * If the verdict for this layer is "clean", we can cache it.
     */
    if (verdict_at_this_level == CL_CLEAN) {
        // clean_cache_add() will check the fmap->dont_cache_flag,
        // so this may not actually cache if we exceeded limits earlier.
        perf_start(ctx, PERFT_CACHE);
        clean_cache_add(hash, hashed_size, ctx);
        perf_stop(ctx, PERFT_CACHE);
    }

early_ret:

    if ((ctx->engine->keeptmp) && (NULL != old_temp_path)) {
        /* Use rmdir to remove empty tmp subdirectories. If rmdir fails, it wasn't empty. */
        (void)rmdir(ctx->sub_tmpdir);

        free((void *)ctx->sub_tmpdir);
        ctx->sub_tmpdir = old_temp_path;
    }

#if HAVE_JSON
    if (NULL != parent_property) {
        ctx->wrkproperty = (struct json_object *)(parent_property);
    }
#endif

    return ret;
}

cl_error_t cli_magic_scan_desc_type(int desc, const char *filepath, cli_ctx *ctx, cli_file_t type,
                                    const char *name, uint32_t attributes)
{
    STATBUF sb;
    cl_error_t status = CL_CLEAN;
    fmap_t *new_map   = NULL;

    if (!ctx) {
        return CL_EARG;
    }

    const char *parent_filepath = ctx->sub_filepath;
    ctx->sub_filepath           = filepath;

#ifdef HAVE__INTERNAL__SHA_COLLECT
    if (ctx->sha_collect > 0)
        ctx->sha_collect = 0;
#endif

    cli_dbgmsg("in cli_magic_scan_desc_type (recursion_level: %u/%u)\n", ctx->recursion_level, ctx->engine->max_recursion_level);

    if (FSTAT(desc, &sb) == -1) {
        cli_errmsg("cli_magic_scan_desc_type: Can't fstat descriptor %d\n", desc);

        status = CL_ESTAT;
        cli_dbgmsg("cli_magic_scan_desc_type: returning %d %s (no post, no cache)\n", status, __AT__);
        goto done;
    }
    if (sb.st_size <= 5) {
        cli_dbgmsg("Small data (%u bytes)\n", (unsigned int)sb.st_size);

        status = CL_CLEAN;
        cli_dbgmsg("cli_magic_scan_desc_type: returning %d %s (no post, no cache)\n", status, __AT__);
        goto done;
    }

    perf_start(ctx, PERFT_MAP);
    new_map = fmap(desc, 0, sb.st_size, name);
    perf_stop(ctx, PERFT_MAP);
    if (NULL == new_map) {
        cli_errmsg("CRITICAL: fmap() failed\n");
        status = CL_EMEM;
        cli_dbgmsg("cli_magic_scan_desc_type: returning %d %s (no post, no cache)\n", status, __AT__);
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
        funmap(new_map);
    }

    ctx->sub_filepath = parent_filepath;

    return status;
}

cl_error_t cli_magic_scan_desc(int desc, const char *filepath, cli_ctx *ctx, const char *name, uint32_t attributes)
{
    return cli_magic_scan_desc_type(desc, filepath, ctx, CL_TYPE_ANY, name, attributes);
}

cl_error_t cl_scandesc(int desc, const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, struct cl_scan_options *scanoptions)
{
    return cl_scandesc_callback(desc, filename, virname, scanned, engine, scanoptions, NULL);
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
    cl_error_t status = CL_CLEAN;
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
    cl_error_t ret = CL_CLEAN;

    cli_dbgmsg("cli_magic_scan_nested_fmap_type: [%zu, +%zu)\n", offset, length);
    if (offset >= map->len) {
        cli_dbgmsg("Invalid offset: %zu\n", offset);
        return CL_CLEAN;
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
            return CL_CLEAN;
        }
        if (!CLI_ISCONTAINED_0_TO(map->len, offset, length)) {
            cli_dbgmsg("cli_magic_scan_nested_fmap_type: map error occurred [%zu, %zu] not within [0, %zu]\n", offset, length, map->len);
            return CL_CLEAN;
        }

        /* Length checked, now get map */
        mapdata = fmap_need_off_once_len(map, offset, length, &nread);
        if (!mapdata || (nread != length)) {
            cli_errmsg("cli_magic_scan_nested_fmap_type: could not map sub-file\n");
            return CL_EMAP;
        }

        ret = cli_gentempfd(ctx->sub_tmpdir, &tempfile, &fd);
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

    funmap(map);

    return ret;
}

/**
 * @brief   The main function to initiate a scan of an fmap.
 *
 * @param map               File map.
 * @param filepath          (optional, recommended) filepath of the open file descriptor or file map.
 * @param[out] virname      Will be set to a statically allocated (i.e. needs not be freed) signature name if the scan matches against a signature.
 * @param[out] scanned      The number of bytes scanned.
 * @param engine            The scanning engine.
 * @param scanoptions       Scanning options.
 * @param[in,out] context   An opaque context structure allowing the caller to record details about the sample being scanned.
 * @return int              CL_CLEAN, CL_VIRUS, or an error code if an error occured during the scan.
 */
static cl_error_t scan_common(cl_fmap_t *map, const char *filepath, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, struct cl_scan_options *scanoptions, void *context)
{
    cl_error_t status = CL_SUCCESS;
    cl_error_t ret;
    cl_error_t verdict = CL_CLEAN;

    cli_ctx ctx = {0};

    bool logg_initalized = false;

    char *target_basename = NULL;
    char *new_temp_prefix = NULL;
    size_t new_temp_prefix_len;
    char *new_temp_path = NULL;

    time_t current_time;
    struct tm tm_struct;

    if (NULL == map || NULL == scanoptions) {
        return CL_ENULLARG;
    }

    size_t num_potentially_unwanted_indicators = 0;

    *virname = NULL;

    ctx.engine  = engine;
    ctx.scanned = scanned;
    MALLOC(ctx.options, sizeof(struct cl_scan_options), status = CL_EMEM);

    memcpy(ctx.options, scanoptions, sizeof(struct cl_scan_options));

    ctx.evidence = evidence_new();

    ctx.dconf  = (struct cli_dconf *)engine->dconf;
    ctx.cb_ctx = context;

    if (!(ctx.hook_lsig_matches = cli_bitset_init())) {
        status = CL_EMEM;
        goto done;
    }

    ctx.recursion_stack_size = ctx.engine->max_recursion_level;
    ctx.recursion_stack      = cli_calloc(sizeof(recursion_level_t), ctx.recursion_stack_size);
    if (!ctx.recursion_stack) {
        status = CL_EMEM;
        goto done;
    }

    // ctx was memset, so recursion_level starts at 0.
    ctx.recursion_stack[ctx.recursion_level].fmap = map;
    ctx.recursion_stack[ctx.recursion_level].type = CL_TYPE_ANY; // ANY for the top level, because we don't yet know the type.
    ctx.recursion_stack[ctx.recursion_level].size = map->len;

    ctx.fmap = ctx.recursion_stack[ctx.recursion_level].fmap;

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

    if ((ctx.engine->keeptmp) &&
        (NULL != ctx.target_filepath) &&
        (CL_SUCCESS == cli_basename(ctx.target_filepath, strlen(ctx.target_filepath), &target_basename))) {
        /* Include the basename in the temp directory */
        new_temp_prefix_len = strlen("YYYYMMDD_HHMMSS-") + strlen(target_basename);
        new_temp_prefix     = cli_calloc(1, new_temp_prefix_len + 1);
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
        new_temp_prefix     = cli_calloc(1, new_temp_prefix_len + 1);
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

    ctx.sub_tmpdir = new_temp_path;

    if (mkdir(ctx.sub_tmpdir, 0700)) {
        cli_errmsg("Can't create temporary directory for scan: %s.\n", ctx.sub_tmpdir);
        status = CL_EACCES;
        goto done;
    }

    cli_logg_setup(&ctx);
    logg_initalized = true;

    /* We have a limit of around 2GB (INT_MAX - 2). Enforce it here. */
    /* TODO: Large file support is large-ly untested. Remove this restriction
     * and test with a large set of large files of various types. libclamav's
     * integer type safety has come a long way since 2014, so it's possible
     * we could lift this restriction, but at least one of the parsers is
     * bound to behave badly with large files. */
    if (map->len > INT_MAX - 2) {
        if (scanoptions->heuristic & CL_SCAN_HEURISTIC_EXCEEDS_MAX) {
            status = cli_append_potentially_unwanted(&ctx, "Heuristics.Limits.Exceeded.MaxFileSize");
        } else {
            status = CL_CLEAN;
        }
        goto done;
    }

    status = cli_magic_scan(&ctx, CL_TYPE_ANY);

#if HAVE_JSON
    if (ctx.options->general & CL_SCAN_GENERAL_COLLECT_METADATA && (ctx.properties != NULL)) {
        json_object *jobj;
        const char *jstring;

        /* set value of unique root object tag */
        if (json_object_object_get_ex(ctx.properties, "FileType", &jobj)) {
            enum json_type type;
            const char *jstr;

            type = json_object_get_type(jobj);
            if (type == json_type_string) {
                jstr = json_object_get_string(jobj);
                cli_jsonstr(ctx.properties, "RootFileType", jstr);
            }
        }

        /* serialize json properties to string */
#ifdef JSON_C_TO_STRING_NOSLASHESCAPE
        jstring = json_object_to_json_string_ext(ctx.properties, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE);
#else
        jstring = json_object_to_json_string_ext(ctx.properties, JSON_C_TO_STRING_PRETTY);
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
            if (status != CL_VIRUS && (iroot->ac_lsigs || iroot->ac_patterns
#ifdef HAVE_PCRE
                                       || iroot->pcre_metas
#endif // HAVE_PCRE
                                       )) {
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
         * Write the file properties metadata JSON to metadata.json if keeptmp is enabled.
         */
        if (ctx.engine->keeptmp) {
            int fd        = -1;
            char *tmpname = NULL;

            if ((ret = cli_newfilepathfd(ctx.sub_tmpdir, "metadata.json", &tmpname, &fd)) != CL_SUCCESS) {
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
#endif // HAVE_JSON

    // If any alerts occurred, set the output pointer to the "latest" alert signature name.
    if (0 < evidence_num_alerts(ctx.evidence)) {
        *virname = cli_get_last_virus_str(&ctx);
        verdict  = CL_VIRUS;
    }

    /*
     * Report PUA alerts here.
     */
    num_potentially_unwanted_indicators = evidence_num_indicators_type(
        ctx.evidence,
        IndicatorType_PotentiallyUnwanted);
    if (0 != num_potentially_unwanted_indicators) {
        // We have "potentially unwanted" indicators that would not have been reported yet.
        // We may wish to report them now, ... depending ....

        if (ctx.options->general & CL_SCAN_GENERAL_ALLMATCHES) {
            // We're in allmatch mode, so report all "potentially unwanted" matches now.

            size_t i;

            for (i = 0; i < num_potentially_unwanted_indicators; i++) {
                const char *pua_alert = evidence_get_indicator(
                    ctx.evidence,
                    IndicatorType_PotentiallyUnwanted,
                    i);

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
            if (0 == evidence_num_indicators_type(ctx.evidence, IndicatorType_Strong)) {
                // And it looks like we haven't reported anything else, so report the last "potentially unwanted" one.
                cli_virus_found_cb(&ctx, cli_get_last_virus(&ctx));
            }
        }
    }

    if (verdict != CL_CLEAN) {
        // Reporting "VIRUS" is more important than reporting and error,
        // because... unfortunately we can only do one with the current API.
        status = verdict;
    }

done:
    // Filter the result from the post-scan hooks and stuff, so we don't propagate non-fatal errors.
    // And to convert CL_VERIFIED -> CL_CLEAN
    (void)result_should_goto_done(&ctx, status, &status);

    if (logg_initalized) {
        cli_logg_unsetup();
    }

    if (NULL != ctx.properties) {
        cli_json_delobj(ctx.properties);
    }

    if (NULL != ctx.sub_tmpdir) {
        if (!ctx.engine->keeptmp) {
            (void)cli_rmdirs(ctx.sub_tmpdir);
        }
        free(ctx.sub_tmpdir);
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
        free(ctx.recursion_stack);
    }

    if (NULL != ctx.options) {
        free(ctx.options);
    }

    if (NULL != ctx.evidence) {
        evidence_free(ctx.evidence);
    }

    return status;
}

cl_error_t cl_scandesc_callback(int desc, const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, struct cl_scan_options *scanoptions, void *context)
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
        status = CL_CLEAN;
        goto done;
    }
    if ((engine->maxfilesize > 0) && ((uint64_t)sb.st_size > engine->maxfilesize)) {
        cli_dbgmsg("cl_scandesc_callback: File too large (" STDu64 " bytes), ignoring\n", (uint64_t)sb.st_size);
        if (scanoptions->heuristic & CL_SCAN_HEURISTIC_EXCEEDS_MAX) {
            if (engine->cb_virus_found)
                engine->cb_virus_found(desc, "Heuristics.Limits.Exceeded.MaxFileSize", context);
            status = CL_VIRUS;
        } else {
            status = CL_CLEAN;
        }
        goto done;
    }

    if (NULL != filename) {
        (void)cli_basename(filename, strlen(filename), &filename_base);
    }

    if (NULL == (map = fmap(desc, 0, sb.st_size, filename_base))) {
        cli_errmsg("CRITICAL: fmap() failed\n");
        status = CL_EMEM;
        goto done;
    }

    status = scan_common(map, filename, virname, scanned, engine, scanoptions, context);

done:
    if (NULL != map) {
        funmap(map);
    }
    if (NULL != filename_base) {
        free(filename_base);
    }

    return status;
}

cl_error_t cl_scanmap_callback(cl_fmap_t *map, const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, struct cl_scan_options *scanoptions, void *context)
{
    if ((engine->maxfilesize > 0) && (map->len > engine->maxfilesize)) {
        cli_dbgmsg("cl_scandesc_callback: File too large (%zu bytes), ignoring\n", map->len);
        if (scanoptions->heuristic & CL_SCAN_HEURISTIC_EXCEEDS_MAX) {
            if (engine->cb_virus_found)
                engine->cb_virus_found(fmap_fd(map), "Heuristics.Limits.Exceeded.MaxFileSize", context);
            return CL_VIRUS;
        }
        return CL_CLEAN;
    }

    if (NULL != filename && map->name == NULL) {
        // Use the provided name for the fmap name if one wasn't already set.
        cli_basename(filename, strlen(filename), &map->name);
    }

    return scan_common(map, filename, virname, scanned, engine, scanoptions, context);
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

cl_error_t cl_scanfile(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, struct cl_scan_options *scanoptions)
{
    return cl_scanfile_callback(filename, virname, scanned, engine, scanoptions, NULL);
}

cl_error_t cl_scanfile_callback(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, struct cl_scan_options *scanoptions, void *context)
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

    ret = cl_scandesc_callback(fd, filename, virname, scanned, engine, scanoptions, context);
    close(fd);

    return ret;
}

/*
Local Variables:
   c-basic-offset: 4
End:
*/
