/*
 *  Extract VBA source code for component MS Office Documents
 *
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Trog, Nigel Horne
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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <stdlib.h>
#include <ctype.h>

#include <zlib.h>
#include <json.h>

#include "clamav.h"

#include "others.h"
#include "scanners.h"
#include "vba_extract.h"
#ifdef CL_DEBUG
#include "mbox.h"
#endif
#include "blob.h"
#include "ole2_extract.h"
#include "entconv.h"

#define PPT_LZW_BUFFSIZE 8192
#define VBA_COMPRESSION_WINDOW 4096
#define MIDDLE_SIZE 20
#define MAX_VBA_COUNT 1000 /* If there's more than 1000 macros something's up! */

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif

/*
 * VBA (Visual Basic for Applications), versions 5 and 6
 */
struct vba56_header {
    unsigned char magic[2];
    unsigned char version[4];
    unsigned char ignore[28];
};

typedef struct {
    uint32_t sig;
    const char *ver;
    int big_endian; /* e.g. MAC Office */
} vba_version_t;

static int skip_past_nul(int fd);
static int read_uint16(int fd, uint16_t *u, int big_endian);
static int read_uint32(int fd, uint32_t *u, int big_endian);
static int seekandread(int fd, off_t offset, int whence, void *data, size_t len);
static vba_project_t *create_vba_project(int record_count, const char *dir, struct uniq *U);

static uint16_t
vba_endian_convert_16(uint16_t value, int big_endian)
{
    if (big_endian)
        return (uint16_t)be16_to_host(value);
    else
        return le16_to_host(value);
}

/* Seems to be a duplicate of riff_endian_convert_32() */
static uint32_t
vba_endian_convert_32(uint32_t value, int big_endian)
{
    if (big_endian)
        return be32_to_host(value);
    else
        return le32_to_host(value);
}

static char *
get_unicode_name(const char *name, int size, int big_endian)
{
    int i, increment;
    char *newname, *ret;

    if ((name == NULL) || (*name == '\0') || (size <= 0))
        return NULL;

    newname = (char *)cli_max_malloc(size * 7 + 1);
    if (newname == NULL) {
        cli_errmsg("get_unicode_name: Unable to allocate memory for newname\n");
        return NULL;
    }

    if ((!big_endian) && (size & 0x1)) {
        cli_dbgmsg("get_unicode_name: odd number of bytes %d\n", size);
        --size;
    }

    increment = (big_endian) ? 1 : 2;
    ret       = newname;

    for (i = 0; i < size; i += increment) {
        if ((!(name[i] & 0x80)) && isprint(name[i])) {
            *ret++ = tolower(name[i]);
        } else {
            if ((name[i] < 10) && (name[i] >= 0)) {
                *ret++ = '_';
                *ret++ = (char)(name[i] + '0');
            } else {
                uint16_t x;
                if ((i + 1) >= size)
                    break;
                x = (uint16_t)((name[i] < 0 ? 0 : name[i] << 8) | name[i + 1]);

                *ret++ = '_';
                *ret++ = (char)('a' + ((x & 0xF)));
                *ret++ = (char)('a' + ((x >> 4) & 0xF));
                *ret++ = (char)('a' + ((x >> 8) & 0xF));
                *ret++ = 'a';
                *ret++ = 'a';
            }
            *ret++ = '_';
        }
    }

    *ret = '\0';

    /* Saves a lot of memory */
    ret = cli_max_realloc(newname, (ret - newname) + 1);
    return ret ? ret : newname;
}

static void vba56_test_middle(int fd)
{
    char test_middle[MIDDLE_SIZE];

    /* MacOffice middle */
    static const uint8_t middle1_str[MIDDLE_SIZE] = {
        0x00, 0x01, 0x0d, 0x45, 0x2e, 0xe1, 0xe0, 0x8f, 0x10, 0x1a,
        0x85, 0x2e, 0x02, 0x60, 0x8c, 0x4d, 0x0b, 0xb4, 0x00, 0x00};
    /* MS Office middle */
    static const uint8_t middle2_str[MIDDLE_SIZE] = {
        0x00, 0x00, 0xe1, 0x2e, 0x45, 0x0d, 0x8f, 0xe0, 0x1a, 0x10,
        0x85, 0x2e, 0x02, 0x60, 0x8c, 0x4d, 0x0b, 0xb4, 0x00, 0x00};

    if (cli_readn(fd, &test_middle, MIDDLE_SIZE) != MIDDLE_SIZE)
        return;

    if ((memcmp(test_middle, middle1_str, MIDDLE_SIZE) != 0) &&
        (memcmp(test_middle, middle2_str, MIDDLE_SIZE) != 0)) {
        cli_dbgmsg("middle not found\n");
        if (lseek(fd, -MIDDLE_SIZE, SEEK_CUR) == -1) {
            cli_dbgmsg("vba_test_middle: call to lseek() failed\n");
            return;
        }
    } else
        cli_dbgmsg("middle found\n");
}

/* return count of valid strings found, 0 on error */
static int
vba_read_project_strings(int fd, int big_endian)
{
    unsigned char *buf = NULL;
    uint16_t buflen    = 0;
    uint16_t length    = 0;
    int ret = 0, getnewlength = 1;

    for (;;) {
        off_t offset;
        char *name;

        /* if no initial name length, exit */
        if (getnewlength && !read_uint16(fd, &length, big_endian)) {
            ret = 0;
            break;
        }
        getnewlength = 0;

        /* if too short, break */
        if (length < 6) {
            if (lseek(fd, -2, SEEK_CUR) == -1) {
                cli_dbgmsg("vba_read_project_strings: call to lseek() has failed\n");
                ret = 0;
            }
            break;
        }
        /* ensure buffer is large enough */
        if (length > buflen) {
            unsigned char *newbuf = (unsigned char *)cli_max_realloc(buf, length);
            if (newbuf == NULL) {
                ret = 0;
                break;
            }
            buflen = length;
            buf    = newbuf;
        }

        /* save current offset */
        offset = lseek(fd, 0, SEEK_CUR);
        if (offset == -1) {
            cli_dbgmsg("vba_read_project_strings: call to lseek() has failed\n");
            ret = 0;
            break;
        }

        /* if read name failed, break */
        if (cli_readn(fd, buf, (size_t)length) != (size_t)length) {
            cli_dbgmsg("read name failed - rewinding\n");
            if (lseek(fd, offset, SEEK_SET) == -1) {
                cli_dbgmsg("call to lseek() in read name failed\n");
                ret = 0;
            }
            break;
        }
        name = get_unicode_name((const char *)buf, length, big_endian);
        cli_dbgmsg("length: %d, name: %s\n", length, (name) ? name : "[null]");

        /* if invalid name, break */
        if ((name == NULL) || (memcmp("*\\", name, 2) != 0) ||
            (strchr("ghcd", name[2]) == NULL)) {
            /* Not a valid string, rewind */
            if (lseek(fd, -(length + 2), SEEK_CUR) == -1) {
                cli_dbgmsg("call to lseek() after get_unicode_name has failed\n");
                ret = 0;
            }
            free(name);
            break;
        }
        free(name);

        /* can't get length, break */
        if (!read_uint16(fd, &length, big_endian)) {
            break;
        }

        ret++;

        /* continue on reasonable length value */
        if ((length != 0) && (length != 65535)) {
            continue;
        }

        /* determine offset and run middle test */
        offset = lseek(fd, 10, SEEK_CUR);
        if (offset == -1) {
            cli_dbgmsg("call to lseek() has failed\n");
            ret = 0;
            break;
        }
        cli_dbgmsg("offset: %lu\n", (unsigned long)offset);
        vba56_test_middle(fd);
        getnewlength = 1;
    }

    free(buf);
    return ret;
}

static size_t vba_normalize(unsigned char *buffer, size_t size)
{
    enum {
        NORMAL        = 0,
        IN_STRING     = 1,
        UNDERSCORE    = 2,
        UNDERSCORE_CR = 3,
        SPACE         = 5,
    } state  = NORMAL;
    size_t o = 0;
    size_t i;
    for (i = 0; i < size; ++i) {
        // TODO: Don't normalize stuff in comments
        // FIXME: Use UTF glyphs instead of raw bytes
        switch (buffer[i]) {
            case '"':
                if (state == IN_STRING) {
                    state = NORMAL;
                } else if (state == NORMAL || state == UNDERSCORE || state == SPACE) {
                    state = IN_STRING;
                }
                buffer[o++] = '"';
                break;
            case '_':
                if (state == SPACE) {
                    state = UNDERSCORE;
                }
                buffer[o++] = '_';
                break;
            case '\r':
                if (state == UNDERSCORE) {
                    state = UNDERSCORE_CR;
                }
                buffer[o++] = '\r';
                break;
            case '\n':
                if (state == UNDERSCORE) {
                    o -= 1;
                    state = SPACE;
                } else if (state == UNDERSCORE_CR) {
                    o -= 2;
                    state = SPACE;
                } else {
                    buffer[o++] = '\n';
                    ;
                }
                break;
            case '\t':
            case ' ':
                if (state != SPACE) {
                    buffer[o++] = ' ';
                }
                if (state == NORMAL || state == UNDERSCORE) {
                    state = SPACE;
                }
                break;
            default:
                if (state == NORMAL || state == UNDERSCORE || state == SPACE) {
                    if (buffer[i] >= 'A' && buffer[i] <= 'Z') {
                        buffer[o++] = (unsigned char)tolower((int)buffer[i]);
                    } else {
                        buffer[o++] = buffer[i];
                    }
                    state = NORMAL;
                } else {
                    buffer[o++] = buffer[i];
                }
                break;
        }
    }
    return o;
}

/**
 * Read a VBA project in an OLE directory.
 * Contrary to cli_vba_readdir, this function uses the dir file to locate VBA modules.
 */
cl_error_t cli_vba_readdir_new(cli_ctx *ctx, const char *dir, struct uniq *U, const char *hash, uint32_t which, int *tempfd, int *has_macros, char **tempfile)
{
    cl_error_t ret = CL_SUCCESS;
    char fullname[1024];
    int fd              = -1;
    unsigned char *data = NULL;
    size_t data_len;
    size_t data_offset;
    const char *stream_name = NULL;
    uint16_t codepage       = CODEPAGE_ISO8859_1;
    unsigned i;
    char *mbcs_name = NULL, *utf16_name = NULL;
    size_t mbcs_name_size = 0, utf16_name_size = 0;
    unsigned char *module_data = NULL, *module_data_utf8 = NULL;
    size_t module_data_size = 0, module_data_utf8_size = 0;

    if (dir == NULL || hash == NULL || tempfd == NULL || has_macros == NULL || tempfile == NULL) {
        return CL_EARG;
    }

    cli_dbgmsg("vba_readdir_new: Scanning directory %s for VBA project\n", dir);

    snprintf(fullname, sizeof(fullname), "%s" PATHSEP "%s_%u", dir, hash, which);
    fullname[sizeof(fullname) - 1] = '\0';
    fd                             = open(fullname, O_RDONLY | O_BINARY);

    if (fd == -1) {
        ret = CL_EOPEN;
        goto done;
    }

    if ((data = cli_vba_inflate(fd, 0, &data_len)) == NULL) {
        cli_dbgmsg("vba_readdir_new: Failed to decompress 'dir'\n");
        ret = CL_EARG;
        goto done;
    }

    *has_macros = *has_macros + 1;

    if ((ret = cli_gentempfd_with_prefix(ctx->this_layer_tmpdir, "vba_project", tempfile, tempfd)) != CL_SUCCESS) {
        cli_warnmsg("vba_readdir_new: VBA project cannot be dumped to file\n");
        goto done;
    }

    cli_dbgmsg("Dumping VBA project from dir %s to file %s\n", fullname, *tempfile);

#define CLI_WRITEN(msg, size)                                                 \
    do {                                                                      \
        if (cli_writen(*tempfd, msg, size) != size) {                         \
            cli_warnmsg("vba_readdir_new: Failed to write to output file\n"); \
            ret = CL_EWRITE;                                                  \
            goto done;                                                        \
        }                                                                     \
    } while (0)

#define CLI_WRITENHEX(msg, size)                                                           \
    do {                                                                                   \
        unsigned i;                                                                        \
        for (i = 0; i < size; ++i) {                                                       \
            char buf[4];                                                                   \
            if (snprintf(buf, sizeof(buf), "%02x", (msg)[i]) != 2) {                       \
                cli_warnmsg("vba_readdir_new: Failed to write hex data to output file\n"); \
                ret = CL_EWRITE;                                                           \
                goto done;                                                                 \
            }                                                                              \
            CLI_WRITEN(buf, 2);                                                            \
        }                                                                                  \
    } while (0)

#define CLI_WRITEN_MBCS(msg, size)                                                                                   \
    do {                                                                                                             \
        char *utf8 = NULL;                                                                                           \
        size_t utf8_size;                                                                                            \
        if (size > 0) {                                                                                              \
            if (CL_SUCCESS == cli_codepage_to_utf8((char *)&data[data_offset], size, codepage, &utf8, &utf8_size)) { \
                CLI_WRITEN(utf8, utf8_size);                                                                         \
                free(utf8);                                                                                          \
                utf8 = NULL;                                                                                         \
            } else {                                                                                                 \
                cli_dbgmsg("cli_vba_readdir_new: failed to convert codepage %" PRIu16 " to UTF-8\n", codepage);      \
                CLI_WRITEN("<error decoding string>", 23);                                                           \
            }                                                                                                        \
        }                                                                                                            \
    } while (0)

#define CLI_WRITEN_UTF16LE(msg, size)                                                                                         \
    do {                                                                                                                      \
        char *utf8 = NULL;                                                                                                    \
        size_t utf8_size;                                                                                                     \
        if (size > 0) {                                                                                                       \
            if (CL_SUCCESS == cli_codepage_to_utf8((char *)&data[data_offset], size, CODEPAGE_UTF16_LE, &utf8, &utf8_size)) { \
                CLI_WRITEN(utf8, utf8_size);                                                                                  \
                free(utf8);                                                                                                   \
                utf8 = NULL;                                                                                                  \
            } else {                                                                                                          \
                cli_dbgmsg("cli_vba_readdir_new: failed to convert UTF16LE to UTF-8\n");                                      \
                CLI_WRITEN("<error decoding string>", 23);                                                                    \
            }                                                                                                                 \
        }                                                                                                                     \
    } while (0)

    CLI_WRITEN("REM VBA project extracted from Microsoft Office document\n\n", 58);

    for (data_offset = 0; data_offset < data_len;) {
        uint16_t id, val16;
        uint32_t size, val32;

        if (sizeof(uint16_t) > data_len - data_offset) {
            cli_warnmsg("vba_readdir_new: Failed to read record type from dir\n");
            ret = CL_EREAD;
            goto done;
        }
        memcpy(&val16, &data[data_offset], sizeof(uint16_t));
        id = le16_to_host(val16);
        data_offset += sizeof(uint16_t);

        if (sizeof(uint32_t) > data_len - data_offset) {
            cli_warnmsg("vba_readdir_new: Failed to read record size from dir\n");
            ret = CL_EREAD;
            goto done;
        }
        memcpy(&val32, &data[data_offset], sizeof(uint32_t));
        size = le32_to_host(val32);
        data_offset += sizeof(uint32_t);

        if (size > data_len - data_offset) {
            cli_warnmsg("vba_readdir_new: Record stretches past the end of the file\n");
            ret = CL_EREAD;
            goto done;
        }

        switch (id) {
            // MS-OVBA 2.3.4.2.1.1 PROJECTSYSKIND
            case 0x0001: {
                if (size != sizeof(uint32_t)) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTSYSKIND record size (%" PRIu32 " != 4)\n", size);
                    ret = CL_EREAD;
                    goto done;
                }
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                uint32_t sys_kind = le32_to_host(val32);
                data_offset += sizeof(uint32_t);
                CLI_WRITEN("REM PROJECTSYSKIND: ", 20);
                switch (sys_kind) {
                    case 0x0:
                        CLI_WRITEN("Windows 16 bit", 14);
                        break;
                    case 0x1:
                        CLI_WRITEN("Windows 32 bit", 14);
                        break;
                    case 0x2:
                        CLI_WRITEN("Macintosh", 9);
                        break;
                    case 0x3:
                        CLI_WRITEN("Windows 64 bit", 14);
                        break;
                    default: {
                        char str_sys_kind[22];
                        int len                                = snprintf(str_sys_kind, sizeof(str_sys_kind), "Unknown (0x%x)", sys_kind);
                        str_sys_kind[sizeof(str_sys_kind) - 1] = '\0';
                        if (len > 0) {
                            CLI_WRITEN(str_sys_kind, (size_t)len);
                        }
                        break;
                    }
                }
                CLI_WRITEN("\n", 1);
                break;
            }
            // MS-OVBA 2.3.4.2.1.2 PROJECTLCID
            case 0x0002: {
                if (size != sizeof(uint32_t)) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTLCID record size (%" PRIu32 " != 4)\n", size);
                    ret = CL_EREAD;
                    goto done;
                }
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                uint32_t lcid = le32_to_host(val32);
                char buf[64];
                data_offset += size;
                int buf_length       = snprintf(buf, sizeof(buf), "REM PROJECTLCID: 0x%08x\n", lcid);
                buf[sizeof(buf) - 1] = '\0';
                if (buf_length > 0) {
                    CLI_WRITEN(buf, (size_t)buf_length);
                }
                break;
            }
            // MS-OVBA 2.3.4.2.1.3 PROJECTLCIDINVOKE
            case 0x0014: {
                if (size != sizeof(uint32_t)) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTLCIDINVOKE record size (%" PRIu32 " != 4)\n", size);
                    ret = CL_EREAD;
                    goto done;
                }
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                uint32_t lcid_invoke = le32_to_host(val32);
                char buf[64];
                data_offset += sizeof(uint32_t);
                int buf_length       = snprintf(buf, sizeof(buf), "REM PROJECTLCIDINVOKE: 0x%08x\n", lcid_invoke);
                buf[sizeof(buf) - 1] = '\0';
                if (buf_length > 0) {
                    CLI_WRITEN(buf, (size_t)buf_length);
                }
                break;
            }
            // MS-OVBA 2.3.4.2.1.4 PROJECTCODEPAGE
            case 0x0003: {
                if (size != sizeof(uint16_t)) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTCODEPAGE record size (%" PRIu32 " != 2)\n", size);
                    ret = CL_EREAD;
                    goto done;
                }
                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                codepage = le16_to_host(val16);
                char buf[64];
                data_offset += sizeof(uint16_t);
                int buf_length       = snprintf(buf, sizeof(buf), "REM PROJECTCODEPAGE: 0x%04x\n", codepage);
                buf[sizeof(buf) - 1] = '\0';
                if (buf_length > 0) {
                    CLI_WRITEN(buf, (size_t)buf_length);
                }
                break;
            }
            // MS-OVBA 2.3.4.2.1.5 PROJECTNAME
            case 0x0004: {
                if (size < 1 || size > 128) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTNAME record size (1 <= %" PRIu32 " <= 128)\n", size);
                    ret = CL_EREAD;
                    goto done;
                }

                CLI_WRITEN("REM PROJECTNAME: ", 17);
                CLI_WRITEN_MBCS(&data[data_offset], size);
                data_offset += size;
                CLI_WRITEN("\n", 1);
                break;
            }
            // MS-OVBA 2.3.4.2.1.6 PROJECTDOCSTRING
            case 0x0005: {
                if (size > 2000) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTDOCSTRING record size (%" PRIu32 " <= 2000)\n", size);
                    ret = CL_EREAD;
                    goto done;
                }

                CLI_WRITEN("REM PROJECTDOCSTRING: ", 22);
                CLI_WRITEN_MBCS(&data[data_offset], size);
                data_offset += size;
                CLI_WRITEN("\n", 1);
                break;
            }
            // MS-OVBA 2.3.4.2.1.6 PROJECTDOCSTRING Unicode
            case 0x0040: {
                if (size % 2 != 0) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTDOCSTRINGUNICODE record size (%" PRIu32 " but should be even)\n", size);
                    ret = CL_EREAD;
                    goto done;
                }
                CLI_WRITEN("REM PROJECTDOCSTRINGUNICODE: ", 29);
                CLI_WRITEN_UTF16LE(&data[data_offset], size);
                data_offset += size;
                CLI_WRITEN("\n", 1);
                break;
            }
            // MS-OVBA 2.3.4.2.1.7 PROJECTHELPFILEPATH
            case 0x0006: {
                if (size > 260) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTHELPFILEPATH record size (%" PRIu32 " <= 260)\n", size);
                    ret = CL_EREAD;
                    goto done;
                }
                const size_t projecthelpfilepath_offset = data_offset;
                CLI_WRITEN("REM PROJECTHELPFILEPATH: ", 25);
                CLI_WRITEN_MBCS(&data[data_offset], size);
                data_offset += size;
                CLI_WRITEN("\n", 1);

                if (sizeof(uint16_t) > data_len - data_offset) {
                    cli_warnmsg("vba_readdir_new: Failed to read record type from dir\n");
                    ret = CL_EREAD;
                    goto done;
                }
                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                id = le16_to_host(val16);
                if (id != 0x003d) {
                    cli_warnmsg("vba_readdir_new: PROJECTHELPFILEPATH is not followed by PROJECTHELPFILEPATH2\n");
                    CLI_WRITEN("REM WARNING: PROJECTHELPFILEPATH is not followed by PROJECTHELPFILEPATH2\n", 73);
                    continue;
                }
                data_offset += sizeof(uint16_t);

                if (sizeof(uint32_t) > data_len - data_offset) {
                    cli_warnmsg("vba_readdir_new: Failed to read record size of PROJECTHELPFILEPATH2 record from dir\n");
                    ret = CL_EREAD;
                    goto done;
                }
                uint32_t size2;
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                size2 = le32_to_host(val32);
                data_offset += sizeof(uint32_t);

                if (size2 > data_len - data_offset) {
                    cli_warnmsg("vba_readdir_new: PROJECTHELPFILEPATH2 record stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                if (size2 > 260) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTHELPFILEPATH2 record size (%" PRIu32 " <= 260)\n", size);
                    ret = CL_EREAD;
                    goto done;
                }

                if (size != size2) {
                    CLI_WRITEN("REM WARNING: PROJECTHELPFILEPATH and PROJECTHELPFILEPATH2 record sizes differ\n", 78);
                } else {
                    if (memcmp(&data[projecthelpfilepath_offset], &data[data_offset], size) != 0) {
                        CLI_WRITEN("REM WARNING: PROJECTHELPFILEPATH and PROJECTHELPFILEPATH2 contents differ\n", 74);
                    }
                }

                CLI_WRITEN("REM PROJECTHELPFILEPATH2: ", 26);
                CLI_WRITEN_UTF16LE(&data[data_offset], size2);
                data_offset += size2;
                CLI_WRITEN("\n", 1);
                break;
            }
            // MS-OVBA 2.3.4.2.1.8 PROJECTHELPCONTEXT
            case 0x0007: {
                if (size != sizeof(uint32_t)) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTHELPCONTEXT record size (%" PRIu32 " != 4)\n", size);
                    ret = CL_EREAD;
                    goto done;
                }
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                uint32_t context = le32_to_host(val32);
                char buf[64];
                data_offset += size;
                int buf_length       = snprintf(buf, sizeof(buf), "REM PROJECTHELPCONTEXT: 0x%04x\n", context);
                buf[sizeof(buf) - 1] = '\0';
                if (buf_length > 0) {
                    CLI_WRITEN(buf, (size_t)buf_length);
                }
                break;
            }
            // MS-OVBA 2.3.4.2.1.9 PROJECTLIBFLAGS
            case 0x0008: {
                if (size != sizeof(uint32_t)) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTLIBFLAGS record size (%" PRIu32 " != 4)\n", size);
                    ret = CL_EREAD;
                    goto done;
                }
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                uint32_t libflags = le32_to_host(val32);
                char buf[64];
                data_offset += sizeof(uint32_t);
                int buf_length       = snprintf(buf, sizeof(buf), "REM PROJECTLIBFLAGS: 0x%04x\n", libflags);
                buf[sizeof(buf) - 1] = '\0';
                if (buf_length > 0) {
                    CLI_WRITEN(buf, (size_t)buf_length);
                }
                break;
            }
            // MS-OVBA 2.3.4.2.1.10 PROJECTVERSION
            case 0x0009: {
                // The PROJECTVERSION record size is expected to be 4, even though the record size is 6.
                if (size != 4) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTVERSION record size (%" PRIu32 " != 4)\n", size);
                    ret = CL_EREAD;
                    goto done;
                }
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                uint32_t major = le32_to_host(val32);
                data_offset += size;

                if (sizeof(uint16_t) > data_len - data_offset) {
                    cli_warnmsg("vba_readdir_new: PROJECTVERSION record stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }
                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                uint16_t minor = le16_to_host(val16);
                data_offset += sizeof(uint16_t);
                char buf[64];
                int buf_length       = snprintf(buf, sizeof(buf), "REM PROJECTVERSION: %u.%u\n", major, minor);
                buf[sizeof(buf) - 1] = '\0';
                if (buf_length > 0) {
                    CLI_WRITEN(buf, (size_t)buf_length);
                }
                break;
            }
            // MS-OVBA 2.3.4.2.3 PROJECTMODULES
            case 0x000f: {
                if (size != sizeof(uint16_t)) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTMODULES record size\n");
                    ret = CL_EREAD;
                    goto done;
                }
                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                uint16_t modules = le16_to_host(val16);
                data_offset += sizeof(uint16_t);
                char buf[64];
                int buf_length       = snprintf(buf, sizeof(buf), "REM PROJECTMODULES: %u\n", modules);
                buf[sizeof(buf) - 1] = '\0';
                if (buf_length > 0) {
                    CLI_WRITEN(buf, (size_t)buf_length);
                }
                break;
            }
            // MS-OVBA 2.3.4.2.3.1 PROJECTCOOKIE
            case 0x0013: {
                if (size != sizeof(uint16_t)) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected PROJECTCOOKIE record size\n");
                    ret = CL_EREAD;
                    goto done;
                }
                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                uint16_t cookie = le16_to_host(val16);
                data_offset += sizeof(uint16_t);
                char buf[64];
                int buf_length       = snprintf(buf, sizeof(buf), "REM PROJECTCOOKIE: 0x%04x\n", cookie);
                buf[sizeof(buf) - 1] = '\0';
                if (buf_length > 0) {
                    CLI_WRITEN(buf, (size_t)buf_length);
                }
                break;
            }
            // MS-OVBA 2.3.4.2.3.2 MODULE record
            case 0x0019: {

                // MS-OVBA 2.3.4.2.3.2.1 MODULENAME
                CLI_WRITEN("\n\nREM MODULENAME: ", 18);
                if (size > 0) {
                    if (CL_SUCCESS == cli_codepage_to_utf8((char *)&data[data_offset], size, codepage, &mbcs_name, &mbcs_name_size)) {
                        CLI_WRITEN(mbcs_name, mbcs_name_size);
                    } else {
                        cli_dbgmsg("cli_vba_readdir_new: failed to convert codepage %" PRIu16 " to UTF-8\n", codepage);
                        CLI_WRITEN("<error decoding string>", 23);
                    }
                }
                data_offset += size;

                // MS-OVBA 2.3.4.2.3.2.2 MODULENAMEUNICODE
                cli_dbgmsg("Reading MODULENAMEUNICODE record\n");
                if (sizeof(uint16_t) + sizeof(uint32_t) > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULENAMEUNICODE record stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                if ((id = le16_to_host(val16)) != 0x0047) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULENAMEUNICODE (0x47) record, but got 0x%04x\n", id);
                    ret = CL_EREAD;
                    goto done;
                }
                data_offset += sizeof(uint16_t);
                CLI_WRITEN("\nREM MODULENAMEUNICODE: ", 24);
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                size = le32_to_host(val32);
                data_offset += sizeof(uint32_t);

                if (size > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULENAMEUNICODE stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                if (size > 0) {
                    if (CL_SUCCESS == cli_codepage_to_utf8((char *)&data[data_offset], size, CODEPAGE_UTF16_LE, &utf16_name, &utf16_name_size)) {
                        CLI_WRITEN(utf16_name, utf16_name_size);
                    } else {
                        cli_dbgmsg("cli_vba_readdir_new: failed to convert UTF16LE to UTF-8\n");
                        CLI_WRITEN("<error decoding string>", 23);
                    }
                }
                data_offset += size;

                if (mbcs_name && utf16_name &&
                    (mbcs_name_size != utf16_name_size ||
                     memcmp(mbcs_name, utf16_name, mbcs_name_size) != 0)) {
                    CLI_WRITEN("\nREM WARNING: MODULENAME and MODULENAMEUNICODE differ", 53);
                }

                if (mbcs_name) {
                    free(mbcs_name);
                    mbcs_name = NULL;
                }
                if (utf16_name) {
                    free(utf16_name);
                    utf16_name = NULL;
                }

                // MS-OVBA 2.3.4.2.3.2.3 MODULESTREAMNAME
                cli_dbgmsg("Reading MODULESTREAMNAME record\n");
                if (sizeof(uint16_t) + sizeof(uint32_t) > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULESTREAMNAME record stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                if ((id = le16_to_host(val16)) != 0x001a) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULESTREAMNAME (0x1a) record, but got 0x%04x\n", id);
                    ret = CL_EREAD;
                    goto done;
                }
                data_offset += sizeof(uint16_t);
                CLI_WRITEN("\nREM MODULESTREAMNAME: ", 23);
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                size = le32_to_host(val32);
                data_offset += sizeof(uint32_t);

                if (size > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULESTREAMNAME stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                if (size > 0) {
                    if (CL_SUCCESS == cli_codepage_to_utf8((char *)&data[data_offset], size, codepage, &mbcs_name, &mbcs_name_size)) {
                        CLI_WRITEN(mbcs_name, mbcs_name_size);
                    } else {
                        cli_dbgmsg("cli_vba_readdir_new: failed to convert codepage %" PRIu16 " to UTF-8\n", codepage);
                        CLI_WRITEN("<error decoding string>", 23);
                    }
                }
                data_offset += size;

                cli_dbgmsg("Reading MODULESTREAMNAMEUNICODE record\n");
                if (sizeof(uint16_t) + sizeof(uint32_t) > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULESTREAMNAMEUNICODE record stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                if ((id = le16_to_host(val16)) != 0x0032) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULESTREAMNAMEUNICODE (0x32) record, but got 0x%04x\n", id);
                    ret = CL_EREAD;
                    goto done;
                }
                data_offset += sizeof(uint16_t);
                CLI_WRITEN("\nREM MODULESTREAMNAMEUNICODE: ", 30);
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                uint32_t module_stream_name_size = le32_to_host(val32);
                data_offset += sizeof(uint32_t);

                if (module_stream_name_size > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULESTREAMNAMEUNICODE stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                const unsigned char *module_stream_name = &data[data_offset];
                if (module_stream_name_size > 0) {
                    if (CL_SUCCESS == cli_codepage_to_utf8((char *)&data[data_offset], module_stream_name_size, CODEPAGE_UTF16_LE, &utf16_name, &utf16_name_size)) {
                        CLI_WRITEN(utf16_name, utf16_name_size);
                    } else {
                        cli_dbgmsg("cli_vba_readdir_new: failed to convert UTF16LE to UTF-8\n");
                        CLI_WRITEN("<error decoding string>", 23);
                    }
                }
                data_offset += module_stream_name_size;

                if (mbcs_name && utf16_name &&
                    (mbcs_name_size != utf16_name_size ||
                     memcmp(mbcs_name, utf16_name, mbcs_name_size) != 0)) {
                    CLI_WRITEN("\nREM WARNING: MODULESTREAMNAME and MODULESTREAMNAMEUNICODE differ", 65);
                }

                if (mbcs_name) {
                    free(mbcs_name);
                    mbcs_name = NULL;
                }
                if (utf16_name) {
                    free(utf16_name);
                    utf16_name = NULL;
                }

                // MS-OVBA 2.3.4.2.3.2.4 MODULEDOCSTRING
                cli_dbgmsg("Reading MODULEDOCSTRING record\n");
                if (sizeof(uint16_t) + sizeof(uint32_t) > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULEDOCSTRING record stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                if ((id = le16_to_host(val16)) != 0x001c) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULEDOCSTRING (0x1c) record, but got 0x%04x\n", id);
                    ret = CL_EREAD;
                    goto done;
                }
                data_offset += sizeof(uint16_t);
                CLI_WRITEN("\nREM MODULEDOCSTRING: ", 22);
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                size = le32_to_host(val32);
                data_offset += sizeof(uint32_t);

                if (size > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULEDOCSTRING stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                if (size > 0) {
                    if (CL_SUCCESS == cli_codepage_to_utf8((char *)&data[data_offset], size, codepage, &mbcs_name, &mbcs_name_size)) {
                        CLI_WRITEN(mbcs_name, mbcs_name_size);
                    } else {
                        cli_dbgmsg("cli_vba_readdir_new: failed to convert codepage %" PRIu16 " to UTF-8\n", codepage);
                        CLI_WRITEN("<error decoding string>", 23);
                    }
                }
                data_offset += size;

                cli_dbgmsg("Reading MODULEDOCSTRINGUNICODE record\n");
                if (sizeof(uint16_t) + sizeof(uint32_t) > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULEDOCSTRINGUNICODE record stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                if ((id = le16_to_host(val16)) != 0x0048) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULEDOCSTRINGUNICODE (0x32) record, but got 0x%04x\n", id);
                    ret = CL_EREAD;
                    goto done;
                }
                data_offset += sizeof(uint16_t);
                CLI_WRITEN("\nREM MODULEDOCSTRINGUNICODE: ", 29);
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                size = le32_to_host(val32);
                data_offset += sizeof(uint32_t);

                if (size > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULEDOCSTRINGUNICODE stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                if (size > 0) {
                    if (CL_SUCCESS == cli_codepage_to_utf8((char *)&data[data_offset], size, CODEPAGE_UTF16_LE, &utf16_name, &utf16_name_size)) {
                        CLI_WRITEN(utf16_name, utf16_name_size);
                    } else {
                        cli_dbgmsg("cli_vba_readdir_new: failed to convert UTF16LE to UTF-8\n");
                        CLI_WRITEN("<error decoding string>", 23);
                    }
                }
                data_offset += size;

                if (mbcs_name && utf16_name &&
                    (mbcs_name_size != utf16_name_size ||
                     memcmp(mbcs_name, utf16_name, mbcs_name_size) != 0)) {
                    CLI_WRITEN("\nREM WARNING: MODULEDOCSTRING and MODULEDOCSTRINGUNICODE differ", 63);
                }

                if (mbcs_name) {
                    free(mbcs_name);
                    mbcs_name = NULL;
                }
                if (utf16_name) {
                    free(utf16_name);
                    utf16_name = NULL;
                }

                // MS-OVBA 2.3.4.2.3.2.5 MODULEOFFSET
                cli_dbgmsg("Reading MODULEOFFSET record\n");
                if (sizeof(uint16_t) + sizeof(uint32_t) > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULEOFFSET record stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                if ((id = le16_to_host(val16)) != 0x0031) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULEOFFSET (0x31) record, but got 0x%04x\n", id);
                    ret = CL_EREAD;
                    goto done;
                }
                data_offset += sizeof(uint16_t);
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                size = le32_to_host(val32);
                data_offset += sizeof(uint32_t);
                if (size != sizeof(uint32_t)) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULEOFFSET record size");
                    ret = CL_EREAD;
                    goto done;
                }

                if (size > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULEOFFSET stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                uint32_t module_offset = le32_to_host(val32);
                data_offset += size;
                char buffer[64];
                int buffer_size = snprintf(buffer, sizeof(buffer), "\nREM MODULEOFFSET: 0x%08x", module_offset);
                if (buffer_size > 0) {
                    CLI_WRITEN(buffer, (size_t)buffer_size);
                }

                // MS-OVBA 2.3.4.2.3.2.6 MODULEHELPCONTEXT
                cli_dbgmsg("Reading MODULEHELPCONTEXT record\n");
                if (sizeof(uint16_t) + sizeof(uint32_t) > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULEHELPCONTEXT record stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                if ((id = le16_to_host(val16)) != 0x001e) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULEHELPCONTEXT (0x1e) record, but got 0x%04x\n", id);
                    ret = CL_EREAD;
                    goto done;
                }

                data_offset += sizeof(uint16_t);
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                size = le32_to_host(val32);
                data_offset += sizeof(uint32_t);
                if (size != sizeof(uint32_t)) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULEHELPCONTEXT record size");
                    ret = CL_EREAD;
                    goto done;
                }

                if (size > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULEHELPCONTEXT stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                uint32_t help_context = le32_to_host(val32);
                data_offset += size;
                buffer_size = snprintf(buffer, sizeof(buffer), "\nREM MODULEHELPCONTEXT: 0x%08x", help_context);
                if (buffer_size > 0) {
                    CLI_WRITEN(buffer, (size_t)buffer_size);
                }

                // MS-OVBA 2.3.4.2.3.2.7 MODULECOOKIE
                cli_dbgmsg("Reading MODULECOOKIE record\n");
                if (sizeof(uint16_t) + sizeof(uint32_t) > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULECOOKIE record stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                if ((id = le16_to_host(val16)) != 0x002c) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULECOOKIE (0x2c) record, but got 0x%04x\n", id);
                    ret = CL_EREAD;
                    goto done;
                }
                data_offset += sizeof(uint16_t);
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                size = le32_to_host(val32);
                data_offset += sizeof(uint32_t);
                if (size != sizeof(uint16_t)) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULECOOKIE record size");
                    ret = CL_EREAD;
                    goto done;
                }

                if (size > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULECOOKIE record's cookie stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                uint16_t cookie = le16_to_host(val16);
                data_offset += size;
                buffer_size = snprintf(buffer, sizeof(buffer), "\nREM MODULECOOKIE: 0x%04x", cookie);
                if (buffer_size > 0) {
                    CLI_WRITEN(buffer, (size_t)buffer_size);
                }

                // MS-OVBA 2.3.4.2.3.2.8 MODULETYPE
                if (sizeof(uint16_t) + sizeof(uint32_t) > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULETYPE record stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                id = le16_to_host(val16);
                if (id != 0x0021 && id != 0x0022) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULETYPE (0x21/0x22) record, but got 0x%04x\n", id);
                    ret = CL_EREAD;
                    goto done;
                }
                data_offset += sizeof(uint16_t);
                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                size = le32_to_host(val32);
                data_offset += sizeof(uint32_t);
                if (size != 0) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULETYPE record size");
                    ret = CL_EREAD;
                    goto done;
                }
                if (id == 0x21) {
                    CLI_WRITEN("\nREM MODULETYPE: Procedural", 27);
                } else {
                    CLI_WRITEN("\nREM MODULETYPE: Class", 22);
                }

                // MS-OVBA 2.3.4.2.3.2.9 MODULEREADONLY
                if (sizeof(uint16_t) > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULEREADONLY record id field stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                id = le16_to_host(val16);
                data_offset += sizeof(uint16_t);

                if (id == 0x0025) {
                    if (sizeof(uint32_t) > data_len - data_offset) {
                        cli_dbgmsg("vba_readdir_new: MODULEREADONLY record size field stretches past the end of the file\n");
                        ret = CL_EREAD;
                        goto done;
                    }

                    memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                    size = le32_to_host(val32);
                    data_offset += sizeof(uint32_t);
                    if (size != 0) {
                        cli_dbgmsg("cli_vba_readdir_new: Expected MODULEREADONLY record size");
                        ret = CL_EREAD;
                        goto done;
                    }
                    CLI_WRITEN("\nREM MODULEREADONLY", 19);

                    if (sizeof(uint16_t) > data_len - data_offset) {
                        cli_dbgmsg("vba_readdir_new: record id field after MODULEREADONLY stretches past the end of the file\n");
                        ret = CL_EREAD;
                        goto done;
                    }

                    memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                    id = le16_to_host(val16);
                    data_offset += sizeof(uint16_t);
                }

                // MS-OVBA 2.3.4.2.3.2.10 MODULEPRIVATE
                if (id == 0x0028) {
                    if (sizeof(uint32_t) > data_len - data_offset) {
                        cli_dbgmsg("vba_readdir_new: MODULEPRIVATE record size field stretches past the end of the file\n");
                        ret = CL_EREAD;
                        goto done;
                    }

                    memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                    size = le32_to_host(val32);
                    data_offset += sizeof(uint32_t);
                    if (size != 0) {
                        cli_dbgmsg("cli_vba_readdir_new: Expected MODULEPRIVATE record size");
                        ret = CL_EREAD;
                        goto done;
                    }
                    CLI_WRITEN("\nREM MODULEPRIVATE", 18);

                    if (sizeof(uint16_t) > data_len - data_offset) {
                        cli_dbgmsg("vba_readdir_new: record id field after MODULEPRIVATE stretches past the end of the file\n");
                        ret = CL_EREAD;
                        goto done;
                    }

                    memcpy(&val16, &data[data_offset], sizeof(uint16_t));
                    id = le16_to_host(val16);
                    data_offset += sizeof(uint16_t);
                }

                // Terminator
                if (id != 0x002b) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULETERMINATOR ....");
                    ret = CL_EREAD;
                    goto done;
                }

                if (sizeof(uint32_t) > data_len - data_offset) {
                    cli_dbgmsg("vba_readdir_new: MODULETERMINATOR record size field stretches past the end of the file\n");
                    ret = CL_EREAD;
                    goto done;
                }

                memcpy(&val32, &data[data_offset], sizeof(uint32_t));
                size = le32_to_host(val32);
                data_offset += sizeof(uint32_t);
                if (size != 0) {
                    cli_dbgmsg("cli_vba_readdir_new: Expected MODULETERMINATOR record size");
                    ret = CL_EREAD;
                    goto done;
                }

                CLI_WRITEN("\nREM ##################################################\n", 56);

                stream_name = cli_ole2_get_property_name2((const char *)module_stream_name, (int)(module_stream_name_size + 2));
                char *module_hash;
                uint32_t module_hashcnt;
                if (stream_name == NULL) {
                    ret = CL_EMEM;
                    goto done;
                }
                if (uniq_get(U, stream_name, (uint32_t)strlen(stream_name), &module_hash, &module_hashcnt) != CL_SUCCESS) {
                    cli_dbgmsg("cli_vba_readdir_new: Cannot find module stream %s\n", stream_name);
                    ret = CL_EOPEN;
                    goto done;
                }

                int module_stream_found = 0;

                for (i = 1; i <= module_hashcnt; ++i) {
                    char module_filename[PATH_MAX];
                    snprintf(module_filename, sizeof(module_filename), "%s" PATHSEP "%s_%u", dir, module_hash, i);
                    module_filename[sizeof(module_filename) - 1] = '\0';

                    int module_fd = open(module_filename, O_RDONLY | O_BINARY);
                    if (module_fd == -1) {
                        continue;
                    }

                    module_data = cli_vba_inflate(module_fd, module_offset, &module_data_size);
                    if (!module_data) {
                        cli_dbgmsg("cli_vba_readdir_new: Failed to extract module data\n");
                        close(module_fd);
                        continue;
                    }

                    close(module_fd);

                    if (CL_SUCCESS == cli_codepage_to_utf8((char *)module_data, module_data_size, codepage, (char **)&module_data_utf8, &module_data_utf8_size)) {
                        module_data_utf8_size = vba_normalize(module_data_utf8, module_data_utf8_size);

                        CLI_WRITEN(module_data_utf8, module_data_utf8_size);

                        if (NULL != ctx->engine->cb_vba) {
                            ctx->engine->cb_vba(module_data_utf8, module_data_utf8_size, ctx->cb_ctx);
                        }

                        module_stream_found = 1;
                        free(module_data_utf8);
                        module_data_utf8 = NULL;
                    } else {
                        /*If normalization didn't work, fall back to the pre-normalized data.*/
                        if (NULL != ctx->engine->cb_vba) {
                            ctx->engine->cb_vba(module_data, module_data_size, ctx->cb_ctx);
                        }

                        CLI_WRITEN("\n<Error decoding module data>\n", 30);
                        cli_dbgmsg("cli_vba_readdir_new: Failed to decode VBA module content from codepage %" PRIu16 " to UTF8\n", codepage);
                    }

                    free(module_data);
                    module_data = NULL;
                    break;
                }

                if (!module_stream_found) {
                    cli_dbgmsg("cli_vba_readdir_new: Cannot find module stream %s\n", stream_name);
                }
                free((void *)stream_name);
                stream_name = NULL;

                break;
            }
            case 0x0010: { // Terminator
                ret = CL_SUCCESS;
                goto done;
            }
            default: {
                data_offset += size;
            }
        }
    }

#undef CLI_WRITEN
#undef CLI_WRITENHEX
#undef CLI_WRITEN_MBCS
#undef CLI_WRITEN_UTF16LE

done:
    if (fd >= 0) {
        close(fd);
    }
    if (data) {
        free((void *)data);
    }
    if (stream_name) {
        free((void *)stream_name);
    }
    if (ret != CL_SUCCESS && *tempfd >= 0) {
        close(*tempfd);
        *tempfd = -1;
    }
    if (utf16_name) {
        free(utf16_name);
        utf16_name = NULL;
    }
    if (mbcs_name) {
        free(mbcs_name);
        mbcs_name = NULL;
    }
    if (module_data) {
        free(module_data);
        module_data = NULL;
    }
    if (module_data_utf8) {
        free(module_data_utf8);
        module_data_utf8 = NULL;
    }

    return ret;
}

vba_project_t *
cli_vba_readdir(const char *dir, struct uniq *U, uint32_t which)
{
    unsigned char *buf;
    const unsigned char vba56_signature[] = {0xcc, 0x61};
    uint16_t record_count, buflen, ffff, byte_count;
    uint32_t offset;
    int i, j, fd, big_endian = FALSE;
    vba_project_t *vba_project;
    struct vba56_header v56h;
    off_t seekback;
    char fullname[1024], *hash;
    uint32_t hashcnt = 0;

    cli_dbgmsg("in cli_vba_readdir()\n");

    if (dir == NULL)
        return NULL;

    /*
     * _VBA_PROJECT files are embedded within office documents (OLE2)
     */

    if (CL_SUCCESS != uniq_get(U, "_vba_project", 12, &hash, &hashcnt)) {
        cli_dbgmsg("vba_readdir: uniq_get('_vba_project') failed. Unable to check # of embedded vba proj files\n");
        return NULL;
    }
    if (hashcnt == 0) {
        return NULL;
    }
    snprintf(fullname, sizeof(fullname), "%s" PATHSEP "%s_%u", dir, hash, which);
    fullname[sizeof(fullname) - 1] = '\0';
    fd                             = open(fullname, O_RDONLY | O_BINARY);

    if (fd == -1)
        return NULL;

    if (cli_readn(fd, &v56h, sizeof(struct vba56_header)) != sizeof(struct vba56_header)) {
        close(fd);
        return NULL;
    }
    if (memcmp(v56h.magic, vba56_signature, sizeof(v56h.magic)) != 0) {
        close(fd);
        return NULL;
    }

    i = vba_read_project_strings(fd, TRUE);
    if ((seekback = lseek(fd, 0, SEEK_CUR)) == -1) {
        cli_dbgmsg("vba_readdir: lseek() failed. Unable to guess VBA type\n");
        close(fd);
        return NULL;
    }
    if (lseek(fd, sizeof(struct vba56_header), SEEK_SET) == -1) {
        cli_dbgmsg("vba_readdir: lseek() failed. Unable to guess VBA type\n");
        close(fd);
        return NULL;
    }
    j = vba_read_project_strings(fd, FALSE);
    if (!i && !j) {
        close(fd);
        cli_dbgmsg("vba_readdir: Unable to guess VBA type\n");
        return NULL;
    }
    if (i > j) {
        big_endian = TRUE;
        if (lseek(fd, seekback, SEEK_SET) == -1) {
            cli_dbgmsg("vba_readdir: call to lseek() while guessing big-endian has failed\n");
            close(fd);
            return NULL;
        }
        cli_dbgmsg("vba_readdir: Guessing big-endian\n");
    } else {
        cli_dbgmsg("vba_readdir: Guessing little-endian\n");
    }

    /* junk some more stuff */
    do
        if (cli_readn(fd, &ffff, 2) != 2) {
            close(fd);
            return NULL;
        }
    while (ffff != 0xFFFF);

    /* check for alignment error */
    if (!seekandread(fd, -3, SEEK_CUR, &ffff, sizeof(uint16_t))) {
        close(fd);
        return NULL;
    }
    if (ffff != 0xFFFF) {
        if (lseek(fd, 1, SEEK_CUR) == -1) {
            cli_dbgmsg("call to lseek() while checking alignment error has failed\n");
            close(fd);
            return NULL;
        }
    }

    if (!read_uint16(fd, &ffff, big_endian)) {
        close(fd);
        return NULL;
    }

    if (ffff != 0xFFFF) {
        if (lseek(fd, ffff, SEEK_CUR) == -1) {
            cli_dbgmsg("call to lseek() while checking alignment error has failed\n");
            close(fd);
            return NULL;
        }
    }

    if (!read_uint16(fd, &ffff, big_endian)) {
        close(fd);
        return NULL;
    }

    if (ffff == 0xFFFF)
        ffff = 0;

    if (lseek(fd, ffff + 100, SEEK_CUR) == -1) {
        cli_dbgmsg("call to lseek() failed\n");
        close(fd);
        return NULL;
    }

    if (!read_uint16(fd, &record_count, big_endian)) {
        close(fd);
        return NULL;
    }
    cli_dbgmsg("vba_readdir: VBA Record count %d\n", record_count);
    if (record_count == 0) {
        /* No macros, assume clean */
        close(fd);
        return NULL;
    }
    if (record_count > MAX_VBA_COUNT) {
        /* Almost certainly an error */
        cli_dbgmsg("vba_readdir: VBA Record count too big\n");
        close(fd);
        return NULL;
    }

    vba_project = create_vba_project(record_count, dir, U);
    if (vba_project == NULL) {
        close(fd);
        return NULL;
    }
    buf    = NULL;
    buflen = 0;
    for (i = 0; i < record_count; i++) {
        uint16_t length;
        char *ptr;

        vba_project->colls[i] = 0;
        if (!read_uint16(fd, &length, big_endian))
            break;

        if (length == 0) {
            cli_dbgmsg("vba_readdir: zero name length\n");
            break;
        }
        if (length > buflen) {
            unsigned char *newbuf = (unsigned char *)cli_max_realloc(buf, length);
            if (newbuf == NULL)
                break;
            buflen = length;
            buf    = newbuf;
        }
        if (cli_readn(fd, buf, (size_t)length) != (size_t)length) {
            cli_dbgmsg("vba_readdir: read name failed\n");
            break;
        }
        ptr = get_unicode_name((const char *)buf, length, big_endian);
        if (ptr == NULL) break;
        if (CL_SUCCESS != uniq_get(U, ptr, strlen(ptr), &hash, &hashcnt)) {
            cli_dbgmsg("vba_readdir: uniq_get('%s') failed.\n", ptr);
            free(ptr);
            break;
        }
        vba_project->colls[i] = hashcnt;
        if (0 == vba_project->colls[i]) {
            cli_dbgmsg("vba_readdir: cannot find project %s (%s)\n", ptr, hash);
            free(ptr);
            break;
        }
        cli_dbgmsg("vba_readdir: project name: %s (%s)\n", ptr, hash);
        free(ptr);
        vba_project->name[i] = hash;
        if (!read_uint16(fd, &length, big_endian))
            break;
        lseek(fd, length, SEEK_CUR);

        if (!read_uint16(fd, &ffff, big_endian))
            break;
        if (ffff == 0xFFFF) {
            lseek(fd, 2, SEEK_CUR);
            if (!read_uint16(fd, &ffff, big_endian))
                break;
            lseek(fd, ffff + 8, SEEK_CUR);
        } else
            lseek(fd, ffff + 10, SEEK_CUR);

        if (!read_uint16(fd, &byte_count, big_endian))
            break;
        lseek(fd, (8 * byte_count) + 5, SEEK_CUR);
        if (!read_uint32(fd, &offset, big_endian))
            break;
        cli_dbgmsg("vba_readdir: offset: %u\n", (unsigned int)offset);
        vba_project->offset[i] = offset;
        lseek(fd, 2, SEEK_CUR);
    }

    if (buf)
        free(buf);

    close(fd);

    if (i < record_count) {
        free(vba_project->name);
        free(vba_project->colls);
        free(vba_project->dir);
        free(vba_project->offset);
        free(vba_project);
        return NULL;
    }

    return vba_project;
}

unsigned char *
cli_vba_inflate(int fd, off_t offset, size_t *size)
{
    unsigned int pos, shift, mask, distance, clean;
    uint8_t flag;
    uint16_t token;
    blob *b;
    unsigned char buffer[VBA_COMPRESSION_WINDOW];

    if (fd < 0)
        return NULL;

    b = blobCreate();

    if (b == NULL)
        return NULL;

    memset(buffer, 0, sizeof(buffer));
    lseek(fd, offset + 3, SEEK_SET); /* 1byte ?? , 2byte length ?? */
    clean = TRUE;
    pos   = 0;

    while (cli_readn(fd, &flag, 1) == 1) {
        for (mask = 1; mask < 0x100; mask <<= 1) {
            unsigned int winpos = pos % VBA_COMPRESSION_WINDOW;
            if (flag & mask) {
                uint16_t len;
                unsigned int srcpos;

                if (!read_uint16(fd, &token, FALSE)) {
                    blobDestroy(b);
                    if (size)
                        *size = 0;
                    return NULL;
                }
                shift    = 12 - (winpos > 0x10) - (winpos > 0x20) - (winpos > 0x40) - (winpos > 0x80) - (winpos > 0x100) - (winpos > 0x200) - (winpos > 0x400) - (winpos > 0x800);
                len      = (uint16_t)((token & ((1 << shift) - 1)) + 3);
                distance = token >> shift;

                srcpos = pos - distance - 1;
                if ((((srcpos + len) % VBA_COMPRESSION_WINDOW) < winpos) &&
                    ((winpos + len) < VBA_COMPRESSION_WINDOW) &&
                    (((srcpos % VBA_COMPRESSION_WINDOW) + len) < VBA_COMPRESSION_WINDOW) &&
                    (len <= VBA_COMPRESSION_WINDOW)) {
                    srcpos %= VBA_COMPRESSION_WINDOW;
                    memcpy(&buffer[winpos], &buffer[srcpos],
                           len);
                    pos += len;
                } else
                    while (len-- > 0) {
                        srcpos                                 = (pos - distance - 1) % VBA_COMPRESSION_WINDOW;
                        buffer[pos++ % VBA_COMPRESSION_WINDOW] = buffer[srcpos];
                    }
            } else {
                if ((pos != 0) && (winpos == 0) && clean) {
                    if (cli_readn(fd, &token, 2) != 2) {
                        blobDestroy(b);
                        if (size)
                            *size = 0;
                        return NULL;
                    }
                    (void)blobAddData(b, buffer, VBA_COMPRESSION_WINDOW);
                    clean = FALSE;
                    break;
                }
                if (cli_readn(fd, &buffer[winpos], 1) == 1)
                    pos++;
            }
            clean = TRUE;
        }
    }

    if (blobAddData(b, buffer, pos % VBA_COMPRESSION_WINDOW) < 0) {
        blobDestroy(b);
        if (size)
            *size = 0;
        return NULL;
    }

    if (size)
        *size = blobGetDataSize(b);
    return (unsigned char *)blobToMem(b);
}

/*
 * See also cli_filecopy()
 */
static void
ole_copy_file_data(int s, int d, uint32_t len)
{
    unsigned char data[FILEBUFF];

    while (len > 0) {
        size_t todo = MIN(sizeof(data), len);

        if (cli_readn(s, data, todo) != todo)
            break;
        if (cli_writen(d, data, todo) != todo)
            break;

        if (todo > len) {
            break;
        } else {
            len -= todo;
        }
    }
}

int cli_scan_ole10(int fd, cli_ctx *ctx)
{
    int ofd;
    cl_error_t ret;
    uint32_t object_size;
    STATBUF statbuf;
    char *fullname;

    if (fd < 0)
        return CL_CLEAN;

    lseek(fd, 0, SEEK_SET);
    if (!read_uint32(fd, &object_size, FALSE))
        return CL_CLEAN;

    if (FSTAT(fd, &statbuf) == -1)
        return CL_ESTAT;

    if ((statbuf.st_size - object_size) >= 4) {
        /* Probably the OLE type id */
        if (lseek(fd, 2, SEEK_CUR) == -1) {
            return CL_CLEAN;
        }

        /* Attachment name */
        if (!skip_past_nul(fd))
            return CL_CLEAN;

        /* Attachment full path */
        if (!skip_past_nul(fd))
            return CL_CLEAN;

        /* ??? */
        if (lseek(fd, 8, SEEK_CUR) == -1)
            return CL_CLEAN;

        /* Attachment full path */
        if (!skip_past_nul(fd))
            return CL_CLEAN;

        if (!read_uint32(fd, &object_size, FALSE))
            return CL_CLEAN;
    }
    if (!(fullname = cli_gentemp(ctx ? ctx->this_layer_tmpdir : NULL))) {
        return CL_EMEM;
    }
    ofd = open(fullname, O_RDWR | O_CREAT | O_TRUNC | O_BINARY | O_EXCL,
               S_IWUSR | S_IRUSR);
    if (ofd < 0) {
        cli_warnmsg("cli_decode_ole_object: can't create %s\n", fullname);
        free(fullname);
        return CL_ECREAT;
    }

    cli_dbgmsg("cli_decode_ole_object: decoding to %s\n", fullname);

    ole_copy_file_data(fd, ofd, object_size);

    lseek(ofd, 0, SEEK_SET);

    ret = cli_magic_scan_desc(ofd, fullname, ctx, NULL, LAYER_ATTRIBUTES_NONE);

    close(ofd);

    if (ctx && !ctx->engine->keeptmp) {
        if (cli_unlink(fullname)) {
            cli_dbgmsg("cli_decode_ole_object: Failed to remove temp file: %s\n", fullname);
        }
    }

    free(fullname);

    return ret;
}

/*
 * Powerpoint files
 */
typedef struct {
    uint16_t type;
    uint32_t length;
} atom_header_t;

static int
ppt_read_atom_header(int fd, atom_header_t *atom_header)
{
    uint16_t v;
    struct ppt_header {
        uint16_t ver;
        uint16_t type;
        uint32_t length;
    } h;

    cli_dbgmsg("in ppt_read_atom_header\n");
    if (cli_readn(fd, &h, sizeof(struct ppt_header)) != sizeof(struct ppt_header)) {
        cli_dbgmsg("read ppt_header failed\n");
        return FALSE;
    }
    v = vba_endian_convert_16(h.ver, FALSE);
    cli_dbgmsg("\tversion: 0x%.2x\n", v & 0xF);
    cli_dbgmsg("\tinstance: 0x%.2x\n", v >> 4);

    atom_header->type = vba_endian_convert_16(h.type, FALSE);
    cli_dbgmsg("\ttype: 0x%.4x\n", atom_header->type);
    atom_header->length = vba_endian_convert_32(h.length, FALSE);
    cli_dbgmsg("\tlength: 0x%.8x\n", (int)atom_header->length);

    return TRUE;
}

/*
 * TODO: combine shared code with flatedecode() or cli_unzip_single()
 *	Needs cli_unzip_single to have a "length" argument
 */
static int
ppt_unlzw(const char *dir, int fd, uint32_t length)
{
    int ofd;
    z_stream stream;
    unsigned char inbuff[PPT_LZW_BUFFSIZE], outbuff[PPT_LZW_BUFFSIZE];
    char fullname[PATH_MAX + 1];

    snprintf(fullname, sizeof(fullname) - 1, "%s" PATHSEP "ppt%.8lx.doc",
             dir, (long)lseek(fd, 0L, SEEK_CUR));

    ofd = open(fullname, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY | O_EXCL,
               S_IWUSR | S_IRUSR);
    if (ofd == -1) {
        cli_warnmsg("ppt_unlzw: can't create %s\n", fullname);
        return FALSE;
    }

    memset(&stream, 0, sizeof(stream));

    stream.zalloc    = Z_NULL;
    stream.zfree     = Z_NULL;
    stream.opaque    = (void *)NULL;
    stream.next_in   = (Bytef *)inbuff;
    stream.next_out  = outbuff;
    stream.avail_out = sizeof(outbuff);
    stream.avail_in  = MIN(length, PPT_LZW_BUFFSIZE);

    if (cli_readn(fd, inbuff, (size_t)stream.avail_in) != (size_t)stream.avail_in) {
        close(ofd);
        cli_unlink(fullname);
        return FALSE;
    }
    length -= stream.avail_in;

    if (inflateInit(&stream) != Z_OK) {
        close(ofd);
        cli_unlink(fullname);
        cli_warnmsg("ppt_unlzw: inflateInit failed\n");
        return FALSE;
    }

    do {
        if (stream.avail_out == 0) {
            if (cli_writen(ofd, outbuff, PPT_LZW_BUFFSIZE) != PPT_LZW_BUFFSIZE) {
                close(ofd);
                inflateEnd(&stream);
                return FALSE;
            }
            stream.next_out  = outbuff;
            stream.avail_out = PPT_LZW_BUFFSIZE;
        }
        if (stream.avail_in == 0) {
            stream.next_in  = inbuff;
            stream.avail_in = MIN(length, PPT_LZW_BUFFSIZE);
            if (cli_readn(fd, inbuff, (size_t)stream.avail_in) != (size_t)stream.avail_in) {
                close(ofd);
                inflateEnd(&stream);
                return FALSE;
            }
            length -= stream.avail_in;
        }
    } while (inflate(&stream, Z_NO_FLUSH) == Z_OK);

    if (cli_writen(ofd, outbuff, PPT_LZW_BUFFSIZE - stream.avail_out) != (size_t)(PPT_LZW_BUFFSIZE - stream.avail_out)) {
        close(ofd);
        inflateEnd(&stream);
        return FALSE;
    }
    close(ofd);
    return inflateEnd(&stream) == Z_OK;
}

static const char *
ppt_stream_iter(int fd, const char *dir)
{
    atom_header_t atom_header;

    while (ppt_read_atom_header(fd, &atom_header)) {
        if (atom_header.length == 0)
            return NULL;

        if (atom_header.type == 0x1011) {
            uint32_t length;

            /* Skip over ID */
            if (lseek(fd, sizeof(uint32_t), SEEK_CUR) == -1) {
                cli_dbgmsg("ppt_stream_iter: seek failed\n");
                return NULL;
            }
            length = atom_header.length - 4;
            cli_dbgmsg("length: %d\n", (int)length);
            if (!ppt_unlzw(dir, fd, length)) {
                cli_dbgmsg("ppt_unlzw failed\n");
                return NULL;
            }
        } else {
            off_t offset = lseek(fd, 0, SEEK_CUR);
            /* Check we don't wrap */
            if ((offset + (off_t)atom_header.length) < offset) {
                break;
            }
            offset += atom_header.length;
            if (lseek(fd, offset, SEEK_SET) != offset) {
                break;
            }
        }
    }
    return dir;
}

char *
cli_ppt_vba_read(int ifd, cli_ctx *ctx)
{
    char *dir;
    const char *ret;

    /* Create a directory to store the extracted OLE2 objects */
    dir = cli_gentemp_with_prefix(ctx ? ctx->this_layer_tmpdir : NULL, "ppt-ole2-tmp");
    if (dir == NULL)
        return NULL;
    if (mkdir(dir, 0700)) {
        cli_errmsg("cli_ppt_vba_read: Can't create temporary directory %s\n", dir);
        free(dir);
        return NULL;
    }
    ret = ppt_stream_iter(ifd, dir);
    if (ret == NULL) {
        cli_rmdirs(dir);
        free(dir);
        return NULL;
    }
    return dir;
}

/*
 * Word 6 macros
 */
typedef struct {
    unsigned char unused[12];
    uint32_t macro_offset;
    uint32_t macro_len;
} mso_fib_t;

typedef struct macro_entry_tag {
    uint32_t len;
    uint32_t offset;
    unsigned char key;
} macro_entry_t;

typedef struct macro_info_tag {
    struct macro_entry_tag *entries;
    uint16_t count;
} macro_info_t;

static int
word_read_fib(int fd, mso_fib_t *fib)
{
    struct {
        uint32_t offset;
        uint32_t len;
    } macro_details;

    if (!seekandread(fd, 0x118, SEEK_SET, &macro_details, sizeof(macro_details))) {
        cli_dbgmsg("read word_fib failed\n");
        return FALSE;
    }
    fib->macro_offset = vba_endian_convert_32(macro_details.offset, FALSE);
    fib->macro_len    = vba_endian_convert_32(macro_details.len, FALSE);

    return TRUE;
}

static int
word_read_macro_entry(int fd, macro_info_t *macro_info)
{
    size_t msize;
    uint16_t count = macro_info->count;
    macro_entry_t *macro_entry;
#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif
    struct macro {
        unsigned char version;
        unsigned char key;
        unsigned char ignore[10];
        uint32_t len __attribute__((packed));
        uint32_t state __attribute__((packed));
        uint32_t offset __attribute__((packed));
    } *m;
    const struct macro *n;
#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif
    if (count == 0)
        return TRUE;

    msize = count * sizeof(struct macro);
    m     = cli_max_malloc(msize);
    if (m == NULL) {
        cli_errmsg("word_read_macro_entry: Unable to allocate memory for 'm'\n");
        return FALSE;
    }

    if (cli_readn(fd, m, msize) != msize) {
        free(m);
        cli_warnmsg("read %u macro_entries failed\n", count);
        return FALSE;
    }
    macro_entry = macro_info->entries;
    n           = m;
    do {
        macro_entry->key    = n->key;
        macro_entry->len    = vba_endian_convert_32(n->len, FALSE);
        macro_entry->offset = vba_endian_convert_32(n->offset, FALSE);
        macro_entry++;
        n++;
    } while (--count > 0);
    free(m);
    return TRUE;
}

static macro_info_t *
word_read_macro_info(int fd, macro_info_t *macro_info)
{
    if (!read_uint16(fd, &macro_info->count, FALSE)) {
        cli_dbgmsg("read macro_info failed\n");
        macro_info->count = 0;
        return NULL;
    }
    cli_dbgmsg("macro count: %d\n", macro_info->count);
    if (macro_info->count == 0)
        return NULL;
    macro_info->entries = (macro_entry_t *)cli_max_malloc(sizeof(macro_entry_t) * macro_info->count);
    if (macro_info->entries == NULL) {
        macro_info->count = 0;
        cli_errmsg("word_read_macro_info: Unable to allocate memory for macro_info->entries\n");
        return NULL;
    }
    if (!word_read_macro_entry(fd, macro_info)) {
        free(macro_info->entries);
        macro_info->entries = NULL;
        macro_info->count = 0;
        return NULL;
    }
    return macro_info;
}

static int
word_skip_oxo3(int fd)
{
    uint8_t count;

    if (cli_readn(fd, &count, 1) != 1) {
        cli_dbgmsg("read oxo3 record1 failed\n");
        return FALSE;
    }
    cli_dbgmsg("oxo3 records1: %d\n", count);

    if (!seekandread(fd, count * 14, SEEK_CUR, &count, 1)) {
        cli_dbgmsg("read oxo3 record2 failed\n");
        return FALSE;
    }

    if (count == 0) {
        uint8_t twobytes[2];

        if (cli_readn(fd, twobytes, 2) != 2) {
            cli_dbgmsg("read oxo3 failed\n");
            return FALSE;
        }
        if (twobytes[0] != 2) {
            lseek(fd, -2, SEEK_CUR);
            return TRUE;
        }
        count = twobytes[1];
    }
    if (count > 0)
        if (lseek(fd, (count * 4) + 1, SEEK_CUR) == -1) {
            cli_dbgmsg("lseek oxo3 failed\n");
            return FALSE;
        }

    cli_dbgmsg("oxo3 records2: %d\n", count);
    return TRUE;
}

static int
word_skip_menu_info(int fd)
{
    uint16_t count;

    if (!read_uint16(fd, &count, FALSE)) {
        cli_dbgmsg("read menu_info failed\n");
        return FALSE;
    }
    cli_dbgmsg("menu_info count: %d\n", count);

    if (count)
        if (lseek(fd, count * 12, SEEK_CUR) == -1)
            return FALSE;
    return TRUE;
}

static int
word_skip_macro_extnames(int fd)
{
    int is_unicode, nbytes;
    int16_t size;

    if (!read_uint16(fd, (uint16_t *)&size, FALSE)) {
        cli_dbgmsg("read macro_extnames failed\n");
        return FALSE;
    }
    if (size == -1) { /* Unicode flag */
        if (!read_uint16(fd, (uint16_t *)&size, FALSE)) {
            cli_dbgmsg("read macro_extnames failed\n");
            return FALSE;
        }
        is_unicode = 1;
    } else
        is_unicode = 0;

    cli_dbgmsg("ext names size: 0x%x\n", size);

    nbytes = size;
    while (nbytes > 0) {
        uint8_t length;
        off_t offset;

        if (cli_readn(fd, &length, 1) != 1) {
            cli_dbgmsg("read macro_extnames failed\n");
            return FALSE;
        }

        if (is_unicode)
            offset = (off_t)length * 2 + 1;
        else
            offset = (off_t)length;

        /* ignore numref as well */
        if (lseek(fd, offset + sizeof(uint16_t), SEEK_CUR) == -1) {
            cli_dbgmsg("read macro_extnames failed to seek\n");
            return FALSE;
        }
        nbytes -= size;
    }
    return TRUE;
}

static int
word_skip_macro_intnames(int fd)
{
    uint16_t count;

    if (!read_uint16(fd, &count, FALSE)) {
        cli_dbgmsg("read macro_intnames failed\n");
        return FALSE;
    }
    cli_dbgmsg("intnames count: %u\n", (unsigned int)count);

    while (count-- > 0) {
        uint8_t length;

        /* id */
        if (!seekandread(fd, sizeof(uint16_t), SEEK_CUR, &length, sizeof(uint8_t))) {
            cli_dbgmsg("skip_macro_intnames failed\n");
            return FALSE;
        }

        /* Internal name, plus one byte of unknown data */
        if (lseek(fd, length + 1, SEEK_CUR) == -1) {
            cli_dbgmsg("skip_macro_intnames failed\n");
            return FALSE;
        }
    }
    return TRUE;
}

vba_project_t *
cli_wm_readdir(int fd)
{
    int done;
    off_t end_offset;
    unsigned char info_id;
    macro_info_t macro_info;
    vba_project_t *vba_project;
    mso_fib_t fib;

    if (!word_read_fib(fd, &fib))
        return NULL;

    if (fib.macro_len == 0) {
        cli_dbgmsg("wm_readdir: No macros detected\n");
        /* Must be clean */
        return NULL;
    }
    cli_dbgmsg("wm_readdir: macro offset: 0x%.4x\n", (int)fib.macro_offset);
    cli_dbgmsg("wm_readdir: macro len: 0x%.4x\n\n", (int)fib.macro_len);

    /* Go one past the start to ignore start_id */
    if (lseek(fd, fib.macro_offset + 1, SEEK_SET) != (off_t)(fib.macro_offset + 1)) {
        cli_dbgmsg("wm_readdir: lseek macro_offset failed\n");
        return NULL;
    }

    end_offset         = fib.macro_offset + fib.macro_len;
    done               = FALSE;
    macro_info.entries = NULL;
    macro_info.count   = 0;

    while ((lseek(fd, 0, SEEK_CUR) < end_offset) && !done) {
        if (cli_readn(fd, &info_id, 1) != 1) {
            cli_dbgmsg("wm_readdir: read macro_info failed\n");
            break;
        }
        switch (info_id) {
            case 0x01:
                if (macro_info.count)
                    free(macro_info.entries);
                word_read_macro_info(fd, &macro_info);
                done = TRUE;
                break;
            case 0x03:
                if (!word_skip_oxo3(fd))
                    done = TRUE;
                break;
            case 0x05:
                if (!word_skip_menu_info(fd))
                    done = TRUE;
                break;
            case 0x10:
                if (!word_skip_macro_extnames(fd))
                    done = TRUE;
                break;
            case 0x11:
                if (!word_skip_macro_intnames(fd))
                    done = TRUE;
                break;
            case 0x40: /* end marker */
            case 0x12: /* ??? */
                done = TRUE;
                break;
            default:
                cli_dbgmsg("wm_readdir: unknown type: 0x%x\n", info_id);
                done = TRUE;
        }
    }

    if (macro_info.count == 0)
        return NULL;

    vba_project = create_vba_project(macro_info.count, "", NULL);

    if (vba_project) {
        vba_project->length = (uint32_t *)cli_max_malloc(sizeof(uint32_t) * macro_info.count);
        vba_project->key    = (unsigned char *)cli_max_malloc(sizeof(unsigned char) * macro_info.count);
        if ((vba_project->length != NULL) &&
            (vba_project->key != NULL)) {
            int i;
            const macro_entry_t *m = macro_info.entries;

            for (i = 0; i < macro_info.count; i++) {
                vba_project->offset[i] = m->offset;
                vba_project->length[i] = m->len;
                vba_project->key[i]    = m->key;
                m++;
            }
        } else {
            cli_errmsg("cli_wm_readdir: Unable to allocate memory for vba_project\n");
            free(vba_project->name);
            free(vba_project->colls);
            free(vba_project->dir);
            free(vba_project->offset);
            if (vba_project->length)
                free(vba_project->length);
            if (vba_project->key)
                free(vba_project->key);
            free(vba_project);
            vba_project = NULL;
        }
    }
    free(macro_info.entries);

    return vba_project;
}

unsigned char *
cli_wm_decrypt_macro(int fd, off_t offset, uint32_t len, unsigned char key)
{
    unsigned char *buff;

    if (len == 0)
        return NULL;

    if (fd < 0)
        return NULL;

    buff = (unsigned char *)cli_max_malloc(len);
    if (buff == NULL) {
        cli_errmsg("cli_wm_decrypt_macro: Unable to allocate memory for buff\n");
        return NULL;
    }

    if (!seekandread(fd, offset, SEEK_SET, buff, len)) {
        free(buff);
        return NULL;
    }
    if (key) {
        unsigned char *p;

        for (p = buff; p < &buff[len]; p++)
            *p ^= key;
    }
    return buff;
}

/**
 * @brief Keep reading bytes until we reach a NUL.
 *
 * @param fd   File descriptor
 * @return int Returns FALSE if none is found, else TRUE
 */
static int skip_past_nul(int fd)
{
    char *end;
    char smallbuf[128];

    do {
        size_t nread = cli_readn(fd, smallbuf, sizeof(smallbuf));
        if ((nread == 0) || (nread == (size_t)-1))
            return FALSE;
        end = memchr(smallbuf, '\0', nread);
        if (end) {
            if (lseek(fd, 1 + (end - smallbuf) - (off_t)nread, SEEK_CUR) < 0)
                return FALSE;
            return TRUE;
        }
    } while (1);
}

/*
 * Read 2 bytes as a 16-bit number, host byte order. Return success or fail
 */
static int
read_uint16(int fd, uint16_t *u, int big_endian)
{
    if (cli_readn(fd, u, sizeof(uint16_t)) != sizeof(uint16_t))
        return FALSE;

    *u = vba_endian_convert_16(*u, big_endian);

    return TRUE;
}

/*
 * Read 4 bytes as a 32-bit number, host byte order. Return success or fail
 */
static int
read_uint32(int fd, uint32_t *u, int big_endian)
{
    if (cli_readn(fd, u, sizeof(uint32_t)) != sizeof(uint32_t))
        return FALSE;

    *u = vba_endian_convert_32(*u, big_endian);

    return TRUE;
}

/*
 * Miss some bytes then read a bit
 */
static int
seekandread(int fd, off_t offset, int whence, void *data, size_t len)
{
    if (lseek(fd, offset, whence) == (off_t)-1) {
        cli_dbgmsg("lseek failed\n");
        return FALSE;
    }
    return cli_readn(fd, data, len) == len;
}

/*
 * Create and initialise a vba_project structure
 */
static vba_project_t *
create_vba_project(int record_count, const char *dir, struct uniq *U)
{
    vba_project_t *ret;

    ret = (vba_project_t *)calloc(1, sizeof(struct vba_project_tag));

    if (ret == NULL) {
        cli_errmsg("create_vba_project: Unable to allocate memory for vba project structure\n");
        return NULL;
    }

    ret->name   = (char **)cli_max_malloc(sizeof(char *) * record_count);
    ret->colls  = (uint32_t *)cli_max_malloc(sizeof(uint32_t) * record_count);
    ret->dir    = cli_safer_strdup(dir);
    ret->offset = (uint32_t *)cli_max_malloc(sizeof(uint32_t) * record_count);

    if ((ret->colls == NULL) || (ret->name == NULL) || (ret->dir == NULL) || (ret->offset == NULL)) {
        cli_free_vba_project(ret);
        cli_errmsg("create_vba_project: Unable to allocate memory for vba project elements\n");
        return NULL;
    }
    ret->count = record_count;
    ret->U     = U;

    return ret;
}

/**
 * @brief Free up the memory associated with the vba_project_t type.
 *
 * @param project A vba_project_t type allocated by one of these:
 *  - create_vba_project()
 *  - cli_wm_readdir()
 *  - cli_vba_readdir()
 */
void cli_free_vba_project(vba_project_t *vba_project)
{
    if (vba_project) {
        if (vba_project->dir)
            free(vba_project->dir);
        if (vba_project->colls)
            free(vba_project->colls);
        if (vba_project->name)
            free(vba_project->name);
        if (vba_project->offset)
            free(vba_project->offset);
        if (vba_project->length)
            free(vba_project->length);
        if (vba_project->key)
            free(vba_project->key);
        free(vba_project);
    }

    return;
}
