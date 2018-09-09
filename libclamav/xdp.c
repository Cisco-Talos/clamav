/*
 *  Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
 *
 *  Author: Shawn Webb
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
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif
#include <errno.h>
#include "xar.h"
#include "fmap.h"
#if HAVE_LIBXML2
#include <libxml/xmlreader.h>
#endif
#include "clamav.h"
#include "str.h"
#include "scanners.h"
#include "conv.h"
#include "xdp.h"
#include "bignum_fast.h"
#include "filetypes.h"

static char *dump_xdp(cli_ctx *ctx, const char *start, size_t sz);

static char *dump_xdp(cli_ctx *ctx, const char *start, size_t sz)
{
    int fd;
    char *filename;
    size_t nwritten=0;
    ssize_t writeret;

    if (cli_gentempfd(ctx->engine->tmpdir, &filename, &fd) != CL_SUCCESS)
        return NULL;

    while (nwritten < sz) {
        writeret = write(fd, start+nwritten, sz-nwritten);
        if (writeret < 0) {
            if (errno == EAGAIN)
                continue;

            close(fd);
            cli_unlink(filename);
            free(filename);

            return NULL;
        }

        nwritten += writeret;
    }

    cli_dbgmsg("dump_xdp: Dumped payload to %s\n", filename);

    close(fd);

    return filename;
}

int cli_scanxdp(cli_ctx *ctx)
{
#if HAVE_LIBXML2
    xmlTextReaderPtr reader = NULL;
    fmap_t *map = *(ctx->fmap);
    const char *buf;
    const xmlChar *name, *value;
    char *decoded;
    size_t decodedlen;
    int rc = CL_SUCCESS;
    char *dumpname;
    size_t i;
    
    buf = (const char *)fmap_need_off_once(map, map->offset, map->len);
    if (!(buf))
        return CL_EREAD;

    if (ctx->engine->keeptmp) {
        dumpname = dump_xdp(ctx, buf, map->len);
        if (dumpname)
            free(dumpname);
    }

    /*
     * Since a PDF file can contain embedded XDP documents,
     * it's possible that the filetyping code matched an embedded XDP document.
     * If that's the case, then xmlReaderForMemory will throw an error. For now,
     * silently ignore the error and return CL_SUCCESS so the filetyping code can
     * continue on.
     */
    reader = xmlReaderForMemory(buf, (int)(map->len), "noname.xml", NULL, CLAMAV_MIN_XMLREADER_FLAGS);
    if (!(reader))
        return CL_SUCCESS;

    while (xmlTextReaderRead(reader) == 1) {
        name = xmlTextReaderConstLocalName(reader);
        if (!(name))
            continue;

        if (!strcmp((const char *)name, "chunk") && xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
            value = xmlTextReaderReadInnerXml(reader);
            if (value) {
                decoded = cl_base64_decode((char *)value, strlen((const char *)value), NULL, &decodedlen, 0);
                if (decoded) {
                    unsigned int shouldscan=0;

                    if (decodedlen > 5) {
                        for (i=0; i < MIN(MAGIC_BUFFER_SIZE, decodedlen-5); i++) {
                            if (decoded[i] != '%')
                                continue;

                            if (decoded[i+1] == 'P' || decoded[i+1] == 'p') {
                                if (decoded[i+2] == 'D' || decoded[i+2] == 'd') {
                                    if (decoded[i+3] == 'F' || decoded[i+3] == 'f') {
                                        if (decoded[i+4] == '-') {
                                            shouldscan=1;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (!shouldscan) {
                        free(decoded);
                        xmlFree((void *)value);
                        break;
                    }

                    rc = cli_mem_scandesc(decoded, decodedlen, ctx);
                    free(decoded);
                    if (rc != CL_SUCCESS || rc == CL_BREAK) {
                        xmlFree((void *)value);
                        break;
                    }
                }

                xmlFree((void *)value);
            }
        }
    }

    xmlFreeTextReader(reader);

    return rc;
#else
    return CL_SUCCESS;
#endif
}
