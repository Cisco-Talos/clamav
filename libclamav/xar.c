/*
 *  Copyright (C) 2013 Sourcefire, Inc.
 *
 *  Authors: Steven Morgan <smorgan@sourcefire.com>
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

#include <errno.h>
#include "xar.h"
#include "fmap.h"
#if HAVE_LIBXML2
#include <libxml/xmlreader.h>
#include "scanners.h"
#include "inflate64.h"
#include "lzma_iface.h"

/*
   xar_cleanup_temp_file - cleanup after cli_gentempfd
   parameters:
     ctx - cli_ctx context pointer
     fd  - fd to close
     tmpname - name of file to unlink, address of storage to free
   returns - CL_SUCCESS or CL_EUNLINK
 */
static int xar_cleanup_temp_file(cli_ctx *ctx, int fd, char * tmpname)
{
    int rc = CL_SUCCESS;
    close(fd);
    if(!ctx->engine->keeptmp) {
        if (cli_unlink(tmpname)) {
            cli_errmsg("cli_scanxar: error unlinking tmpfile %s\n", tmpname); 
            rc = CL_EUNLINK;
        }
    }
    free(tmpname);
    return rc;
}

/*
   xar_get_numeric_from_xml_element - extract xml element value as numeric
   parameters:
     reader - xmlTextReaderPtr
     value - pointer to long to contain the returned value
   returns - CL_SUCCESS or CL_EFORMAT
 */
static int xar_get_numeric_from_xml_element(xmlTextReaderPtr reader, long * value)
{
    if (xmlTextReaderRead(reader) == 1 && xmlTextReaderNodeType(reader) == XML_READER_TYPE_TEXT) {
        *value = atol((const char *)xmlTextReaderConstValue(reader));
        if (*value < 0) {
            cli_errmsg("cli_scanxar: XML element value %li\n", *value);
            return CL_EFORMAT;
        }
        return CL_SUCCESS;
    }
    cli_errmsg("cli_scanxar: No text for XML element\n");
    return CL_EFORMAT;
}

/*
   xar_get_toc_data_values - return the values of a <data> or <ea> xml element that represent 
                             an extent of data on the heap.
   parameters:
     reader - xmlTextReaderPtr
     length - pointer to long for returning value of the <length> element.
     offset - pointer to long for returning value of the <offset> element.
     size - pointer to long for returning value of the <size> element.
     encoding - pointer to int for returning indication of the <encoding> style attribute.
   returns - CL_FORMAT, CL_SUCCESS, CL_BREAK. CL_BREAK indicates no more <data>/<ea> element.
 */
static int xar_get_toc_data_values(xmlTextReaderPtr reader, long *length, long *offset, long *size, int *encoding)
{
    const xmlChar *name;
    int indata = 0, inea = 0;
    int rc, gotoffset=0, gotlength=0, gotsize=0;

    rc = xmlTextReaderRead(reader);
    while (rc == 1) {
        name = xmlTextReaderConstLocalName(reader);
        if (indata || inea) {
            /*  cli_dbgmsg("cli_scanxar: xmlTextReaderRead read %s\n", name); */
            if (xmlStrEqual(name, (const xmlChar *)"offset") && 
                xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
                if (CL_SUCCESS == xar_get_numeric_from_xml_element(reader, offset))
                    gotoffset=1;
            } else if (xmlStrEqual(name, (const xmlChar *)"length") &&
                       xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
                if (CL_SUCCESS == xar_get_numeric_from_xml_element(reader, length))
                    gotlength=1;

            } else if (xmlStrEqual(name, (const xmlChar *)"size") &&
                       xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
                if (CL_SUCCESS == xar_get_numeric_from_xml_element(reader, size))
                    gotsize=1;

            } else if (xmlStrEqual(name, (const xmlChar *)"encoding") &&
                       xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
                xmlChar * style;
                style = xmlTextReaderGetAttribute(reader, (const xmlChar *)"style");
                if (style == NULL) {
                    cli_errmsg("cli_scaxar: xmlTextReaderGetAttribute no style attribute "
                               "for encoding element\n");
                    *encoding = CL_TYPE_ANY;
                } else if (xmlStrEqual(style, (const xmlChar *)"application/x-gzip")) {
                    cli_dbgmsg("cli_scanxar: encoding = application/x-gzip.\n");
                    *encoding = CL_TYPE_GZ; 
                } else if (xmlStrEqual(style, (const xmlChar *)"application/octet-stream")) {
                    cli_dbgmsg("cli_scanxar: encoding = application/octet-stream.\n");
                    *encoding = CL_TYPE_ANY; 
                } else if (xmlStrEqual(style, (const xmlChar *)"application/x-bzip2")) {
                    cli_dbgmsg("cli_scanxar: encoding = application/x-bzip2.\n");
                    *encoding = CL_TYPE_BZ;
                } else if (xmlStrEqual(style, (const xmlChar *)"application/x-lzma")) {
                    cli_dbgmsg("cli_scanxar: encoding = application/x-lzma.\n");
                    *encoding = CL_TYPE_7Z;
                 } else if (xmlStrEqual(style, (const xmlChar *)"application/x-xz")) {
                    cli_dbgmsg("cli_scanxar: encoding = application/x-xz.\n");
                    *encoding = CL_TYPE_7Z;
                } else {
                    cli_errmsg("cli_scaxar: unknown style value=%s for encoding element\n", style);
                    *encoding = CL_TYPE_ANY;
                }
            } else if (indata && xmlStrEqual(name, (const xmlChar *)"data") &&
                       xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT) {
                break;
            } else if (inea && xmlStrEqual(name, (const xmlChar *)"ea") &&
                       xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT) {
                break;
            }
        } else {
            if (xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
                if (xmlStrEqual(name, (const xmlChar *)"data")) {
                    cli_dbgmsg("cli_scanxar: xmlTextReaderRead read <data>\n");
                    indata = 1;
                } else if (xmlStrEqual(name, (const xmlChar *)"ea")) {
                    cli_dbgmsg("cli_scanxar: xmlTextReaderRead read <ea>\n");
                    inea = 1;
                }
            } else if ((xmlTextReaderNodeType(reader) == XML_READER_TYPE_END_ELEMENT) &&
                       xmlStrEqual(name, (const xmlChar *)"xar")) {
                cli_dbgmsg("cli_scanxar: finished parsing xar TOC.\n");   
            }
        }
        rc = xmlTextReaderRead(reader);
    }
    
    if (gotoffset && gotlength && gotsize) {
        rc = CL_SUCCESS;
    }
    else if (0 == gotoffset + gotlength + gotsize)
        rc = CL_BREAK;
    else
        rc = CL_EFORMAT;

    return rc;
}

#endif
/*
  cli_scanxar - scan an xar archive.
  Parameters:
    ctx - pointer to cli_ctx.
  returns - CL_SUCCESS or CL_ error code.
*/

int cli_scanxar(cli_ctx *ctx)
{
    int rc = CL_SUCCESS;
#if HAVE_LIBXML2
    int fd = -1;
    struct xar_header hdr;
    fmap_t *map = *ctx->fmap;
    long length, offset, size, at;
    int encoding;
    z_stream strm = {0};
    char *toc, *tmpname;
    xmlTextReaderPtr reader = NULL;

    /* retrieve xar header */
    if (fmap_readn(*ctx->fmap, &hdr, 0, sizeof(hdr)) != sizeof(hdr)) {
        cli_errmsg("cli_scanxar: Invalid header, too short.\n");
        return CL_EFORMAT;
    }
    hdr.magic = be32_to_host(hdr.magic);

    if (hdr.magic == XAR_HEADER_MAGIC) {
        cli_dbgmsg("cli_scanxar: Matched magic\n");
    }
    else {
        cli_errmsg("cli_scanxar: Invalid magic\n");
        return CL_EFORMAT;
    }
    hdr.size = be16_to_host(hdr.size);
    hdr.version = be16_to_host(hdr.version);
    hdr.toc_length_compressed = be64_to_host(hdr.toc_length_compressed);
    hdr.toc_length_decompressed = be64_to_host(hdr.toc_length_decompressed);
    hdr.chksum_alg = be32_to_host(hdr.chksum_alg);

    /* cli_dbgmsg("hdr.magic %x\n", hdr.magic); */
    /* cli_dbgmsg("hdr.size %i\n", hdr.size); */
    /* cli_dbgmsg("hdr.version %i\n", hdr.version); */
    /* cli_dbgmsg("hdr.toc_length_compressed %lu\n", hdr.toc_length_compressed); */
    /* cli_dbgmsg("hdr.toc_length_decompressed %lu\n", hdr.toc_length_decompressed); */
    /* cli_dbgmsg("hdr.chksum_alg %i\n", hdr.chksum_alg); */
 
    /* Uncompress TOC */
    strm.next_in = (unsigned char *)fmap_need_off_once(*ctx->fmap, hdr.size, hdr.toc_length_compressed);
    if (strm.next_in == NULL) {
        cli_errmsg("cli_scanxar: fmap_need_off_once fails on TOC.\n");
        return CL_EFORMAT;
    }
    strm.avail_in = hdr.toc_length_compressed; 
    toc = cli_malloc(hdr.toc_length_decompressed+1);
    if (toc == NULL) {
        cli_errmsg("cli_scanxar: cli_malloc fails on TOC decompress buffer.\n");
        return CL_EMEM;
    }
    toc[hdr.toc_length_decompressed] = '\0';
    strm.avail_out = hdr.toc_length_decompressed;
    strm.next_out = (unsigned char *)toc;
    rc = inflateInit(&strm);
    if (rc != Z_OK) {
        cli_errmsg("cli_scanxar:inflateInit error %i \n", rc);
        rc = CL_EFORMAT;
        goto exit_toc;
    }    
    rc = inflate(&strm, Z_SYNC_FLUSH);
    if (rc != Z_OK && rc != Z_STREAM_END) {
        cli_errmsg("cli_scanxar:inflate error %i \n", rc);
        rc = CL_EFORMAT;
        goto exit_toc;
    }
    rc = inflateEnd(&strm);
    if (rc != Z_OK) {
        cli_errmsg("cli_scanxar:inflateEnd error %i \n", rc);
        rc = CL_EFORMAT;
        goto exit_toc;
    }

    /* cli_dbgmsg("cli_scanxar: TOC xml:\n%s\n", toc); */
    /* printf("cli_scanxar: TOC xml:\n%s\n", toc); */
    /* cli_dbgmsg("cli_scanxar: TOC end:\n"); */
    /* printf("cli_scanxar: TOC end:\n"); */

    /* scan the xml */
    cli_dbgmsg("cli_scanxar: scanning xar TOC xml.\n"); 
    rc = cli_mem_scandesc(toc, hdr.toc_length_decompressed, ctx);
    if (rc != CL_SUCCESS) {
        if (rc != CL_VIRUS || !SCAN_ALL)
            goto exit_toc;        
    }

    /* make a file to leave if --leave-temps in effect */
    if(ctx->engine->keeptmp) {
        if ((rc = cli_gentempfd(ctx->engine->tmpdir, &tmpname, &fd)) != CL_SUCCESS) {
            cli_errmsg("cli_scanxar: Can't create temporary file for TOC.\n");
            goto exit_toc;
        }
        if (cli_writen(fd, toc, hdr.toc_length_decompressed) < 0) {
            cli_errmsg("cli_scanxar: cli_writen error writing TOC.\n");
            rc = CL_EWRITE;
            xar_cleanup_temp_file(ctx, fd, tmpname);
            goto exit_toc;
        }
        rc = xar_cleanup_temp_file(ctx, fd, tmpname);
        if (rc != CL_SUCCESS)
            goto exit_toc;
    }

    /*TODO: subdocuments*/

    reader = xmlReaderForMemory(toc, hdr.toc_length_decompressed, "noname.xml", NULL, 0);
    if (reader == NULL) {
        cli_errmsg("cli_scanxar: xmlReaderForMemory error for TOC\n");
        goto exit_toc;
    }

    /* Walk the TOC XML and extract files */
    fd = -1;
    tmpname = NULL;
    while (CL_SUCCESS == (rc = xar_get_toc_data_values(reader, &length, &offset, &size, &encoding))) {
        char * blockp;

        /* clean up temp file from previous loop iteration */
        if (fd > -1 && tmpname) {
            rc = xar_cleanup_temp_file(ctx, fd, tmpname);
            if (rc != CL_SUCCESS)
                goto exit_reader;
        }

        at = offset + hdr.toc_length_compressed + hdr.size;

        if ((rc = cli_gentempfd(ctx->engine->tmpdir, &tmpname, &fd)) != CL_SUCCESS) {
            cli_errmsg("cli_scanxar: Can't generate temporary file.\n");
            goto exit_reader;
        }

        cli_dbgmsg("cli_scanxar: decompress into temp file:\n%s, size %li,\n"
                   "from xar heap offset %li length %li\n",
                   tmpname, size, offset, length);

        switch (encoding) {
        case CL_TYPE_GZ:
            /* inflate gzip directly because file segments do not contain magic */
            memset(&strm, 0, sizeof(strm));
            if ((rc = inflateInit(&strm)) != Z_OK) {
                cli_errmsg("cli_scanxar: InflateInit failed: %d\n", rc);
                rc = CL_EFORMAT;
                goto exit_tmpfile;
            }
            
            while (at < map->len && at < offset+hdr.toc_length_compressed+hdr.size+length) {
                unsigned int bytes = MIN(map->len - at, map->pgsz);
                bytes = MIN(length, bytes);
                cli_dbgmsg("cli_scanxar: fmap %u bytes\n", bytes);
                if(!(strm.next_in = (void*)fmap_need_off_once(map, at, bytes))) {
                    cli_dbgmsg("cli_scanxar: Can't read %u bytes @ %lu.\n", bytes, (long unsigned)at);
                    inflateEnd(&strm);
                    rc = CL_EREAD;
                    goto exit_tmpfile;
                }
                at += bytes;
                strm.avail_in = bytes;
                do {
                    int inf, outsize = 0;
                    unsigned char buff[FILEBUFF];
                    strm.avail_out = sizeof(buff);
                    strm.next_out = buff;
                    cli_dbgmsg("cli_scanxar: inflating.....\n");
                    inf = inflate(&strm, Z_SYNC_FLUSH);
                    if (inf != Z_OK && inf != Z_STREAM_END && inf != Z_BUF_ERROR) {
                        cli_errmsg("cli_scanxar: inflate error %i %s.\n", inf, strm.msg?strm.msg:"");
                        at = map->len;
                        rc = CL_EFORMAT;
                        goto exit_tmpfile;
                    }
                    if (cli_writen(fd, buff, sizeof(buff) - strm.avail_out) < 0) {
                        cli_errmsg("cli_scanxar: cli_writen error file %s.\n", tmpname);
                        inflateEnd(&strm);
                        rc = CL_EWRITE;
                        goto exit_tmpfile;
                    }
                    outsize += sizeof(buff) - strm.avail_out;
                    if (cli_checklimits("cli_scanxar", ctx, outsize, 0, 0) != CL_CLEAN) {
                        break;
                    }
                    if (inf == Z_STREAM_END) {
                        break;
                    }
                } while (strm.avail_out == 0);
            }
            
            inflateEnd(&strm);
            break;
        case CL_TYPE_7Z:
            {
#define CLI_LZMA_OBUF_SIZE 1024*1024
#define CLI_LZMA_HDR_SIZE LZMA_PROPS_SIZE+8
#define CLI_LZMA_CRATIO_SHIFT 2 /* estimated compression ratio 25% */
                struct CLI_LZMA lz = {0};
                unsigned long in_remaining = length;
                unsigned long out_size = 0;
                char * buff = __lzma_wrap_alloc(NULL, CLI_LZMA_OBUF_SIZE);
                
                if (buff == NULL) {
                    cli_errmsg("cli_scanxar: memory request for lzma decompression buffer fails.\n");
                    rc = CL_EMEM;
                    goto exit_tmpfile;
                    
                }

                blockp = (void*)fmap_need_off_once(map, at, CLI_LZMA_HDR_SIZE);
                if (blockp == NULL) {
                    cli_errmsg("cli_scanxar: Can't read %li bytes @ %li, errno:%s.\n",
                               length, at, strerror(errno));
                    rc = CL_EREAD;
                    __lzma_wrap_free(NULL, buff);
                    goto exit_tmpfile;
                }

                lz.next_in = blockp;
                lz.avail_in = CLI_LZMA_HDR_SIZE;

                rc = cli_LzmaInit(&lz, 0);
                if (rc != LZMA_RESULT_OK) {
                    cli_errmsg("cli_scanxar: cli_LzmaInit() fails: %i.\n", rc);
                    rc = CL_EFORMAT;
                    __lzma_wrap_free(NULL, buff);
                    goto exit_tmpfile;
                }
                
                at += CLI_LZMA_HDR_SIZE;
                in_remaining -= CLI_LZMA_HDR_SIZE;                
                while (at < map->len && at < offset+hdr.toc_length_compressed+hdr.size+length) {
                    SizeT avail_in;
                    SizeT avail_out;
                    unsigned long in_consumed;

                    lz.next_out = buff;
                    lz.avail_out = CLI_LZMA_OBUF_SIZE;
                    lz.avail_in = avail_in = MIN(CLI_LZMA_OBUF_SIZE>>CLI_LZMA_CRATIO_SHIFT, in_remaining);
                    lz.next_in = (void*)fmap_need_off_once(map, at, lz.avail_in);
                    if (lz.next_in == NULL) {
                        cli_errmsg("cli_scanxar: Can't read %li bytes @ %li, errno: %s.\n",
                                   length, at, strerror(errno));
                        rc = CL_EREAD;
                        __lzma_wrap_free(NULL, buff);
                        cli_LzmaShutdown(&lz);
                        goto exit_tmpfile;
                    }

                    rc = cli_LzmaDecode(&lz);
                    if (rc != LZMA_RESULT_OK && rc != LZMA_STREAM_END) {
                        cli_errmsg("cli_scanxar: cli_LzmaDecode() fails: %i.\n", rc);
                        rc = CL_EFORMAT;
                        __lzma_wrap_free(NULL, buff);
                        cli_LzmaShutdown(&lz);
                        goto exit_tmpfile;
                    }

                    in_consumed = avail_in - lz.avail_in;
                    in_remaining -= in_consumed;
                    at += in_consumed;
                    avail_out = CLI_LZMA_OBUF_SIZE - lz.avail_out;
                    
                    if (avail_out == 0) {
                        cli_errmsg("cli_scanxar: cli_LzmaDecode() produces no output for "
                                   "avail_in %lu, avail_out %lu.\n", avail_in, avail_out);
                        rc = CL_EFORMAT;
                        __lzma_wrap_free(NULL, buff);
                        cli_LzmaShutdown(&lz);
                        goto exit_tmpfile;
                    }
                    
                    /* Write a decompressed block. */
                    cli_dbgmsg("Writing %li bytes to LZMA decompress temp file, "
                               "consumed %li of %li available bytes.\n",
                               avail_out, in_consumed, avail_in);
                    
                    if (cli_writen(fd, buff, avail_out) < 0) {
                        cli_dbgmsg("cli_scanxar: cli_writen error writing lzma temp file for %li bytes.\n",
                                   avail_out);
                        __lzma_wrap_free(NULL, buff);
                        cli_LzmaShutdown(&lz);
                        rc = CL_EWRITE;
                        goto exit_tmpfile;
                    }
                    
                    /* Check file size limitation. */
                    out_size += avail_out;
                    if (cli_checklimits("cli_scanxar", ctx, out_size, 0, 0) != CL_CLEAN) {
                        break;
                    }
                    
                    if (rc == LZMA_STREAM_END)
                        break;
                }

                cli_LzmaShutdown(&lz);
                __lzma_wrap_free(NULL, buff);
            }
            break; 
        default:
        case CL_TYPE_BZ:
        case CL_TYPE_ANY:
            /* for uncompressed, bzip2, and unknown, just pull the file, cli_magic_scandesc does the rest */
            if (!(blockp = (void*)fmap_need_off_once(map, at, length))) {
                cli_errmsg("cli_scanxar: Can't read %li bytes @ %li, errno:%s.\n", length, at, strerror(errno));
                rc = CL_EREAD;
                goto exit_tmpfile;
            }
            
            if (cli_writen(fd, blockp, length) < 0) {
                cli_dbgmsg("cli_scanxar: cli_writen error %li bytes @ %li.\n", length, at);
                rc = CL_EWRITE;
                goto exit_tmpfile;
            }
            /*break;*/           
        }

        rc = cli_magic_scandesc(fd, ctx);
        if (rc != CL_SUCCESS) {
            if (rc == CL_VIRUS) {
                cli_dbgmsg("cli_scanxar: Infected with %s\n", cli_get_last_virus(ctx));
                if (!SCAN_ALL)
                    goto exit_tmpfile;
            } else if (rc != CL_BREAK) {
                cli_errmsg("cli_scanxar: cli_magic_scandesc error %i\n", rc);
                goto exit_tmpfile;
            }
        }
   }

 exit_tmpfile:
    xar_cleanup_temp_file(ctx, fd, tmpname);

 exit_reader:
    xmlFreeTextReader(reader);
    xmlCleanupParser();

 exit_toc:
    free(toc);
    if (rc == CL_BREAK)
        rc = CL_SUCCESS;
#else
    cli_dbgmsg("cli_scanxar: can't scan xar files, need libxml2.\n");
#endif

    return rc;
}
