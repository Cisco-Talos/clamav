/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#include "clamav.h"
#include "str.h"
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
    if (fd > -1)
        close(fd);
    if (tmpname != NULL) {
        if (!ctx->engine->keeptmp) {
            if (cli_unlink(tmpname)) {
                cli_dbgmsg("cli_scanxar: error unlinking tmpfile %s\n", tmpname); 
                rc = CL_EUNLINK;
            }
        }
        free(tmpname);
    }
    return rc;
}

/*
   xar_get_numeric_from_xml_element - extract xml element value as numeric
   parameters:
     reader - xmlTextReaderPtr
     value - pointer to long to contain the returned value
   returns - CL_SUCCESS or CL_EFORMAT
 */
static int xar_get_numeric_from_xml_element(xmlTextReaderPtr reader, size_t * value)
{
    const xmlChar * numstr;

    if (xmlTextReaderRead(reader) == 1 && xmlTextReaderNodeType(reader) == XML_READER_TYPE_TEXT) {
        numstr = xmlTextReaderConstValue(reader);
        if (numstr) {
            long numval;
            char *endptr = NULL;
            errno = 0;
            numval = strtol((const char *)numstr, &endptr, 10);
            if (((numval == LONG_MAX || numval == LONG_MIN) && errno) || endptr == numstr) {
                cli_dbgmsg("cli_scanxar: XML element value invalid\n");
                return CL_EFORMAT;
            } else if (numval < 0) {
                cli_dbgmsg("cli_scanxar: XML element value %li\n", numval);
                return CL_EFORMAT;
            }
            *value = numval;
            return CL_SUCCESS;
        }
    }
    cli_dbgmsg("cli_scanxar: No text for XML element\n");
    return CL_EFORMAT;
}

/*
  xar_get_checksum_values - extract checksum and hash algorithm from xml element
  parameters:
    reader - xmlTextReaderPtr
    cksum - pointer to char* for returning checksum value.
    hash - pointer to int for returning checksum algorithm.
  returns - void
 */
static void xar_get_checksum_values(xmlTextReaderPtr reader, unsigned char ** cksum, int * hash)
{
    xmlChar * style = xmlTextReaderGetAttribute(reader, (const xmlChar *)"style");
    const xmlChar * xmlval;

    *hash = XAR_CKSUM_NONE;
    if (style == NULL) {
        cli_dbgmsg("cli_scaxar: xmlTextReaderGetAttribute no style attribute "
                   "for checksum element\n");
    } else {
        cli_dbgmsg("cli_scanxar: checksum algorithm is %s.\n", style);        
        if (0 == xmlStrcasecmp(style, (const xmlChar *)"sha1")) {
            *hash = XAR_CKSUM_SHA1;
        } else if (0 == xmlStrcasecmp(style, (const xmlChar *)"md5")) {
            *hash = XAR_CKSUM_MD5;
        } else {
            cli_dbgmsg("cli_scanxar: checksum algorithm %s is unsupported.\n", style);
            *hash = XAR_CKSUM_OTHER;
        }
    }
    if (style != NULL)
        xmlFree(style);

    if (xmlTextReaderRead(reader) == 1 && xmlTextReaderNodeType(reader) == XML_READER_TYPE_TEXT) {
        xmlval = xmlTextReaderConstValue(reader);
        if (xmlval) {
            cli_dbgmsg("cli_scanxar: checksum value is %s.\n", xmlval);
            if (( (*hash == XAR_CKSUM_SHA1)  &&  (xmlStrlen(xmlval) == 2 * CLI_HASHLEN_SHA1))  ||
                ( (*hash == XAR_CKSUM_MD5)  &&  (xmlStrlen(xmlval) == 2 * CLI_HASHLEN_MD5) ))
                {
                    *cksum = xmlStrdup(xmlval); 
                } 
            else
                {
                    cli_dbgmsg("cli_scanxar: checksum type is unknown or length is invalid.\n");
                    *hash = XAR_CKSUM_OTHER;
                    *cksum = NULL;
                }
        } else {
            *cksum = NULL;
            cli_dbgmsg("cli_scanxar: xmlTextReaderConstValue() returns NULL for checksum value.\n");           
        }
    }
    else
        cli_dbgmsg("cli_scanxar: No text for XML checksum element.\n");
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
     a_cksum - pointer to char* for return archived checksum value.
     a_hash - pointer to int for returning archived checksum algorithm.
     e_cksum - pointer to char* for return extracted checksum value.
     e_hash - pointer to int for returning extracted checksum algorithm.
   returns - CL_FORMAT, CL_SUCCESS, CL_BREAK. CL_BREAK indicates no more <data>/<ea> element.
 */
static int xar_get_toc_data_values(xmlTextReaderPtr reader, size_t *length, size_t *offset, size_t *size, int *encoding,
                                   unsigned char ** a_cksum, int * a_hash, unsigned char ** e_cksum, int * e_hash)
{
    const xmlChar *name;
    int indata = 0, inea = 0;
    int rc, gotoffset=0, gotlength=0, gotsize=0;

    *a_cksum = NULL;
    *a_hash = XAR_CKSUM_NONE;
    *e_cksum = NULL;
    *e_hash = XAR_CKSUM_NONE;
    *encoding = CL_TYPE_ANY;

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

            } else if (xmlStrEqual(name, (const xmlChar *)"archived-checksum") &&
                       xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
                cli_dbgmsg("cli_scanxar: <archived-checksum>:\n");
                xar_get_checksum_values(reader, a_cksum, a_hash);
                
            } else if ((xmlStrEqual(name, (const xmlChar *)"extracted-checksum") ||
                        xmlStrEqual(name, (const xmlChar *)"unarchived-checksum")) &&
                       xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
                cli_dbgmsg("cli_scanxar: <extracted-checksum>:\n");
                xar_get_checksum_values(reader, e_cksum, e_hash);

            } else if (xmlStrEqual(name, (const xmlChar *)"encoding") &&
                       xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
                xmlChar * style = xmlTextReaderGetAttribute(reader, (const xmlChar *)"style");
                if (style == NULL) {
                    cli_dbgmsg("cli_scaxar: xmlTextReaderGetAttribute no style attribute "
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
                    *encoding = CL_TYPE_XZ;
                } else {
                    cli_dbgmsg("cli_scaxar: unknown style value=%s for encoding element\n", style);
                    *encoding = CL_TYPE_ANY;
                }
                if (style != NULL)
                    xmlFree(style);

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
                break;
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

/*
  xar_process_subdocument - check TOC for xml subdocument. If found, extract and
                            scan in memory.
  Parameters:
     reader - xmlTextReaderPtr
     ctx - pointer to cli_ctx
  Returns:
     CL_SUCCESS - subdoc found and clean scan (or virus found and SCAN_ALLMATCHES), or no subdocument
     other - error return code from cli_mem_scandesc()
*/                        
static int xar_scan_subdocuments(xmlTextReaderPtr reader, cli_ctx *ctx)
{
    int rc = CL_SUCCESS, subdoc_len, fd;
    xmlChar * subdoc;
    const xmlChar *name;
    char * tmpname;

    while (xmlTextReaderRead(reader) == 1) {
        name = xmlTextReaderConstLocalName(reader);
        if (name == NULL) {
            cli_dbgmsg("cli_scanxar: xmlTextReaderConstLocalName() no name.\n");
            rc = CL_EFORMAT;
            break;
        }
        if (xmlStrEqual(name, (const xmlChar *)"toc") && 
            xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT)
            return CL_SUCCESS;
        if (xmlStrEqual(name, (const xmlChar *)"subdoc") && 
            xmlTextReaderNodeType(reader) == XML_READER_TYPE_ELEMENT) {
            subdoc = xmlTextReaderReadInnerXml(reader);
            if (subdoc == NULL) {
                cli_dbgmsg("cli_scanxar: no content in subdoc element.\n");
                xmlTextReaderNext(reader);
                continue;
            }
            subdoc_len = xmlStrlen(subdoc);
            cli_dbgmsg("cli_scanxar: in-memory scan of xml subdocument, len %i.\n", subdoc_len);
            rc = cli_mem_scandesc(subdoc, subdoc_len, ctx);
            if (rc == CL_VIRUS && SCAN_ALLMATCHES)
                rc = CL_SUCCESS;
            
            /* make a file to leave if --leave-temps in effect */
            if(ctx->engine->keeptmp) {
                if ((rc = cli_gentempfd(ctx->engine->tmpdir, &tmpname, &fd)) != CL_SUCCESS) {
                    cli_dbgmsg("cli_scanxar: Can't create temporary file for subdocument.\n");
                } else {
                    cli_dbgmsg("cli_scanxar: Writing subdoc to temp file %s.\n", tmpname);
                    if (cli_writen(fd, subdoc, subdoc_len) < 0) {
                        cli_dbgmsg("cli_scanxar: cli_writen error writing subdoc temporary file.\n");
                        rc = CL_EWRITE;
                    }
                    rc = xar_cleanup_temp_file(ctx, fd, tmpname);
                }
            }

            xmlFree(subdoc);
            if (rc != CL_SUCCESS)
                return rc;
            xmlTextReaderNext(reader);
        }        
    }
    return rc;
}

static void * xar_hash_init(int hash, void **sc, void **mc)
{
    if (!sc && !mc)
        return NULL;
    switch (hash) {
    case XAR_CKSUM_SHA1:
        *sc = cl_hash_init("sha1");
        if (!(*sc)) {
            return NULL;
        }

        return *sc;
    case XAR_CKSUM_MD5:
        *mc = cl_hash_init("md5");
        if (!(*mc)) {
            return NULL;
        }

        return *mc;
    case XAR_CKSUM_OTHER:
    case XAR_CKSUM_NONE:
    default:
        return NULL;
    }
}

static void xar_hash_update(void * hash_ctx, void * data, unsigned long size, int hash)
{
    if (!hash_ctx || !data || !size)
        return;

    switch (hash) {
    case XAR_CKSUM_NONE:
    case XAR_CKSUM_OTHER:
        return;
    }

    cl_update_hash(hash_ctx, data, size);
}

static void xar_hash_final(void * hash_ctx, void * result, int hash)
{
    if (!hash_ctx || !result)
        return;

    switch (hash) {
    case XAR_CKSUM_OTHER:
    case XAR_CKSUM_NONE:
        return;
    }

    cl_finish_hash(hash_ctx, result);
}

static int xar_hash_check(int hash, const void * result, const void * expected)
{
    int len;

    if (!result || !expected)
        return 1;
    switch (hash) {
    case XAR_CKSUM_SHA1:
        len = CLI_HASHLEN_SHA1;
        break;
    case XAR_CKSUM_MD5:
        len = CLI_HASHLEN_MD5;
        break;
    case XAR_CKSUM_OTHER:
    case XAR_CKSUM_NONE:
    default:
        return 1;
    }
    return memcmp(result, expected, len);
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
    unsigned int cksum_fails = 0;
    unsigned int extract_errors = 0;
#if HAVE_LIBXML2
    int fd = -1;
    struct xar_header hdr;
    fmap_t *map = *ctx->fmap;
    size_t length, offset, size, at;
    int encoding;
    z_stream strm;
    char *toc, *tmpname;
    xmlTextReaderPtr reader = NULL;
    int a_hash, e_hash;
    unsigned char *a_cksum = NULL, *e_cksum = NULL;
    void *a_hash_ctx = NULL, *e_hash_ctx = NULL;
    char result[SHA1_HASH_SIZE];

    memset(&strm, 0x00, sizeof(z_stream));

    /* retrieve xar header */
    if (fmap_readn(*ctx->fmap, &hdr, 0, sizeof(hdr)) != sizeof(hdr)) {
        cli_dbgmsg("cli_scanxar: Invalid header, too short.\n");
        return CL_EFORMAT;
    }
    hdr.magic = be32_to_host(hdr.magic);

    if (hdr.magic == XAR_HEADER_MAGIC) {
        cli_dbgmsg("cli_scanxar: Matched magic\n");
    }
    else {
        cli_dbgmsg("cli_scanxar: Invalid magic\n");
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
        cli_dbgmsg("cli_scanxar: fmap_need_off_once fails on TOC.\n");
        return CL_EREAD;
    }
    strm.avail_in = hdr.toc_length_compressed; 
    toc = cli_malloc(hdr.toc_length_decompressed+1);
    if (toc == NULL) {
        cli_dbgmsg("cli_scanxar: cli_malloc fails on TOC decompress buffer.\n");
        return CL_EMEM;
    }
    toc[hdr.toc_length_decompressed] = '\0';
    strm.avail_out = hdr.toc_length_decompressed;
    strm.next_out = (unsigned char *)toc;
    rc = inflateInit(&strm);
    if (rc != Z_OK) {
        cli_dbgmsg("cli_scanxar:inflateInit error %i \n", rc);
        rc = CL_EFORMAT;
        goto exit_toc;
    }    
    rc = inflate(&strm, Z_SYNC_FLUSH);
    if (rc != Z_OK && rc != Z_STREAM_END) {
        cli_dbgmsg("cli_scanxar:inflate error %i \n", rc);
        rc = CL_EFORMAT;
        goto exit_toc;
    }
    rc = inflateEnd(&strm);
    if (rc != Z_OK) {
        cli_dbgmsg("cli_scanxar:inflateEnd error %i \n", rc);
        rc = CL_EFORMAT;
        goto exit_toc;
    }

    if (hdr.toc_length_decompressed != strm.total_out) {
        cli_dbgmsg("TOC decompress length %" PRIu64 " does not match amount decompressed %lu\n",
                   hdr.toc_length_decompressed, strm.total_out);
        toc[strm.total_out] = '\0';
        hdr.toc_length_decompressed = strm.total_out;
    }

    /* cli_dbgmsg("cli_scanxar: TOC xml:\n%s\n", toc); */
    /* printf("cli_scanxar: TOC xml:\n%s\n", toc); */
    /* cli_dbgmsg("cli_scanxar: TOC end:\n"); */
    /* printf("cli_scanxar: TOC end:\n"); */

    /* scan the xml */
    cli_dbgmsg("cli_scanxar: scanning xar TOC xml in memory.\n"); 
    rc = cli_mem_scandesc(toc, hdr.toc_length_decompressed, ctx);
    if (rc != CL_SUCCESS) {
        if (rc != CL_VIRUS || !SCAN_ALLMATCHES)
            goto exit_toc;        
    }

    /* make a file to leave if --leave-temps in effect */
    if(ctx->engine->keeptmp) {
        if ((rc = cli_gentempfd(ctx->engine->tmpdir, &tmpname, &fd)) != CL_SUCCESS) {
            cli_dbgmsg("cli_scanxar: Can't create temporary file for TOC.\n");
            goto exit_toc;
        }
        if (cli_writen(fd, toc, hdr.toc_length_decompressed) < 0) {
            cli_dbgmsg("cli_scanxar: cli_writen error writing TOC.\n");
            rc = CL_EWRITE;
            xar_cleanup_temp_file(ctx, fd, tmpname);
            goto exit_toc;
        }
        rc = xar_cleanup_temp_file(ctx, fd, tmpname);
        if (rc != CL_SUCCESS)
            goto exit_toc;
    }

    reader = xmlReaderForMemory(toc, hdr.toc_length_decompressed, "noname.xml", NULL, CLAMAV_MIN_XMLREADER_FLAGS);
    if (reader == NULL) {
        cli_dbgmsg("cli_scanxar: xmlReaderForMemory error for TOC\n");
        goto exit_toc;
    }

    rc = xar_scan_subdocuments(reader, ctx);
    if (rc != CL_SUCCESS) {
        cli_dbgmsg("xar_scan_subdocuments returns %i.\n", rc);
        goto exit_reader;
    }

    /* Walk the TOC XML and extract files */
    fd = -1;
    tmpname = NULL;
    while (CL_SUCCESS == (rc = xar_get_toc_data_values(reader, &length, &offset, &size, &encoding,
                                                       &a_cksum, &a_hash, &e_cksum, &e_hash))) {
        int do_extract_cksum = 1;
        unsigned char * blockp;
        void *a_sc, *e_sc;
        void *a_mc, *e_mc;
        char * expected;

        /* clean up temp file from previous loop iteration */
        if (fd > -1 && tmpname) {
            rc = xar_cleanup_temp_file(ctx, fd, tmpname);
            if (rc != CL_SUCCESS)
                goto exit_reader;
        }

        at = offset + hdr.toc_length_compressed + hdr.size;

        if ((rc = cli_gentempfd(ctx->engine->tmpdir, &tmpname, &fd)) != CL_SUCCESS) {
            cli_dbgmsg("cli_scanxar: Can't generate temporary file.\n");
            goto exit_reader;
        }

        cli_dbgmsg("cli_scanxar: decompress into temp file:\n%s, size %zu,\n"
                   "from xar heap offset %zu length %zu\n",
                   tmpname, size, offset, length);


        a_hash_ctx = xar_hash_init(a_hash, &a_sc, &a_mc);
        e_hash_ctx = xar_hash_init(e_hash, &e_sc, &e_mc);

        switch (encoding) {
        case CL_TYPE_GZ:
            /* inflate gzip directly because file segments do not contain magic */
            memset(&strm, 0, sizeof(strm));
            if ((rc = inflateInit(&strm)) != Z_OK) {
                cli_dbgmsg("cli_scanxar: InflateInit failed: %d\n", rc);
                rc = CL_EFORMAT;
                extract_errors++;
                break;
            }
            
            while ((size_t)at < map->len && (unsigned long)at < offset+hdr.toc_length_compressed+hdr.size+length) {
                unsigned long avail_in;
                void * next_in;
                unsigned int bytes = MIN(map->len - at, map->pgsz);
                bytes = MIN(length, bytes);
                if(!(strm.next_in = next_in = (void*)fmap_need_off_once(map, at, bytes))) {
                    cli_dbgmsg("cli_scanxar: Can't read %u bytes @ %lu.\n", bytes, (long unsigned)at);
                    inflateEnd(&strm);
                    rc = CL_EREAD;
                    goto exit_tmpfile;
                }
                at += bytes;
                strm.avail_in = avail_in = bytes;
                do {
                    int inf, outsize = 0;
                    unsigned char buff[FILEBUFF];
                    strm.avail_out = sizeof(buff);
                    strm.next_out = buff;
                    inf = inflate(&strm, Z_SYNC_FLUSH);
                    if (inf != Z_OK && inf != Z_STREAM_END && inf != Z_BUF_ERROR) {
                        cli_dbgmsg("cli_scanxar: inflate error %i %s.\n", inf, strm.msg?strm.msg:"");
                        rc = CL_EFORMAT;
                        extract_errors++;
                        break;
                    }

                    bytes = sizeof(buff) - strm.avail_out;

                    if (e_hash_ctx != NULL)
                        xar_hash_update(e_hash_ctx, buff, bytes, e_hash);
                   
                    if (cli_writen(fd, buff, bytes) < 0) {
                        cli_dbgmsg("cli_scanxar: cli_writen error file %s.\n", tmpname);
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

                if (rc != CL_SUCCESS)
                    break;

                avail_in -= strm.avail_in;
                if (a_hash_ctx != NULL)
                    xar_hash_update(a_hash_ctx, next_in, avail_in, a_hash);
            }

            inflateEnd(&strm);
            break;
        case CL_TYPE_7Z:
#define CLI_LZMA_OBUF_SIZE 1024*1024
#define CLI_LZMA_HDR_SIZE LZMA_PROPS_SIZE+8
#define CLI_LZMA_IBUF_SIZE CLI_LZMA_OBUF_SIZE>>2 /* estimated compression ratio 25% */
            {
                struct CLI_LZMA lz;
                unsigned long in_remaining = MIN(length, map->len - at);
                unsigned long out_size = 0;
                unsigned char * buff = __lzma_wrap_alloc(NULL, CLI_LZMA_OBUF_SIZE);
                int lret;

                if (length > in_remaining)
                    length = in_remaining;

                memset(&lz, 0, sizeof(lz));
                if (buff == NULL) {
                    cli_dbgmsg("cli_scanxar: memory request for lzma decompression buffer fails.\n");
                    rc = CL_EMEM;
                    goto exit_tmpfile;
                    
                }

                blockp = (void*)fmap_need_off_once(map, at, CLI_LZMA_HDR_SIZE);
                if (blockp == NULL) {
                    char errbuff[128];
                    cli_strerror(errno, errbuff, sizeof(errbuff));
                    cli_dbgmsg("cli_scanxar: Can't read %i bytes @ %zu, errno:%s.\n",
                               CLI_LZMA_HDR_SIZE, at, errbuff);
                    rc = CL_EREAD;
                    __lzma_wrap_free(NULL, buff);
                    goto exit_tmpfile;
                }

                lz.next_in = blockp;
                lz.avail_in = CLI_LZMA_HDR_SIZE;

                if (a_hash_ctx != NULL)
                    xar_hash_update(a_hash_ctx, blockp, CLI_LZMA_HDR_SIZE, a_hash);

                lret = cli_LzmaInit(&lz, 0);
                if (lret != LZMA_RESULT_OK) {
                    cli_dbgmsg("cli_scanxar: cli_LzmaInit() fails: %i.\n", lret);
                    rc = CL_EFORMAT;
                    __lzma_wrap_free(NULL, buff);
                    extract_errors++;
                    break;
                }

                at += CLI_LZMA_HDR_SIZE;
                in_remaining -= CLI_LZMA_HDR_SIZE;
                while (at < map->len && at < offset + (size_t)hdr.toc_length_compressed + (size_t)hdr.size + length) {
                    SizeT avail_in;
                    SizeT avail_out;
                    void * next_in;
                    unsigned long in_consumed;

                    lz.next_out = buff;
                    lz.avail_out = CLI_LZMA_OBUF_SIZE;
                    lz.avail_in = avail_in = MIN(CLI_LZMA_IBUF_SIZE, in_remaining);
                    lz.next_in = next_in = (void*)fmap_need_off_once(map, at, lz.avail_in);
                    if (lz.next_in == NULL) {
                        char errbuff[128];
                        cli_strerror(errno, errbuff, sizeof(errbuff));
                        cli_dbgmsg("cli_scanxar: Can't read %zu bytes @ %zu, errno: %s.\n",
                                   lz.avail_in, at, errbuff);
                        rc = CL_EREAD;
                        __lzma_wrap_free(NULL, buff);
                        cli_LzmaShutdown(&lz);
                        goto exit_tmpfile;
                    }

                    lret = cli_LzmaDecode(&lz);
                    if (lret != LZMA_RESULT_OK && lret != LZMA_STREAM_END) {
                        cli_dbgmsg("cli_scanxar: cli_LzmaDecode() fails: %i.\n", lret);
                        rc = CL_EFORMAT;
                        extract_errors++;
                        break;
                    }

                    in_consumed = avail_in - lz.avail_in;
                    in_remaining -= in_consumed;
                    at += in_consumed;
                    avail_out = CLI_LZMA_OBUF_SIZE - lz.avail_out;
                    
                    if (avail_out == 0)
                        cli_dbgmsg("cli_scanxar: cli_LzmaDecode() produces no output for "
                                   "avail_in %llu, avail_out %llu.\n",
                                   (long long unsigned)avail_in, (long long unsigned)avail_out);

                    if (a_hash_ctx != NULL)
                        xar_hash_update(a_hash_ctx, next_in, in_consumed, a_hash);                    
                    if (e_hash_ctx != NULL)
                        xar_hash_update(e_hash_ctx, buff, avail_out, e_hash);

                    /* Write a decompressed block. */
                    /* cli_dbgmsg("Writing %li bytes to LZMA decompress temp file, " */
                    /*            "consumed %li of %li available compressed bytes.\n", */
                    /*            avail_out, in_consumed, avail_in); */

                    if (cli_writen(fd, buff, avail_out) < 0) {
                        cli_dbgmsg("cli_scanxar: cli_writen error writing lzma temp file for %llu bytes.\n",
                                   (long long unsigned)avail_out);
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

                    if (lret == LZMA_STREAM_END)
                        break;
                }

                cli_LzmaShutdown(&lz);
                __lzma_wrap_free(NULL, buff);
            }
            break; 
        case CL_TYPE_ANY:
        default:
        case CL_TYPE_BZ:
        case CL_TYPE_XZ:
            /* for uncompressed, bzip2, xz, and unknown, just pull the file, cli_magic_scandesc does the rest */
            do_extract_cksum = 0;
            {
                size_t writelen = MIN(map->len - at, length);

                if (ctx->engine->maxfilesize)
                    writelen = MIN((size_t)(ctx->engine->maxfilesize), writelen);
                    
                if (!(blockp = (void*)fmap_need_off_once(map, at, writelen))) {
                    char errbuff[128];
                    cli_strerror(errno, errbuff, sizeof(errbuff));
                    cli_dbgmsg("cli_scanxar: Can't read %zu bytes @ %zu, errno:%s.\n",
                               writelen, at, errbuff);
                    rc = CL_EREAD;
                    goto exit_tmpfile;
                }
                
                if (a_hash_ctx != NULL)
                    xar_hash_update(a_hash_ctx, blockp, writelen, a_hash);
                
                if (cli_writen(fd, blockp, writelen) < 0) {
                    cli_dbgmsg("cli_scanxar: cli_writen error %zu bytes @ %zu.\n", writelen, at);
                    rc = CL_EWRITE;
                    goto exit_tmpfile;
                }
                /*break;*/
            }          
        } /* end of switch */

        if (rc == CL_SUCCESS) {
            if (a_hash_ctx != NULL) {
                xar_hash_final(a_hash_ctx, result, a_hash);
                a_hash_ctx = NULL;
            } else {
                cli_dbgmsg("cli_scanxar: archived-checksum missing.\n");
                cksum_fails++;
            }
            if (a_cksum != NULL) {
                expected = cli_hex2str((char *)a_cksum);
                if (xar_hash_check(a_hash, result, expected) != 0) {
                    cli_dbgmsg("cli_scanxar: archived-checksum mismatch.\n");
                    cksum_fails++;
                } else {
                    cli_dbgmsg("cli_scanxar: archived-checksum matched.\n");                
                }
                free(expected);
            }

            if (e_hash_ctx != NULL) {
                xar_hash_final(e_hash_ctx, result, e_hash);
                e_hash_ctx = NULL;
            } else {
                cli_dbgmsg("cli_scanxar: extracted-checksum(unarchived-checksum) missing.\n");
                cksum_fails++;
            }
            if (e_cksum != NULL) {
                if (do_extract_cksum) {
                    expected = cli_hex2str((char *)e_cksum);
                    if (xar_hash_check(e_hash, result, expected) != 0) {
                        cli_dbgmsg("cli_scanxar: extracted-checksum mismatch.\n");
                        cksum_fails++;
                    } else {
                        cli_dbgmsg("cli_scanxar: extracted-checksum matched.\n");                
                    }
                    free(expected);
                }
            }
        
            rc = cli_magic_scandesc(fd, tmpname, ctx);
            if (rc != CL_SUCCESS) {
                if (rc == CL_VIRUS) {
                    cli_dbgmsg("cli_scanxar: Infected with %s\n", cli_get_last_virus(ctx));
                    if (!SCAN_ALLMATCHES)
                        goto exit_tmpfile;
                } else if (rc != CL_BREAK) {
                    cli_dbgmsg("cli_scanxar: cli_magic_scandesc error %i\n", rc);
                    goto exit_tmpfile;
                }
            }
        }
        
        if (a_cksum != NULL) {
            xmlFree(a_cksum);
            a_cksum = NULL;
        }
        if (e_cksum != NULL) {
            xmlFree(e_cksum);
            e_cksum = NULL;
        }
    }

 exit_tmpfile:
    xar_cleanup_temp_file(ctx, fd, tmpname);
    if (a_hash_ctx != NULL)
        xar_hash_final(a_hash_ctx, result, a_hash);
    if (e_hash_ctx != NULL)
        xar_hash_final(e_hash_ctx, result, e_hash);
 
 exit_reader:
    if (a_cksum != NULL)
        xmlFree(a_cksum);   
    if (e_cksum != NULL)
        xmlFree(e_cksum);
    xmlTextReaderClose(reader);
    xmlFreeTextReader(reader);

 exit_toc:
    free(toc);
    if (rc == CL_BREAK)
        rc = CL_SUCCESS;
#else
    cli_dbgmsg("cli_scanxar: can't scan xar files, need libxml2.\n");
#endif
    if (cksum_fails + extract_errors != 0) {
        cli_dbgmsg("cli_scanxar: %u checksum errors and %u extraction errors.\n",
                    cksum_fails, extract_errors);
    }

    return rc;
}
