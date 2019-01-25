/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2011-2013 Sourcefire, Inc.
 *
 *  The code is based on Flasm, command line assembler & disassembler of Flash
 *  ActionScript bytecode Copyright (c) 2001 Opaque Industries, (c) 2002-2007
 *  Igor Kogan, (c) 2005 Wang Zhen. All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice, this list
 *  of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or other
 *  materials provided with the distribution.
 *  - Neither the name of the Opaque Industries nor the names of its contributors may
 *  be used to endorse or promote products derived from this software without specific
 *  prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY 
 *  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES 
 *  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 *  SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED 
 *  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY 
 *  WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef        HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <time.h>
#include <zlib.h>

#include "swf.h"
#include "clamav.h"
#include "scanners.h"
#include "lzma_iface.h"

#define EC16(v)        le16_to_host(v)
#define EC32(v)        le32_to_host(v)

#define INITBITS                                                                \
{                                                                               \
    if(fmap_readn(map, &get_c, offset, sizeof(get_c)) == sizeof(get_c)) {       \
        bitpos = 8;                                                             \
        bitbuf = (unsigned int) get_c;                                          \
        offset += sizeof(get_c);                                                \
    } else {                                                                    \
        cli_warnmsg("cli_scanswf: INITBITS: Can't read file or file truncated\n"); \
        return CL_EFORMAT;                                                      \
    }                                                                           \
}

#define GETBITS(v, n)                                                           \
{                                                                               \
    getbits_n = n;                                                              \
    bits = 0;                                                                   \
    while(getbits_n > bitpos) {                                                 \
        getbits_n -= bitpos;                                                    \
        bits |= bitbuf << getbits_n;                                            \
        if(fmap_readn(map, &get_c, offset, sizeof(get_c)) == sizeof(get_c)) {   \
            bitbuf = (unsigned int) get_c;                                      \
            bitpos = 8;                                                         \
            offset += sizeof(get_c);                                            \
        } else {                                                                \
            cli_warnmsg("cli_scanswf: GETBITS: Can't read file or file truncated\n"); \
            return CL_EFORMAT;                                                  \
        }                                                                       \
    }                                                                           \
    bitpos -= getbits_n;                                                        \
    bits |= bitbuf >> bitpos;                                                   \
    bitbuf &= 0xff >> (8 - bitpos);                                             \
    v = bits & 0xffff;                                                          \
}

#define GETWORD(v)                                                              \
{                                                                               \
    if(fmap_readn(map, &get_c, offset, sizeof(get_c)) == sizeof(get_c)) {       \
        getword_1 = (unsigned int) get_c;                                       \
        offset += sizeof(get_c);                                                \
    } else {                                                                    \
        cli_warnmsg("cli_scanswf: GETWORD: Can't read file or file truncated\n"); \
        return CL_EFORMAT;                                                      \
    }                                                                           \
    if(fmap_readn(map, &get_c, offset, sizeof(get_c)) == sizeof(get_c)) {       \
        getword_2 = (unsigned int) get_c;                                       \
        offset += sizeof(get_c);                                                \
    } else {                                                                    \
        cli_warnmsg("cli_scanswf: GETWORD: Can't read file or file truncated\n"); \
        return CL_EFORMAT;                                                      \
    }                                                                           \
    v = (uint16_t)(getword_1 & 0xff) | ((getword_2 & 0xff) << 8);               \
}

#define GETDWORD(v)                                                             \
{                                                                               \
    GETWORD(getdword_1);                                                        \
    GETWORD(getdword_2);                                                        \
    v = (uint32_t)(getdword_1 | (getdword_2 << 16));                            \
}

struct swf_file_hdr {
    char signature[3];
    uint8_t version;
    uint32_t filesize;
};

static int scanzws(cli_ctx *ctx, struct swf_file_hdr *hdr)
{
        struct CLI_LZMA lz;
        unsigned char inbuff[FILEBUFF], outbuff[FILEBUFF];
        fmap_t *map = *ctx->fmap;
        /* strip off header */
        off_t offset = 8;
        uint32_t d_insize;
        size_t outsize = 8;
        int ret, lret, count;
        char *tmpname;
        int fd;

    if((ret = cli_gentempfd(ctx->engine->tmpdir, &tmpname, &fd)) != CL_SUCCESS) {
        cli_errmsg("scanzws: Can't generate temporary file\n");
        return ret;
    }

    hdr->signature[0] = 'F';
    if(cli_writen(fd, hdr, sizeof(struct swf_file_hdr)) != sizeof(struct swf_file_hdr)) {
        cli_errmsg("scanzws: Can't write to file %s\n", tmpname);
        close(fd);
        if(cli_unlink(tmpname)) {
            free(tmpname);
            return CL_EUNLINK;
        }
        free(tmpname);
        return CL_EWRITE;
    }

    /* read 4 bytes (for compressed 32-bit filesize) [not used for LZMA] */
    if (fmap_readn(map, &d_insize, offset, sizeof(d_insize)) != sizeof(d_insize)) {
        cli_errmsg("scanzws: Error reading SWF file\n");
        close(fd);
        if (cli_unlink(tmpname)) {
            free(tmpname);
            return CL_EUNLINK;
        }
        free(tmpname);
        return CL_EREAD;
    }
    offset += sizeof(d_insize);

    /* check if declared input size matches actual output size */
    /* map->len = header (8 bytes) + d_insize (4 bytes) + flags (5 bytes) + compressed stream */
    if (d_insize != (map->len - 17)) {
        cli_warnmsg("SWF: declared input length != compressed stream size, %u != %llu\n",
                    d_insize, (long long unsigned)(map->len - 17));
    } else {
        cli_dbgmsg("SWF: declared input length == compressed stream size, %u == %llu\n",
                    d_insize, (long long unsigned)(map->len - 17));
    }

    /* first buffer required for initializing LZMA */
    ret = fmap_readn(map, inbuff, offset, FILEBUFF);
    if (ret < 0) {
        cli_errmsg("scanzws: Error reading SWF file\n");
        close(fd);
        if (cli_unlink(tmpname)) {
            free(tmpname);
            return CL_EUNLINK;
        }
        free(tmpname);
        return CL_EUNPACK;
    }
    /* nothing written, likely truncated */
    if (!ret) {
        cli_errmsg("scanzws: possibly truncated file\n");
        close(fd);
        if (cli_unlink(tmpname)) {
            free(tmpname);
            return CL_EUNLINK;
        }
        free(tmpname);
        return CL_EFORMAT;
    }
    offset += ret;

    memset(&lz, 0, sizeof(lz));
    lz.next_in = inbuff;
    lz.next_out = outbuff;
    lz.avail_in = ret;
    lz.avail_out = FILEBUFF;

    lret = cli_LzmaInit(&lz, hdr->filesize);
    if (lret != LZMA_RESULT_OK) {
        cli_errmsg("scanzws: LzmaInit() failed\n");
        close(fd);
        if (cli_unlink(tmpname)) {
            free(tmpname);
            return CL_EUNLINK;
        }
        free(tmpname);
        return CL_EUNPACK;
    }

    while (lret == LZMA_RESULT_OK) {
        if (lz.avail_in == 0) {
            lz.next_in = inbuff;

            ret = fmap_readn(map, inbuff, offset, FILEBUFF);
            if (ret < 0) {
                cli_errmsg("scanzws: Error reading SWF file\n");
                cli_LzmaShutdown(&lz);
                close(fd);
                if (cli_unlink(tmpname)) {
                    free(tmpname);
                    return CL_EUNLINK;
                }
                free(tmpname);
                return CL_EUNPACK;
            }
            if (!ret)
                break;
            lz.avail_in = ret;
            offset += ret;
        }
        lret = cli_LzmaDecode(&lz);
        count = FILEBUFF - lz.avail_out;
        if (count) {
            if (cli_checklimits("SWF", ctx, outsize + count, 0, 0) != CL_SUCCESS)
                break;
            if (cli_writen(fd, outbuff, count) != count) {
                cli_errmsg("scanzws: Can't write to file %s\n", tmpname);
                cli_LzmaShutdown(&lz);
                close(fd);
                if (cli_unlink(tmpname)) {
                    free(tmpname);
                    return CL_EUNLINK;
                }
                free(tmpname);
                return CL_EWRITE;
            }
            outsize += count;
        }
        lz.next_out = outbuff;
        lz.avail_out = FILEBUFF;
    }

    cli_LzmaShutdown(&lz);

    if (lret != LZMA_STREAM_END && lret != LZMA_RESULT_OK) {
        /* outsize starts at 8, therefore, if its still 8, nothing was decompressed */
        if (outsize == 8) {
            cli_infomsg(ctx, "scanzws: Error decompressing SWF file. No data decompressed.\n");
            close(fd);
            if (cli_unlink(tmpname)) {
                free(tmpname);
                return CL_EUNLINK;
            }
            free(tmpname);
            return CL_EUNPACK;
        }
        cli_infomsg(ctx, "scanzws: Error decompressing SWF file. Scanning what was decompressed.\n");
    }
    cli_dbgmsg("SWF: Decompressed[LZMA] to %s, size %llu\n", tmpname, (long long unsigned)outsize);

    /* check if declared output size matches actual output size */
    if (hdr->filesize != outsize) {
        cli_warnmsg("SWF: declared output length != inflated stream size, %u != %llu\n",
                    hdr->filesize, (long long unsigned)outsize);
    } else {
        cli_dbgmsg("SWF: declared output length == inflated stream size, %u == %llu\n",
                   hdr->filesize, (long long unsigned)outsize);
    }

    ret = cli_magic_scandesc(fd, tmpname, ctx);

    close(fd);
    if (!(ctx->engine->keeptmp)) {
        if (cli_unlink(tmpname)) {
            free(tmpname);
            return CL_EUNLINK;
        }
    }
    free(tmpname);
    return ret;
}

static int scancws(cli_ctx *ctx, struct swf_file_hdr *hdr)
{
        z_stream stream;
        char inbuff[FILEBUFF], outbuff[FILEBUFF];
        fmap_t *map = *ctx->fmap;
        int offset = 8, ret, zret, outsize = 8, count, zend;
        char *tmpname;
        int fd;

    if((ret = cli_gentempfd(ctx->engine->tmpdir, &tmpname, &fd)) != CL_SUCCESS) {
        cli_errmsg("scancws: Can't generate temporary file\n");
        return ret;
    }

    hdr->signature[0] = 'F';
    if(cli_writen(fd, hdr, sizeof(struct swf_file_hdr)) != sizeof(struct swf_file_hdr)) {
        cli_errmsg("scancws: Can't write to file %s\n", tmpname);
        close(fd);
        if(cli_unlink(tmpname)) {
            free(tmpname);
            return CL_EUNLINK;
        }
        free(tmpname);
        return CL_EWRITE;
    }

    stream.avail_in = 0;
    stream.next_in = (Bytef *)inbuff;
    stream.next_out = (Bytef *)outbuff;
    stream.zalloc = (alloc_func) NULL;
    stream.zfree = (free_func) NULL;
    stream.opaque = (voidpf) 0;
    stream.avail_out = FILEBUFF;

    zret = inflateInit(&stream);
    if(zret != Z_OK) {
        cli_errmsg("scancws: inflateInit() failed\n");
        close(fd);
        if(cli_unlink(tmpname)) {
            free(tmpname);
            return CL_EUNLINK;
        }
        free(tmpname);
        return CL_EUNPACK;
    }

    do {
        if(stream.avail_in == 0) {
            stream.next_in = (Bytef *)inbuff;
            ret = fmap_readn(map, inbuff, offset, FILEBUFF);
            if(ret < 0) {
                cli_errmsg("scancws: Error reading SWF file\n");
                close(fd);
                inflateEnd(&stream);
                if(cli_unlink(tmpname)) {
                    free(tmpname);
                    return CL_EUNLINK;
                }
                free(tmpname);
                return CL_EUNPACK;
            }
            if(!ret)
                break;
            stream.avail_in = ret;
            offset += ret;
        }
        zret = inflate(&stream, Z_SYNC_FLUSH);
        count = FILEBUFF - stream.avail_out;
        if(count) {
            if(cli_checklimits("SWF", ctx, outsize + count, 0, 0) != CL_SUCCESS)
                break;
            if(cli_writen(fd, outbuff, count) != count) {
                cli_errmsg("scancws: Can't write to file %s\n", tmpname);
                inflateEnd(&stream);
                close(fd);
                if(cli_unlink(tmpname)) {
                    free(tmpname);
                    return CL_EUNLINK;
                }
                free(tmpname);
                return CL_EWRITE;
            }
            outsize += count;
        }
        stream.next_out = (Bytef *)outbuff;
        stream.avail_out = FILEBUFF;
    } while(zret == Z_OK);

    zend = inflateEnd(&stream);

    if((zret != Z_STREAM_END && zret != Z_OK) || zend != Z_OK) {
        /*
         * outsize is initialized to 8, it being 8 here means that we couldn't even read a single byte.
         * If outsize > 8, then we have data. Let's scan what we have.
         */
        if (outsize == 8) {
            cli_infomsg(ctx, "scancws: Error decompressing SWF file. No data decompressed.\n");
            close(fd);
            if(cli_unlink(tmpname)) {
                free(tmpname);
                return CL_EUNLINK;
            }
            free(tmpname);
            return CL_EUNPACK;
        }
        cli_infomsg(ctx, "scancws: Error decompressing SWF file. Scanning what was decompressed.\n");
    }
    cli_dbgmsg("SWF: Decompressed[zlib] to %s, size %d\n", tmpname, outsize);

    /* check if declared output size matches actual output size */
    if (hdr->filesize != outsize) {
        cli_warnmsg("SWF: declared output length != inflated stream size, %u != %llu\n",
                    hdr->filesize, (long long unsigned)outsize);
    } else {
        cli_dbgmsg("SWF: declared output length == inflated stream size, %u == %llu\n",
                   hdr->filesize, (long long unsigned)outsize);
    }

    ret = cli_magic_scandesc(fd, tmpname, ctx);

    close(fd);
    if(!ctx->engine->keeptmp) {
        if(cli_unlink(tmpname)) {
            free(tmpname);
            return CL_EUNLINK;
        }
    }
    free(tmpname);
    return ret;
}

static const char *tagname(tag_id id)
{
        unsigned int i;

    for(i = 0; tag_names[i].name; i++)
        if(tag_names[i].id == id)
            return tag_names[i].name;
    return NULL;
}

int cli_scanswf(cli_ctx *ctx)
{
    struct swf_file_hdr file_hdr;
    fmap_t *map = *ctx->fmap;
    unsigned int bitpos, bitbuf, getbits_n, nbits, getword_1, getword_2, getdword_1, getdword_2;
    const char *pt;
    unsigned char get_c;
    size_t offset = 0;
    unsigned int val, foo, tag_hdr, tag_type, tag_len;
    unsigned long int bits;

    cli_dbgmsg("in cli_scanswf()\n");

    if(fmap_readn(map, &file_hdr, offset, sizeof(file_hdr)) != sizeof(file_hdr)) {
        cli_dbgmsg("SWF: Can't read file header\n");
        return CL_CLEAN;
    }
    offset += sizeof(file_hdr);
    /*
    **  SWF stores the integer bytes with the least significate byte first
    */
    
    file_hdr.filesize = le32_to_host (file_hdr.filesize); 

    cli_dbgmsg("SWF: Version: %u\n", file_hdr.version);
    cli_dbgmsg("SWF: File size: %u\n", file_hdr.filesize);

    if(!strncmp(file_hdr.signature, "CWS", 3)) {
        cli_dbgmsg("SWF: zlib compressed file\n");
        return scancws(ctx, &file_hdr);
    } else if(!strncmp(file_hdr.signature, "ZWS", 3)) {
        cli_dbgmsg("SWF: LZMA compressed file\n");
        return scanzws(ctx, &file_hdr);
    } else if(!strncmp(file_hdr.signature, "FWS", 3)) {
        cli_dbgmsg("SWF: Uncompressed file\n");
    } else {
        cli_dbgmsg("SWF: Not a SWF file\n");
        return CL_CLEAN;
    }

    INITBITS;

    GETBITS(nbits, 5);
    cli_dbgmsg("SWF: FrameSize RECT size bits: %u\n", nbits);
    {
        uint32_t xMin = 0, xMax = 0, yMin = 0, yMax = 0;
        GETBITS(xMin, nbits); /* Should be zero */
        GETBITS(xMax, nbits);
        GETBITS(yMin, nbits); /* Should be zero */
        GETBITS(yMax, nbits);
        cli_dbgmsg("SWF: FrameSize xMin %u xMax %u yMin %u yMax %u\n", xMin, xMax, yMin, yMax);
    }

    GETWORD(foo);
    GETWORD(val);
    cli_dbgmsg("SWF: Frames total: %d\n", val);

    /* Skip Flash tag walk unless debug mode */
    if(!cli_debug_flag) {
        return CL_CLEAN;
    }

    while(offset < map->len) {
        GETWORD(tag_hdr);
        tag_type = tag_hdr >> 6;
        if(tag_type == 0)
            break;
        tag_len = tag_hdr & 0x3f;
        if(tag_len == 0x3f)
            GETDWORD(tag_len);

        pt = tagname(tag_type);
        cli_dbgmsg("SWF: %s\n", pt ? pt : "UNKNOWN TAG");
        cli_dbgmsg("SWF: Tag length: %u\n", tag_len);
        if (tag_len > map->len) {
            cli_dbgmsg("SWF: Invalid tag length.\n");
            return CL_EFORMAT;
        }
        if ((offset + tag_len) < offset) {
            cli_warnmsg("SWF: Tag length too large.\n");
            break;
        }
        if(!pt) {
            offset += tag_len;
            continue;
        }

        switch(tag_type) {
            case TAG_SCRIPTLIMITS: {
                unsigned int recursion, timeout;
                GETWORD(recursion);
                GETWORD(timeout);
                cli_dbgmsg("SWF: scriptLimits recursion %u timeout %u\n", recursion, timeout);
                break;
            }

            case TAG_FILEATTRIBUTES:
                GETDWORD(val);
                cli_dbgmsg("SWF: File attributes:\n");
                if(val & SWF_ATTR_USENETWORK)
                    cli_dbgmsg("    * Use network\n");
                if(val & SWF_ATTR_RELATIVEURLS)
                    cli_dbgmsg("    * Relative URLs\n");
                if(val & SWF_ATTR_SUPPRESSCROSSDOMAINCACHE)
                    cli_dbgmsg("    * Suppress cross domain cache\n");
                if(val & SWF_ATTR_ACTIONSCRIPT3)
                    cli_dbgmsg("    * ActionScript 3.0\n");
                if(val & SWF_ATTR_HASMETADATA)
                    cli_dbgmsg("    * Has metadata\n");
                if(val & SWF_ATTR_USEDIRECTBLIT)
                    cli_dbgmsg("    * Use hardware acceleration\n");
                if(val & SWF_ATTR_USEGPU)
                    cli_dbgmsg("    * Use GPU\n");
                break;

            default:
                offset += tag_len;
                continue;
        }
    }

    return CL_CLEAN;
}
