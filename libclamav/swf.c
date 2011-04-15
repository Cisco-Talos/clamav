/*
 *  Copyright (C) 2011 Sourcefire, Inc.
 *  Authors: Tomasz Kojm <tkojm@clamav.net>
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
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <time.h>
#include <zlib.h>

#include "cltypes.h"
#include "swf.h"
#include "clamav.h"
#include "scanners.h"

#define EC16(v)	le16_to_host(v)
#define EC32(v)	le32_to_host(v)

#define INITBITS								\
{										\
    if(fmap_readn(map, &get_c, offset, sizeof(get_c)) == sizeof(get_c)) {	\
	bitpos = 8;								\
	bitbuf = (unsigned int) get_c;						\
	offset += sizeof(get_c);						\
    } else {									\
	cli_errmsg("cli_scanswf: INITBITS: Can't read file\n");			\
	return CL_EREAD;							\
    }										\
}

#define GETBITS(v, n)								\
{										\
    getbits_n = n;								\
    bits = 0;									\
    while(getbits_n > bitpos) {							\
	getbits_n -= bitpos;							\
	bits |= bitbuf << getbits_n;						\
	if(fmap_readn(map, &get_c, offset, sizeof(get_c)) == sizeof(get_c)) {	\
	    bitbuf = (unsigned int) get_c;					\
	    bitpos = 8;								\
	    offset += sizeof(get_c);						\
	} else {								\
	    cli_errmsg("cli_scanswf: GETBITS: Can't read file\n");		\
	    return CL_EREAD;							\
	}									\
    }										\
    bitpos -= getbits_n;							\
    bits |= bitbuf >> bitpos;							\
    bitbuf &= 0xff >> (8 - bitpos);						\
    v = bits & 0xffff;								\
}

#define GETWORD(v)								\
{										\
    if(fmap_readn(map, &get_c, offset, sizeof(get_c)) == sizeof(get_c)) {	\
	getword_1 = (unsigned int) get_c;					\
	offset += sizeof(get_c);						\
    } else {									\
	cli_errmsg("cli_scanswf: GETWORD: Can't read file\n");			\
	return CL_EREAD;							\
    }										\
    if(fmap_readn(map, &get_c, offset, sizeof(get_c)) == sizeof(get_c)) {	\
	getword_2 = (unsigned int) get_c;					\
	offset += sizeof(get_c);						\
    } else {									\
	cli_errmsg("cli_scanswf: GETWORD: Can't read file\n");			\
	return CL_EREAD;							\
    }										\
    v = (uint16_t)(getword_1 & 0xff) | ((getword_2 & 0xff) << 8);		\
}

#define GETDWORD(v)								\
{										\
    GETWORD(getdword_1);							\
    GETWORD(getdword_2);							\
    v = (uint32_t)(getdword_1 | (getdword_2 << 16));				\
}

struct swf_file_hdr {
    char signature[3];
    uint8_t version;
    uint32_t filesize;
};

static int scancws(cli_ctx *ctx, struct swf_file_hdr *hdr)
{
	z_stream stream;
	char inbuff[FILEBUFF], outbuff[FILEBUFF];
	fmap_t *map = *ctx->fmap;
	int offset = 8, ret, zret, outsize = 8, count;
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
    stream.next_in = inbuff;
    stream.next_out = outbuff;
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
	    stream.next_in = inbuff;
	    ret = fmap_readn(map, inbuff, offset, FILEBUFF);
	    if(ret < 0) {
		cli_errmsg("scancws: Error reading SWF file\n");
		close(fd);
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
	stream.next_out = outbuff;
	stream.avail_out = FILEBUFF;
    } while(zret == Z_OK);

    if((zret != Z_STREAM_END && zret != Z_OK) || (zret = inflateEnd(&stream)) != Z_OK) {
	cli_errmsg("scancws: Error decompressing SWF file\n");
	close(fd);
	if(cli_unlink(tmpname)) {
	    free(tmpname);
	    return CL_EUNLINK;
	}
	free(tmpname);
	return CL_EUNPACK;
    }
    cli_dbgmsg("SWF: Decompressed to %s, size %d\n", tmpname, outsize);

    ret = cli_magic_scandesc(fd, ctx);

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

static int dumpscan(fmap_t *map, unsigned int offset, unsigned int size, const char *obj, int version, cli_ctx *ctx)
{
	int newfd, ret = CL_CLEAN;
	unsigned int bread, sum = 0;
	char buff[FILEBUFF];
	char *name;

    if(!(name = cli_gentemp(ctx->engine->tmpdir)))
	return CL_EMEM;

    if((newfd = open(name, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
	cli_errmsg("dumpscan: Can't create file %s\n", name);
	free(name);
	return CL_ECREAT;
    }

    while((bread = fmap_readn(map, buff, offset, sizeof(buff))) > 0) {
	if(!sum && ctx->img_validate) {
	    if(!memcmp(buff, "\xff\xd8", 2)) {
		cli_dbgmsg("SWF: JPEG image data\n");
	    } else if(!memcmp(buff, "\xff\xd9\xff\xd8", 4)) {
		cli_dbgmsg("SWF: JPEG image data (erroneous header)\n");
		if(version >= 8) {
		    *ctx->virname = "Heuristics.SWF.SuspectImage.A";
		    ret = CL_VIRUS;
		}
	    } else if(!memcmp(buff, "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a", 8)) {
		cli_dbgmsg("SWF: PNG image data\n");
		if(version < 8) {
		    *ctx->virname = "Heuristics.SWF.SuspectImage.B";
		    ret = CL_VIRUS;
		}
	    } else if(!memcmp(buff, "\x47\x49\x46\x38\x39\x61", 6)) {
		cli_dbgmsg("SWF: GIF89a image data\n");
		if(version < 8) {
		    *ctx->virname = "Heuristics.SWF.SuspectImage.C";
		    ret = CL_VIRUS;
		}
	    } else {
		cli_warnmsg("SWF: Unknown image data\n");
		*ctx->virname = "Heuristics.SWF.SuspectImage.D";
		ret = CL_VIRUS;
	    }
	    if(ret == CL_VIRUS) {
		close(newfd);
		cli_unlink(name);
		free(name);
		return ret;
	    }
	}
	if(sum + bread >= size) {
	    if(cli_writen(newfd, buff, size - sum) == -1) {
		cli_errmsg("dumpscan: Can't write to %s\n", name);
		close(newfd);
		cli_unlink(name);
		free(name);
		return CL_EWRITE;
	    }
	    break;
	} else {
	    if(cli_writen(newfd, buff, bread) == -1) {
		cli_errmsg("cli_dumpscan: Can't write to %s\n", name);
		close(newfd);
		cli_unlink(name);
		free(name);
		return CL_EWRITE;
	    }
	}
	sum += bread;
	offset += bread;
    }
    cli_dbgmsg("SWF: %s data extracted to %s\n", obj, name);
    lseek(newfd, 0, SEEK_SET);
    if((ret = cli_magic_scandesc(newfd, ctx)) == CL_VIRUS)
	cli_dbgmsg("cli_dumpscan: Infected with %s\n", *ctx->virname);

    close(newfd);
    if(!ctx->engine->keeptmp) {
	if(cli_unlink(name)) {
	    free(name);
	    return CL_EUNLINK;
	}
    }
    free(name);
    if(ctx->img_validate && ret == CL_EPARSE) {
	*ctx->virname = "Heuristics.SWF.SuspectImage.E";
	return CL_VIRUS;
    }
    return ret;
}

int cli_scanswf(cli_ctx *ctx)
{
	struct swf_file_hdr file_hdr;
	fmap_t *map = *ctx->fmap;
	unsigned int bitpos, bitbuf, getbits_n, nbits, getword_1, getword_2, getdword_1, getdword_2;
	const char *pt;
	char get_c;
	unsigned int val, foo, offset = 0, tag_hdr, tag_type, tag_len;
	unsigned long int bits;


    cli_dbgmsg("in cli_scanswf()\n");

    if(fmap_readn(map, &file_hdr, offset, sizeof(file_hdr)) != sizeof(file_hdr)) {
	cli_dbgmsg("SWF: Can't read file header\n");
	return CL_CLEAN;
    }
    offset += sizeof(file_hdr);

    if(!strncmp(file_hdr.signature, "CWS", 3)) {
	cli_dbgmsg("SWF: Compressed file\n");
	return scancws(ctx, &file_hdr);
    } else if(!strncmp(file_hdr.signature, "FWS", 3)) {
	cli_dbgmsg("SWF: Uncompressed file\n");
    } else {
	cli_dbgmsg("SWF: Not a SWF file\n");
	return CL_CLEAN;
    }

    cli_dbgmsg("SWF: Version: %u\n", file_hdr.version);
    cli_dbgmsg("SWF: File size: %u\n", EC32(file_hdr.filesize));

    INITBITS;

    GETBITS(nbits, 5);
    GETBITS(foo, nbits); /* xMin */
    GETBITS(foo, nbits); /* xMax */
    GETBITS(foo, nbits); /* yMin */
    GETBITS(foo, nbits); /* yMax */

    GETWORD(foo);
    GETWORD(val);
    cli_dbgmsg("SWF: Frames total: %d\n", val);

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

	    case TAG_METADATA:
		if(tag_len) {
		    if(dumpscan(map, offset, tag_len, "Metadata", file_hdr.version, ctx) == CL_VIRUS)
			return CL_VIRUS;
		}
		offset += tag_len;
		break;

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

	    case TAG_DEFINEBITSJPEG3:
		GETWORD(foo); /* CharacterID */
		GETDWORD(val); /* AlphaDataOffset */
		if(val) {
		    ctx->img_validate = 1;
		    if(dumpscan(map, offset, val, "Image", file_hdr.version, ctx) == CL_VIRUS)
			return CL_VIRUS;
		    ctx->img_validate = 0;
		}
		offset += tag_len - 6;
		break;

	    case TAG_DEFINEBINARYDATA:
		GETWORD(foo); /* CharacterID */
		GETDWORD(foo); /* Reserved */
		if(tag_len > 6) {
		    if(dumpscan(map, offset, tag_len - 6, "Binary", file_hdr.version, ctx) == CL_VIRUS)
			return CL_VIRUS;
		}
		offset += tag_len - 6;
		break;

	    default:
		cli_dbgmsg("SWF: Unhandled tag\n");
		offset += tag_len;
		continue;
	}
    }

    return CL_CLEAN;
}
