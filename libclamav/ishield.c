/*
 *  Copyright (C) 2009 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>
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

/* common routines to deal with installshield archives and installers */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#define _XOPEN_SOURCE 500

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <strings.h>
#include <zlib.h>

#include "scanners.h"
#include "cltypes.h"
#include "others.h"
#include "ishield.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif
#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif
#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

/* PACKED things go here */

struct IS_FB {
    char fname[0x104]; /* MAX_PATH */
    uint32_t unk1; /* 6 */
    uint32_t unk2;
    uint64_t csize;
    uint32_t unk3;
    uint32_t unk4; /* 1 */
    uint32_t unk5;
    uint32_t unk6;
    uint32_t unk7;
    uint32_t unk8;
    uint32_t unk9;
    uint32_t unk10;
    uint32_t unk11;
} __attribute__((packed));

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif
#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif



static int is_dump_and_scan(int desc, cli_ctx *ctx, off_t off, size_t fsize);
static const uint8_t skey[] = { 0xec, 0xca, 0x79, 0xf8 }; /* ~0x13, ~0x35, ~0x86, ~0x07 */

/* Extract the content of MSI based IS */
int cli_scanishield_msi(int desc, cli_ctx *ctx, off_t off) {
    uint8_t buf[BUFSIZ];
    unsigned int fcount, scanned = 0;
    int ret;

    cli_dbgmsg("in ishield-msi\n");
    lseek(desc, off, SEEK_SET);
    if(cli_readn(desc, buf, 0x20) != 0x20) {
	cli_dbgmsg("ishield-msi: short read for header\n");
	return CL_CLEAN;
    }
    if(cli_readint32(buf + 8) | cli_readint32(buf + 0xc) | cli_readint32(buf + 0x10) | cli_readint32(buf + 0x14) | cli_readint32(buf + 0x18) | cli_readint32(buf + 0x1c))
	return CL_CLEAN;
    if(!(fcount = cli_readint32(buf))) {
	cli_dbgmsg("ishield-msi: no files?\n");
	return CL_CLEAN;
    }
    while(fcount--) {
	struct IS_FB fb;
	uint8_t obuf[BUFSIZ], *key = (uint8_t *)&fb.fname;
	char *tempfile;
	unsigned int i, lameidx=0, keylen;
	int ofd;
	uint64_t csize;
	z_stream z;

	if(cli_readn(desc, &fb, sizeof(fb)) != sizeof(fb)) {
	    cli_dbgmsg("ishield-msi: short read for fileblock\n");
	    return CL_CLEAN;
	}
	fb.fname[sizeof(fb.fname)-1] = '\0';
	csize = le64_to_host(fb.csize);

	if(ctx->engine->maxfilesize && csize > ctx->engine->maxfilesize) {
	    cli_dbgmsg("ishield-msi: skipping stream due to size limits (%lu vs %lu)\n", csize, ctx->engine->maxfilesize);
	    lseek(desc, csize, SEEK_CUR);
	    continue;
	}

	keylen = strlen((const char *)key);
	if(!keylen) return CL_CLEAN;
	/* FIXMEISHIELD: cleanup the spam below */
	cli_dbgmsg("ishield-msi: File %s (csize: %x, unk1:%x unk2:%x unk3:%x unk4:%x unk5:%x unk6:%x unk7:%x unk8:%x unk9:%x unk10:%x unk11:%x)\n", key, csize, fb.unk1, fb.unk2, fb.unk3, fb.unk4, fb.unk5, fb.unk6, fb.unk7, fb.unk8, fb.unk9, fb.unk10, fb.unk11);
	if(!(tempfile = cli_gentemp(ctx->engine->tmpdir))) return CL_EMEM;
	if((ofd = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRUSR|S_IWUSR)) < 0) {
	    cli_dbgmsg("ishield-msi: failed to create file %s\n", tempfile);
	    free(tempfile);
	    return CL_ECREAT;
	}

	for(i=0; i<keylen; i++)
	    key[i] ^= skey[i & 3];
	memset(&z, 0, sizeof(z));
	inflateInit(&z);
	
	while(csize) {
	    unsigned int sz = csize < sizeof(buf) ? csize : sizeof(buf);
	    z.avail_in = cli_readn(desc, buf, sz);
	    if(z.avail_in <= 0) {
		cli_dbgmsg("ishield-msi: premature EOS or read fail\n");
		break;    
	    }
	    for(i=0; i<z.avail_in; i++, lameidx++) {
		uint8_t c = buf[i];
		c = (c>>4) | (c<<4);
		c ^= key[(lameidx & 0x3ff) % keylen];
		buf[i] = c;
	    }
	    csize -= z.avail_in;
	    z.next_in = buf;
	    do {
		int def;
		z.avail_out = sizeof(obuf);
		z.next_out = obuf;
		def = inflate(&z, 0);
		if(def != Z_OK && def != Z_STREAM_END && def != Z_BUF_ERROR) {
		    cli_dbgmsg("ishield-msi: bad stream\n");
		    csize = 0;
		    lseek(desc, csize, SEEK_CUR);
		    break;
		}
		write(ofd, obuf, sizeof(obuf) - z.avail_out);
		if(ctx->engine->maxfilesize && z.total_out > ctx->engine->maxfilesize) {
		    cli_dbgmsg("ishield-msi: trimming output file due to size limits (%lu vs %lu)\n", z.total_out, ctx->engine->maxfilesize);
		    lseek(desc, csize, SEEK_CUR);
		    csize = 0;
		    break;
		}
	    } while (!z.avail_out);
	}

	inflateEnd(&z);

	cli_dbgmsg("ishield-msi: extracted to %s\n", tempfile);

	lseek(ofd, 0, SEEK_SET);
	ret = cli_magic_scandesc(ofd, ctx);
	close(ofd);

	if(!ctx->engine->keeptmp)
	    if(cli_unlink(tempfile)) ret = CL_EUNLINK;
	free(tempfile);

	if(ret != CL_CLEAN)
	    return ret;

	scanned++;
	if (ctx->engine->maxfiles && scanned>=ctx->engine->maxfiles) {
	    cli_dbgmsg("ishield-msi: File limit reached (max: %u)\n", ctx->engine->maxfiles);
	    return CL_EMAXFILES;
	}
    }
    return CL_CLEAN;
}

struct CABSTUFF {
    struct CABARRAY {
	unsigned int cabno;
	off_t off;
	size_t sz;
    } *cabs;
    off_t hdr;
    size_t hdrsz;
    unsigned int cabcnt;
};


int cli_scanishield(int desc, cli_ctx *ctx, off_t off, size_t sz) {
    char *fname, *path, *version, *strsz, *eostr, *data;
    char buf[2048];
    int rd, ret = CL_CLEAN;
    long fsize;
    off_t coff = off;
    struct CABSTUFF c = { NULL, -1, 0, 0 };

    while(ret == CL_CLEAN) {
	rd = pread(desc, buf, sizeof(buf), coff);
	if(rd <= 0)
	    break;

	fname = buf;
	if(!*fname) break;
	path = memchr(fname, 0, rd);
	if(!path)
	    break;

	path++;
	rd -= (path - buf);
	if(rd<=0 || !(version = memchr(path, 0, rd)))
	    break;

	version++;
	rd -= (version - path);
	if(rd<=0 || !(strsz = memchr(version, 0, rd)))
	    break;

	strsz++;
	rd -= (strsz - version);
	if(rd<=0 || !(data = memchr(strsz, 0, rd)))
	    break;

	data++;
	fsize = strtol(strsz, &eostr, 10);
	if(fsize < 0 || fsize == LONG_MAX
	   || !*strsz || !eostr || eostr == strsz || *eostr ||
	   (unsigned long)fsize >= sz ||
	   data - buf >= sz - fsize)
	    break;

	cli_errmsg("ishield: @%lx found file %s (%s) - version %s - size %lu\n", coff, fname, path, version, fsize);
	sz -= (data - buf) + fsize;
	coff += (data - buf);
	if(!strncasecmp(fname, "data", 4)) {
	    long cabno;
	    if(!strcasecmp(fname + 4, "1.hdr")) {
		if(c.hdr == -1) {
		    c.hdr = coff;
		    c.hdrsz = fsize;
		    coff += fsize;
		    continue;
		}
		cli_warnmsg("ishield: got multiple header files\n");
	    }
	    cabno = strtol(fname + 4, &eostr, 10);
	    if(cabno > 0 && cabno < 65536 && fname[4] && eostr && eostr != &fname[4] && !strcasecmp(eostr, ".cab")) {
		unsigned int i;
		for(i=0; i<c.cabcnt && i!=c.cabs[i].cabno; i++) { }
		if(i==c.cabcnt) {
		    c.cabcnt++;
		    if(!(c.cabs = cli_realloc2(c.cabs, sizeof(struct CABARRAY) * c.cabcnt))) {
			ret = CL_EMEM;
			break;
		    }
		    c.cabs[i].cabno = cabno;
		    c.cabs[i].off = coff;
		    c.cabs[i].sz = fsize;
		    coff += fsize;
		    continue;
		}
		cli_warnmsg("ishield: got multiple data%lu.cab files\n", cabno);
	    }
	}

	ret = is_dump_and_scan(desc, ctx, coff, fsize);
	coff += fsize;
    }

    if(ret == CL_CLEAN && (c.cabcnt || c.hdr != -1)) {
	if(1 /* FIXMEISHIELD */) {
	    unsigned int i;
	    if(c.hdr != -1) ret = is_dump_and_scan(desc, ctx, c.hdr, c.hdrsz);
	    for(i=0; i<c.cabcnt && ret == CL_CLEAN; i++) {
		cli_errmsg("ishield: scanning data%u.cab\n", c.cabs[i].cabno);
		ret = is_dump_and_scan(desc, ctx, c.cabs[i].off, c.cabs[i].sz);
	    }
	}
    }

    if(c.cabs) free(c.cabs);
    return CL_CLEAN;
}



static int is_dump_and_scan(int desc, cli_ctx *ctx, off_t off, size_t fsize) {
    char *fname, buf[BUFSIZ];
    int ofd, ret = CL_CLEAN;

    cli_errmsg("dumping %u bytes @%x\n", fsize, off);
    if(!fsize) {
	cli_errmsg("ishield: skipping empty file\n");
	return CL_CLEAN;
    }
    if(!(fname = cli_gentemp(ctx->engine->tmpdir)))
	return CL_EMEM;

    if((ofd = open(fname, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRUSR|S_IWUSR)) < 0) {
	cli_errmsg("ishield: failed to create file %s\n", fname);
	free(fname);
	return CL_ECREAT;
    }
    while(fsize) {
	size_t rd = fsize < sizeof(buf) ? fsize : sizeof(buf);
	int got = pread(desc, buf, rd, off);
	if(got <= 0) {
	    cli_errmsg("ishield: read error\n");
	    ret = CL_EREAD;
	    break;
	}
	if(cli_writen(ofd, buf, got) <= 0) {
	    cli_errmsg("ishield: write error\n");		
	    ret = CL_EWRITE;
	    break;
	}
	fsize -= got;
	off += got;
    }
    if(!fsize) {
	cli_errmsg("ishield: extracted to %s\n", fname);
	lseek(ofd, 0, SEEK_SET);
	ret = cli_magic_scandesc(ofd, ctx);
    }
    close(ofd);
    if(!ctx->engine->keeptmp)
	if(cli_unlink(fname)) ret = CL_EUNLINK;
    free(fname);
    return ret;
}
