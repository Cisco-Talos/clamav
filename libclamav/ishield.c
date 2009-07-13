#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <zlib.h>

#include "scanners.h"
#include "cltypes.h"
#include "others.h"
#include "ishield.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

static const uint8_t skey[] = { 0xec, 0xca, 0x79, 0xf8 }; /* ~0x13, ~0x35, ~0x86, ~0x07 */

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
	struct {
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
	} __attribute__((packed)) fb;
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
