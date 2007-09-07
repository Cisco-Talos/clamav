/*
 *  Copyright (C) 2002 - 2007 Tomasz Kojm <tkojm@clamav.net>
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

#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "clamav.h"
#include "others.h"
#include "matcher-ac.h"
#include "matcher-bm.h"
#include "md5.h"
#include "filetypes.h"
#include "matcher.h"
#include "pe.h"
#include "elf.h"
#include "execs.h"
#include "special.h"
#include "str.h"
#include "cltypes.h"

static cli_file_t targettab[CL_TARGET_TABLE_SIZE] = { 0, CL_TYPE_MSEXE, CL_TYPE_MSOLE2, CL_TYPE_HTML, CL_TYPE_MAIL, CL_TYPE_GRAPHICS, CL_TYPE_ELF };

int cli_scanbuff(const unsigned char *buffer, uint32_t length, const char **virname, const struct cl_engine *engine, cli_file_t ftype)
{
	int ret = CL_CLEAN;
	unsigned int i;
	struct cli_ac_data mdata;
	struct cli_matcher *groot, *troot = NULL;


    if(!engine) {
	cli_errmsg("cli_scanbuff: engine == NULL\n");
	return CL_ENULLARG;
    }

    groot = engine->root[0]; /* generic signatures */

    if(ftype) {
	for(i = 1; i < CL_TARGET_TABLE_SIZE; i++) {
	    if(targettab[i] == ftype) {
		troot = engine->root[i];
		break;
	    }
	}
    }

    if(troot) {

	if((ret = cli_ac_initdata(&mdata, troot->ac_partsigs, AC_DEFAULT_TRACKLEN)))
	    return ret;

	if(troot->ac_only || (ret = cli_bm_scanbuff(buffer, length, virname, troot, 0, ftype, -1)) != CL_VIRUS)
	    ret = cli_ac_scanbuff(buffer, length, virname, troot, &mdata, 0, 0, ftype, -1, NULL);

	cli_ac_freedata(&mdata);

	if(ret == CL_VIRUS)
	    return ret;
    }

    if((ret = cli_ac_initdata(&mdata, groot->ac_partsigs, AC_DEFAULT_TRACKLEN)))
	return ret;

    if(groot->ac_only || (ret = cli_bm_scanbuff(buffer, length, virname, groot, 0, ftype, -1)) != CL_VIRUS)
	ret = cli_ac_scanbuff(buffer, length, virname, groot, &mdata, 0, 0, ftype, -1, NULL);

    cli_ac_freedata(&mdata);

    return ret;
}

struct cli_md5_node *cli_vermd5(const unsigned char *md5, const struct cl_engine *engine)
{
	struct cli_md5_node *pt;


    if(!(pt = engine->md5_hlist[md5[0] & 0xff]))
	return NULL;

    while(pt) {
	if(!memcmp(pt->md5, md5, 16))
	    return pt;

	pt = pt->next;
    }

    return NULL;
}

off_t cli_caloff(const char *offstr, struct cli_target_info *info, int fd, cli_file_t ftype, int *ret, unsigned int *maxshift)
{
	int (*einfo)(int, struct cli_exe_info *) = NULL;
	unsigned int n, val;
	const char *pt;
	off_t pos, offset;


    *ret = 0;

    if(!strncmp(offstr, "EP", 2) || offstr[0] == 'S') {

	if(info->status == -1) {
	    *ret = -1;
	    return 0;

	} else if(!info->status) {

	    if(ftype == CL_TYPE_MSEXE)
		einfo = cli_peheader;
	    else if(ftype == CL_TYPE_ELF)
		einfo = cli_elfheader;

	    if(einfo) {
		if((pos = lseek(fd, 0, SEEK_CUR)) == -1) {
		    cli_dbgmsg("Invalid descriptor\n");
		    info->status = *ret = -1;
		    return 0;
		}

		lseek(fd, 0, SEEK_SET);
		if(einfo(fd, &info->exeinfo)) {
		    lseek(fd, pos, SEEK_SET);
		    info->status = *ret = -1;
		    return 0;
		}
		lseek(fd, pos, SEEK_SET);
		info->status = 1;
	    }
	}
    }

    if((pt = strchr(offstr, ',')))
	*maxshift = atoi(++pt);

    if(isdigit(offstr[0])) {
	return atoi(offstr);

    } else if(info->status == 1 && (!strncmp(offstr, "EP+", 3) || !strncmp(offstr, "EP-", 3))) {

	if(offstr[2] == '+')
	    return info->exeinfo.ep + atoi(offstr + 3);
	else
	    return info->exeinfo.ep - atoi(offstr + 3);

    } else if(info->status == 1 && offstr[0] == 'S') {

	if(!strncmp(offstr, "SL", 2) && info->exeinfo.section[info->exeinfo.nsections - 1].rsz) {

	    if(sscanf(offstr, "SL+%u", &val) != 1) {
		*ret = -1;
		return 0;
	    }

	    offset = val + info->exeinfo.section[info->exeinfo.nsections - 1].raw;

	} else {

	    if(sscanf(offstr, "S%u+%u", &n, &val) != 2) {
		*ret = -1;
		return 0;
	    }

	    if(n >= info->exeinfo.nsections || !info->exeinfo.section[n].rsz) {
		*ret = -1;
		return 0;
	    }

	    offset = val + info->exeinfo.section[n].raw;
	}

	return offset;

    } else if(!strncmp(offstr, "EOF-", 4)) {
	    struct stat sb;

	if(!info->fsize) {
	    if(fstat(fd, &sb) == -1) {
		info->status = *ret = -1;
		return 0;
	    }
	    info->fsize = sb.st_size;
	}

	return info->fsize - atoi(offstr + 4);
    }

    *ret = -1;
    return 0;
}

static int cli_checkfp(int fd, const struct cl_engine *engine)
{
	struct cli_md5_node *md5_node;
	unsigned char *digest;


    if(engine->md5_hlist) {

	if(!(digest = cli_md5digest(fd))) {
	    cli_errmsg("cli_checkfp(): Can't generate MD5 checksum\n");
	    return 0;
	}

	if((md5_node = cli_vermd5(digest, engine)) && md5_node->fp) {
		struct stat sb;

	    if(fstat(fd, &sb))
		return CL_EIO;

	    if((unsigned int) sb.st_size != md5_node->size) {
		cli_warnmsg("Detected false positive MD5 match. Please report.\n");
	    } else {
		cli_dbgmsg("Eliminated false positive match (fp sig: %s)\n", md5_node->virname);
		free(digest);
		return 1;
	    }
	}

	free(digest);
    }

    return 0;
}

int cli_validatesig(cli_file_t ftype, const char *offstr, off_t fileoff, struct cli_target_info *info, int desc, const char *virname)
{
	off_t offset;
	int ret;
	unsigned int maxshift = 0;


    if(offstr && desc != -1) {
	offset = cli_caloff(offstr, info, desc, ftype, &ret, &maxshift);

	if(ret == -1) {
	    cli_dbgmsg("cli_validatesig: Can't calculate offset for signature %s\n", virname);
	    return 0;
	}

	if(maxshift) {
	    if((fileoff < offset) || (fileoff > offset + (off_t) maxshift)) {
		cli_dbgmsg("Signature offset: %lu, expected: [%lu..%lu] (%s)\n", fileoff, offset, offset + maxshift, virname);
		return 0;
	    }
	} else if(fileoff != offset) {
	    cli_dbgmsg("Signature offset: %lu, expected: %lu (%s)\n", fileoff, offset, virname);
	    return 0;
	}
    }

    return 1;
}

int cli_scandesc(int desc, cli_ctx *ctx, uint8_t otfrec, cli_file_t ftype, uint8_t ftonly, struct cli_matched_type **ftoffset)
{
 	unsigned char *buffer, *buff, *endbl, *upt;
	int ret = CL_CLEAN, type = CL_CLEAN, i, bytes;
	uint32_t buffersize, length, maxpatlen, shift = 0, offset = 0;
	struct cli_ac_data gdata, tdata;
	cli_md5_ctx md5ctx;
	unsigned char digest[16];
	struct cli_md5_node *md5_node;
	struct cli_matcher *groot = NULL, *troot = NULL;


    if(!ctx->engine) {
	cli_errmsg("cli_scandesc: engine == NULL\n");
	return CL_ENULLARG;
    }

    if(!ftonly)
	groot = ctx->engine->root[0]; /* generic signatures */

    if(ftype) {
	for(i = 1; i < CL_TARGET_TABLE_SIZE; i++) {
	    if(targettab[i] == ftype) {
		troot = ctx->engine->root[i];
		break;
	    }
	}
    }

    if(ftonly) {
	if(!troot)
	    return CL_CLEAN;

	maxpatlen = troot->maxpatlen;
    } else {
	if(troot)
	    maxpatlen = MAX(troot->maxpatlen, groot->maxpatlen);
	else
	    maxpatlen = groot->maxpatlen;
    }

    /* prepare the buffer */
    buffersize = maxpatlen + SCANBUFF;
    if(!(buffer = (unsigned char *) cli_calloc(buffersize, sizeof(unsigned char)))) {
	cli_dbgmsg("cli_scandesc(): unable to cli_calloc(%u)\n", buffersize);
	return CL_EMEM;
    }

    if(!ftonly && (ret = cli_ac_initdata(&gdata, groot->ac_partsigs, AC_DEFAULT_TRACKLEN)))
	return ret;

    if(troot) {
	if((ret = cli_ac_initdata(&tdata, troot->ac_partsigs, AC_DEFAULT_TRACKLEN)))
	    return ret;
    }

    if(!ftonly && ctx->engine->md5_hlist)
	cli_md5_init(&md5ctx);

    buff = buffer;
    buff += maxpatlen; /* pointer to read data block */
    endbl = buff + SCANBUFF - maxpatlen; /* pointer to the last block
					  * length of maxpatlen
					  */

    upt = buff;
    while((bytes = cli_readn(desc, buff + shift, SCANBUFF - shift)) > 0) {

	if(ctx->scanned)
	    *ctx->scanned += bytes / CL_COUNT_PRECISION;

	length = shift + bytes;
	if(upt == buffer)
	    length += maxpatlen;

	if(troot) {
	    if(troot->ac_only || (ret = cli_bm_scanbuff(upt, length, ctx->virname, troot, offset, ftype, desc)) != CL_VIRUS)
		ret = cli_ac_scanbuff(upt, length, ctx->virname, troot, &tdata, otfrec, offset, ftype, desc, ftoffset);

	    if(ret == CL_VIRUS) {
		free(buffer);
		if(!ftonly)
		    cli_ac_freedata(&gdata);
		cli_ac_freedata(&tdata);

		lseek(desc, 0, SEEK_SET);
		if(cli_checkfp(desc, ctx->engine))
		    return CL_CLEAN;
		else
		    return CL_VIRUS;
	    }
	}

	if(!ftonly) {
	    if(groot->ac_only || (ret = cli_bm_scanbuff(upt, length, ctx->virname, groot, offset, ftype, desc)) != CL_VIRUS)
		ret = cli_ac_scanbuff(upt, length, ctx->virname, groot, &gdata, otfrec, offset, ftype, desc, ftoffset);

	    if(ret == CL_VIRUS) {
		free(buffer);
		cli_ac_freedata(&gdata);
		if(troot)
		    cli_ac_freedata(&tdata);
		lseek(desc, 0, SEEK_SET);
		if(cli_checkfp(desc, ctx->engine))
		    return CL_CLEAN;
		else
		    return CL_VIRUS;

	    } else if(otfrec && ret >= CL_TYPENO) {
		if(ret > type)
		    type = ret;
	    }

	    if(ctx->engine->md5_hlist)
		cli_md5_update(&md5ctx, buff + shift, bytes);
	}

	if(bytes + shift == SCANBUFF) {
	    memmove(buffer, endbl, maxpatlen);
	    offset += SCANBUFF;

	    if(upt == buff) {
		upt = buffer;
		offset -= maxpatlen;
	    }

	    shift = 0;

	} else {
	    shift += bytes;
	}

    }

    free(buffer);
    if(!ftonly)
	cli_ac_freedata(&gdata);
    if(troot)
	cli_ac_freedata(&tdata);

    if(!ftonly && ctx->engine->md5_hlist) {
	cli_md5_final(digest, &md5ctx);

	if((md5_node = cli_vermd5(digest, ctx->engine)) && !md5_node->fp) {
		struct stat sb;

	    if(fstat(desc, &sb))
		return CL_EIO;

	    if((unsigned int) sb.st_size != md5_node->size) {
		cli_warnmsg("Detected false positive MD5 match. Please report.\n");
	    } else {
		if(ctx->virname)
		    *ctx->virname = md5_node->virname;

		return CL_VIRUS;
	    }
	}
    }

    return otfrec ? type : CL_CLEAN;
}
