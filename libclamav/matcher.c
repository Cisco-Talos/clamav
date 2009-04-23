/*
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
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
#include "default.h"


int cli_scanbuff(const unsigned char *buffer, uint32_t length, uint32_t offset, cli_ctx *ctx, cli_file_t ftype, struct cli_ac_data **acdata)
{
	int ret = CL_CLEAN;
	unsigned int i;
	struct cli_ac_data mdata;
	struct cli_matcher *groot, *troot = NULL;
	const char **virname=ctx->virname;
	const struct cl_engine *engine=ctx->engine;

    if(!engine) {
	cli_errmsg("cli_scanbuff: engine == NULL\n");
	return CL_ENULLARG;
    }

    groot = engine->root[0]; /* generic signatures */

    if(ftype) {
	for(i = 1; i < CLI_MTARGETS; i++) {
	    if(cli_mtargets[i].target == ftype) {
		troot = engine->root[i];
		break;
	    }
	}
    }

    if(troot) {

	if(!acdata && (ret = cli_ac_initdata(&mdata, troot->ac_partsigs, troot->ac_lsigs, CLI_DEFAULT_AC_TRACKLEN)))
	    return ret;

	if(troot->ac_only || (ret = cli_bm_scanbuff(buffer, length, virname, troot, offset, ftype, -1)) != CL_VIRUS)
	    ret = cli_ac_scanbuff(buffer, length, virname, NULL, NULL, troot, acdata ? (acdata[0]) : (&mdata), offset, ftype, -1, NULL, AC_SCAN_VIR, NULL);

	if(!acdata)
	    cli_ac_freedata(&mdata);

	if(ret == CL_VIRUS)
	    return ret;
    }

    if(!acdata && (ret = cli_ac_initdata(&mdata, groot->ac_partsigs, groot->ac_lsigs, CLI_DEFAULT_AC_TRACKLEN)))
	return ret;

    if(groot->ac_only || (ret = cli_bm_scanbuff(buffer, length, virname, groot, offset, ftype, -1)) != CL_VIRUS)
	ret = cli_ac_scanbuff(buffer, length, virname, NULL, NULL, groot, acdata ? (acdata[1]) : (&mdata), offset, ftype, -1, NULL, AC_SCAN_VIR, NULL);

    if(!acdata)
	cli_ac_freedata(&mdata);

    return ret;
}

off_t cli_caloff(const char *offstr, struct cli_target_info *info, int fd, cli_file_t ftype, int *ret, unsigned int *maxshift)
{
	int (*einfo)(int, struct cli_exe_info *) = NULL;
	unsigned int n, val;
	const char *pt;
	off_t pos, offset;


    *ret = 0;

    if((pt = strchr(offstr, ',')))
	*maxshift = atoi(++pt);

    if(isdigit(offstr[0]))
	return atoi(offstr);

    if(fd == -1) {
	*ret = -1;
	return 0;
    }

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

    if(info->status == 1 && (!strncmp(offstr, "EP+", 3) || !strncmp(offstr, "EP-", 3))) {

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

int cli_checkfp(int fd, cli_ctx *ctx)
{
	unsigned char *digest;
	const char *virname;
	off_t pos;


    if((pos = lseek(fd, 0, SEEK_CUR)) == -1) {
	cli_errmsg("cli_checkfp(): lseek() failed\n");
	return 0;
    }

    lseek(fd, 0, SEEK_SET);

    if(ctx->engine->md5_fp) {
	if(!(digest = cli_md5digest(fd))) {
	    cli_errmsg("cli_checkfp(): Can't generate MD5 checksum\n");
	    lseek(fd, pos, SEEK_SET);
	    return 0;
	}

	if(cli_bm_scanbuff(digest, 16, &virname, ctx->engine->md5_fp, 0, 0, -1) == CL_VIRUS) {
	    cli_dbgmsg("cli_checkfp(): Found false positive detection (fp sig: %s)\n", virname);
	    free(digest);
	    lseek(fd, pos, SEEK_SET);
	    return 1;
	}
	free(digest);
    }

    lseek(fd, pos, SEEK_SET);
    return 0;
}

int cli_validatesig(cli_file_t ftype, const char *offstr, off_t fileoff, struct cli_target_info *info, int desc, const char *virname)
{
	off_t offset;
	int ret;
	unsigned int maxshift = 0;


    if(offstr) {
	offset = cli_caloff(offstr, info, desc, ftype, &ret, &maxshift);

	if(ret == -1)
	    return 0;

	if(maxshift) {
	    if((fileoff < offset) || (fileoff > offset + (off_t) maxshift)) {
		/* cli_dbgmsg("Signature offset: %lu, expected: [%lu..%lu] (%s)\n", (unsigned long int) fileoff, (unsigned long int) offset, (unsigned long int) (offset + maxshift), virname); */
		return 0;
	    }
	} else if(fileoff != offset) {
	    /* cli_dbgmsg("Signature offset: %lu, expected: %lu (%s)\n", (unsigned long int) fileoff, (unsigned long int) offset, virname); */
	    return 0;
	}
    }

    return 1;
}

int cli_scandesc(int desc, cli_ctx *ctx, cli_file_t ftype, uint8_t ftonly, struct cli_matched_type **ftoffset, unsigned int acmode)
{
 	unsigned char *buffer, *buff, *endbl, *upt;
	int ret = CL_CLEAN, type = CL_CLEAN, bytes;
	unsigned int i, evalcnt;
	uint32_t buffersize, length, maxpatlen, shift = 0, offset = 0;
	uint64_t evalids;
	struct cli_ac_data gdata, tdata;
	cli_md5_ctx md5ctx;
	unsigned char digest[16];
	struct cli_matcher *groot = NULL, *troot = NULL;


    if(!ctx->engine) {
	cli_errmsg("cli_scandesc: engine == NULL\n");
	return CL_ENULLARG;
    }

    if(!ftonly)
	groot = ctx->engine->root[0]; /* generic signatures */

    if(ftype) {
	for(i = 1; i < CLI_MTARGETS; i++) {
	    if(cli_mtargets[i].target == ftype) {
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

    if(!ftonly && (ret = cli_ac_initdata(&gdata, groot->ac_partsigs, groot->ac_lsigs, CLI_DEFAULT_AC_TRACKLEN)))
	return ret;

    if(troot) {
	if((ret = cli_ac_initdata(&tdata, troot->ac_partsigs, troot->ac_lsigs, CLI_DEFAULT_AC_TRACKLEN)))
	    return ret;
    }

    if(!ftonly && ctx->engine->md5_hdb)
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
		ret = cli_ac_scanbuff(upt, length, ctx->virname, NULL, NULL, troot, &tdata, offset, ftype, desc, ftoffset, acmode, NULL);

	    if(ret == CL_VIRUS) {
		free(buffer);
		if(!ftonly)
		    cli_ac_freedata(&gdata);
		cli_ac_freedata(&tdata);

		if(cli_checkfp(desc, ctx))
		    return CL_CLEAN;
		else
		    return CL_VIRUS;
	    }
	}

	if(!ftonly) {
	    if(groot->ac_only || (ret = cli_bm_scanbuff(upt, length, ctx->virname, groot, offset, ftype, desc)) != CL_VIRUS)
		ret = cli_ac_scanbuff(upt, length, ctx->virname, NULL, NULL, groot, &gdata, offset, ftype, desc, ftoffset, acmode, NULL);

	    if(ret == CL_VIRUS) {
		free(buffer);
		cli_ac_freedata(&gdata);
		if(troot)
		    cli_ac_freedata(&tdata);
		if(cli_checkfp(desc, ctx))
		    return CL_CLEAN;
		else
		    return CL_VIRUS;

	    } else if((acmode & AC_SCAN_FT) && ret >= CL_TYPENO) {
		if(ret > type)
		    type = ret;
	    }

	    if(ctx->engine->md5_hdb)
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

    if(troot) {
	for(i = 0; i < troot->ac_lsigs; i++) {
	    evalcnt = 0;
	    evalids = 0;
	    if(cli_ac_chklsig(troot->ac_lsigtable[i]->logic, troot->ac_lsigtable[i]->logic + strlen(troot->ac_lsigtable[i]->logic), tdata.lsigcnt[i], &evalcnt, &evalids, 0) == 1) {
		if(ctx->virname)
		    *ctx->virname = troot->ac_lsigtable[i]->virname;
		ret = CL_VIRUS;
		break;
	    }
	}
	cli_ac_freedata(&tdata);
    }

    if(groot) {
	if(ret != CL_VIRUS) for(i = 0; i < groot->ac_lsigs; i++) {
	    evalcnt = 0;
	    evalids = 0;
	    if(cli_ac_chklsig(groot->ac_lsigtable[i]->logic, groot->ac_lsigtable[i]->logic + strlen(groot->ac_lsigtable[i]->logic), gdata.lsigcnt[i], &evalcnt, &evalids, 0) == 1) {
		if(ctx->virname)
		    *ctx->virname = groot->ac_lsigtable[i]->virname;
		ret = CL_VIRUS;
		break;
	    }
	}
	cli_ac_freedata(&gdata);
    }

    if(ret == CL_VIRUS) {
	lseek(desc, 0, SEEK_SET);
	if(cli_checkfp(desc, ctx))
	    return CL_CLEAN;
	else
	    return CL_VIRUS;
    }

    if(!ftonly && ctx->engine->md5_hdb) {
	cli_md5_final(digest, &md5ctx);
	if(cli_bm_scanbuff(digest, 16, ctx->virname, ctx->engine->md5_hdb, 0, 0, -1) == CL_VIRUS && (cli_bm_scanbuff(digest, 16, NULL, ctx->engine->md5_fp, 0, 0, -1) != CL_VIRUS))
	    return CL_VIRUS;
    }

    return (acmode & AC_SCAN_FT) ? type : CL_CLEAN;
}
