/*
 *  Copyright (C) 2002 - 2006 Tomasz Kojm <tkojm@clamav.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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

static int targettab[CL_TARGET_TABLE_SIZE] = { 0, CL_TYPE_MSEXE, CL_TYPE_MSOLE2, CL_TYPE_HTML, CL_TYPE_MAIL, CL_TYPE_GRAPHICS, CL_TYPE_ELF };

extern short cli_debug_flag;

#ifdef HAVE_NCORE
#include <sn_sigscan/sn_sigscan.h>
#define HWBUFFSIZE 32768
#endif


int cli_scanbuff(const unsigned char *buffer, unsigned int length, const char **virname, const struct cl_engine *engine, unsigned short ftype)
{
	int ret = CL_CLEAN, i, tid = 0;
	struct cli_ac_data mdata;
	struct cli_matcher *groot, *troot = NULL;
#ifdef HAVE_NCORE
	void *streamhandle;
	void *resulthandle;
	uint32_t datamask[2] = { 0xffffffff, 0xffffffff };
	int count, hret;
	unsigned long long offset;
	char *pt;
#endif


    if(!engine) {
	cli_errmsg("cli_scanbuff: engine == NULL\n");
	return CL_ENULLARG;
    }

#ifdef HAVE_NCORE
    if(engine->ncore) {
	/* TODO: Setup proper data bitmask (need specs) */
	if((hret = sn_sigscan_createstream(engine->ncdb, datamask, 2, &streamhandle)) < 0) {
	    cli_errmsg("cli_scanbuff: can't create new hardware stream: %d\n", hret);
	    return CL_ENCIO;
	}

	if((hret = sn_sigscan_writestream(streamhandle, buffer, length)) < 0) {
	    cli_errmsg("cli_scanbuff: can't write %u bytes to hardware stream: %d\n", length, hret);
	    sn_sigscan_closestream(streamhandle, &resulthandle);
	    return CL_ENCIO;
	}

	if((hret = sn_sigscan_closestream(streamhandle, &resulthandle)) < 0) {
	    cli_errmsg("cli_scanbuff: can't close hardware stream: %d\n", hret);
	    return CL_ENCIO;
	}

	count = sn_sigscan_resultcount(resulthandle);

	for(i = 0; i < count; i++) {
		const char *matchname = NULL, *offsetstring = NULL, *optionalsigdata = NULL;
		int targettype = 0;

	    if((hret = sn_sigscan_resultget_name(resulthandle, i, &matchname) < 0)) {
		cli_errmsg("cli_scanbuff: sn_sigscan_resultget_name failed for result %u: %d\n", i, hret);
		sn_sigscan_resultfree(resulthandle);
		return CL_ENCIO;
	    }
	    if(!matchname) {
		cli_errmsg("cli_scanbuff: HW Result[%u]: Signature without name\n", i);
		sn_sigscan_resultfree(resulthandle);
		return CL_EMALFDB;
	    }

	    if((hret = sn_sigscan_resultget_targettype(resulthandle, i, &targettype) < 0)) {
		cli_errmsg("cli_scanbuff: sn_sigscan_resultget_targettype failed for result %u, signature %s: %d\n", i, matchname, hret);
		sn_sigscan_resultfree(resulthandle);
		return CL_ENCIO;
	    }
	    if(targettype && targettab[targettype] != (int) ftype) {
		cli_dbgmsg("cli_scanbuff: HW Result[%u]: %s: Target type: %u, expected: %u\n", i, matchname, targettab[targettype], ftype);
		continue;
	    }

	    if((hret = sn_sigscan_resultget_offsetstring(resulthandle, i, &offsetstring) < 0)) {
		cli_errmsg("cli_scanbuff: sn_sigscan_resultget_offsetstring failed for result %u, signature %s: %d\n", i, matchname, hret);
		sn_sigscan_resultfree(resulthandle);
		return CL_ENCIO;
	    }
	    if(offsetstring) {
		cli_dbgmsg("cli_scanbuff: HW Result[%u]: %s: Offset based signature not supported in buffer mode\n", i, matchname);
		continue;
	    }

	    if((hret = sn_sigscan_resultget_extradata(resulthandle, i, &optionalsigdata) < 0)) {
		cli_errmsg("cli_scanbuff: sn_sigscan_resultget_extradata failed for result %u, signature %s: %d\n", i, matchname, hret);
		sn_sigscan_resultfree(resulthandle);
		return CL_ENCIO;
	    }
	    if(optionalsigdata && strlen(optionalsigdata)) {
		if((pt = cli_strtok(optionalsigdata, 1, ":"))) { /* max version */
		    if(!isdigit(*pt)) {
			free(pt);
			cli_errmsg("cli_scanbuff: HW Result[%u]: %s: Incorrect optional signature data: %s\n", i, matchname, optionalsigdata);
			sn_sigscan_resultfree(resulthandle);
			return CL_EMALFDB;
		    }

		    if(atoi(pt) < cl_retflevel()) {
			cli_dbgmsg("cli_scanbuff: HW Result[%u]: %s: Signature max flevel: %u, current: %u\n", i, matchname, atoi(pt), cl_retflevel());
			free(pt);
			continue;
		    }

		    free(pt);
		    if((pt = cli_strtok(optionalsigdata, 0, ":"))) { /* min version */
			if(!isdigit(*pt)) {
			    free(pt);
			    cli_errmsg("cli_scanbuff: HW Result[%u]: %s: Incorrect optional signature data: %s\n", i, matchname, optionalsigdata);
			    sn_sigscan_resultfree(resulthandle);
			    return CL_EMALFDB;
			}

			if(atoi(pt) > cl_retflevel()) {
			    cli_dbgmsg("cli_scanbuff: HW Result[%u]: %s: Signature required flevel: %u, current: %u\n", i, matchname, atoi(pt), cl_retflevel());
			    free(pt);
			    continue;
			}
			free(pt);
		    }

		} else {
		    if(!isdigit(*optionalsigdata)) {
			cli_errmsg("cli_scanbuff: HW Result[%u]: %s: Incorrect optional signature data: %s\n", i, matchname, optionalsigdata);
			sn_sigscan_resultfree(resulthandle);
			return CL_EMALFDB;
		    }

		    if(atoi(optionalsigdata) > cl_retflevel()) {
			cli_dbgmsg("cli_scandesc: HW Result[%u]: %s: Signature required flevel: %u, current: %u\n", i, matchname, atoi(optionalsigdata), cl_retflevel());
			continue;
		    }
		}
	    }

	    *virname = matchname;
	    ret = CL_VIRUS;
	    break;
	}

	if((hret = sn_sigscan_resultfree(resulthandle)) < 0) {
	    cli_errmsg("cli_scanbuff: can't free results: %d\n", ret);
	    return CL_ENCIO;
	}

	return ret;
    }
#endif /* HAVE_NCORE */


    groot = engine->root[0]; /* generic signatures */

    if(ftype) {
	for(i = 0; i < CL_TARGET_TABLE_SIZE; i++) {
	    if(targettab[i] == ftype) {
		tid = i;
		break;
	    }
	}
	if(tid)
	    troot = engine->root[tid];
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

static struct cli_md5_node *cli_vermd5(const unsigned char *md5, const struct cl_engine *engine)
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

static off_t cli_caloff(const char *offstr, struct cli_target_info *info, int fd, unsigned short ftype, int *ret)
{
	int (*einfo)(int, struct cli_exe_info *) = NULL;
	unsigned int n;
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

    if(isdigit(offstr[0])) {
	return atoi(offstr);

    } else if(info->status == 1 && (!strncmp(offstr, "EP+", 3) || !strncmp(offstr, "EP-", 3))) {

	if(offstr[2] == '+')
	    return info->exeinfo.ep + atoi(offstr + 3);
	else
	    return info->exeinfo.ep - atoi(offstr + 3);

    } else if(info->status == 1 && offstr[0] == 'S') {

	if(!strncmp(offstr, "SL", 2)) {

	    if(sscanf(offstr, "SL+%lu", &offset) != 1) {
		*ret = -1;
		return 0;
	    }

	    offset += info->exeinfo.section[info->exeinfo.nsections - 1].raw;

	} else {

	    if(sscanf(offstr, "S%u+%lu", &n, &offset) != 2) {
		*ret = -1;
		return 0;
	    }

	    if(n >= info->exeinfo.nsections) {
		*ret = -1;
		return 0;
	    }

	    offset += info->exeinfo.section[n].raw;
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

int cli_validatesig(unsigned short ftype, const char *offstr, off_t fileoff, struct cli_target_info *info, int desc, const char *virname)
{
	off_t offset;
	int ret;


    if(offstr && desc != -1) {
	offset = cli_caloff(offstr, info, desc, ftype, &ret);

	if(ret == -1) {
	    cli_dbgmsg("cli_validatesig: Can't calculate offset for signature %s\n", virname);
	    return 0;
	}

	if(fileoff != offset) {
	    cli_dbgmsg("Signature offset: %lu, expected: %lu (%s)\n", fileoff, offset, virname);
	    return 0;
	}
    }

    return 1;
}

int cli_scandesc(int desc, cli_ctx *ctx, unsigned short otfrec, unsigned short ftype, struct cli_matched_type **ftoffset)
{
 	unsigned char *buffer, *buff, *endbl, *upt;
	int ret = CL_CLEAN, type = CL_CLEAN, i, tid = 0, bytes;
	unsigned int buffersize, length, maxpatlen, shift = 0;
	unsigned long int offset = 0;
	struct cli_ac_data gdata, tdata;
	MD5_CTX md5ctx;
	unsigned char digest[16];
	struct cli_md5_node *md5_node;
	struct cli_matcher *groot, *troot = NULL;
#ifdef HAVE_NCORE
	void *streamhandle;
	void *resulthandle;
	unsigned long long hoffset;
	uint32_t datamask[2] = { 0xffffffff, 0xffffffff };
	int count, hret;
	off_t origoff;
	char *pt;
	struct cli_target_info info;
#endif


    if(!ctx->engine) {
	cli_errmsg("cli_scandesc: engine == NULL\n");
	return CL_ENULLARG;
    }

#ifdef HAVE_NCORE
    if(ctx->engine->ncore) {
	/* TODO: Setup proper data bitmask (need specs) */
	if((hret = sn_sigscan_createstream(ctx->engine->ncdb, datamask, 2, &streamhandle)) < 0) {
	    cli_errmsg("cli_scandesc: can't create new hardware stream: %d\n", hret);
	    return CL_ENCIO;
	}

	if(!(buffer = (char *) cli_calloc(HWBUFFSIZE, sizeof(char)))) {
	    cli_dbgmsg("cli_scandesc: unable to cli_calloc(%u)\n", HWBUFFSIZE);
	    return CL_EMEM;
	}

	if((origoff = lseek(desc, 0, SEEK_CUR)) == -1) {
	    cli_errmsg("cli_scandesc: lseek() failed for descriptor %d\n", desc);
	    free(buffer);
	    return CL_EIO;
	}

	if(ctx->engine->md5_hlist)
	    MD5_Init(&md5ctx);

	while((bytes = cli_readn(desc, buffer, HWBUFFSIZE)) > 0) {
	    if((hret = sn_sigscan_writestream(streamhandle, buffer, bytes)) < 0) {
		cli_errmsg("cli_scandesc: can't write to hardware stream: %d\n", hret);
		ret = CL_ENCIO;
		break;
	    } else {
		if(ctx->scanned)
		    *ctx->scanned += bytes / CL_COUNT_PRECISION;

		if(ctx->engine->md5_hlist)
		    MD5_Update(&md5ctx, buffer, bytes);
	    }
	}

	free(buffer);

	if((hret = sn_sigscan_closestream(streamhandle, &resulthandle)) < 0) {
	    cli_errmsg("cli_scandesc: can't close hardware stream: %d\n", hret);
	    return CL_ENCIO;
	}

	count = sn_sigscan_resultcount(resulthandle);

	memset(&info, 0, sizeof(info));

	for(i = 0; i < count; i++) {
		const char *matchname = NULL, *offsetstring = NULL, *optionalsigdata = NULL;
		unsigned long long startoffset = 0;
		off_t offset;
		int targettype = 0;

	    if((hret = sn_sigscan_resultget_name(resulthandle, i, &matchname) < 0)) {
		cli_errmsg("cli_scandesc: sn_sigscan_resultget_name failed for result %u: %d\n", i, hret);
		sn_sigscan_resultfree(resulthandle);
		if(info.exeinfo.section)
		    free(info.exeinfo.section);
		return CL_ENCIO;
	    }

	    if(!matchname) {
		cli_errmsg("cli_scandesc: HW Result[%u]: Signature without name\n", i);
		sn_sigscan_resultfree(resulthandle);
		if(info.exeinfo.section)
		    free(info.exeinfo.section);
		return CL_EMALFDB;
	    }

	    if((hret = sn_sigscan_resultget_targettype(resulthandle, i, &targettype) < 0)) {
		cli_errmsg("cli_scandesc: sn_sigscan_resultget_targettype failed for result %u, signature %s: %d\n", i, matchname, hret);
		sn_sigscan_resultfree(resulthandle);
		if(info.exeinfo.section)
		    free(info.exeinfo.section);
		return CL_ENCIO;
	    }
	    if(targettype && targettab[targettype] != (int) ftype) {
		cli_dbgmsg("cli_scandesc: HW Result[%u]: %s: Target type: %u, expected: %u\n", i, matchname, targettab[targettype], ftype);
		continue;
	    }

	    if((hret = sn_sigscan_resultget_offsetstring(resulthandle, i, &offsetstring) < 0)) {
		cli_errmsg("cli_scandesc: sn_sigscan_resultget_offsetstring failed for result %u, signature %s: %d\n", i, matchname, hret);
		sn_sigscan_resultfree(resulthandle);
		if(info.exeinfo.section)
		    free(info.exeinfo.section);
		return CL_ENCIO;
	    }
	    if((hret = sn_sigscan_resultget_startoffset(resulthandle, i, &startoffset) < 0)) {
		cli_errmsg("cli_scandesc: sn_sigscan_resultget_startoffset failed for result %u, signature %s: %d\n", i, matchname, hret);
		sn_sigscan_resultfree(resulthandle);
		if(info.exeinfo.section)
		    free(info.exeinfo.section);
		return CL_ENCIO;
	    }
	    if(offsetstring && strcmp(offsetstring, "*")) {
		    off_t off = cli_caloff(offsetstring, &info, desc, ftype, &hret);

		if(hret == -1) {
		    cli_dbgmsg("cli_scandesc: HW Result[%u]: %s: Bad offset in signature\n", i, matchname);
		    sn_sigscan_resultfree(resulthandle);
		    if(info.exeinfo.section)
			free(info.exeinfo.section);
		    return CL_EMALFDB;
		}

		if(startoffset != (unsigned long long) off) {
		    cli_dbgmsg("cli_scandesc: HW Result[%u]: %s: Virus offset: %lu, expected: %lu\n", i, matchname, startoffset, off);
		    continue;
		}
	    }

	    if((hret = sn_sigscan_resultget_extradata(resulthandle, i, &optionalsigdata) < 0)) {
		cli_errmsg("cli_scandesc: sn_sigscan_resultget_extradata failed for result %u, signature %s: %u\n", i, matchname, hret);
		sn_sigscan_resultfree(resulthandle);
		if(info.exeinfo.section)
		    free(info.exeinfo.section);
		return CL_ENCIO;
	    }
	    if(optionalsigdata && strlen(optionalsigdata)) {
		if((pt = cli_strtok(optionalsigdata, 1, ":"))) { /* max version */
		    if(!isdigit(*pt)) {
			free(pt);
			cli_errmsg("cli_scandesc: HW Result[%u]: %s: Incorrect optional signature data: %s\n", i, matchname, optionalsigdata);
			sn_sigscan_resultfree(resulthandle);
			if(info.exeinfo.section)
			    free(info.exeinfo.section);
			return CL_EMALFDB;
		    }

		    if(atoi(pt) < cl_retflevel()) {
			cli_dbgmsg("cli_scandesc: HW Result[%u]: %s: Signature max flevel: %u, current: %u\n", i, matchname, atoi(pt), cl_retflevel());
			free(pt);
			continue;
		    }

		    free(pt);
		    if((pt = cli_strtok(optionalsigdata, 0, ":"))) { /* min version */
			if(!isdigit(*pt)) {
			    free(pt);
			    cli_errmsg("cli_scandesc: HW Result[%u]: %s: Incorrect optional signature data: %s\n", i, matchname, optionalsigdata);
			    sn_sigscan_resultfree(resulthandle);
			    if(info.exeinfo.section)
				free(info.exeinfo.section);
			    return CL_EMALFDB;
			}

			if(atoi(pt) > cl_retflevel()) {
			    cli_dbgmsg("cli_scandesc: HW Result[%u]: %s: Signature required flevel: %u, current: %u\n", i, matchname, atoi(pt), cl_retflevel());
			    free(pt);
			    continue;
			}
			free(pt);
		    }

		} else {
		    if(!isdigit(*optionalsigdata)) {
			cli_errmsg("cli_scandesc: HW Result[%u]: %s: Incorrect optional signature data: %s\n", i, matchname, optionalsigdata);
			sn_sigscan_resultfree(resulthandle);
			if(info.exeinfo.section)
			    free(info.exeinfo.section);
			return CL_EMALFDB;
		    }

		    if(atoi(optionalsigdata) > cl_retflevel()) {
			cli_dbgmsg("cli_scandesc: HW Result[%u]: %s: Signature required flevel: %u, current: %u\n", i, matchname, atoi(optionalsigdata), cl_retflevel());
			continue;
		    }
		}
	    }

	    *ctx->virname = matchname;
	    ret = CL_VIRUS;
	    break;
	}

	if(info.exeinfo.section)
	    free(info.exeinfo.section);

	if((hret = sn_sigscan_resultfree(resulthandle)) < 0) {
	    cli_errmsg("cli_scandesc: can't free results: %d\n", ret);
	    return CL_ENCIO;
	}

	if(ctx->engine->md5_hlist) {
	    MD5_Final(digest, &md5ctx);

	    if((md5_node = cli_vermd5(digest, ctx->engine))) {
		struct stat sb;

		if(fstat(desc, &sb))
		    return CL_EIO;

		if((unsigned int) sb.st_size != md5_node->size) {
		    cli_warnmsg("Detected false positive MD5 match. Please report.\n");
		} else {
		    if(md5_node->fp) {
			cli_dbgmsg("Eliminated false positive match (fp sig: %s)\n", md5_node->virname);
			ret = CL_CLEAN;
		    } else {
			if(ctx->virname)
			    *ctx->virname = md5_node->virname;
			ret = CL_VIRUS;
		    }
		}
	    }
	}

	if(ret == CL_VIRUS || (ftype != CL_TYPE_UNKNOWN_TEXT && ftype != CL_TYPE_UNKNOWN_DATA))
	    return ret;

	if((origoff = lseek(desc, origoff, SEEK_SET)) == -1) {
	    cli_errmsg("cli_scandesc: lseek() failed for descriptor %d\n", desc);
	    return CL_EIO;
	}
    }
#endif /* HAVE_NCORE */


    groot = ctx->engine->root[0]; /* generic signatures */

    if(ftype) {
	for(i = 0; i < CL_TARGET_TABLE_SIZE; i++) {
	    if(targettab[i] == ftype) {
		tid = i;
		break;
	    }
	}
	if(tid)
	    troot = ctx->engine->root[tid];
    }

    if(troot)
	maxpatlen = MAX(troot->maxpatlen, groot->maxpatlen);
    else
	maxpatlen = groot->maxpatlen;

    /* prepare the buffer */
    buffersize = maxpatlen + SCANBUFF;
    if(!(buffer = (unsigned char *) cli_calloc(buffersize, sizeof(unsigned char)))) {
	cli_dbgmsg("cli_scandesc(): unable to cli_calloc(%u)\n", buffersize);
	return CL_EMEM;
    }

    if((ret = cli_ac_initdata(&gdata, groot->ac_partsigs, AC_DEFAULT_TRACKLEN)))
	return ret;

    if(troot) {
	if((ret = cli_ac_initdata(&tdata, troot->ac_partsigs, AC_DEFAULT_TRACKLEN)))
	    return ret;
    }

    if(ctx->engine->md5_hlist)
	MD5_Init(&md5ctx);


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
		cli_ac_freedata(&gdata);
		cli_ac_freedata(&tdata);

		lseek(desc, 0, SEEK_SET);
		if(cli_checkfp(desc, ctx->engine))
		    return CL_CLEAN;
		else
		    return CL_VIRUS;
	    }
	}

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
	    if(ret >= type)
		type = ret;
	}

	if(ctx->engine->md5_hlist)
	    MD5_Update(&md5ctx, buff + shift, bytes);

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
    cli_ac_freedata(&gdata);
    if(troot)
	cli_ac_freedata(&tdata);

    if(ctx->engine->md5_hlist) {
	MD5_Final(digest, &md5ctx);

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
