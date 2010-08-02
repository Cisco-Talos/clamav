/*
 *  Copyright (C) 2007-2009 Sourcefire, Inc.
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
#include "matcher-md5.h"
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
#include "macho.h"
#include "fmap.h"
#include "pe_icons.h"
#include "regex/regex.h"
#include "filtering.h"
#include "perflogging.h"
#include "bytecode_priv.h"
#include "bytecode_api_impl.h"

#ifdef HAVE__INTERNAL__SHA_COLLECT
#include "sha256.h"
#include "sha1.h"
#endif

#ifdef CLI_PERF_LOGGING

static inline void PERF_LOG_FILTER(int32_t pos, int32_t length, int8_t trie)
{
    cli_perf_log_add(RAW_BYTES_SCANNED, length);
    cli_perf_log_add(FILTER_BYTES_SCANNED, length - pos);
    cli_perf_log_count2(TRIE_SCANNED, trie, length - pos);
}

static inline int PERF_LOG_TRIES(int8_t acmode, int8_t bm_called, int32_t length)
{
    if (bm_called)
	cli_perf_log_add(BM_SCANNED, length);
    if (acmode)
	cli_perf_log_add(AC_SCANNED, length);
    return 0;
}

#else
static inline void PERF_LOG_FILTER(int32_t pos, uint32_t length, int8_t trie) {}
static inline int PERF_LOG_TRIES(int8_t acmode, int8_t bm_called, int32_t length) { return 0; }
#endif

static inline int matcher_run(const struct cli_matcher *root,
			      const unsigned char *buffer, uint32_t length,
			      const char **virname, struct cli_ac_data *mdata,
			      uint32_t offset,
			      const struct cli_target_info *tinfo,
			      cli_file_t ftype,
			      struct cli_matched_type **ftoffset,
			      unsigned int acmode,
			      struct cli_ac_result **acres,
			      fmap_t *map,
			      struct cli_bm_off *offdata)
{
    int ret;
    int32_t pos = 0;
    struct filter_match_info info;
    uint32_t orig_length, orig_offset;
    const unsigned char* orig_buffer;

    if (root->filter) {
	if(filter_search_ext(root->filter, buffer, length, &info) == -1) {
	    /*  for safety always scan last maxpatlen bytes */
	    pos = length - root->maxpatlen - 1;
	    if (pos < 0) pos = 0;
	    PERF_LOG_FILTER(pos, length, root->type);
	} else {
	    /* must not cut buffer for 64[4-4]6161, because we must be able to check
	     * 64! */
	    pos = info.first_match - root->maxpatlen - 1;
	    if (pos < 0) pos = 0;
	    PERF_LOG_FILTER(pos, length, root->type);
	}
    } else {
	PERF_LOG_FILTER(0, length, root->type);
    }

    orig_length = length;
    orig_buffer = buffer;
    orig_offset = offset;
    length -= pos;
    buffer += pos;
    offset += pos;
    if (!root->ac_only) {
	PERF_LOG_TRIES(0, 1, length);
	if (root->bm_offmode) {
	    /* Don't use prefiltering for BM offset mode, since BM keeps tracks
	     * of offsets itself, and doesn't work if we skip chunks of input
	     * data */
	    ret = cli_bm_scanbuff(orig_buffer, orig_length, virname, NULL, root, orig_offset, tinfo, offdata);
	} else {
	    ret = cli_bm_scanbuff(buffer, length, virname, NULL, root, offset, tinfo, offdata);
	}
	if (ret == CL_VIRUS)
	    return ret;
    }
    PERF_LOG_TRIES(acmode, 0, length);
    ret = cli_ac_scanbuff(buffer, length, virname, NULL, acres, root, mdata, offset, ftype, ftoffset, acmode, NULL);
    return ret;
}

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

	if(!acdata && (ret = cli_ac_initdata(&mdata, troot->ac_partsigs, troot->ac_lsigs, troot->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN)))
	    return ret;

	ret = matcher_run(troot, buffer, length, virname, acdata ? (acdata[0]): (&mdata), offset, NULL, ftype, NULL, AC_SCAN_VIR, NULL, *ctx->fmap, NULL);

	if(!acdata)
	    cli_ac_freedata(&mdata);

	if(ret == CL_VIRUS || ret == CL_EMEM)
	    return ret;
    }

    if(!acdata && (ret = cli_ac_initdata(&mdata, groot->ac_partsigs, groot->ac_lsigs, groot->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN)))
	return ret;

    ret = matcher_run(groot, buffer, length, virname, acdata ? (acdata[1]): (&mdata), offset, NULL, ftype, NULL, AC_SCAN_VIR, NULL, *ctx->fmap, NULL);

    if(!acdata)
	cli_ac_freedata(&mdata);

    return ret;
}

/*
 * offdata[0]: type
 * offdata[1]: offset value
 * offdata[2]: max shift
 * offdata[3]: section number
 */
int cli_caloff(const char *offstr, const struct cli_target_info *info, unsigned int target, uint32_t *offdata, uint32_t *offset_min, uint32_t *offset_max)
{
	char offcpy[65];
	unsigned int n, val;
	char *pt;

    if(!info) { /* decode offset string */
	if(!offstr) {
	    cli_errmsg("cli_caloff: offstr == NULL\n");
	    return CL_ENULLARG;
	}

	if(!strcmp(offstr, "*")) {
	    offdata[0] = *offset_max = *offset_min = CLI_OFF_ANY;
	    return CL_SUCCESS;
	}

	if(strlen(offstr) > 64) {
	    cli_errmsg("cli_caloff: Offset string too long\n");
	    return CL_EMALFDB;
	}
	strcpy(offcpy, offstr);

	if((pt = strchr(offcpy, ','))) {
	    if(!cli_isnumber(pt + 1)) {
		cli_errmsg("cli_caloff: Invalid offset shift value\n");
		return CL_EMALFDB;
	    }
	    offdata[2] = atoi(pt + 1);
	    *pt = 0;
	} else {
	    offdata[2] = 0;
	}

	*offset_max = *offset_min = CLI_OFF_NONE;

	if(!strncmp(offcpy, "EP+", 3) || !strncmp(offcpy, "EP-", 3)) {
	    if(offcpy[2] == '+')
		offdata[0] = CLI_OFF_EP_PLUS;
	    else
		offdata[0] = CLI_OFF_EP_MINUS;

	    if(!cli_isnumber(&offcpy[3])) {
		cli_errmsg("cli_caloff: Invalid offset value\n");
		return CL_EMALFDB;
	    }
	    offdata[1] = atoi(&offcpy[3]);

	} else if(offcpy[0] == 'S') {
	    if(!strncmp(offstr, "SL+", 3)) {
		offdata[0] = CLI_OFF_SL_PLUS;
		if(!cli_isnumber(&offcpy[3])) {
		    cli_errmsg("cli_caloff: Invalid offset value\n");
		    return CL_EMALFDB;
		}
		offdata[1] = atoi(&offcpy[3]);

	    } else if(sscanf(offcpy, "S%u+%u", &n, &val) == 2) {
		offdata[0] = CLI_OFF_SX_PLUS;
		offdata[1] = val;
		offdata[3] = n;
	    } else {
		cli_errmsg("cli_caloff: Invalid offset string\n");
		return CL_EMALFDB;
	    }

	} else if(!strncmp(offcpy, "EOF-", 4)) {
	    offdata[0] = CLI_OFF_EOF_MINUS;
	    if(!cli_isnumber(&offcpy[4])) {
		cli_errmsg("cli_caloff: Invalid offset value\n");
		return CL_EMALFDB;
	    }
	    offdata[1] = atoi(&offcpy[4]);
	} else if(!strncmp(offcpy, "VI", 2)) {
	    /* versioninfo */
	    offdata[0] = CLI_OFF_VERSION;
	} else if (strchr(offcpy, '$')) {
	    if (sscanf(offcpy, "$%u$", &n) != 1) {
		cli_errmsg("cli_caloff: Invalid macro($) in offset: %s\n", offcpy);
		return CL_EMALFDB;
	    }
	    if (n >= 32) {
		cli_errmsg("cli_caloff: at most 32 macro groups supported\n");
		return CL_EMALFDB;
	    }
	    offdata[0] = CLI_OFF_MACRO;
	    offdata[1] = n;
	} else {
	    offdata[0] = CLI_OFF_ABSOLUTE;
	    if(!cli_isnumber(offcpy)) {
		cli_errmsg("cli_caloff: Invalid offset value\n");
		return CL_EMALFDB;
	    }
	    *offset_min = offdata[1] = atoi(offcpy);
	    *offset_max = *offset_min + offdata[2];
	}

	if(offdata[0] != CLI_OFF_ANY && offdata[0] != CLI_OFF_ABSOLUTE &&
	   offdata[0] != CLI_OFF_EOF_MINUS && offdata[0] != CLI_OFF_MACRO) {
	    if(target != 1 && target != 6 && target != 9) {
		cli_errmsg("cli_caloff: Invalid offset type for target %u\n", target);
		return CL_EMALFDB;
	    }
	}

    } else {
	/* calculate relative offsets */
	if(info->status == -1) {
	    *offset_min = CLI_OFF_NONE;
	    if(offset_max)
		*offset_max = CLI_OFF_NONE;
	    return CL_SUCCESS;
	}

	switch(offdata[0]) {
	    case CLI_OFF_EOF_MINUS:
		*offset_min = info->fsize - offdata[1];
		break;

	    case CLI_OFF_EP_PLUS:
		*offset_min = info->exeinfo.ep + offdata[1];
		break;

	    case CLI_OFF_EP_MINUS:
		*offset_min = info->exeinfo.ep - offdata[1];
		break;

	    case CLI_OFF_SL_PLUS:
		*offset_min = info->exeinfo.section[info->exeinfo.nsections - 1].raw + offdata[1];
		break;

	    case CLI_OFF_SX_PLUS:
		if(offdata[3] >= info->exeinfo.nsections)
		    *offset_min = CLI_OFF_NONE;
		else
		    *offset_min = info->exeinfo.section[offdata[3]].raw + offdata[1];
		break;
	    case CLI_OFF_VERSION:
		*offset_min = *offset_max = CLI_OFF_ANY;
		break;
	    default:
		cli_errmsg("cli_caloff: Not a relative offset (type: %u)\n", offdata[0]);
		return CL_EARG;
	}

	if(offset_max) {
	    if(*offset_min != CLI_OFF_NONE)
		*offset_max = *offset_min + offdata[2];
	    else
		*offset_max = CLI_OFF_NONE;
	}
    }

    return CL_SUCCESS;
}

static void targetinfo(struct cli_target_info *info, unsigned int target, fmap_t *map)
{
	int (*einfo)(fmap_t *, struct cli_exe_info *) = NULL;


    memset(info, 0, sizeof(struct cli_target_info));
    info->fsize = map->len;

    if(target == 1)
	einfo = cli_peheader;
    else if(target == 6)
	einfo = cli_elfheader;
    else if(target == 9)
	einfo = cli_machoheader;
    else return;

    if(einfo(map, &info->exeinfo))
	info->status = -1;
    else
	info->status = 1;
}

int cli_checkfp(unsigned char *digest, size_t size, cli_ctx *ctx)
{
	char md5[33];
	unsigned int i;
	const char *virname;
	const struct cli_md5m_patt *patt = NULL;


    if(ctx->engine->md5_fp && cli_md5m_scan(digest, size, &virname, ctx->engine->md5_fp) == CL_VIRUS) {
	cli_dbgmsg("cli_checkfp(): Found false positive detection (fp sig: %s)\n", virname);
	return CL_CLEAN;
    }
    for(i = 0; i < 16; i++)
	sprintf(md5 + i * 2, "%02x", digest[i]);
    md5[32] = 0;
    cli_dbgmsg("FP SIGNATURE: %s:%u:%s\n", md5, (unsigned int) size, *ctx->virname ? *ctx->virname : "Name");

#ifdef HAVE__INTERNAL__SHA_COLLECT
    if((ctx->options & CL_SCAN_INTERNAL_COLLECT_SHA) && ctx->sha_collect>0) {
        SHA1Context sha1;
        SHA256_CTX sha256;
        fmap_t *map = *ctx->fmap;
        char *ptr;
        uint8_t shash1[SHA1_HASH_SIZE*2+1];
        uint8_t shash256[SHA256_HASH_SIZE*2+1];

        if((ptr = fmap_need_off_once(map, 0, size))) {
            sha256_init(&sha256);
            sha256_update(&sha256, ptr, size);
            sha256_final(&sha256, &shash256[SHA256_HASH_SIZE]);
            for(i=0; i<SHA256_HASH_SIZE; i++)
                sprintf((char *)shash256+i*2, "%02x", shash256[SHA256_HASH_SIZE+i]);

            SHA1Init(&sha1);
            SHA1Update(&sha1, ptr, size);
            SHA1Final(&sha1, &shash1[SHA1_HASH_SIZE]);
            for(i=0; i<SHA1_HASH_SIZE; i++)
                sprintf((char *)shash1+i*2, "%02x", shash1[SHA1_HASH_SIZE+i]);

	    cli_errmsg("COLLECT:%s:%s:%u:%s:%s\n", shash256, shash1, size, *ctx->virname, ctx->entry_filename);
        } else
            cli_errmsg("can't compute sha\n!");
        ctx->sha_collect = -1;
    }
#endif

    if(ctx->virsize && !*ctx->virsize) {
	if(ctx->virsize)
	    *ctx->virsize = size;
	if(ctx->virhash)
	    strcpy(ctx->virhash, md5);
    }

    return CL_VIRUS;
}

static int matchicon(cli_ctx *ctx, struct cli_exe_info *exeinfo, const char *grp1, const char *grp2)
{
	icon_groupset iconset;

    if(!ctx ||
       !ctx->engine ||
       !ctx->engine->iconcheck ||
       !ctx->engine->iconcheck->group_counts[0] ||
       !ctx->engine->iconcheck->group_counts[1] ||
       !exeinfo->res_addr
    ) return CL_CLEAN;

    cli_icongroupset_init(&iconset);
    cli_icongroupset_add(grp1 ? grp1 : "*", &iconset, 0, ctx);
    cli_icongroupset_add(grp2 ? grp2 : "*", &iconset, 1, ctx);
    return cli_scanicon(&iconset, exeinfo->res_addr, ctx, exeinfo->section, exeinfo->nsections, exeinfo->hdr_size);
}

int32_t cli_bcapi_matchicon(struct cli_bc_ctx *ctx , const uint8_t* grp1, int32_t grp1len,
			    const uint8_t* grp2, int32_t grp2len)
{
    int ret;
    char group1[128], group2[128];
    const char *oldvirname;
    struct cli_exe_info info;

    if (ctx->bc->kind != BC_PE_UNPACKER) {
	cli_dbgmsg("bytecode: matchicon only works with PE files\n");
	return -1;
    }
    if (grp1len > sizeof(group1)-1 ||
	grp2len > sizeof(group2)-1)
	return -1;
    oldvirname = ctx->ctx->virname;
    memcpy(group1, grp1, grp1len);
    memcpy(group2, grp2, grp2len);
    group1[grp1len] = 0;
    group2[grp1len] = 0;
    memset(&info, 0, sizeof(info));
    if(le16_to_host(ctx->hooks.pedata->file_hdr.Characteristics) & 0x2000 ||
       !ctx->hooks.pedata->dirs[2].Size)
	info.res_addr = 0;
    else
	info.res_addr = le32_to_host(ctx->hooks.pedata->dirs[2].VirtualAddress);
    info.section = (struct cli_exe_section*)ctx->sections;
    info.nsections = ctx->hooks.pedata->nsections;
    info.hdr_size = ctx->hooks.pedata->hdr_size;
    ret = matchicon(ctx->ctx, &info, group1, group2);
    ctx->ctx->virname = oldvirname;
    return ret;
}


int cli_scandesc(int desc, cli_ctx *ctx, cli_file_t ftype, uint8_t ftonly, struct cli_matched_type **ftoffset, unsigned int acmode, struct cli_ac_result **acres)
{
    int ret = CL_EMEM, empty;
    fmap_t *map = *ctx->fmap;

    if((*ctx->fmap = fmap_check_empty(desc, 0, 0, &empty))) {
	ret = cli_fmap_scandesc(ctx, ftype, ftonly, ftoffset, acmode, acres, NULL);
	map->dont_cache_flag = (*ctx->fmap)->dont_cache_flag;
	funmap(*ctx->fmap);
    }
    *ctx->fmap = map;
    if(empty)
	return CL_CLEAN;
    return ret;
}

int cli_lsig_eval(cli_ctx *ctx, struct cli_matcher *root, struct cli_ac_data *acdata, struct cli_target_info *target_info)
{
	unsigned int i, evalcnt;
	uint64_t evalids;
	fmap_t *map = *ctx->fmap;

    for(i = 0; i < root->ac_lsigs; i++) {
	evalcnt = 0;
	evalids = 0;
	cli_ac_chkmacro(root, acdata, i);
	if(cli_ac_chklsig(root->ac_lsigtable[i]->logic, root->ac_lsigtable[i]->logic + strlen(root->ac_lsigtable[i]->logic), acdata->lsigcnt[i], &evalcnt, &evalids, 0) == 1) {
	    if(root->ac_lsigtable[i]->tdb.container && root->ac_lsigtable[i]->tdb.container[0] != ctx->container_type)
		continue;
	    if(root->ac_lsigtable[i]->tdb.filesize && (root->ac_lsigtable[i]->tdb.filesize[0] > map->len || root->ac_lsigtable[i]->tdb.filesize[1] < map->len))
		continue;

	    if(root->ac_lsigtable[i]->tdb.ep || root->ac_lsigtable[i]->tdb.nos) {
		if(!target_info || target_info->status != 1)
		    continue;
		if(root->ac_lsigtable[i]->tdb.ep && (root->ac_lsigtable[i]->tdb.ep[0] > target_info->exeinfo.ep || root->ac_lsigtable[i]->tdb.ep[1] < target_info->exeinfo.ep))
		    continue;
		if(root->ac_lsigtable[i]->tdb.nos && (root->ac_lsigtable[i]->tdb.nos[0] > target_info->exeinfo.nsections || root->ac_lsigtable[i]->tdb.nos[1] < target_info->exeinfo.nsections))
		    continue;
	    }

	    if(root->ac_lsigtable[i]->tdb.icongrp1 || root->ac_lsigtable[i]->tdb.icongrp2) {
		if(!target_info || target_info->status != 1)
		    continue;
		if(matchicon(ctx, &target_info->exeinfo, root->ac_lsigtable[i]->tdb.icongrp1, root->ac_lsigtable[i]->tdb.icongrp2) == CL_VIRUS) {
		    if(!root->ac_lsigtable[i]->bc_idx) {
			if(ctx->virname)
			    *ctx->virname = root->ac_lsigtable[i]->virname;
			return CL_VIRUS;
		    } else if(cli_bytecode_runlsig(ctx, &ctx->engine->bcs, root->ac_lsigtable[i]->bc_idx, ctx->virname, acdata->lsigcnt[i], acdata->lsigsuboff[i], map) == CL_VIRUS) {
			return CL_VIRUS;
		    }
		}
		continue;
	    }
	    if(!root->ac_lsigtable[i]->bc_idx) {
		if(ctx->virname)
		    *ctx->virname = root->ac_lsigtable[i]->virname;
		return CL_VIRUS;
	    }
	    if(cli_bytecode_runlsig(ctx, &ctx->engine->bcs, root->ac_lsigtable[i]->bc_idx, ctx->virname, acdata->lsigcnt[i], acdata->lsigsuboff[i], map) == CL_VIRUS) {
		return CL_VIRUS;
	    }
	}
    }
    return CL_CLEAN;
}

int cli_fmap_scandesc(cli_ctx *ctx, cli_file_t ftype, uint8_t ftonly, struct cli_matched_type **ftoffset, unsigned int acmode, struct cli_ac_result **acres, unsigned char *refhash)
{
 	unsigned char *buff;
	int ret = CL_CLEAN, type = CL_CLEAN, bytes;
	unsigned int i = 0, bm_offmode = 0;
	uint32_t maxpatlen, offset = 0;
	struct cli_ac_data gdata, tdata;
	struct cli_bm_off toff;
	cli_md5_ctx md5ctx;
	unsigned char digest[16];
	struct cli_matcher *groot = NULL, *troot = NULL;
	struct cli_target_info info;
	fmap_t *map = *ctx->fmap;

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

    targetinfo(&info, i, map);

    if(!ftonly)
	if((ret = cli_ac_initdata(&gdata, groot->ac_partsigs, groot->ac_lsigs, groot->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN)) || (ret = cli_ac_caloff(groot, &gdata, &info))) {
	    if(info.exeinfo.section)
		free(info.exeinfo.section);
	    return ret;
	}

    if(troot) {
	if((ret = cli_ac_initdata(&tdata, troot->ac_partsigs, troot->ac_lsigs, troot->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN)) || (ret = cli_ac_caloff(troot, &tdata, &info))) {
	    if(!ftonly)
		cli_ac_freedata(&gdata);
	    if(info.exeinfo.section)
		free(info.exeinfo.section);
	    return ret;
	}
	if(troot->bm_offmode) {
	    if(map->len >= CLI_DEFAULT_BM_OFFMODE_FSIZE) {
		if((ret = cli_bm_initoff(troot, &toff, &info))) {
		    if(!ftonly)
			cli_ac_freedata(&gdata);
		    cli_ac_freedata(&tdata);
		    if(info.exeinfo.section)
			free(info.exeinfo.section);
		    return ret;
		}
		bm_offmode = 1;
	    }
	}
    }

    if(!refhash && !ftonly && ctx->engine->md5_hdb)
	cli_md5_init(&md5ctx);

    while(offset < map->len) {
	bytes = MIN(map->len - offset, SCANBUFF);
	if(!(buff = fmap_need_off_once(map, offset, bytes)))
	    break;
	if(ctx->scanned)
	    *ctx->scanned += bytes / CL_COUNT_PRECISION;

	if(troot) {
	    ret = matcher_run(troot, buff, bytes, ctx->virname, &tdata, offset, &info, ftype, ftoffset, acmode, acres, map, bm_offmode ? &toff : NULL);

	    if(ret == CL_VIRUS || ret == CL_EMEM) {
		if(!ftonly)
		    cli_ac_freedata(&gdata);
		cli_ac_freedata(&tdata);
		if(bm_offmode)
		    cli_bm_freeoff(&toff);
		if(info.exeinfo.section)
		    free(info.exeinfo.section);
		return ret;
	    }
	}

	if(!ftonly) {
	    ret = matcher_run(groot, buff, bytes, ctx->virname, &gdata, offset, &info, ftype, ftoffset, acmode, acres, map, NULL);

	    if(ret == CL_VIRUS || ret == CL_EMEM) {
		cli_ac_freedata(&gdata);
		if(troot) {
		    cli_ac_freedata(&tdata);
		    if(bm_offmode)
			cli_bm_freeoff(&toff);
		}
		if(info.exeinfo.section)
		    free(info.exeinfo.section);
		return ret;
	    } else if((acmode & AC_SCAN_FT) && ret >= CL_TYPENO) {
		if(ret > type)
		    type = ret;
	    }

	    if(!refhash && ctx->engine->md5_hdb)
		cli_md5_update(&md5ctx, buff + maxpatlen * (offset!=0), bytes - maxpatlen * (offset!=0));
	}

	if(bytes < SCANBUFF) break;
	offset += bytes - maxpatlen;
    }

    if(troot) {
	ret = cli_lsig_eval(ctx, troot, &tdata, &info);
	cli_ac_freedata(&tdata);
	if(bm_offmode)
	    cli_bm_freeoff(&toff);
    }

    if(groot) {
	if(ret != CL_VIRUS)
	    ret = cli_lsig_eval(ctx, groot, &gdata, &info);
	cli_ac_freedata(&gdata);
    }

    if(info.exeinfo.section)
	free(info.exeinfo.section);

    if(ret == CL_VIRUS)
	return CL_VIRUS;

    if(!ftonly && ctx->engine->md5_hdb) {
	    const struct cli_md5m_patt *patt;
	if(!refhash) {
	    cli_md5_final(digest, &md5ctx);
	    refhash = digest;
	}
	if(cli_md5m_scan(refhash, map->len, ctx->virname, ctx->engine->md5_hdb) == CL_VIRUS && cli_md5m_scan(refhash, map->len, NULL, ctx->engine->md5_fp) != CL_VIRUS)
	    return CL_VIRUS;
    }

    return (acmode & AC_SCAN_FT) ? type : CL_CLEAN;
}

int cli_matchmeta(cli_ctx *ctx, const char *fname, size_t fsizec, size_t fsizer, int encrypted, int filepos, int res1, void *res2)
{
	const struct cli_cdb *cdb;

    if(!(cdb = ctx->engine->cdb))
	return CL_CLEAN;

    do {
	if(cdb->ctype != CL_TYPE_ANY && cdb->ctype != ctx->container_type)
	    continue;

	if(cdb->encrypted != 2 && cdb->encrypted != encrypted)
	    continue;

	if(cdb->res1 && (cdb->ctype == CL_TYPE_ZIP || cdb->ctype == CL_TYPE_RAR) && cdb->res1 != res1)
	    continue;

#define CDBRANGE(field, val)						    \
	if(field[0] != CLI_OFF_ANY) {					    \
	    if(field[0] == field[1] && field[0] != val)			    \
		continue;						    \
	    else if(field[0] != field[1] && ((field[0] && field[0] > val) ||\
	      (field[1] && field[1] < val)))				    \
		continue;						    \
	}

	CDBRANGE(cdb->csize, ctx->container_size);
	CDBRANGE(cdb->fsizec, fsizec);
	CDBRANGE(cdb->fsizer, fsizer);
	CDBRANGE(cdb->filepos, filepos);

	if(cdb->name.re_magic && (!fname || cli_regexec(&cdb->name, fname, 0, NULL, 0) == REG_NOMATCH))
	    continue;

	*ctx->virname = cdb->virname;
	return CL_VIRUS;

    } while((cdb = cdb->next));

    return CL_CLEAN;
}
