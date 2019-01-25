/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
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
#include "matcher-pcre.h"
#include "filetypes.h"
#include "matcher.h"
#include "pe.h"
#include "elf.h"
#include "execs.h"
#include "special.h"
#include "scanners.h"
#include "str.h"
#include "default.h"
#include "macho.h"
#include "fmap.h"
#include "pe_icons.h"
#include "regex/regex.h"
#include "filtering.h"
#include "perflogging.h"
#include "bytecode_priv.h"
#include "bytecode_api_impl.h"
#ifdef HAVE_YARA
#include "yara_clam.h"
#include "yara_exec.h"
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
static inline void PERF_LOG_FILTER(int32_t pos, uint32_t length, int8_t trie) {
    UNUSEDPARAM(pos);
    UNUSEDPARAM(length);
    UNUSEDPARAM(trie);
}

static inline int PERF_LOG_TRIES(int8_t acmode, int8_t bm_called, int32_t length) {
    UNUSEDPARAM(acmode);
    UNUSEDPARAM(bm_called);
    UNUSEDPARAM(length);

    return 0;
}
#endif

static inline int matcher_run(const struct cli_matcher *root,
			      const unsigned char *buffer, uint32_t length,
			      const char **virname, struct cli_ac_data *mdata,
			      uint32_t offset,
			      const struct cli_target_info *tinfo,
			      cli_file_t ftype,
			      struct cli_matched_type **ftoffset,
			      unsigned int acmode,
                              unsigned int pcremode,
			      struct cli_ac_result **acres,
			      fmap_t *map,
			      struct cli_bm_off *offdata,
			      struct cli_pcre_off *poffdata,
			      cli_ctx *ctx)
{
    int ret, saved_ret = CL_CLEAN;
    int32_t pos = 0;
    struct filter_match_info info;
    uint32_t orig_length, orig_offset;
    const unsigned char* orig_buffer;
    unsigned int viruses_found = 0;

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
	    ret = cli_bm_scanbuff(orig_buffer, orig_length, virname, NULL, root, orig_offset, tinfo, offdata, ctx);
	} else {
	    ret = cli_bm_scanbuff(buffer, length, virname, NULL, root, offset, tinfo, offdata, ctx);
	}
	if (ret != CL_CLEAN) {
	    if (ret != CL_VIRUS)
		return ret;

	    /* else (ret == CL_VIRUS) */
	    if (SCAN_ALLMATCHES)
		viruses_found = 1;
	    else {
		ret = cli_append_virus(ctx, *virname);
		if (ret != CL_CLEAN)
                    return ret;
	    }
	}
    }
    PERF_LOG_TRIES(acmode, 0, length);
    ret = cli_ac_scanbuff(buffer, length, virname, NULL, acres, root, mdata, offset, ftype, ftoffset, acmode, ctx);
    if (ret != CL_CLEAN) {
        if (ret == CL_VIRUS) {
            if (SCAN_ALLMATCHES)
                viruses_found = 1;
            else {
                ret = cli_append_virus(ctx, *virname);
                if (ret != CL_CLEAN)
                    return ret;
            }
        } else if (ret > CL_TYPENO && acmode & AC_SCAN_VIR)
            saved_ret = ret;
        else
            return ret;
    }

    if (root->bcomp_metas) {
        ret = cli_bcomp_scanbuf(orig_buffer, orig_length, virname, acres, root, mdata, ctx);
        if (ret != CL_CLEAN) {
            if (ret == CL_VIRUS) {
                if (SCAN_ALLMATCHES)
                    viruses_found = 1;
                else {
                    ret = cli_append_virus(ctx, *virname);
                    if (ret != CL_CLEAN)
                        return ret;
                }
            } else if (ret > CL_TYPENO && acmode & AC_SCAN_VIR)
                saved_ret = ret;
            else
                return ret;
        }
    }

    /* due to logical triggered, pcres cannot be evaluated until after full subsig matching */
    /* cannot save pcre execution state without possible evasion; must scan entire buffer */
    /* however, scanning the whole buffer may require the whole buffer being loaded into memory */
#if HAVE_PCRE
    if (root->pcre_metas) {
        int rc;
        uint64_t maxfilesize;

        if (map && (pcremode == PCRE_SCAN_FMAP)) {
            if (offset+length >= map->len) {
                /* check that scanned map does not exceed pcre maxfilesize limit */
                maxfilesize = (uint64_t)cl_engine_get_num(ctx->engine, CL_ENGINE_PCRE_MAX_FILESIZE, &rc);
                if (rc != CL_SUCCESS)
                    return rc;
                if (maxfilesize && (map->len > maxfilesize)) {
                    cli_dbgmsg("matcher_run: pcre max filesize (map) exceeded (limit: %llu, needed: %llu)\n",
                               (long long unsigned)maxfilesize, (long long unsigned)map->len);
                    return CL_EMAXSIZE;
                }

                cli_dbgmsg("matcher_run: performing regex matching on full map: %u+%u(%u) >= %zu\n", offset, length, offset+length, map->len);

                buffer = fmap_need_off_once(map, 0, map->len);
                if (!buffer)
                    return CL_EMEM;

                /* scan the full buffer */
                ret = cli_pcre_scanbuf(buffer, map->len, virname, acres, root, mdata, poffdata, ctx);
            }
        }
        else if (pcremode == PCRE_SCAN_BUFF) {
            /* check that scanned buffer does not exceed pcre maxfilesize limit */
            maxfilesize = (uint64_t)cl_engine_get_num(ctx->engine, CL_ENGINE_PCRE_MAX_FILESIZE, &rc);
            if (rc != CL_SUCCESS)
                return rc;
            if (maxfilesize && (length > maxfilesize)) {
                cli_dbgmsg("matcher_run: pcre max filesize (buf) exceeded (limit: %llu, needed: %u)\n", (long long unsigned)maxfilesize, length);
                return CL_EMAXSIZE;
            }

            cli_dbgmsg("matcher_run: performing regex matching on buffer with no map: %u+%u(%u)\n", offset, length, offset+length);
            /* scan the specified buffer */
            ret = cli_pcre_scanbuf(buffer, length, virname, acres, root, mdata, poffdata, ctx);
        }
    }
#endif /* HAVE_PCRE */
    /* end experimental fragment */

    if (ctx && !SCAN_ALLMATCHES && ret == CL_VIRUS) {
        return cli_append_virus(ctx, *virname);
    }
    if (ctx && SCAN_ALLMATCHES && viruses_found) {
        return CL_VIRUS;
    }
    if (saved_ret && ret == CL_CLEAN) {
        return saved_ret;
    }

    return ret;
}

int cli_scanbuff(const unsigned char *buffer, uint32_t length, uint32_t offset, cli_ctx *ctx, cli_file_t ftype, struct cli_ac_data **acdata)
{
	int ret = CL_CLEAN;
	unsigned int i = 0, j = 0, viruses_found = 0;
	struct cli_ac_data mdata;
	struct cli_matcher *groot, *troot = NULL;
	const char *virname = NULL;
	const struct cl_engine *engine=ctx->engine;

    if(!engine) {
	cli_errmsg("cli_scanbuff: engine == NULL\n");
	return CL_ENULLARG;
    }

    groot = engine->root[0]; /* generic signatures */

    if(ftype) {
        for(i = 1; i < CLI_MTARGETS; i++) {
            for (j = 0; j < cli_mtargets[i].target_count; ++j) {
                if(cli_mtargets[i].target[j] == ftype) {
                    troot = ctx->engine->root[i];
                    break;
                }
            }
            if (troot) break;
        }
    }

    if(troot) {

	if(!acdata && (ret = cli_ac_initdata(&mdata, troot->ac_partsigs, troot->ac_lsigs, troot->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN)))
	    return ret;

	ret = matcher_run(troot, buffer, length, &virname, acdata ? (acdata[0]): (&mdata), offset, NULL, ftype, NULL, AC_SCAN_VIR, PCRE_SCAN_BUFF, NULL, *ctx->fmap, NULL, NULL, ctx);

	if(!acdata)
	    cli_ac_freedata(&mdata);

	if(ret == CL_EMEM)
	    return ret;
	if(ret == CL_VIRUS) {
	    viruses_found = 1;
	    if(ctx && !SCAN_ALLMATCHES) {
		return ret;
	    }
	}
    }

    virname = NULL;

    if(!acdata && (ret = cli_ac_initdata(&mdata, groot->ac_partsigs, groot->ac_lsigs, groot->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN)))
	return ret;

    ret = matcher_run(groot, buffer, length, &virname, acdata ? (acdata[1]): (&mdata), offset, NULL, ftype, NULL, AC_SCAN_VIR, PCRE_SCAN_BUFF, NULL, *ctx->fmap, NULL, NULL, ctx);

    if(!acdata)
	cli_ac_freedata(&mdata);

    if(viruses_found)
	return CL_VIRUS;
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
	    if(offcpy[1] == 'E') {
		if(!cli_isnumber(&offcpy[2])) {
		    cli_errmsg("cli_caloff: Invalid section number\n");
		    return CL_EMALFDB;
		}
		offdata[0] = CLI_OFF_SE;
		offdata[3] = atoi(&offcpy[2]);

	    } else if(!strncmp(offstr, "SL+", 3)) {
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
	*offset_min = CLI_OFF_NONE;
	if(offset_max)
	    *offset_max = CLI_OFF_NONE;
	if(info->status == -1)
	    return CL_SUCCESS;

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

	    case CLI_OFF_SE:
		if(offdata[3] >= info->exeinfo.nsections) {
		    *offset_min = CLI_OFF_NONE;
		} else {
		    *offset_min = info->exeinfo.section[offdata[3]].raw;
            if (offset_max)
		        *offset_max = *offset_min + info->exeinfo.section[offdata[3]].rsz + offdata[2];
		}
		break;

	    case CLI_OFF_VERSION:
        if (offset_max)
		*offset_min = *offset_max = CLI_OFF_ANY;
		break;
	    default:
		cli_errmsg("cli_caloff: Not a relative offset (type: %u)\n", offdata[0]);
		return CL_EARG;
	}

	if(offset_max && *offset_max == CLI_OFF_NONE && *offset_min != CLI_OFF_NONE)
	    *offset_max = *offset_min + offdata[2];
    }

    return CL_SUCCESS;
}

void cli_targetinfo(struct cli_target_info *info, unsigned int target, fmap_t *map)
{
	int (*einfo)(fmap_t *, struct cli_exe_info *) = NULL;


    memset(info, 0, sizeof(struct cli_target_info));
    info->fsize = map->len;
    cli_hashset_init_noalloc(&info->exeinfo.vinfo);

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
    return cli_checkfp_virus(digest, size, ctx, NULL);
}

int cli_checkfp_virus(unsigned char *digest, size_t size, cli_ctx *ctx, const char * vname)
{
    char md5[33];
    unsigned int i;
    const char *virname=NULL;
    fmap_t *map;
    const char *ptr;
    uint8_t shash1[SHA1_HASH_SIZE*2+1];
    uint8_t shash256[SHA256_HASH_SIZE*2+1];
    int have_sha1, have_sha256, do_dsig_check = 1;
    stats_section_t sections;

    if(cli_hm_scan(digest, size, &virname, ctx->engine->hm_fp, CLI_HASH_MD5) == CL_VIRUS) {
        cli_dbgmsg("cli_checkfp(md5): Found false positive detection (fp sig: %s), size: %d\n", virname, (int)size);
        return CL_CLEAN;
    }
    else if(cli_hm_scan_wild(digest, &virname, ctx->engine->hm_fp, CLI_HASH_MD5) == CL_VIRUS) {
        cli_dbgmsg("cli_checkfp(md5): Found false positive detection (fp sig: %s), size: *\n", virname);
        return CL_CLEAN;
    }

    if(cli_debug_flag || ctx->engine->cb_hash) {
        for(i = 0; i < 16; i++)
            sprintf(md5 + i * 2, "%02x", digest[i]);
        md5[32] = 0;
        cli_dbgmsg("FP SIGNATURE: %s:%u:%s\n", md5, (unsigned int) size,
                   vname ? vname : "Name");
    }

    if(vname)
        do_dsig_check = strncmp("W32S.", vname, 5);

    map = *ctx->fmap;
    have_sha1 = cli_hm_have_size(ctx->engine->hm_fp, CLI_HASH_SHA1, size)
     || cli_hm_have_wild(ctx->engine->hm_fp, CLI_HASH_SHA1)
     || (cli_hm_have_size(ctx->engine->hm_fp, CLI_HASH_SHA1, 1) && do_dsig_check);
    have_sha256 = cli_hm_have_size(ctx->engine->hm_fp, CLI_HASH_SHA256, size)
     || cli_hm_have_wild(ctx->engine->hm_fp, CLI_HASH_SHA256);
    if(have_sha1 || have_sha256) {
        if((ptr = fmap_need_off_once(map, 0, size))) {
            if(have_sha1) {
                cl_sha1(ptr, size, &shash1[SHA1_HASH_SIZE], NULL);

                if(cli_hm_scan(&shash1[SHA1_HASH_SIZE], size, &virname, ctx->engine->hm_fp, CLI_HASH_SHA1) == CL_VIRUS) {
                    cli_dbgmsg("cli_checkfp(sha1): Found false positive detection (fp sig: %s)\n", virname);
                    return CL_CLEAN;
                }
                if(cli_hm_scan_wild(&shash1[SHA1_HASH_SIZE], &virname, ctx->engine->hm_fp, CLI_HASH_SHA1) == CL_VIRUS) {
                    cli_dbgmsg("cli_checkfp(sha1): Found false positive detection (fp sig: %s)\n", virname);
                    return CL_CLEAN;
                }
                if(do_dsig_check && cli_hm_scan(&shash1[SHA1_HASH_SIZE], 1, &virname, ctx->engine->hm_fp, CLI_HASH_SHA1) == CL_VIRUS) {
                    cli_dbgmsg("cli_checkfp(sha1): Found false positive detection via catalog file\n");
                    return CL_CLEAN;
                }
            }

            if(have_sha256) {
                cl_sha256(ptr, size, &shash256[SHA256_HASH_SIZE], NULL);

                if(cli_hm_scan(&shash256[SHA256_HASH_SIZE], size, &virname, ctx->engine->hm_fp, CLI_HASH_SHA256) == CL_VIRUS) {
                    cli_dbgmsg("cli_checkfp(sha256): Found false positive detection (fp sig: %s)\n", virname);
                    return CL_CLEAN;
                }
                if(cli_hm_scan_wild(&shash256[SHA256_HASH_SIZE], &virname, ctx->engine->hm_fp, CLI_HASH_SHA256) == CL_VIRUS) {
                    cli_dbgmsg("cli_checkfp(sha256): Found false positive detection (fp sig: %s)\n", virname);
                    return CL_CLEAN;
                }
            }
        }
    }

#ifdef HAVE__INTERNAL__SHA_COLLECT
    if(SCAN_DEV_COLLECT_SHA && (ctx->sha_collect > 0)) {
        if((ptr = fmap_need_off_once(map, 0, size))) {
            if(!have_sha256)
                cl_sha256(ptr, size, shash256+SHA256_HASH_SIZE, NULL);

            for(i=0; i<SHA256_HASH_SIZE; i++)
                sprintf((char *)shash256+i*2, "%02x", shash256[SHA256_HASH_SIZE+i]);

            if(!have_sha1)
                cl_sha1(ptr, size, shash1+SHA1_HASH_SIZE);

            for(i=0; i<SHA1_HASH_SIZE; i++)
                sprintf((char *)shash1+i*2, "%02x", shash1[SHA1_HASH_SIZE+i]);

            if (NULL == ctx->target_filepath) {
                cli_errmsg("COLLECT:%s:%s:%u:%s:%s\n", shash256, shash1, size, vname?vname:"noname", "NO_IDEA");
            } else {
                cli_errmsg("COLLECT:%s:%s:%u:%s:%s\n", shash256, shash1, size, vname?vname:"noname", ctx->target_filepath);
            }
        } else
            cli_errmsg("can't compute sha\n!");

        ctx->sha_collect = -1;
    }
#endif

    memset(&sections, 0x00, sizeof(stats_section_t));
    if(do_dsig_check || ctx->engine->cb_stats_add_sample) {
        uint32_t flags = (do_dsig_check ? CL_CHECKFP_PE_FLAG_AUTHENTICODE : 0);
        if (!(ctx->engine->engine_options & ENGINE_OPTIONS_DISABLE_PE_STATS) && !(ctx->engine->dconf->stats & (DCONF_STATS_DISABLED | DCONF_STATS_PE_SECTION_DISABLED)))
            flags |= CL_CHECKFP_PE_FLAG_STATS;

        switch(cli_checkfp_pe(ctx, &sections, flags)) {
        case CL_CLEAN:
            cli_dbgmsg("cli_checkfp(pe): PE file whitelisted due to valid digital signature\n");
            if (sections.sections)
                free(sections.sections);
            return CL_CLEAN;
        default:
            break;
        }
    }

    if (ctx->engine->cb_hash)
        ctx->engine->cb_hash(fmap_fd(*ctx->fmap), size, (const unsigned char *)md5, vname?vname:"noname", ctx->cb_ctx);

    if (ctx->engine->cb_stats_add_sample)
        ctx->engine->cb_stats_add_sample(vname?vname:"noname", digest, size, &sections, ctx->engine->stats_data);

    if (sections.sections)
        free(sections.sections);

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

    if (!(ctx->dconf->pe & PE_CONF_MATCHICON))
        return CL_CLEAN;

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
    const char **oldvirname;
    struct cli_exe_info info;

    if (!ctx->hooks.pedata->ep) {
	cli_dbgmsg("bytecode: matchicon only works with PE files\n");
	return -1;
    }
    if ((size_t) grp1len > sizeof(group1)-1 ||
	(size_t) grp2len > sizeof(group2)-1)
	return -1;
    oldvirname = ((cli_ctx*)ctx->ctx)->virname;
    ((cli_ctx*)ctx->ctx)->virname = NULL;
    memcpy(group1, grp1, grp1len);
    memcpy(group2, grp2, grp2len);
    group1[grp1len] = 0;
    group2[grp2len] = 0;
    memset(&info, 0, sizeof(info));
    if (ctx->bc->kind == BC_PE_UNPACKER || ctx->bc->kind == BC_PE_ALL) {
	if(le16_to_host(ctx->hooks.pedata->file_hdr.Characteristics) & 0x2000 ||
	   !ctx->hooks.pedata->dirs[2].Size)
	    info.res_addr = 0;
	else
	    info.res_addr = le32_to_host(ctx->hooks.pedata->dirs[2].VirtualAddress);
    } else
	info.res_addr = ctx->resaddr; /* from target_info */
    info.section = (struct cli_exe_section*)ctx->sections;
    info.nsections = ctx->hooks.pedata->nsections;
    info.hdr_size = ctx->hooks.pedata->hdr_size;
    cli_dbgmsg("bytecode matchicon %s %s\n", group1, group2);
    ret = matchicon(ctx->ctx, &info, group1[0] ? group1 : NULL,
		    group2[0] ? group2 : NULL);
    ((cli_ctx*)ctx->ctx)->virname = oldvirname;
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

static int intermediates_eval(cli_ctx *ctx, struct cli_ac_lsig *ac_lsig)
{
    uint32_t i, icnt = ac_lsig->tdb.intermediates[0];
    int32_t j = -1;

    if (ctx->recursion < icnt)
        return 0;

    for (i = icnt; i > 0; i--) {
        if (ac_lsig->tdb.intermediates[i] == CL_TYPE_ANY)
            continue;
        if (ac_lsig->tdb.intermediates[i] != cli_get_container_intermediate(ctx, j--))
            return 0;
    }
    return 1;
}

static int lsig_eval(cli_ctx *ctx, struct cli_matcher *root, struct cli_ac_data *acdata, struct cli_target_info *target_info, const char *hash, uint32_t lsid)
{
    unsigned evalcnt = 0;
    uint64_t evalids = 0;
    fmap_t *map = *ctx->fmap;
    struct cli_ac_lsig *ac_lsig = root->ac_lsigtable[lsid];
    char * exp = ac_lsig->u.logic;
    char* exp_end = exp + strlen(exp);
    int rc;

    rc = cli_ac_chkmacro(root, acdata, lsid);
    if (rc != CL_SUCCESS)
        return rc;
    if (cli_ac_chklsig(exp, exp_end, acdata->lsigcnt[lsid], &evalcnt, &evalids, 0) == 1) {
        if(ac_lsig->tdb.container && ac_lsig->tdb.container[0] != cli_get_container(ctx, -1))
            return CL_CLEAN;
        if(ac_lsig->tdb.intermediates && !intermediates_eval(ctx, ac_lsig))
            return CL_CLEAN;
        if(ac_lsig->tdb.filesize && (ac_lsig->tdb.filesize[0] > map->len || ac_lsig->tdb.filesize[1] < map->len))
            return CL_CLEAN;

        if(ac_lsig->tdb.ep || ac_lsig->tdb.nos) {
            if(!target_info || target_info->status != 1)
                return CL_CLEAN;
            if(ac_lsig->tdb.ep && (ac_lsig->tdb.ep[0] > target_info->exeinfo.ep || ac_lsig->tdb.ep[1] < target_info->exeinfo.ep))
                return CL_CLEAN;
            if(ac_lsig->tdb.nos && (ac_lsig->tdb.nos[0] > target_info->exeinfo.nsections || ac_lsig->tdb.nos[1] < target_info->exeinfo.nsections))
                return CL_CLEAN;
        }

        if(hash && ac_lsig->tdb.handlertype) {
            if(memcmp(ctx->handlertype_hash, hash, 16)) {
                ctx->recursion++;
                memcpy(ctx->handlertype_hash, hash, 16);
                if(cli_magic_scandesc_type(ctx, ac_lsig->tdb.handlertype[0]) == CL_VIRUS) {
                    ctx->recursion--;
                    return CL_VIRUS;
                }
                ctx->recursion--;
                return CL_CLEAN;
            }
        }
        
        if(ac_lsig->tdb.icongrp1 || ac_lsig->tdb.icongrp2) {
            if(!target_info || target_info->status != 1)
                return CL_CLEAN;
            if(matchicon(ctx, &target_info->exeinfo, ac_lsig->tdb.icongrp1, ac_lsig->tdb.icongrp2) == CL_VIRUS) {
                if(!ac_lsig->bc_idx) {
                    rc = cli_append_virus(ctx, ac_lsig->virname);
                    if (rc != CL_CLEAN)
                        return rc;
                } else if(cli_bytecode_runlsig(ctx, target_info, &ctx->engine->bcs, ac_lsig->bc_idx, acdata->lsigcnt[lsid], acdata->lsigsuboff_first[lsid], map) == CL_VIRUS) {
                    return CL_VIRUS;
                }
            }
            return CL_CLEAN;
        }
        if(!ac_lsig->bc_idx) {
            rc = cli_append_virus(ctx, ac_lsig->virname);
            if (rc != CL_CLEAN)
                return rc;
        }
        if(cli_bytecode_runlsig(ctx, target_info, &ctx->engine->bcs, ac_lsig->bc_idx, acdata->lsigcnt[lsid], acdata->lsigsuboff_first[lsid], map) == CL_VIRUS) {
            return CL_VIRUS;
        }
    }
    
    return CL_CLEAN;
}

#ifdef HAVE_YARA
static int yara_eval(cli_ctx *ctx, struct cli_matcher *root, struct cli_ac_data *acdata, struct cli_target_info *target_info, const char *hash, uint32_t lsid)
{
    struct cli_ac_lsig *ac_lsig = root->ac_lsigtable[lsid];
    int rc;
    YR_SCAN_CONTEXT context;

    (void)hash;
 
    memset(&context, 0, sizeof(YR_SCAN_CONTEXT));
    context.fmap = *ctx->fmap;
    context.file_size = (*ctx->fmap)->len;
    if (target_info != NULL) {
        if (target_info->status == 1)   
            context.entry_point = target_info->exeinfo.ep;
    }

    rc = yr_execute_code(ac_lsig, acdata, &context, 0, 0);

    if (rc == CL_VIRUS) {
        if (ac_lsig->flag & CLI_LSIG_FLAG_PRIVATE) {
            rc = CL_CLEAN;
        } else {
            rc = cli_append_virus(ctx, ac_lsig->virname);
        }
    }
    return rc;
}
#endif

int cli_exp_eval(cli_ctx *ctx, struct cli_matcher *root, struct cli_ac_data *acdata, struct cli_target_info *target_info, const char *hash)
{
    uint8_t viruses_found = 0;
    uint32_t i;
    int32_t rc = CL_SUCCESS;

    for(i = 0; i < root->ac_lsigs; i++) {
        if (root->ac_lsigtable[i]->type == CLI_LSIG_NORMAL)
            rc = lsig_eval(ctx, root, acdata, target_info, hash, i);
#ifdef HAVE_YARA
        else if (root->ac_lsigtable[i]->type == CLI_YARA_NORMAL || root->ac_lsigtable[i]->type == CLI_YARA_OFFSET)
            rc = yara_eval(ctx, root, acdata, target_info, hash, i);
#endif
        if (rc == CL_VIRUS) {
            viruses_found = 1;
            if (SCAN_ALLMATCHES)
                continue;
            break;
        }
    }
    if (viruses_found)
	return CL_VIRUS;
    return CL_CLEAN;
}

int cli_fmap_scandesc(cli_ctx *ctx, cli_file_t ftype, uint8_t ftonly, struct cli_matched_type **ftoffset, unsigned int acmode, struct cli_ac_result **acres, unsigned char *refhash)
{
    const unsigned char *buff;
    int ret = CL_CLEAN, type = CL_CLEAN, compute_hash[CLI_HASH_AVAIL_TYPES];
    unsigned int i = 0, j = 0, bm_offmode = 0;
    uint32_t maxpatlen, bytes, offset = 0;
    struct cli_ac_data gdata, tdata;
    struct cli_bm_off toff;
    struct cli_pcre_off gpoff, tpoff;
    unsigned char digest[CLI_HASH_AVAIL_TYPES][32];
    struct cli_matcher *groot = NULL, *troot = NULL;
    struct cli_target_info info;
    fmap_t *map = *ctx->fmap;
    struct cli_matcher *hdb, *fp;
    const char *virname = NULL;
    uint32_t viruses_found = 0;
    void *md5ctx, *sha1ctx, *sha256ctx;

    if(!ctx->engine) {
        cli_errmsg("cli_scandesc: engine == NULL\n");
        return CL_ENULLARG;
    }

    md5ctx = cl_hash_init("md5");
    if (!(md5ctx))
        return CL_EMEM;

    sha1ctx = cl_hash_init("sha1");
    if (!(sha1ctx)) {
        cl_hash_destroy(md5ctx);
        return CL_EMEM;
    }

    sha256ctx = cl_hash_init("sha256");
    if (!(sha256ctx)) {
        cl_hash_destroy(md5ctx);
        cl_hash_destroy(sha1ctx);
        return CL_EMEM;
    }

    if(!ftonly)
        groot = ctx->engine->root[0]; /* generic signatures */

    if(ftype) {
        for(i = 1; i < CLI_MTARGETS; i++) {
            for (j = 0; j < cli_mtargets[i].target_count; ++j) {
                if(cli_mtargets[i].target[j] == ftype) {
                    troot = ctx->engine->root[i];
                    break;
                }
            }
            if (troot) break;
        }
    }

    if(ftonly) {
        if(!troot) {
            cl_hash_destroy(md5ctx);
            cl_hash_destroy(sha1ctx);
            cl_hash_destroy(sha256ctx);
            return CL_CLEAN;
        }

        maxpatlen = troot->maxpatlen;
    } else {
        if(troot)
            maxpatlen = MAX(troot->maxpatlen, groot->maxpatlen);
        else
            maxpatlen = groot->maxpatlen;
    }

    cli_targetinfo(&info, i, map);

    if(!ftonly) {
        if((ret = cli_ac_initdata(&gdata, groot->ac_partsigs, groot->ac_lsigs, groot->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN)) || (ret = cli_ac_caloff(groot, &gdata, &info))) {
            if(info.exeinfo.section)
                free(info.exeinfo.section);

            cli_hashset_destroy(&info.exeinfo.vinfo);
            cl_hash_destroy(md5ctx);
            cl_hash_destroy(sha1ctx);
            cl_hash_destroy(sha256ctx);
            return ret;
        }
        if((ret = cli_pcre_recaloff(groot, &gpoff, &info, ctx))) {
            cli_ac_freedata(&gdata);
            if(info.exeinfo.section)
                free(info.exeinfo.section);

            cli_hashset_destroy(&info.exeinfo.vinfo);
            cl_hash_destroy(md5ctx);
            cl_hash_destroy(sha1ctx);
            cl_hash_destroy(sha256ctx);
            return ret;

        }
    }

    if(troot) {
        if((ret = cli_ac_initdata(&tdata, troot->ac_partsigs, troot->ac_lsigs, troot->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN)) || (ret = cli_ac_caloff(troot, &tdata, &info))) {
            if(!ftonly) {
                cli_ac_freedata(&gdata);
                cli_pcre_freeoff(&gpoff);
            }
            if(info.exeinfo.section)
                free(info.exeinfo.section);

            cli_hashset_destroy(&info.exeinfo.vinfo);
            cl_hash_destroy(md5ctx);
            cl_hash_destroy(sha1ctx);
            cl_hash_destroy(sha256ctx);
            return ret;
        }
        if(troot->bm_offmode) {
            if(map->len >= CLI_DEFAULT_BM_OFFMODE_FSIZE) {
                if((ret = cli_bm_initoff(troot, &toff, &info))) {
                    if(!ftonly) {
                        cli_ac_freedata(&gdata);
                        cli_pcre_freeoff(&gpoff);
                    }

                    cli_ac_freedata(&tdata);
                    if(info.exeinfo.section)
                        free(info.exeinfo.section);

                    cli_hashset_destroy(&info.exeinfo.vinfo);
                    cl_hash_destroy(md5ctx);
                    cl_hash_destroy(sha1ctx);
                    cl_hash_destroy(sha256ctx);
                    return ret;
                }

                bm_offmode = 1;
            }
        }
        if ((ret = cli_pcre_recaloff(troot, &tpoff, &info, ctx))) {
            if(!ftonly) {
                cli_ac_freedata(&gdata);
                cli_pcre_freeoff(&gpoff);
            }

            cli_ac_freedata(&tdata);
            if(bm_offmode)
                cli_bm_freeoff(&toff);
            if(info.exeinfo.section)
                free(info.exeinfo.section);

            cli_hashset_destroy(&info.exeinfo.vinfo);
            cl_hash_destroy(md5ctx);
            cl_hash_destroy(sha1ctx);
            cl_hash_destroy(sha256ctx);
            return ret;
        }
    }

    hdb = ctx->engine->hm_hdb;
    fp = ctx->engine->hm_fp;

    if(!ftonly && hdb) {
        if(!refhash) {
            if(cli_hm_have_size(hdb, CLI_HASH_MD5, map->len) || cli_hm_have_size(fp, CLI_HASH_MD5, map->len)
               || cli_hm_have_wild(hdb, CLI_HASH_MD5) || cli_hm_have_wild(fp, CLI_HASH_MD5)) {
                compute_hash[CLI_HASH_MD5] = 1;
            } else {
                compute_hash[CLI_HASH_MD5] = 0;
            }
        } else {
            compute_hash[CLI_HASH_MD5] = 0;
            memcpy(digest[CLI_HASH_MD5], refhash, 16);
        }

        if(cli_hm_have_size(hdb, CLI_HASH_SHA1, map->len) || cli_hm_have_wild(hdb, CLI_HASH_SHA1)
            || cli_hm_have_size(fp, CLI_HASH_SHA1, map->len) || cli_hm_have_wild(fp, CLI_HASH_SHA1) ) {
            compute_hash[CLI_HASH_SHA1] = 1;
        } else {
            compute_hash[CLI_HASH_SHA1] = 0;
        }

        if(cli_hm_have_size(hdb, CLI_HASH_SHA256, map->len) || cli_hm_have_wild(hdb, CLI_HASH_SHA256)
            || cli_hm_have_size(fp, CLI_HASH_SHA256, map->len) || cli_hm_have_wild(fp, CLI_HASH_SHA256)) {
            compute_hash[CLI_HASH_SHA256] = 1;
        } else {
            compute_hash[CLI_HASH_SHA256] = 0;
        }
    }

    while(offset < map->len) {
        bytes = MIN(map->len - offset, SCANBUFF);
        if(!(buff = fmap_need_off_once(map, offset, bytes)))
            break;
        if(ctx->scanned)
            *ctx->scanned += bytes / CL_COUNT_PRECISION;

        if(troot) {
                virname = NULL;
                ret = matcher_run(troot, buff, bytes, &virname, &tdata, offset, &info, ftype, ftoffset, acmode, PCRE_SCAN_FMAP, acres, map, bm_offmode ? &toff : NULL, &tpoff, ctx);

            if (virname) {
                /* virname already appended by matcher_run */
                viruses_found = 1;
            }
            if((ret == CL_VIRUS && !SCAN_ALLMATCHES) || ret == CL_EMEM) {
                if(!ftonly) {
                    cli_ac_freedata(&gdata);
                    cli_pcre_freeoff(&gpoff);
                }

                cli_ac_freedata(&tdata);
                if(bm_offmode)
                    cli_bm_freeoff(&toff);
                cli_pcre_freeoff(&tpoff);

                if(info.exeinfo.section)
                    free(info.exeinfo.section);

                cli_hashset_destroy(&info.exeinfo.vinfo);
                cl_hash_destroy(md5ctx);
                cl_hash_destroy(sha1ctx);
                cl_hash_destroy(sha256ctx);
                return ret;
            }
        }

        if(!ftonly) {
            virname = NULL;
            ret = matcher_run(groot, buff, bytes, &virname, &gdata, offset, &info, ftype, ftoffset, acmode, PCRE_SCAN_FMAP, acres, map, NULL, &gpoff, ctx);

            if (virname) {
                /* virname already appended by matcher_run */
                viruses_found = 1;
            }
            if((ret == CL_VIRUS && !SCAN_ALLMATCHES) || ret == CL_EMEM) {
                cli_ac_freedata(&gdata);
                cli_pcre_freeoff(&gpoff);
                if(troot) {
                    cli_ac_freedata(&tdata);
                    if(bm_offmode)
                        cli_bm_freeoff(&toff);
                    cli_pcre_freeoff(&tpoff);
                }

                if(info.exeinfo.section)
                    free(info.exeinfo.section);

                cli_hashset_destroy(&info.exeinfo.vinfo);
                cl_hash_destroy(md5ctx);
                cl_hash_destroy(sha1ctx);
                cl_hash_destroy(sha256ctx);
                return ret;
            } else if((acmode & AC_SCAN_FT) && ret >= CL_TYPENO) {
                if(ret > type)
                    type = ret;
            }

            /* if (bytes <= (maxpatlen * (offset!=0))), it means the last window finished the file hashing *
             *   since the last window is responsible for adding intersection between windows (maxpatlen)  */
            if(hdb && (bytes > (maxpatlen * (offset!=0)))) {
                const void *data = buff + maxpatlen * (offset!=0);
                uint32_t data_len = bytes - maxpatlen * (offset!=0);

                if(compute_hash[CLI_HASH_MD5])
                    cl_update_hash(md5ctx, (void *)data, data_len);
                if(compute_hash[CLI_HASH_SHA1])
                    cl_update_hash(sha1ctx, (void *)data, data_len);
                if(compute_hash[CLI_HASH_SHA256])
                    cl_update_hash(sha256ctx, (void *)data, data_len);
            }
        }

        if(bytes < SCANBUFF)
            break;

        offset += bytes - maxpatlen;
    }

    if(!ftonly && hdb) {
        enum CLI_HASH_TYPE hashtype, hashtype2;

        if(compute_hash[CLI_HASH_MD5]) {
            cl_finish_hash(md5ctx, digest[CLI_HASH_MD5]);
            md5ctx = NULL;
        }
        if(refhash)
            compute_hash[CLI_HASH_MD5] = 1;
        if(compute_hash[CLI_HASH_SHA1]) {
            cl_finish_hash(sha1ctx, digest[CLI_HASH_SHA1]);
            sha1ctx = NULL;
        }
        if(compute_hash[CLI_HASH_SHA256]) {
            cl_finish_hash(sha256ctx, digest[CLI_HASH_SHA256]);
            sha256ctx = NULL;
        }

        virname = NULL;
        for(hashtype = CLI_HASH_MD5; hashtype < CLI_HASH_AVAIL_TYPES; hashtype++) {
            const char * virname_w = NULL;
            int found = 0;

            /* If no hash, skip to next type */
            if(!compute_hash[hashtype])
                continue;

            /* Do hash scan */
            if((ret = cli_hm_scan(digest[hashtype], map->len, &virname, hdb, hashtype)) == CL_VIRUS) {
                found += 1;
            }
            if(!found || SCAN_ALLMATCHES) {
                if ((ret = cli_hm_scan_wild(digest[hashtype], &virname_w, hdb, hashtype)) == CL_VIRUS)
                    found += 2;
            }

            /* If found, do immediate hash-only FP check */
            if (found && fp) {
                for(hashtype2 = CLI_HASH_MD5; hashtype2 < CLI_HASH_AVAIL_TYPES; hashtype2++) {
                    if(!compute_hash[hashtype2])
                        continue;
                    if(cli_hm_scan(digest[hashtype2], map->len, NULL, fp, hashtype2) == CL_VIRUS) {
                        found = 0;
                        ret = CL_CLEAN;
                        break;
                    }
                    else if(cli_hm_scan_wild(digest[hashtype2], NULL, fp, hashtype2) == CL_VIRUS) {
                        found = 0;
                        ret = CL_CLEAN;
                        break;
                    }
                }
            }

            /* If matched size-based hash ... */
            if (found % 2) {
                viruses_found = 1;
                ret = cli_append_virus(ctx, virname);
                if (!SCAN_ALLMATCHES || ret != CL_CLEAN)
                    break;
                virname = NULL;
            }
            /* If matched size-agnostic hash ... */
            if (found > 1) {
                viruses_found = 1;
                ret = cli_append_virus(ctx, virname_w);
                if (!SCAN_ALLMATCHES || ret != CL_CLEAN)
                    break;
             }
        }
    }

    cl_hash_destroy(md5ctx);
    cl_hash_destroy(sha1ctx);
    cl_hash_destroy(sha256ctx);

    if(troot) {
        if(ret != CL_VIRUS || SCAN_ALLMATCHES)
            ret = cli_exp_eval(ctx, troot, &tdata, &info, (const char *)refhash);
        if (ret == CL_VIRUS)
            viruses_found++;

        cli_ac_freedata(&tdata);
        if(bm_offmode)
            cli_bm_freeoff(&toff);
        cli_pcre_freeoff(&tpoff);

    }

    if(groot) {
        if(ret != CL_VIRUS || SCAN_ALLMATCHES)
            ret = cli_exp_eval(ctx, groot, &gdata, &info, (const char *)refhash);
        cli_ac_freedata(&gdata);
        cli_pcre_freeoff(&gpoff);
    }

    if(info.exeinfo.section)
        free(info.exeinfo.section);

    cli_hashset_destroy(&info.exeinfo.vinfo);

    if (SCAN_ALLMATCHES && viruses_found) {
        return CL_VIRUS;
    }
    if(ret == CL_VIRUS) {
        return CL_VIRUS;
    }

    return (acmode & AC_SCAN_FT) ? type : CL_CLEAN;
}

int cli_matchmeta(cli_ctx *ctx, const char *fname, size_t fsizec, size_t fsizer, int encrypted, unsigned int filepos, int res1, void *res2)
{
	const struct cli_cdb *cdb;
	unsigned int viruses_found = 0;
        int ret = CL_CLEAN;

    cli_dbgmsg("CDBNAME:%s:%llu:%s:%llu:%llu:%d:%u:%u:%p\n",
	       cli_ftname(cli_get_container(ctx, -1)), (long long unsigned)fsizec, fname, (long long unsigned)fsizec, (long long unsigned)fsizer,
	       encrypted, filepos, res1, res2);

    if (ctx->engine && ctx->engine->cb_meta)
	if (ctx->engine->cb_meta(cli_ftname(cli_get_container(ctx, -1)), fsizec, fname, fsizer, encrypted, filepos, ctx->cb_ctx) == CL_VIRUS) {
	    cli_dbgmsg("inner file blacklisted by callback: %s\n", fname);

	    ret = cli_append_virus(ctx, "Detected.By.Callback");
	    viruses_found++;
	    if(!SCAN_ALLMATCHES || ret != CL_CLEAN)
		return ret;
	}

    if(!ctx->engine || !(cdb = ctx->engine->cdb))
	return CL_CLEAN;

    do {
	if(cdb->ctype != CL_TYPE_ANY && cdb->ctype != cli_get_container(ctx, -1))
	    continue;

	if(cdb->encrypted != 2 && cdb->encrypted != encrypted)
	    continue;

	if(cdb->res1 && (cdb->ctype == CL_TYPE_ZIP || cdb->ctype == CL_TYPE_RAR) && cdb->res1 != res1)
	    continue;

    #define CDBRANGE(field, val)                                              \
        if (field[0] != CLI_OFF_ANY)                                          \
        {                                                                     \
            if (field[0] == field[1] && field[0] != val)                      \
                continue;                                                     \
            else if (field[0] != field[1] && ((field[0] && field[0] > val) || \
                                            (field[1] && field[1] < val)))    \
                continue;                                                     \
        }

    CDBRANGE(cdb->csize, cli_get_container_size(ctx, -1));
	CDBRANGE(cdb->fsizec, fsizec);
	CDBRANGE(cdb->fsizer, fsizer);
	CDBRANGE(cdb->filepos, filepos);

	if(cdb->name.re_magic && (!fname || cli_regexec(&cdb->name, fname, 0, NULL, 0) == REG_NOMATCH))
	    continue;

	ret = cli_append_virus(ctx, cdb->virname);
	viruses_found++;
	if(!SCAN_ALLMATCHES || ret != CL_CLEAN)
	    return ret;

    } while((cdb = cdb->next));

    if (SCAN_ALLMATCHES && viruses_found)
	return CL_VIRUS;
    return CL_CLEAN;
}
