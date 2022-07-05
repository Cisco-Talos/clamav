/*
 *  Copyright (C) 2013-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdbool.h>

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

static inline void perf_log_filter(int32_t pos, int32_t length, int8_t trie)
{
    cli_perf_log_add(RAW_BYTES_SCANNED, length);
    cli_perf_log_add(FILTER_BYTES_SCANNED, length - pos);
    cli_perf_log_count2(TRIE_SCANNED, trie, length - pos);
}

static inline int perf_log_tries(int8_t acmode, int8_t bm_called, int32_t length)
{
    if (bm_called)
        cli_perf_log_add(BM_SCANNED, length);
    if (acmode)
        cli_perf_log_add(AC_SCANNED, length);
    return 0;
}

#else
static inline void perf_log_filter(int32_t pos, uint32_t length, int8_t trie)
{
    UNUSEDPARAM(pos);
    UNUSEDPARAM(length);
    UNUSEDPARAM(trie);
}

static inline int perf_log_tries(int8_t acmode, int8_t bm_called, int32_t length)
{
    UNUSEDPARAM(acmode);
    UNUSEDPARAM(bm_called);
    UNUSEDPARAM(length);

    return 0;
}
#endif

static inline cl_error_t matcher_run(const struct cli_matcher *root,
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
    cl_error_t ret, saved_ret = CL_CLEAN;
    int32_t pos = 0;
    struct filter_match_info info;
    uint32_t orig_length, orig_offset;
    const unsigned char *orig_buffer;
    unsigned int viruses_found = 0;

    if (root->filter) {
        if (filter_search_ext(root->filter, buffer, length, &info) == -1) {
            /*  for safety always scan last maxpatlen bytes */
            pos = length - root->maxpatlen - 1;
            if (pos < 0) pos = 0;
            perf_log_filter(pos, length, root->type);
        } else {
            /* must not cut buffer for 64[4-4]6161, because we must be able to check
             * 64! */
            pos = info.first_match - root->maxpatlen - 1;
            if (pos < 0) pos = 0;
            perf_log_filter(pos, length, root->type);
        }
    } else {
        perf_log_filter(0, length, root->type);
    }

    orig_length = length;
    orig_buffer = buffer;
    orig_offset = offset;
    length -= pos;
    buffer += pos;
    offset += pos;
    if (!root->ac_only) {
        perf_log_tries(0, 1, length);
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
    perf_log_tries(acmode, 0, length);
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
        ret = cli_bcomp_scanbuf(orig_buffer, orig_length, acres, root, mdata, ctx);
        if (ret != CL_CLEAN) {
            if (ret > CL_TYPENO && acmode & AC_SCAN_VIR)
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
            if (offset + length >= map->len) {
                /* check that scanned map does not exceed pcre maxfilesize limit */
                maxfilesize = (uint64_t)cl_engine_get_num(ctx->engine, CL_ENGINE_PCRE_MAX_FILESIZE, &rc);
                if (rc != CL_SUCCESS)
                    return rc;
                if (maxfilesize && (map->len > maxfilesize)) {
                    cli_dbgmsg("matcher_run: pcre max filesize (map) exceeded (limit: %llu, needed: %llu)\n",
                               (long long unsigned)maxfilesize, (long long unsigned)map->len);
                    return CL_EMAXSIZE;
                }

                cli_dbgmsg("matcher_run: performing regex matching on full map: %u+%u(%u) >= %zu\n", offset, length, offset + length, map->len);

                buffer = fmap_need_off_once(map, 0, map->len);
                if (!buffer)
                    return CL_EMEM;

                /* scan the full buffer */
                ret = cli_pcre_scanbuf(buffer, map->len, virname, acres, root, mdata, poffdata, ctx);
            }
        } else if (pcremode == PCRE_SCAN_BUFF) {
            /* check that scanned buffer does not exceed pcre maxfilesize limit */
            maxfilesize = (uint64_t)cl_engine_get_num(ctx->engine, CL_ENGINE_PCRE_MAX_FILESIZE, &rc);
            if (rc != CL_SUCCESS)
                return rc;
            if (maxfilesize && (length > maxfilesize)) {
                cli_dbgmsg("matcher_run: pcre max filesize (buf) exceeded (limit: %llu, needed: %u)\n", (long long unsigned)maxfilesize, length);
                return CL_EMAXSIZE;
            }

            cli_dbgmsg("matcher_run: performing regex matching on buffer with no map: %u+%u(%u)\n", offset, length, offset + length);
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

cl_error_t cli_scan_buff(const unsigned char *buffer, uint32_t length, uint32_t offset, cli_ctx *ctx, cli_file_t ftype, struct cli_ac_data **acdata)
{
    cl_error_t ret = CL_CLEAN;
    unsigned int i = 0, j = 0, viruses_found = 0;
    struct cli_ac_data mdata;
    struct cli_matcher *groot, *troot = NULL;
    const char *virname            = NULL;
    const struct cl_engine *engine = ctx->engine;

    if (!engine) {
        cli_errmsg("cli_scan_buff: engine == NULL\n");
        return CL_ENULLARG;
    }

    groot = engine->root[0]; /* generic signatures */

    if (ftype) {
        for (i = 1; i < CLI_MTARGETS; i++) {
            for (j = 0; j < cli_mtargets[i].target_count; ++j) {
                if (cli_mtargets[i].target[j] == ftype) {
                    troot = ctx->engine->root[i];
                    break;
                }
            }
            if (troot) break;
        }
    }

    if (troot) {

        if (!acdata && (ret = cli_ac_initdata(&mdata, troot->ac_partsigs, troot->ac_lsigs, troot->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN)))
            return ret;

        ret = matcher_run(troot, buffer, length, &virname, acdata ? (acdata[0]) : (&mdata), offset, NULL, ftype, NULL, AC_SCAN_VIR, PCRE_SCAN_BUFF, NULL, ctx->fmap, NULL, NULL, ctx);

        if (!acdata)
            cli_ac_freedata(&mdata);

        if (ret == CL_EMEM)
            return ret;
        if (ret == CL_VIRUS) {
            viruses_found = 1;
            if (ctx && !SCAN_ALLMATCHES) {
                return ret;
            }
        }
    }

    virname = NULL;

    if (!acdata && (ret = cli_ac_initdata(&mdata, groot->ac_partsigs, groot->ac_lsigs, groot->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN)))
        return ret;

    ret = matcher_run(groot, buffer, length, &virname, acdata ? (acdata[1]) : (&mdata), offset, NULL, ftype, NULL, AC_SCAN_VIR, PCRE_SCAN_BUFF, NULL, ctx->fmap, NULL, NULL, ctx);

    if (!acdata)
        cli_ac_freedata(&mdata);

    if (viruses_found)
        return CL_VIRUS;
    return ret;
}

/*
 * offdata[0]: type
 * offdata[1]: offset value
 * offdata[2]: max shift
 * offdata[3]: section number
 */
cl_error_t cli_caloff(const char *offstr, const struct cli_target_info *info, unsigned int target, uint32_t *offdata, uint32_t *offset_min, uint32_t *offset_max)
{
    char offcpy[65];
    unsigned int n, val;
    char *pt;

    if (!info) { /* decode offset string */
        if (!offstr) {
            cli_errmsg("cli_caloff: offstr == NULL\n");
            return CL_ENULLARG;
        }

        if (!strcmp(offstr, "*")) {
            offdata[0] = *offset_max = *offset_min = CLI_OFF_ANY;
            return CL_SUCCESS;
        }

        if (strlen(offstr) > 64) {
            cli_errmsg("cli_caloff: Offset string too long\n");
            return CL_EMALFDB;
        }
        strcpy(offcpy, offstr);

        if ((pt = strchr(offcpy, ','))) {
            if (!cli_isnumber(pt + 1)) {
                cli_errmsg("cli_caloff: Invalid offset shift value\n");
                return CL_EMALFDB;
            }
            offdata[2] = atoi(pt + 1);
            *pt        = 0;
        } else {
            offdata[2] = 0;
        }

        *offset_max = *offset_min = CLI_OFF_NONE;

        if (!strncmp(offcpy, "EP+", 3) || !strncmp(offcpy, "EP-", 3)) {
            if (offcpy[2] == '+')
                offdata[0] = CLI_OFF_EP_PLUS;
            else
                offdata[0] = CLI_OFF_EP_MINUS;

            if (!cli_isnumber(&offcpy[3])) {
                cli_errmsg("cli_caloff: Invalid offset value\n");
                return CL_EMALFDB;
            }
            offdata[1] = atoi(&offcpy[3]);

        } else if (offcpy[0] == 'S') {
            if (offcpy[1] == 'E') {
                if (!cli_isnumber(&offcpy[2])) {
                    cli_errmsg("cli_caloff: Invalid section number\n");
                    return CL_EMALFDB;
                }
                offdata[0] = CLI_OFF_SE;
                offdata[3] = atoi(&offcpy[2]);

            } else if (!strncmp(offstr, "SL+", 3)) {
                offdata[0] = CLI_OFF_SL_PLUS;
                if (!cli_isnumber(&offcpy[3])) {
                    cli_errmsg("cli_caloff: Invalid offset value\n");
                    return CL_EMALFDB;
                }
                offdata[1] = atoi(&offcpy[3]);

            } else if (sscanf(offcpy, "S%u+%u", &n, &val) == 2) {
                offdata[0] = CLI_OFF_SX_PLUS;
                offdata[1] = val;
                offdata[3] = n;
            } else {
                cli_errmsg("cli_caloff: Invalid offset string\n");
                return CL_EMALFDB;
            }

        } else if (!strncmp(offcpy, "EOF-", 4)) {
            offdata[0] = CLI_OFF_EOF_MINUS;
            if (!cli_isnumber(&offcpy[4])) {
                cli_errmsg("cli_caloff: Invalid offset value\n");
                return CL_EMALFDB;
            }
            offdata[1] = atoi(&offcpy[4]);
        } else if (!strncmp(offcpy, "VI", 2)) {
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
            if (!cli_isnumber(offcpy)) {
                cli_errmsg("cli_caloff: Invalid offset value\n");
                return CL_EMALFDB;
            }
            *offset_min = offdata[1] = atoi(offcpy);
            *offset_max              = *offset_min + offdata[2];
        }

        if (offdata[0] != CLI_OFF_ANY && offdata[0] != CLI_OFF_ABSOLUTE &&
            offdata[0] != CLI_OFF_EOF_MINUS && offdata[0] != CLI_OFF_MACRO) {
            if (target != 1 && target != 6 && target != 9) {
                cli_errmsg("cli_caloff: Invalid offset type for target %u\n", target);
                return CL_EMALFDB;
            }
        }

    } else {
        /* calculate relative offsets */
        *offset_min = CLI_OFF_NONE;
        if (offset_max)
            *offset_max = CLI_OFF_NONE;
        if (info->status == -1) {
            // If the executable headers weren't parsed successfully then we
            // can't process any ndb/ldb EOF-n/EP+n/EP-n/Sx+n/SEx/SL+n subsigs
            return CL_SUCCESS;
        }

        switch (offdata[0]) {
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
                *offset_min = info->exeinfo.sections[info->exeinfo.nsections - 1].raw + offdata[1];
                break;

            case CLI_OFF_SX_PLUS:
                if (offdata[3] >= info->exeinfo.nsections)
                    *offset_min = CLI_OFF_NONE;
                else
                    *offset_min = info->exeinfo.sections[offdata[3]].raw + offdata[1];
                break;

            case CLI_OFF_SE:
                if (offdata[3] >= info->exeinfo.nsections) {
                    *offset_min = CLI_OFF_NONE;
                } else {
                    *offset_min = info->exeinfo.sections[offdata[3]].raw;
                    if (offset_max)
                        *offset_max = *offset_min + info->exeinfo.sections[offdata[3]].rsz + offdata[2];
                    // TODO offdata[2] == MaxShift. Won't this make offset_max
                    // extend beyond the end of the section?  This doesn't seem like
                    // what we want...
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

        if (offset_max && *offset_max == CLI_OFF_NONE && *offset_min != CLI_OFF_NONE)
            *offset_max = *offset_min + offdata[2];
    }

    return CL_SUCCESS;
}

void cli_targetinfo_init(struct cli_target_info *info)
{

    if (NULL == info) {
        return;
    }
    info->status = 0;
    cli_exe_info_init(&(info->exeinfo), 0);
}

void cli_targetinfo(struct cli_target_info *info, unsigned int target, cli_ctx *ctx)
{
    int (*einfo)(cli_ctx *, struct cli_exe_info *) = NULL;

    info->fsize = ctx->fmap->len;

    if (target == 1)
        einfo = cli_pe_targetinfo;
    else if (target == 6)
        einfo = cli_elfheader;
    else if (target == 9)
        einfo = cli_machoheader;
    else
        return;

    if (einfo(ctx, &info->exeinfo))
        info->status = -1;
    else
        info->status = 1;
}

void cli_targetinfo_destroy(struct cli_target_info *info)
{

    if (NULL == info) {
        return;
    }

    cli_exe_info_destroy(&(info->exeinfo));
    info->status = 0;
}

cl_error_t cli_check_fp(cli_ctx *ctx, const char *vname)
{
    cl_error_t status = CL_VIRUS;
    char md5[33];
    unsigned int i;
    const char *virname = NULL;
    fmap_t *map;
    int32_t stack_index;
    const char *ptr;
    uint8_t shash1[SHA1_HASH_SIZE * 2 + 1];
    uint8_t shash256[SHA256_HASH_SIZE * 2 + 1];
    int have_sha1, have_sha256;
    unsigned char *digest;
    size_t size;

    stack_index = (int32_t)ctx->recursion_level;

    while (stack_index >= 0) {
        map = ctx->recursion_stack[stack_index].fmap;

        if (CL_SUCCESS != fmap_get_MD5(map, &digest)) {
            cli_dbgmsg("cli_check_fp: Failed to get a hash for the map at stack index # %u\n", stack_index);
            stack_index--;
            continue;
        }
        size = map->len;

        /*
         * First, check the MD5 digest.
         * MD5 is default, so it always exists.
         */
        if (cli_hm_scan(digest, size, &virname, ctx->engine->hm_fp, CLI_HASH_MD5) == CL_VIRUS) {
            cli_dbgmsg("cli_check_fp(md5): Found false positive detection (fp sig: %s), size: %d\n", virname, (int)size);
            return CL_CLEAN;
        } else if (cli_hm_scan_wild(digest, &virname, ctx->engine->hm_fp, CLI_HASH_MD5) == CL_VIRUS) {
            cli_dbgmsg("cli_check_fp(md5): Found false positive detection (fp sig: %s), size: *\n", virname);
            return CL_CLEAN;
        }

        if (cli_debug_flag || ctx->engine->cb_hash) {
            const char *name = ctx->recursion_stack[stack_index].fmap->name;
            const char *type = cli_ftname(ctx->recursion_stack[stack_index].type);

            for (i = 0; i < 16; i++)
                sprintf(md5 + i * 2, "%02x", digest[i]);
            md5[32] = 0;

            cli_dbgmsg("FP SIGNATURE: %s:%u:%s  # Name: %s, Type: %s\n",
                       md5, (unsigned int)size, vname ? vname : "Name", name ? name : "n/a", type);
        }

        have_sha1   = cli_hm_have_size(ctx->engine->hm_fp, CLI_HASH_SHA1, size) || cli_hm_have_wild(ctx->engine->hm_fp, CLI_HASH_SHA1) || cli_hm_have_size(ctx->engine->hm_fp, CLI_HASH_SHA1, 1);
        have_sha256 = cli_hm_have_size(ctx->engine->hm_fp, CLI_HASH_SHA256, size) || cli_hm_have_wild(ctx->engine->hm_fp, CLI_HASH_SHA256);
        if (have_sha1 || have_sha256) {
            if ((ptr = fmap_need_off_once(map, 0, size))) {
                if (have_sha1) {
                    cl_sha1(ptr, size, &shash1[SHA1_HASH_SIZE], NULL);

                    if (cli_hm_scan(&shash1[SHA1_HASH_SIZE], size, &virname, ctx->engine->hm_fp, CLI_HASH_SHA1) == CL_VIRUS) {
                        cli_dbgmsg("cli_check_fp(sha1): Found false positive detection (fp sig: %s)\n", virname);
                        return CL_CLEAN;
                    }
                    if (cli_hm_scan_wild(&shash1[SHA1_HASH_SIZE], &virname, ctx->engine->hm_fp, CLI_HASH_SHA1) == CL_VIRUS) {
                        cli_dbgmsg("cli_check_fp(sha1): Found false positive detection (fp sig: %s)\n", virname);
                        return CL_CLEAN;
                    }
                    /* See whether the hash matches those loaded in from .cat files
                     * (associated with the .CAB file type) */
                    if (cli_hm_scan(&shash1[SHA1_HASH_SIZE], 1, &virname, ctx->engine->hm_fp, CLI_HASH_SHA1) == CL_VIRUS) {
                        cli_dbgmsg("cli_check_fp(sha1): Found .CAB false positive detection via catalog file\n");
                        return CL_CLEAN;
                    }
                }

                if (have_sha256) {
                    cl_sha256(ptr, size, &shash256[SHA256_HASH_SIZE], NULL);

                    if (cli_hm_scan(&shash256[SHA256_HASH_SIZE], size, &virname, ctx->engine->hm_fp, CLI_HASH_SHA256) == CL_VIRUS) {
                        cli_dbgmsg("cli_check_fp(sha256): Found false positive detection (fp sig: %s)\n", virname);
                        return CL_CLEAN;
                    }
                    if (cli_hm_scan_wild(&shash256[SHA256_HASH_SIZE], &virname, ctx->engine->hm_fp, CLI_HASH_SHA256) == CL_VIRUS) {
                        cli_dbgmsg("cli_check_fp(sha256): Found false positive detection (fp sig: %s)\n", virname);
                        return CL_CLEAN;
                    }
                    /* See whether the hash matches those loaded in from .cat files
                     * (associated with the .CAB file type) */
                    if (cli_hm_scan(&shash256[SHA256_HASH_SIZE], 1, &virname, ctx->engine->hm_fp, CLI_HASH_SHA256) == CL_VIRUS) {
                        cli_dbgmsg("cli_check_fp(sha256): Found .CAB false positive detection via catalog file\n");
                        return CL_CLEAN;
                    }
                }
            }
        }

#ifdef HAVE__INTERNAL__SHA_COLLECT
        if (SCAN_DEV_COLLECT_SHA && (ctx->sha_collect > 0)) {
            if ((ptr = fmap_need_off_once(map, 0, size))) {
                if (!have_sha256)
                    cl_sha256(ptr, size, shash256 + SHA256_HASH_SIZE, NULL);

                for (i = 0; i < SHA256_HASH_SIZE; i++)
                    sprintf((char *)shash256 + i * 2, "%02x", shash256[SHA256_HASH_SIZE + i]);

                if (!have_sha1)
                    cl_sha1(ptr, size, shash1 + SHA1_HASH_SIZE);

                for (i = 0; i < SHA1_HASH_SIZE; i++)
                    sprintf((char *)shash1 + i * 2, "%02x", shash1[SHA1_HASH_SIZE + i]);

                if (NULL == ctx->target_filepath) {
                    cli_errmsg("COLLECT:%s:%s:%u:%s:%s\n", shash256, shash1, size, vname ? vname : "noname", "NO_IDEA");
                } else {
                    cli_errmsg("COLLECT:%s:%s:%u:%s:%s\n", shash256, shash1, size, vname ? vname : "noname", ctx->target_filepath);
                }
            } else
                cli_errmsg("can't compute sha\n!");

            ctx->sha_collect = -1;
        }
#endif

        if (ctx->engine->cb_hash)
            ctx->engine->cb_hash(fmap_fd(ctx->fmap), size, (const unsigned char *)md5, vname ? vname : "noname", ctx->cb_ctx);

        if (ctx->engine->cb_stats_add_sample) {
            stats_section_t sections;
            memset(&sections, 0x00, sizeof(stats_section_t));

            if (!(ctx->engine->engine_options & ENGINE_OPTIONS_DISABLE_PE_STATS) &&
                !(ctx->engine->dconf->stats & (DCONF_STATS_DISABLED | DCONF_STATS_PE_SECTION_DISABLED)))
                cli_genhash_pe(ctx, CL_GENHASH_PE_CLASS_SECTION, 1, &sections);

            // TODO We probably only want to call cb_stats_add_sample when
            // sections.section != NULL... leaving as is for now
            ctx->engine->cb_stats_add_sample(vname ? vname : "noname", digest, size, &sections, ctx->engine->stats_data);

            if (sections.sections) {
                free(sections.sections);
            }
        }

        stack_index -= 1;
    }

    return status;
}

static cl_error_t matchicon(cli_ctx *ctx, struct cli_exe_info *exeinfo, const char *grp1, const char *grp2)
{
    icon_groupset iconset;

    if (!ctx ||
        !ctx->engine ||
        !ctx->engine->iconcheck ||
        !ctx->engine->iconcheck->group_counts[0] ||
        !ctx->engine->iconcheck->group_counts[1] ||
        !exeinfo->res_addr) return CL_CLEAN;

    if (!(ctx->dconf->pe & PE_CONF_MATCHICON))
        return CL_CLEAN;

    cli_icongroupset_init(&iconset);
    cli_icongroupset_add(grp1 ? grp1 : "*", &iconset, 0, ctx);
    cli_icongroupset_add(grp2 ? grp2 : "*", &iconset, 1, ctx);
    return cli_scanicon(&iconset, ctx, exeinfo);
}

int32_t cli_bcapi_matchicon(struct cli_bc_ctx *ctx, const uint8_t *grp1, int32_t grp1len,
                            const uint8_t *grp2, int32_t grp2len)
{
    cl_error_t ret;
    char group1[128], group2[128];
    const char **oldvirname;
    struct cli_exe_info info;

    // TODO This isn't a good check, since EP will be zero for DLLs and
    // (assuming pedata->ep is populated from exeinfo->pe) non-zero for
    // some MachO and ELF executables
    if (!ctx->hooks.pedata->ep) {
        cli_dbgmsg("bytecode: matchicon only works with PE files\n");
        return -1;
    }
    if ((size_t)grp1len > sizeof(group1) - 1 ||
        (size_t)grp2len > sizeof(group2) - 1)
        return -1;
    oldvirname                     = ((cli_ctx *)ctx->ctx)->virname;
    ((cli_ctx *)ctx->ctx)->virname = NULL;
    memcpy(group1, grp1, grp1len);
    memcpy(group2, grp2, grp2len);
    group1[grp1len] = 0;
    group2[grp2len] = 0;
    memset(&info, 0, sizeof(info));
    if (ctx->bc->kind == BC_PE_UNPACKER || ctx->bc->kind == BC_PE_ALL) {
        if (le16_to_host(ctx->hooks.pedata->file_hdr.Characteristics) & 0x2000 ||
            !ctx->hooks.pedata->dirs[2].Size)
            info.res_addr = 0;
        else
            info.res_addr = le32_to_host(ctx->hooks.pedata->dirs[2].VirtualAddress);
    } else
        info.res_addr = ctx->resaddr; /* from target_info */
    info.sections  = (struct cli_exe_section *)ctx->sections;
    info.nsections = ctx->hooks.pedata->nsections;
    info.hdr_size  = ctx->hooks.pedata->hdr_size;
    cli_dbgmsg("bytecode matchicon %s %s\n", group1, group2);
    ret                            = matchicon(ctx->ctx, &info, group1[0] ? group1 : NULL,
                    group2[0] ? group2 : NULL);
    ((cli_ctx *)ctx->ctx)->virname = oldvirname;
    return (int32_t)ret;
}

cl_error_t cli_scan_desc(int desc, cli_ctx *ctx, cli_file_t ftype, uint8_t ftonly, struct cli_matched_type **ftoffset, unsigned int acmode, struct cli_ac_result **acres, const char *name)
{
    cl_error_t status = CL_CLEAN;
    int empty;
    fmap_t *new_map = NULL;
    fmap_t *map     = ctx->fmap; /* Store off the parent fmap for easy reference */

    new_map = fmap_check_empty(desc, 0, 0, &empty, name);
    if (NULL == new_map) {
        if (!empty) {
            cli_dbgmsg("cli_scan_desc: Failed to allocate new map for file descriptor scan.\n");
            status = CL_EMEM;
        }
        goto done;
    }

    status = cli_recursion_stack_push(ctx, new_map, ftype, true); /* Perform scan with child fmap */
    if (CL_SUCCESS != status) {
        cli_dbgmsg("cli_scan_desc: Failed to scan fmap.\n");
        goto done;
    }

    status = cli_scan_fmap(ctx, ftype, ftonly, ftoffset, acmode, acres, NULL);

    map->dont_cache_flag = ctx->fmap->dont_cache_flag; /* Set the parent layer's "don't cache" flag to match the child.
                                                          TODO: This may not be needed since `emax_reached()` should've
                                                          already done that for us. */

    (void)cli_recursion_stack_pop(ctx); /* Restore the parent fmap */

done:
    if (NULL != new_map) {
        funmap(new_map);
    }

    return status;
}

static int intermediates_eval(cli_ctx *ctx, struct cli_ac_lsig *ac_lsig)
{
    uint32_t i, icnt = ac_lsig->tdb.intermediates[0];

    // -1 is the deepest layer (the current layer), so we start at -2, which is the first ancestor
    int32_t j = -2;

    if (ctx->recursion_level < icnt)
        return 0;

    for (i = icnt; i > 0; i--) {
        if (ac_lsig->tdb.intermediates[i] == CL_TYPE_ANY)
            continue;
        if (ac_lsig->tdb.intermediates[i] != cli_recursion_stack_get_type(ctx, j--))
            return 0;
    }
    return 1;
}

static cl_error_t lsig_eval(cli_ctx *ctx, struct cli_matcher *root, struct cli_ac_data *acdata, struct cli_target_info *target_info, const char *hash, uint32_t lsid)
{
    cl_error_t status           = CL_CLEAN;
    unsigned evalcnt            = 0;
    uint64_t evalids            = 0;
    fmap_t *new_map             = NULL;
    struct cli_ac_lsig *ac_lsig = root->ac_lsigtable[lsid];
    char *exp                   = ac_lsig->u.logic;
    char *exp_end               = exp + strlen(exp);

    status = cli_ac_chkmacro(root, acdata, lsid);
    if (status != CL_SUCCESS)
        return status;

    if (cli_ac_chklsig(exp, exp_end, acdata->lsigcnt[lsid], &evalcnt, &evalids, 0) == 1) {
        if (ac_lsig->tdb.container && ac_lsig->tdb.container[0] != cli_recursion_stack_get_type(ctx, -2))
            goto done;
        if (ac_lsig->tdb.intermediates && !intermediates_eval(ctx, ac_lsig))
            goto done;
        if (ac_lsig->tdb.filesize && (ac_lsig->tdb.filesize[0] > ctx->fmap->len || ac_lsig->tdb.filesize[1] < ctx->fmap->len))
            goto done;

        if (ac_lsig->tdb.ep || ac_lsig->tdb.nos) {
            if (!target_info || target_info->status != 1)
                goto done;
            if (ac_lsig->tdb.ep && (ac_lsig->tdb.ep[0] > target_info->exeinfo.ep || ac_lsig->tdb.ep[1] < target_info->exeinfo.ep))
                goto done;
            if (ac_lsig->tdb.nos && (ac_lsig->tdb.nos[0] > target_info->exeinfo.nsections || ac_lsig->tdb.nos[1] < target_info->exeinfo.nsections))
                goto done;
        }

        if (hash && ac_lsig->tdb.handlertype) {
            if (0 != memcmp(ctx->handlertype_hash, hash, 16)) {
                /*
                 * Create an fmap window into our current fmap using the original offset & length, and rescan as the new type
                 *
                 * TODO: Unsure if creating an fmap is the right move, or if we should rescan with the current fmap as-is,
                 * since it's not really a container so much as it is type reassignment. This new fmap layer protect agains
                 * a possible infinite loop by applying the scan recursion limit, but maybe there's a better way?
                 * Testing with both HandlerType type reassignment sigs + Container/Intermediates sigs should indicate if
                 * a change is needed.
                 */
                new_map = fmap_duplicate(ctx->fmap, 0, ctx->fmap->len, ctx->fmap->name);
                if (NULL == new_map) {
                    status = CL_EMEM;
                    cli_dbgmsg("Failed to duplicate the current fmap for a re-scan as a different type.\n");
                    goto done;
                }

                memcpy(ctx->handlertype_hash, hash, 16);

                status = cli_recursion_stack_push(ctx, new_map, ac_lsig->tdb.handlertype[0], true); /* Perform scan with child fmap */
                if (CL_SUCCESS != status) {
                    cli_dbgmsg("Failed to re-scan fmap as a new type.\n");
                    goto done;
                }

                status = cli_magic_scan(ctx, ac_lsig->tdb.handlertype[0]);

                (void)cli_recursion_stack_pop(ctx); /* Restore the parent fmap */

                if (CL_VIRUS == status) {
                    status = CL_VIRUS;
                    goto done;
                }

                goto done;
            }
        }

        if (ac_lsig->tdb.icongrp1 || ac_lsig->tdb.icongrp2) {
            if (!target_info || target_info->status != 1) {
                goto done;
            }

            if (CL_VIRUS == matchicon(ctx, &target_info->exeinfo, ac_lsig->tdb.icongrp1, ac_lsig->tdb.icongrp2)) {
                if (!ac_lsig->bc_idx) {
                    status = cli_append_virus(ctx, ac_lsig->virname);
                    if (status != CL_CLEAN) {
                        goto done;
                    }
                } else if (CL_VIRUS == cli_bytecode_runlsig(ctx, target_info, &ctx->engine->bcs, ac_lsig->bc_idx, acdata->lsigcnt[lsid], acdata->lsigsuboff_first[lsid], ctx->fmap)) {
                    status = CL_VIRUS;
                    goto done;
                }
            }
            goto done;
        }
        if (!ac_lsig->bc_idx) {
            status = cli_append_virus(ctx, ac_lsig->virname);
            if (status != CL_CLEAN) {
                goto done;
            }
        }
        if (CL_VIRUS == cli_bytecode_runlsig(ctx, target_info, &ctx->engine->bcs, ac_lsig->bc_idx, acdata->lsigcnt[lsid], acdata->lsigsuboff_first[lsid], ctx->fmap)) {
            status = CL_VIRUS;
            goto done;
        }
    }

done:
    if (NULL != new_map) {
        free_duplicate_fmap(new_map);
    }

    return status;
}

#ifdef HAVE_YARA
static cl_error_t yara_eval(cli_ctx *ctx, struct cli_matcher *root, struct cli_ac_data *acdata, struct cli_target_info *target_info, const char *hash, uint32_t lsid)
{
    struct cli_ac_lsig *ac_lsig = root->ac_lsigtable[lsid];
    cl_error_t rc;
    YR_SCAN_CONTEXT context;

    (void)hash;

    memset(&context, 0, sizeof(YR_SCAN_CONTEXT));
    context.fmap      = ctx->fmap;
    context.file_size = ctx->fmap->len;
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

cl_error_t cli_exp_eval(cli_ctx *ctx, struct cli_matcher *root, struct cli_ac_data *acdata, struct cli_target_info *target_info, const char *hash)
{
    uint8_t viruses_found = 0;
    uint32_t i;
    cl_error_t rc = CL_SUCCESS;

    for (i = 0; i < root->ac_lsigs; i++) {
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

cl_error_t cli_scan_fmap(cli_ctx *ctx, cli_file_t ftype, uint8_t ftonly, struct cli_matched_type **ftoffset, unsigned int acmode, struct cli_ac_result **acres, unsigned char *refhash)
{
    const unsigned char *buff;
    cl_error_t ret = CL_CLEAN, type = CL_CLEAN;
    int compute_hash[CLI_HASH_AVAIL_TYPES];
    unsigned int i = 0, j = 0, bm_offmode = 0;
    uint32_t maxpatlen, bytes, offset     = 0;
    struct cli_ac_data gdata, tdata;
    struct cli_bm_off toff;
    struct cli_pcre_off gpoff, tpoff;
    unsigned char digest[CLI_HASH_AVAIL_TYPES][32];
    struct cli_matcher *groot = NULL, *troot = NULL;
    struct cli_target_info info;
    struct cli_matcher *hdb, *fp;
    const char *virname;
    uint32_t viruses_found = 0;
    void *md5ctx, *sha1ctx, *sha256ctx;

    if (!ctx->engine) {
        cli_errmsg("cli_scan_fmap: engine == NULL\n");
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

    if (!ftonly)
        groot = ctx->engine->root[0]; /* generic signatures */

    if (ftype) {
        for (i = 1; i < CLI_MTARGETS; i++) {
            for (j = 0; j < cli_mtargets[i].target_count; ++j) {
                if (cli_mtargets[i].target[j] == ftype) {
                    troot = ctx->engine->root[i];
                    break;
                }
            }
            if (troot) break;
        }
    }

    if (ftonly) {
        if (!troot) {
            cl_hash_destroy(md5ctx);
            cl_hash_destroy(sha1ctx);
            cl_hash_destroy(sha256ctx);
            return CL_CLEAN;
        }

        maxpatlen = troot->maxpatlen;
    } else {
        if (troot)
            maxpatlen = MAX(troot->maxpatlen, groot->maxpatlen);
        else
            maxpatlen = groot->maxpatlen;
    }

    cli_targetinfo_init(&info);
    cli_targetinfo(&info, i, ctx);

    if (-1 == info.status) {
        cli_dbgmsg("cli_scan_fmap: Failed to successfully parse the executable header. "
                   "Scan features will be disabled, such as "
                   "NDB/LDB subsigs using EOF-n/EP+n/EP-n/Sx+n/SEx/SL+n, "
                   "fuzzy icon matching, "
                   "MDB/IMP sigs, "
                   "and bytecode sigs that require exe metadata\n");
    }

    /* If it's a PE, check the Authenticode header.  This would be more
     * appropriate in cli_scanpe, but scanraw->cli_scan_fmap gets
     * called first for PEs, and we want to determine the whitelist/blacklist
     * status early on so we can skip things like embedded PE extraction
     * (which is broken for signed binaries within signed binaries).
     *
     * If we want to add support for more signature parsing in the future
     * (Ex: MachO sigs), do that here too.
     *
     * One benefit of not continuing on to scan files with trusted signatures
     * is that the bytes associated with the exe won't get counted against the
     * scansize limits, which means we have an increased chance of catching
     * malware in container types (NSIS, iShield, etc.) where the file size is
     * large.  A common case where this occurs is installers that embed one
     * or more of the various Microsoft Redistributable Setup packages.  These
     * can easily be 5 MB or more in size, and might appear before malware
     * does in a given sample.
     */

    if (1 == info.status && i == 1) {
        ret = cli_check_auth_header(ctx, &(info.exeinfo));

        if ((ret == CL_VIRUS || ret == CL_VERIFIED) && !SCAN_ALLMATCHES) {
            cli_targetinfo_destroy(&info);
            cl_hash_destroy(md5ctx);
            cl_hash_destroy(sha1ctx);
            cl_hash_destroy(sha256ctx);
            return ret;
        }

        ret = CL_CLEAN;
    }

    if (!ftonly) {
        if ((ret = cli_ac_initdata(&gdata, groot->ac_partsigs, groot->ac_lsigs, groot->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN)) ||
            (ret = cli_ac_caloff(groot, &gdata, &info))) {
            cli_targetinfo_destroy(&info);
            cl_hash_destroy(md5ctx);
            cl_hash_destroy(sha1ctx);
            cl_hash_destroy(sha256ctx);
            return ret;
        }
        if ((ret = cli_pcre_recaloff(groot, &gpoff, &info, ctx))) {
            cli_ac_freedata(&gdata);
            cli_targetinfo_destroy(&info);
            cl_hash_destroy(md5ctx);
            cl_hash_destroy(sha1ctx);
            cl_hash_destroy(sha256ctx);
            return ret;
        }
    }

    if (troot) {
        if ((ret = cli_ac_initdata(&tdata, troot->ac_partsigs, troot->ac_lsigs, troot->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN)) ||
            (ret = cli_ac_caloff(troot, &tdata, &info))) {
            if (!ftonly) {
                cli_ac_freedata(&gdata);
                cli_pcre_freeoff(&gpoff);
            }
            cli_targetinfo_destroy(&info);
            cl_hash_destroy(md5ctx);
            cl_hash_destroy(sha1ctx);
            cl_hash_destroy(sha256ctx);
            return ret;
        }
        if (troot->bm_offmode) {
            if (ctx->fmap->len >= CLI_DEFAULT_BM_OFFMODE_FSIZE) {
                if ((ret = cli_bm_initoff(troot, &toff, &info))) {
                    if (!ftonly) {
                        cli_ac_freedata(&gdata);
                        cli_pcre_freeoff(&gpoff);
                    }

                    cli_ac_freedata(&tdata);
                    cli_targetinfo_destroy(&info);
                    cl_hash_destroy(md5ctx);
                    cl_hash_destroy(sha1ctx);
                    cl_hash_destroy(sha256ctx);
                    return ret;
                }

                bm_offmode = 1;
            }
        }
        if ((ret = cli_pcre_recaloff(troot, &tpoff, &info, ctx))) {
            if (!ftonly) {
                cli_ac_freedata(&gdata);
                cli_pcre_freeoff(&gpoff);
            }

            cli_ac_freedata(&tdata);
            if (bm_offmode)
                cli_bm_freeoff(&toff);
            cli_targetinfo_destroy(&info);
            cl_hash_destroy(md5ctx);
            cl_hash_destroy(sha1ctx);
            cl_hash_destroy(sha256ctx);
            return ret;
        }
    }

    hdb = ctx->engine->hm_hdb;
    fp  = ctx->engine->hm_fp;

    if (!ftonly && hdb) {
        if (!refhash) {
            if (cli_hm_have_size(hdb, CLI_HASH_MD5, ctx->fmap->len) ||
                cli_hm_have_size(fp, CLI_HASH_MD5, ctx->fmap->len) ||
                cli_hm_have_wild(hdb, CLI_HASH_MD5) ||
                cli_hm_have_wild(fp, CLI_HASH_MD5)) {
                compute_hash[CLI_HASH_MD5] = 1;
            } else {
                compute_hash[CLI_HASH_MD5] = 0;
            }
        } else {
            compute_hash[CLI_HASH_MD5] = 0;
            memcpy(digest[CLI_HASH_MD5], refhash, 16);
        }

        if (cli_hm_have_size(hdb, CLI_HASH_SHA1, ctx->fmap->len) ||
            cli_hm_have_wild(hdb, CLI_HASH_SHA1) ||
            cli_hm_have_size(fp, CLI_HASH_SHA1, ctx->fmap->len) ||
            cli_hm_have_wild(fp, CLI_HASH_SHA1)) {
            compute_hash[CLI_HASH_SHA1] = 1;
        } else {
            compute_hash[CLI_HASH_SHA1] = 0;
        }

        if (cli_hm_have_size(hdb, CLI_HASH_SHA256, ctx->fmap->len) ||
            cli_hm_have_wild(hdb, CLI_HASH_SHA256) ||
            cli_hm_have_size(fp, CLI_HASH_SHA256, ctx->fmap->len) ||
            cli_hm_have_wild(fp, CLI_HASH_SHA256)) {
            compute_hash[CLI_HASH_SHA256] = 1;
        } else {
            compute_hash[CLI_HASH_SHA256] = 0;
        }
    }

    while (offset < ctx->fmap->len) {
        bytes = MIN(ctx->fmap->len - offset, SCANBUFF);
        if (!(buff = fmap_need_off_once(ctx->fmap, offset, bytes)))
            break;
        if (ctx->scanned)
            *ctx->scanned += bytes / CL_COUNT_PRECISION;

        if (troot) {
            virname = NULL;
            ret     = matcher_run(troot, buff, bytes, &virname, &tdata, offset, &info, ftype, ftoffset, acmode, PCRE_SCAN_FMAP, acres, ctx->fmap, bm_offmode ? &toff : NULL, &tpoff, ctx);

            if (virname) {
                /* virname already appended by matcher_run */
                viruses_found = 1;
            }
            if ((ret == CL_VIRUS && !SCAN_ALLMATCHES) || ret == CL_EMEM) {
                if (!ftonly) {
                    cli_ac_freedata(&gdata);
                    cli_pcre_freeoff(&gpoff);
                }

                cli_ac_freedata(&tdata);
                if (bm_offmode)
                    cli_bm_freeoff(&toff);
                cli_pcre_freeoff(&tpoff);

                cli_targetinfo_destroy(&info);
                cl_hash_destroy(md5ctx);
                cl_hash_destroy(sha1ctx);
                cl_hash_destroy(sha256ctx);
                return ret;
            }
        }

        if (!ftonly) {
            virname = NULL;
            ret     = matcher_run(groot, buff, bytes, &virname, &gdata, offset, &info, ftype, ftoffset, acmode, PCRE_SCAN_FMAP, acres, ctx->fmap, NULL, &gpoff, ctx);

            if (virname) {
                /* virname already appended by matcher_run */
                viruses_found = 1;
            }
            if ((ret == CL_VIRUS && !SCAN_ALLMATCHES) || ret == CL_EMEM) {
                cli_ac_freedata(&gdata);
                cli_pcre_freeoff(&gpoff);
                if (troot) {
                    cli_ac_freedata(&tdata);
                    if (bm_offmode)
                        cli_bm_freeoff(&toff);
                    cli_pcre_freeoff(&tpoff);
                }

                cli_targetinfo_destroy(&info);
                cl_hash_destroy(md5ctx);
                cl_hash_destroy(sha1ctx);
                cl_hash_destroy(sha256ctx);
                return ret;
            } else if ((acmode & AC_SCAN_FT) && ((cli_file_t)ret >= CL_TYPENO)) {
                if (ret > type)
                    type = ret;
            }

            /* if (bytes <= (maxpatlen * (offset!=0))), it means the last window finished the file hashing *
             *   since the last window is responsible for adding intersection between windows (maxpatlen)  */
            if (hdb && (bytes > (maxpatlen * (offset != 0)))) {
                const void *data  = buff + maxpatlen * (offset != 0);
                uint32_t data_len = bytes - maxpatlen * (offset != 0);

                if (compute_hash[CLI_HASH_MD5])
                    cl_update_hash(md5ctx, (void *)data, data_len);
                if (compute_hash[CLI_HASH_SHA1])
                    cl_update_hash(sha1ctx, (void *)data, data_len);
                if (compute_hash[CLI_HASH_SHA256])
                    cl_update_hash(sha256ctx, (void *)data, data_len);
            }
        }

        if (bytes < SCANBUFF)
            break;

        offset += bytes - maxpatlen;
    }

    if (!ftonly && hdb) {
        enum CLI_HASH_TYPE hashtype, hashtype2;

        if (compute_hash[CLI_HASH_MD5]) {
            cl_finish_hash(md5ctx, digest[CLI_HASH_MD5]);
            md5ctx = NULL;
        }
        if (refhash)
            compute_hash[CLI_HASH_MD5] = 1;
        if (compute_hash[CLI_HASH_SHA1]) {
            cl_finish_hash(sha1ctx, digest[CLI_HASH_SHA1]);
            sha1ctx = NULL;
        }
        if (compute_hash[CLI_HASH_SHA256]) {
            cl_finish_hash(sha256ctx, digest[CLI_HASH_SHA256]);
            sha256ctx = NULL;
        }

        virname = NULL;
        for (hashtype = CLI_HASH_MD5; hashtype < CLI_HASH_AVAIL_TYPES; hashtype++) {
            const char *virname_w = NULL;
            int found             = 0;

            /* If no hash, skip to next type */
            if (!compute_hash[hashtype])
                continue;

            /* Do hash scan */
            if ((ret = cli_hm_scan(digest[hashtype], ctx->fmap->len, &virname, hdb, hashtype)) == CL_VIRUS) {
                found += 1;
            }
            if (!found || SCAN_ALLMATCHES) {
                if ((ret = cli_hm_scan_wild(digest[hashtype], &virname_w, hdb, hashtype)) == CL_VIRUS)
                    found += 2;
            }

            /* If found, do immediate hash-only FP check */
            if (found && fp) {
                for (hashtype2 = CLI_HASH_MD5; hashtype2 < CLI_HASH_AVAIL_TYPES; hashtype2++) {
                    if (!compute_hash[hashtype2])
                        continue;
                    if (cli_hm_scan(digest[hashtype2], ctx->fmap->len, NULL, fp, hashtype2) == CL_VIRUS) {
                        found = 0;
                        ret   = CL_CLEAN;
                        break;
                    } else if (cli_hm_scan_wild(digest[hashtype2], NULL, fp, hashtype2) == CL_VIRUS) {
                        found = 0;
                        ret   = CL_CLEAN;
                        break;
                    }
                }
            }

            /* If matched size-based hash ... */
            if (found % 2) {
                viruses_found = 1;
                ret           = cli_append_virus(ctx, virname);
                if (!SCAN_ALLMATCHES || ret != CL_CLEAN)
                    break;
                virname = NULL;
            }
            /* If matched size-agnostic hash ... */
            if (found > 1) {
                viruses_found = 1;
                ret           = cli_append_virus(ctx, virname_w);
                if (!SCAN_ALLMATCHES || ret != CL_CLEAN)
                    break;
            }
        }
    }

    cl_hash_destroy(md5ctx);
    cl_hash_destroy(sha1ctx);
    cl_hash_destroy(sha256ctx);

    if (troot) {
        if (ret != CL_VIRUS || SCAN_ALLMATCHES)
            ret = cli_exp_eval(ctx, troot, &tdata, &info, (const char *)refhash);
        if (ret == CL_VIRUS)
            viruses_found++;

        cli_ac_freedata(&tdata);
        if (bm_offmode)
            cli_bm_freeoff(&toff);
        cli_pcre_freeoff(&tpoff);
    }

    if (groot) {
        if (ret != CL_VIRUS || SCAN_ALLMATCHES)
            ret = cli_exp_eval(ctx, groot, &gdata, &info, (const char *)refhash);
        cli_ac_freedata(&gdata);
        cli_pcre_freeoff(&gpoff);
    }

    cli_targetinfo_destroy(&info);

    if (SCAN_ALLMATCHES && viruses_found) {
        return CL_VIRUS;
    }
    if (ret == CL_VIRUS) {
        return CL_VIRUS;
    }

    return (acmode & AC_SCAN_FT) ? type : CL_CLEAN;
}

#define CDBRANGE(field, val)                                              \
    if (field[0] != CLI_OFF_ANY) {                                        \
        if (field[0] == field[1] && field[0] != val)                      \
            continue;                                                     \
        else if (field[0] != field[1] && ((field[0] && field[0] > val) || \
                                          (field[1] && field[1] < val)))  \
            continue;                                                     \
    }

cl_error_t cli_matchmeta(cli_ctx *ctx, const char *fname, size_t fsizec, size_t fsizer, int encrypted, unsigned int filepos, int res1, void *res2)
{
    const struct cli_cdb *cdb;
    unsigned int viruses_found = 0;
    cl_error_t ret             = CL_CLEAN;

    cli_dbgmsg("CDBNAME:%s:%llu:%s:%llu:%llu:%d:%u:%u:%p\n",
               cli_ftname(cli_recursion_stack_get_type(ctx, -1)), (long long unsigned)fsizec, fname, (long long unsigned)fsizec, (long long unsigned)fsizer,
               encrypted, filepos, res1, res2);

    if (ctx->engine && ctx->engine->cb_meta)
        if (ctx->engine->cb_meta(cli_ftname(cli_recursion_stack_get_type(ctx, -1)), fsizec, fname, fsizer, encrypted, filepos, ctx->cb_ctx) == CL_VIRUS) {
            cli_dbgmsg("inner file blocked by callback: %s\n", fname);

            ret = cli_append_virus(ctx, "Detected.By.Callback");
            viruses_found++;
            if (!SCAN_ALLMATCHES || ret != CL_CLEAN)
                return ret;
        }

    if (!ctx->engine || !(cdb = ctx->engine->cdb))
        return CL_CLEAN;

    do {
        if (cdb->ctype != CL_TYPE_ANY && cdb->ctype != cli_recursion_stack_get_type(ctx, -1))
            continue;

        if (cdb->encrypted != 2 && cdb->encrypted != encrypted)
            continue;

        if (cdb->res1 && (cdb->ctype == CL_TYPE_ZIP || cdb->ctype == CL_TYPE_RAR) && cdb->res1 != res1)
            continue;

        CDBRANGE(cdb->csize, cli_recursion_stack_get_size(ctx, -1));
        CDBRANGE(cdb->fsizec, fsizec);
        CDBRANGE(cdb->fsizer, fsizer);
        CDBRANGE(cdb->filepos, filepos);

        if (cdb->name.re_magic && (!fname || cli_regexec(&cdb->name, fname, 0, NULL, 0) == REG_NOMATCH))
            continue;

        ret = cli_append_virus(ctx, cdb->virname);
        viruses_found++;
        if (!SCAN_ALLMATCHES || ret != CL_CLEAN)
            return ret;

    } while ((cdb = cdb->next));

    if (SCAN_ALLMATCHES && viruses_found)
        return CL_VIRUS;
    return CL_CLEAN;
}
