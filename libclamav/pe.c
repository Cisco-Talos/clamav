/*
 *  Copyright (C) 2013-2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Alberto Wu, Tomasz Kojm, Andrew Williams
 *
 *  Acknowledgements: The header structures were based upon a PE format
 *                    analysis by B. Luevelsmeyer.
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

/*
#define _XOPEN_SOURCE 500
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#if HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "clamav.h"
#include "others.h"
#include "pe.h"
#include "scanners.h"
#include "execs.h"
#include "matcher.h"
#include "ishield.h"

#include "json_api.h"

#include "clamav_rust.h"

#define DCONF ctx->dconf->pe

void findres(uint32_t by_type, uint32_t by_name, fmap_t *map, struct cli_exe_info *peinfo, int (*cb)(void *, uint32_t, uint32_t, uint32_t, uint32_t), void *opaque)
{
    if (NULL == peinfo || NULL == cb) {
        return;
    }

    findres_rust(by_type, by_name, map, peinfo->sections, peinfo->nsections, peinfo->offset, peinfo->hdr_size, peinfo->ndatadirs, peinfo->dirs[2].VirtualAddress, cb, opaque);
}


static cl_error_t run_pe_bytecode_hook(cli_ctx *ctx, const struct cli_pe_hook_data *pedata, const struct cli_exe_section *sections, unsigned hook, bool scan_result_file)
{
    struct cli_bc_ctx *bc_ctx;
    cl_error_t ret;

    bc_ctx = cli_bytecode_context_alloc();
    if (!bc_ctx) {
        cli_errmsg("cli_scanpe: can't allocate memory for bc_ctx\n");
        return CL_EMEM;
    }

    cli_bytecode_context_setpe(bc_ctx, pedata, sections);
    cli_bytecode_context_setctx(bc_ctx, ctx);
    ret = cli_bytecode_runhook(ctx, ctx->engine, bc_ctx, hook, ctx->fmap);
    switch (ret) {
        case CL_ENULLARG:
            cli_warnmsg("cli_scanpe: NULL argument supplied\n");
            cli_bytecode_context_destroy(bc_ctx);
            return CL_SUCCESS;
        case CL_VIRUS:
            cli_bytecode_context_destroy(bc_ctx);
            return CL_VIRUS;
        case CL_BREAK:
            cli_bytecode_context_destroy(bc_ctx);
            return CL_CLEAN;
        case CL_SUCCESS:
            break;
        default:
            cli_bytecode_context_destroy(bc_ctx);
            return ret;
    }

    if (scan_result_file) {
        char *tempfile = NULL;
        int ndesc      = cli_bytecode_context_getresult_file(bc_ctx, &tempfile);
        cli_bytecode_context_destroy(bc_ctx);
        if (ndesc != -1 && tempfile) {
            lseek(ndesc, 0, SEEK_SET);
            cli_dbgmsg("***** Scanning rebuilt PE file from bytecode hook *****\n");
            ret = cli_magic_scan_desc(ndesc, tempfile, ctx, NULL, LAYER_ATTRIBUTES_NONE);
            close(ndesc);
            if (!ctx->engine->keeptmp && cli_unlink(tempfile)) {
                free(tempfile);
                return CL_EUNLINK;
            }
            free(tempfile);
            return ret == CL_CLEAN ? CL_SUCCESS : ret;
        }
        free(tempfile);
        return CL_SUCCESS;
    }

    cli_bytecode_context_destroy(bc_ctx);
    return CL_SUCCESS;
}

cl_error_t cli_scanpe_clamav_services_from_rust(
    cli_ctx *ctx,
    const struct cli_pe_hook_data *pedata,
    const struct cli_exe_section *sections,
    uint16_t nsections,
    uint32_t is_pe32plus,
    const char *import_md5_hex,
    const char *import_sha1_hex,
    const char *import_sha256_hex,
    uint32_t import_hash_size)
{
    cl_error_t ret;
    unsigned int i;
    int toval = 0;

    if (!ctx || !pedata)
        return CL_ENULLARG;

    if (cli_json_timeout_cycle_check(ctx, &toval) != CL_SUCCESS)
        return CL_ETIMEOUT;

    for (i = 0; i < nsections; i++) {
        if (sections && sections[i].rsz && (DCONF & PE_CONF_MD5SECT) && ctx->engine->hm_mdb) {
            ret = scan_pe_section_hash_rust(ctx, ctx->fmap, &sections[i]);
            if (ret != CL_SUCCESS) {
                if (ret != CL_VIRUS)
                    cli_errmsg("cli_scanpe: scan_pe_section_hash_rust failed: %s!\n", cl_strerror(ret));
                return ret;
            }
        }
    }

    if (!is_pe32plus && pedata->overlays && pedata->overlays_sz > 0) {
        ret = cli_scanishield(ctx, pedata->overlays, (uint32_t)pedata->overlays_sz);
        if (ret != CL_SUCCESS)
            return ret;
    }

    ret = run_pe_bytecode_hook(ctx, pedata, sections, BC_PE_ALL, false);
    if (ret != CL_SUCCESS && ret != CL_CLEAN)
        return ret;

    if (DCONF & PE_CONF_IMPTBL) {
        ret = scan_pe_import_hashes_rust(ctx, import_md5_hex, import_sha1_hex, import_sha256_hex, import_hash_size);
        if (ret != CL_SUCCESS)
            return ret == CL_BREAK ? CL_CLEAN : ret;
    }

    ret = run_pe_bytecode_hook(ctx, pedata, sections, BC_PE_UNPACKER, true);
    return ret == CL_CLEAN ? CL_SUCCESS : ret;
}

cl_error_t cli_pe_targetinfo_from_rust(
    void *peinfo_void,
    const struct cli_exe_section *sections,
    uint16_t nsections,
    uint32_t ep,
    uint32_t res_addr,
    uint32_t hdr_size,
    uint32_t vep,
    uint32_t ndatadirs,
    uint32_t is_dll,
    uint32_t is_pe32plus,
    uint32_t e_lfanew,
    uint32_t min,
    uint32_t max,
    uint32_t overlay_start,
    uint32_t overlay_size,
    const struct pe_image_data_dir *dirs,
    uintptr_t dir_count,
    const uint32_t *version_offsets,
    uintptr_t version_offset_count)
{
    struct cli_exe_info *peinfo = (struct cli_exe_info *)peinfo_void;
    size_t i;

    if (!peinfo)
        return CL_ENULLARG;

    if (nsections) {
        if (!sections)
            return CL_ENULLARG;
        peinfo->sections = (struct cli_exe_section *)cli_max_calloc(nsections, sizeof(struct cli_exe_section));
        if (!peinfo->sections)
            return CL_EMEM;
        memcpy(peinfo->sections, sections, (size_t)nsections * sizeof(struct cli_exe_section));
    }

    peinfo->ep            = ep;
    peinfo->nsections     = nsections;
    peinfo->res_addr      = res_addr;
    peinfo->hdr_size      = hdr_size;
    peinfo->vep           = vep;
    peinfo->ndatadirs     = ndatadirs;
    peinfo->is_dll        = is_dll;
    peinfo->is_pe32plus   = is_pe32plus;
    peinfo->e_lfanew      = e_lfanew;
    peinfo->min           = min;
    peinfo->max           = max;
    peinfo->overlay_start = overlay_start;
    peinfo->overlay_size  = overlay_size;

    if (dirs) {
        size_t copy_count = MIN(dir_count, sizeof(peinfo->dirs) / sizeof(peinfo->dirs[0]));
        for (i = 0; i < copy_count; i++) {
            peinfo->dirs[i].VirtualAddress = dirs[i].VirtualAddress;
            peinfo->dirs[i].Size           = dirs[i].Size;
        }
    }

    if (version_offsets && version_offset_count) {
        if (cli_hashset_init(&peinfo->vinfo, 32, 80)) {
            cli_errmsg("cli_pe_targetinfo_from_rust: Unable to init vinfo hashset\n");
            return CL_EMEM;
        }
        for (i = 0; i < version_offset_count; i++) {
            if (cli_hashset_addkey(&peinfo->vinfo, version_offsets[i])) {
                cli_errmsg("cli_pe_targetinfo_from_rust: Unable to add vinfo offset\n");
                return CL_EMEM;
            }
        }
    }

    return CL_SUCCESS;
}

int cli_scanpe(cli_ctx *ctx)
{
    if (!ctx) {
        cli_errmsg("cli_scanpe: ctx == NULL\n");
        return CL_ENULLARG;
    }

    cli_dbgmsg("cli_scanpe: using Rust executable parser\n");
    return scan_pe_rust(ctx);
}

cl_error_t cli_pe_targetinfo(cli_ctx *ctx, struct cli_exe_info *peinfo)
{
    return populate_pe_target_info_rust(ctx, peinfo);
}

/* Generate and, when debug logging is enabled, print the MD5, SHA1, or
 * SHA2-256 associated with the imphash or the individual sections. Section
 * hashes are computed after sorting sections by raw file offset.
 *
 * A few other notes:
 *  - Sections with zero raw size, sections larger than CLI_MAX_ALLOCATION, or
 *    sections whose raw data cannot be mapped do not produce a hash.
 *  - The Rust PE parser validates section ranges before hashing. Sections
 *    outside the file or without raw data do not produce a hash.
 */
cl_error_t cli_genhash_pe(cli_ctx *ctx, unsigned int class, cli_hash_type_t type)
{
    return genhash_pe_rust(ctx, class, type);
}
