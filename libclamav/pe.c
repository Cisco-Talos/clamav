/*
 *  Copyright (C) 2013-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
/*
  Portions of Code (i.e. pe_ordinal) Copyright (c) 2014. The YARA Authors. All Rights Reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <time.h>
#include <stdarg.h>

#include "clamav.h"
#include "others.h"
#include "pe.h"
#include "petite.h"
#include "fsg.h"
#include "spin.h"
#include "upx.h"
#include "yc.h"
#include "aspack.h"
#include "wwunpack.h"
#include "unsp.h"
#include "scanners.h"
#include "str.h"
#include "entconv.h"
#include "execs.h"
#include "mew.h"
#include "upack.h"
#include "matcher.h"
#include "matcher-hash.h"
#include "disasm.h"
#include "special.h"
#include "ishield.h"
#include "asn1.h"

#include "json_api.h"

#include "clamav_rust.h"

#define DCONF ctx->dconf->pe

#define PE_IMAGE_DOS_SIGNATURE 0x5a4d     /* MZ */
#define PE_IMAGE_DOS_SIGNATURE_OLD 0x4d5a /* ZM */
#define PE_IMAGE_NT_SIGNATURE 0x00004550
#define PE32_SIGNATURE 0x010b
#define PE32P_SIGNATURE 0x020b
#define OPT_HDR_SIZE_DIFF (sizeof(struct pe_image_optional_hdr64) - sizeof(struct pe_image_optional_hdr32))

#define UPX_NRV2B "\x11\xdb\x11\xc9\x01\xdb\x75\x07\x8b\x1e\x83\xee\xfc\x11\xdb\x11\xc9\x11\xc9\x75\x20\x41\x01\xdb"
#define UPX_NRV2D "\x83\xf0\xff\x74\x78\xd1\xf8\x89\xc5\xeb\x0b\x01\xdb\x75\x07\x8b\x1e\x83\xee\xfc\x11\xdb\x11\xc9"
#define UPX_NRV2E "\xeb\x52\x31\xc9\x83\xe8\x03\x72\x11\xc1\xe0\x08\x8a\x06\x46\x83\xf0\xff\x74\x75\xd1\xf8\x89\xc5"
#define UPX_LZMA1_FIRST "\x56\x83\xc3\x04\x53\x50\xc7\x03"
#define UPX_LZMA1_SECOND "\x90\x90\x90\x55\x57\x56\x53\x83"
#define UPX_LZMA0 "\x56\x83\xc3\x04\x53\x50\xc7\x03\x03\x00\x00\x00\x90\x90\x90\x55\x57\x56\x53\x83"
#define UPX_LZMA2 "\x56\x83\xc3\x04\x53\x50\xc7\x03\x03\x00\x02\x00\x90\x90\x90\x90\x90\x55\x57\x56"

#define PE_MAXNAMESIZE 256
#define PE_MAXIMPORTS 1024

#define EC64(x) ((uint64_t)cli_readint64(&(x))) /* Convert little endian to host */
#define EC32(x) ((uint32_t)cli_readint32(&(x)))
#define EC16(x) ((uint16_t)cli_readint16(&(x)))
/* lower and upper boundary alignment (size vs offset) */
#define PEALIGN(o, a) (((a)) ? (((o) / (a)) * (a)) : (o))
#define PESALIGN(o, a) (((a)) ? (((o) / (a) + ((o) % (a) != 0)) * (a)) : (o))

// TODO Replace all of these with static inline functions
#define CLI_UNPSIZELIMITS(NAME, CHK)                           \
    if (cli_checklimits(NAME, ctx, (CHK), 0, 0) != CL_CLEAN) { \
        cli_exe_info_destroy(peinfo);                          \
        return CL_CLEAN;                                       \
    }

#define CLI_UNPTEMP(NAME, FREEME)                                                                 \
    if (!(tempfile = cli_gentemp(ctx->sub_tmpdir))) {                                             \
        cli_exe_info_destroy(peinfo);                                                             \
        cli_multifree FREEME;                                                                     \
        return CL_EMEM;                                                                           \
    }                                                                                             \
    if ((ndesc = open(tempfile, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR)) < 0) { \
        cli_dbgmsg(NAME ": Can't create file %s\n", tempfile);                                    \
        free(tempfile);                                                                           \
        cli_exe_info_destroy(peinfo);                                                             \
        cli_multifree FREEME;                                                                     \
        return CL_ECREAT;                                                                         \
    }

#define CLI_TMPUNLK()               \
    if (!ctx->engine->keeptmp) {    \
        if (cli_unlink(tempfile)) { \
            free(tempfile);         \
            return CL_EUNLINK;      \
        }                           \
    }

#ifdef HAVE__INTERNAL__SHA_COLLECT
#define SHA_OFF                \
    do {                       \
        ctx->sha_collect = -1; \
    } while (0)
#define SHA_RESET                       \
    do {                                \
        ctx->sha_collect = sha_collect; \
    } while (0)
#else
#define SHA_OFF \
    do {        \
    } while (0)
#define SHA_RESET \
    do {          \
    } while (0)
#endif

#define FSGCASE(NAME, FREESEC)                            \
    case 0: /* Unpacked and NOT rebuilt */                \
        cli_dbgmsg(NAME ": Successfully decompressed\n"); \
        close(ndesc);                                     \
        if (cli_unlink(tempfile)) {                       \
            cli_exe_info_destroy(peinfo);                 \
            free(tempfile);                               \
            FREESEC;                                      \
            return CL_EUNLINK;                            \
        }                                                 \
        free(tempfile);                                   \
        FREESEC;                                          \
        found       = 0;                                  \
        upx_success = 1;                                  \
        break; /* FSG ONLY! - scan raw data after upx block */

#define SPINCASE()                                         \
    case 2:                                                \
        free(spinned);                                     \
        close(ndesc);                                      \
        if (cli_unlink(tempfile)) {                        \
            cli_exe_info_destroy(peinfo);                  \
            free(tempfile);                                \
            return CL_EUNLINK;                             \
        }                                                  \
        cli_dbgmsg("cli_scanpe: PESpin: Size exceeded\n"); \
        free(tempfile);                                    \
        break;

#define CLI_UNPRESULTS_(NAME, FSGSTUFF, EXPR, GOOD, FREEME)                               \
    switch (EXPR) {                                                                       \
        case GOOD: /* Unpacked and rebuilt */                                             \
            cli_dbgmsg(NAME ": Unpacked and rebuilt executable saved in %s\n", tempfile); \
            cli_multifree FREEME;                                                         \
            cli_exe_info_destroy(peinfo);                                                 \
            lseek(ndesc, 0, SEEK_SET);                                                    \
            cli_dbgmsg("***** Scanning rebuilt PE file *****\n");                         \
            SHA_OFF;                                                                      \
            if (CL_SUCCESS != (ret = cli_magic_scan_desc(ndesc, tempfile, ctx, NULL))) {  \
                close(ndesc);                                                             \
                SHA_RESET;                                                                \
                CLI_TMPUNLK();                                                            \
                free(tempfile);                                                           \
                return ret;                                                               \
            }                                                                             \
            SHA_RESET;                                                                    \
            close(ndesc);                                                                 \
            CLI_TMPUNLK();                                                                \
            free(tempfile);                                                               \
            return CL_CLEAN;                                                              \
                                                                                          \
            FSGSTUFF;                                                                     \
                                                                                          \
        default:                                                                          \
            cli_dbgmsg(NAME ": Unpacking failed\n");                                      \
            close(ndesc);                                                                 \
            if (cli_unlink(tempfile)) {                                                   \
                cli_exe_info_destroy(peinfo);                                             \
                free(tempfile);                                                           \
                cli_multifree FREEME;                                                     \
                return CL_EUNLINK;                                                        \
            }                                                                             \
            cli_multifree FREEME;                                                         \
            free(tempfile);                                                               \
    }

// The GOOD parameter indicates what a successful unpacking should return.
#define CLI_UNPRESULTS(NAME, EXPR, GOOD, FREEME) CLI_UNPRESULTS_(NAME, (void)0, EXPR, GOOD, FREEME)

// TODO The second argument to FSGCASE below should match what gets freed as
// indicated by FREEME, otherwise a memory leak can occur (as currently used,
// it looks like dest can get leaked by these macros).
#define CLI_UNPRESULTSFSG1(NAME, EXPR, GOOD, FREEME) CLI_UNPRESULTS_(NAME, FSGCASE(NAME, free(sections)), EXPR, GOOD, FREEME)
#define CLI_UNPRESULTSFSG2(NAME, EXPR, GOOD, FREEME) CLI_UNPRESULTS_(NAME, FSGCASE(NAME, (void)0), EXPR, GOOD, FREEME)

#define DETECT_BROKEN_PE (SCAN_HEURISTIC_BROKEN && !ctx->corrupted_input)

extern const unsigned int hashlen[];

struct offset_list {
    uint32_t offset;
    struct offset_list *next;
};

struct pe_image_import_descriptor {
    union {
        uint32_t Characteristics;
        uint32_t OriginalFirstThunk;
    } u;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
};

#define PE_IMAGEDIR_ORDINAL_FLAG32 0x80000000
#define PE_IMAGEDIR_ORDINAL_FLAG64 0x8000000000000000L

struct pe_image_thunk32 {
    union {
        uint32_t ForwarderString;
        uint32_t Function;
        uint32_t Ordinal;
        uint32_t AddressOfData;
    } u;
};

struct pe_image_thunk64 {
    union {
        uint64_t ForwarderString;
        uint64_t Function;
        uint64_t Ordinal;
        uint64_t AddressOfData;
    } u;
};

struct pe_image_import_by_name {
    uint16_t Hint;
    uint8_t Name[1];
};

static void cli_multifree(void *f, ...)
{
    void *ff;
    va_list ap;
    free(f);
    va_start(ap, f);
    while ((ff = va_arg(ap, void *))) free(ff);
    va_end(ap);
}

struct vinfo_list {
    uint32_t rvas[16];
    unsigned int count;
};

static int versioninfo_cb(void *opaque, uint32_t type, uint32_t name, uint32_t lang, uint32_t rva)
{
    struct vinfo_list *vlist = (struct vinfo_list *)opaque;

    cli_dbgmsg("versioninfo_cb: type: %x, name: %x, lang: %x, rva: %x\n", type, name, lang, rva);
    vlist->rvas[vlist->count] = rva;
    if (++vlist->count == sizeof(vlist->rvas) / sizeof(vlist->rvas[0]))
        return 1;
    return 0;
}

/* Given an RVA (relative to the ImageBase), return the file offset of the
 * corresponding data */
uint32_t cli_rawaddr(uint32_t rva, const struct cli_exe_section *shp, uint16_t nos, unsigned int *err, size_t fsize, uint32_t hdr_size)
{
    int i, found = 0;
    uint32_t ret;

    if (rva < hdr_size) { /* Out of section EP - mapped to imagebase+rva */
        if (rva >= fsize) {
            *err = 1;
            return 0;
        }

        *err = 0;
        return rva;
    }

    for (i = nos - 1; i >= 0; i--) {
        if (shp[i].rsz && shp[i].rva <= rva && shp[i].rsz > (rva - shp[i].rva)) {
            found = 1;
            break;
        }
    }

    if (!found) {
        *err = 1;
        return 0;
    }

    ret  = (rva - shp[i].rva) + shp[i].raw;
    *err = 0;
    return ret;
}

/*
   void findres(uint32_t by_type, uint32_t by_name, fmap_t *map, struct cli_exe_info *peinfo, int (*cb)(void *, uint32_t, uint32_t, uint32_t, uint32_t), void *opaque)
   callback based res lookup

   by_type: lookup type
   by_name: lookup name or (unsigned)-1 to look for any name
   res_rva: base resource rva (i.e. dirs[2].VirtualAddress)
   map, peinfo: same as in scanpe
   cb: the callback function executed on each successful match
   opaque: an opaque pointer passed to the callback

   the callback proto is
   int pe_res_cballback (void *opaque, uint32_t type, uint32_t name, uint32_t lang, uint32_t rva);
   the callback shall return 0 to continue the lookup or 1 to abort
*/
void findres(uint32_t by_type, uint32_t by_name, fmap_t *map, struct cli_exe_info *peinfo, int (*cb)(void *, uint32_t, uint32_t, uint32_t, uint32_t), void *opaque)
{
    unsigned int err = 0;
    uint32_t type, type_offs, name, name_offs, lang, lang_offs;
    const uint8_t *resdir, *type_entry, *name_entry, *lang_entry;
    uint16_t type_cnt, name_cnt, lang_cnt;
    uint32_t res_rva;

    if (NULL == peinfo || peinfo->ndatadirs < 3) {
        return;
    }

    if (0 != peinfo->offset) {
        cli_dbgmsg("findres: Assumption Violated: Looking for version info when peinfo->offset != 0\n");
    }

    res_rva = EC32(peinfo->dirs[2].VirtualAddress);

    if (!(resdir = fmap_need_off_once(map, cli_rawaddr(res_rva, peinfo->sections, peinfo->nsections, &err, map->len, peinfo->hdr_size), 16)) || err)
        return;

    type_cnt   = (uint16_t)cli_readint16(resdir + 12);
    type_entry = resdir + 16;
    if (!(by_type >> 31)) {
        type_entry += type_cnt * 8;
        type_cnt = (uint16_t)cli_readint16(resdir + 14);
    }

    while (type_cnt--) {
        if (!fmap_need_ptr_once(map, type_entry, 8))
            return;
        type      = cli_readint32(type_entry);
        type_offs = cli_readint32(type_entry + 4);
        if (type == by_type && (type_offs >> 31)) {
            type_offs &= 0x7fffffff;
            if (!(resdir = fmap_need_off_once(map, cli_rawaddr(res_rva + type_offs, peinfo->sections, peinfo->nsections, &err, map->len, peinfo->hdr_size), 16)) || err)
                return;

            name_cnt   = (uint16_t)cli_readint16(resdir + 12);
            name_entry = resdir + 16;
            if (by_name == 0xffffffff)
                name_cnt += (uint16_t)cli_readint16(resdir + 14);
            else if (!(by_name >> 31)) {
                name_entry += name_cnt * 8;
                name_cnt = (uint16_t)cli_readint16(resdir + 14);
            }
            while (name_cnt--) {
                if (!fmap_need_ptr_once(map, name_entry, 8))
                    return;
                name      = cli_readint32(name_entry);
                name_offs = cli_readint32(name_entry + 4);
                if ((by_name == 0xffffffff || name == by_name) && (name_offs >> 31)) {
                    name_offs &= 0x7fffffff;
                    if (!(resdir = fmap_need_off_once(map, cli_rawaddr(res_rva + name_offs, peinfo->sections, peinfo->nsections, &err, map->len, peinfo->hdr_size), 16)) || err)
                        return;

                    lang_cnt   = (uint16_t)cli_readint16(resdir + 12) + (uint16_t)cli_readint16(resdir + 14);
                    lang_entry = resdir + 16;
                    while (lang_cnt--) {
                        if (!fmap_need_ptr_once(map, lang_entry, 8))
                            return;
                        lang      = cli_readint32(lang_entry);
                        lang_offs = cli_readint32(lang_entry + 4);
                        if (!(lang_offs >> 31)) {
                            if (cb(opaque, type, name, lang, res_rva + lang_offs))
                                return;
                        }
                        lang_entry += 8;
                    }
                }
                name_entry += 8;
            }
            return; /* FIXME: unless we want to find ALL types */
        }
        type_entry += 8;
    }
}

static void cli_parseres_special(uint32_t base, uint32_t rva, fmap_t *map, struct cli_exe_info *peinfo, size_t fsize, unsigned int level, uint32_t type, unsigned int *maxres, struct swizz_stats *stats)
{
    unsigned int err = 0, i;
    const uint8_t *resdir;
    const uint8_t *entry, *oentry;
    uint16_t named, unnamed;
    uint32_t rawaddr = cli_rawaddr(rva, peinfo->sections, peinfo->nsections, &err, fsize, peinfo->hdr_size);
    uint32_t entries;

    if (level > 2 || !*maxres) return;
    *maxres -= 1;
    if (err || !(resdir = fmap_need_off_once(map, rawaddr, 16)))
        return;
    named   = (uint16_t)cli_readint16(resdir + 12);
    unnamed = (uint16_t)cli_readint16(resdir + 14);

    entries = /*named+*/ unnamed;
    if (!entries)
        return;
    rawaddr += named * 8; /* skip named */
    /* this is just used in a heuristic detection, so don't give error on failure */
    if (!(entry = fmap_need_off(map, rawaddr + 16, entries * 8))) {
        cli_dbgmsg("cli_parseres_special: failed to read resource directory at:%lu\n", (unsigned long)rawaddr + 16);
        return;
    }
    oentry = entry;
    /*for (i=0; i<named; i++) {
        uint32_t id, offs;
        id = cli_readint32(entry);
        offs = cli_readint32(entry+4);
        if(offs>>31)
            cli_parseres( base, base + (offs&0x7fffffff), srcfd, peinfo, fsize, level+1, type, maxres, stats);
        entry+=8;
    }*/
    for (i = 0; i < unnamed; i++, entry += 8) {
        uint32_t id, offs;
        if (stats->errors >= SWIZZ_MAXERRORS) {
            cli_dbgmsg("cli_parseres_special: resources broken, ignoring\n");
            return;
        }
        id = cli_readint32(entry) & 0x7fffffff;
        if (level == 0) {
            type = 0;
            switch (id) {
                case 4:  /* menu */
                case 5:  /* dialog */
                case 6:  /* string */
                case 11: /* msgtable */
                    type = id;
                    break;
                case 16:
                    type = id;
                    /* 14: version */
                    stats->has_version = 1;
                    break;
                case 24: /* manifest */
                    stats->has_manifest = 1;
                    break;
                    /* otherwise keep it 0, we don't want it */
            }
        }
        if (!type) {
            /* if we are not interested in this type, skip */
            continue;
        }
        offs = cli_readint32(entry + 4);
        if (offs >> 31)
            cli_parseres_special(base, base + (offs & 0x7fffffff), map, peinfo, fsize, level + 1, type, maxres, stats);
        else {
            offs    = cli_readint32(entry + 4);
            rawaddr = cli_rawaddr(base + offs, peinfo->sections, peinfo->nsections, &err, fsize, peinfo->hdr_size);
            if (!err && (resdir = fmap_need_off_once(map, rawaddr, 16))) {
                uint32_t isz = cli_readint32(resdir + 4);
                const uint8_t *str;
                rawaddr = cli_rawaddr(cli_readint32(resdir), peinfo->sections, peinfo->nsections, &err, fsize, peinfo->hdr_size);
                if (err || !isz || isz >= fsize || rawaddr + isz >= fsize) {
                    cli_dbgmsg("cli_parseres_special: invalid resource table entry: %lu + %lu\n",
                               (unsigned long)rawaddr,
                               (unsigned long)isz);
                    stats->errors++;
                    continue;
                }
                if ((id & 0xff) != 0x09) /* english res only */
                    continue;
                if ((str = fmap_need_off_once(map, rawaddr, isz)))
                    cli_detect_swizz_str(str, isz, stats, type);
            }
        }
    }
    fmap_unneed_ptr(map, oentry, entries * 8);
}

static unsigned int cli_hashsect(fmap_t *map, struct cli_exe_section *s, unsigned char **digest, int *foundhash, int *foundwild)
{
    const void *hashme;

    if (s->rsz > CLI_MAX_ALLOCATION) {
        cli_dbgmsg("cli_hashsect: skipping hash calculation for too big section\n");
        return 0;
    }

    if (!s->rsz) return 0;
    if (!(hashme = fmap_need_off_once(map, s->raw, s->rsz))) {
        cli_dbgmsg("cli_hashsect: unable to read section data\n");
        return 0;
    }

    if (foundhash[CLI_HASH_MD5] || foundwild[CLI_HASH_MD5])
        cl_hash_data("md5", hashme, s->rsz, digest[CLI_HASH_MD5], NULL);
    if (foundhash[CLI_HASH_SHA1] || foundwild[CLI_HASH_SHA1])
        cl_sha1(hashme, s->rsz, digest[CLI_HASH_SHA1], NULL);
    if (foundhash[CLI_HASH_SHA256] || foundwild[CLI_HASH_SHA256])
        cl_sha256(hashme, s->rsz, digest[CLI_HASH_SHA256], NULL);

    return 1;
}

/* check hash section sigs */
static cl_error_t scan_pe_mdb(cli_ctx *ctx, struct cli_exe_section *exe_section)
{
    struct cli_matcher *mdb_sect = ctx->engine->hm_mdb;
    unsigned char *hashset[CLI_HASH_AVAIL_TYPES];
    const char *virname = NULL;
    int foundsize[CLI_HASH_AVAIL_TYPES];
    int foundwild[CLI_HASH_AVAIL_TYPES];
    cli_hash_type_t type;
    cl_error_t ret     = CL_CLEAN;
    unsigned char *md5 = NULL;

    /* pick hashtypes to generate */
    for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
        foundsize[type] = cli_hm_have_size(mdb_sect, type, exe_section->rsz);
        foundwild[type] = cli_hm_have_wild(mdb_sect, type);
        if (foundsize[type] || foundwild[type]) {
            hashset[type] = cli_malloc(hashlen[type]);
            if (!hashset[type]) {
                cli_errmsg("scan_pe_mdb: cli_malloc failed!\n");
                for (; type > 0;)
                    free(hashset[--type]);
                return CL_EMEM;
            }
        } else {
            hashset[type] = NULL;
        }
    }

    /* Generate hashes */
    cli_hashsect(ctx->fmap, exe_section, hashset, foundsize, foundwild);

    /* Print hash */
    if (cli_debug_flag) {
        md5 = hashset[CLI_HASH_MD5];
        if (md5) {
            cli_dbgmsg("MDB hashset: %u:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
                       exe_section->rsz, md5[0], md5[1], md5[2], md5[3], md5[4], md5[5], md5[6], md5[7],
                       md5[8], md5[9], md5[10], md5[11], md5[12], md5[13], md5[14], md5[15]);
        } else if (cli_always_gen_section_hash) {
            const void *hashme = fmap_need_off_once(ctx->fmap, exe_section->raw, exe_section->rsz);
            if (!(hashme)) {
                cli_errmsg("scan_pe_mdb: unable to read section data\n");
                ret = CL_EREAD;
                goto end;
            }

            md5 = cli_malloc(16);
            if (!(md5)) {
                cli_errmsg("scan_pe_mdb: cli_malloc failed!\n");
                ret = CL_EMEM;
                goto end;
            }

            cl_hash_data("md5", hashme, exe_section->rsz, md5, NULL);

            cli_dbgmsg("MDB: %u:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
                       exe_section->rsz, md5[0], md5[1], md5[2], md5[3], md5[4], md5[5], md5[6], md5[7],
                       md5[8], md5[9], md5[10], md5[11], md5[12], md5[13], md5[14], md5[15]);

            free(md5);

        } else {
            cli_dbgmsg("MDB: %u:notgenerated\n", exe_section->rsz);
        }
    }

    /* Do scans */
    for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
        if (foundsize[type] && cli_hm_scan(hashset[type], exe_section->rsz, &virname, mdb_sect, type) == CL_VIRUS) {
            ret = cli_append_virus(ctx, virname);
            if (ret != CL_SUCCESS) {
                break;
            }
        }
        if (foundwild[type] && cli_hm_scan_wild(hashset[type], &virname, mdb_sect, type) == CL_VIRUS) {
            ret = cli_append_virus(ctx, virname);
            if (ret != CL_SUCCESS) {
                break;
            }
        }
    }

end:
    for (type = CLI_HASH_AVAIL_TYPES; type > 0;)
        free(hashset[--type]);
    return ret;
}

/* imptbl scanning */
static char *pe_ordinal(const char *dll, uint16_t ord)
{
    char name[64];
    name[0] = '\0';

    if (strncasecmp(dll, "WS2_32.dll", 10) == 0 ||
        strncasecmp(dll, "wsock32.dll", 11) == 0) {
        switch (ord) {
            case 1:
                sprintf(name, "accept");
                break;
            case 2:
                sprintf(name, "bind");
                break;
            case 3:
                sprintf(name, "closesocket");
                break;
            case 4:
                sprintf(name, "connect");
                break;
            case 5:
                sprintf(name, "getpeername");
                break;
            case 6:
                sprintf(name, "getsockname");
                break;
            case 7:
                sprintf(name, "getsockopt");
                break;
            case 8:
                sprintf(name, "htonl");
                break;
            case 9:
                sprintf(name, "htons");
                break;
            case 10:
                sprintf(name, "ioctlsocket");
                break;
            case 11:
                sprintf(name, "inet_addr");
                break;
            case 12:
                sprintf(name, "inet_ntoa");
                break;
            case 13:
                sprintf(name, "listen");
                break;
            case 14:
                sprintf(name, "ntohl");
                break;
            case 15:
                sprintf(name, "ntohs");
                break;
            case 16:
                sprintf(name, "recv");
                break;
            case 17:
                sprintf(name, "recvfrom");
                break;
            case 18:
                sprintf(name, "select");
                break;
            case 19:
                sprintf(name, "send");
                break;
            case 20:
                sprintf(name, "sendto");
                break;
            case 21:
                sprintf(name, "setsockopt");
                break;
            case 22:
                sprintf(name, "shutdown");
                break;
            case 23:
                sprintf(name, "socket");
                break;
            case 24:
                sprintf(name, "GetAddrInfoW");
                break;
            case 25:
                sprintf(name, "GetNameInfoW");
                break;
            case 26:
                sprintf(name, "WSApSetPostRoutine");
                break;
            case 27:
                sprintf(name, "FreeAddrInfoW");
                break;
            case 28:
                sprintf(name, "WPUCompleteOverlappedRequest");
                break;
            case 29:
                sprintf(name, "WSAAccept");
                break;
            case 30:
                sprintf(name, "WSAAddressToStringA");
                break;
            case 31:
                sprintf(name, "WSAAddressToStringW");
                break;
            case 32:
                sprintf(name, "WSACloseEvent");
                break;
            case 33:
                sprintf(name, "WSAConnect");
                break;
            case 34:
                sprintf(name, "WSACreateEvent");
                break;
            case 35:
                sprintf(name, "WSADuplicateSocketA");
                break;
            case 36:
                sprintf(name, "WSADuplicateSocketW");
                break;
            case 37:
                sprintf(name, "WSAEnumNameSpaceProvidersA");
                break;
            case 38:
                sprintf(name, "WSAEnumNameSpaceProvidersW");
                break;
            case 39:
                sprintf(name, "WSAEnumNetworkEvents");
                break;
            case 40:
                sprintf(name, "WSAEnumProtocolsA");
                break;
            case 41:
                sprintf(name, "WSAEnumProtocolsW");
                break;
            case 42:
                sprintf(name, "WSAEventSelect");
                break;
            case 43:
                sprintf(name, "WSAGetOverlappedResult");
                break;
            case 44:
                sprintf(name, "WSAGetQOSByName");
                break;
            case 45:
                sprintf(name, "WSAGetServiceClassInfoA");
                break;
            case 46:
                sprintf(name, "WSAGetServiceClassInfoW");
                break;
            case 47:
                sprintf(name, "WSAGetServiceClassNameByClassIdA");
                break;
            case 48:
                sprintf(name, "WSAGetServiceClassNameByClassIdW");
                break;
            case 49:
                sprintf(name, "WSAHtonl");
                break;
            case 50:
                sprintf(name, "WSAHtons");
                break;
            case 51:
                sprintf(name, "gethostbyaddr");
                break;
            case 52:
                sprintf(name, "gethostbyname");
                break;
            case 53:
                sprintf(name, "getprotobyname");
                break;
            case 54:
                sprintf(name, "getprotobynumber");
                break;
            case 55:
                sprintf(name, "getservbyname");
                break;
            case 56:
                sprintf(name, "getservbyport");
                break;
            case 57:
                sprintf(name, "gethostname");
                break;
            case 58:
                sprintf(name, "WSAInstallServiceClassA");
                break;
            case 59:
                sprintf(name, "WSAInstallServiceClassW");
                break;
            case 60:
                sprintf(name, "WSAIoctl");
                break;
            case 61:
                sprintf(name, "WSAJoinLeaf");
                break;
            case 62:
                sprintf(name, "WSALookupServiceBeginA");
                break;
            case 63:
                sprintf(name, "WSALookupServiceBeginW");
                break;
            case 64:
                sprintf(name, "WSALookupServiceEnd");
                break;
            case 65:
                sprintf(name, "WSALookupServiceNextA");
                break;
            case 66:
                sprintf(name, "WSALookupServiceNextW");
                break;
            case 67:
                sprintf(name, "WSANSPIoctl");
                break;
            case 68:
                sprintf(name, "WSANtohl");
                break;
            case 69:
                sprintf(name, "WSANtohs");
                break;
            case 70:
                sprintf(name, "WSAProviderConfigChange");
                break;
            case 71:
                sprintf(name, "WSARecv");
                break;
            case 72:
                sprintf(name, "WSARecvDisconnect");
                break;
            case 73:
                sprintf(name, "WSARecvFrom");
                break;
            case 74:
                sprintf(name, "WSARemoveServiceClass");
                break;
            case 75:
                sprintf(name, "WSAResetEvent");
                break;
            case 76:
                sprintf(name, "WSASend");
                break;
            case 77:
                sprintf(name, "WSASendDisconnect");
                break;
            case 78:
                sprintf(name, "WSASendTo");
                break;
            case 79:
                sprintf(name, "WSASetEvent");
                break;
            case 80:
                sprintf(name, "WSASetServiceA");
                break;
            case 81:
                sprintf(name, "WSASetServiceW");
                break;
            case 82:
                sprintf(name, "WSASocketA");
                break;
            case 83:
                sprintf(name, "WSASocketW");
                break;
            case 84:
                sprintf(name, "WSAStringToAddressA");
                break;
            case 85:
                sprintf(name, "WSAStringToAddressW");
                break;
            case 86:
                sprintf(name, "WSAWaitForMultipleEvents");
                break;
            case 87:
                sprintf(name, "WSCDeinstallProvider");
                break;
            case 88:
                sprintf(name, "WSCEnableNSProvider");
                break;
            case 89:
                sprintf(name, "WSCEnumProtocols");
                break;
            case 90:
                sprintf(name, "WSCGetProviderPath");
                break;
            case 91:
                sprintf(name, "WSCInstallNameSpace");
                break;
            case 92:
                sprintf(name, "WSCInstallProvider");
                break;
            case 93:
                sprintf(name, "WSCUnInstallNameSpace");
                break;
            case 94:
                sprintf(name, "WSCUpdateProvider");
                break;
            case 95:
                sprintf(name, "WSCWriteNameSpaceOrder");
                break;
            case 96:
                sprintf(name, "WSCWriteProviderOrder");
                break;
            case 97:
                sprintf(name, "freeaddrinfo");
                break;
            case 98:
                sprintf(name, "getaddrinfo");
                break;
            case 99:
                sprintf(name, "getnameinfo");
                break;
            case 101:
                sprintf(name, "WSAAsyncSelect");
                break;
            case 102:
                sprintf(name, "WSAAsyncGetHostByAddr");
                break;
            case 103:
                sprintf(name, "WSAAsyncGetHostByName");
                break;
            case 104:
                sprintf(name, "WSAAsyncGetProtoByNumber");
                break;
            case 105:
                sprintf(name, "WSAAsyncGetProtoByName");
                break;
            case 106:
                sprintf(name, "WSAAsyncGetServByPort");
                break;
            case 107:
                sprintf(name, "WSAAsyncGetServByName");
                break;
            case 108:
                sprintf(name, "WSACancelAsyncRequest");
                break;
            case 109:
                sprintf(name, "WSASetBlockingHook");
                break;
            case 110:
                sprintf(name, "WSAUnhookBlockingHook");
                break;
            case 111:
                sprintf(name, "WSAGetLastError");
                break;
            case 112:
                sprintf(name, "WSASetLastError");
                break;
            case 113:
                sprintf(name, "WSACancelBlockingCall");
                break;
            case 114:
                sprintf(name, "WSAIsBlocking");
                break;
            case 115:
                sprintf(name, "WSAStartup");
                break;
            case 116:
                sprintf(name, "WSACleanup");
                break;
            case 151:
                sprintf(name, "__WSAFDIsSet");
                break;
            case 500:
                sprintf(name, "WEP");
                break;
            default:
                break;
        }
    } else if (strncasecmp(dll, "oleaut32.dll", 12) == 0) {
        switch (ord) {
            case 2:
                sprintf(name, "SysAllocString");
                break;
            case 3:
                sprintf(name, "SysReAllocString");
                break;
            case 4:
                sprintf(name, "SysAllocStringLen");
                break;
            case 5:
                sprintf(name, "SysReAllocStringLen");
                break;
            case 6:
                sprintf(name, "SysFreeString");
                break;
            case 7:
                sprintf(name, "SysStringLen");
                break;
            case 8:
                sprintf(name, "VariantInit");
                break;
            case 9:
                sprintf(name, "VariantClear");
                break;
            case 10:
                sprintf(name, "VariantCopy");
                break;
            case 11:
                sprintf(name, "VariantCopyInd");
                break;
            case 12:
                sprintf(name, "VariantChangeType");
                break;
            case 13:
                sprintf(name, "VariantTimeToDosDateTime");
                break;
            case 14:
                sprintf(name, "DosDateTimeToVariantTime");
                break;
            case 15:
                sprintf(name, "SafeArrayCreate");
                break;
            case 16:
                sprintf(name, "SafeArrayDestroy");
                break;
            case 17:
                sprintf(name, "SafeArrayGetDim");
                break;
            case 18:
                sprintf(name, "SafeArrayGetElemsize");
                break;
            case 19:
                sprintf(name, "SafeArrayGetUBound");
                break;
            case 20:
                sprintf(name, "SafeArrayGetLBound");
                break;
            case 21:
                sprintf(name, "SafeArrayLock");
                break;
            case 22:
                sprintf(name, "SafeArrayUnlock");
                break;
            case 23:
                sprintf(name, "SafeArrayAccessData");
                break;
            case 24:
                sprintf(name, "SafeArrayUnaccessData");
                break;
            case 25:
                sprintf(name, "SafeArrayGetElement");
                break;
            case 26:
                sprintf(name, "SafeArrayPutElement");
                break;
            case 27:
                sprintf(name, "SafeArrayCopy");
                break;
            case 28:
                sprintf(name, "DispGetParam");
                break;
            case 29:
                sprintf(name, "DispGetIDsOfNames");
                break;
            case 30:
                sprintf(name, "DispInvoke");
                break;
            case 31:
                sprintf(name, "CreateDispTypeInfo");
                break;
            case 32:
                sprintf(name, "CreateStdDispatch");
                break;
            case 33:
                sprintf(name, "RegisterActiveObject");
                break;
            case 34:
                sprintf(name, "RevokeActiveObject");
                break;
            case 35:
                sprintf(name, "GetActiveObject");
                break;
            case 36:
                sprintf(name, "SafeArrayAllocDescriptor");
                break;
            case 37:
                sprintf(name, "SafeArrayAllocData");
                break;
            case 38:
                sprintf(name, "SafeArrayDestroyDescriptor");
                break;
            case 39:
                sprintf(name, "SafeArrayDestroyData");
                break;
            case 40:
                sprintf(name, "SafeArrayRedim");
                break;
            case 41:
                sprintf(name, "SafeArrayAllocDescriptorEx");
                break;
            case 42:
                sprintf(name, "SafeArrayCreateEx");
                break;
            case 43:
                sprintf(name, "SafeArrayCreateVectorEx");
                break;
            case 44:
                sprintf(name, "SafeArraySetRecordInfo");
                break;
            case 45:
                sprintf(name, "SafeArrayGetRecordInfo");
                break;
            case 46:
                sprintf(name, "VarParseNumFromStr");
                break;
            case 47:
                sprintf(name, "VarNumFromParseNum");
                break;
            case 48:
                sprintf(name, "VarI2FromUI1");
                break;
            case 49:
                sprintf(name, "VarI2FromI4");
                break;
            case 50:
                sprintf(name, "VarI2FromR4");
                break;
            case 51:
                sprintf(name, "VarI2FromR8");
                break;
            case 52:
                sprintf(name, "VarI2FromCy");
                break;
            case 53:
                sprintf(name, "VarI2FromDate");
                break;
            case 54:
                sprintf(name, "VarI2FromStr");
                break;
            case 55:
                sprintf(name, "VarI2FromDisp");
                break;
            case 56:
                sprintf(name, "VarI2FromBool");
                break;
            case 57:
                sprintf(name, "SafeArraySetIID");
                break;
            case 58:
                sprintf(name, "VarI4FromUI1");
                break;
            case 59:
                sprintf(name, "VarI4FromI2");
                break;
            case 60:
                sprintf(name, "VarI4FromR4");
                break;
            case 61:
                sprintf(name, "VarI4FromR8");
                break;
            case 62:
                sprintf(name, "VarI4FromCy");
                break;
            case 63:
                sprintf(name, "VarI4FromDate");
                break;
            case 64:
                sprintf(name, "VarI4FromStr");
                break;
            case 65:
                sprintf(name, "VarI4FromDisp");
                break;
            case 66:
                sprintf(name, "VarI4FromBool");
                break;
            case 67:
                sprintf(name, "SafeArrayGetIID");
                break;
            case 68:
                sprintf(name, "VarR4FromUI1");
                break;
            case 69:
                sprintf(name, "VarR4FromI2");
                break;
            case 70:
                sprintf(name, "VarR4FromI4");
                break;
            case 71:
                sprintf(name, "VarR4FromR8");
                break;
            case 72:
                sprintf(name, "VarR4FromCy");
                break;
            case 73:
                sprintf(name, "VarR4FromDate");
                break;
            case 74:
                sprintf(name, "VarR4FromStr");
                break;
            case 75:
                sprintf(name, "VarR4FromDisp");
                break;
            case 76:
                sprintf(name, "VarR4FromBool");
                break;
            case 77:
                sprintf(name, "SafeArrayGetVartype");
                break;
            case 78:
                sprintf(name, "VarR8FromUI1");
                break;
            case 79:
                sprintf(name, "VarR8FromI2");
                break;
            case 80:
                sprintf(name, "VarR8FromI4");
                break;
            case 81:
                sprintf(name, "VarR8FromR4");
                break;
            case 82:
                sprintf(name, "VarR8FromCy");
                break;
            case 83:
                sprintf(name, "VarR8FromDate");
                break;
            case 84:
                sprintf(name, "VarR8FromStr");
                break;
            case 85:
                sprintf(name, "VarR8FromDisp");
                break;
            case 86:
                sprintf(name, "VarR8FromBool");
                break;
            case 87:
                sprintf(name, "VarFormat");
                break;
            case 88:
                sprintf(name, "VarDateFromUI1");
                break;
            case 89:
                sprintf(name, "VarDateFromI2");
                break;
            case 90:
                sprintf(name, "VarDateFromI4");
                break;
            case 91:
                sprintf(name, "VarDateFromR4");
                break;
            case 92:
                sprintf(name, "VarDateFromR8");
                break;
            case 93:
                sprintf(name, "VarDateFromCy");
                break;
            case 94:
                sprintf(name, "VarDateFromStr");
                break;
            case 95:
                sprintf(name, "VarDateFromDisp");
                break;
            case 96:
                sprintf(name, "VarDateFromBool");
                break;
            case 97:
                sprintf(name, "VarFormatDateTime");
                break;
            case 98:
                sprintf(name, "VarCyFromUI1");
                break;
            case 99:
                sprintf(name, "VarCyFromI2");
                break;
            case 100:
                sprintf(name, "VarCyFromI4");
                break;
            case 101:
                sprintf(name, "VarCyFromR4");
                break;
            case 102:
                sprintf(name, "VarCyFromR8");
                break;
            case 103:
                sprintf(name, "VarCyFromDate");
                break;
            case 104:
                sprintf(name, "VarCyFromStr");
                break;
            case 105:
                sprintf(name, "VarCyFromDisp");
                break;
            case 106:
                sprintf(name, "VarCyFromBool");
                break;
            case 107:
                sprintf(name, "VarFormatNumber");
                break;
            case 108:
                sprintf(name, "VarBstrFromUI1");
                break;
            case 109:
                sprintf(name, "VarBstrFromI2");
                break;
            case 110:
                sprintf(name, "VarBstrFromI4");
                break;
            case 111:
                sprintf(name, "VarBstrFromR4");
                break;
            case 112:
                sprintf(name, "VarBstrFromR8");
                break;
            case 113:
                sprintf(name, "VarBstrFromCy");
                break;
            case 114:
                sprintf(name, "VarBstrFromDate");
                break;
            case 115:
                sprintf(name, "VarBstrFromDisp");
                break;
            case 116:
                sprintf(name, "VarBstrFromBool");
                break;
            case 117:
                sprintf(name, "VarFormatPercent");
                break;
            case 118:
                sprintf(name, "VarBoolFromUI1");
                break;
            case 119:
                sprintf(name, "VarBoolFromI2");
                break;
            case 120:
                sprintf(name, "VarBoolFromI4");
                break;
            case 121:
                sprintf(name, "VarBoolFromR4");
                break;
            case 122:
                sprintf(name, "VarBoolFromR8");
                break;
            case 123:
                sprintf(name, "VarBoolFromDate");
                break;
            case 124:
                sprintf(name, "VarBoolFromCy");
                break;
            case 125:
                sprintf(name, "VarBoolFromStr");
                break;
            case 126:
                sprintf(name, "VarBoolFromDisp");
                break;
            case 127:
                sprintf(name, "VarFormatCurrency");
                break;
            case 128:
                sprintf(name, "VarWeekdayName");
                break;
            case 129:
                sprintf(name, "VarMonthName");
                break;
            case 130:
                sprintf(name, "VarUI1FromI2");
                break;
            case 131:
                sprintf(name, "VarUI1FromI4");
                break;
            case 132:
                sprintf(name, "VarUI1FromR4");
                break;
            case 133:
                sprintf(name, "VarUI1FromR8");
                break;
            case 134:
                sprintf(name, "VarUI1FromCy");
                break;
            case 135:
                sprintf(name, "VarUI1FromDate");
                break;
            case 136:
                sprintf(name, "VarUI1FromStr");
                break;
            case 137:
                sprintf(name, "VarUI1FromDisp");
                break;
            case 138:
                sprintf(name, "VarUI1FromBool");
                break;
            case 139:
                sprintf(name, "VarFormatFromTokens");
                break;
            case 140:
                sprintf(name, "VarTokenizeFormatString");
                break;
            case 141:
                sprintf(name, "VarAdd");
                break;
            case 142:
                sprintf(name, "VarAnd");
                break;
            case 143:
                sprintf(name, "VarDiv");
                break;
            case 144:
                sprintf(name, "DllCanUnloadNow");
                break;
            case 145:
                sprintf(name, "DllGetClassObject");
                break;
            case 146:
                sprintf(name, "DispCallFunc");
                break;
            case 147:
                sprintf(name, "VariantChangeTypeEx");
                break;
            case 148:
                sprintf(name, "SafeArrayPtrOfIndex");
                break;
            case 149:
                sprintf(name, "SysStringByteLen");
                break;
            case 150:
                sprintf(name, "SysAllocStringByteLen");
                break;
            case 151:
                sprintf(name, "DllRegisterServer");
                break;
            case 152:
                sprintf(name, "VarEqv");
                break;
            case 153:
                sprintf(name, "VarIdiv");
                break;
            case 154:
                sprintf(name, "VarImp");
                break;
            case 155:
                sprintf(name, "VarMod");
                break;
            case 156:
                sprintf(name, "VarMul");
                break;
            case 157:
                sprintf(name, "VarOr");
                break;
            case 158:
                sprintf(name, "VarPow");
                break;
            case 159:
                sprintf(name, "VarSub");
                break;
            case 160:
                sprintf(name, "CreateTypeLib");
                break;
            case 161:
                sprintf(name, "LoadTypeLib");
                break;
            case 162:
                sprintf(name, "LoadRegTypeLib");
                break;
            case 163:
                sprintf(name, "RegisterTypeLib");
                break;
            case 164:
                sprintf(name, "QueryPathOfRegTypeLib");
                break;
            case 165:
                sprintf(name, "LHashValOfNameSys");
                break;
            case 166:
                sprintf(name, "LHashValOfNameSysA");
                break;
            case 167:
                sprintf(name, "VarXor");
                break;
            case 168:
                sprintf(name, "VarAbs");
                break;
            case 169:
                sprintf(name, "VarFix");
                break;
            case 170:
                sprintf(name, "OaBuildVersion");
                break;
            case 171:
                sprintf(name, "ClearCustData");
                break;
            case 172:
                sprintf(name, "VarInt");
                break;
            case 173:
                sprintf(name, "VarNeg");
                break;
            case 174:
                sprintf(name, "VarNot");
                break;
            case 175:
                sprintf(name, "VarRound");
                break;
            case 176:
                sprintf(name, "VarCmp");
                break;
            case 177:
                sprintf(name, "VarDecAdd");
                break;
            case 178:
                sprintf(name, "VarDecDiv");
                break;
            case 179:
                sprintf(name, "VarDecMul");
                break;
            case 180:
                sprintf(name, "CreateTypeLib2");
                break;
            case 181:
                sprintf(name, "VarDecSub");
                break;
            case 182:
                sprintf(name, "VarDecAbs");
                break;
            case 183:
                sprintf(name, "LoadTypeLibEx");
                break;
            case 184:
                sprintf(name, "SystemTimeToVariantTime");
                break;
            case 185:
                sprintf(name, "VariantTimeToSystemTime");
                break;
            case 186:
                sprintf(name, "UnRegisterTypeLib");
                break;
            case 187:
                sprintf(name, "VarDecFix");
                break;
            case 188:
                sprintf(name, "VarDecInt");
                break;
            case 189:
                sprintf(name, "VarDecNeg");
                break;
            case 190:
                sprintf(name, "VarDecFromUI1");
                break;
            case 191:
                sprintf(name, "VarDecFromI2");
                break;
            case 192:
                sprintf(name, "VarDecFromI4");
                break;
            case 193:
                sprintf(name, "VarDecFromR4");
                break;
            case 194:
                sprintf(name, "VarDecFromR8");
                break;
            case 195:
                sprintf(name, "VarDecFromDate");
                break;
            case 196:
                sprintf(name, "VarDecFromCy");
                break;
            case 197:
                sprintf(name, "VarDecFromStr");
                break;
            case 198:
                sprintf(name, "VarDecFromDisp");
                break;
            case 199:
                sprintf(name, "VarDecFromBool");
                break;
            case 200:
                sprintf(name, "GetErrorInfo");
                break;
            case 201:
                sprintf(name, "SetErrorInfo");
                break;
            case 202:
                sprintf(name, "CreateErrorInfo");
                break;
            case 203:
                sprintf(name, "VarDecRound");
                break;
            case 204:
                sprintf(name, "VarDecCmp");
                break;
            case 205:
                sprintf(name, "VarI2FromI1");
                break;
            case 206:
                sprintf(name, "VarI2FromUI2");
                break;
            case 207:
                sprintf(name, "VarI2FromUI4");
                break;
            case 208:
                sprintf(name, "VarI2FromDec");
                break;
            case 209:
                sprintf(name, "VarI4FromI1");
                break;
            case 210:
                sprintf(name, "VarI4FromUI2");
                break;
            case 211:
                sprintf(name, "VarI4FromUI4");
                break;
            case 212:
                sprintf(name, "VarI4FromDec");
                break;
            case 213:
                sprintf(name, "VarR4FromI1");
                break;
            case 214:
                sprintf(name, "VarR4FromUI2");
                break;
            case 215:
                sprintf(name, "VarR4FromUI4");
                break;
            case 216:
                sprintf(name, "VarR4FromDec");
                break;
            case 217:
                sprintf(name, "VarR8FromI1");
                break;
            case 218:
                sprintf(name, "VarR8FromUI2");
                break;
            case 219:
                sprintf(name, "VarR8FromUI4");
                break;
            case 220:
                sprintf(name, "VarR8FromDec");
                break;
            case 221:
                sprintf(name, "VarDateFromI1");
                break;
            case 222:
                sprintf(name, "VarDateFromUI2");
                break;
            case 223:
                sprintf(name, "VarDateFromUI4");
                break;
            case 224:
                sprintf(name, "VarDateFromDec");
                break;
            case 225:
                sprintf(name, "VarCyFromI1");
                break;
            case 226:
                sprintf(name, "VarCyFromUI2");
                break;
            case 227:
                sprintf(name, "VarCyFromUI4");
                break;
            case 228:
                sprintf(name, "VarCyFromDec");
                break;
            case 229:
                sprintf(name, "VarBstrFromI1");
                break;
            case 230:
                sprintf(name, "VarBstrFromUI2");
                break;
            case 231:
                sprintf(name, "VarBstrFromUI4");
                break;
            case 232:
                sprintf(name, "VarBstrFromDec");
                break;
            case 233:
                sprintf(name, "VarBoolFromI1");
                break;
            case 234:
                sprintf(name, "VarBoolFromUI2");
                break;
            case 235:
                sprintf(name, "VarBoolFromUI4");
                break;
            case 236:
                sprintf(name, "VarBoolFromDec");
                break;
            case 237:
                sprintf(name, "VarUI1FromI1");
                break;
            case 238:
                sprintf(name, "VarUI1FromUI2");
                break;
            case 239:
                sprintf(name, "VarUI1FromUI4");
                break;
            case 240:
                sprintf(name, "VarUI1FromDec");
                break;
            case 241:
                sprintf(name, "VarDecFromI1");
                break;
            case 242:
                sprintf(name, "VarDecFromUI2");
                break;
            case 243:
                sprintf(name, "VarDecFromUI4");
                break;
            case 244:
                sprintf(name, "VarI1FromUI1");
                break;
            case 245:
                sprintf(name, "VarI1FromI2");
                break;
            case 246:
                sprintf(name, "VarI1FromI4");
                break;
            case 247:
                sprintf(name, "VarI1FromR4");
                break;
            case 248:
                sprintf(name, "VarI1FromR8");
                break;
            case 249:
                sprintf(name, "VarI1FromDate");
                break;
            case 250:
                sprintf(name, "VarI1FromCy");
                break;
            case 251:
                sprintf(name, "VarI1FromStr");
                break;
            case 252:
                sprintf(name, "VarI1FromDisp");
                break;
            case 253:
                sprintf(name, "VarI1FromBool");
                break;
            case 254:
                sprintf(name, "VarI1FromUI2");
                break;
            case 255:
                sprintf(name, "VarI1FromUI4");
                break;
            case 256:
                sprintf(name, "VarI1FromDec");
                break;
            case 257:
                sprintf(name, "VarUI2FromUI1");
                break;
            case 258:
                sprintf(name, "VarUI2FromI2");
                break;
            case 259:
                sprintf(name, "VarUI2FromI4");
                break;
            case 260:
                sprintf(name, "VarUI2FromR4");
                break;
            case 261:
                sprintf(name, "VarUI2FromR8");
                break;
            case 262:
                sprintf(name, "VarUI2FromDate");
                break;
            case 263:
                sprintf(name, "VarUI2FromCy");
                break;
            case 264:
                sprintf(name, "VarUI2FromStr");
                break;
            case 265:
                sprintf(name, "VarUI2FromDisp");
                break;
            case 266:
                sprintf(name, "VarUI2FromBool");
                break;
            case 267:
                sprintf(name, "VarUI2FromI1");
                break;
            case 268:
                sprintf(name, "VarUI2FromUI4");
                break;
            case 269:
                sprintf(name, "VarUI2FromDec");
                break;
            case 270:
                sprintf(name, "VarUI4FromUI1");
                break;
            case 271:
                sprintf(name, "VarUI4FromI2");
                break;
            case 272:
                sprintf(name, "VarUI4FromI4");
                break;
            case 273:
                sprintf(name, "VarUI4FromR4");
                break;
            case 274:
                sprintf(name, "VarUI4FromR8");
                break;
            case 275:
                sprintf(name, "VarUI4FromDate");
                break;
            case 276:
                sprintf(name, "VarUI4FromCy");
                break;
            case 277:
                sprintf(name, "VarUI4FromStr");
                break;
            case 278:
                sprintf(name, "VarUI4FromDisp");
                break;
            case 279:
                sprintf(name, "VarUI4FromBool");
                break;
            case 280:
                sprintf(name, "VarUI4FromI1");
                break;
            case 281:
                sprintf(name, "VarUI4FromUI2");
                break;
            case 282:
                sprintf(name, "VarUI4FromDec");
                break;
            case 283:
                sprintf(name, "BSTR_UserSize");
                break;
            case 284:
                sprintf(name, "BSTR_UserMarshal");
                break;
            case 285:
                sprintf(name, "BSTR_UserUnmarshal");
                break;
            case 286:
                sprintf(name, "BSTR_UserFree");
                break;
            case 287:
                sprintf(name, "VARIANT_UserSize");
                break;
            case 288:
                sprintf(name, "VARIANT_UserMarshal");
                break;
            case 289:
                sprintf(name, "VARIANT_UserUnmarshal");
                break;
            case 290:
                sprintf(name, "VARIANT_UserFree");
                break;
            case 291:
                sprintf(name, "LPSAFEARRAY_UserSize");
                break;
            case 292:
                sprintf(name, "LPSAFEARRAY_UserMarshal");
                break;
            case 293:
                sprintf(name, "LPSAFEARRAY_UserUnmarshal");
                break;
            case 294:
                sprintf(name, "LPSAFEARRAY_UserFree");
                break;
            case 295:
                sprintf(name, "LPSAFEARRAY_Size");
                break;
            case 296:
                sprintf(name, "LPSAFEARRAY_Marshal");
                break;
            case 297:
                sprintf(name, "LPSAFEARRAY_Unmarshal");
                break;
            case 298:
                sprintf(name, "VarDecCmpR8");
                break;
            case 299:
                sprintf(name, "VarCyAdd");
                break;
            case 300:
                sprintf(name, "DllUnregisterServer");
                break;
            case 301:
                sprintf(name, "OACreateTypeLib2");
                break;
            case 303:
                sprintf(name, "VarCyMul");
                break;
            case 304:
                sprintf(name, "VarCyMulI4");
                break;
            case 305:
                sprintf(name, "VarCySub");
                break;
            case 306:
                sprintf(name, "VarCyAbs");
                break;
            case 307:
                sprintf(name, "VarCyFix");
                break;
            case 308:
                sprintf(name, "VarCyInt");
                break;
            case 309:
                sprintf(name, "VarCyNeg");
                break;
            case 310:
                sprintf(name, "VarCyRound");
                break;
            case 311:
                sprintf(name, "VarCyCmp");
                break;
            case 312:
                sprintf(name, "VarCyCmpR8");
                break;
            case 313:
                sprintf(name, "VarBstrCat");
                break;
            case 314:
                sprintf(name, "VarBstrCmp");
                break;
            case 315:
                sprintf(name, "VarR8Pow");
                break;
            case 316:
                sprintf(name, "VarR4CmpR8");
                break;
            case 317:
                sprintf(name, "VarR8Round");
                break;
            case 318:
                sprintf(name, "VarCat");
                break;
            case 319:
                sprintf(name, "VarDateFromUdateEx");
                break;
            case 322:
                sprintf(name, "GetRecordInfoFromGuids");
                break;
            case 323:
                sprintf(name, "GetRecordInfoFromTypeInfo");
                break;
            case 325:
                sprintf(name, "SetVarConversionLocaleSetting");
                break;
            case 326:
                sprintf(name, "GetVarConversionLocaleSetting");
                break;
            case 327:
                sprintf(name, "SetOaNoCache");
                break;
            case 329:
                sprintf(name, "VarCyMulI8");
                break;
            case 330:
                sprintf(name, "VarDateFromUdate");
                break;
            case 331:
                sprintf(name, "VarUdateFromDate");
                break;
            case 332:
                sprintf(name, "GetAltMonthNames");
                break;
            case 333:
                sprintf(name, "VarI8FromUI1");
                break;
            case 334:
                sprintf(name, "VarI8FromI2");
                break;
            case 335:
                sprintf(name, "VarI8FromR4");
                break;
            case 336:
                sprintf(name, "VarI8FromR8");
                break;
            case 337:
                sprintf(name, "VarI8FromCy");
                break;
            case 338:
                sprintf(name, "VarI8FromDate");
                break;
            case 339:
                sprintf(name, "VarI8FromStr");
                break;
            case 340:
                sprintf(name, "VarI8FromDisp");
                break;
            case 341:
                sprintf(name, "VarI8FromBool");
                break;
            case 342:
                sprintf(name, "VarI8FromI1");
                break;
            case 343:
                sprintf(name, "VarI8FromUI2");
                break;
            case 344:
                sprintf(name, "VarI8FromUI4");
                break;
            case 345:
                sprintf(name, "VarI8FromDec");
                break;
            case 346:
                sprintf(name, "VarI2FromI8");
                break;
            case 347:
                sprintf(name, "VarI2FromUI8");
                break;
            case 348:
                sprintf(name, "VarI4FromI8");
                break;
            case 349:
                sprintf(name, "VarI4FromUI8");
                break;
            case 360:
                sprintf(name, "VarR4FromI8");
                break;
            case 361:
                sprintf(name, "VarR4FromUI8");
                break;
            case 362:
                sprintf(name, "VarR8FromI8");
                break;
            case 363:
                sprintf(name, "VarR8FromUI8");
                break;
            case 364:
                sprintf(name, "VarDateFromI8");
                break;
            case 365:
                sprintf(name, "VarDateFromUI8");
                break;
            case 366:
                sprintf(name, "VarCyFromI8");
                break;
            case 367:
                sprintf(name, "VarCyFromUI8");
                break;
            case 368:
                sprintf(name, "VarBstrFromI8");
                break;
            case 369:
                sprintf(name, "VarBstrFromUI8");
                break;
            case 370:
                sprintf(name, "VarBoolFromI8");
                break;
            case 371:
                sprintf(name, "VarBoolFromUI8");
                break;
            case 372:
                sprintf(name, "VarUI1FromI8");
                break;
            case 373:
                sprintf(name, "VarUI1FromUI8");
                break;
            case 374:
                sprintf(name, "VarDecFromI8");
                break;
            case 375:
                sprintf(name, "VarDecFromUI8");
                break;
            case 376:
                sprintf(name, "VarI1FromI8");
                break;
            case 377:
                sprintf(name, "VarI1FromUI8");
                break;
            case 378:
                sprintf(name, "VarUI2FromI8");
                break;
            case 379:
                sprintf(name, "VarUI2FromUI8");
                break;
            case 401:
                sprintf(name, "OleLoadPictureEx");
                break;
            case 402:
                sprintf(name, "OleLoadPictureFileEx");
                break;
            case 411:
                sprintf(name, "SafeArrayCreateVector");
                break;
            case 412:
                sprintf(name, "SafeArrayCopyData");
                break;
            case 413:
                sprintf(name, "VectorFromBstr");
                break;
            case 414:
                sprintf(name, "BstrFromVector");
                break;
            case 415:
                sprintf(name, "OleIconToCursor");
                break;
            case 416:
                sprintf(name, "OleCreatePropertyFrameIndirect");
                break;
            case 417:
                sprintf(name, "OleCreatePropertyFrame");
                break;
            case 418:
                sprintf(name, "OleLoadPicture");
                break;
            case 419:
                sprintf(name, "OleCreatePictureIndirect");
                break;
            case 420:
                sprintf(name, "OleCreateFontIndirect");
                break;
            case 421:
                sprintf(name, "OleTranslateColor");
                break;
            case 422:
                sprintf(name, "OleLoadPictureFile");
                break;
            case 423:
                sprintf(name, "OleSavePictureFile");
                break;
            case 424:
                sprintf(name, "OleLoadPicturePath");
                break;
            case 425:
                sprintf(name, "VarUI4FromI8");
                break;
            case 426:
                sprintf(name, "VarUI4FromUI8");
                break;
            case 427:
                sprintf(name, "VarI8FromUI8");
                break;
            case 428:
                sprintf(name, "VarUI8FromI8");
                break;
            case 429:
                sprintf(name, "VarUI8FromUI1");
                break;
            case 430:
                sprintf(name, "VarUI8FromI2");
                break;
            case 431:
                sprintf(name, "VarUI8FromR4");
                break;
            case 432:
                sprintf(name, "VarUI8FromR8");
                break;
            case 433:
                sprintf(name, "VarUI8FromCy");
                break;
            case 434:
                sprintf(name, "VarUI8FromDate");
                break;
            case 435:
                sprintf(name, "VarUI8FromStr");
                break;
            case 436:
                sprintf(name, "VarUI8FromDisp");
                break;
            case 437:
                sprintf(name, "VarUI8FromBool");
                break;
            case 438:
                sprintf(name, "VarUI8FromI1");
                break;
            case 439:
                sprintf(name, "VarUI8FromUI2");
                break;
            case 440:
                sprintf(name, "VarUI8FromUI4");
                break;
            case 441:
                sprintf(name, "VarUI8FromDec");
                break;
            case 442:
                sprintf(name, "RegisterTypeLibForUser");
                break;
            case 443:
                sprintf(name, "UnRegisterTypeLibForUser");
                break;
            default:
                break;
        }
    }

    if (name[0] == '\0')
        sprintf(name, "ord%u", ord);

    return cli_strdup(name);
}

static int validate_impname(const char *name, uint32_t length, int dll)
{
    uint32_t i    = 0;
    const char *c = name;

    if (!name || length == 0)
        return 1;

    while (i < length && *c != '\0') {
        if ((*c >= '0' && *c <= '9') ||
            (*c >= 'a' && *c <= 'z') ||
            (*c >= 'A' && *c <= 'Z') ||
            (*c == '_') ||
            (dll && *c == '.')) {

            c++;
            i++;
        } else
            return 0;
    }

    return 1;
}

static inline int hash_impfns(cli_ctx *ctx, void **hashctx, uint32_t *impsz, struct pe_image_import_descriptor *image, const char *dllname, struct cli_exe_info *peinfo, int *first)
{
    uint32_t thuoff = 0, offset;
    fmap_t *map     = ctx->fmap;
    size_t dlllen = 0, fsize = map->len;
    unsigned int err = 0;
    int num_fns = 0, ret = CL_SUCCESS;
    const char *buffer;
    cli_hash_type_t type;
#if HAVE_JSON
    json_object *imptbl = NULL;
#else
    void *imptbl = NULL;
#endif

    if (image->u.OriginalFirstThunk)
        thuoff = cli_rawaddr(image->u.OriginalFirstThunk, peinfo->sections, peinfo->nsections, &err, fsize, peinfo->hdr_size);
    if (err || thuoff == 0)
        thuoff = cli_rawaddr(image->FirstThunk, peinfo->sections, peinfo->nsections, &err, fsize, peinfo->hdr_size);
    if (err) {
        cli_dbgmsg("scan_pe: invalid rva for image first thunk\n");
        return CL_EFORMAT;
    }

#if HAVE_JSON
    if (ctx->wrkproperty) {
        imptbl = cli_jsonarray(ctx->wrkproperty, "ImportTable");
        if (!imptbl) {
            cli_dbgmsg("scan_pe: cannot allocate import table json object\n");
            return CL_EMEM;
        }
    }
#endif

#define UPDATE_IMPHASH()                                                            \
    do {                                                                            \
        if (funcname) {                                                             \
            size_t i, j;                                                            \
            char *fname;                                                            \
            size_t funclen;                                                         \
                                                                                    \
            if (dlllen == 0) {                                                      \
                char *ext = strstr(dllname, ".");                                   \
                                                                                    \
                if (ext && (strncasecmp(ext, ".ocx", 4) == 0 ||                     \
                            strncasecmp(ext, ".sys", 4) == 0 ||                     \
                            strncasecmp(ext, ".dll", 4) == 0))                      \
                    dlllen = ext - dllname;                                         \
                else                                                                \
                    dlllen = strlen(dllname);                                       \
            }                                                                       \
                                                                                    \
            funclen = strlen(funcname);                                             \
            if (validate_impname(funcname, funclen, 1) == 0) {                      \
                cli_dbgmsg("scan_pe: invalid name for imported function\n");        \
                ret = CL_EFORMAT;                                                   \
                break;                                                              \
            }                                                                       \
                                                                                    \
            fname = cli_calloc(funclen + dlllen + 3, sizeof(char));                 \
            if (fname == NULL) {                                                    \
                cli_dbgmsg("scan_pe: cannot allocate memory for imphash string\n"); \
                ret = CL_EMEM;                                                      \
                break;                                                              \
            }                                                                       \
            j = 0;                                                                  \
            if (!*first)                                                            \
                fname[j++] = ',';                                                   \
            for (i = 0; i < dlllen; i++, j++)                                       \
                fname[j] = tolower(dllname[i]);                                     \
            fname[j++] = '.';                                                       \
            for (i = 0; i < funclen; i++, j++)                                      \
                fname[j] = tolower(funcname[i]);                                    \
                                                                                    \
            if (imptbl) {                                                           \
                char *jname = *first ? fname : fname + 1;                           \
                cli_jsonstr(imptbl, NULL, jname);                                   \
            }                                                                       \
                                                                                    \
            for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++)          \
                cl_update_hash(hashctx[type], fname, strlen(fname));                \
            *impsz += strlen(fname);                                                \
                                                                                    \
            *first = 0;                                                             \
            free(fname);                                                            \
        }                                                                           \
    } while (0)

    if (!peinfo->is_pe32plus) {
        struct pe_image_thunk32 thunk32;

        while ((num_fns < PE_MAXIMPORTS) && (fmap_readn(map, &thunk32, thuoff, sizeof(struct pe_image_thunk32)) == sizeof(struct pe_image_thunk32)) && (thunk32.u.Ordinal != 0)) {
            char *funcname = NULL;
            thuoff += sizeof(struct pe_image_thunk32);

            thunk32.u.Ordinal = EC32(thunk32.u.Ordinal);

            if (!(thunk32.u.Ordinal & PE_IMAGEDIR_ORDINAL_FLAG32)) {
                offset = cli_rawaddr(thunk32.u.Function, peinfo->sections, peinfo->nsections, &err, fsize, peinfo->hdr_size);

                if (!ret) {
                    /* Hint field is a uint16_t and precedes the Name field */
                    if ((buffer = fmap_need_off_once(map, offset + sizeof(uint16_t), MIN(PE_MAXNAMESIZE, fsize - offset))) != NULL) {
                        funcname = CLI_STRNDUP(buffer, MIN(PE_MAXNAMESIZE, fsize - offset));
                        if (funcname == NULL) {
                            cli_dbgmsg("scan_pe: cannot duplicate function name\n");
                            return CL_EMEM;
                        }
                    }
                }
            } else {
                /* ordinal lookup */
                funcname = pe_ordinal(dllname, thunk32.u.Ordinal & 0xFFFF);
                if (funcname == NULL) {
                    cli_dbgmsg("scan_pe: cannot duplicate function name\n");
                    return CL_EMEM;
                }
            }

            UPDATE_IMPHASH();
            free(funcname);
            if (ret != CL_SUCCESS)
                return ret;
        }
    } else {
        struct pe_image_thunk64 thunk64;

        while ((num_fns < PE_MAXIMPORTS) && (fmap_readn(map, &thunk64, thuoff, sizeof(struct pe_image_thunk64)) == sizeof(struct pe_image_thunk64)) && (thunk64.u.Ordinal != 0)) {
            char *funcname = NULL;
            thuoff += sizeof(struct pe_image_thunk64);

            thunk64.u.Ordinal = EC64(thunk64.u.Ordinal);

            if (!(thunk64.u.Ordinal & PE_IMAGEDIR_ORDINAL_FLAG64)) {
                offset = cli_rawaddr(thunk64.u.Function, peinfo->sections, peinfo->nsections, &err, fsize, peinfo->hdr_size);

                if (!err) {
                    /* Hint field is a uint16_t and precedes the Name field */
                    if ((buffer = fmap_need_off_once(map, offset + sizeof(uint16_t), MIN(PE_MAXNAMESIZE, fsize - offset))) != NULL) {
                        funcname = CLI_STRNDUP(buffer, MIN(PE_MAXNAMESIZE, fsize - offset));
                        if (funcname == NULL) {
                            cli_dbgmsg("scan_pe: cannot duplicate function name\n");
                            return CL_EMEM;
                        }
                    }
                }
            } else {
                /* ordinal lookup */
                funcname = pe_ordinal(dllname, thunk64.u.Ordinal & 0xFFFF);
                if (funcname == NULL) {
                    cli_dbgmsg("scan_pe: cannot duplicate function name\n");
                    return CL_EMEM;
                }
            }

            UPDATE_IMPHASH();
            free(funcname);
            if (ret != CL_SUCCESS)
                return ret;
        }
    }

    return CL_SUCCESS;
}

static cl_error_t hash_imptbl(cli_ctx *ctx, unsigned char **digest, uint32_t *impsz, int *genhash, struct cli_exe_info *peinfo)
{
    cl_error_t status = CL_ERROR;
    cl_error_t ret;
    struct pe_image_import_descriptor image = {0};
    const struct pe_image_import_descriptor *impdes;
    fmap_t *map = ctx->fmap;
    size_t left, fsize = map->len;
    uint32_t impoff, offset;
    const char *buffer;
    void *hashctx[CLI_HASH_AVAIL_TYPES] = {0};
    cli_hash_type_t type;
    int nimps = 0;
    unsigned int err;
    int first          = 1;
    bool needed_impoff = false;

    /* If the PE doesn't have an import table then skip it. This is an
     * uncommon case but can happen. */
    if (peinfo->dirs[1].VirtualAddress == 0 || peinfo->dirs[1].Size == 0) {
        cli_dbgmsg("scan_pe: import table data dir does not exist (skipping .imp scanning)\n");
        status = CL_BREAK;
        goto done;
    }

    // TODO Add EC32 wrappers
    impoff = cli_rawaddr(peinfo->dirs[1].VirtualAddress, peinfo->sections, peinfo->nsections, &err, fsize, peinfo->hdr_size);
    if (err || impoff + peinfo->dirs[1].Size > fsize) {
        cli_dbgmsg("scan_pe: invalid rva for import table data\n");
        status = CL_BREAK;
        goto done;
    }

    // TODO Add EC32 wrapper
    impdes = (const struct pe_image_import_descriptor *)fmap_need_off(map, impoff, peinfo->dirs[1].Size);
    if (impdes == NULL) {
        cli_dbgmsg("scan_pe: failed to acquire fmap buffer\n");
        status = CL_EREAD;
        goto done;
    }
    needed_impoff = true;

    /* Safety: We can trust peinfo->dirs[1].Size only because `fmap_need_off()` (above)
     * would have failed if the size exceeds the end of the fmap. */
    left = peinfo->dirs[1].Size;

    if (genhash[CLI_HASH_MD5]) {
        hashctx[CLI_HASH_MD5] = cl_hash_init("md5");
        if (hashctx[CLI_HASH_MD5] == NULL) {
            status = CL_EMEM;
            goto done;
        }
    }
    if (genhash[CLI_HASH_SHA1]) {
        hashctx[CLI_HASH_SHA1] = cl_hash_init("sha1");
        if (hashctx[CLI_HASH_SHA1] == NULL) {
            status = CL_EMEM;
            goto done;
        }
    }
    if (genhash[CLI_HASH_SHA256]) {
        hashctx[CLI_HASH_SHA256] = cl_hash_init("sha256");
        if (hashctx[CLI_HASH_SHA256] == NULL) {
            status = CL_EMEM;
            goto done;
        }
    }

    while (left > sizeof(struct pe_image_import_descriptor) && nimps < PE_MAXIMPORTS) {
        char *dllname = NULL;

        /* Get copy of image import descriptor to work with */
        memcpy(&image, impdes, sizeof(struct pe_image_import_descriptor));

        if (image.Name == 0) {
            // Name RVA is 0, which doesn't seem right. I guess we skip the rest?
            // TODO: Is that right?
            break;
        }

        /* Prepare for next iteration, in case we need to `continue;` */
        left -= sizeof(struct pe_image_import_descriptor);
        nimps++;
        impdes++;

        /* Endian Conversion */
        image.u.OriginalFirstThunk = EC32(image.u.OriginalFirstThunk);
        image.TimeDateStamp        = EC32(image.TimeDateStamp);
        image.ForwarderChain       = EC32(image.ForwarderChain);
        image.Name                 = EC32(image.Name);
        image.FirstThunk           = EC32(image.FirstThunk);

        /* DLL name acquisition */
        offset = cli_rawaddr(image.Name, peinfo->sections, peinfo->nsections, &err, fsize, peinfo->hdr_size);
        if (err || offset > fsize) {
            cli_dbgmsg("scan_pe: invalid rva for dll name\n");
            /* TODO: ignore or return? */
            /*
            continue;
             */
            status = CL_EFORMAT;
            goto done;
        }

        buffer = fmap_need_off_once(map, offset, MIN(PE_MAXNAMESIZE, fsize - offset));
        if (buffer == NULL) {
            cli_dbgmsg("scan_pe: failed to read name for dll\n");
            status = CL_EREAD;
            goto done;
        }

        if (validate_impname(dllname, MIN(PE_MAXNAMESIZE, fsize - offset), 1) == 0) {
            cli_dbgmsg("scan_pe: invalid name for imported dll\n");
            status = CL_EFORMAT;
            goto done;
        }

        dllname = CLI_STRNDUP(buffer, MIN(PE_MAXNAMESIZE, fsize - offset));
        if (dllname == NULL) {
            cli_dbgmsg("scan_pe: cannot duplicate dll name\n");
            status = CL_EMEM;
            goto done;
        }

        /* DLL function handling - inline function */
        ret = hash_impfns(ctx, hashctx, impsz, &image, dllname, peinfo, &first);
        free(dllname);
        dllname = NULL;
        if (ret != CL_SUCCESS) {
            status = ret;
            goto done;
        }
    }

    for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
        cl_finish_hash(hashctx[type], digest[type]);
        hashctx[type] = NULL;
    }

    status = CL_SUCCESS;

done:
    if (needed_impoff) {
        fmap_unneed_off(map, impoff, peinfo->dirs[1].Size);
    }

    for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
        if (NULL != hashctx[type]) {
            cl_hash_destroy(hashctx[type]);
        }
    }

    return status;
}

static cl_error_t scan_pe_imp(cli_ctx *ctx, struct cli_exe_info *peinfo)
{
    struct cli_matcher *imp = ctx->engine->hm_imp;
    unsigned char *hashset[CLI_HASH_AVAIL_TYPES];
    const char *virname = NULL;
    int genhash[CLI_HASH_AVAIL_TYPES];
    uint32_t impsz = 0;
    cli_hash_type_t type;
    cl_error_t ret = CL_CLEAN;

    /* pick hashtypes to generate */
    for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
        genhash[type] = cli_hm_have_any(imp, type);
        if (genhash[type]) {
            hashset[type] = cli_malloc(hashlen[type]);
            if (!hashset[type]) {
                cli_errmsg("scan_pe: cli_malloc failed!\n");
                for (; type > 0;)
                    free(hashset[--type]);
                return CL_EMEM;
            }
        } else {
            hashset[type] = NULL;
        }
    }

    /* Force md5 hash generation for debug and preclass */
#if HAVE_JSON
    if ((cli_debug_flag || ctx->wrkproperty) && !genhash[CLI_HASH_MD5]) {
#else
    if (cli_debug_flag && !genhash[CLI_HASH_MD5]) {
#endif
        genhash[CLI_HASH_MD5] = 1;
        hashset[CLI_HASH_MD5] = cli_calloc(hashlen[CLI_HASH_MD5], sizeof(char));
        if (!hashset[CLI_HASH_MD5]) {
            cli_errmsg("scan_pe: cli_malloc failed!\n");
            for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++)
                free(hashset[type]);
            return CL_EMEM;
        }
    }

    /* Generate hashes */
    ret = hash_imptbl(ctx, hashset, &impsz, genhash, peinfo);
    if (ret != CL_SUCCESS) {
        for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
            free(hashset[type]);
        }
        if (ret == CL_BREAK) {
            ret = CL_SUCCESS;
        }
        return ret;
    }

    /* Print hash */
#if HAVE_JSON
    if (cli_debug_flag || ctx->wrkproperty) {
#else
    if (cli_debug_flag) {
#endif
        char *dstr = cli_str2hex((char *)hashset[CLI_HASH_MD5], hashlen[CLI_HASH_MD5]);
        cli_dbgmsg("IMP: %s:%u\n", dstr ? (char *)dstr : "(NULL)", impsz);
#if HAVE_JSON
        if (ctx->wrkproperty)
            cli_jsonstr(ctx->wrkproperty, "Imphash", dstr ? dstr : "(NULL)");
#endif
        if (dstr)
            free(dstr);
    }

    /* Do scans */
    for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
        if (cli_hm_scan(hashset[type], impsz, &virname, imp, type) == CL_VIRUS) {
            ret = cli_append_virus(ctx, virname);
            if (ret != CL_SUCCESS) {
                break;
            }
        }
        if (cli_hm_scan_wild(hashset[type], &virname, imp, type) == CL_VIRUS) {
            cli_append_virus(ctx, virname);
            if (ret != CL_SUCCESS) {
                break;
            }
        }
    }

    for (type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++)
        free(hashset[type]);
    return ret;
}

#if HAVE_JSON
static struct json_object *get_pe_property(cli_ctx *ctx)
{
    struct json_object *pe;

    if (!(ctx) || !(ctx->wrkproperty))
        return NULL;

    if (!json_object_object_get_ex(ctx->wrkproperty, "PE", &pe)) {
        pe = json_object_new_object();
        if (!(pe))
            return NULL;

        json_object_object_add(ctx->wrkproperty, "PE", pe);
    }

    return pe;
}

static void pe_add_heuristic_property(cli_ctx *ctx, const char *key)
{
    struct json_object *heuristics;
    struct json_object *pe;
    struct json_object *str;

    pe = get_pe_property(ctx);
    if (!(pe))
        return;

    if (!json_object_object_get_ex(pe, "Heuristics", &heuristics)) {
        heuristics = json_object_new_array();
        if (!(heuristics))
            return;

        json_object_object_add(pe, "Heuristics", heuristics);
    }

    str = json_object_new_string(key);
    if (!(str))
        return;

    json_object_array_add(heuristics, str);
}

static struct json_object *get_section_json(cli_ctx *ctx)
{
    struct json_object *pe;
    struct json_object *section;

    pe = get_pe_property(ctx);
    if (!(pe))
        return NULL;

    if (!json_object_object_get_ex(pe, "Sections", &section)) {
        section = json_object_new_array();
        if (!(section))
            return NULL;

        json_object_object_add(pe, "Sections", section);
    }

    return section;
}

static void add_section_info(cli_ctx *ctx, struct cli_exe_section *s)
{
    struct json_object *sections, *section, *obj;
    char address[16];

    sections = get_section_json(ctx);
    if (!(sections))
        return;

    section = json_object_new_object();
    if (!(section))
        return;

    obj = json_object_new_int((int32_t)(s->rsz));
    if (!(obj))
        return;

    json_object_object_add(section, "RawSize", obj);

    obj = json_object_new_int((int32_t)(s->raw));
    if (!(obj))
        return;

    json_object_object_add(section, "RawOffset", obj);

    snprintf(address, sizeof(address), "0x%08x", s->rva);

    obj = json_object_new_string(address);
    if (!(obj))
        return;

    json_object_object_add(section, "VirtualAddress", obj);

    obj = json_object_new_boolean((s->chr & 0x20000000) == 0x20000000);
    if ((obj))
        json_object_object_add(section, "Executable", obj);

    obj = json_object_new_boolean((s->chr & 0x80000000) == 0x80000000);
    if ((obj))
        json_object_object_add(section, "Writable", obj);

    obj = json_object_new_boolean(s->urva >> 31 || s->uvsz >> 31 || (s->rsz && s->uraw >> 31) || s->ursz >> 31);
    if ((obj))
        json_object_object_add(section, "Signed", obj);

    json_object_array_add(sections, section);
}
#endif

int cli_scanpe(cli_ctx *ctx)
{
    uint8_t polipos = 0;
    char epbuff[4096], *tempfile;
    size_t epsize;
    size_t bytes;
    unsigned int i, j, found, upx_success = 0, err;
    unsigned int ssize = 0, dsize = 0, corrupted_cur;
    int (*upxfn)(const char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t) = NULL;
    const char *src                                                                        = NULL;
    char *dest                                                                             = NULL;
    int ndesc;
    cl_error_t ret = CL_SUCCESS;
    cl_error_t peheader_ret;
    int upack = 0;
    size_t fsize;
    struct cli_bc_ctx *bc_ctx;
    fmap_t *map;
    struct cli_pe_hook_data pedata;
#ifdef HAVE__INTERNAL__SHA_COLLECT
    int sha_collect = ctx->sha_collect;
#endif
#if HAVE_JSON
    int toval                   = 0;
    struct json_object *pe_json = NULL;
#endif

    if (!ctx) {
        cli_errmsg("cli_scanpe: ctx == NULL\n");
        return CL_ENULLARG;
    }

#if HAVE_JSON
    if (cli_json_timeout_cycle_check(ctx, &toval) != CL_SUCCESS) {
        return CL_ETIMEOUT;
    }

    if (SCAN_COLLECT_METADATA) {
        pe_json = get_pe_property(ctx);
    }
#endif
    map   = ctx->fmap;
    fsize = map->len;

    struct cli_exe_info _peinfo;
    struct cli_exe_info *peinfo = &_peinfo;

    uint32_t opts = CLI_PEHEADER_OPT_DBG_PRINT_INFO | CLI_PEHEADER_OPT_REMOVE_MISSING_SECTIONS;

#if HAVE_JSON
    if (SCAN_COLLECT_METADATA) {
        opts |= CLI_PEHEADER_OPT_COLLECT_JSON;
    }
#endif

    if (DETECT_BROKEN_PE) {
        opts |= CLI_PEHEADER_OPT_STRICT_ON_PE_ERRORS;
    }

    cli_exe_info_init(peinfo, 0);

    peheader_ret = cli_peheader(map, peinfo, opts, ctx);

    // Warn the user if PE header parsing failed - if it's a binary that runs
    // successfully on Windows, we need to relax our PE parsing standards so
    // that we make sure the executable gets scanned appropriately

    switch (peheader_ret) {
        case CL_EFORMAT:
            ret = CL_SUCCESS;
            if (DETECT_BROKEN_PE) {
                ret = cli_append_potentially_unwanted(ctx, "Heuristics.Broken.Executable");
            }
            cli_dbgmsg("cli_scanpe: PE header appears broken - won't attempt .mdb / .imp / PE-specific BC rule matching or exe unpacking\n");
            cli_exe_info_destroy(peinfo);
            return ret;

        case CL_ERROR:
            ret = CL_SUCCESS;
            cli_dbgmsg("cli_scanpe: An error occurred when parsing the PE header - won't attempt .mdb / .imp / PE-specific BC rule matching or exe unpacking\n");
            cli_exe_info_destroy(peinfo);
            return ret;

        case CL_ETIMEOUT:
            ret = CL_ETIMEOUT;
            cli_dbgmsg("cli_scanpe: JSON creation timed out - won't attempt .mdb / .imp / PE-specific BC rule matching or exe unpacking\n");
            cli_exe_info_destroy(peinfo);
            return ret;

        default:
            break;
    }

    if (!peinfo->is_pe32plus) { /* PE */
        if (DCONF & PE_CONF_UPACK) {
            upack = (EC16(peinfo->file_hdr.SizeOfOptionalHeader) == 0x148);
        }
    }

    for (i = 0; i < peinfo->nsections; i++) {
        if (peinfo->sections[i].rsz) { /* Don't bother with virtual only sections */
            // TODO Regarding the commented out check below:
            // This used to check that the section name was NULL, but now that
            // header parsing is done in cli_peheader (and since we don't yet
            // make the section name availabe via peinfo->sections[]) it would
            // be a pain to fetch the name here.  Since this is the only place
            // in cli_scanpe that needs the section name, and since I verified
            // that detection still occurs for Polipos without this check,
            // let's leave it commented out for now.
            if (SCAN_HEURISTICS && (DCONF & PE_CONF_POLIPOS) && /*!*peinfo->sections[i].sname &&*/ peinfo->sections[i].vsz > 40000 && peinfo->sections[i].vsz < 70000 && peinfo->sections[i].chr == 0xe0000060) polipos = i;

            /* check hash section sigs */
            if ((DCONF & PE_CONF_MD5SECT) && ctx->engine->hm_mdb) {
                ret = scan_pe_mdb(ctx, &(peinfo->sections[i]));
                if (ret != CL_SUCCESS) {
                    if (ret != CL_VIRUS) {
                        cli_errmsg("cli_scanpe: scan_pe_mdb failed: %s!\n", cl_strerror(ret));
                    }
                    cli_dbgmsg("------------------------------------\n");
                    cli_exe_info_destroy(peinfo);
                    return ret;
                }
            }
        }
    }

    // TODO Don't bail out here
    if (peinfo->is_pe32plus) { /* Do not continue for PE32+ files */
        cli_exe_info_destroy(peinfo);
        return CL_CLEAN;
    }

    epsize = fmap_readn(map, epbuff, peinfo->ep, 4096);
    if ((size_t)-1 == epsize) {
        /* Do not continue, all future logic requires at least a partial read into epbuff */
        cli_exe_info_destroy(peinfo);
        return CL_CLEAN;
    }

    /* Disasm scan disabled since it's now handled by the bytecode */

    /* CLI_UNPTEMP("cli_scanpe: DISASM",(peinfo->sections,0)); */
    /* if(disasmbuf((unsigned char*)epbuff, epsize, ndesc)) */
    /*  ret = cli_scan_desc(ndesc, ctx, CL_TYPE_PE_DISASM, true, NULL, AC_SCAN_VIR); */
    /* close(ndesc); */
    /* if(ret == CL_VIRUS) { */
    /*  cli_exe_info_destroy(peinfo); */
    /*  CLI_TMPUNLK(); */
    /*  free(tempfile); */
    /*  return ret; */
    /* } */
    /* CLI_TMPUNLK(); */
    /* free(tempfile); */

    if (peinfo->overlay_start && peinfo->overlay_size > 0) {
        ret = cli_scanishield(ctx, peinfo->overlay_start, peinfo->overlay_size);
        if (ret != CL_SUCCESS) {
            cli_exe_info_destroy(peinfo);
            return ret;
        }
    }

    pedata.nsections = peinfo->nsections;
    pedata.ep        = peinfo->ep;
    pedata.offset    = 0;
    memcpy(&pedata.file_hdr, &(peinfo->file_hdr), sizeof(peinfo->file_hdr));
    // TODO no need to copy both of these for each binary
    memcpy(&pedata.opt32, &(peinfo->pe_opt.opt32), sizeof(peinfo->pe_opt.opt32));
    memcpy(&pedata.opt64, &(peinfo->pe_opt.opt64), sizeof(peinfo->pe_opt.opt64));
    memcpy(&pedata.dirs, &(peinfo->dirs), sizeof(peinfo->dirs));
    // Gross
    memcpy(&pedata.opt32_dirs, &(peinfo->dirs), sizeof(peinfo->dirs));
    memcpy(&pedata.opt64_dirs, &(peinfo->dirs), sizeof(peinfo->dirs));
    pedata.e_lfanew    = peinfo->e_lfanew;
    pedata.overlays    = peinfo->overlay_start;
    pedata.overlays_sz = peinfo->overlay_size;
    pedata.hdr_size    = peinfo->hdr_size;

    /* Bytecode BC_PE_ALL hook */
    bc_ctx = cli_bytecode_context_alloc();
    if (!bc_ctx) {
        cli_errmsg("cli_scanpe: can't allocate memory for bc_ctx\n");
        cli_exe_info_destroy(peinfo);
        return CL_EMEM;
    }

    cli_bytecode_context_setpe(bc_ctx, &pedata, peinfo->sections);
    cli_bytecode_context_setctx(bc_ctx, ctx);
    ret = cli_bytecode_runhook(ctx, ctx->engine, bc_ctx, BC_PE_ALL, map);
    switch (ret) {
        case CL_ENULLARG:
            cli_warnmsg("cli_scanpe: NULL argument supplied\n");
            break;
        case CL_VIRUS:
        case CL_BREAK:
            cli_exe_info_destroy(peinfo);
            cli_bytecode_context_destroy(bc_ctx);
            return ret == CL_VIRUS ? CL_VIRUS : CL_CLEAN;
        default:
            break;
    }
    cli_bytecode_context_destroy(bc_ctx);

    /* Attempt to run scans on import table */
    /* Run if there are existing signatures and/or preclassing */
#if HAVE_JSON
    if (DCONF & PE_CONF_IMPTBL && (ctx->engine->hm_imp || ctx->wrkproperty)) {
#else
    if (DCONF & PE_CONF_IMPTBL && ctx->engine->hm_imp) {
#endif
        ret = scan_pe_imp(ctx, peinfo);
        switch (ret) {
            case CL_SUCCESS:
                break;
            case CL_ENULLARG:
                cli_warnmsg("cli_scanpe: NULL argument supplied\n");
                break;
            case CL_VIRUS:
            case CL_BREAK:
                cli_exe_info_destroy(peinfo);
                return ret == CL_VIRUS ? CL_VIRUS : CL_CLEAN;
            default:
                cli_exe_info_destroy(peinfo);
                return ret;
        }
    }
    /* Attempt to detect some popular polymorphic viruses */

    /* W32.Parite.B */
    if (SCAN_HEURISTICS && (DCONF & PE_CONF_PARITE) && !peinfo->is_dll && epsize == 4096 && peinfo->ep == peinfo->sections[peinfo->nsections - 1].raw) {
        const char *pt = cli_memstr(epbuff, 4040, "\x47\x65\x74\x50\x72\x6f\x63\x41\x64\x64\x72\x65\x73\x73\x00", 15);
        if (pt) {
            pt += 15;
            if ((((uint32_t)cli_readint32(pt) ^ (uint32_t)cli_readint32(pt + 4)) == 0x505a4f) && (((uint32_t)cli_readint32(pt + 8) ^ (uint32_t)cli_readint32(pt + 12)) == 0xffffb) && (((uint32_t)cli_readint32(pt + 16) ^ (uint32_t)cli_readint32(pt + 20)) == 0xb8)) {
                ret = cli_append_potentially_unwanted(ctx, "Heuristics.W32.Parite.B");
                if (ret != CL_SUCCESS) {
                    cli_exe_info_destroy(peinfo);
                    return ret;
                }
            }
        }
    }

    /* Kriz */
    if (SCAN_HEURISTICS && (DCONF & PE_CONF_KRIZ) && epsize >= 200 && CLI_ISCONTAINED(peinfo->sections[peinfo->nsections - 1].raw, peinfo->sections[peinfo->nsections - 1].rsz, peinfo->ep, 0x0fd2) && epbuff[1] == '\x9c' && epbuff[2] == '\x60') {
        enum { KZSTRASH,
               KZSCDELTA,
               KZSPDELTA,
               KZSGETSIZE,
               KZSXORPRFX,
               KZSXOR,
               KZSDDELTA,
               KZSLOOP,
               KZSTOP };
        uint8_t kzs[]    = {KZSTRASH, KZSCDELTA, KZSPDELTA, KZSGETSIZE, KZSTRASH, KZSXORPRFX, KZSXOR, KZSTRASH, KZSDDELTA, KZSTRASH, KZSLOOP, KZSTOP};
        uint8_t *kzstate = kzs;
        uint8_t *kzcode  = (uint8_t *)epbuff + 3;
        uint8_t kzdptr = 0xff, kzdsize = 0xff;
        int kzlen = 197, kzinitlen = 0xffff, kzxorlen = -1;
        cli_dbgmsg("cli_scanpe: in kriz\n");

        while (*kzstate != KZSTOP) {
            uint8_t op;
            if (kzlen <= 6)
                break;

            op = *kzcode++;
            kzlen--;

            switch (*kzstate) {
                case KZSTRASH:
                case KZSGETSIZE: {
                    int opsz = 0;
                    switch (op) {
                        case 0x81:
                            kzcode += 5;
                            kzlen -= 5;
                            break;
                        case 0xb8:
                        case 0xb9:
                        case 0xba:
                        case 0xbb:
                        case 0xbd:
                        case 0xbe:
                        case 0xbf:
                            if (*kzstate == KZSGETSIZE && cli_readint32(kzcode) == 0x0fd2) {
                                kzinitlen = kzlen - 5;
                                kzdsize   = op - 0xb8;
                                kzstate++;
                                op = 4; /* fake the register to avoid breaking out */

                                cli_dbgmsg("cli_scanpe: kriz: using #%d as size counter\n", kzdsize);
                            }
                            opsz = 4;
                            /* fall-through */
                        case 0x48:
                        case 0x49:
                        case 0x4a:
                        case 0x4b:
                        case 0x4d:
                        case 0x4e:
                        case 0x4f:
                            op &= 7;
                            if (op != kzdptr && op != kzdsize) {
                                kzcode += opsz;
                                kzlen -= opsz;
                                break;
                            }
                            /* fall-through */
                        default:
                            kzcode--;
                            kzlen++;
                            kzstate++;
                    }

                    break;
                }
                case KZSCDELTA:
                    if (op == 0xe8 && (uint32_t)cli_readint32(kzcode) < 0xff) {
                        kzlen -= *kzcode + 4;
                        kzcode += *kzcode + 4;
                        kzstate++;
                    } else {
                        *kzstate = KZSTOP;
                    }

                    break;
                case KZSPDELTA:
                    if ((op & 0xf8) == 0x58 && (kzdptr = op - 0x58) != 4) {
                        kzstate++;
                        cli_dbgmsg("cli_scanpe: kriz: using #%d as pointer\n", kzdptr);
                    } else {
                        *kzstate = KZSTOP;
                    }

                    break;
                case KZSXORPRFX:
                    kzstate++;
                    if (op == 0x3e) {
                        break;
                    }
                    /* fall-through */
                case KZSXOR:
                    if (op == 0x80 && *kzcode == kzdptr + 0xb0) {
                        kzxorlen = kzlen;
                        kzcode += +6;
                        kzlen -= +6;
                        kzstate++;
                    } else {
                        *kzstate = KZSTOP;
                    }

                    break;
                case KZSDDELTA:
                    if (op == kzdptr + 0x48)
                        kzstate++;
                    else
                        *kzstate = KZSTOP;

                    break;
                case KZSLOOP:
                    if (op == kzdsize + 0x48 && *kzcode == 0x75 && kzlen - (int8_t)kzcode[1] - 3 <= kzinitlen && kzlen - (int8_t)kzcode[1] >= kzxorlen) {
                        ret = cli_append_potentially_unwanted(ctx, "Heuristics.W32.Kriz");
                        if (ret != CL_SUCCESS) {
                            cli_exe_info_destroy(peinfo);
                            return ret;
                        }
                    }
                    cli_dbgmsg("cli_scanpe: kriz: loop out of bounds, corrupted sample?\n");
                    kzstate++;
            }
        }
    }

    /* W32.Magistr.A/B */
    if (SCAN_HEURISTICS && (DCONF & PE_CONF_MAGISTR) && !peinfo->is_dll && (peinfo->nsections > 1) && (peinfo->sections[peinfo->nsections - 1].chr & 0x80000000)) {
        uint32_t rsize, vsize, dam = 0;

        vsize = peinfo->sections[peinfo->nsections - 1].uvsz;
        rsize = peinfo->sections[peinfo->nsections - 1].rsz;
        if (rsize < peinfo->sections[peinfo->nsections - 1].ursz) {
            rsize = peinfo->sections[peinfo->nsections - 1].ursz;
            dam   = 1;
        }

        if (vsize >= 0x612c && rsize >= 0x612c && ((vsize & 0xff) == 0xec)) {
            int bw = rsize < 0x7000 ? rsize : 0x7000;
            const char *tbuff;

            if ((tbuff = fmap_need_off_once(map, peinfo->sections[peinfo->nsections - 1].raw + rsize - bw, 4096))) {
                if (cli_memstr(tbuff, 4091, "\xe8\x2c\x61\x00\x00", 5)) {
                    ret = cli_append_potentially_unwanted(ctx, dam ? "Heuristics.W32.Magistr.A.dam" : "Heuristics.W32.Magistr.A");
                    if (ret != CL_SUCCESS) {
                        cli_exe_info_destroy(peinfo);
                        return ret;
                    }
                }
            }
        } else if (rsize >= 0x7000 && vsize >= 0x7000 && ((vsize & 0xff) == 0xed)) {
            int bw = rsize < 0x8000 ? rsize : 0x8000;
            const char *tbuff;

            if ((tbuff = fmap_need_off_once(map, peinfo->sections[peinfo->nsections - 1].raw + rsize - bw, 4096))) {
                if (cli_memstr(tbuff, 4091, "\xe8\x04\x72\x00\x00", 5)) {
                    ret = cli_append_potentially_unwanted(ctx, dam ? "Heuristics.W32.Magistr.B.dam" : "Heuristics.W32.Magistr.B");
                    if (ret != CL_SUCCESS) {
                        cli_exe_info_destroy(peinfo);
                        return ret;
                    }
                }
            }
        }
    }

    /* W32.Polipos.A */
    // TODO Add endianness correction to SizeOfStackReserve access
    while (polipos && !peinfo->is_dll && peinfo->nsections > 2 && peinfo->nsections < 13 && peinfo->e_lfanew <= 0x800 && (EC16(peinfo->pe_opt.opt32.Subsystem) == 2 || EC16(peinfo->pe_opt.opt32.Subsystem) == 3) && EC16(peinfo->file_hdr.Machine) == 0x14c && peinfo->pe_opt.opt32.SizeOfStackReserve >= 0x80000) {
        uint32_t jump, jold, *jumps = NULL;
        const uint8_t *code;
        unsigned int xsjs = 0;

        if (peinfo->sections[0].rsz > CLI_MAX_ALLOCATION)
            break;
        if (peinfo->sections[0].rsz < 5)
            break;
        if (!(code = fmap_need_off_once(map, peinfo->sections[0].raw, peinfo->sections[0].rsz)))
            break;

        for (i = 0; i < peinfo->sections[0].rsz - 5; i++) {
            if ((uint8_t)(code[i] - 0xe8) > 1)
                continue;

            jump = cli_rawaddr(peinfo->sections[0].rva + i + 5 + cli_readint32(&code[i + 1]), peinfo->sections, peinfo->nsections, &err, fsize, peinfo->hdr_size);
            if (err || !CLI_ISCONTAINED(peinfo->sections[polipos].raw, peinfo->sections[polipos].rsz, jump, 9))
                continue;

            if (xsjs % 128 == 0) {
                if (xsjs == 1280)
                    break;

                if (!(jumps = (uint32_t *)cli_realloc2(jumps, (xsjs + 128) * sizeof(uint32_t)))) {
                    cli_exe_info_destroy(peinfo);
                    return CL_EMEM;
                }
            }

            j = 0;
            for (; j < xsjs; j++) {
                if (jumps[j] < jump)
                    continue;
                if (jumps[j] == jump) {
                    xsjs--;
                    break;
                }

                jold     = jumps[j];
                jumps[j] = jump;
                jump     = jold;
            }

            jumps[j] = jump;
            xsjs++;
        }

        if (!xsjs)
            break;

        cli_dbgmsg("cli_scanpe: Polipos: Checking %d xsect jump(s)\n", xsjs);
        for (i = 0; i < xsjs; i++) {
            if (!(code = fmap_need_off_once(map, jumps[i], 9)))
                continue;

            if ((jump = cli_readint32(code)) == 0x60ec8b55 || (code[4] == 0x0ec && ((jump == 0x83ec8b55 && code[6] == 0x60) || (jump == 0x81ec8b55 && !code[7] && !code[8])))) {
                ret = cli_append_potentially_unwanted(ctx, "Heuristics.W32.Polipos.A");
                if (ret != CL_SUCCESS) {
                    free(jumps);
                    cli_exe_info_destroy(peinfo);
                    return ret;
                }
            }
        }

        free(jumps);
        break;
    }

    /* Trojan.Swizzor.Gen */
    if (SCAN_HEURISTICS && (DCONF & PE_CONF_SWIZZOR) && peinfo->nsections > 1 && fsize > 64 * 1024 && fsize < 4 * 1024 * 1024) {
        if (peinfo->dirs[2].Size) {
            struct swizz_stats *stats = cli_calloc(1, sizeof(*stats));
            unsigned int m            = 1000;
            ret                       = CL_CLEAN;

            if (!stats) {
                cli_exe_info_destroy(peinfo);
                return CL_EMEM;
            } else {
                cli_parseres_special(EC32(peinfo->dirs[2].VirtualAddress), EC32(peinfo->dirs[2].VirtualAddress), map, peinfo, fsize, 0, 0, &m, stats);
                if ((ret = cli_detect_swizz(stats)) == CL_VIRUS) {
                    ret = cli_append_potentially_unwanted(ctx, "Heuristics.Trojan.Swizzor.Gen");
                    if (ret != CL_SUCCESS) {
                        free(stats);
                        cli_exe_info_destroy(peinfo);
                        return ret;
                    }
                }
            }
        }
    }

    /* !!!!!!!!!!!!!!    PACKERS START HERE    !!!!!!!!!!!!!! */
    corrupted_cur        = ctx->corrupted_input;
    ctx->corrupted_input = 2; /* caller will reset on return */

    /* UPX, FSG, MEW support */

    /* try to find the first section with physical size == 0 */
    found = 0;
    if (DCONF & (PE_CONF_UPX | PE_CONF_FSG | PE_CONF_MEW)) {
        for (i = 0; i < (unsigned int)peinfo->nsections - 1; i++) {
            if (!peinfo->sections[i].rsz && peinfo->sections[i].vsz && peinfo->sections[i + 1].rsz && peinfo->sections[i + 1].vsz) {
                found = 1;
                cli_dbgmsg("cli_scanpe: UPX/FSG/MEW: empty section found - assuming compression\n");
#if HAVE_JSON
                if (pe_json != NULL)
                    cli_jsonbool(pe_json, "HasEmptySection", 1);
#endif
                break;
            }
        }
    }

    /* MEW support */
    if (found && (DCONF & PE_CONF_MEW) && epsize >= 16 && epbuff[0] == '\xe9') {
        uint32_t fileoffset;
        const char *tbuff;

        // TODO shouldn't peinfo->ep be used here instead?  ep is the file
        // offset, vep is the entry point RVA
        fileoffset = (peinfo->vep + cli_readint32(epbuff + 1) + 5);
        while (fileoffset == 0x154 || fileoffset == 0x158) {
            char *src;
            uint32_t offdiff, uselzma;

            cli_dbgmsg("cli_scanpe: MEW: found MEW characteristics %08X + %08X + 5 = %08X\n",
                       cli_readint32(epbuff + 1), peinfo->vep, cli_readint32(epbuff + 1) + peinfo->vep + 5);

            if (!(tbuff = fmap_need_off_once(map, fileoffset, 0xb0)))
                break;

            if (fileoffset == 0x154)
                cli_dbgmsg("cli_scanpe: MEW: Win9x compatibility was set!\n");
            else
                cli_dbgmsg("cli_scanpe: MEW: Win9x compatibility was NOT set!\n");

            offdiff = cli_readint32(tbuff + 1) - EC32(peinfo->pe_opt.opt32.ImageBase);
            if ((offdiff <= peinfo->sections[i + 1].rva) ||
                (offdiff >= peinfo->sections[i + 1].rva + peinfo->sections[i + 1].raw - 4)) {
                cli_dbgmsg("cli_scanpe: MEW: ESI is not in proper section\n");
                break;
            }

            offdiff -= peinfo->sections[i + 1].rva;

            if (!peinfo->sections[i + 1].rsz) {
                cli_dbgmsg("cli_scanpe: MEW: mew section is empty\n");
                break;
            }

            ssize = peinfo->sections[i + 1].vsz;
            dsize = peinfo->sections[i].vsz;

            /* Guard against integer overflow */
            if ((ssize + dsize < ssize) || (ssize + dsize < dsize)) {
                cli_dbgmsg("cli_scanpe: MEW: section size (%08x) + diff size (%08x) exceeds max size of unsigned int (%08x)\n", ssize, dsize, UINT32_MAX);
                break;
            }

            /* Verify that offdiff does not exceed the ssize + sdiff */
            if (offdiff >= ssize + dsize) {
                cli_dbgmsg("cli_scanpe: MEW: offdiff (%08x) exceeds section size + diff size (%08x)\n", offdiff, ssize + dsize);
                break;
            }

            cli_dbgmsg("cli_scanpe: MEW: ssize %08x dsize %08x offdiff: %08x\n", ssize, dsize, offdiff);

            CLI_UNPSIZELIMITS("cli_scanpe: MEW", MAX(ssize, dsize));
            CLI_UNPSIZELIMITS("cli_scanpe: MEW", MAX(ssize + dsize, peinfo->sections[i + 1].rsz));

            if (peinfo->sections[i + 1].rsz < offdiff + 12 || peinfo->sections[i + 1].rsz > ssize) {
                cli_dbgmsg("cli_scanpe: MEW: Size mismatch: %08x\n", peinfo->sections[i + 1].rsz);
                break;
            }

            /* allocate needed buffer */
            if (!(src = cli_calloc(ssize + dsize, sizeof(char)))) {
                cli_exe_info_destroy(peinfo);
                return CL_EMEM;
            }

            bytes = fmap_readn(map, src + dsize, peinfo->sections[i + 1].raw, peinfo->sections[i + 1].rsz);
            if (bytes != peinfo->sections[i + 1].rsz) {
                cli_dbgmsg("cli_scanpe: MEW: Can't read %u bytes [read: %zu]\n", peinfo->sections[i + 1].rsz, bytes);
                cli_exe_info_destroy(peinfo);
                free(src);
                return CL_EREAD;
            }

            cli_dbgmsg("cli_scanpe: MEW: %zu (%08zx) bytes read\n", bytes, bytes);

            /* count offset to lzma proc, if lzma used, 0xe8 -> call */
            if (tbuff[0x7b] == '\xe8') {
                if (!CLI_ISCONTAINED(peinfo->sections[1].rva, peinfo->sections[1].vsz, cli_readint32(tbuff + 0x7c) + fileoffset + 0x80, 4)) {
                    cli_dbgmsg("cli_scanpe: MEW: lzma proc out of bounds!\n");
                    free(src);
                    break; /* to next unpacker in chain */
                }

                uselzma = cli_readint32(tbuff + 0x7c) - (peinfo->sections[0].rva - fileoffset - 0x80);
            } else {
                uselzma = 0;
            }

#if HAVE_JSON
            if (pe_json != NULL)
                cli_jsonstr(pe_json, "Packer", "MEW");
#endif

            CLI_UNPTEMP("cli_scanpe: MEW", (src, 0));
            CLI_UNPRESULTS("cli_scanpe: MEW", (unmew11(src, offdiff, ssize, dsize, EC32(peinfo->pe_opt.opt32.ImageBase), peinfo->sections[0].rva, uselzma, ndesc)), 1, (src, 0));
            break;
        }
    }

    // TODO Why do we bail here
    if (epsize < 168) {
        cli_exe_info_destroy(peinfo);
        return CL_CLEAN;
    }

    if (found || upack) {
        /* Check EP for UPX vs. FSG vs. Upack */

        /* Upack 0.39 produces 2 types of executables
         * 3 sections:           | 2 sections (one empty, I don't check found if !upack, since it's in OR above):
         *   mov esi, value      |   pusha
         *   lodsd               |   call $+0x9
         *   push eax            |
         *
         * Upack 1.1/1.2 Beta produces [based on 2 samples (sUx) provided by aCaB]:
         * 2 sections
         *   mov esi, value
         *   loads
         *   mov edi, eax
         *
         * Upack unknown [sample 0297729]
         * 3 sections
         *   mov esi, value
         *   push [esi]
         *   jmp
         *
         */
        /* upack 0.39-3s + sample 0151477*/
        while (((upack && peinfo->nsections == 3) && /* 3 sections */
                ((
                     epbuff[0] == '\xbe' && cli_readint32(epbuff + 1) - EC32(peinfo->pe_opt.opt32.ImageBase) > peinfo->min && /* mov esi */
                     epbuff[5] == '\xad' && epbuff[6] == '\x50'                                                               /* lodsd; push eax */
                     ) ||
                 /* based on 0297729 sample from aCaB */
                 (epbuff[0] == '\xbe' && cli_readint32(epbuff + 1) - EC32(peinfo->pe_opt.opt32.ImageBase) > peinfo->min && /* mov esi */
                  epbuff[5] == '\xff' && epbuff[6] == '\x36'                                                               /* push [esi] */
                  ))) ||
               ((!upack && peinfo->nsections == 2) &&                                            /* 2 sections */
                ((                                                                               /* upack 0.39-2s */
                  epbuff[0] == '\x60' && epbuff[1] == '\xe8' && cli_readint32(epbuff + 2) == 0x9 /* pusha; call+9 */
                  ) ||
                 (                                                                                                         /* upack 1.1/1.2, based on 2 samples */
                  epbuff[0] == '\xbe' && cli_readint32(epbuff + 1) - EC32(peinfo->pe_opt.opt32.ImageBase) < peinfo->min && /* mov esi */
                  cli_readint32(epbuff + 1) > EC32(peinfo->pe_opt.opt32.ImageBase) &&
                  epbuff[5] == '\xad' && epbuff[6] == '\x8b' && epbuff[7] == '\xf8' /* loads;  mov edi, eax */
                  )))) {
            uint32_t vma, off;
            int a, b, c;

            cli_dbgmsg("cli_scanpe: Upack characteristics found.\n");
            a = peinfo->sections[0].vsz;
            b = peinfo->sections[1].vsz;
            if (upack) {
                cli_dbgmsg("cli_scanpe: Upack: var set\n");

                c     = peinfo->sections[2].vsz;
                ssize = peinfo->sections[0].ursz + peinfo->sections[0].uraw;
                off   = peinfo->sections[0].rva;
                vma   = EC32(peinfo->pe_opt.opt32.ImageBase) + peinfo->sections[0].rva;
            } else {
                cli_dbgmsg("cli_scanpe: Upack: var NOT set\n");
                c     = peinfo->sections[1].rva;
                ssize = peinfo->sections[1].uraw;
                off   = 0;
                vma   = peinfo->sections[1].rva - peinfo->sections[1].uraw;
            }

            dsize = a + b + c;

            CLI_UNPSIZELIMITS("cli_scanpe: Upack", MAX(MAX(dsize, ssize), peinfo->sections[1].ursz));

            if (!CLI_ISCONTAINED_0_TO(dsize, peinfo->sections[1].rva - off, peinfo->sections[1].ursz) || (upack && !CLI_ISCONTAINED_0_TO(dsize, peinfo->sections[2].rva - peinfo->sections[0].rva, ssize)) || ssize > dsize) {
                cli_dbgmsg("cli_scanpe: Upack: probably malformed pe-header, skipping to next unpacker\n");
                break;
            }

            if ((dest = (char *)cli_calloc(dsize, sizeof(char))) == NULL) {
                cli_exe_info_destroy(peinfo);
                return CL_EMEM;
            }

            if (fmap_readn(map, dest, 0, ssize) != ssize) {
                cli_dbgmsg("cli_scanpe: Upack: Can't read raw data of section 0\n");
                free(dest);
                break;
            }

            if (upack)
                memmove(dest + peinfo->sections[2].rva - peinfo->sections[0].rva, dest, ssize);

            if (fmap_readn(map, dest + peinfo->sections[1].rva - off, peinfo->sections[1].uraw, peinfo->sections[1].ursz) != peinfo->sections[1].ursz) {
                cli_dbgmsg("cli_scanpe: Upack: Can't read raw data of section 1\n");
                free(dest);
                break;
            }

#if HAVE_JSON
            if (pe_json != NULL)
                cli_jsonstr(pe_json, "Packer", "Upack");
#endif

            CLI_UNPTEMP("cli_scanpe: Upack", (dest, 0));
            CLI_UNPRESULTS("cli_scanpe: Upack", (unupack(upack, dest, dsize, epbuff, vma, peinfo->ep, EC32(peinfo->pe_opt.opt32.ImageBase), peinfo->sections[0].rva, ndesc)), 1, (dest, 0));

            break;
        }
    }

    while (found && (DCONF & PE_CONF_FSG) && epbuff[0] == '\x87' && epbuff[1] == '\x25') {
        const char *dst;
        uint32_t newesi, newedi, newebx, newedx;

        /* FSG v2.0 support - thanks to aCaB ! */

        ssize = peinfo->sections[i + 1].rsz;
        dsize = peinfo->sections[i].vsz;

        CLI_UNPSIZELIMITS("cli_scanpe: FSG", MAX(dsize, ssize));

        if (ssize <= 0x19 || dsize <= ssize) {
            cli_dbgmsg("cli_scanpe: FSG: Size mismatch (ssize: %d, dsize: %d)\n", ssize, dsize);
            cli_exe_info_destroy(peinfo);
            return CL_CLEAN;
        }

        newedx = cli_readint32(epbuff + 2) - EC32(peinfo->pe_opt.opt32.ImageBase);
        if (!CLI_ISCONTAINED(peinfo->sections[i + 1].rva, peinfo->sections[i + 1].rsz, newedx, 4)) {
            cli_dbgmsg("cli_scanpe: FSG: xchg out of bounds (%x), giving up\n", newedx);
            break;
        }

        if (!peinfo->sections[i + 1].rsz || !(src = fmap_need_off_once(map, peinfo->sections[i + 1].raw, ssize))) {
            cli_dbgmsg("cli_scanpe: Can't read raw data of section %d\n", i + 1);
            cli_exe_info_destroy(peinfo);
            return CL_ESEEK;
        }

        dst = src + newedx - peinfo->sections[i + 1].rva;
        if (newedx < peinfo->sections[i + 1].rva || !CLI_ISCONTAINED(src, ssize, dst, 4)) {
            cli_dbgmsg("cli_scanpe: FSG: New ESP out of bounds\n");
            break;
        }

        newedx = cli_readint32(dst) - EC32(peinfo->pe_opt.opt32.ImageBase);
        if (!CLI_ISCONTAINED(peinfo->sections[i + 1].rva, peinfo->sections[i + 1].rsz, newedx, 4)) {
            cli_dbgmsg("cli_scanpe: FSG: New ESP (%x) is wrong\n", newedx);
            break;
        }

        dst = src + newedx - peinfo->sections[i + 1].rva;
        if (!CLI_ISCONTAINED(src, ssize, dst, 32)) {
            cli_dbgmsg("cli_scanpe: FSG: New stack out of bounds\n");
            break;
        }

        newedi = cli_readint32(dst) - EC32(peinfo->pe_opt.opt32.ImageBase);
        newesi = cli_readint32(dst + 4) - EC32(peinfo->pe_opt.opt32.ImageBase);
        newebx = cli_readint32(dst + 16) - EC32(peinfo->pe_opt.opt32.ImageBase);
        newedx = cli_readint32(dst + 20);

        if (newedi != peinfo->sections[i].rva) {
            cli_dbgmsg("cli_scanpe: FSG: Bad destination buffer (edi is %x should be %x)\n", newedi, peinfo->sections[i].rva);
            break;
        }

        if (newesi < peinfo->sections[i + 1].rva || newesi - peinfo->sections[i + 1].rva >= peinfo->sections[i + 1].rsz) {
            cli_dbgmsg("cli_scanpe: FSG: Source buffer out of section bounds\n");
            break;
        }

        if (!CLI_ISCONTAINED(peinfo->sections[i + 1].rva, peinfo->sections[i + 1].rsz, newebx, 16)) {
            cli_dbgmsg("cli_scanpe: FSG: Array of functions out of bounds\n");
            break;
        }

        newedx = cli_readint32(newebx + 12 - peinfo->sections[i + 1].rva + src) - EC32(peinfo->pe_opt.opt32.ImageBase);
        cli_dbgmsg("cli_scanpe: FSG: found old EP @%x\n", newedx);

        if ((dest = (char *)cli_calloc(dsize, sizeof(char))) == NULL) {
            cli_exe_info_destroy(peinfo);
            return CL_EMEM;
        }

#if HAVE_JSON
        if (pe_json != NULL)
            cli_jsonstr(pe_json, "Packer", "FSG");
#endif

        CLI_UNPTEMP("cli_scanpe: FSG", (dest, 0));
        CLI_UNPRESULTSFSG2("cli_scanpe: FSG", (unfsg_200(newesi - peinfo->sections[i + 1].rva + src, dest, ssize + peinfo->sections[i + 1].rva - newesi, dsize, newedi, EC32(peinfo->pe_opt.opt32.ImageBase), newedx, ndesc)), 1, (dest, 0));
        break;
    }

    while (found && (DCONF & PE_CONF_FSG) && epbuff[0] == '\xbe' && cli_readint32(epbuff + 1) - EC32(peinfo->pe_opt.opt32.ImageBase) < peinfo->min) {
        int sectcnt = 0;
        const char *support;
        uint32_t newesi, newedi, oldep, gp, t;
        struct cli_exe_section *sections;

        /* FSG support - v. 1.33 (thx trog for the many samples) */

        ssize = peinfo->sections[i + 1].rsz;
        dsize = peinfo->sections[i].vsz;

        CLI_UNPSIZELIMITS("cli_scanpe: FSG", MAX(dsize, ssize));

        if (ssize <= 0x19 || dsize <= ssize) {
            cli_dbgmsg("cli_scanpe: FSG: Size mismatch (ssize: %d, dsize: %d)\n", ssize, dsize);
            cli_exe_info_destroy(peinfo);
            return CL_CLEAN;
        }

        if (!(t = cli_rawaddr(cli_readint32(epbuff + 1) - EC32(peinfo->pe_opt.opt32.ImageBase), NULL, 0, &err, fsize, peinfo->hdr_size)) && err) {
            cli_dbgmsg("cli_scanpe: FSG: Support data out of padding area\n");
            break;
        }

        gp = peinfo->sections[i + 1].raw - t;

        CLI_UNPSIZELIMITS("cli_scanpe: FSG", gp);

        if (!(support = fmap_need_off_once(map, t, gp))) {
            cli_dbgmsg("cli_scanpe: Can't read %d bytes from padding area\n", gp);
            cli_exe_info_destroy(peinfo);
            return CL_EREAD;
        }

        /* newebx = cli_readint32(support) - EC32(peinfo->pe_opt.opt32.ImageBase);  Unused */
        newedi = cli_readint32(support + 4) - EC32(peinfo->pe_opt.opt32.ImageBase); /* 1st dest */
        newesi = cli_readint32(support + 8) - EC32(peinfo->pe_opt.opt32.ImageBase); /* Source */

        if (newesi < peinfo->sections[i + 1].rva || newesi - peinfo->sections[i + 1].rva >= peinfo->sections[i + 1].rsz) {
            cli_dbgmsg("cli_scanpe: FSG: Source buffer out of section bounds\n");
            break;
        }

        if (newedi != peinfo->sections[i].rva) {
            cli_dbgmsg("cli_scanpe: FSG: Bad destination (is %x should be %x)\n", newedi, peinfo->sections[i].rva);
            break;
        }

        /* Counting original sections */
        for (t = 12; t < gp - 4; t += 4) {
            uint32_t rva = cli_readint32(support + t);

            if (!rva)
                break;

            rva -= EC32(peinfo->pe_opt.opt32.ImageBase) + 1;
            sectcnt++;

            if (rva % 0x1000)
                cli_dbgmsg("cli_scanpe: FSG: Original section %d is misaligned\n", sectcnt);

            if (rva < peinfo->sections[i].rva || rva - peinfo->sections[i].rva >= peinfo->sections[i].vsz) {
                cli_dbgmsg("cli_scanpe: FSG: Original section %d is out of bounds\n", sectcnt);
                break;
            }
        }

        if (t >= gp - 4 || cli_readint32(support + t)) {
            break;
        }

        if ((sections = (struct cli_exe_section *)cli_malloc((sectcnt + 1) * sizeof(struct cli_exe_section))) == NULL) {
            cli_errmsg("cli_scanpe: FSG: Unable to allocate memory for sections %llu\n", (long long unsigned)((sectcnt + 1) * sizeof(struct cli_exe_section)));
            cli_exe_info_destroy(peinfo);
            return CL_EMEM;
        }

        sections[0].rva = newedi;
        for (t = 1; t <= (uint32_t)sectcnt; t++)
            sections[t].rva = cli_readint32(support + 8 + t * 4) - 1 - EC32(peinfo->pe_opt.opt32.ImageBase);

        if (!peinfo->sections[i + 1].rsz || !(src = fmap_need_off_once(map, peinfo->sections[i + 1].raw, ssize))) {
            cli_dbgmsg("cli_scanpe: Can't read raw data of section %d\n", i);
            cli_exe_info_destroy(peinfo);
            free(sections);
            return CL_EREAD;
        }

        if ((dest = (char *)cli_calloc(dsize, sizeof(char))) == NULL) {
            cli_exe_info_destroy(peinfo);
            free(sections);
            return CL_EMEM;
        }

        oldep = peinfo->vep + 161 + 6 + cli_readint32(epbuff + 163);
        cli_dbgmsg("cli_scanpe: FSG: found old EP @%x\n", oldep);

#if HAVE_JSON
        if (pe_json != NULL)
            cli_jsonstr(pe_json, "Packer", "FSG");
#endif

        CLI_UNPTEMP("cli_scanpe: FSG", (dest, sections, 0));
        CLI_UNPRESULTSFSG1("cli_scanpe: FSG", (unfsg_133(src + newesi - peinfo->sections[i + 1].rva, dest, ssize + peinfo->sections[i + 1].rva - newesi, dsize, sections, sectcnt, EC32(peinfo->pe_opt.opt32.ImageBase), oldep, ndesc)), 1, (dest, sections, 0));
        break; /* were done with 1.33 */
    }

    while (found && (DCONF & PE_CONF_FSG) && epbuff[0] == '\xbb' && cli_readint32(epbuff + 1) - EC32(peinfo->pe_opt.opt32.ImageBase) < peinfo->min && epbuff[5] == '\xbf' && epbuff[10] == '\xbe' && peinfo->vep >= peinfo->sections[i + 1].rva && peinfo->vep - peinfo->sections[i + 1].rva > peinfo->sections[i + 1].rva - 0xe0) {
        int sectcnt = 0;
        uint32_t gp, t = cli_rawaddr(cli_readint32(epbuff + 1) - EC32(peinfo->pe_opt.opt32.ImageBase), NULL, 0, &err, fsize, peinfo->hdr_size);
        const char *support;
        uint32_t newesi = cli_readint32(epbuff + 11) - EC32(peinfo->pe_opt.opt32.ImageBase);
        uint32_t newedi = cli_readint32(epbuff + 6) - EC32(peinfo->pe_opt.opt32.ImageBase);
        uint32_t oldep  = peinfo->vep - peinfo->sections[i + 1].rva;
        struct cli_exe_section *sections;

        /* FSG support - v. 1.31 */

        ssize = peinfo->sections[i + 1].rsz;
        dsize = peinfo->sections[i].vsz;

        if (err) {
            cli_dbgmsg("cli_scanpe: FSG: Support data out of padding area\n");
            break;
        }

        if (newesi < peinfo->sections[i + 1].rva || newesi - peinfo->sections[i + 1].rva >= peinfo->sections[i + 1].raw) {
            cli_dbgmsg("cli_scanpe: FSG: Source buffer out of section bounds\n");
            break;
        }

        if (newedi != peinfo->sections[i].rva) {
            cli_dbgmsg("cli_scanpe: FSG: Bad destination (is %x should be %x)\n", newedi, peinfo->sections[i].rva);
            break;
        }

        CLI_UNPSIZELIMITS("cli_scanpe: FSG", MAX(dsize, ssize));

        if (ssize <= 0x19 || dsize <= ssize) {
            cli_dbgmsg("cli_scanpe: FSG: Size mismatch (ssize: %d, dsize: %d)\n", ssize, dsize);
            cli_exe_info_destroy(peinfo);
            return CL_CLEAN;
        }

        gp = peinfo->sections[i + 1].raw - t;

        CLI_UNPSIZELIMITS("cli_scanpe: FSG", gp)

        if (!(support = fmap_need_off_once(map, t, gp))) {
            cli_dbgmsg("cli_scanpe: Can't read %d bytes from padding area\n", gp);
            cli_exe_info_destroy(peinfo);
            return CL_EREAD;
        }

        /* Counting original sections */
        for (t = 0; t < gp - 2; t += 2) {
            uint32_t rva = support[t] | (support[t + 1] << 8);

            if (rva == 2 || rva == 1)
                break;

            rva = ((rva - 2) << 12) - EC32(peinfo->pe_opt.opt32.ImageBase);
            sectcnt++;

            if (rva < peinfo->sections[i].rva || rva - peinfo->sections[i].rva >= peinfo->sections[i].vsz) {
                cli_dbgmsg("cli_scanpe: FSG: Original section %d is out of bounds\n", sectcnt);
                break;
            }
        }

        if (t >= gp - 10 || cli_readint32(support + t + 6) != 2)
            break;

        if ((sections = (struct cli_exe_section *)cli_malloc((sectcnt + 1) * sizeof(struct cli_exe_section))) == NULL) {
            cli_errmsg("cli_scanpe: FSG: Unable to allocate memory for sections %llu\n", (long long unsigned)((sectcnt + 1) * sizeof(struct cli_exe_section)));
            cli_exe_info_destroy(peinfo);
            return CL_EMEM;
        }

        sections[0].rva = newedi;
        for (t = 0; t <= (uint32_t)sectcnt - 1; t++)
            sections[t + 1].rva = (((support[t * 2] | (support[t * 2 + 1] << 8)) - 2) << 12) - EC32(peinfo->pe_opt.opt32.ImageBase);

        if (!peinfo->sections[i + 1].rsz || !(src = fmap_need_off_once(map, peinfo->sections[i + 1].raw, ssize))) {
            cli_dbgmsg("cli_scanpe: FSG: Can't read raw data of section %d\n", i);
            cli_exe_info_destroy(peinfo);
            free(sections);
            return CL_EREAD;
        }

        if ((dest = (char *)cli_calloc(dsize, sizeof(char))) == NULL) {
            cli_exe_info_destroy(peinfo);
            free(sections);
            return CL_EMEM;
        }

        gp    = 0xda + 6 * (epbuff[16] == '\xe8');
        oldep = peinfo->vep + gp + 6 + cli_readint32(src + gp + 2 + oldep);
        cli_dbgmsg("cli_scanpe: FSG: found old EP @%x\n", oldep);

#if HAVE_JSON
        if (pe_json != NULL)
            cli_jsonstr(pe_json, "Packer", "FSG");
#endif

        CLI_UNPTEMP("cli_scanpe: FSG", (dest, sections, 0));
        CLI_UNPRESULTSFSG1("cli_scanpe: FSG", (unfsg_133(src + newesi - peinfo->sections[i + 1].rva, dest, ssize + peinfo->sections[i + 1].rva - newesi, dsize, sections, sectcnt, EC32(peinfo->pe_opt.opt32.ImageBase), oldep, ndesc)), 1, (dest, sections, 0));

        break; /* were done with 1.31 */
    }

    if (found && (DCONF & PE_CONF_UPX)) {
        ssize = peinfo->sections[i + 1].rsz;
        dsize = peinfo->sections[i].vsz + peinfo->sections[i + 1].vsz;

        /*
         * UPX support
         * we assume (i + 1) is UPX1
         */

        /* cli_dbgmsg("UPX: ssize %u dsize %u\n", ssize, dsize); */

        CLI_UNPSIZELIMITS("cli_scanpe: UPX", MAX(dsize, ssize));

        if (ssize <= 0x19 || dsize <= ssize || dsize > CLI_MAX_ALLOCATION) {
            cli_dbgmsg("cli_scanpe: UPX: Size mismatch or dsize too big (ssize: %d, dsize: %d)\n", ssize, dsize);
            cli_exe_info_destroy(peinfo);
            return CL_CLEAN;
        }

        if (!peinfo->sections[i + 1].rsz || !(src = fmap_need_off_once(map, peinfo->sections[i + 1].raw, ssize))) {
            cli_dbgmsg("cli_scanpe: UPX: Can't read raw data of section %d\n", i + 1);
            cli_exe_info_destroy(peinfo);
            return CL_EREAD;
        }

        if ((dest = (char *)cli_calloc(dsize + 8192, sizeof(char))) == NULL) {
            cli_exe_info_destroy(peinfo);
            return CL_EMEM;
        }

        /* try to detect UPX code */
        if (cli_memstr(UPX_NRV2B, 24, epbuff + 0x69, 13) || cli_memstr(UPX_NRV2B, 24, epbuff + 0x69 + 8, 13)) {
            cli_dbgmsg("cli_scanpe: UPX: Looks like a NRV2B decompression routine\n");
            upxfn = upx_inflate2b;
        } else if (cli_memstr(UPX_NRV2D, 24, epbuff + 0x69, 13) || cli_memstr(UPX_NRV2D, 24, epbuff + 0x69 + 8, 13)) {
            cli_dbgmsg("cli_scanpe: UPX: Looks like a NRV2D decompression routine\n");
            upxfn = upx_inflate2d;
        } else if (cli_memstr(UPX_NRV2E, 24, epbuff + 0x69, 13) || cli_memstr(UPX_NRV2E, 24, epbuff + 0x69 + 8, 13)) {
            cli_dbgmsg("cli_scanpe: UPX: Looks like a NRV2E decompression routine\n");
            upxfn = upx_inflate2e;
        }

        if (upxfn) {
            int skew = cli_readint32(epbuff + 2) - EC32(peinfo->pe_opt.opt32.ImageBase) - peinfo->sections[i + 1].rva;

            if (epbuff[1] != '\xbe' || skew <= 0 || skew > 0xfff) {
                /* FIXME: legit skews?? */
                skew = 0;
            } else if ((unsigned int)skew > ssize) {
                /* Ignore suggested skew larger than section size */
                skew = 0;
            } else {
                cli_dbgmsg("cli_scanpe: UPX: UPX1 seems skewed by %d bytes\n", skew);
            }

            /* Try skewed first (skew may be zero) */
            if (upxfn(src + skew, ssize - skew, dest, &dsize, peinfo->sections[i].rva, peinfo->sections[i + 1].rva, peinfo->vep - skew) >= 0) {
                upx_success = 1;
            }
            /* If skew not successful and non-zero, try no skew */
            else if (skew && (upxfn(src, ssize, dest, &dsize, peinfo->sections[i].rva, peinfo->sections[i + 1].rva, peinfo->vep) >= 0)) {
                upx_success = 1;
            }

            if (upx_success)
                cli_dbgmsg("cli_scanpe: UPX: Successfully decompressed\n");
            else
                cli_dbgmsg("cli_scanpe: UPX: Preferred decompressor failed\n");
        }

        if (!upx_success && upxfn != upx_inflate2b) {
            if (upx_inflate2b(src, ssize, dest, &dsize, peinfo->sections[i].rva, peinfo->sections[i + 1].rva, peinfo->vep) == -1 && upx_inflate2b(src + 0x15, ssize - 0x15, dest, &dsize, peinfo->sections[i].rva, peinfo->sections[i + 1].rva, peinfo->vep - 0x15) == -1) {

                cli_dbgmsg("cli_scanpe: UPX: NRV2B decompressor failed\n");
            } else {
                upx_success = 1;
                cli_dbgmsg("cli_scanpe: UPX: Successfully decompressed with NRV2B\n");
            }
        }

        if (!upx_success && upxfn != upx_inflate2d) {
            if (upx_inflate2d(src, ssize, dest, &dsize, peinfo->sections[i].rva, peinfo->sections[i + 1].rva, peinfo->vep) == -1 && upx_inflate2d(src + 0x15, ssize - 0x15, dest, &dsize, peinfo->sections[i].rva, peinfo->sections[i + 1].rva, peinfo->vep - 0x15) == -1) {

                cli_dbgmsg("cli_scanpe: UPX: NRV2D decompressor failed\n");
            } else {
                upx_success = 1;
                cli_dbgmsg("cli_scanpe: UPX: Successfully decompressed with NRV2D\n");
            }
        }

        if (!upx_success && upxfn != upx_inflate2e) {
            if (upx_inflate2e(src, ssize, dest, &dsize, peinfo->sections[i].rva, peinfo->sections[i + 1].rva, peinfo->vep) == -1 && upx_inflate2e(src + 0x15, ssize - 0x15, dest, &dsize, peinfo->sections[i].rva, peinfo->sections[i + 1].rva, peinfo->vep - 0x15) == -1) {
                cli_dbgmsg("cli_scanpe: UPX: NRV2E decompressor failed\n");
            } else {
                upx_success = 1;
                cli_dbgmsg("cli_scanpe: UPX: Successfully decompressed with NRV2E\n");
            }
        }

        if (cli_memstr(UPX_LZMA2, 20, epbuff + 0x2f, 20)) {
            uint32_t strictdsize = cli_readint32(epbuff + 0x21), skew = 0;
            if (ssize > 0x15 && epbuff[0] == '\x60' && epbuff[1] == '\xbe') {
                // TODO Add EC32
                skew = cli_readint32(epbuff + 2) - peinfo->sections[i + 1].rva - peinfo->pe_opt.opt32.ImageBase;
                if (skew != 0x15)
                    skew = 0;
            }

            if (strictdsize <= dsize)
                upx_success = upx_inflatelzma(src + skew, ssize - skew, dest, &strictdsize, peinfo->sections[i].rva, peinfo->sections[i + 1].rva, peinfo->vep, 0x20003) >= 0;
        } else if (cli_memstr(UPX_LZMA1_FIRST, 8, epbuff + 0x39, 8) && cli_memstr(UPX_LZMA1_SECOND, 8, epbuff + 0x45, 8)) {
            uint32_t strictdsize = cli_readint32(epbuff + 0x2b), skew = 0;
            uint32_t properties = cli_readint32(epbuff + 0x41);
            if (ssize > 0x15 && epbuff[0] == '\x60' && epbuff[1] == '\xbe') {
                // TODO Add EC32
                skew = cli_readint32(epbuff + 2) - peinfo->sections[i + 1].rva - peinfo->pe_opt.opt32.ImageBase;
                if (skew != 0x15)
                    skew = 0;
            }

            if (strictdsize <= dsize)
                upx_success = upx_inflatelzma(src + skew, ssize - skew, dest, &strictdsize, peinfo->sections[i].rva, peinfo->sections[i + 1].rva, peinfo->vep, properties) >= 0;
        }

        if (!upx_success) {
            cli_dbgmsg("cli_scanpe: UPX: All decompressors failed\n");
            free(dest);
        }
    }

    if (upx_success) {
        cli_exe_info_destroy(peinfo);

        CLI_UNPTEMP("cli_scanpe: UPX/FSG", (dest, 0));
#if HAVE_JSON
        if (pe_json != NULL)
            cli_jsonstr(pe_json, "Packer", "UPX");
#endif

        if ((unsigned int)write(ndesc, dest, dsize) != dsize) {
            cli_dbgmsg("cli_scanpe: UPX/FSG: Can't write %d bytes\n", dsize);
            free(tempfile);
            free(dest);
            close(ndesc);
            return CL_EWRITE;
        }

        free(dest);
        if (lseek(ndesc, 0, SEEK_SET) == -1) {
            cli_dbgmsg("cli_scanpe: UPX/FSG: lseek() failed\n");
            close(ndesc);
            SHA_RESET;
            CLI_TMPUNLK();
            free(tempfile);
            return CL_ESEEK;
        }

        if (ctx->engine->keeptmp)
            cli_dbgmsg("cli_scanpe: UPX/FSG: Decompressed data saved in %s\n", tempfile);

        cli_dbgmsg("***** Scanning decompressed file *****\n");
        SHA_OFF;
        ret = cli_magic_scan_desc(ndesc, tempfile, ctx, NULL);
        if (CL_SUCCESS != ret) {
            close(ndesc);
            SHA_RESET;
            CLI_TMPUNLK();
            free(tempfile);
            return ret;
        }

        SHA_RESET;
        close(ndesc);
        CLI_TMPUNLK();
        free(tempfile);
        return ret;
    }

    /* Petite */

    if (epsize < 200) {
        cli_exe_info_destroy(peinfo);
        return CL_CLEAN;
    }

    found = 2;

    if (epbuff[0] != '\xb8' || (uint32_t)cli_readint32(epbuff + 1) != peinfo->sections[peinfo->nsections - 1].rva + EC32(peinfo->pe_opt.opt32.ImageBase)) {
        if (peinfo->nsections < 2 || epbuff[0] != '\xb8' || (uint32_t)cli_readint32(epbuff + 1) != peinfo->sections[peinfo->nsections - 2].rva + EC32(peinfo->pe_opt.opt32.ImageBase))
            found = 0;
        else
            found = 1;
    }

    if (found && (DCONF & PE_CONF_PETITE)) {
        cli_dbgmsg("cli_scanpe: Petite: v2.%d compression detected\n", found);

        if (cli_readint32(epbuff + 0x80) == 0x163c988d) {
            cli_dbgmsg("cli_scanpe: Petite: level zero compression is not supported yet\n");
        } else {
            dsize = peinfo->max - peinfo->min;

            CLI_UNPSIZELIMITS("cli_scanpe: Petite", dsize);

            if ((dest = (char *)cli_calloc(dsize, sizeof(char))) == NULL) {
                cli_dbgmsg("cli_scanpe: Petite: Can't allocate %d bytes\n", dsize);
                cli_exe_info_destroy(peinfo);
                return CL_EMEM;
            }

            for (i = 0; i < peinfo->nsections; i++) {
                if (peinfo->sections[i].raw) {
                    unsigned int r_ret;

                    if (!peinfo->sections[i].rsz)
                        goto out_no_petite;

                    if (!CLI_ISCONTAINED(dest, dsize,
                                         dest + peinfo->sections[i].rva - peinfo->min,
                                         peinfo->sections[i].ursz))
                        goto out_no_petite;

                    r_ret = fmap_readn(map, dest + peinfo->sections[i].rva - peinfo->min,
                                       peinfo->sections[i].raw,
                                       peinfo->sections[i].ursz);
                    if (r_ret != peinfo->sections[i].ursz) {
                    out_no_petite:
                        cli_exe_info_destroy(peinfo);
                        free(dest);
                        return CL_CLEAN;
                    }
                }
            }

#if HAVE_JSON
            if (pe_json != NULL)
                cli_jsonstr(pe_json, "Packer", "Petite");
#endif

            CLI_UNPTEMP("cli_scanpe: Petite", (dest, 0));
            CLI_UNPRESULTS("Petite", (petite_inflate2x_1to9(dest, peinfo->min, peinfo->max - peinfo->min, peinfo->sections, peinfo->nsections - (found == 1 ? 1 : 0), EC32(peinfo->pe_opt.opt32.ImageBase), peinfo->vep, ndesc, found, EC32(peinfo->dirs[2].VirtualAddress), EC32(peinfo->dirs[2].Size))), 0, (dest, 0));
        }
    }

    /* PESpin 1.1 */

    if ((DCONF & PE_CONF_PESPIN) && peinfo->nsections > 1 &&
        peinfo->vep >= peinfo->sections[peinfo->nsections - 1].rva &&
        0x3217 - 4 <= peinfo->sections[peinfo->nsections - 1].rva + peinfo->sections[peinfo->nsections - 1].rsz &&
        peinfo->vep < peinfo->sections[peinfo->nsections - 1].rva + peinfo->sections[peinfo->nsections - 1].rsz - 0x3217 - 4 &&
        memcmp(epbuff + 4, "\xe8\x00\x00\x00\x00\x8b\x1c\x24\x83\xc3", 10) == 0) {

        char *spinned;

        CLI_UNPSIZELIMITS("cli_scanpe: PEspin", fsize);

        if ((spinned = (char *)cli_malloc(fsize)) == NULL) {
            cli_errmsg("cli_scanpe: PESping: Unable to allocate memory for spinned %lu\n", (unsigned long)fsize);
            cli_exe_info_destroy(peinfo);
            return CL_EMEM;
        }

        if (fmap_readn(map, spinned, 0, fsize) != fsize) {
            cli_dbgmsg("cli_scanpe: PESpin: Can't read %lu bytes\n", (unsigned long)fsize);
            free(spinned);
            cli_exe_info_destroy(peinfo);
            return CL_EREAD;
        }

#if HAVE_JSON
        if (pe_json != NULL)
            cli_jsonstr(pe_json, "Packer", "PEspin");
#endif

        CLI_UNPTEMP("cli_scanpe: PESpin", (spinned, 0));
        CLI_UNPRESULTS_("cli_scanpe: PEspin", SPINCASE(), (unspin(spinned, fsize, peinfo->sections, peinfo->nsections - 1, peinfo->vep, ndesc, ctx)), 0, (spinned, 0));
    }

    /* yC 1.3 & variants */
    if ((DCONF & PE_CONF_YC) && peinfo->nsections > 1 &&
        (EC32(peinfo->pe_opt.opt32.AddressOfEntryPoint) == peinfo->sections[peinfo->nsections - 1].rva + 0x60)) {

        uint32_t ecx = 0;
        int16_t offset;

        /* yC 1.3 */
        if (!memcmp(epbuff, "\x55\x8B\xEC\x53\x56\x57\x60\xE8\x00\x00\x00\x00\x5D\x81\xED", 15) &&
            !memcmp(epbuff + 0x26, "\x8D\x3A\x8B\xF7\x33\xC0\xEB\x04\x90\xEB\x01\xC2\xAC", 13) &&
            ((uint8_t)epbuff[0x13] == 0xB9) &&
            ((uint16_t)(cli_readint16(epbuff + 0x18)) == 0xE981) &&
            !memcmp(epbuff + 0x1e, "\x8B\xD5\x81\xC2", 4)) {

            offset = 0;
            if (0x6c - cli_readint32(epbuff + 0xf) + cli_readint32(epbuff + 0x22) == 0xC6)
                ecx = cli_readint32(epbuff + 0x14) - cli_readint32(epbuff + 0x1a);
        }

        /* yC 1.3 variant */
        if (!ecx && !memcmp(epbuff, "\x55\x8B\xEC\x83\xEC\x40\x53\x56\x57", 9) &&
            !memcmp(epbuff + 0x17, "\xe8\x00\x00\x00\x00\x5d\x81\xed", 8) &&
            ((uint8_t)epbuff[0x23] == 0xB9)) {

            offset = 0x10;
            if (0x6c - cli_readint32(epbuff + 0x1f) + cli_readint32(epbuff + 0x32) == 0xC6)
                ecx = cli_readint32(epbuff + 0x24) - cli_readint32(epbuff + 0x2a);
        }

        /* yC 1.x/modified */
        if (!ecx && !memcmp(epbuff, "\x60\xe8\x00\x00\x00\x00\x5d\x81\xed", 9) &&
            ((uint8_t)epbuff[0xd] == 0xb9) &&
            ((uint16_t)cli_readint16(epbuff + 0x12) == 0xbd8d) &&
            !memcmp(epbuff + 0x18, "\x8b\xf7\xac", 3)) {

            offset = -0x18;
            if (0x66 - cli_readint32(epbuff + 0x9) + cli_readint32(epbuff + 0x14) == 0xae)
                ecx = cli_readint32(epbuff + 0xe);
        }

        if (ecx > 0x800 && ecx < 0x2000 &&
            !memcmp(epbuff + 0x63 + offset, "\xaa\xe2\xcc", 3) &&
            (fsize >= peinfo->sections[peinfo->nsections - 1].raw + 0xC6 + ecx + offset)) {

            size_t num_alerts;
            char *spinned;

            if ((spinned = (char *)cli_malloc(fsize)) == NULL) {
                cli_errmsg("cli_scanpe: yC: Unable to allocate memory for spinned %lu\n", (unsigned long)fsize);
                cli_exe_info_destroy(peinfo);
                return CL_EMEM;
            }

            if (fmap_readn(map, spinned, 0, fsize) != fsize) {
                cli_dbgmsg("cli_scanpe: yC: Can't read %lu bytes\n", (unsigned long)fsize);
                free(spinned);
                cli_exe_info_destroy(peinfo);
                return CL_EREAD;
            }

#if HAVE_JSON
            if (pe_json != NULL)
                cli_jsonstr(pe_json, "Packer", "yC");
#endif

            // record number of alerts before unpacking and scanning
            num_alerts = evidence_num_alerts(ctx->evidence);

            cli_dbgmsg("%d,%d,%d,%d\n", peinfo->nsections - 1, peinfo->e_lfanew, ecx, offset);
            CLI_UNPTEMP("cli_scanpe: yC", (spinned, 0));
            CLI_UNPRESULTS("cli_scanpe: yC", (yc_decrypt(ctx, spinned, fsize, peinfo->sections, peinfo->nsections - 1, peinfo->e_lfanew, ndesc, ecx, offset)), 0, (spinned, 0));

            // Unpacking may have added new alerts if the bounds-check failed.
            // Compare number of alerts now with number of alerts before unpacking/scanning.
            // If the number of alerts has increased, then bail.
            //
            // This preserves the intention of https://github.com/Cisco-Talos/clamav/commit/771c23099893f02f1316960fbe84f62b115a3556
            // although that commit had it bailing if a match occured even in allmatch-mode, which we do not want to do.
            if (!SCAN_ALLMATCHES && num_alerts != evidence_num_alerts(ctx->evidence)) {
                cli_exe_info_destroy(peinfo);
                return CL_VIRUS;
            }
        }
    }

    /* WWPack */

    while ((DCONF & PE_CONF_WWPACK) && peinfo->nsections > 1 &&
           peinfo->vep == peinfo->sections[peinfo->nsections - 1].rva &&
           memcmp(epbuff, "\x53\x55\x8b\xe8\x33\xdb\xeb", 7) == 0 &&
           memcmp(epbuff + 0x68, "\xe8\x00\x00\x00\x00\x58\x2d\x6d\x00\x00\x00\x50\x60\x33\xc9\x50\x58\x50\x50", 19) == 0) {
        uint32_t head = peinfo->sections[peinfo->nsections - 1].raw;
        uint8_t *packer;
        char *src;

        ssize = 0;
        for (i = 0;; i++) {
            if (peinfo->sections[i].raw < head)
                head = peinfo->sections[i].raw;

            if (i + 1 == peinfo->nsections)
                break;

            if (ssize < peinfo->sections[i].rva + peinfo->sections[i].vsz)
                ssize = peinfo->sections[i].rva + peinfo->sections[i].vsz;
        }

        if (!head || !ssize || head > ssize)
            break;

        CLI_UNPSIZELIMITS("cli_scanpe: WWPack", ssize);

        if (!(src = (char *)cli_calloc(ssize, sizeof(char)))) {
            cli_exe_info_destroy(peinfo);
            return CL_EMEM;
        }

        if (fmap_readn(map, src, 0, head) != head) {
            cli_dbgmsg("cli_scanpe: WWPack: Can't read %d bytes from headers\n", head);
            free(src);
            cli_exe_info_destroy(peinfo);
            return CL_EREAD;
        }

        for (i = 0; i < (unsigned int)peinfo->nsections - 1; i++) {
            if (!peinfo->sections[i].rsz)
                continue;

            if (!CLI_ISCONTAINED(src, ssize, src + peinfo->sections[i].rva, peinfo->sections[i].rsz))
                break;

            if (fmap_readn(map, src + peinfo->sections[i].rva, peinfo->sections[i].raw, peinfo->sections[i].rsz) != peinfo->sections[i].rsz)
                break;
        }

        if (i + 1 != peinfo->nsections) {
            cli_dbgmsg("cli_scanpe: WWpack: Probably hacked/damaged file.\n");
            free(src);
            break;
        }

        if ((packer = (uint8_t *)cli_calloc(peinfo->sections[peinfo->nsections - 1].rsz, sizeof(char))) == NULL) {
            free(src);
            cli_exe_info_destroy(peinfo);
            return CL_EMEM;
        }

        if (!peinfo->sections[peinfo->nsections - 1].rsz || fmap_readn(map, packer, peinfo->sections[peinfo->nsections - 1].raw, peinfo->sections[peinfo->nsections - 1].rsz) != peinfo->sections[peinfo->nsections - 1].rsz) {
            cli_dbgmsg("cli_scanpe: WWPack: Can't read %d bytes from wwpack sect\n", peinfo->sections[peinfo->nsections - 1].rsz);
            free(src);
            free(packer);
            cli_exe_info_destroy(peinfo);
            return CL_EREAD;
        }

#if HAVE_JSON
        if (pe_json != NULL)
            cli_jsonstr(pe_json, "Packer", "WWPack");
#endif

        CLI_UNPTEMP("cli_scanpe: WWPack", (src, packer, 0));
        CLI_UNPRESULTS("cli_scanpe: WWPack", (wwunpack((uint8_t *)src, ssize, packer, peinfo->sections, peinfo->nsections - 1, peinfo->e_lfanew, ndesc)), 0, (src, packer, 0));
        break;
    }

    /* ASPACK support */
    while ((DCONF & PE_CONF_ASPACK) &&
           ((peinfo->ep + ASPACK_EP_OFFSET_212 < fsize) ||
            (peinfo->ep + ASPACK_EP_OFFSET_OTHER < fsize) ||
            (peinfo->ep + ASPACK_EP_OFFSET_242 < fsize)) &&
           (!memcmp(epbuff, "\x60\xe8\x03\x00\x00\x00\xe9\xeb", 8))) {
        char *src;
        aspack_version_t aspack_ver = ASPACK_VER_NONE;

        if (epsize < 0x3bf)
            break;

        if (0 == memcmp(epbuff + ASPACK_EPBUFF_OFFSET_212, "\x68\x00\x00\x00\x00\xc3", 6)) {
            aspack_ver = ASPACK_VER_212;
        } else if (0 == memcmp(epbuff + ASPACK_EPBUFF_OFFSET_OTHER, "\x68\x00\x00\x00\x00\xc3", 6)) {
            aspack_ver = ASPACK_VER_OTHER;
        } else if (0 == memcmp(epbuff + ASPACK_EPBUFF_OFFSET_242, "\x68\x00\x00\x00\x00\xc3", 6)) {
            aspack_ver = ASPACK_VER_242;
        } else {
            break;
        }
        ssize = 0;
        for (i = 0; i < peinfo->nsections; i++)
            if (ssize < peinfo->sections[i].rva + peinfo->sections[i].vsz)
                ssize = peinfo->sections[i].rva + peinfo->sections[i].vsz;

        if (!ssize)
            break;

        CLI_UNPSIZELIMITS("cli_scanpe: Aspack", ssize);

        if (!(src = (char *)cli_calloc(ssize, sizeof(char)))) {
            cli_exe_info_destroy(peinfo);
            return CL_EMEM;
        }
        for (i = 0; i < (unsigned int)peinfo->nsections; i++) {
            if (!peinfo->sections[i].rsz)
                continue;

            if (!CLI_ISCONTAINED(src, ssize, src + peinfo->sections[i].rva, peinfo->sections[i].rsz))
                break;

            if (fmap_readn(map, src + peinfo->sections[i].rva, peinfo->sections[i].raw, peinfo->sections[i].rsz) != peinfo->sections[i].rsz)
                break;
        }

        if (i != peinfo->nsections) {
            cli_dbgmsg("cli_scanpe: Aspack: Probably hacked/damaged Aspack file.\n");
            free(src);
            break;
        }

#if HAVE_JSON
        if (pe_json != NULL)
            cli_jsonstr(pe_json, "Packer", "Aspack");
#endif

        CLI_UNPTEMP("cli_scanpe: Aspack", (src, 0));
        CLI_UNPRESULTS("cli_scanpe: Aspack", (unaspack((uint8_t *)src, ssize, peinfo->sections, peinfo->nsections, peinfo->vep - 1, EC32(peinfo->pe_opt.opt32.ImageBase), ndesc, aspack_ver)), 1, (src, 0));
        break;
    }

    /* NsPack */

    while (DCONF & PE_CONF_NSPACK) {
        uint32_t eprva = peinfo->vep;
        uint32_t start_of_stuff, rep = peinfo->ep;
        unsigned int nowinldr;
        const char *nbuff;

        src = epbuff;
        if (*epbuff == '\xe9') { /* bitched headers */
            eprva = cli_readint32(epbuff + 1) + peinfo->vep + 5;
            if (!(rep = cli_rawaddr(eprva, peinfo->sections, peinfo->nsections, &err, fsize, peinfo->hdr_size)) && err)
                break;

            if (!(nbuff = fmap_need_off_once(map, rep, 24)))
                break;

            src = nbuff;
        }

        if (memcmp(src, "\x9c\x60\xe8\x00\x00\x00\x00\x5d\xb8\x07\x00\x00\x00", 13))
            break;

        nowinldr = 0x54 - cli_readint32(src + 17);
        cli_dbgmsg("cli_scanpe: NsPack: Found *start_of_stuff @delta-%x\n", nowinldr);

        if (!(nbuff = fmap_need_off_once(map, rep - nowinldr, 4)))
            break;

        start_of_stuff = rep + cli_readint32(nbuff);
        if (!(nbuff = fmap_need_off_once(map, start_of_stuff, 20)))
            break;

        src = nbuff;
        if (!cli_readint32(nbuff)) {
            start_of_stuff += 4; /* FIXME: more to do */
            src += 4;
        }

        ssize = cli_readint32(src + 5) | 0xff;
        dsize = cli_readint32(src + 9);

        CLI_UNPSIZELIMITS("cli_scanpe: NsPack", MAX(ssize, dsize));

        if (!ssize || !dsize || dsize != peinfo->sections[0].vsz)
            break;

        if (!(dest = cli_malloc(dsize))) {
            cli_errmsg("cli_scanpe: NsPack: Unable to allocate memory for dest %u\n", dsize);
            break;
        }
        /* memset(dest, 0xfc, dsize); */

        if (!(src = fmap_need_off(map, start_of_stuff, ssize))) {
            free(dest);
            break;
        }
        /* memset(src, 0x00, ssize); */

        eprva += 0x27a;
        if (!(rep = cli_rawaddr(eprva, peinfo->sections, peinfo->nsections, &err, fsize, peinfo->hdr_size)) && err) {
            free(dest);
            break;
        }

        if (!(nbuff = fmap_need_off_once(map, rep, 5))) {
            free(dest);
            break;
        }

        fmap_unneed_off(map, start_of_stuff, ssize);
        eprva = eprva + 5 + cli_readint32(nbuff + 1);
        cli_dbgmsg("cli_scanpe: NsPack: OEP = %08x\n", eprva);

#if HAVE_JSON
        if (pe_json != NULL)
            cli_jsonstr(pe_json, "Packer", "NsPack");
#endif

        CLI_UNPTEMP("cli_scanpe: NsPack", (dest, 0));
        CLI_UNPRESULTS("cli_scanpe: NsPack", (unspack(src, dest, ctx, peinfo->sections[0].rva, EC32(peinfo->pe_opt.opt32.ImageBase), eprva, ndesc)), 0, (dest, 0));
        break;
    }

    /* to be continued ... */

    /* !!!!!!!!!!!!!!    PACKERS END HERE    !!!!!!!!!!!!!! */
    ctx->corrupted_input = corrupted_cur;

    /* Bytecode BC_PE_UNPACKER hook */
    bc_ctx = cli_bytecode_context_alloc();
    if (!bc_ctx) {
        cli_errmsg("cli_scanpe: can't allocate memory for bc_ctx\n");
        return CL_EMEM;
    }

    cli_bytecode_context_setpe(bc_ctx, &pedata, peinfo->sections);
    cli_bytecode_context_setctx(bc_ctx, ctx);

    ret = cli_bytecode_runhook(ctx, ctx->engine, bc_ctx, BC_PE_UNPACKER, map);
    switch (ret) {
        case CL_VIRUS:
            cli_exe_info_destroy(peinfo);
            cli_bytecode_context_destroy(bc_ctx);
            return CL_VIRUS;
        case CL_SUCCESS:
            ndesc = cli_bytecode_context_getresult_file(bc_ctx, &tempfile);
            cli_bytecode_context_destroy(bc_ctx);
            if (ndesc != -1 && tempfile) {
                CLI_UNPRESULTS("cli_scanpe: bytecode PE hook", 1, 1, (0));
            }

            break;
        default:
            cli_bytecode_context_destroy(bc_ctx);
    }

    cli_exe_info_destroy(peinfo);

#if HAVE_JSON
    if (cli_json_timeout_cycle_check(ctx, &toval) != CL_SUCCESS)
        return CL_ETIMEOUT;
#endif

    return CL_SUCCESS;
}

cl_error_t cli_pe_targetinfo(cli_ctx *ctx, struct cli_exe_info *peinfo)
{
    return cli_peheader(ctx->fmap, peinfo, CLI_PEHEADER_OPT_EXTRACT_VINFO, NULL);
}

/** Parse the PE header and, if successful, populate peinfo
 *
 * @param map The fmap_t backing the file being scanned
 * @param peinfo A structure to populate with info from the PE header. This
 *               MUST be initialized via cli_exe_info_init prior to calling
 * @param opts A bitfield indicating various options related to PE header
 *             parsing.  The options are (prefixed with CLI_PEHEADER_OPT_):
 *              - NONE - Do default parsing
 *              - COLLECT_JSON - Populate ctx's json obj with PE header
 *                               info
 *              - DBG_PRINT_INFO - Print debug information about the
 *                                 PE file. Right now, cli_peheader is
 *                                 called multiple times for a given PE,
 *                                 so you don't want to print out the
 *                                 same info each time.
 *              - EXTRACT_VINFO - Parse the PEs VERSION_INFO metadata
 *                                and store it in peinfo->vinfo
 *              - STRICT_ON_PE_ERRORS - If specified, some cases that
 *                                      might be considered a broken
 *                                      executable cause RET_BROKEN_PE
 *                                      to be returned, but otherwise
 *                                      these will be tolerated.
 *              - REMOVE_MISSING_SECTIONS - If a section exists outside of the
 *                                          file, remove it from
 *                                          peinfo->sections. Otherwise, the
 *                                          rsz is just set to 0 for it.
 * @param ctx The overarching cli_ctx.  This is required with certain opts, but
 *            optional otherwise.
 * @return If the PE header is parsed successfully, CL_SUCCESS is returned.
 *         If it seems like the PE is broken, CL_EFORMAT is returned.
 *         Otherwise, one of the other error codes is returned.
 *         The caller MUST destroy peinfo, regardless of what this function
 *         returns.
 *
 * TODO What constitutes a "broken PE" seems somewhat arbitrary in places.
 * I think a PE should only be considered broken if it will not run on
 * any version of Windows.  We should invest more time to ensure that our
 * broken PE detection more closely aligns with this.
 *
 * TODO Simplify and get rid of CLI_PEHEADER_OPT_STRICT_ON_PE_ERRORS if
 * possible.  We should either fail always or ignore always, IMO.
 *
 * TODO Simplify and get rid of CLI_PEHEADER_OPT_REMOVE_MISSING_SECTIONS if
 * possible.  I don't think it makes sense to have pieces of the code work
 * off of incomplete representations of the sections (for instance, I wonder
 * if this makes any of the bytecode APIs return unexpected values).  This
 * appears to have been implemented to prevent ClamAV from crashing, though,
 * (bb11155) so we need to ensure the underlying issues are addressed.
 *
 * TODO Consolidate when information about the PE is printed (after successful
 * PE parsing).  This will allow us to simplify the code.  Some fail cases,
 * then, will cause PE info to not be printed at all, but I think this is
 * acceptable.  The debug messages generated in the fail cases should point to
 * what happened, and that's enough to track down the cause of any issues.
 *
 * TODO Same as above but with JSON creation
 */
cl_error_t cli_peheader(fmap_t *map, struct cli_exe_info *peinfo, uint32_t opts, cli_ctx *ctx)
{
    cl_error_t ret = CL_ERROR;

    uint16_t e_magic; /* DOS signature ("MZ") */
    const char *archtype = NULL, *subsystem = NULL;
    time_t timestamp;
    char timestr[32];
    uint32_t data_dirs_size;
    uint16_t opt_hdr_size;
    uint32_t stored_opt_hdr_size;
    struct pe_image_file_hdr *file_hdr;
    struct pe_image_optional_hdr32 *opt32;
    struct pe_image_optional_hdr64 *opt64;
    struct pe_image_section_hdr *section_hdrs = NULL;
    size_t i, j, section_pe_idx;
    unsigned int err;
    uint32_t salign, falign;
    size_t fsize;
    ssize_t at;
    uint32_t is_dll = 0;
    uint32_t is_exe = 0;
    int native      = 0;
    size_t read;

#if HAVE_JSON
    int toval                   = 0;
    struct json_object *pe_json = NULL;
    char jsonbuf[128];
#endif

    if (ctx == NULL &&
        (opts & CLI_PEHEADER_OPT_COLLECT_JSON ||
         opts & CLI_PEHEADER_OPT_DBG_PRINT_INFO)) {
        cli_errmsg("cli_peheader: ctx can't be NULL for options specified\n");
        goto done;
    }

#if HAVE_JSON
    if (opts & CLI_PEHEADER_OPT_COLLECT_JSON) {
        pe_json = get_pe_property(ctx);
    }
#endif

    fsize = map->len - peinfo->offset;
    if (fmap_readn(map, &e_magic, peinfo->offset, sizeof(e_magic)) != sizeof(e_magic)) {
        cli_dbgmsg("cli_peheader: Can't read DOS signature\n");
        goto done;
    }

    if (EC16(e_magic) != PE_IMAGE_DOS_SIGNATURE && EC16(e_magic) != PE_IMAGE_DOS_SIGNATURE_OLD) {
        cli_dbgmsg("cli_peheader: Invalid DOS signature\n");
        goto done;
    }

    if (fmap_readn(map, &(peinfo->e_lfanew), peinfo->offset + 58 + sizeof(e_magic), sizeof(peinfo->e_lfanew)) != sizeof(peinfo->e_lfanew)) {
        /* truncated header? */
        cli_dbgmsg("cli_peheader: Unable to read e_lfanew - truncated header?\n");
        ret = CL_EFORMAT;
        goto done;
    }

    peinfo->e_lfanew = EC32(peinfo->e_lfanew);
    if (opts & CLI_PEHEADER_OPT_DBG_PRINT_INFO) {
        cli_dbgmsg("e_lfanew == %d\n", peinfo->e_lfanew);
    }
    if (!peinfo->e_lfanew) {
        cli_dbgmsg("cli_peheader: Not a PE file - e_lfanew == 0\n");
        goto done;
    }

    if (fmap_readn(map, &(peinfo->file_hdr), peinfo->offset + peinfo->e_lfanew, sizeof(struct pe_image_file_hdr)) != sizeof(struct pe_image_file_hdr)) {
        /* bad information in e_lfanew - probably not a PE file */
        cli_dbgmsg("cli_peheader: Can't read file header\n");
        goto done;
    }

    file_hdr = &(peinfo->file_hdr);

    if (EC32(file_hdr->Magic) != PE_IMAGE_NT_SIGNATURE) {
        cli_dbgmsg("cli_peheader: Invalid PE signature (probably NE file)\n");
        goto done;
    }

    if (EC16(file_hdr->Characteristics) & 0x2000) {

#if HAVE_JSON
        if (opts & CLI_PEHEADER_OPT_COLLECT_JSON)
            cli_jsonstr(pe_json, "Type", "DLL");
#endif
        if (opts & CLI_PEHEADER_OPT_DBG_PRINT_INFO) {
            cli_dbgmsg("File type: DLL\n");
        }

        is_dll = 1;
    } else if (EC16(file_hdr->Characteristics) & 0x0002) {

#if HAVE_JSON
        if (opts & CLI_PEHEADER_OPT_COLLECT_JSON)
            cli_jsonstr(pe_json, "Type", "EXE");
#endif
        if (opts & CLI_PEHEADER_OPT_DBG_PRINT_INFO) {
            cli_dbgmsg("File type: Executable\n");
        }

        is_exe = 1;
    }

    if (!is_dll && !is_exe) {
        cli_dbgmsg("cli_peheader: Assumption Violated: PE is not a DLL or EXE\n");
        // TODO Don't continue if not an exe or dll?
    }

    peinfo->is_dll = is_dll;

    if (opts & CLI_PEHEADER_OPT_DBG_PRINT_INFO ||
        opts & CLI_PEHEADER_OPT_COLLECT_JSON) {
        switch (EC16(file_hdr->Machine)) {
            case 0x0:
                archtype = "Unknown";
                break;
            case 0x1:
                // New as of Windows 10, version 1607 and Windows Server 2016
                archtype = "Target Host";
                break;
            case 0x14c:
                archtype = "80386";
                break;
            case 0x14d:
                archtype = "80486";
                break;
            case 0x14e:
                archtype = "80586";
                break;
            case 0x160:
                archtype = "R3000 MIPS BE";
                break;
            case 0x162:
                archtype = "R3000 MIPS LE";
                break;
            case 0x166:
                archtype = "R4000 MIPS LE";
                break;
            case 0x168:
                archtype = "R10000 MIPS LE";
                break;
            case 0x169:
                archtype = "WCE MIPS LE";
                break;
            case 0x184:
                archtype = "DEC Alpha AXP";
                break;
            case 0x1a2:
                archtype = "Hitachi SH3 LE";
                break;
            case 0x1a3:
                archtype = "Hitachi SH3-DSP";
                break;
            case 0x1a4:
                archtype = "Hitachi SH3-E LE";
                break;
            case 0x1a6:
                archtype = "Hitachi SH4 LE";
                break;
            case 0x1a8:
                archtype = "Hitachi SH5";
                break;
            case 0x1c0:
                archtype = "ARM LE";
                break;
            case 0x1c2:
                archtype = "ARM Thumb/Thumb-2 LE";
                break;
            case 0x1c4:
                archtype = "ARM Thumb-2 LE";
                break;
            case 0x1d3:
                archtype = "AM33";
                break;
            case 0x1f0:
                archtype = "PowerPC LE";
                break;
            case 0x1f1:
                archtype = "PowerPC FP";
                break;
            case 0x200:
                archtype = "IA64";
                break;
            case 0x266:
                archtype = "MIPS16";
                break;
            case 0x268:
                archtype = "M68k";
                break;
            case 0x284:
                archtype = "DEC Alpha AXP 64bit";
                break;
            case 0x366:
                archtype = "MIPS+FPU";
                break;
            case 0x466:
                archtype = "MIPS16+FPU";
                break;
            case 0x520:
                archtype = "Infineon TriCore";
                break;
            case 0xcef:
                archtype = "CEF";
                break;
            case 0xebc:
                archtype = "EFI Byte Code";
                break;
            case 0x8664:
                archtype = "AMD64";
                break;
            case 0x9041:
                archtype = "M32R";
                break;
            case 0xaa64:
                archtype = "ARM64 LE";
                break;
            case 0xc0ee:
                archtype = "CEE";
                break;
            default:
                archtype = "Unknown";
        }

        if (opts & CLI_PEHEADER_OPT_DBG_PRINT_INFO)
            cli_dbgmsg("Machine type: %s\n", archtype);

#if HAVE_JSON
        if (opts & CLI_PEHEADER_OPT_COLLECT_JSON)
            cli_jsonstr(pe_json, "ArchType", archtype);
#endif
    }

    peinfo->nsections = EC16(file_hdr->NumberOfSections);
    if (peinfo->nsections == 0) {

#if HAVE_JSON
        if (opts & CLI_PEHEADER_OPT_COLLECT_JSON) {
            pe_add_heuristic_property(ctx, "BadNumberOfSections");
        }
#endif
        // TODO Investigate how corrupted_input is set and whether this
        // check is needed
        if (opts & CLI_PEHEADER_OPT_DBG_PRINT_INFO &&
            !ctx->corrupted_input) {
            if (peinfo->nsections == 0) {
                cli_dbgmsg("cli_peheader: Invalid NumberOfSections (0)\n");
            }
        }
        ret = CL_EFORMAT;
        goto done;
    }

    timestamp    = (time_t)EC32(file_hdr->TimeDateStamp);
    opt_hdr_size = EC16(file_hdr->SizeOfOptionalHeader);

    if (opts & CLI_PEHEADER_OPT_DBG_PRINT_INFO) {
        cli_dbgmsg("NumberOfSections: %d\n", peinfo->nsections);
        cli_dbgmsg("TimeDateStamp: %s", cli_ctime(&timestamp, timestr, sizeof(timestr)));
        cli_dbgmsg("SizeOfOptionalHeader: 0x%x\n", opt_hdr_size);
    }

#if HAVE_JSON
    if (opts & CLI_PEHEADER_OPT_COLLECT_JSON) {
        cli_jsonint(pe_json, "NumberOfSections", peinfo->nsections);
        /* NOTE: the TimeDateStamp value will look like "Wed Dec 31 19:00:00 1969\n" */
        cli_jsonstr(pe_json, "TimeDateStamp", cli_ctime(&timestamp, timestr, sizeof(timestr)));
        cli_jsonint(pe_json, "SizeOfOptionalHeader", opt_hdr_size);
    }
#endif

    // Ensure there are enough bytes to cover the full optional header,
    // not including the data directory entries (which aren't all gauranteed
    // to be there)
    if (opt_hdr_size < sizeof(struct pe_image_optional_hdr32)) {
        cli_dbgmsg("cli_peheader: SizeOfOptionalHeader too small\n");

#if HAVE_JSON
        if (opts & CLI_PEHEADER_OPT_COLLECT_JSON) {
            pe_add_heuristic_property(ctx, "BadOptionalHeaderSize");
        }
#endif
        ret = CL_EFORMAT;
        goto done;
    }

    at = peinfo->offset + peinfo->e_lfanew + sizeof(struct pe_image_file_hdr);
    if (fmap_readn(map, &(peinfo->pe_opt.opt32), at, sizeof(struct pe_image_optional_hdr32)) != sizeof(struct pe_image_optional_hdr32)) {
        cli_dbgmsg("cli_peheader: Can't read optional file header\n");
        ret = CL_EFORMAT;
        goto done;
    }
    stored_opt_hdr_size = sizeof(struct pe_image_optional_hdr32);
    at += stored_opt_hdr_size;

    opt32 = &(peinfo->pe_opt.opt32);

    if (EC16(opt32->Magic) == PE32P_SIGNATURE) { /* PE+ */
        // The PE32+ optional header is bigger by 16 bytes, so map in the
        // additional bytes here

        if (opt_hdr_size < sizeof(struct pe_image_optional_hdr64)) {
            cli_dbgmsg("cli_peheader: Incorrect SizeOfOptionalHeader for PE32+\n");
#if HAVE_JSON
            if (opts & CLI_PEHEADER_OPT_COLLECT_JSON) {
                pe_add_heuristic_property(ctx, "BadOptionalHeaderSizePE32Plus");
            }
#endif
            ret = CL_EFORMAT;
            goto done;
        }

        if (fmap_readn(map, (void *)(((size_t) & (peinfo->pe_opt.opt64)) + sizeof(struct pe_image_optional_hdr32)), at, OPT_HDR_SIZE_DIFF) != OPT_HDR_SIZE_DIFF) {
            cli_dbgmsg("cli_peheader: Can't read additional optional file header bytes\n");
            ret = CL_EFORMAT;
            goto done;
        }

        stored_opt_hdr_size += OPT_HDR_SIZE_DIFF;
        at += OPT_HDR_SIZE_DIFF;
        peinfo->is_pe32plus = 1;

        opt64 = &(peinfo->pe_opt.opt64);

        peinfo->vep       = EC32(opt64->AddressOfEntryPoint);
        peinfo->hdr_size  = EC32(opt64->SizeOfHeaders);
        peinfo->ndatadirs = EC32(opt64->NumberOfRvaAndSizes);

        if (opts & CLI_PEHEADER_OPT_DBG_PRINT_INFO) {
            cli_dbgmsg("File format: PE32+\n");
            cli_dbgmsg("MajorLinkerVersion: %d\n", opt64->MajorLinkerVersion);
            cli_dbgmsg("MinorLinkerVersion: %d\n", opt64->MinorLinkerVersion);
            cli_dbgmsg("SizeOfCode: 0x%x\n", EC32(opt64->SizeOfCode));
            cli_dbgmsg("SizeOfInitializedData: 0x%x\n", EC32(opt64->SizeOfInitializedData));
            cli_dbgmsg("SizeOfUninitializedData: 0x%x\n", EC32(opt64->SizeOfUninitializedData));
            cli_dbgmsg("AddressOfEntryPoint: 0x%x\n", peinfo->vep);
            cli_dbgmsg("BaseOfCode: 0x%x\n", EC32(opt64->BaseOfCode));
            cli_dbgmsg("SectionAlignment: 0x%x\n", EC32(opt64->SectionAlignment));
            cli_dbgmsg("FileAlignment: 0x%x\n", EC32(opt64->FileAlignment));
            cli_dbgmsg("MajorSubsystemVersion: %d\n", EC16(opt64->MajorSubsystemVersion));
            cli_dbgmsg("MinorSubsystemVersion: %d\n", EC16(opt64->MinorSubsystemVersion));
            cli_dbgmsg("SizeOfImage: 0x%x\n", EC32(opt64->SizeOfImage));
            cli_dbgmsg("SizeOfHeaders: 0x%x\n", peinfo->hdr_size);
            cli_dbgmsg("NumberOfRvaAndSizes: %u\n", peinfo->ndatadirs);
        }

#if HAVE_JSON
        if (opts & CLI_PEHEADER_OPT_COLLECT_JSON) {
            cli_jsonint(pe_json, "MajorLinkerVersion", opt64->MajorLinkerVersion);
            cli_jsonint(pe_json, "MinorLinkerVersion", opt64->MinorLinkerVersion);
            cli_jsonint(pe_json, "SizeOfCode", EC32(opt64->SizeOfCode));
            cli_jsonint(pe_json, "SizeOfInitializedData", EC32(opt64->SizeOfInitializedData));
            cli_jsonint(pe_json, "SizeOfUninitializedData", EC32(opt64->SizeOfUninitializedData));
            cli_jsonint(pe_json, "NumberOfRvaAndSizes", EC32(opt64->NumberOfRvaAndSizes));
            cli_jsonint(pe_json, "MajorSubsystemVersion", EC16(opt64->MajorSubsystemVersion));
            cli_jsonint(pe_json, "MinorSubsystemVersion", EC16(opt64->MinorSubsystemVersion));

            snprintf(jsonbuf, sizeof(jsonbuf), "0x%x", peinfo->vep);
            cli_jsonstr(pe_json, "EntryPoint", jsonbuf);

            snprintf(jsonbuf, sizeof(jsonbuf), "0x%x", EC32(opt64->BaseOfCode));
            cli_jsonstr(pe_json, "BaseOfCode", jsonbuf);

            snprintf(jsonbuf, sizeof(jsonbuf), "0x%x", EC32(opt64->SectionAlignment));
            cli_jsonstr(pe_json, "SectionAlignment", jsonbuf);

            snprintf(jsonbuf, sizeof(jsonbuf), "0x%x", EC32(opt64->FileAlignment));
            cli_jsonstr(pe_json, "FileAlignment", jsonbuf);

            snprintf(jsonbuf, sizeof(jsonbuf), "0x%x", EC32(opt64->SizeOfImage));
            cli_jsonstr(pe_json, "SizeOfImage", jsonbuf);

            snprintf(jsonbuf, sizeof(jsonbuf), "0x%x", peinfo->hdr_size);
            cli_jsonstr(pe_json, "SizeOfHeaders", jsonbuf);
        }
#endif

    } else { /* PE */
        peinfo->is_pe32plus = 0;
        peinfo->vep         = EC32(opt32->AddressOfEntryPoint);
        peinfo->hdr_size    = EC32(opt32->SizeOfHeaders);
        peinfo->ndatadirs   = EC32(opt32->NumberOfRvaAndSizes);

        if (opts & CLI_PEHEADER_OPT_DBG_PRINT_INFO) {
            cli_dbgmsg("File format: PE\n");
            cli_dbgmsg("MajorLinkerVersion: %d\n", opt32->MajorLinkerVersion);
            cli_dbgmsg("MinorLinkerVersion: %d\n", opt32->MinorLinkerVersion);
            cli_dbgmsg("SizeOfCode: 0x%x\n", EC32(opt32->SizeOfCode));
            cli_dbgmsg("SizeOfInitializedData: 0x%x\n", EC32(opt32->SizeOfInitializedData));
            cli_dbgmsg("SizeOfUninitializedData: 0x%x\n", EC32(opt32->SizeOfUninitializedData));
            cli_dbgmsg("AddressOfEntryPoint: 0x%x\n", peinfo->vep);
            cli_dbgmsg("BaseOfCode: 0x%x\n", EC32(opt32->BaseOfCode));
            cli_dbgmsg("SectionAlignment: 0x%x\n", EC32(opt32->SectionAlignment));
            cli_dbgmsg("FileAlignment: 0x%x\n", EC32(opt32->FileAlignment));
            cli_dbgmsg("MajorSubsystemVersion: %d\n", EC16(opt32->MajorSubsystemVersion));
            cli_dbgmsg("MinorSubsystemVersion: %d\n", EC16(opt32->MinorSubsystemVersion));
            cli_dbgmsg("SizeOfImage: 0x%x\n", EC32(opt32->SizeOfImage));
            cli_dbgmsg("SizeOfHeaders: 0x%x\n", peinfo->hdr_size);
            cli_dbgmsg("NumberOfRvaAndSizes: %u\n", peinfo->ndatadirs);
        }

#if HAVE_JSON
        if (opts & CLI_PEHEADER_OPT_COLLECT_JSON) {
            cli_jsonint(pe_json, "MajorLinkerVersion", opt32->MajorLinkerVersion);
            cli_jsonint(pe_json, "MinorLinkerVersion", opt32->MinorLinkerVersion);
            cli_jsonint(pe_json, "SizeOfCode", EC32(opt32->SizeOfCode));
            cli_jsonint(pe_json, "SizeOfInitializedData", EC32(opt32->SizeOfInitializedData));
            cli_jsonint(pe_json, "SizeOfUninitializedData", EC32(opt32->SizeOfUninitializedData));
            cli_jsonint(pe_json, "NumberOfRvaAndSizes", EC32(opt32->NumberOfRvaAndSizes));
            cli_jsonint(pe_json, "MajorSubsystemVersion", EC16(opt32->MajorSubsystemVersion));
            cli_jsonint(pe_json, "MinorSubsystemVersion", EC16(opt32->MinorSubsystemVersion));

            snprintf(jsonbuf, sizeof(jsonbuf), "0x%x", peinfo->vep);
            cli_jsonstr(pe_json, "EntryPoint", jsonbuf);

            snprintf(jsonbuf, sizeof(jsonbuf), "0x%x", EC32(opt32->BaseOfCode));
            cli_jsonstr(pe_json, "BaseOfCode", jsonbuf);

            snprintf(jsonbuf, sizeof(jsonbuf), "0x%x", EC32(opt32->SectionAlignment));
            cli_jsonstr(pe_json, "SectionAlignment", jsonbuf);

            snprintf(jsonbuf, sizeof(jsonbuf), "0x%x", EC32(opt32->FileAlignment));
            cli_jsonstr(pe_json, "FileAlignment", jsonbuf);

            snprintf(jsonbuf, sizeof(jsonbuf), "0x%x", EC32(opt32->SizeOfImage));
            cli_jsonstr(pe_json, "SizeOfImage", jsonbuf);

            snprintf(jsonbuf, sizeof(jsonbuf), "0x%x", peinfo->hdr_size);
            cli_jsonstr(pe_json, "SizeOfHeaders", jsonbuf);
        }
#endif
    }

    salign = (peinfo->is_pe32plus) ? EC32(opt64->SectionAlignment) : EC32(opt32->SectionAlignment);
    falign = (peinfo->is_pe32plus) ? EC32(opt64->FileAlignment) : EC32(opt32->FileAlignment);

    switch (peinfo->is_pe32plus ? EC16(opt64->Subsystem) : EC16(opt32->Subsystem)) {
        case 0:
            subsystem = "Unknown";
            break;
        case 1:
            subsystem = "Native (svc)";
            native    = 1;
            break;
        case 2:
            subsystem = "Win32 GUI";
            break;
        case 3:
            subsystem = "Win32 console";
            break;
        case 5:
            subsystem = "OS/2 console";
            break;
        case 7:
            subsystem = "POSIX console";
            break;
        case 8:
            subsystem = "Native Win9x driver";
            break;
        case 9:
            subsystem = "WinCE GUI";
            break;
        case 10:
            subsystem = "EFI application";
            break;
        case 11:
            subsystem = "EFI driver";
            break;
        case 12:
            subsystem = "EFI runtime driver";
            break;
        case 13:
            subsystem = "EFI ROM image";
            break;
        case 14:
            subsystem = "Xbox";
            break;
        case 16:
            subsystem = "Boot application";
            break;
        default:
            subsystem = "Unknown";
    }

    if (opts & CLI_PEHEADER_OPT_DBG_PRINT_INFO) {
        cli_dbgmsg("Subsystem: %s\n", subsystem);
        cli_dbgmsg("------------------------------------\n");
    }

#if HAVE_JSON
    if (opts & CLI_PEHEADER_OPT_COLLECT_JSON)
        cli_jsonstr(pe_json, "Subsystem", subsystem);
#endif

    if (!native && (!salign || (salign % 0x1000))) {
        cli_dbgmsg("cli_peheader: Bad section alignment\n");
        if (opts & CLI_PEHEADER_OPT_STRICT_ON_PE_ERRORS) {
            ret = CL_EFORMAT;
            goto done;
        }
    }

    if (!native && (!falign || (falign % 0x200))) {
        cli_dbgmsg("cli_peheader: Bad file alignment\n");
        if (opts & CLI_PEHEADER_OPT_STRICT_ON_PE_ERRORS) {
            ret = CL_EFORMAT;
            goto done;
        }
    }

    // Map in the optional header data directories.  The spec defines 16
    // directory entries, but NumberOfRvaAndSizes can be less than that
    // and the Windows loader will pretend that the data directory does
    // not exist. NumberOfRvaAndSizes can be larger than that too, which
    // the Windows loader is OK with.  To populate peinfo->dirs, we will
    // copy in as many data dirs are specified but for a max of 16 (and
    // adjust peinfo->ndatadirs accordingly)

    if (peinfo->ndatadirs > 0x10) {
        cli_dbgmsg("cli_peheader: Encountered NumberOfRvaAndSizes > 16 (suspicious)\n");
    }

    // In the case where we won't fully populate dirs with file data,
    // ensure that the underlying memory is zero so that existing code
    // can interact with peinfo->dirs without using peinfo->ndatadirs
    if (peinfo->ndatadirs < sizeof(peinfo->dirs) / sizeof(peinfo->dirs[0])) {
        memset(&(peinfo->dirs), '\0', sizeof(peinfo->dirs));
    }

    peinfo->ndatadirs = MIN(peinfo->ndatadirs, sizeof(peinfo->dirs) / sizeof(peinfo->dirs[0]));

    data_dirs_size = sizeof(struct pe_image_data_dir) * peinfo->ndatadirs;

    if (opt_hdr_size < (stored_opt_hdr_size + data_dirs_size)) {
        cli_dbgmsg("cli_peheader: SizeOfOptionalHeader too small (doesn't include data dir size)\n");
        ret = CL_EFORMAT;
        goto done;
    }

    read = fmap_readn(map, peinfo->dirs, at, data_dirs_size);
    if ((read == (size_t)-1) || (read != data_dirs_size)) {
        cli_dbgmsg("cli_peheader: Can't read optional file header data dirs\n");
        goto done;
    }
    at += data_dirs_size;

    if (opt_hdr_size != (stored_opt_hdr_size + data_dirs_size)) {
        /* Seek to the end of the long header */
        cli_dbgmsg("cli_peheader: Encountered case where SizeOfOptionalHeader appears bigger than required\n");
        at += opt_hdr_size - (stored_opt_hdr_size + data_dirs_size);
    }

    // TODO This level of processing might not be needed in all cases

    // Sanity checks
    // TODO Also check that salign >= falign
    if (peinfo->hdr_size != PESALIGN(peinfo->hdr_size, salign)) {
        cli_dbgmsg("cli_peheader: SizeOfHeader is not aligned to the SectionAlignment\n");
    }
    if (peinfo->hdr_size != PESALIGN(peinfo->hdr_size, falign)) {
        cli_dbgmsg("cli_peheader: SizeOfHeader is not aligned to the FileAlignment\n");
    }

    // TODO Why align here? -- /* Aligned headers virtual size */
    // hdr_size should already be rounded up
    // to a multiple of the file alignment.
    // TODO in cli_checkpe_fp this aligned to falign, elsewhere it aligned to salign
    peinfo->hdr_size = PESALIGN(peinfo->hdr_size, salign);

    peinfo->sections = (struct cli_exe_section *)cli_calloc(peinfo->nsections, sizeof(struct cli_exe_section));

    if (!peinfo->sections) {
        cli_dbgmsg("cli_peheader: Can't allocate memory for section headers\n");
        goto done;
    }

    section_hdrs = (struct pe_image_section_hdr *)cli_calloc(peinfo->nsections, sizeof(struct pe_image_section_hdr));

    if (!section_hdrs) {
        cli_dbgmsg("cli_peheader: Can't allocate memory for section headers\n");
        goto done;
    }

    read = fmap_readn(map, section_hdrs, at, peinfo->nsections * sizeof(struct pe_image_section_hdr));
    if ((read == (size_t)-1) || (read != peinfo->nsections * sizeof(struct pe_image_section_hdr))) {
        cli_dbgmsg("cli_peheader: Can't read section header - possibly broken PE file\n");
        ret = CL_EFORMAT;
        goto done;
    }
    at += sizeof(struct pe_image_section_hdr) * peinfo->nsections;

    // TODO Verify that this performs correctly
    // TODO I'm not sure why this is necessary since the specification says
    // that PointerToRawData is expected to be a multiple of the file
    // alignment.  Should we report this is as a PE with an error?

    for (i = 0; falign != 0x200 && i < (size_t)peinfo->nsections; i++) {
        /* file alignment fallback mode - blah */
        if (falign && section_hdrs[i].SizeOfRawData && EC32(section_hdrs[i].PointerToRawData) % falign && !(EC32(section_hdrs[i].PointerToRawData) % 0x200)) {
            cli_dbgmsg("cli_peheader: Encountered section with unexpected alignment - triggering fallback mode\n");
            falign = 0x200;
        }
    }

    fsize = (map->len - peinfo->offset);

    // TODO Why do we fix up these alignments?  This shouldn't be needed?
    for (i = 0, section_pe_idx = 0; i < peinfo->nsections; i++, section_pe_idx++) {

        struct cli_exe_section *section          = &(peinfo->sections[i]);
        struct pe_image_section_hdr *section_hdr = &(section_hdrs[i]);
        char sname[9];

        // TODO I don't see any documentation that says VirtualAddress and VirtualSize must be aligned
        section->rva  = PEALIGN(EC32(section_hdr->VirtualAddress), salign);
        section->vsz  = PESALIGN(EC32(section_hdr->VirtualSize), salign);
        section->raw  = PEALIGN(EC32(section_hdr->PointerToRawData), falign);
        section->rsz  = PESALIGN(EC32(section_hdr->SizeOfRawData), falign);
        section->chr  = EC32(section_hdr->Characteristics);
        section->urva = EC32(section_hdr->VirtualAddress); /* Just in case */
        section->uvsz = EC32(section_hdr->VirtualSize);
        section->uraw = EC32(section_hdr->PointerToRawData);
        section->ursz = EC32(section_hdr->SizeOfRawData);

        /* First, if a section exists totally outside of a file, remove the
         * section from the list or zero out it's size. */
        if (section->rsz) { /* Don't bother with virtual only sections */
            if (section->raw >= fsize || section->uraw >= fsize) {
                cli_dbgmsg("cli_peheader: Broken PE file - Section %zu starts or exists beyond the end of file (Offset@ %lu, Total filesize %lu)\n", section_pe_idx, (unsigned long)section->raw, (unsigned long)fsize);

                if (opts & CLI_PEHEADER_OPT_REMOVE_MISSING_SECTIONS) {
                    if (peinfo->nsections == 1) {
                        ret = CL_EFORMAT;
                        goto done;
                    }

                    for (j = i; j < (size_t)(peinfo->nsections - 1); j++)
                        memcpy(&(peinfo->sections[j]), &(peinfo->sections[j + 1]), sizeof(struct cli_exe_section));

                    for (j = i; j < (size_t)(peinfo->nsections - 1); j++)
                        memcpy(&section_hdrs[j], &section_hdrs[j + 1], sizeof(struct pe_image_section_hdr));

                    peinfo->nsections--;

                    // Adjust i since we removed a section and continue on
                    i--;
                    continue;

                } else {
                    section->rsz  = 0;
                    section->ursz = 0;
                }
            } else {

                /* If a section is truncated, adjust it's size value */
                if (!CLI_ISCONTAINED_0_TO(fsize, section->raw, section->rsz)) {
                    cli_dbgmsg("cli_peheader: PE Section %zu raw+rsz extends past the end of the file by %lu bytes\n", section_pe_idx, (section->raw + section->rsz) - fsize);
                    section->rsz = fsize - section->raw;
                }

                if (!CLI_ISCONTAINED_0_TO(fsize, section->uraw, section->ursz)) {
                    cli_dbgmsg("cli_peheader: PE Section %zu uraw+ursz extends past the end of the file by %lu bytes\n", section_pe_idx, (section->uraw + section->ursz) - fsize);
                    section->ursz = fsize - section->uraw;
                }
            }
        }

        strncpy(sname, (char *)section_hdr->Name, 8);
        sname[8] = '\0';

#if HAVE_JSON
        if (opts & CLI_PEHEADER_OPT_COLLECT_JSON) {
            add_section_info(ctx, &peinfo->sections[i]);

            if (cli_json_timeout_cycle_check(ctx, &toval) != CL_SUCCESS) {
                ret = CL_ETIMEOUT;
                goto done;
            }
        }
#endif

        // TODO Why do we do this
        // TODO Should this be done before we dump the json
        if (!section->vsz && section->rsz)
            section->vsz = PESALIGN(section->ursz, salign);

        if (opts & CLI_PEHEADER_OPT_DBG_PRINT_INFO) {
            cli_dbgmsg("Section %zu\n", section_pe_idx);
            cli_dbgmsg("Section name: %s\n", sname);
            cli_dbgmsg("Section data (from headers - in memory)\n");
            cli_dbgmsg("VirtualSize: 0x%x 0x%x\n", section->uvsz, section->vsz);
            cli_dbgmsg("VirtualAddress: 0x%x 0x%x\n", section->urva, section->rva);
            cli_dbgmsg("SizeOfRawData: 0x%x 0x%x\n", section->ursz, section->rsz);
            cli_dbgmsg("PointerToRawData: 0x%x 0x%x\n", section->uraw, section->raw);

            if (section->chr & 0x20) {
                cli_dbgmsg("Section contains executable code\n");
            }

            if (section->vsz < section->rsz) {
                cli_dbgmsg("Section contains free space\n");
                /*
                cli_dbgmsg("Dumping %d bytes\n", section_hdr.SizeOfRawData - section_hdr.VirtualSize);
                ddump(desc, section_hdr.PointerToRawData + section_hdr.VirtualSize, section_hdr.SizeOfRawData - section_hdr.VirtualSize, cli_gentemp(NULL));
                */
            }

            if (section->chr & 0x20000000)
                cli_dbgmsg("Section's memory is executable\n");

            if (section->chr & 0x80000000)
                cli_dbgmsg("Section's memory is writeable\n");

            cli_dbgmsg("------------------------------------\n");
        }

        if (!salign || (section->urva % salign)) { /* Bad section alignment */
            cli_dbgmsg("cli_peheader: Broken PE - section's VirtualAddress is misaligned\n");
            if (opts & CLI_PEHEADER_OPT_STRICT_ON_PE_ERRORS) {
                ret = CL_EFORMAT;
                goto done;
            }
        }

        // TODO should we skip all of these checks if it's an empty
        // section? Why the exception for uraw?
        if (section->urva >> 31 || section->uvsz >> 31 || (section->rsz && section->uraw >> 31) || peinfo->sections[i].ursz >> 31) {
            cli_dbgmsg("cli_peheader: Found PE values with sign bit set\n");
            ret = CL_EFORMAT;
            goto done;
        }

        if (!i) {
            if (section->urva != peinfo->hdr_size) { /* Bad first section RVA */
                cli_dbgmsg("cli_peheader: First section doesn't start immediately after the header\n");
                if (opts & CLI_PEHEADER_OPT_STRICT_ON_PE_ERRORS) {
                    ret = CL_EFORMAT;
                    goto done;
                }
            }

            peinfo->min = section->rva;
            peinfo->max = section->rva + section->rsz;
        } else {
            if (section->urva - peinfo->sections[i - 1].urva != peinfo->sections[i - 1].vsz) { /* No holes, no overlapping, no virtual disorder */
                cli_dbgmsg("cli_peheader: Virtually misplaced section (wrong order, overlapping, non contiguous)\n");
                if (opts & CLI_PEHEADER_OPT_STRICT_ON_PE_ERRORS) {
                    ret = CL_EFORMAT;
                    goto done;
                }
            }

            if (section->rva < peinfo->min)
                peinfo->min = section->rva;

            if (section->rva + section->rsz > peinfo->max) {
                peinfo->max           = section->rva + section->rsz;
                peinfo->overlay_start = section->raw + section->rsz;
            }

            // TODO This case might be possible, which would lead to us
            // mislabelling the overlay
            if (section->raw + section->rsz > peinfo->max) {
                cli_dbgmsg("cli_peheader: Assumption Violated: Last section end RVA isn't tied to the last section\n");
            }
        }
    }

    peinfo->overlay_size = fsize - peinfo->overlay_start;

    // NOTE: For DLLs the entrypoint is likely to be zero
    // TODO Should this offset include peinfo->offset?
    if (!(peinfo->ep = cli_rawaddr(peinfo->vep, peinfo->sections, peinfo->nsections, &err, fsize, peinfo->hdr_size)) && err) {
        cli_dbgmsg("cli_peheader: Broken PE file - Can't map EntryPoint to a file offset\n");
        ret = CL_EFORMAT;
        goto done;
    }

#if HAVE_JSON
    if (opts & CLI_PEHEADER_OPT_COLLECT_JSON) {
        cli_jsonint(pe_json, "EntryPointOffset", peinfo->ep);

        if (cli_json_timeout_cycle_check(ctx, &toval) != CL_SUCCESS) {
            ret = CL_ETIMEOUT;
            goto done;
        }
    }
#endif

    if (opts & CLI_PEHEADER_OPT_DBG_PRINT_INFO) {
        cli_dbgmsg("EntryPoint offset: 0x%x (%d)\n", peinfo->ep, peinfo->ep);
    }

    if (is_dll || peinfo->ndatadirs < 3 || !peinfo->dirs[2].Size)
        peinfo->res_addr = 0;
    else
        peinfo->res_addr = EC32(peinfo->dirs[2].VirtualAddress);

    while (opts & CLI_PEHEADER_OPT_EXTRACT_VINFO &&
           peinfo->ndatadirs >= 3 && peinfo->dirs[2].Size) {
        struct vinfo_list vlist;
        const uint8_t *vptr, *baseptr;
        uint32_t rva, res_sz;

        // TODO This code assumes peinfo->offset == 0, which might not always
        // be the case.
        if (0 != peinfo->offset) {
            cli_dbgmsg("cli_peheader: Assumption Violated: Looking for version info when peinfo->offset != 0\n");
        }

        memset(&vlist, 0, sizeof(vlist));
        findres(0x10, 0xffffffff, map, peinfo, versioninfo_cb, &vlist);
        if (!vlist.count)
            break; /* No version_information */

        if (cli_hashset_init(&peinfo->vinfo, 32, 80)) {
            cli_errmsg("cli_peheader: Unable to init vinfo hashset\n");
            goto done;
        }

        err = 0;
        for (i = 0; i < vlist.count; i++) { /* enum all version_information res - RESUMABLE */
            cli_dbgmsg("cli_peheader: parsing version info @ rva %x (%zu/%u)\n", vlist.rvas[i], i + 1, vlist.count);
            rva = cli_rawaddr(vlist.rvas[i], peinfo->sections, peinfo->nsections, &err, fsize, peinfo->hdr_size);
            if (err)
                continue;

            if (!(vptr = fmap_need_off_once(map, rva, 16)))
                continue;

            baseptr = vptr - rva;
            /* parse resource */
            rva    = cli_readint32(vptr);     /* ptr to version_info */
            res_sz = cli_readint32(vptr + 4); /* sizeof(resource) */
            rva    = cli_rawaddr(rva, peinfo->sections, peinfo->nsections, &err, fsize, peinfo->hdr_size);
            if (err)
                continue;
            if (!(vptr = fmap_need_off_once(map, rva, res_sz)))
                continue;

            while (res_sz > 4) { /* look for version_info - NOT RESUMABLE (expecting exactly one versioninfo) */
                uint32_t vinfo_sz, vinfo_val_sz, got_varfileinfo = 0;

                vinfo_sz = vinfo_val_sz = cli_readint32(vptr);
                vinfo_sz &= 0xffff;
                if (vinfo_sz > res_sz)
                    break; /* the content is larger than the container */

                vinfo_val_sz >>= 16;
                if (vinfo_sz <= 6 + 0x20 + 2 + 0x34 ||
                    vinfo_val_sz != 0x34 ||
                    memcmp(vptr + 6, "V\0S\0_\0V\0E\0R\0S\0I\0O\0N\0_\0I\0N\0F\0O\0\0\0", 0x20) ||
                    (unsigned int)cli_readint32(vptr + 0x28) != 0xfeef04bd) {
                    /* - there should be enough room for the header(6), the key "VS_VERSION_INFO"(20), the padding(2) and the value(34)
                     * - the value should be sizeof(fixedfileinfo)
                     * - the key should match
                     * - there should be some proper magic for fixedfileinfo */
                    break; /* there's no point in looking further */
                }

                /* move to the end of fixedfileinfo where the child elements are located */
                vptr += 6 + 0x20 + 2 + 0x34;
                vinfo_sz -= 6 + 0x20 + 2 + 0x34;

                while (vinfo_sz > 6) { /* look for stringfileinfo - NOT RESUMABLE (expecting at most one stringfileinfo) */
                    uint32_t sfi_sz = cli_readint32(vptr) & 0xffff;

                    if (sfi_sz > vinfo_sz)
                        break; /* the content is larger than the container */

                    if (!got_varfileinfo && sfi_sz > 6 + 0x18 && !memcmp(vptr + 6, "V\0a\0r\0F\0i\0l\0e\0I\0n\0f\0o\0\0\0", 0x18)) {
                        /* skip varfileinfo as it sometimes appear before stringtableinfo */
                        vptr += sfi_sz;
                        vinfo_sz -= sfi_sz;
                        got_varfileinfo = 1;
                        continue;
                    }

                    if (sfi_sz <= 6 + 0x1e || memcmp(vptr + 6, "S\0t\0r\0i\0n\0g\0F\0i\0l\0e\0I\0n\0f\0o\0\0\0", 0x1e)) {
                        /* - there should be enough room for the header(6) and the key "StringFileInfo"(1e)
                         * - the key should match */
                        break; /* this is an implicit hard fail: parent is not resumable */
                    }

                    /* move to the end of stringfileinfo where the child elements are located */
                    vptr += 6 + 0x1e;
                    sfi_sz -= 6 + 0x1e;

                    while (sfi_sz > 6) { /* enum all stringtables - RESUMABLE */
                        uint32_t st_sz           = cli_readint32(vptr) & 0xffff;
                        const uint8_t *next_vptr = vptr + st_sz;
                        uint32_t next_sfi_sz     = sfi_sz - st_sz;

                        if (st_sz > sfi_sz || st_sz <= 24) {
                            /* - the content is larger than the container
                               - there's no room for a stringtables (headers(6) + key(16) + padding(2)) */
                            break; /* this is an implicit hard fail: parent is not resumable */
                        }

                        /* move to the end of stringtable where the child elements are located */
                        vptr += 24;
                        st_sz -= 24;

                        while (st_sz > 6) { /* enum all strings - RESUMABLE */
                            uint32_t s_sz, s_key_sz, s_val_sz;

                            s_sz = (cli_readint32(vptr) & 0xffff) + 3;
                            s_sz &= ~3;
                            if (s_sz > st_sz || s_sz <= 6 + 2 + 8) {
                                /* - the content is larger than the container
                                 * - there's no room for a minimal string
                                 * - there's no room for the value */
                                st_sz  = 0;
                                sfi_sz = 0;
                                break; /* force a hard fail */
                            }

                            /* ~wcstrlen(key) */
                            for (s_key_sz = 6; s_key_sz + 1 < s_sz; s_key_sz += 2) {
                                if (vptr[s_key_sz] || vptr[s_key_sz + 1])
                                    continue;

                                s_key_sz += 2;
                                break;
                            }

                            s_key_sz += 3;
                            s_key_sz &= ~3;

                            if (s_key_sz >= s_sz) {
                                /* key overflow */
                                vptr += s_sz;
                                st_sz -= s_sz;
                                continue;
                            }

                            s_val_sz = s_sz - s_key_sz;
                            s_key_sz -= 6;

                            if (s_val_sz <= 2) {
                                /* skip unset value */
                                vptr += s_sz;
                                st_sz -= s_sz;
                                continue;
                            }

                            if (cli_hashset_addkey(&peinfo->vinfo, (uint32_t)(vptr - baseptr + 6))) {
                                cli_errmsg("cli_peheader: Unable to add rva to vinfo hashset\n");
                                goto done;
                            }

                            if (cli_debug_flag) {
                                char *k, *v, *s;

                                /* FIXME: skip too long strings */
                                k = cli_utf16toascii((const char *)vptr + 6, s_key_sz);
                                if (k) {
                                    v = cli_utf16toascii((const char *)vptr + s_key_sz + 6, s_val_sz);
                                    if (v) {
                                        s = cli_str2hex((const char *)vptr + 6, s_key_sz + s_val_sz);
                                        if (s) {
                                            cli_dbgmsg("VersionInfo (%x): '%s'='%s' - VI:%s\n", (uint32_t)(vptr - baseptr + 6), k, v, s);
                                            free(s);
                                        }
                                        free(v);
                                    }
                                    free(k);
                                }
                            }
                            vptr += s_sz;
                            st_sz -= s_sz;
                        } /* enum all strings - RESUMABLE */
                        vptr   = next_vptr;
                        sfi_sz = next_sfi_sz * (sfi_sz != 0);
                    } /* enum all stringtables - RESUMABLE */
                    break;
                } /* look for stringfileinfo - NOT RESUMABLE */
                break;
            } /* look for version_info - NOT RESUMABLE */
        }     /* enum all version_information res - RESUMABLE */
        break;
    } /* while(dirs[2].Size) */

    // Do final preperations for peinfo to be passed back
    peinfo->is_dll = is_dll;

    ret = CL_SUCCESS;

done:
    /* In the fail case, peinfo will get destroyed by the caller */

    if (NULL != section_hdrs) {
        free(section_hdrs);
    }

    return ret;
}

// TODO We should sort based on VirtualAddress instead, since PointerToRawData
// will be zero for sections where SizeOfRawData is zero.  This also aligns
// with what tools like pefile do.
static int sort_sects(const void *first, const void *second)
{
    const struct cli_exe_section *a = first, *b = second;
    return (a->raw - b->raw);
}

/* Check the given PE file for an authenticode signature and return whether
 * the signature is valid.  There are two cases that this function should
 * handle:
 * - A PE file has an embedded Authenticode section
 * - The PE file has no embedded Authenticode section but is covered by a
 *   catalog file that was loaded in via a -d
 *
 * If peinfo is NULL, one will be created internally and used
 *
 * CL_VERIFIED will be returned if the file was trusted based on its
 * signature.  CL_VIRUS will be returned if the file was blocked based on
 * its signature.  Otherwise, a cl_error_t error value will be returned.
 *
 * If CL_VIRUS is returned, cli_append_virus will get called, adding the
 * name associated with the block list CRB rules to the list of found viruses.*/
cl_error_t cli_check_auth_header(cli_ctx *ctx, struct cli_exe_info *peinfo)
{
    size_t at;
    unsigned int i, j, hlen;
    size_t fsize;
    fmap_t *map   = ctx->fmap;
    void *hashctx = NULL;
    struct pe_certificate_hdr cert_hdr;
    struct cli_mapped_region *regions = NULL;
    unsigned int nregions;
    cl_error_t ret = CL_EVERIFY;
    uint8_t authsha[SHA256_HASH_SIZE];
    uint32_t sec_dir_offset;
    uint32_t sec_dir_size;
    struct cli_exe_info _peinfo;

    // If Authenticode parsing has been disabled via DCONF or an engine
    // option, then don't continue on.
    if (!(DCONF & PE_CONF_CERTS))
        return CL_EVERIFY;

    if (ctx->engine->engine_options & ENGINE_OPTIONS_DISABLE_PE_CERTS)
        return CL_EVERIFY;

    // If peinfo is NULL, initialize one.  This makes it so that this function
    // can be used easily by sigtool
    if (NULL == peinfo) {
        peinfo = &_peinfo;
        cli_exe_info_init(peinfo, 0);

        if (CL_SUCCESS != cli_peheader(ctx->fmap, peinfo, CLI_PEHEADER_OPT_NONE, NULL)) {
            cli_exe_info_destroy(peinfo);
            return CL_EFORMAT;
        }
    }

    sec_dir_offset = EC32(peinfo->dirs[4].VirtualAddress);
    sec_dir_size   = EC32(peinfo->dirs[4].Size);

    // As an optimization, check the security DataDirectory here and if
    // it's less than 8-bytes (and we aren't relying on this code to compute
    // the section hashes), bail out if we don't have any Authenticode hashes
    // loaded from .cat files. The value 2 in these calls is the sentinel value
    // for the 'PE' .cat Authenticode hash file type.
    if (sec_dir_size < 8 &&
        !cli_hm_have_size(ctx->engine->hm_fp, CLI_HASH_SHA1, 2) &&
        !cli_hm_have_size(ctx->engine->hm_fp, CLI_HASH_SHA256, 2)) {
        ret = CL_BREAK;
        goto finish;
    }
    fsize = map->len;

    // We'll build a list of the regions that need to be hashed and pass it to
    // asn1_check_mscat to do hash verification there (the hash algorithm is
    // specified in the PKCS7 structure).  We need to hash up to 4 regions
    regions = (struct cli_mapped_region *)cli_calloc(4, sizeof(struct cli_mapped_region));
    if (!regions) {
        ret = CL_EMEM;
        goto finish;
    }
    nregions = 0;

#define add_chunk_to_hash_list(_offset, _size) \
    do {                                       \
        regions[nregions].offset = (_offset);  \
        regions[nregions].size   = (_size);    \
        nregions++;                            \
    } while (0)

    // Pretty much every case below should return CL_EFORMAT
    ret = CL_EFORMAT;

    /* MZ to checksum */
    at   = 0;
    hlen = peinfo->e_lfanew + sizeof(struct pe_image_file_hdr) + (peinfo->is_pe32plus ? offsetof(struct pe_image_optional_hdr64, CheckSum) : offsetof(struct pe_image_optional_hdr32, CheckSum));
    add_chunk_to_hash_list(0, hlen);
    at = hlen + 4;

    /* Checksum to security */
    if (peinfo->is_pe32plus)
        hlen = sizeof(struct pe_image_optional_hdr64) - offsetof(struct pe_image_optional_hdr64, CheckSum) - 4;
    else
        hlen = sizeof(struct pe_image_optional_hdr32) - offsetof(struct pe_image_optional_hdr32, CheckSum) - 4;

    hlen += sizeof(struct pe_image_data_dir) * 4;
    add_chunk_to_hash_list(at, hlen);
    at += hlen + 8;

    if (at > peinfo->hdr_size) {
        goto finish;
    }

    if (sec_dir_offset) {

        // Verify that we have all the bytes we expect in the authenticode sig
        // and that the certificate table is the last thing in the file
        // (according to the MS13-098 bulletin, this is a requirement)
        if (fsize != sec_dir_size + sec_dir_offset) {
            cli_dbgmsg("cli_check_auth_header: expected authenticode data at the end of the file\n");
            goto finish;
        }

        // Hash everything else up to the start of the security section. Allow
        // the case where at == sec_dir_offset without adding another region
        // to hash, since this could technically be valid (although I haven't
        // verified this).
        if (at < sec_dir_offset) {
            hlen = sec_dir_offset - at;
            add_chunk_to_hash_list(at, hlen);
        } else if (at > sec_dir_offset) {
            cli_dbgmsg("cli_check_auth_header: security directory offset appears to overlap with the PE header\n");
            goto finish;
        }

        // Parse the security directory header

        if (fmap_readn(map, &cert_hdr, sec_dir_offset, sizeof(cert_hdr)) != sizeof(cert_hdr)) {
            goto finish;
        }

        if (EC16(cert_hdr.revision) != WIN_CERT_REV_2) {
            cli_dbgmsg("cli_check_auth_header: unsupported authenticode data revision\n");
            goto finish;
        }

        if (EC16(cert_hdr.type) != WIN_CERT_TYPE_PKCS7) {
            cli_dbgmsg("cli_check_auth_header: unsupported authenticode data type\n");
            goto finish;
        }

        hlen = sec_dir_size;

        if (EC32(cert_hdr.length) != hlen) {
            /* This is the case that MS13-098 aimed to address, but it got
             * pushback to where the fix (not allowing additional, non-zero
             * bytes in the security directory) is now opt-in via a registry
             * key.  Given that most machines will treat these binaries as
             * valid, we'll still parse the signature and just trust that
             * our trust signatures are tailored enough to where any
             * instances of this are reasonable (for instance, I saw one
             * binary that appeared to use this to embed a license key.) */
            cli_dbgmsg("cli_check_auth_header: MS13-098 violation detected, but continuing on to verify certificate\n");
        }

        at = sec_dir_offset + sizeof(cert_hdr);
        hlen -= sizeof(cert_hdr);

        ret = asn1_check_mscat((struct cl_engine *)(ctx->engine), map, at, hlen, regions, nregions, ctx);

        if (CL_VERIFIED == ret) {
            // We validated the embedded signature.  Hooray!
            goto finish;
        } else if (CL_VIRUS == ret) {
            // A block list rule hit - don't continue on to check hm_fp for a match
            goto finish;
        }

        // Otherwise, we still need to check to see whether this file is
        // covered by a .cat file (it's common these days for driver files
        // to have .cat files covering PEs with embedded signatures)

    } else {

        // Hash everything else
        if (at < fsize) {
            hlen = fsize - at;
            add_chunk_to_hash_list(at, hlen);
        }
    }

    // At this point we should compute the SHA1 authenticode hash to see
    // whether we've had any hashes added from external catalog files
    static const struct supported_hashes {
        const cli_hash_type_t hashtype;
        const char *hashctx_name;
    } supported_hashes[] = {
        {CLI_HASH_SHA1, "sha1"},
        {CLI_HASH_SHA256, "sha256"},
    };

    for (i = 0; i < (sizeof(supported_hashes) / sizeof(supported_hashes[0])); i++) {
        const cli_hash_type_t hashtype = supported_hashes[i].hashtype;
        const char *hashctx_name       = supported_hashes[i].hashctx_name;

        if (!cli_hm_have_size(ctx->engine->hm_fp, hashtype, 2)) {
            continue;
        }

        hashctx = cl_hash_init(hashctx_name);

        if (NULL == hashctx) {
            ret = CL_EMEM;
            goto finish;
        }

        for (j = 0; j < nregions; j++) {
            const uint8_t *hptr;
            if (0 == regions[j].size) {
                continue;
            }
            if (!(hptr = fmap_need_off_once(map, regions[j].offset, regions[j].size))) {
                break;
            }

            cl_update_hash(hashctx, hptr, regions[j].size);
        }

        if (j != nregions) {
            goto finish;
        }

        cl_finish_hash(hashctx, authsha);
        hashctx = NULL;

        if (cli_hm_scan(authsha, 2, NULL, ctx->engine->hm_fp, hashtype) == CL_VIRUS) {
            cli_dbgmsg("cli_check_auth_header: PE file trusted by catalog file (%s)\n", hashctx_name);
            ret = CL_VERIFIED;
            goto finish;
        }
    }

    ret = CL_EVERIFY;

finish:
    if (NULL != hashctx) {
        cl_hash_destroy(hashctx);
    }

    if (NULL != regions) {
        free(regions);
    }

    // If we created the peinfo, then destroy it.  Otherwise we don't own it
    if (&_peinfo == peinfo) {
        cli_exe_info_destroy(peinfo);
    }
    return ret;
}

/* Print out either the MD5, SHA1, or SHA256 associated with the imphash or
 * the individual sections. Also, this function computes the hashes of each
 * section (sorted based on the RVAs of the sections) if hashes is non-NULL.
 *
 * If the section hashes are to be computed and returned, this function
 * allocates memory for the section hashes, and it's up to the caller to free
 * it.  hashes->sections will be initialized to NULL at the beginning of the
 * function, and if after the call it's value is non-NULL, the memory should be
 * freed.  Furthermore, if hashes->sections is non-NULL, the hashes can assume
 * to be valid regardless of the return code.
 *
 * Also, a few other notes:
 *  - If a section has a virtual size of zero, it's corresponding hash value
 *    will not be computed and the hash contents will be all zeroes.
 *  - If a section extends beyond the end of the file, the section data and
 *    length will be truncated, and the hash generated accordingly
 *  - If a section exists completely outside of the file, it won't be included
 *    in the list of sections, and nsections will be adjusted accordingly.
 */
cl_error_t cli_genhash_pe(cli_ctx *ctx, unsigned int class, int type, stats_section_t *hashes)
{
    unsigned int i;
    struct cli_exe_info _peinfo;
    struct cli_exe_info *peinfo = &_peinfo;

    unsigned char *hash, *hashset[CLI_HASH_AVAIL_TYPES];
    int genhash[CLI_HASH_AVAIL_TYPES];
    int hlen = 0;

    if (hashes) {
        hashes->sections = NULL;

        if (class != CL_GENHASH_PE_CLASS_SECTION || type != 1) {
            cli_dbgmsg("`hashes` can only be populated with MD5 PE section data\n");
            return CL_EARG;
        }
    }

    if (class >= CL_GENHASH_PE_CLASS_LAST)
        return CL_EARG;

    // TODO see if peinfo can be passed in (or lives in ctx or something) and
    // if so, use that to avoid having to re-parse the header
    cli_exe_info_init(peinfo, 0);

    if (cli_peheader(ctx->fmap, peinfo, CLI_PEHEADER_OPT_NONE, NULL) != CL_SUCCESS) {
        cli_exe_info_destroy(peinfo);
        return CL_EFORMAT;
    }

    cli_qsort(peinfo->sections, peinfo->nsections, sizeof(*(peinfo->sections)), sort_sects);

    /* pick hashtypes to generate */
    memset(genhash, 0, sizeof(genhash));
    memset(hashset, 0, sizeof(hashset));
    switch (type) {
        case 1:
            genhash[CLI_HASH_MD5] = 1;
            hlen                  = hashlen[CLI_HASH_MD5];
            hash = hashset[CLI_HASH_MD5] = cli_calloc(hlen, sizeof(char));
            break;
        case 2:
            genhash[CLI_HASH_SHA1] = 1;
            hlen                   = hashlen[CLI_HASH_SHA1];
            hash = hashset[CLI_HASH_SHA1] = cli_calloc(hlen, sizeof(char));
            break;
        default:
            genhash[CLI_HASH_SHA256] = 1;
            hlen                     = hashlen[CLI_HASH_SHA256];
            hash = hashset[CLI_HASH_SHA256] = cli_calloc(hlen, sizeof(char));
            break;
    }

    if (!hash) {
        cli_errmsg("cli_genhash_pe: cli_malloc failed!\n");
        cli_exe_info_destroy(peinfo);
        return CL_EMEM;
    }

    if (hashes) {
        hashes->nsections = peinfo->nsections;
        hashes->sections  = cli_calloc(peinfo->nsections, sizeof(struct cli_section_hash));

        if (!(hashes->sections)) {
            cli_exe_info_destroy(peinfo);
            free(hash);
            return CL_EMEM;
        }
    }

    if (class == CL_GENHASH_PE_CLASS_SECTION) {
        char *dstr;

        for (i = 0; i < peinfo->nsections; i++) {
            /* Generate hashes */
            if (cli_hashsect(ctx->fmap, &peinfo->sections[i], hashset, genhash, genhash) == 1) {
                if (cli_debug_flag) {
                    dstr = cli_str2hex((char *)hash, hlen);
                    cli_dbgmsg("Section{%u}: %u:%s\n", i, peinfo->sections[i].rsz, dstr ? (char *)dstr : "(NULL)");
                    if (dstr != NULL) {
                        free(dstr);
                    }
                }
                if (hashes) {
                    memcpy(hashes->sections[i].md5, hash, sizeof(hashes->sections[i].md5));
                    hashes->sections[i].len = peinfo->sections[i].rsz;
                }
            } else if (peinfo->sections[i].rsz) {
                cli_dbgmsg("Section{%u}: failed to generate hash for section\n", i);
            } else {
                cli_dbgmsg("Section{%u}: section contains no data\n", i);
            }
        }
    } else if (class == CL_GENHASH_PE_CLASS_IMPTBL) {
        char *dstr;
        uint32_t impsz = 0;
        cl_error_t ret;

        /* Generate hash */
        ret = hash_imptbl(ctx, hashset, &impsz, genhash, peinfo);
        if (ret == CL_SUCCESS) {
            if (cli_debug_flag) {
                dstr = cli_str2hex((char *)hash, hlen);
                cli_dbgmsg("Imphash: %s:%u\n", dstr ? (char *)dstr : "(NULL)", impsz);
                if (dstr != NULL) {
                    free(dstr);
                }
            }
        } else {
            cli_dbgmsg("Imphash: failed to generate hash for import table (%d)\n", ret);
        }
    } else {
        cli_dbgmsg("cli_genhash_pe: unknown pe genhash class: %u\n", class);
    }

    free(hash);
    cli_exe_info_destroy(peinfo);
    return CL_SUCCESS;
}
