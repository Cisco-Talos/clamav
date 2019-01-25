/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Alberto Wu, Tomasz Kojm
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

#define DCONF ctx->dconf->pe

#define PE_IMAGE_DOS_SIGNATURE      0x5a4d          /* MZ */
#define PE_IMAGE_DOS_SIGNATURE_OLD  0x4d5a          /* ZM */
#define PE_IMAGE_NT_SIGNATURE       0x00004550
#define PE32_SIGNATURE              0x010b
#define PE32P_SIGNATURE             0x020b

#define optional_hdr64 pe_opt.opt64
#define optional_hdr32 pe_opt.opt32

#define UPX_NRV2B "\x11\xdb\x11\xc9\x01\xdb\x75\x07\x8b\x1e\x83\xee\xfc\x11\xdb\x11\xc9\x11\xc9\x75\x20\x41\x01\xdb"
#define UPX_NRV2D "\x83\xf0\xff\x74\x78\xd1\xf8\x89\xc5\xeb\x0b\x01\xdb\x75\x07\x8b\x1e\x83\xee\xfc\x11\xdb\x11\xc9"
#define UPX_NRV2E "\xeb\x52\x31\xc9\x83\xe8\x03\x72\x11\xc1\xe0\x08\x8a\x06\x46\x83\xf0\xff\x74\x75\xd1\xf8\x89\xc5"
#define UPX_LZMA1_FIRST  "\x56\x83\xc3\x04\x53\x50\xc7\x03"
#define UPX_LZMA1_SECOND "\x90\x90\x90\x55\x57\x56\x53\x83"
#define UPX_LZMA0 "\x56\x83\xc3\x04\x53\x50\xc7\x03\x03\x00\x00\x00\x90\x90\x90\x55\x57\x56\x53\x83"
#define UPX_LZMA2 "\x56\x83\xc3\x04\x53\x50\xc7\x03\x03\x00\x02\x00\x90\x90\x90\x90\x90\x55\x57\x56"

#define PE_MAXNAMESIZE 256
#define PE_MAXIMPORTS  1024
// TODO On Vista and above, up to 65535 sections are allowed.  Make sure
// that using this lower limit from XP is acceptable in all cases
#define PE_MAXSECTIONS  96

#define EC64(x) ((uint64_t)cli_readint64(&(x))) /* Convert little endian to host */
#define EC32(x) ((uint32_t)cli_readint32(&(x)))
#define EC16(x) ((uint16_t)cli_readint16(&(x)))
/* lower and upper boundary alignment (size vs offset) */
#define PEALIGN(o,a) (((a))?(((o)/(a))*(a)):(o))
#define PESALIGN(o,a) (((a))?(((o)/(a)+((o)%(a)!=0))*(a)):(o))

#define CLI_UNPSIZELIMITS(NAME,CHK) \
if(cli_checklimits(NAME, ctx, (CHK), 0, 0)!=CL_CLEAN) { \
    free(exe_sections);                                 \
    return CL_CLEAN;                                    \
}

#define CLI_UNPTEMP(NAME,FREEME) \
if(!(tempfile = cli_gentemp(ctx->engine->tmpdir))) { \
    cli_multifree FREEME; \
    return CL_EMEM; \
} \
if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) { \
    cli_dbgmsg(NAME": Can't create file %s\n", tempfile); \
    free(tempfile); \
    cli_multifree FREEME; \
    return CL_ECREAT; \
}

#define CLI_TMPUNLK() if(!ctx->engine->keeptmp) { \
    if (cli_unlink(tempfile)) { \
        free(tempfile); \
        return CL_EUNLINK; \
    } \
}

#ifdef HAVE__INTERNAL__SHA_COLLECT
#define SHA_OFF do { ctx->sha_collect = -1; } while(0)
#define SHA_RESET do { ctx->sha_collect = sha_collect; } while(0)
#else
#define SHA_OFF do {} while(0)
#define SHA_RESET do {} while(0)
#endif

#define FSGCASE(NAME,FREESEC) \
    case 0: /* Unpacked and NOT rebuilt */ \
    cli_dbgmsg(NAME": Successfully decompressed\n"); \
    close(ndesc); \
    if (cli_unlink(tempfile)) { \
        free(exe_sections); \
        free(tempfile); \
        FREESEC; \
        return CL_EUNLINK; \
    } \
    free(tempfile); \
    FREESEC; \
    found = 0; \
    upx_success = 1; \
    break; /* FSG ONLY! - scan raw data after upx block */

#define SPINCASE() \
    case 2: \
    free(spinned); \
    close(ndesc); \
    if (cli_unlink(tempfile)) { \
        free(exe_sections); \
        free(tempfile); \
        return CL_EUNLINK; \
    } \
    cli_dbgmsg("PESpin: Size exceeded\n"); \
    free(tempfile); \
    break; \

#define CLI_UNPRESULTS_(NAME,FSGSTUFF,EXPR,GOOD,FREEME) \
    switch(EXPR) { \
    case GOOD: /* Unpacked and rebuilt */ \
        if(ctx->engine->keeptmp) \
            cli_dbgmsg(NAME": Unpacked and rebuilt executable saved in %s\n", tempfile); \
        else \
            cli_dbgmsg(NAME": Unpacked and rebuilt executable\n"); \
        cli_multifree FREEME; \
        free(exe_sections); \
        lseek(ndesc, 0, SEEK_SET); \
        cli_dbgmsg("***** Scanning rebuilt PE file *****\n"); \
        SHA_OFF; \
        if(cli_magic_scandesc(ndesc, tempfile, ctx) == CL_VIRUS) { \
            close(ndesc); \
            CLI_TMPUNLK(); \
            free(tempfile); \
            SHA_RESET; \
            return CL_VIRUS; \
        } \
        SHA_RESET; \
        close(ndesc); \
        CLI_TMPUNLK(); \
        free(tempfile); \
        return CL_CLEAN; \
\
FSGSTUFF; \
\
    default: \
        cli_dbgmsg(NAME": Unpacking failed\n"); \
        close(ndesc); \
        if (cli_unlink(tempfile)) { \
            free(exe_sections); \
            free(tempfile); \
            cli_multifree FREEME; \
            return CL_EUNLINK; \
        } \
        cli_multifree FREEME; \
        free(tempfile); \
    }


#define CLI_UNPRESULTS(NAME,EXPR,GOOD,FREEME) CLI_UNPRESULTS_(NAME,(void)0,EXPR,GOOD,FREEME)
#define CLI_UNPRESULTSFSG1(NAME,EXPR,GOOD,FREEME) CLI_UNPRESULTS_(NAME,FSGCASE(NAME,free(sections)),EXPR,GOOD,FREEME)
#define CLI_UNPRESULTSFSG2(NAME,EXPR,GOOD,FREEME) CLI_UNPRESULTS_(NAME,FSGCASE(NAME,(void)0),EXPR,GOOD,FREEME)

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

#define PE_IMAGEDIR_ORDINAL_FLAG32  0x80000000
#define PE_IMAGEDIR_ORDINAL_FLAG64  0x8000000000000000L

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

static void cli_multifree(void *f, ...) {
    void *ff;
    va_list ap;
    free(f);
    va_start(ap, f);
    while((ff=va_arg(ap, void*))) free(ff);
    va_end(ap);
}

struct vinfo_list {
    uint32_t rvas[16];
    unsigned int count;
};

static int versioninfo_cb(void *opaque, uint32_t type, uint32_t name, uint32_t lang, uint32_t rva) {
    struct vinfo_list *vlist = (struct vinfo_list *)opaque;

    cli_dbgmsg("versioninfo_cb: type: %x, name: %x, lang: %x, rva: %x\n", type, name, lang, rva);
    vlist->rvas[vlist->count] = rva;
    if(++vlist->count == sizeof(vlist->rvas) / sizeof(vlist->rvas[0]))
        return 1;
    return 0;
}


uint32_t cli_rawaddr(uint32_t rva, const struct cli_exe_section *shp, uint16_t nos, unsigned int *err, size_t fsize, uint32_t hdr_size)
{
    int i, found = 0;
    uint32_t ret;

    if (rva<hdr_size) { /* Out of section EP - mapped to imagebase+rva */
        if (rva >= fsize) {
            *err=1;
            return 0;
        }

        *err=0;
        return rva;
    }

    for(i = nos-1; i >= 0; i--) {
        if(shp[i].rsz && shp[i].rva <= rva && shp[i].rsz > rva - shp[i].rva) {
            found = 1;
            break;
        }
    }

    if(!found) {
        *err = 1;
        return 0;
    }

    ret = rva - shp[i].rva + shp[i].raw;
    *err = 0;
    return ret;
}

/* 
   void findres(uint32_t by_type, uint32_t by_name, uint32_t res_rva, cli_ctx *ctx, struct cli_exe_section *exe_sections, uint16_t nsections, uint32_t hdr_size, int (*cb)(void *, uint32_t, uint32_t, uint32_t, uint32_t), void *opaque)
   callback based res lookup

   by_type: lookup type
   by_name: lookup name or (unsigned)-1 to look for any name
   res_rva: base resource rva (i.e. dirs[2].VirtualAddress)
   ctx, exe_sections, nsections, hdr_size: same as in scanpe
   cb: the callback function executed on each successful match
   opaque: an opaque pointer passed to the callback

   the callback proto is
   int pe_res_cballback (void *opaque, uint32_t type, uint32_t name, uint32_t lang, uint32_t rva);
   the callback shall return 0 to continue the lookup or 1 to abort
*/
void findres(uint32_t by_type, uint32_t by_name, uint32_t res_rva, fmap_t *map, struct cli_exe_section *exe_sections, uint16_t nsections, uint32_t hdr_size, int (*cb)(void *, uint32_t, uint32_t, uint32_t, uint32_t), void *opaque) {
    unsigned int err = 0;
    uint32_t type, type_offs, name, name_offs, lang, lang_offs;
    const uint8_t *resdir, *type_entry, *name_entry, *lang_entry ;
    uint16_t type_cnt, name_cnt, lang_cnt;

    if (!(resdir = fmap_need_off_once(map, cli_rawaddr(res_rva, exe_sections, nsections, &err, map->len, hdr_size), 16)) || err)
        return;

    type_cnt = (uint16_t)cli_readint16(resdir+12);
    type_entry = resdir+16;
    if(!(by_type>>31)) {
        type_entry += type_cnt * 8;
        type_cnt = (uint16_t)cli_readint16(resdir+14);
    }

    while(type_cnt--) {
        if(!fmap_need_ptr_once(map, type_entry, 8))
            return;
        type = cli_readint32(type_entry);
        type_offs = cli_readint32(type_entry+4);
        if(type == by_type && (type_offs>>31)) {
            type_offs &= 0x7fffffff;
            if (!(resdir = fmap_need_off_once(map, cli_rawaddr(res_rva + type_offs, exe_sections, nsections, &err, map->len, hdr_size), 16)) || err)
                return;

            name_cnt = (uint16_t)cli_readint16(resdir+12);
            name_entry = resdir+16;
            if(by_name == 0xffffffff)
                name_cnt += (uint16_t)cli_readint16(resdir+14);
            else if(!(by_name>>31)) {
                name_entry += name_cnt * 8;
                name_cnt = (uint16_t)cli_readint16(resdir+14);
            }
            while(name_cnt--) {
                if(!fmap_need_ptr_once(map, name_entry, 8))
                    return;
                name = cli_readint32(name_entry);
                name_offs = cli_readint32(name_entry+4);
                if((by_name == 0xffffffff || name == by_name) && (name_offs>>31)) {
                    name_offs &= 0x7fffffff;
                    if (!(resdir = fmap_need_off_once(map, cli_rawaddr(res_rva + name_offs, exe_sections, nsections, &err, map->len, hdr_size), 16)) || err)
                        return;

                    lang_cnt = (uint16_t)cli_readint16(resdir+12) + (uint16_t)cli_readint16(resdir+14);
                    lang_entry = resdir+16;
                    while(lang_cnt--) {
                        if(!fmap_need_ptr_once(map, lang_entry, 8))
                            return;
                        lang = cli_readint32(lang_entry);
                        lang_offs = cli_readint32(lang_entry+4);
                        if(!(lang_offs >>31)) {
                            if(cb(opaque, type, name, lang, res_rva + lang_offs))
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

static void cli_parseres_special(uint32_t base, uint32_t rva, fmap_t *map, struct cli_exe_section *exe_sections, uint16_t nsections, size_t fsize, uint32_t hdr_size, unsigned int level, uint32_t type, unsigned int *maxres, struct swizz_stats *stats) {
    unsigned int err = 0, i;
    const uint8_t *resdir;
    const uint8_t *entry, *oentry;
    uint16_t named, unnamed;
    uint32_t rawaddr = cli_rawaddr(rva, exe_sections, nsections, &err, fsize, hdr_size);
    uint32_t entries;

    if(level>2 || !*maxres) return;
    *maxres-=1;
    if(err || !(resdir = fmap_need_off_once(map, rawaddr, 16)))
            return;
    named = (uint16_t)cli_readint16(resdir+12);
    unnamed = (uint16_t)cli_readint16(resdir+14);

    entries = /*named+*/unnamed;
    if (!entries)
            return;
    rawaddr += named*8; /* skip named */
    /* this is just used in a heuristic detection, so don't give error on failure */
    if(!(entry = fmap_need_off(map, rawaddr+16, entries*8))) {
            cli_dbgmsg("cli_parseres_special: failed to read resource directory at:%lu\n", (unsigned long)rawaddr+16);
            return;
    }
    oentry = entry;
    /*for (i=0; i<named; i++) {
        uint32_t id, offs;
        id = cli_readint32(entry);
        offs = cli_readint32(entry+4);
        if(offs>>31)
            cli_parseres( base, base + (offs&0x7fffffff), srcfd, exe_sections, nsections, fsize, hdr_size, level+1, type, maxres, stats);
        entry+=8;
    }*/
    for (i=0; i<unnamed; i++, entry += 8) {
        uint32_t id, offs;
        if (stats->errors >= SWIZZ_MAXERRORS) {
            cli_dbgmsg("cli_parseres_special: resources broken, ignoring\n");
            return;
        }
        id = cli_readint32(entry)&0x7fffffff;
        if(level==0) {
                type = 0;
                switch(id) {
                        case 4: /* menu */
                        case 5: /* dialog */
                        case 6: /* string */
                        case 11:/* msgtable */
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
        offs = cli_readint32(entry+4);
        if(offs>>31)
                cli_parseres_special(base, base + (offs&0x7fffffff), map, exe_sections, nsections, fsize, hdr_size, level+1, type, maxres, stats);
        else {
                        offs = cli_readint32(entry+4);
                        rawaddr = cli_rawaddr(base + offs, exe_sections, nsections, &err, fsize, hdr_size);
                        if (!err && (resdir = fmap_need_off_once(map, rawaddr, 16))) {
                                uint32_t isz = cli_readint32(resdir+4);
                                const uint8_t *str;
                                rawaddr = cli_rawaddr(cli_readint32(resdir), exe_sections, nsections, &err, fsize, hdr_size);
                                if (err || !isz || isz >= fsize || rawaddr+isz >= fsize) {
                                        cli_dbgmsg("cli_parseres_special: invalid resource table entry: %lu + %lu\n", 
                                                        (unsigned long)rawaddr, 
                                                        (unsigned long)isz);
                                        stats->errors++;
                                        continue;
                                }
                                if ((id&0xff) != 0x09) /* english res only */
                                    continue;
                                if((str = fmap_need_off_once(map, rawaddr, isz)))
                                        cli_detect_swizz_str(str, isz, stats, type);
                        }
        }
    }
    fmap_unneed_ptr(map, oentry, entries*8);
}

static unsigned int cli_hashsect(fmap_t *map, struct cli_exe_section *s, unsigned char **digest, int * foundhash, int * foundwild)
{
    const void *hashme;

    if (s->rsz > CLI_MAX_ALLOCATION) {
        cli_dbgmsg("cli_hashsect: skipping hash calculation for too big section\n");
        return 0;
    }

    if(!s->rsz) return 0;
    if(!(hashme=fmap_need_off_once(map, s->raw, s->rsz))) {
        cli_dbgmsg("cli_hashsect: unable to read section data\n");
        return 0;
    }

    if(foundhash[CLI_HASH_MD5] || foundwild[CLI_HASH_MD5])
        cl_hash_data("md5", hashme, s->rsz, digest[CLI_HASH_MD5], NULL);
    if(foundhash[CLI_HASH_SHA1] || foundwild[CLI_HASH_SHA1])
        cl_sha1(hashme, s->rsz, digest[CLI_HASH_SHA1], NULL);
    if(foundhash[CLI_HASH_SHA256] || foundwild[CLI_HASH_SHA256])
        cl_sha256(hashme, s->rsz, digest[CLI_HASH_SHA256], NULL);

    return 1;
}

/* check hash section sigs */
static int scan_pe_mdb (cli_ctx * ctx, struct cli_exe_section *exe_section)
{
    struct cli_matcher * mdb_sect = ctx->engine->hm_mdb;
    unsigned char * hashset[CLI_HASH_AVAIL_TYPES];
    const char * virname = NULL;
    int foundsize[CLI_HASH_AVAIL_TYPES];
    int foundwild[CLI_HASH_AVAIL_TYPES];
    enum CLI_HASH_TYPE type;
    int ret = CL_CLEAN;
    unsigned char * md5 = NULL;
 
    /* pick hashtypes to generate */
    for(type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
        foundsize[type] = cli_hm_have_size(mdb_sect, type, exe_section->rsz);
        foundwild[type] = cli_hm_have_wild(mdb_sect, type);
        if(foundsize[type] || foundwild[type]) {
            hashset[type] = cli_malloc(hashlen[type]);
            if(!hashset[type]) {
                cli_errmsg("scan_pe: cli_malloc failed!\n");
                for(; type > 0;)
                    free(hashset[--type]);
                return CL_EMEM;
            }
        }
        else {
            hashset[type] = NULL;
        }
    }

    /* Generate hashes */
    cli_hashsect(*ctx->fmap, exe_section, hashset, foundsize, foundwild);

    /* Print hash */
    if (cli_debug_flag) {
        md5 = hashset[CLI_HASH_MD5];
        if (md5) {
            cli_dbgmsg("MDB hashset: %u:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
                exe_section->rsz, md5[0], md5[1], md5[2], md5[3], md5[4], md5[5], md5[6], md5[7],
                md5[8], md5[9], md5[10], md5[11], md5[12], md5[13], md5[14], md5[15]);
        } else if (cli_always_gen_section_hash) {
            const void *hashme = fmap_need_off_once(*ctx->fmap, exe_section->raw, exe_section->rsz);
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
    for(type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
       if(foundsize[type] && cli_hm_scan(hashset[type], exe_section->rsz, &virname, mdb_sect, type) == CL_VIRUS) {
            ret = cli_append_virus(ctx, virname);
            if (ret != CL_CLEAN) {
                if (ret != CL_VIRUS)
                    break;
                else if (!SCAN_ALLMATCHES)
                    break;
            }
       }
       if(foundwild[type] && cli_hm_scan_wild(hashset[type], &virname, mdb_sect, type) == CL_VIRUS) {
            ret = cli_append_virus(ctx, virname);
            if (ret != CL_CLEAN) {
                if (ret != CL_VIRUS)
                    break;
                else if (!SCAN_ALLMATCHES)
                    break;
            }
       }
    }

end:
    for(type = CLI_HASH_AVAIL_TYPES; type > 0;)
        free(hashset[--type]);
    return ret;
}

/* imptbl scanning */
static char *pe_ordinal(const char *dll, uint16_t ord)
{
  char name[64];
  name[0] = '\0';

  if (strncasecmp(dll, "WS2_32.dll", 10) == 0 ||
      strncasecmp(dll, "wsock32.dll", 11) == 0)
  {
    switch(ord) {
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
  }
  else if (strncasecmp(dll, "oleaut32.dll", 12) == 0)
  {
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
    uint32_t i = 0;
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

static inline int hash_impfns(cli_ctx *ctx, void **hashctx, uint32_t *impsz, struct pe_image_import_descriptor *image, const char *dllname, struct cli_exe_section *exe_sections, uint16_t nsections, uint32_t hdr_size, int pe_plus, int *first)
{
    uint32_t thuoff = 0, offset;
    fmap_t *map = *ctx->fmap;
    size_t dlllen = 0, fsize = map->len;
    unsigned int err = 0;
    int num_fns = 0, ret = CL_SUCCESS;
    const char *buffer;
    enum CLI_HASH_TYPE type;
#if HAVE_JSON
    json_object *imptbl = NULL;
#else
    void *imptbl = NULL;
#endif

    if (image->u.OriginalFirstThunk)
        thuoff = cli_rawaddr(image->u.OriginalFirstThunk, exe_sections, nsections, &err, fsize, hdr_size);
    if (err || thuoff == 0)
        thuoff = cli_rawaddr(image->FirstThunk, exe_sections, nsections, &err, fsize, hdr_size);
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

#define UPDATE_IMPHASH()                                                \
    do {                                                                \
    if (funcname) {                                                     \
        size_t i, j;                                                    \
        char *fname;                                                    \
        size_t funclen;                                                 \
                                                                        \
        if (dlllen == 0) {                                              \
            char* ext = strstr(dllname, ".");                           \
                                                                        \
            if (ext && (strncasecmp(ext, ".ocx", 4) == 0 ||             \
                        strncasecmp(ext, ".sys", 4) == 0 ||             \
                        strncasecmp(ext, ".dll", 4) == 0))              \
                dlllen = ext - dllname;                                 \
            else                                                        \
                dlllen = strlen(dllname);                               \
        }                                                               \
                                                                        \
        funclen = strlen(funcname);                                     \
        if (validate_impname(funcname, funclen, 1) == 0) {              \
            cli_dbgmsg("scan_pe: invalid name for imported function\n"); \
            ret = CL_EFORMAT;                                           \
            break;                                                      \
        }                                                               \
                                                                        \
        fname = cli_calloc(funclen + dlllen + 3, sizeof(char));         \
        if (fname == NULL) {                                            \
            cli_dbgmsg("scan_pe: cannot allocate memory for imphash string\n"); \
            ret = CL_EMEM;                                              \
            break;                                                      \
        }                                                               \
        j = 0;                                                          \
        if (!*first)                                                    \
            fname[j++] = ',';                                           \
        for (i = 0; i < dlllen; i++, j++)                               \
            fname[j] = tolower(dllname[i]);                             \
        fname[j++] = '.';                                               \
        for (i = 0; i < funclen; i++, j++)                              \
            fname[j] = tolower(funcname[i]);                            \
                                                                        \
        if (imptbl) {                                                   \
            char *jname = *first ? fname : fname+1;                     \
            cli_jsonstr(imptbl, NULL, jname);                           \
        }                                                               \
                                                                        \
        for(type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++)   \
            cl_update_hash(hashctx[type], fname, strlen(fname));        \
        *impsz += strlen(fname);                                        \
                                                                        \
        *first = 0;                                                     \
        free(fname);                                                    \
    }                                                                   \
    } while(0)

    if (!pe_plus) {
        struct pe_image_thunk32 thunk32;

        while ((num_fns < PE_MAXIMPORTS) && (fmap_readn(map, &thunk32, thuoff, sizeof(struct pe_image_thunk32)) == sizeof(struct pe_image_thunk32)) && (thunk32.u.Ordinal != 0)) {
            char *funcname = NULL;
            thuoff += sizeof(struct pe_image_thunk32);

            thunk32.u.Ordinal = EC32(thunk32.u.Ordinal);

            if (!(thunk32.u.Ordinal & PE_IMAGEDIR_ORDINAL_FLAG32)) {
                offset = cli_rawaddr(thunk32.u.Function, exe_sections, nsections, &err, fsize, hdr_size);

                if (!ret) {
                    /* Hint field is a uint16_t and precedes the Name field */
                    if ((buffer = fmap_need_off_once(map, offset+sizeof(uint16_t), MIN(PE_MAXNAMESIZE, fsize-offset))) != NULL) {
                        funcname = cli_strndup(buffer, MIN(PE_MAXNAMESIZE, fsize-offset));
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
                offset = cli_rawaddr(thunk64.u.Function, exe_sections, nsections, &err, fsize, hdr_size);

                if (!err) {
                    /* Hint field is a uint16_t and precedes the Name field */
                    if ((buffer = fmap_need_off_once(map, offset+sizeof(uint16_t), MIN(PE_MAXNAMESIZE, fsize-offset))) != NULL) {
                        funcname = cli_strndup(buffer, MIN(PE_MAXNAMESIZE, fsize-offset));
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

static unsigned int hash_imptbl(cli_ctx *ctx, unsigned char **digest, uint32_t *impsz, int *genhash, struct pe_image_data_dir *datadir, struct cli_exe_section *exe_sections, uint16_t nsections, uint32_t hdr_size, int pe_plus)
{
    struct pe_image_import_descriptor *image;
    fmap_t *map = *ctx->fmap;
    size_t left, fsize = map->len;
    uint32_t impoff, offset;
    const char *impdes, *buffer;
    void *hashctx[CLI_HASH_AVAIL_TYPES];
    enum CLI_HASH_TYPE type;
    int nimps = 0, ret = CL_SUCCESS;
    unsigned int err;
    int first = 1;

    if(datadir->VirtualAddress == 0 || datadir->Size == 0) {
        cli_errmsg("scan_pe: import table data directory does not exist\n");
        return CL_SUCCESS;
    }

    impoff = cli_rawaddr(datadir->VirtualAddress, exe_sections, nsections, &err, fsize, hdr_size);
    if(err || impoff + datadir->Size > fsize) {
        cli_dbgmsg("scan_pe: invalid rva for import table data\n");
        return CL_SUCCESS;
    }

    impdes = fmap_need_off(map, impoff, datadir->Size);
    if(impdes == NULL) {
        cli_dbgmsg("scan_pe: failed to acquire fmap buffer\n");
        return CL_EREAD;
    }
    left = datadir->Size;

    memset(hashctx, 0, sizeof(hashctx));
    if(genhash[CLI_HASH_MD5]) {
        hashctx[CLI_HASH_MD5] = cl_hash_init("md5");
        if (hashctx[CLI_HASH_MD5] == NULL) {
            fmap_unneed_off(map, impoff, datadir->Size);
            return CL_EMEM;
        }
    }
    if(genhash[CLI_HASH_SHA1]) {
        hashctx[CLI_HASH_SHA1] = cl_hash_init("sha1");
        if (hashctx[CLI_HASH_SHA1] == NULL) {
            fmap_unneed_off(map, impoff, datadir->Size);
            return CL_EMEM;
        }
    }
    if(genhash[CLI_HASH_SHA256]) {
        hashctx[CLI_HASH_SHA256] = cl_hash_init("sha256");
        if (hashctx[CLI_HASH_SHA256] == NULL) {
            fmap_unneed_off(map, impoff, datadir->Size);
            return CL_EMEM;
        }
    }

    image = (struct pe_image_import_descriptor *)impdes;
    while(left > sizeof(struct pe_image_import_descriptor) && image->Name != 0 && nimps < PE_MAXIMPORTS) {
        char *dllname = NULL;

        left -= sizeof(struct pe_image_import_descriptor);
        nimps++;

        /* Endian Conversion */
        image->u.OriginalFirstThunk = EC32(image->u.OriginalFirstThunk);
        image->TimeDateStamp = EC32(image->TimeDateStamp);
        image->ForwarderChain = EC32(image->ForwarderChain);
        image->Name = EC32(image->Name);
        image->FirstThunk = EC32(image->FirstThunk);

        /* DLL name acquisition */
        offset = cli_rawaddr(image->Name, exe_sections, nsections, &err, fsize, hdr_size);
        if(err || offset > fsize) {
            cli_dbgmsg("scan_pe: invalid rva for dll name\n");
            /* TODO: ignore or return? */
            /*
              image++;
              continue;
             */
            ret = CL_EFORMAT;
            goto hash_imptbl_end;
        }

        buffer = fmap_need_off_once(map, offset, MIN(PE_MAXNAMESIZE, fsize-offset));
        if (buffer == NULL) {
            cli_dbgmsg("scan_pe: failed to read name for dll\n");
            ret = CL_EREAD;
            goto hash_imptbl_end;
        }

        if (validate_impname(dllname, MIN(PE_MAXNAMESIZE, fsize-offset), 1) == 0) {
            cli_dbgmsg("scan_pe: invalid name for imported dll\n");
            ret = CL_EFORMAT;
            goto hash_imptbl_end;
        }

        dllname = cli_strndup(buffer, MIN(PE_MAXNAMESIZE, fsize-offset));
        if (dllname == NULL) {
            cli_dbgmsg("scan_pe: cannot duplicate dll name\n");
            ret = CL_EMEM;
            goto hash_imptbl_end;
        }

        /* DLL function handling - inline function */
        ret = hash_impfns(ctx, hashctx, impsz, image, dllname, exe_sections, nsections, hdr_size, pe_plus, &first);
        free(dllname);
        dllname = NULL;
        if (ret != CL_SUCCESS)
            goto hash_imptbl_end;

        image++;
    }

 hash_imptbl_end:
    fmap_unneed_off(map, impoff, datadir->Size);
    for(type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++)
        cl_finish_hash(hashctx[type], digest[type]);
    return ret;
}

static int scan_pe_imp(cli_ctx *ctx, struct pe_image_data_dir *dirs, struct cli_exe_section *exe_sections, uint16_t nsections, uint32_t hdr_size, int pe_plus)
{
    struct cli_matcher *imp = ctx->engine->hm_imp;
    unsigned char *hashset[CLI_HASH_AVAIL_TYPES];
    const char *virname = NULL;
    int genhash[CLI_HASH_AVAIL_TYPES];
    uint32_t impsz = 0;
    enum CLI_HASH_TYPE type;
    int ret = CL_CLEAN;

    /* pick hashtypes to generate */
    for(type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
        genhash[type] = cli_hm_have_any(imp, type);
        if(genhash[type]) {
            hashset[type] = cli_malloc(hashlen[type]);
            if(!hashset[type]) {
                cli_errmsg("scan_pe: cli_malloc failed!\n");
                for(; type > 0;)
                    free(hashset[--type]);
                return CL_EMEM;
            }
        }
        else {
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
        if(!hashset[CLI_HASH_MD5]) {
            cli_errmsg("scan_pe: cli_malloc failed!\n");
            for(type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++)
                free(hashset[type]);
            return CL_EMEM;
        }
    }

    /* Generate hashes */
    ret = hash_imptbl(ctx, hashset, &impsz, genhash, &dirs[1], exe_sections, nsections, hdr_size, pe_plus);
    if (ret != CL_SUCCESS) {
        for(type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++)
            free(hashset[type]);
        return ret;
    }

    /* Print hash */
#if HAVE_JSON
    if (cli_debug_flag || ctx->wrkproperty) {
#else
    if (cli_debug_flag) {
#endif
        char *dstr = cli_str2hex((char*)hashset[CLI_HASH_MD5], hashlen[CLI_HASH_MD5]);
        cli_dbgmsg("IMP: %s:%u\n", dstr ? (char *)dstr : "(NULL)", impsz);
#if HAVE_JSON
        if (ctx->wrkproperty)
            cli_jsonstr(ctx->wrkproperty, "Imphash", dstr ? dstr : "(NULL)");
#endif
        if (dstr)
            free(dstr);
    }

    /* Do scans */
    for(type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++) {
        if(cli_hm_scan(hashset[type], impsz, &virname, imp, type) == CL_VIRUS) {
            ret = cli_append_virus(ctx, virname);
            if (ret != CL_CLEAN) {
                if (ret != CL_VIRUS)
                    break;
                else if (!SCAN_ALLMATCHES)
                    break;
            }
        }
        if(cli_hm_scan_wild(hashset[type], &virname, imp, type) == CL_VIRUS) {
            cli_append_virus(ctx, virname);
            if (ret != CL_CLEAN) {
                if (ret != CL_VIRUS)
                    break;
                else if (!SCAN_ALLMATCHES)
                    break;
            }
       }
    }

    for(type = CLI_HASH_MD5; type < CLI_HASH_AVAIL_TYPES; type++)
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

    obj = json_object_new_boolean(s->urva>>31 || s->uvsz>>31 || (s->rsz && s->uraw>>31) || s->ursz>>31);
    if ((obj))
        json_object_object_add(section, "Signed", obj);

    json_object_array_add(sections, section);
}
#endif

int cli_scanpe(cli_ctx *ctx)
{
    uint16_t e_magic; /* DOS signature ("MZ") */
    uint16_t nsections;
    uint32_t e_lfanew; /* address of new exe header */
    uint32_t ep, vep; /* entry point (raw, virtual) */
    uint8_t polipos = 0;
    time_t timestamp;
    struct pe_image_file_hdr file_hdr;
    union {
        struct pe_image_optional_hdr64 opt64;
        struct pe_image_optional_hdr32 opt32;
    } pe_opt;
    struct pe_image_section_hdr *section_hdr;
    char sname[9], epbuff[4096], *tempfile;
    uint32_t epsize;
    ssize_t bytes, at;
    unsigned int i, j, found, upx_success = 0, min = 0, max = 0, err, overlays = 0, rescan = 1;
    unsigned int ssize = 0, dsize = 0, dll = 0, pe_plus = 0, corrupted_cur;
    int (*upxfn)(const char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t) = NULL;
    const char *src = NULL;
    char *dest = NULL;
    int ndesc, ret = CL_CLEAN, upack = 0, native=0;
    size_t fsize;
    uint32_t valign, falign, hdr_size;
    struct cli_exe_section *exe_sections;
    char timestr[32];
    struct pe_image_data_dir *dirs;
    struct cli_bc_ctx *bc_ctx;
    fmap_t *map;
    struct cli_pe_hook_data pedata;
#ifdef HAVE__INTERNAL__SHA_COLLECT
    int sha_collect = ctx->sha_collect;
#endif
    const char *archtype=NULL, *subsystem=NULL;
    uint32_t viruses_found = 0;
#if HAVE_JSON
    int toval = 0;
    struct json_object *pe_json=NULL;
    char jsonbuf[128];
#endif

    if(!ctx) {
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
    map = *ctx->fmap;
    if(fmap_readn(map, &e_magic, 0, sizeof(e_magic)) != sizeof(e_magic)) {
        cli_dbgmsg("Can't read DOS signature\n");
        return CL_CLEAN;
    }

    if(EC16(e_magic) != PE_IMAGE_DOS_SIGNATURE && EC16(e_magic) != PE_IMAGE_DOS_SIGNATURE_OLD) {
        cli_dbgmsg("Invalid DOS signature\n");
        return CL_CLEAN;
    }

    if(fmap_readn(map, &e_lfanew, 58 + sizeof(e_magic), sizeof(e_lfanew)) != sizeof(e_lfanew)) {
        cli_dbgmsg("Can't read new header address\n");
        /* truncated header? */
        if(DETECT_BROKEN_PE) {
            ret = cli_append_virus(ctx,"Heuristics.Broken.Executable");
            return ret;
        }

        return CL_CLEAN;
    }

    e_lfanew = EC32(e_lfanew);
    cli_dbgmsg("e_lfanew == %d\n", e_lfanew);
    if(!e_lfanew) {
        cli_dbgmsg("Not a PE file\n");
        return CL_CLEAN;
    }

    if(fmap_readn(map, &file_hdr, e_lfanew, sizeof(struct pe_image_file_hdr)) != sizeof(struct pe_image_file_hdr)) {
        /* bad information in e_lfanew - probably not a PE file */
        cli_dbgmsg("cli_scanpe: Can't read file header\n");
        return CL_CLEAN;
    }

    if(EC32(file_hdr.Magic) != PE_IMAGE_NT_SIGNATURE) {
        cli_dbgmsg("Invalid PE signature (probably NE file)\n");
        return CL_CLEAN;
    }

    if(EC16(file_hdr.Characteristics) & 0x2000) {
#if HAVE_JSON
        if (pe_json != NULL)
            cli_jsonstr(pe_json, "Type", "DLL");
#endif
        cli_dbgmsg("File type: DLL\n");
        dll = 1;
    } else if(EC16(file_hdr.Characteristics) & 0x01) {
#if HAVE_JSON
        if (pe_json != NULL)
            cli_jsonstr(pe_json, "Type", "EXE");
#endif
        cli_dbgmsg("File type: Executable\n");
    }

    switch(EC16(file_hdr.Machine)) {
    case 0x0:
        archtype = "Unknown";
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
        archtype = "R30000 (big-endian)";
        break;
    case 0x162:
        archtype = "R3000";
        break;
    case 0x166:
        archtype = "R4000";
        break;
    case 0x168:
        archtype = "R10000";
        break;
    case 0x184:
        archtype = "DEC Alpha AXP";
        break;
    case 0x284:
        archtype = "DEC Alpha AXP 64bit";
        break;
    case 0x1f0:
        archtype = "PowerPC";
        break;
    case 0x200:
        archtype = "IA64";
        break;
    case 0x268:
        archtype = "M68k";
        break;
    case 0x266:
        archtype = "MIPS16";
        break;
    case 0x366:
        archtype = "MIPS+FPU";
        break;
    case 0x466:
        archtype = "MIPS16+FPU";
        break;
    case 0x1a2:
        archtype = "Hitachi SH3";
        break;
    case 0x1a3:
        archtype = "Hitachi SH3-DSP";
        break;
    case 0x1a4:
        archtype = "Hitachi SH3-E";
        break;
    case 0x1a6:
        archtype = "Hitachi SH4";
        break;
    case 0x1a8:
        archtype = "Hitachi SH5";
        break;
    case 0x1c0:
        archtype = "ARM";
        break;
    case 0x1c2:
        archtype = "THUMB";
        break;
    case 0x1d3:
        archtype = "AM33";
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
    case 0x9041:
        archtype = "M32R";
        break;
    case 0xc0ee:
        archtype = "CEEE";
        break;
    case 0x8664:
        archtype = "AMD64";
        break;
    default:
        archtype = "Unknown";
    }

    if ((archtype)) {
        cli_dbgmsg("Machine type: %s\n", archtype);
#if HAVE_JSON
        if (pe_json != NULL)
            cli_jsonstr(pe_json, "ArchType", archtype);
#endif
    }

    nsections = EC16(file_hdr.NumberOfSections);
    if(nsections < 1 || nsections > PE_MAXSECTIONS) {
#if HAVE_JSON
        pe_add_heuristic_property(ctx, "BadNumberOfSections");
#endif
        if(DETECT_BROKEN_PE) {
            ret = cli_append_virus(ctx,"Heuristics.Broken.Executable");
            return ret;
        }

        if(!ctx->corrupted_input) {
            if(nsections)
            cli_warnmsg("PE file contains %d sections\n", nsections);
            else
            cli_warnmsg("PE file contains no sections\n");
        }

        return CL_CLEAN;
    }

    cli_dbgmsg("NumberOfSections: %d\n", nsections);

    timestamp = (time_t) EC32(file_hdr.TimeDateStamp);
    cli_dbgmsg("TimeDateStamp: %s", cli_ctime(&timestamp, timestr, sizeof(timestr)));

#if HAVE_JSON
    if (pe_json != NULL)
        cli_jsonstr(pe_json, "TimeDateStamp", cli_ctime(&timestamp, timestr, sizeof(timestr)));
#endif

    cli_dbgmsg("SizeOfOptionalHeader: %x\n", EC16(file_hdr.SizeOfOptionalHeader));

#if HAVE_JSON
    if (pe_json != NULL)
        cli_jsonint(pe_json, "SizeOfOptionalHeader", EC16(file_hdr.SizeOfOptionalHeader));
#endif

    if (EC16(file_hdr.SizeOfOptionalHeader) < sizeof(struct pe_image_optional_hdr32)) {
#if HAVE_JSON
        pe_add_heuristic_property(ctx, "BadOptionalHeaderSize");
#endif
        cli_dbgmsg("SizeOfOptionalHeader too small\n");
        if(DETECT_BROKEN_PE) {
            ret = cli_append_virus(ctx,"Heuristics.Broken.Executable");
            return ret;
        }

        return CL_CLEAN;
    }

    at = e_lfanew + sizeof(struct pe_image_file_hdr);
    if(fmap_readn(map, &optional_hdr32, at, sizeof(struct pe_image_optional_hdr32)) != sizeof(struct pe_image_optional_hdr32)) {
        cli_dbgmsg("Can't read optional file header\n");
        if(DETECT_BROKEN_PE) {
            ret = cli_append_virus(ctx,"Heuristics.Broken.Executable");
            return ret;
        }

        return CL_CLEAN;
    }
    at += sizeof(struct pe_image_optional_hdr32);

    /* This will be a chicken and egg problem until we drop 9x */
    if(EC16(optional_hdr64.Magic)==PE32P_SIGNATURE) {
#if HAVE_JSON
        pe_add_heuristic_property(ctx, "BadOptionalHeaderSizePE32Plus");
#endif
        if(EC16(file_hdr.SizeOfOptionalHeader)!=sizeof(struct pe_image_optional_hdr64)) {
            /* FIXME: need to play around a bit more with xp64 */
            cli_dbgmsg("Incorrect SizeOfOptionalHeader for PE32+\n");

            if(DETECT_BROKEN_PE) {
                ret = cli_append_virus(ctx,"Heuristics.Broken.Executable");
                return ret;
            }

            return CL_CLEAN;
        }
        pe_plus = 1;
    }

    if(!pe_plus) { /* PE */
        if (EC16(file_hdr.SizeOfOptionalHeader)!=sizeof(struct pe_image_optional_hdr32)) {
            /* Seek to the end of the long header */
            at += EC16(file_hdr.SizeOfOptionalHeader)-sizeof(struct pe_image_optional_hdr32);
        }

        if(DCONF & PE_CONF_UPACK)
            upack = (EC16(file_hdr.SizeOfOptionalHeader)==0x148);

        vep = EC32(optional_hdr32.AddressOfEntryPoint);
        hdr_size = EC32(optional_hdr32.SizeOfHeaders);
        cli_dbgmsg("File format: PE\n");

        cli_dbgmsg("MajorLinkerVersion: %d\n", optional_hdr32.MajorLinkerVersion);
        cli_dbgmsg("MinorLinkerVersion: %d\n", optional_hdr32.MinorLinkerVersion);
        cli_dbgmsg("SizeOfCode: 0x%x\n", EC32(optional_hdr32.SizeOfCode));
        cli_dbgmsg("SizeOfInitializedData: 0x%x\n", EC32(optional_hdr32.SizeOfInitializedData));
        cli_dbgmsg("SizeOfUninitializedData: 0x%x\n", EC32(optional_hdr32.SizeOfUninitializedData));
        cli_dbgmsg("AddressOfEntryPoint: 0x%x\n", vep);
        cli_dbgmsg("BaseOfCode: 0x%x\n", EC32(optional_hdr32.BaseOfCode));
        cli_dbgmsg("SectionAlignment: 0x%x\n", EC32(optional_hdr32.SectionAlignment));
        cli_dbgmsg("FileAlignment: 0x%x\n", EC32(optional_hdr32.FileAlignment));
        cli_dbgmsg("MajorSubsystemVersion: %d\n", EC16(optional_hdr32.MajorSubsystemVersion));
        cli_dbgmsg("MinorSubsystemVersion: %d\n", EC16(optional_hdr32.MinorSubsystemVersion));
        cli_dbgmsg("SizeOfImage: 0x%x\n", EC32(optional_hdr32.SizeOfImage));
        cli_dbgmsg("SizeOfHeaders: 0x%x\n", hdr_size);
        cli_dbgmsg("NumberOfRvaAndSizes: %d\n", EC32(optional_hdr32.NumberOfRvaAndSizes));
        dirs = optional_hdr32.DataDirectory;
#if HAVE_JSON
        if (pe_json != NULL) {
            cli_jsonint(pe_json, "MajorLinkerVersion", optional_hdr32.MajorLinkerVersion);
            cli_jsonint(pe_json, "MinorLinkerVersion", optional_hdr32.MinorLinkerVersion);
            cli_jsonint(pe_json, "SizeOfCode", EC32(optional_hdr32.SizeOfCode));
            cli_jsonint(pe_json, "SizeOfInitializedData", EC32(optional_hdr32.SizeOfInitializedData));
            cli_jsonint(pe_json, "SizeOfUninitializedData", EC32(optional_hdr32.SizeOfUninitializedData));
            cli_jsonint(pe_json, "NumberOfRvaAndSizes", EC32(optional_hdr32.NumberOfRvaAndSizes));
            cli_jsonint(pe_json, "MajorSubsystemVersion", EC16(optional_hdr32.MajorSubsystemVersion));
            cli_jsonint(pe_json, "MinorSubsystemVersion", EC16(optional_hdr32.MinorSubsystemVersion));

            snprintf(jsonbuf, sizeof(jsonbuf), "0x%x", EC32(optional_hdr32.BaseOfCode));
            cli_jsonstr(pe_json, "BaseOfCode", jsonbuf);

            snprintf(jsonbuf, sizeof(jsonbuf), "0x%x", EC32(optional_hdr32.SectionAlignment));
            cli_jsonstr(pe_json, "SectionAlignment", jsonbuf);

            snprintf(jsonbuf, sizeof(jsonbuf), "0x%x", EC32(optional_hdr32.FileAlignment));
            cli_jsonstr(pe_json, "FileAlignment", jsonbuf);

            snprintf(jsonbuf, sizeof(jsonbuf), "0x%x", EC32(optional_hdr32.SizeOfImage));
            cli_jsonstr(pe_json, "SizeOfImage", jsonbuf);

            snprintf(jsonbuf, sizeof(jsonbuf), "0x%x", hdr_size);
            cli_jsonstr(pe_json, "SizeOfHeaders", jsonbuf);
        }
#endif

    } else { /* PE+ */
            /* read the remaining part of the header */
            if(fmap_readn(map, &optional_hdr32 + 1, at, sizeof(struct pe_image_optional_hdr64) - sizeof(struct pe_image_optional_hdr32)) != sizeof(struct pe_image_optional_hdr64) - sizeof(struct pe_image_optional_hdr32)) {
            cli_dbgmsg("Can't read optional file header\n");
            if(DETECT_BROKEN_PE) {
                ret = cli_append_virus(ctx,"Heuristics.Broken.Executable");
                return ret;
            }

            return CL_CLEAN;
        }

        at += sizeof(struct pe_image_optional_hdr64) - sizeof(struct pe_image_optional_hdr32);
        vep = EC32(optional_hdr64.AddressOfEntryPoint);
        hdr_size = EC32(optional_hdr64.SizeOfHeaders);
        cli_dbgmsg("File format: PE32+\n");

        cli_dbgmsg("MajorLinkerVersion: %d\n", optional_hdr64.MajorLinkerVersion);
        cli_dbgmsg("MinorLinkerVersion: %d\n", optional_hdr64.MinorLinkerVersion);
        cli_dbgmsg("SizeOfCode: 0x%x\n", EC32(optional_hdr64.SizeOfCode));
        cli_dbgmsg("SizeOfInitializedData: 0x%x\n", EC32(optional_hdr64.SizeOfInitializedData));
        cli_dbgmsg("SizeOfUninitializedData: 0x%x\n", EC32(optional_hdr64.SizeOfUninitializedData));
        cli_dbgmsg("AddressOfEntryPoint: 0x%x\n", vep);
        cli_dbgmsg("BaseOfCode: 0x%x\n", EC32(optional_hdr64.BaseOfCode));
        cli_dbgmsg("SectionAlignment: 0x%x\n", EC32(optional_hdr64.SectionAlignment));
        cli_dbgmsg("FileAlignment: 0x%x\n", EC32(optional_hdr64.FileAlignment));
        cli_dbgmsg("MajorSubsystemVersion: %d\n", EC16(optional_hdr64.MajorSubsystemVersion));
        cli_dbgmsg("MinorSubsystemVersion: %d\n", EC16(optional_hdr64.MinorSubsystemVersion));
        cli_dbgmsg("SizeOfImage: 0x%x\n", EC32(optional_hdr64.SizeOfImage));
        cli_dbgmsg("SizeOfHeaders: 0x%x\n", hdr_size);
        cli_dbgmsg("NumberOfRvaAndSizes: %d\n", EC32(optional_hdr64.NumberOfRvaAndSizes));
        dirs = optional_hdr64.DataDirectory;
#if HAVE_JSON
        if (pe_json != NULL) {
            cli_jsonint(pe_json, "MajorLinkerVersion", optional_hdr64.MajorLinkerVersion);
            cli_jsonint(pe_json, "MinorLinkerVersion", optional_hdr64.MinorLinkerVersion);
            cli_jsonint(pe_json, "SizeOfCode", EC32(optional_hdr64.SizeOfCode));
            cli_jsonint(pe_json, "SizeOfInitializedData", EC32(optional_hdr64.SizeOfInitializedData));
            cli_jsonint(pe_json, "SizeOfUninitializedData", EC32(optional_hdr64.SizeOfUninitializedData));
            cli_jsonint(pe_json, "NumberOfRvaAndSizes", EC32(optional_hdr64.NumberOfRvaAndSizes));
            cli_jsonint(pe_json, "MajorSubsystemVersion", EC16(optional_hdr64.MajorSubsystemVersion));
            cli_jsonint(pe_json, "MinorSubsystemVersion", EC16(optional_hdr64.MinorSubsystemVersion));

            snprintf(jsonbuf, sizeof(jsonbuf), "0x%x", EC32(optional_hdr64.BaseOfCode));
            cli_jsonstr(pe_json, "BaseOfCode", jsonbuf);

            snprintf(jsonbuf, sizeof(jsonbuf), "0x%x", EC32(optional_hdr64.SectionAlignment));
            cli_jsonstr(pe_json, "SectionAlignment", jsonbuf);

            snprintf(jsonbuf, sizeof(jsonbuf), "0x%x", EC32(optional_hdr64.FileAlignment));
            cli_jsonstr(pe_json, "FileAlignment", jsonbuf);

            snprintf(jsonbuf, sizeof(jsonbuf), "0x%x", EC32(optional_hdr64.SizeOfImage));
            cli_jsonstr(pe_json, "SizeOfImage", jsonbuf);

            snprintf(jsonbuf, sizeof(jsonbuf), "0x%x", hdr_size);
            cli_jsonstr(pe_json, "SizeOfHeaders", jsonbuf);
        }
#endif
    }

#if HAVE_JSON
    if (SCAN_COLLECT_METADATA) {
        snprintf(jsonbuf, sizeof(jsonbuf), "0x%x", vep);
        if (pe_json != NULL)
            cli_jsonstr(pe_json, "EntryPoint", jsonbuf);
    }
#endif


    switch(pe_plus ? EC16(optional_hdr64.Subsystem) : EC16(optional_hdr32.Subsystem)) {
    case 0:
        subsystem = "Unknown";
        break;
    case 1:
        subsystem = "Native (svc)";
        native = 1;
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

    cli_dbgmsg("Subsystem: %s\n", subsystem);

#if HAVE_JSON
    if (pe_json != NULL)
        cli_jsonstr(pe_json, "Subsystem", subsystem);
#endif

    cli_dbgmsg("------------------------------------\n");

    if (DETECT_BROKEN_PE && !native && (!(pe_plus?EC32(optional_hdr64.SectionAlignment):EC32(optional_hdr32.SectionAlignment)) || (pe_plus?EC32(optional_hdr64.SectionAlignment):EC32(optional_hdr32.SectionAlignment))%0x1000)) {
        cli_dbgmsg("Bad virtual alignment\n");
        ret = cli_append_virus(ctx,"Heuristics.Broken.Executable");
        return ret;
    }

    if (DETECT_BROKEN_PE && !native && (!(pe_plus?EC32(optional_hdr64.FileAlignment):EC32(optional_hdr32.FileAlignment)) || (pe_plus?EC32(optional_hdr64.FileAlignment):EC32(optional_hdr32.FileAlignment))%0x200)) {
        cli_dbgmsg("Bad file alignment\n");
        ret = cli_append_virus(ctx, "Heuristics.Broken.Executable");
        return ret;
    }

    fsize = map->len;

    section_hdr = (struct pe_image_section_hdr *) cli_calloc(nsections, sizeof(struct pe_image_section_hdr));

    if(!section_hdr) {
        cli_dbgmsg("Can't allocate memory for section headers\n");
        return CL_EMEM;
    }

    exe_sections = (struct cli_exe_section *) cli_calloc(nsections, sizeof(struct cli_exe_section));
    
    if(!exe_sections) {
        cli_dbgmsg("Can't allocate memory for section headers\n");
        free(section_hdr);
        return CL_EMEM;
    }

    valign = (pe_plus)?EC32(optional_hdr64.SectionAlignment):EC32(optional_hdr32.SectionAlignment);
    falign = (pe_plus)?EC32(optional_hdr64.FileAlignment):EC32(optional_hdr32.FileAlignment);

    if(fmap_readn(map, section_hdr, at, sizeof(struct pe_image_section_hdr)*nsections) != (int)(nsections*sizeof(struct pe_image_section_hdr))) {
        cli_dbgmsg("Can't read section header\n");
        cli_dbgmsg("Possibly broken PE file\n");

        free(section_hdr);
        free(exe_sections);

        if(DETECT_BROKEN_PE) {
            ret = cli_append_virus(ctx,"Heuristics.Broken.Executable");
            return ret;
        }

        return CL_CLEAN;
    }

    at += sizeof(struct pe_image_section_hdr)*nsections;

    for(i = 0; falign!=0x200 && i<nsections; i++) {
        /* file alignment fallback mode - blah */
        if (falign && section_hdr[i].SizeOfRawData && EC32(section_hdr[i].PointerToRawData)%falign && !(EC32(section_hdr[i].PointerToRawData)%0x200)) {
            cli_dbgmsg("Found misaligned section, using 0x200\n");
            falign = 0x200;
        }
    }

    hdr_size = PESALIGN(hdr_size, valign); /* Aligned headers virtual size */

#if HAVE_JSON
    if (pe_json != NULL)
        cli_jsonint(pe_json, "NumberOfSections", nsections);
#endif

    while (rescan==1) {
        rescan=0;
        for (i=0; i < nsections; i++) {
            exe_sections[i].rva = PEALIGN(EC32(section_hdr[i].VirtualAddress), valign);
            exe_sections[i].vsz = PESALIGN(EC32(section_hdr[i].VirtualSize), valign);
            exe_sections[i].raw = PEALIGN(EC32(section_hdr[i].PointerToRawData), falign);
            exe_sections[i].rsz = PESALIGN(EC32(section_hdr[i].SizeOfRawData), falign);
            exe_sections[i].chr = EC32(section_hdr[i].Characteristics);
            exe_sections[i].urva = EC32(section_hdr[i].VirtualAddress); /* Just in case */
            exe_sections[i].uvsz = EC32(section_hdr[i].VirtualSize);
            exe_sections[i].uraw = EC32(section_hdr[i].PointerToRawData);
            exe_sections[i].ursz = EC32(section_hdr[i].SizeOfRawData);

            if (exe_sections[i].rsz) { /* Don't bother with virtual only sections */
                if (exe_sections[i].raw >= fsize || exe_sections[i].uraw > fsize) {
                    cli_dbgmsg("Broken PE file - Section %d starts or exists beyond the end of file (Offset@ %lu, Total filesize %lu)\n", i, (unsigned long)exe_sections[i].raw, (unsigned long)fsize);
                    if (nsections == 1) {
                        free(section_hdr);
                        free(exe_sections);

                        if(DETECT_BROKEN_PE) {
                            ret = cli_append_virus(ctx, "Heuristics.Broken.Executable");
                            return ret;
                        }

                        return CL_CLEAN; /* no ninjas to see here! move along! */
                    }

                    for (j=i; j < nsections-1; j++)
                        memcpy(&exe_sections[j], &exe_sections[j+1], sizeof(struct cli_exe_section));

                    for (j=i; j < nsections-1; j++)
                        memcpy(&section_hdr[j], &section_hdr[j+1], sizeof(struct pe_image_section_hdr));

                    nsections--;
                    rescan=1;
                    break;
                }

                if (!CLI_ISCONTAINED(0, (uint32_t) fsize, exe_sections[i].raw, exe_sections[i].rsz))
                    exe_sections[i].rsz = fsize - exe_sections[i].raw;

                if (!CLI_ISCONTAINED(0, fsize, exe_sections[i].uraw, exe_sections[i].ursz))
                    exe_sections[i].ursz = fsize - exe_sections[i].uraw;
            }
        }
    }

    for(i = 0; i < nsections; i++) {
        strncpy(sname, (char *) section_hdr[i].Name, 8);
        sname[8] = 0;

#if HAVE_JSON
        add_section_info(ctx, &exe_sections[i]);

        if (cli_json_timeout_cycle_check(ctx, &toval) != CL_SUCCESS) {
            free(section_hdr);
            free(exe_sections);
            return CL_ETIMEOUT;
        }
#endif

        if (!exe_sections[i].vsz && exe_sections[i].rsz)
            exe_sections[i].vsz=PESALIGN(exe_sections[i].ursz, valign);

        cli_dbgmsg("Section %d\n", i);
        cli_dbgmsg("Section name: %s\n", sname);
        cli_dbgmsg("Section data (from headers - in memory)\n");
        cli_dbgmsg("VirtualSize: 0x%x 0x%x\n", exe_sections[i].uvsz, exe_sections[i].vsz);
        cli_dbgmsg("VirtualAddress: 0x%x 0x%x\n", exe_sections[i].urva, exe_sections[i].rva);
        cli_dbgmsg("SizeOfRawData: 0x%x 0x%x\n", exe_sections[i].ursz, exe_sections[i].rsz);
        cli_dbgmsg("PointerToRawData: 0x%x 0x%x\n", exe_sections[i].uraw, exe_sections[i].raw);

        if(exe_sections[i].chr & 0x20) {
            cli_dbgmsg("Section contains executable code\n");

            if(exe_sections[i].vsz < exe_sections[i].rsz) {
                cli_dbgmsg("Section contains free space\n");
                /*
                cli_dbgmsg("Dumping %d bytes\n", section_hdr.SizeOfRawData - section_hdr.VirtualSize);
                ddump(desc, section_hdr.PointerToRawData + section_hdr.VirtualSize, section_hdr.SizeOfRawData - section_hdr.VirtualSize, cli_gentemp(NULL));
                */
            }
        }

        if(exe_sections[i].chr & 0x20000000)
            cli_dbgmsg("Section's memory is executable\n");

        if(exe_sections[i].chr & 0x80000000)
            cli_dbgmsg("Section's memory is writeable\n");

        if (DETECT_BROKEN_PE && (!valign || (exe_sections[i].urva % valign))) { /* Bad virtual alignment */
            cli_dbgmsg("VirtualAddress is misaligned\n");
            cli_dbgmsg("------------------------------------\n");
            ret = cli_append_virus(ctx, "Heuristics.Broken.Executable");
            free(section_hdr);
            free(exe_sections);
            return ret;
        }

        if (exe_sections[i].rsz) { /* Don't bother with virtual only sections */
            if(SCAN_HEURISTICS && (DCONF & PE_CONF_POLIPOS) && !*sname && exe_sections[i].vsz > 40000 && exe_sections[i].vsz < 70000 && exe_sections[i].chr == 0xe0000060) polipos = i;

            /* check hash section sigs */
            if((DCONF & PE_CONF_MD5SECT) && ctx->engine->hm_mdb) {
                ret = scan_pe_mdb(ctx, &exe_sections[i]);
                if (ret != CL_CLEAN) {
                    if (ret != CL_VIRUS)
                        cli_errmsg("scan_pe: scan_pe_mdb failed: %s!\n", cl_strerror(ret));

                    cli_dbgmsg("------------------------------------\n");
                    free(section_hdr);
                    free(exe_sections);
                    return ret;
                }
            }
        }
        cli_dbgmsg("------------------------------------\n");

        if (exe_sections[i].urva>>31 || exe_sections[i].uvsz>>31 || (exe_sections[i].rsz && exe_sections[i].uraw>>31) || exe_sections[i].ursz>>31) {
            cli_dbgmsg("Found PE values with sign bit set\n");

            free(section_hdr);
            free(exe_sections);
            if(DETECT_BROKEN_PE) {
                ret = cli_append_virus(ctx, "Heuristics.Broken.Executable");
                return ret;
            }

            return CL_CLEAN;
        }

        if(!i) {
            if (DETECT_BROKEN_PE && exe_sections[i].urva!=hdr_size) { /* Bad first section RVA */
                cli_dbgmsg("First section is in the wrong place\n");
                ret = cli_append_virus(ctx, "Heuristics.Broken.Executable");
                free(section_hdr);
                free(exe_sections);
                return ret;
            }

            min = exe_sections[i].rva;
            max = exe_sections[i].rva + exe_sections[i].rsz;
        } else {
            if (DETECT_BROKEN_PE && exe_sections[i].urva - exe_sections[i-1].urva != exe_sections[i-1].vsz) { /* No holes, no overlapping, no virtual disorder */
                cli_dbgmsg("Virtually misplaced section (wrong order, overlapping, non contiguous)\n");
                ret = cli_append_virus(ctx, "Heuristics.Broken.Executable");
                free(section_hdr);
                free(exe_sections);
                return ret;
            }

            if(exe_sections[i].rva < min)
                min = exe_sections[i].rva;

            if(exe_sections[i].rva + exe_sections[i].rsz > max) {
                max = exe_sections[i].rva + exe_sections[i].rsz;
                overlays = exe_sections[i].raw + exe_sections[i].rsz;
            }
        }
    }

    free(section_hdr);

    if(!(ep = cli_rawaddr(vep, exe_sections, nsections, &err, fsize, hdr_size)) && err) {
        cli_dbgmsg("EntryPoint out of file\n");
        free(exe_sections);
        if(DETECT_BROKEN_PE) {
            ret = cli_append_virus(ctx,"Heuristics.Broken.Executable");
            return ret;
        }

        return CL_CLEAN;
    }

#if HAVE_JSON
    if (pe_json != NULL)
        cli_jsonint(pe_json, "EntryPointOffset", ep);

    if (cli_json_timeout_cycle_check(ctx, &toval) != CL_SUCCESS) {
        return CL_ETIMEOUT;
    }
#endif

    cli_dbgmsg("EntryPoint offset: 0x%x (%d)\n", ep, ep);

    if(pe_plus) { /* Do not continue for PE32+ files */
        free(exe_sections);
        return CL_CLEAN;
    }

    epsize = fmap_readn(map, epbuff, ep, 4096);


    /* Disasm scan disabled since it's now handled by the bytecode */

    /* CLI_UNPTEMP("DISASM",(exe_sections,0)); */
    /* if(disasmbuf((unsigned char*)epbuff, epsize, ndesc)) */
    /*  ret = cli_scandesc(ndesc, ctx, CL_TYPE_PE_DISASM, 1, NULL, AC_SCAN_VIR); */
    /* close(ndesc); */
    /* CLI_TMPUNLK(); */
    /* free(tempfile); */
    /* if(ret == CL_VIRUS) { */
    /*  free(exe_sections); */
    /*  return ret; */
    /* } */

    if(overlays) {
        int overlays_sz = fsize - overlays;
        if(overlays_sz > 0) {
            ret = cli_scanishield(ctx, overlays, overlays_sz);
            if(ret != CL_CLEAN) {
                free(exe_sections);
                return ret;
            }
        }
    }

    pedata.nsections = nsections;
    pedata.ep = ep;
    pedata.offset = 0;
    memcpy(&pedata.file_hdr, &file_hdr, sizeof(file_hdr));
    memcpy(&pedata.opt32, &pe_opt.opt32, sizeof(pe_opt.opt32));
    memcpy(&pedata.opt64, &pe_opt.opt64, sizeof(pe_opt.opt64));
    memcpy(&pedata.dirs, dirs, sizeof(pedata.dirs));
    pedata.e_lfanew = e_lfanew;
    pedata.overlays = overlays;
    pedata.overlays_sz = fsize - overlays;
    pedata.hdr_size = hdr_size;

    /* Bytecode BC_PE_ALL hook */
    bc_ctx = cli_bytecode_context_alloc();
    if (!bc_ctx) {
        cli_errmsg("cli_scanpe: can't allocate memory for bc_ctx\n");
        free(exe_sections);
        return CL_EMEM;
    }

    cli_bytecode_context_setpe(bc_ctx, &pedata, exe_sections);
    cli_bytecode_context_setctx(bc_ctx, ctx);
    ret = cli_bytecode_runhook(ctx, ctx->engine, bc_ctx, BC_PE_ALL, map);
    switch (ret) {
        case CL_ENULLARG:
            cli_warnmsg("cli_scanpe: NULL argument supplied\n");
            break;
        case CL_VIRUS:
        case CL_BREAK:
            free(exe_sections);
            cli_bytecode_context_destroy(bc_ctx);
            return ret == CL_VIRUS ? CL_VIRUS : CL_CLEAN;
    }
    cli_bytecode_context_destroy(bc_ctx);

    /* Attempt to run scans on import table */
    /* Run if there are existing signatures and/or preclassing */
#if HAVE_JSON
    if (DCONF & PE_CONF_IMPTBL && (ctx->engine->hm_imp || ctx->wrkproperty)) {
#else
    if (DCONF & PE_CONF_IMPTBL && ctx->engine->hm_imp) {
#endif
        ret = scan_pe_imp(ctx, dirs, exe_sections, nsections, hdr_size, pe_plus);
        switch (ret) {
            case CL_SUCCESS:
                break;
            case CL_ENULLARG:
                cli_warnmsg("cli_scanpe: NULL argument supplied\n");
                break;
            case CL_VIRUS:
                if (SCAN_ALLMATCHES)
                    break;
                /* intentional fall-through */
            case CL_BREAK:
                free(exe_sections);
                return ret == CL_VIRUS ? CL_VIRUS : CL_CLEAN;
            default:
                free(exe_sections);
                return ret;
        }
    }
    /* Attempt to detect some popular polymorphic viruses */

    /* W32.Parite.B */
    if(SCAN_HEURISTICS && (DCONF & PE_CONF_PARITE) && !dll && epsize == 4096 && ep == exe_sections[nsections - 1].raw) {
        const char *pt = cli_memstr(epbuff, 4040, "\x47\x65\x74\x50\x72\x6f\x63\x41\x64\x64\x72\x65\x73\x73\x00", 15);
        if(pt) {
            pt += 15;
            if((((uint32_t)cli_readint32(pt) ^ (uint32_t)cli_readint32(pt + 4)) == 0x505a4f) && (((uint32_t)cli_readint32(pt + 8) ^ (uint32_t)cli_readint32(pt + 12)) == 0xffffb) && (((uint32_t)cli_readint32(pt + 16) ^ (uint32_t)cli_readint32(pt + 20)) == 0xb8)) {
                ret = cli_append_virus(ctx,"Heuristics.W32.Parite.B");
                if (ret != CL_CLEAN) {
                    if (ret == CL_VIRUS) {
                        if (!SCAN_ALLMATCHES) {
                            free(exe_sections);
                            return ret;
                        }
                        else
                            viruses_found++;
                    } else {
                        free(exe_sections);
                        return ret;
                    }
                }
            }
        }
    }

    /* Kriz */
    if(SCAN_HEURISTICS && (DCONF & PE_CONF_KRIZ) && epsize >= 200 && CLI_ISCONTAINED(exe_sections[nsections - 1].raw, exe_sections[nsections - 1].rsz, ep, 0x0fd2) && epbuff[1]=='\x9c' && epbuff[2]=='\x60') {
        enum {KZSTRASH,KZSCDELTA,KZSPDELTA,KZSGETSIZE,KZSXORPRFX,KZSXOR,KZSDDELTA,KZSLOOP,KZSTOP};
        uint8_t kzs[] = {KZSTRASH,KZSCDELTA,KZSPDELTA,KZSGETSIZE,KZSTRASH,KZSXORPRFX,KZSXOR,KZSTRASH,KZSDDELTA,KZSTRASH,KZSLOOP,KZSTOP};
        uint8_t *kzstate = kzs;
        uint8_t *kzcode = (uint8_t *)epbuff + 3;
        uint8_t kzdptr=0xff, kzdsize=0xff;
        int kzlen = 197, kzinitlen=0xffff, kzxorlen=-1;
        cli_dbgmsg("in kriz\n");

        while(*kzstate!=KZSTOP) {
            uint8_t op;
            if(kzlen<=6)
                break;

            op = *kzcode++;
            kzlen--;

            switch (*kzstate) {
            case KZSTRASH:
            case KZSGETSIZE: {
                int opsz=0;
                switch(op) {
                case 0x81:
                    kzcode+=5;
                    kzlen-=5;
                    break;
                case 0xb8:
                case 0xb9:
                case 0xba:
                case 0xbb:
                case 0xbd:
                case 0xbe:
                case 0xbf:
                    if(*kzstate==KZSGETSIZE && cli_readint32(kzcode)==0x0fd2) {
                        kzinitlen = kzlen-5;
                        kzdsize=op-0xb8;
                        kzstate++;
                        op=4; /* fake the register to avoid breaking out */

                        cli_dbgmsg("kriz: using #%d as size counter\n", kzdsize);
                    }
                    opsz=4;
                case 0x48:
                case 0x49:
                case 0x4a:
                case 0x4b:
                case 0x4d:
                case 0x4e:
                case 0x4f:
                    op&=7;
                    if(op!=kzdptr && op!=kzdsize) {
                        kzcode+=opsz;
                        kzlen-=opsz;
                        break;
                    }
                default:
                    kzcode--;
                    kzlen++;
                    kzstate++;
                }

                break;
            }
            case KZSCDELTA:
                if(op==0xe8 && (uint32_t)cli_readint32(kzcode) < 0xff) {
                    kzlen-=*kzcode+4;
                    kzcode+=*kzcode+4;
                    kzstate++;
                } else {
                    *kzstate=KZSTOP;
                }

                break;
            case KZSPDELTA:
                if((op&0xf8)==0x58 && (kzdptr=op-0x58)!=4) {
                    kzstate++;
                    cli_dbgmsg("kriz: using #%d as pointer\n", kzdptr);
                } else {
                    *kzstate=KZSTOP;
                }

                break;
            case KZSXORPRFX:
                kzstate++;
                if(op==0x3e)
                    break;
            case KZSXOR:
                if (op==0x80 && *kzcode==kzdptr+0xb0) {
                    kzxorlen=kzlen;
                    kzcode+=+6;
                    kzlen-=+6;
                    kzstate++;
                } else {
                    *kzstate=KZSTOP;
                }

                break;
            case KZSDDELTA:
                if (op==kzdptr+0x48)
                    kzstate++;
                else
                    *kzstate=KZSTOP;

                break;
            case KZSLOOP:
                if (op==kzdsize+0x48 && *kzcode==0x75 && kzlen-(int8_t)kzcode[1]-3<=kzinitlen && kzlen-(int8_t)kzcode[1]>=kzxorlen) {
                    ret = cli_append_virus(ctx,"Heuristics.W32.Kriz");
                    if (ret != CL_CLEAN) {
                        if (ret == CL_VIRUS) {
                            if (!SCAN_ALLMATCHES) {
                                free(exe_sections);
                                return ret;
                            }
                            else
                                viruses_found++;
                        } else {
                            free(exe_sections);
                            return ret;
                        }
                    }
                }
                cli_dbgmsg("kriz: loop out of bounds, corrupted sample?\n");
                kzstate++;
            }
        }
    }

    /* W32.Magistr.A/B */
    if(SCAN_HEURISTICS && (DCONF & PE_CONF_MAGISTR) && !dll && (nsections>1) && (exe_sections[nsections - 1].chr & 0x80000000)) {
        uint32_t rsize, vsize, dam = 0;

        vsize = exe_sections[nsections - 1].uvsz;
        rsize = exe_sections[nsections - 1].rsz;
        if(rsize < exe_sections[nsections - 1].ursz) {
            rsize = exe_sections[nsections - 1].ursz;
            dam = 1;
        }

        if(vsize >= 0x612c && rsize >= 0x612c && ((vsize & 0xff) == 0xec)) {
            int bw = rsize < 0x7000 ? rsize : 0x7000;
            const char *tbuff;

            if((tbuff = fmap_need_off_once(map, exe_sections[nsections - 1].raw + rsize - bw, 4096))) {
                if(cli_memstr(tbuff, 4091, "\xe8\x2c\x61\x00\x00", 5)) {
                    ret = cli_append_virus(ctx, dam ? "Heuristics.W32.Magistr.A.dam" : "Heuristics.W32.Magistr.A");
                    if (ret != CL_CLEAN) {
                        if (ret == CL_VIRUS) {
                            if (!SCAN_ALLMATCHES) {
                                free(exe_sections);
                                return ret;
                            }
                            else
                                viruses_found++;
                        } else {
                            free(exe_sections);
                            return ret;
                        }
                    }
                }
            }
        } else if(rsize >= 0x7000 && vsize >= 0x7000 && ((vsize & 0xff) == 0xed)) {
            int bw = rsize < 0x8000 ? rsize : 0x8000;
            const char *tbuff;

            if((tbuff = fmap_need_off_once(map, exe_sections[nsections - 1].raw + rsize - bw, 4096))) {
                if(cli_memstr(tbuff, 4091, "\xe8\x04\x72\x00\x00", 5)) {
                    ret = cli_append_virus(ctx,dam ? "Heuristics.W32.Magistr.B.dam" : "Heuristics.W32.Magistr.B");
                    if (ret != CL_CLEAN) {
                        if (ret == CL_VIRUS) {
                            if (!SCAN_ALLMATCHES) {
                                free(exe_sections);
                                return ret;
                            }
                            else
                                viruses_found++;
                        } else {
                            free(exe_sections);
                            return ret;
                        }
                    }
                } 
            }
        }
    }

    /* W32.Polipos.A */
    while(polipos && !dll && nsections > 2 && nsections < 13 && e_lfanew <= 0x800 && (EC16(optional_hdr32.Subsystem) == 2 || EC16(optional_hdr32.Subsystem) == 3) && EC16(file_hdr.Machine) == 0x14c && optional_hdr32.SizeOfStackReserve >= 0x80000) {
        uint32_t jump, jold, *jumps = NULL;
        const uint8_t *code;
        unsigned int xsjs = 0;

        if(exe_sections[0].rsz > CLI_MAX_ALLOCATION)
            break;
        if(exe_sections[0].rsz < 5)
            break;
        if(!(code=fmap_need_off_once(map, exe_sections[0].raw, exe_sections[0].rsz)))
            break;

        for(i=0; i<exe_sections[0].rsz - 5; i++) {
            if((uint8_t)(code[i]-0xe8) > 1)
                continue;

            jump = cli_rawaddr(exe_sections[0].rva+i+5+cli_readint32(&code[i+1]), exe_sections, nsections, &err, fsize, hdr_size);
            if(err || !CLI_ISCONTAINED(exe_sections[polipos].raw, exe_sections[polipos].rsz, jump, 9))
                continue;

            if(xsjs % 128 == 0) {
                if(xsjs == 1280)
                    break;

                if(!(jumps=(uint32_t *)cli_realloc2(jumps, (xsjs+128)*sizeof(uint32_t)))) {
                    free(exe_sections);
                    return CL_EMEM;
                }
            }

            j=0;
            for(; j<xsjs; j++) {
                if(jumps[j]<jump)
                    continue;
                if(jumps[j]==jump) {
                    xsjs--;
                    break;
                }

                jold=jumps[j];
                jumps[j]=jump;
                jump=jold;
            }

            jumps[j]=jump;
            xsjs++;
        }

        if(!xsjs)
            break;

        cli_dbgmsg("Polipos: Checking %d xsect jump(s)\n", xsjs);
        for(i=0;i<xsjs;i++) {
            if(!(code = fmap_need_off_once(map, jumps[i], 9)))
                continue;

            if((jump=cli_readint32(code))==0x60ec8b55 || (code[4]==0x0ec && ((jump==0x83ec8b55 && code[6]==0x60) || (jump==0x81ec8b55 && !code[7] && !code[8])))) {
                ret = cli_append_virus(ctx,"Heuristics.W32.Polipos.A");
                if (ret != CL_CLEAN) {
                    if (ret == CL_VIRUS) {
                        if (!SCAN_ALLMATCHES) {
                            free(jumps);
                            free(exe_sections);
                            return ret;
                        }
                        else
                            viruses_found++;
                    } else {
                        free(jumps);
                        free(exe_sections);
                        return ret;
                    }
                }
            }
        }

        free(jumps);
        break;
    }

    /* Trojan.Swizzor.Gen */
    if (SCAN_HEURISTICS && (DCONF & PE_CONF_SWIZZOR) && nsections > 1 && fsize > 64*1024 && fsize < 4*1024*1024) {
        if(dirs[2].Size) {
            struct swizz_stats *stats = cli_calloc(1, sizeof(*stats));
            unsigned int m = 1000;
            ret = CL_CLEAN;

            if (!stats) {
                free(exe_sections);
                return CL_EMEM;
            } else {
                cli_parseres_special(EC32(dirs[2].VirtualAddress), EC32(dirs[2].VirtualAddress), map, exe_sections, nsections, fsize, hdr_size, 0, 0, &m, stats);
                if ((ret = cli_detect_swizz(stats)) == CL_VIRUS) {
                    ret = cli_append_virus(ctx,"Heuristics.Trojan.Swizzor.Gen");
                    if (ret != CL_CLEAN) {
                        if (ret == CL_VIRUS) {
                            if (!SCAN_ALLMATCHES) {
                                free(stats);
                                free(exe_sections);
                                return ret;
                            }
                            else
                                viruses_found++;
                        } else {
                            free(stats);
                            free(exe_sections);
                            return ret;
                        }
                    }
                }
            }
        }
    }


    /* !!!!!!!!!!!!!!    PACKERS START HERE    !!!!!!!!!!!!!! */
    corrupted_cur = ctx->corrupted_input;
    ctx->corrupted_input = 2; /* caller will reset on return */


    /* UPX, FSG, MEW support */

    /* try to find the first section with physical size == 0 */
    found = 0;
    if(DCONF & (PE_CONF_UPX | PE_CONF_FSG | PE_CONF_MEW)) {
        for(i = 0; i < (unsigned int) nsections - 1; i++) {
            if(!exe_sections[i].rsz && exe_sections[i].vsz && exe_sections[i + 1].rsz && exe_sections[i + 1].vsz) {
                found = 1;
                cli_dbgmsg("UPX/FSG/MEW: empty section found - assuming compression\n");
#if HAVE_JSON
                if (pe_json != NULL)
                    cli_jsonbool(pe_json, "HasEmptySection", 1);
#endif
                break;
            }
        }
    }

    /* MEW support */
    if (found && (DCONF & PE_CONF_MEW) && epsize>=16 && epbuff[0]=='\xe9') {
        uint32_t fileoffset;
        const char *tbuff;

        fileoffset = (vep + cli_readint32(epbuff + 1) + 5);
        while (fileoffset == 0x154 || fileoffset == 0x158) {
            char *src;
            uint32_t offdiff, uselzma;

            cli_dbgmsg ("MEW: found MEW characteristics %08X + %08X + 5 = %08X\n", 
                cli_readint32(epbuff + 1), vep, cli_readint32(epbuff + 1) + vep + 5);

            if(!(tbuff = fmap_need_off_once(map, fileoffset, 0xb0)))
                break;

            if (fileoffset == 0x154)
                cli_dbgmsg("MEW: Win9x compatibility was set!\n");
            else
                cli_dbgmsg("MEW: Win9x compatibility was NOT set!\n");

            offdiff = cli_readint32(tbuff+1) - EC32(optional_hdr32.ImageBase);
            if ((offdiff <= exe_sections[i + 1].rva) || 
                (offdiff >= exe_sections[i + 1].rva + exe_sections[i + 1].raw - 4))
            {
                cli_dbgmsg("MEW: ESI is not in proper section\n");
                break;
            }

            offdiff -= exe_sections[i + 1].rva;

            if(!exe_sections[i + 1].rsz) {
                cli_dbgmsg("MEW: mew section is empty\n");
                break;
            }

            ssize = exe_sections[i + 1].vsz;
            dsize = exe_sections[i].vsz;

            /* Guard against integer overflow */
            if ((ssize + dsize < ssize) || (ssize + dsize < dsize)) {
                cli_dbgmsg("MEW: section size (%08x) + diff size (%08x) exceeds max size of unsigned int (%08x)\n", ssize, dsize, UINT32_MAX);
                break;
            }

            /* Verify that offdiff does not exceed the ssize + sdiff */
            if (offdiff >= ssize + dsize) {
                cli_dbgmsg("MEW: offdiff (%08x) exceeds section size + diff size (%08x)\n", offdiff, ssize + dsize);
                break;
            }

            cli_dbgmsg("MEW: ssize %08x dsize %08x offdiff: %08x\n", ssize, dsize, offdiff);

            CLI_UNPSIZELIMITS("MEW", MAX(ssize, dsize));
            CLI_UNPSIZELIMITS("MEW", MAX(ssize + dsize, exe_sections[i + 1].rsz));

            if (exe_sections[i + 1].rsz < offdiff + 12 || exe_sections[i + 1].rsz > ssize) {
                cli_dbgmsg("MEW: Size mismatch: %08x\n", exe_sections[i + 1].rsz);
                break;
            }

            /* allocate needed buffer */
            if (!(src = cli_calloc (ssize + dsize, sizeof(char)))) {
                free(exe_sections);
                return CL_EMEM;
            }

            if((bytes = fmap_readn(map, src + dsize, exe_sections[i + 1].raw, exe_sections[i + 1].rsz)) != exe_sections[i + 1].rsz) {
                cli_dbgmsg("MEW: Can't read %d bytes [read: %lu]\n", exe_sections[i + 1].rsz, (unsigned long)bytes);
                free(exe_sections);
                free(src);
                return CL_EREAD;
            }

            cli_dbgmsg("MEW: %u (%08x) bytes read\n", (unsigned int)bytes, (unsigned int)bytes);

            /* count offset to lzma proc, if lzma used, 0xe8 -> call */
            if (tbuff[0x7b] == '\xe8') {
                if (!CLI_ISCONTAINED(exe_sections[1].rva, exe_sections[1].vsz, cli_readint32(tbuff + 0x7c) + fileoffset + 0x80, 4)) {
                    cli_dbgmsg("MEW: lzma proc out of bounds!\n");
                    free(src);
                    break; /* to next unpacker in chain */
                }

                uselzma = cli_readint32(tbuff + 0x7c) - (exe_sections[0].rva - fileoffset - 0x80);
            } else {
                uselzma = 0;
            }

#if HAVE_JSON
            if (pe_json != NULL)
                cli_jsonstr(pe_json, "Packer", "MEW");
#endif

            CLI_UNPTEMP("MEW",(src,exe_sections,0));
            CLI_UNPRESULTS("MEW",(unmew11(src, offdiff, ssize, dsize, EC32(optional_hdr32.ImageBase), exe_sections[0].rva, uselzma, ndesc)),1,(src,0));
            break;
        }
    }

    if(epsize<168) {
        free(exe_sections);
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
        while(((upack && nsections == 3) && /* 3 sections */
            ((
             epbuff[0] == '\xbe' && cli_readint32(epbuff + 1) - EC32(optional_hdr32.ImageBase) > min && /* mov esi */
             epbuff[5] == '\xad' && epbuff[6] == '\x50' /* lodsd; push eax */
             )
            || 
            /* based on 0297729 sample from aCaB */
            (epbuff[0] == '\xbe' && cli_readint32(epbuff + 1) - EC32(optional_hdr32.ImageBase) > min && /* mov esi */
             epbuff[5] == '\xff' && epbuff[6] == '\x36' /* push [esi] */
             )
           )) 
           ||
           ((!upack && nsections == 2) && /* 2 sections */
            (( /* upack 0.39-2s */
             epbuff[0] == '\x60' && epbuff[1] == '\xe8' && cli_readint32(epbuff+2) == 0x9 /* pusha; call+9 */
             )
            ||
            ( /* upack 1.1/1.2, based on 2 samples */
             epbuff[0] == '\xbe' && cli_readint32(epbuff+1) - EC32(optional_hdr32.ImageBase) < min &&  /* mov esi */
             cli_readint32(epbuff + 1) - EC32(optional_hdr32.ImageBase) > 0 &&
             epbuff[5] == '\xad' && epbuff[6] == '\x8b' && epbuff[7] == '\xf8' /* loads;  mov edi, eax */
             )
           ))
           ) { 
            uint32_t vma, off;
            int a,b,c;

            cli_dbgmsg("Upack characteristics found.\n");
            a = exe_sections[0].vsz;
            b = exe_sections[1].vsz;
            if (upack) {
                cli_dbgmsg("Upack: var set\n");

                c = exe_sections[2].vsz;
                ssize = exe_sections[0].ursz + exe_sections[0].uraw;
                off = exe_sections[0].rva;
                vma = EC32(optional_hdr32.ImageBase) + exe_sections[0].rva;
            } else {
                cli_dbgmsg("Upack: var NOT set\n");
                c = exe_sections[1].rva;
                ssize = exe_sections[1].uraw;
                off = 0;
                vma = exe_sections[1].rva - exe_sections[1].uraw;
            }

            dsize = a+b+c;

            CLI_UNPSIZELIMITS("Upack", MAX(MAX(dsize, ssize), exe_sections[1].ursz));

            if (!CLI_ISCONTAINED(0, dsize, exe_sections[1].rva - off, exe_sections[1].ursz) || (upack && !CLI_ISCONTAINED(0, dsize, exe_sections[2].rva - exe_sections[0].rva, ssize)) || ssize > dsize) {
                cli_dbgmsg("Upack: probably malformed pe-header, skipping to next unpacker\n");
                break;
            }
                
            if((dest = (char *) cli_calloc(dsize, sizeof(char))) == NULL) {
                free(exe_sections);
                return CL_EMEM;
            }

            if((unsigned int)fmap_readn(map, dest, 0, ssize) != ssize) {
                cli_dbgmsg("Upack: Can't read raw data of section 0\n");
                free(dest);
                break;
            }

            if(upack)
                memmove(dest + exe_sections[2].rva - exe_sections[0].rva, dest, ssize);

            if((unsigned int)fmap_readn(map, dest + exe_sections[1].rva - off, exe_sections[1].uraw, exe_sections[1].ursz) != exe_sections[1].ursz) {
                cli_dbgmsg("Upack: Can't read raw data of section 1\n");
                free(dest);
                break;
            }

#if HAVE_JSON
            if (pe_json != NULL)
                cli_jsonstr(pe_json, "Packer", "Upack");
#endif

            CLI_UNPTEMP("Upack",(dest,exe_sections,0));
            CLI_UNPRESULTS("Upack",(unupack(upack, dest, dsize, epbuff, vma, ep, EC32(optional_hdr32.ImageBase), exe_sections[0].rva, ndesc)),1,(dest,0));

            break;
        }
    }
    
    while(found  && (DCONF & PE_CONF_FSG) && epbuff[0] == '\x87' && epbuff[1] == '\x25') {
        const char *dst;
        uint32_t newesi, newedi, newebx, newedx;

        /* FSG v2.0 support - thanks to aCaB ! */
        
        ssize = exe_sections[i + 1].rsz;
        dsize = exe_sections[i].vsz;

        CLI_UNPSIZELIMITS("FSG", MAX(dsize, ssize));

        if(ssize <= 0x19 || dsize <= ssize) {
            cli_dbgmsg("FSG: Size mismatch (ssize: %d, dsize: %d)\n", ssize, dsize);
            free(exe_sections);
            return CL_CLEAN;
        }
        
        newedx = cli_readint32(epbuff + 2) - EC32(optional_hdr32.ImageBase);
        if(!CLI_ISCONTAINED(exe_sections[i + 1].rva, exe_sections[i + 1].rsz, newedx, 4)) {
            cli_dbgmsg("FSG: xchg out of bounds (%x), giving up\n", newedx);
            break;
        }
        
        if(!exe_sections[i + 1].rsz || !(src = fmap_need_off_once(map, exe_sections[i + 1].raw, ssize))) {
            cli_dbgmsg("Can't read raw data of section %d\n", i + 1);
            free(exe_sections);
            return CL_ESEEK;
        }

        dst = src + newedx - exe_sections[i + 1].rva;
        if(newedx < exe_sections[i + 1].rva || !CLI_ISCONTAINED(src, ssize, dst, 4)) {
            cli_dbgmsg("FSG: New ESP out of bounds\n");
            break;
        }

        newedx = cli_readint32(dst) - EC32(optional_hdr32.ImageBase);
        if(!CLI_ISCONTAINED(exe_sections[i + 1].rva, exe_sections[i + 1].rsz, newedx, 4)) {
            cli_dbgmsg("FSG: New ESP (%x) is wrong\n", newedx);
            break;
        }
     
        dst = src + newedx - exe_sections[i + 1].rva;
        if(!CLI_ISCONTAINED(src, ssize, dst, 32)) {
            cli_dbgmsg("FSG: New stack out of bounds\n");
            break;
        }

        newedi = cli_readint32(dst) - EC32(optional_hdr32.ImageBase);
        newesi = cli_readint32(dst + 4) - EC32(optional_hdr32.ImageBase);
        newebx = cli_readint32(dst + 16) - EC32(optional_hdr32.ImageBase);
        newedx = cli_readint32(dst + 20);

        if(newedi != exe_sections[i].rva) {
            cli_dbgmsg("FSG: Bad destination buffer (edi is %x should be %x)\n", newedi, exe_sections[i].rva);
            break;
        }

        if(newesi < exe_sections[i + 1].rva || newesi - exe_sections[i + 1].rva >= exe_sections[i + 1].rsz) {
            cli_dbgmsg("FSG: Source buffer out of section bounds\n");
            break;
        }

        if(!CLI_ISCONTAINED(exe_sections[i + 1].rva, exe_sections[i + 1].rsz, newebx, 16)) {
            cli_dbgmsg("FSG: Array of functions out of bounds\n");
            break;
        }

        newedx=cli_readint32(newebx + 12 - exe_sections[i + 1].rva + src) - EC32(optional_hdr32.ImageBase);
        cli_dbgmsg("FSG: found old EP @%x\n",newedx);

        if((dest = (char *) cli_calloc(dsize, sizeof(char))) == NULL) {
            free(exe_sections);
            return CL_EMEM;
        }

#if HAVE_JSON
        if (pe_json != NULL)
            cli_jsonstr(pe_json, "Packer", "FSG");
#endif

        CLI_UNPTEMP("FSG",(dest,exe_sections,0));
        CLI_UNPRESULTSFSG2("FSG",(unfsg_200(newesi - exe_sections[i + 1].rva + src, dest, ssize + exe_sections[i + 1].rva - newesi, dsize, newedi, EC32(optional_hdr32.ImageBase), newedx, ndesc)),1,(dest,0));
        break;
    }


    while(found && (DCONF & PE_CONF_FSG) && epbuff[0] == '\xbe' && cli_readint32(epbuff + 1) - EC32(optional_hdr32.ImageBase) < min) {
        int sectcnt = 0;
        const char *support;
        uint32_t newesi, newedi, oldep, gp, t;
        struct cli_exe_section *sections;

        /* FSG support - v. 1.33 (thx trog for the many samples) */

        ssize = exe_sections[i + 1].rsz;
        dsize = exe_sections[i].vsz;

        CLI_UNPSIZELIMITS("FSG", MAX(dsize, ssize));

        if(ssize <= 0x19 || dsize <= ssize) {
            cli_dbgmsg("FSG: Size mismatch (ssize: %d, dsize: %d)\n", ssize, dsize);
            free(exe_sections);
            return CL_CLEAN;
        }

        if(!(t = cli_rawaddr(cli_readint32(epbuff + 1) - EC32(optional_hdr32.ImageBase), NULL, 0 , &err, fsize, hdr_size)) && err ) {
            cli_dbgmsg("FSG: Support data out of padding area\n");
            break;
        }

        gp = exe_sections[i + 1].raw - t;

        CLI_UNPSIZELIMITS("FSG", gp);

        if(!(support = fmap_need_off_once(map, t, gp))) {
            cli_dbgmsg("Can't read %d bytes from padding area\n", gp); 
            free(exe_sections);
            return CL_EREAD;
        }

        /* newebx = cli_readint32(support) - EC32(optional_hdr32.ImageBase);  Unused */
        newedi = cli_readint32(support + 4) - EC32(optional_hdr32.ImageBase); /* 1st dest */
        newesi = cli_readint32(support + 8) - EC32(optional_hdr32.ImageBase); /* Source */

        if(newesi < exe_sections[i + 1].rva || newesi - exe_sections[i + 1].rva >= exe_sections[i + 1].rsz) {
            cli_dbgmsg("FSG: Source buffer out of section bounds\n");
            break;
        }

        if(newedi != exe_sections[i].rva) {
            cli_dbgmsg("FSG: Bad destination (is %x should be %x)\n", newedi, exe_sections[i].rva);
            break;
        }

        /* Counting original sections */
        for(t = 12; t < gp - 4; t += 4) {
            uint32_t rva = cli_readint32(support+t);

            if(!rva)
                break;

            rva -= EC32(optional_hdr32.ImageBase)+1;
            sectcnt++;

            if(rva % 0x1000)
                cli_dbgmsg("FSG: Original section %d is misaligned\n", sectcnt);

            if(rva < exe_sections[i].rva || rva - exe_sections[i].rva >= exe_sections[i].vsz) {
                cli_dbgmsg("FSG: Original section %d is out of bounds\n", sectcnt);
                break;
            }
        }

        if(t >= gp - 4 || cli_readint32(support + t)) {
            break;
        }

        if((sections = (struct cli_exe_section *) cli_malloc((sectcnt + 1) * sizeof(struct cli_exe_section))) == NULL) {
            cli_errmsg("FSG: Unable to allocate memory for sections %llu\n", (long long unsigned)((sectcnt + 1) * sizeof(struct cli_exe_section)));
            free(exe_sections);
            return CL_EMEM;
        }

        sections[0].rva = newedi;
        for(t = 1; t <= (uint32_t)sectcnt; t++)
            sections[t].rva = cli_readint32(support + 8 + t * 4) - 1 - EC32(optional_hdr32.ImageBase);

        if(!exe_sections[i + 1].rsz || !(src = fmap_need_off_once(map, exe_sections[i + 1].raw, ssize))) {
            cli_dbgmsg("Can't read raw data of section %d\n", i);
            free(exe_sections);
            free(sections);
            return CL_EREAD;
        }

        if((dest = (char *) cli_calloc(dsize, sizeof(char))) == NULL) {
            free(exe_sections);
            free(sections);
            return CL_EMEM;
        }

        oldep = vep + 161 + 6 + cli_readint32(epbuff+163);
        cli_dbgmsg("FSG: found old EP @%x\n", oldep);

#if HAVE_JSON
        if (pe_json != NULL)
            cli_jsonstr(pe_json, "Packer", "FSG");
#endif

        CLI_UNPTEMP("FSG",(dest,sections,exe_sections,0));
        CLI_UNPRESULTSFSG1("FSG",(unfsg_133(src + newesi - exe_sections[i + 1].rva, dest, ssize + exe_sections[i + 1].rva - newesi, dsize, sections, sectcnt, EC32(optional_hdr32.ImageBase), oldep, ndesc)),1,(dest,sections,0));
        break; /* were done with 1.33 */
    }

    while(found && (DCONF & PE_CONF_FSG) && epbuff[0] == '\xbb' && cli_readint32(epbuff + 1) - EC32(optional_hdr32.ImageBase) < min && epbuff[5] == '\xbf' && epbuff[10] == '\xbe' && vep >= exe_sections[i + 1].rva && vep - exe_sections[i + 1].rva > exe_sections[i + 1].rva - 0xe0 ) {
        int sectcnt = 0;
        uint32_t gp, t = cli_rawaddr(cli_readint32(epbuff+1) - EC32(optional_hdr32.ImageBase), NULL, 0 , &err, fsize, hdr_size);
        const char *support;
        uint32_t newesi = cli_readint32(epbuff+11) - EC32(optional_hdr32.ImageBase);
        uint32_t newedi = cli_readint32(epbuff+6) - EC32(optional_hdr32.ImageBase);
        uint32_t oldep = vep - exe_sections[i + 1].rva;
        struct cli_exe_section *sections;

        /* FSG support - v. 1.31 */

        ssize = exe_sections[i + 1].rsz;
        dsize = exe_sections[i].vsz;

        if(err) {
            cli_dbgmsg("FSG: Support data out of padding area\n");
            break;
        }

        if(newesi < exe_sections[i + 1].rva || newesi - exe_sections[i + 1].rva >= exe_sections[i + 1].raw) {
            cli_dbgmsg("FSG: Source buffer out of section bounds\n");
            break;
        }

        if(newedi != exe_sections[i].rva) {
            cli_dbgmsg("FSG: Bad destination (is %x should be %x)\n", newedi, exe_sections[i].rva);
            break;
        }

        CLI_UNPSIZELIMITS("FSG", MAX(dsize, ssize));

        if(ssize <= 0x19 || dsize <= ssize) {
            cli_dbgmsg("FSG: Size mismatch (ssize: %d, dsize: %d)\n", ssize, dsize);
            free(exe_sections);
            return CL_CLEAN;
        }

        gp = exe_sections[i + 1].raw - t;

        CLI_UNPSIZELIMITS("FSG", gp)

        if(!(support = fmap_need_off_once(map, t, gp))) {
            cli_dbgmsg("Can't read %d bytes from padding area\n", gp); 
            free(exe_sections);
            return CL_EREAD;
        }

        /* Counting original sections */
        for(t = 0; t < gp - 2; t += 2) {
            uint32_t rva = support[t]|(support[t+1]<<8);

            if (rva == 2 || rva == 1)
                break;

            rva = ((rva-2)<<12) - EC32(optional_hdr32.ImageBase);
            sectcnt++;

            if(rva < exe_sections[i].rva || rva - exe_sections[i].rva >= exe_sections[i].vsz) {
                cli_dbgmsg("FSG: Original section %d is out of bounds\n", sectcnt);
                break;
            }
        }

        if(t >= gp-10 || cli_readint32(support + t + 6) != 2)
            break;

        if((sections = (struct cli_exe_section *) cli_malloc((sectcnt + 1) * sizeof(struct cli_exe_section))) == NULL) {
            cli_errmsg("FSG: Unable to allocate memory for sections %llu\n", (long long unsigned)((sectcnt + 1) * sizeof(struct cli_exe_section)));
            free(exe_sections);
            return CL_EMEM;
        }

        sections[0].rva = newedi;
        for(t = 0; t <= (uint32_t)sectcnt - 1; t++)
            sections[t+1].rva = (((support[t*2]|(support[t*2+1]<<8))-2)<<12)-EC32(optional_hdr32.ImageBase);

        if(!exe_sections[i + 1].rsz || !(src = fmap_need_off_once(map, exe_sections[i + 1].raw, ssize))) {
            cli_dbgmsg("FSG: Can't read raw data of section %d\n", i);
            free(exe_sections);
            free(sections);
            return CL_EREAD;
        }

        if((dest = (char *) cli_calloc(dsize, sizeof(char))) == NULL) {
            free(exe_sections);
            free(sections);
            return CL_EMEM;
        }

        gp = 0xda + 6*(epbuff[16]=='\xe8');
        oldep = vep + gp + 6 + cli_readint32(src+gp+2+oldep);
        cli_dbgmsg("FSG: found old EP @%x\n", oldep);

#if HAVE_JSON
        if (pe_json != NULL)
            cli_jsonstr(pe_json, "Packer", "FSG");
#endif

        CLI_UNPTEMP("FSG",(dest,sections,exe_sections,0));
        CLI_UNPRESULTSFSG1("FSG",(unfsg_133(src + newesi - exe_sections[i + 1].rva, dest, ssize + exe_sections[i + 1].rva - newesi, dsize, sections, sectcnt, EC32(optional_hdr32.ImageBase), oldep, ndesc)),1,(dest,sections,0));

        break; /* were done with 1.31 */
    }


    if(found && (DCONF & PE_CONF_UPX)) {
        ssize = exe_sections[i + 1].rsz;
        dsize = exe_sections[i].vsz + exe_sections[i + 1].vsz;

        /* 
         * UPX support
         * we assume (i + 1) is UPX1
         */

            /* cli_dbgmsg("UPX: ssize %u dsize %u\n", ssize, dsize); */

        CLI_UNPSIZELIMITS("UPX", MAX(dsize, ssize));

        if(ssize <= 0x19 || dsize <= ssize || dsize > CLI_MAX_ALLOCATION ) {
            cli_dbgmsg("UPX: Size mismatch or dsize too big (ssize: %d, dsize: %d)\n", ssize, dsize);
            free(exe_sections);
            return CL_CLEAN;
        }

        if(!exe_sections[i + 1].rsz || !(src = fmap_need_off_once(map, exe_sections[i + 1].raw, ssize))) {
            cli_dbgmsg("UPX: Can't read raw data of section %d\n", i+1);
            free(exe_sections);
            return CL_EREAD;
        }

        if((dest = (char *) cli_calloc(dsize + 8192, sizeof(char))) == NULL) {
            free(exe_sections);
            return CL_EMEM;
        }

        /* try to detect UPX code */
        if(cli_memstr(UPX_NRV2B, 24, epbuff + 0x69, 13) || cli_memstr(UPX_NRV2B, 24, epbuff + 0x69 + 8, 13)) {
            cli_dbgmsg("UPX: Looks like a NRV2B decompression routine\n");
            upxfn = upx_inflate2b;
        } else if(cli_memstr(UPX_NRV2D, 24, epbuff + 0x69, 13) || cli_memstr(UPX_NRV2D, 24, epbuff + 0x69 + 8, 13)) {
            cli_dbgmsg("UPX: Looks like a NRV2D decompression routine\n");
            upxfn = upx_inflate2d;
        } else if(cli_memstr(UPX_NRV2E, 24, epbuff + 0x69, 13) || cli_memstr(UPX_NRV2E, 24, epbuff + 0x69 + 8, 13)) {
            cli_dbgmsg("UPX: Looks like a NRV2E decompression routine\n");
            upxfn = upx_inflate2e;
        }

        if(upxfn) {
            int skew = cli_readint32(epbuff + 2) - EC32(optional_hdr32.ImageBase) - exe_sections[i + 1].rva;

            if(epbuff[1] != '\xbe' || skew <= 0 || skew > 0xfff) {
                /* FIXME: legit skews?? */
                skew = 0; 
            } else if ((unsigned int)skew > ssize) {
                /* Ignore suggested skew larger than section size */
                skew = 0;
            } else {
                cli_dbgmsg("UPX: UPX1 seems skewed by %d bytes\n", skew);
            }

            /* Try skewed first (skew may be zero) */
            if(upxfn(src + skew, ssize - skew, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep-skew) >= 0) {
                upx_success = 1;
            }
            /* If skew not successful and non-zero, try no skew */
            else if(skew && (upxfn(src, ssize, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep) >= 0)) {
                upx_success = 1;
            }

            if(upx_success)
                cli_dbgmsg("UPX: Successfully decompressed\n");
            else
                cli_dbgmsg("UPX: Preferred decompressor failed\n");
        }

        if(!upx_success && upxfn != upx_inflate2b) {
            if(upx_inflate2b(src, ssize, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep) == -1 && upx_inflate2b(src + 0x15, ssize - 0x15, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep - 0x15) == -1) {

                cli_dbgmsg("UPX: NRV2B decompressor failed\n");
            } else {
                upx_success = 1;
                cli_dbgmsg("UPX: Successfully decompressed with NRV2B\n");
            }
        }

        if(!upx_success && upxfn != upx_inflate2d) {
            if(upx_inflate2d(src, ssize, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep) == -1 && upx_inflate2d(src + 0x15, ssize - 0x15, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep - 0x15) == -1) {

                cli_dbgmsg("UPX: NRV2D decompressor failed\n");
            } else {
                upx_success = 1;
                cli_dbgmsg("UPX: Successfully decompressed with NRV2D\n");
            }
        }

        if(!upx_success && upxfn != upx_inflate2e) {
            if(upx_inflate2e(src, ssize, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep) == -1 && upx_inflate2e(src + 0x15, ssize - 0x15, dest, &dsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep - 0x15) == -1) {
                cli_dbgmsg("UPX: NRV2E decompressor failed\n");
            } else {
                upx_success = 1;
                cli_dbgmsg("UPX: Successfully decompressed with NRV2E\n");
            }
        }

        if(cli_memstr(UPX_LZMA2, 20, epbuff + 0x2f, 20)) {
            uint32_t strictdsize=cli_readint32(epbuff+0x21), skew = 0;
            if(ssize > 0x15 && epbuff[0] == '\x60' && epbuff[1] == '\xbe') {
                skew = cli_readint32(epbuff+2) - exe_sections[i + 1].rva - optional_hdr32.ImageBase;
                if(skew!=0x15)
                    skew = 0;
            }

            if(strictdsize<=dsize)
                upx_success = upx_inflatelzma(src+skew, ssize-skew, dest, &strictdsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep, 0x20003) >=0;
        } else if (cli_memstr(UPX_LZMA1_FIRST, 8, epbuff + 0x39, 8) && cli_memstr(UPX_LZMA1_SECOND, 8, epbuff + 0x45, 8)) {
            uint32_t strictdsize=cli_readint32(epbuff+0x2b), skew = 0;
            uint32_t properties=cli_readint32(epbuff+0x41);
            if(ssize > 0x15 && epbuff[0] == '\x60' && epbuff[1] == '\xbe') {
                skew = cli_readint32(epbuff+2) - exe_sections[i + 1].rva - optional_hdr32.ImageBase;
                if(skew!=0x15)
                    skew = 0;
            }

            if(strictdsize<=dsize)
                upx_success = upx_inflatelzma(src+skew, ssize-skew, dest, &strictdsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep, properties) >=0;
        }

        if(!upx_success) {
            cli_dbgmsg("UPX: All decompressors failed\n");
            free(dest);
        }
    }

    if(upx_success) {
        free(exe_sections);

        CLI_UNPTEMP("UPX/FSG",(dest,0));
#if HAVE_JSON
        if (pe_json != NULL)
            cli_jsonstr(pe_json, "Packer", "UPX");
#endif

        if((unsigned int) write(ndesc, dest, dsize) != dsize) {
            cli_dbgmsg("UPX/FSG: Can't write %d bytes\n", dsize);
            free(tempfile);
            free(dest);
            close(ndesc);
            return CL_EWRITE;
        }

        free(dest);
        if (lseek(ndesc, 0, SEEK_SET) == -1) {
            cli_dbgmsg("UPX/FSG: lseek() failed\n");
            close(ndesc);
            CLI_TMPUNLK();
            free(tempfile);
            SHA_RESET;
            return CL_ESEEK;
        }

        if(ctx->engine->keeptmp)
            cli_dbgmsg("UPX/FSG: Decompressed data saved in %s\n", tempfile);

        cli_dbgmsg("***** Scanning decompressed file *****\n");
        SHA_OFF;
        if((ret = cli_magic_scandesc(ndesc, tempfile, ctx)) == CL_VIRUS) {
            close(ndesc);
            CLI_TMPUNLK();
            free(tempfile);
            SHA_RESET;
            return CL_VIRUS;
        }

        SHA_RESET;
        close(ndesc);
        CLI_TMPUNLK();
        free(tempfile);
        return ret;
    }


    /* Petite */

    if(epsize<200) {
        free(exe_sections);
        return CL_CLEAN;
    }

    found = 2;

    if(epbuff[0] != '\xb8' || (uint32_t) cli_readint32(epbuff + 1) != exe_sections[nsections - 1].rva + EC32(optional_hdr32.ImageBase)) {
        if(nsections < 2 || epbuff[0] != '\xb8' || (uint32_t) cli_readint32(epbuff + 1) != exe_sections[nsections - 2].rva + EC32(optional_hdr32.ImageBase))
            found = 0;
        else
            found = 1;
    }

    if(found && (DCONF & PE_CONF_PETITE)) {
        cli_dbgmsg("Petite: v2.%d compression detected\n", found);

        if(cli_readint32(epbuff + 0x80) == 0x163c988d) {
            cli_dbgmsg("Petite: level zero compression is not supported yet\n");
        } else {
            dsize = max - min;

            CLI_UNPSIZELIMITS("Petite", dsize);

            if((dest = (char *) cli_calloc(dsize, sizeof(char))) == NULL) {
                cli_dbgmsg("Petite: Can't allocate %d bytes\n", dsize);
                free(exe_sections);
                return CL_EMEM;
            }

            for(i = 0 ; i < nsections; i++) {
                if(exe_sections[i].raw) {
                        unsigned int r_ret;

                        if (!exe_sections[i].rsz)
                                goto out_no_petite;

                        if (!CLI_ISCONTAINED(dest, dsize,
                                             dest + exe_sections[i].rva - min,
                                             exe_sections[i].ursz))
                                goto out_no_petite;

                        r_ret = fmap_readn(map, dest + exe_sections[i].rva - min,
                                        exe_sections[i].raw,
                                        exe_sections[i].ursz);
                    if (r_ret != exe_sections[i].ursz) {
out_no_petite:
                        free(exe_sections);
                        free(dest);
                        return CL_CLEAN;
                    }
                }
            }

#if HAVE_JSON
            if (pe_json != NULL)
                cli_jsonstr(pe_json, "Packer", "Petite");
#endif

            CLI_UNPTEMP("Petite",(dest,exe_sections,0));
            CLI_UNPRESULTS("Petite",(petite_inflate2x_1to9(dest, min, max - min, exe_sections, nsections - (found == 1 ? 1 : 0), EC32(optional_hdr32.ImageBase),vep, ndesc, found, EC32(optional_hdr32.DataDirectory[2].VirtualAddress),EC32(optional_hdr32.DataDirectory[2].Size))),0,(dest,0));
        }
    }

    /* PESpin 1.1 */

    if((DCONF & PE_CONF_PESPIN) && nsections > 1 &&
       vep >= exe_sections[nsections - 1].rva &&
       0x3217 - 4 <= exe_sections[nsections - 1].rva + exe_sections[nsections - 1].rsz &&
       vep < exe_sections[nsections - 1].rva + exe_sections[nsections - 1].rsz - 0x3217 - 4 &&
       memcmp(epbuff+4, "\xe8\x00\x00\x00\x00\x8b\x1c\x24\x83\xc3", 10) == 0)  {

        char *spinned;

        CLI_UNPSIZELIMITS("PEspin", fsize);

        if((spinned = (char *) cli_malloc(fsize)) == NULL) {
            cli_errmsg("PESping: Unable to allocate memory for spinned %lu\n", (unsigned long)fsize);
            free(exe_sections);
            return CL_EMEM;
        }

        if((size_t) fmap_readn(map, spinned, 0, fsize) != fsize) {
            cli_dbgmsg("PESpin: Can't read %lu bytes\n", (unsigned long)fsize);
            free(spinned);
            free(exe_sections);
            return CL_EREAD;
        }

#if HAVE_JSON
        if (pe_json != NULL)
            cli_jsonstr(pe_json, "Packer", "PEspin");
#endif

        CLI_UNPTEMP("PESpin",(spinned,exe_sections,0));
        CLI_UNPRESULTS_("PEspin",SPINCASE(),(unspin(spinned, fsize, exe_sections, nsections - 1, vep, ndesc, ctx)),0,(spinned,0));
    }


    /* yC 1.3 & variants */
    if((DCONF & PE_CONF_YC) && nsections > 1 &&
       (EC32(optional_hdr32.AddressOfEntryPoint) == exe_sections[nsections - 1].rva + 0x60)) {

        uint32_t ecx = 0;
        int16_t offset;

        /* yC 1.3 */
        if (!memcmp(epbuff, "\x55\x8B\xEC\x53\x56\x57\x60\xE8\x00\x00\x00\x00\x5D\x81\xED", 15) &&
            !memcmp(epbuff+0x26, "\x8D\x3A\x8B\xF7\x33\xC0\xEB\x04\x90\xEB\x01\xC2\xAC", 13) &&
            ((uint8_t)epbuff[0x13] == 0xB9) &&
            ((uint16_t)(cli_readint16(epbuff+0x18)) == 0xE981) &&
            !memcmp(epbuff+0x1e,"\x8B\xD5\x81\xC2", 4)) {

            offset = 0;
            if (0x6c - cli_readint32(epbuff+0xf) + cli_readint32(epbuff+0x22) == 0xC6)
            ecx = cli_readint32(epbuff+0x14) - cli_readint32(epbuff+0x1a);
        }

        /* yC 1.3 variant */
        if (!ecx && !memcmp(epbuff, "\x55\x8B\xEC\x83\xEC\x40\x53\x56\x57", 9) &&
            !memcmp(epbuff+0x17, "\xe8\x00\x00\x00\x00\x5d\x81\xed", 8) &&
            ((uint8_t)epbuff[0x23] == 0xB9)) {

            offset = 0x10;
            if (0x6c - cli_readint32(epbuff+0x1f) + cli_readint32(epbuff+0x32) == 0xC6)
            ecx = cli_readint32(epbuff+0x24) - cli_readint32(epbuff+0x2a);
        }

        /* yC 1.x/modified */
        if (!ecx && !memcmp(epbuff, "\x60\xe8\x00\x00\x00\x00\x5d\x81\xed",9) &&
            ((uint8_t)epbuff[0xd] == 0xb9) &&
            ((uint16_t)cli_readint16(epbuff + 0x12)== 0xbd8d) &&
            !memcmp(epbuff+0x18, "\x8b\xf7\xac", 3)) {

            offset = -0x18;
            if (0x66 - cli_readint32(epbuff+0x9) + cli_readint32(epbuff+0x14) == 0xae)
            ecx = cli_readint32(epbuff+0xe);
        }

        if (ecx > 0x800 && ecx < 0x2000 &&
            !memcmp(epbuff+0x63+offset, "\xaa\xe2\xcc", 3) &&
            (fsize >= exe_sections[nsections-1].raw + 0xC6 + ecx + offset)) {

            char *spinned;

            if((spinned = (char *) cli_malloc(fsize)) == NULL) {
                cli_errmsg("yC: Unable to allocate memory for spinned %lu\n", (unsigned long)fsize);
                free(exe_sections);
                return CL_EMEM;
            }

            if((size_t) fmap_readn(map, spinned, 0, fsize) != fsize) {
                cli_dbgmsg("yC: Can't read %lu bytes\n", (unsigned long)fsize);
                free(spinned);
                free(exe_sections);
                return CL_EREAD;
            }

#if HAVE_JSON
            if (pe_json != NULL)
                cli_jsonstr(pe_json, "Packer", "yC");
#endif

            do {
                unsigned int yc_unp_num_viruses = ctx->num_viruses;
                const char *yc_unp_virname = NULL;

                if (ctx->virname)
                    yc_unp_virname = ctx->virname[0];

                cli_dbgmsg("%d,%d,%d,%d\n", nsections-1, e_lfanew, ecx, offset);
                CLI_UNPTEMP("yC",(spinned,exe_sections,0));
                CLI_UNPRESULTS("yC",(yc_decrypt(ctx, spinned, fsize, exe_sections, nsections-1, e_lfanew, ndesc, ecx, offset)),0,(spinned,0));

                if (SCAN_ALLMATCHES && yc_unp_num_viruses != ctx->num_viruses) {
                    free(exe_sections);
                    return CL_VIRUS;
                }
                else if (ctx->virname && yc_unp_virname != ctx->virname[0]) {
                    free(exe_sections);
                    return CL_VIRUS;
                }
            } while(0);
        }
    }

    /* WWPack */

    while ((DCONF & PE_CONF_WWPACK) && nsections > 1 &&
       vep == exe_sections[nsections - 1].rva &&
       memcmp(epbuff, "\x53\x55\x8b\xe8\x33\xdb\xeb", 7) == 0 &&
       memcmp(epbuff+0x68, "\xe8\x00\x00\x00\x00\x58\x2d\x6d\x00\x00\x00\x50\x60\x33\xc9\x50\x58\x50\x50", 19) == 0)  {
        uint32_t head = exe_sections[nsections - 1].raw;
        uint8_t *packer;
        char *src;

        ssize = 0;
        for(i=0 ; ; i++) {
            if(exe_sections[i].raw<head)
                head=exe_sections[i].raw;

            if(i+1==nsections)
                break;

            if(ssize<exe_sections[i].rva+exe_sections[i].vsz)
                ssize=exe_sections[i].rva+exe_sections[i].vsz;
        }

        if(!head || !ssize || head>ssize)
            break;

        CLI_UNPSIZELIMITS("WWPack", ssize);

        if(!(src=(char *)cli_calloc(ssize, sizeof(char)))) {
            free(exe_sections);
            return CL_EMEM;
        }

        if((size_t) fmap_readn(map, src, 0, head) != head) {
            cli_dbgmsg("WWPack: Can't read %d bytes from headers\n", head);
            free(src);
            free(exe_sections);
            return CL_EREAD;
        }

        for(i = 0 ; i < (unsigned int)nsections-1; i++) {
            if(!exe_sections[i].rsz)
                continue;

            if(!CLI_ISCONTAINED(src, ssize, src+exe_sections[i].rva, exe_sections[i].rsz))
                break;

            if((unsigned int)fmap_readn(map, src+exe_sections[i].rva, exe_sections[i].raw, exe_sections[i].rsz)!=exe_sections[i].rsz)
                break;
        }

        if(i+1!=nsections) {
            cli_dbgmsg("WWpack: Probably hacked/damaged file.\n");
            free(src);
            break;
        }

        if((packer = (uint8_t *) cli_calloc(exe_sections[nsections - 1].rsz, sizeof(char))) == NULL) {
            free(src);
            free(exe_sections);
            return CL_EMEM;
        }

        if(!exe_sections[nsections - 1].rsz || (size_t) fmap_readn(map, packer, exe_sections[nsections - 1].raw, exe_sections[nsections - 1].rsz) != exe_sections[nsections - 1].rsz) {
            cli_dbgmsg("WWPack: Can't read %d bytes from wwpack sect\n", exe_sections[nsections - 1].rsz);
            free(src);
            free(packer);
            free(exe_sections);
            return CL_EREAD;
        }

#if HAVE_JSON
        if (pe_json != NULL)
            cli_jsonstr(pe_json, "Packer", "WWPack");
#endif

        CLI_UNPTEMP("WWPack",(src,packer,exe_sections,0));
        CLI_UNPRESULTS("WWPack",(wwunpack((uint8_t *)src, ssize, packer, exe_sections, nsections-1, e_lfanew, ndesc)),0,(src,packer,0));
        break;
    }


    /* ASPACK support */
    while((DCONF & PE_CONF_ASPACK) && 
          ((ep+ASPACK_EP_OFFSET_212 < fsize) || 
           (ep+ASPACK_EP_OFFSET_OTHER < fsize) || 
           (ep+ASPACK_EP_OFFSET_242 < fsize)) && 
          (!memcmp(epbuff,"\x60\xe8\x03\x00\x00\x00\xe9\xeb",8))) {
        char *src;
        aspack_version_t aspack_ver = ASPACK_VER_NONE;

        if(epsize<0x3bf)
            break;
        
        if ( 0 == memcmp(epbuff+ASPACK_EPBUFF_OFFSET_212, "\x68\x00\x00\x00\x00\xc3",6)) {
            aspack_ver = ASPACK_VER_212;
        } else if ( 0 == memcmp(epbuff+ASPACK_EPBUFF_OFFSET_OTHER, "\x68\x00\x00\x00\x00\xc3",6)) {
            aspack_ver = ASPACK_VER_OTHER;
        } else if ( 0 == memcmp(epbuff+ASPACK_EPBUFF_OFFSET_242, "\x68\x00\x00\x00\x00\xc3",6)) {
            aspack_ver = ASPACK_VER_242;
        } else {
            break;
        }
        ssize = 0;
        for(i=0 ; i< nsections ; i++)
            if(ssize<exe_sections[i].rva+exe_sections[i].vsz)
                ssize=exe_sections[i].rva+exe_sections[i].vsz;

        if(!ssize)
            break;

        CLI_UNPSIZELIMITS("Aspack", ssize);

        if(!(src=(char *)cli_calloc(ssize, sizeof(char)))) {
            free(exe_sections);
            return CL_EMEM;
        }
        for(i = 0 ; i < (unsigned int)nsections; i++) {
            if(!exe_sections[i].rsz)
                continue;

            if(!CLI_ISCONTAINED(src, ssize, src+exe_sections[i].rva, exe_sections[i].rsz))
                break;

            if((unsigned int)fmap_readn(map, src+exe_sections[i].rva, exe_sections[i].raw, exe_sections[i].rsz)!=exe_sections[i].rsz)
                break;
        }

        if(i!=nsections) {
            cli_dbgmsg("Aspack: Probably hacked/damaged Aspack file.\n");
            free(src);
            break;
        }

#if HAVE_JSON
        if (pe_json != NULL)
            cli_jsonstr(pe_json, "Packer", "Aspack");
#endif

        CLI_UNPTEMP("Aspack",(src,exe_sections,0));
        CLI_UNPRESULTS("Aspack",(unaspack((uint8_t *)src, ssize, exe_sections, nsections, vep-1, EC32(optional_hdr32.ImageBase), ndesc, aspack_ver)),1,(src,0));
        break;
    }

    /* NsPack */

    while (DCONF & PE_CONF_NSPACK) {
        uint32_t eprva = vep;
        uint32_t start_of_stuff, rep = ep;
        unsigned int nowinldr;
        const char *nbuff;

        src=epbuff;
        if (*epbuff=='\xe9') { /* bitched headers */
            eprva = cli_readint32(epbuff+1)+vep+5;
            if (!(rep = cli_rawaddr(eprva, exe_sections, nsections, &err, fsize, hdr_size)) && err)
                break;

            if (!(nbuff = fmap_need_off_once(map, rep, 24)))
                break;

            src = nbuff;
        }

        if (memcmp(src, "\x9c\x60\xe8\x00\x00\x00\x00\x5d\xb8\x07\x00\x00\x00", 13))
            break;

        nowinldr = 0x54-cli_readint32(src+17);
        cli_dbgmsg("NsPack: Found *start_of_stuff @delta-%x\n", nowinldr);

        if(!(nbuff = fmap_need_off_once(map, rep-nowinldr, 4)))
            break;

        start_of_stuff=rep+cli_readint32(nbuff);
        if(!(nbuff = fmap_need_off_once(map, start_of_stuff, 20)))
            break;

        src = nbuff;
        if (!cli_readint32(nbuff)) {
            start_of_stuff+=4; /* FIXME: more to do */
            src+=4;
        }

        ssize = cli_readint32(src+5)|0xff;
        dsize = cli_readint32(src+9);

        CLI_UNPSIZELIMITS("NsPack", MAX(ssize,dsize));

        if (!ssize || !dsize || dsize != exe_sections[0].vsz)
            break;

        if (!(dest=cli_malloc(dsize))) {
            cli_errmsg("NsPack: Unable to allocate memory for dest %u\n", dsize);
            break;
        }
        /* memset(dest, 0xfc, dsize); */

        if(!(src = fmap_need_off(map, start_of_stuff, ssize))) {
            free(dest);
            break;
        }
        /* memset(src, 0x00, ssize); */

        eprva+=0x27a;
        if (!(rep = cli_rawaddr(eprva, exe_sections, nsections, &err, fsize, hdr_size)) && err) {
          free(dest);
          break;
        }

        if(!(nbuff = fmap_need_off_once(map, rep, 5))) {
          free(dest);
          break;
        }

        fmap_unneed_off(map, start_of_stuff, ssize);
        eprva=eprva+5+cli_readint32(nbuff+1);
        cli_dbgmsg("NsPack: OEP = %08x\n", eprva);

#if HAVE_JSON
        if (pe_json != NULL)
            cli_jsonstr(pe_json, "Packer", "NsPack");
#endif

        CLI_UNPTEMP("NsPack",(dest,exe_sections,0));
        CLI_UNPRESULTS("NsPack",(unspack(src, dest, ctx, exe_sections[0].rva, EC32(optional_hdr32.ImageBase), eprva, ndesc)),0,(dest,0));
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

    cli_bytecode_context_setpe(bc_ctx, &pedata, exe_sections);
    cli_bytecode_context_setctx(bc_ctx, ctx);

    ret = cli_bytecode_runhook(ctx, ctx->engine, bc_ctx, BC_PE_UNPACKER, map);
    switch (ret) {
    case CL_VIRUS:
        free(exe_sections);
        cli_bytecode_context_destroy(bc_ctx);
        return CL_VIRUS;
    case CL_SUCCESS:
        ndesc = cli_bytecode_context_getresult_file(bc_ctx, &tempfile);
        cli_bytecode_context_destroy(bc_ctx);
        if (ndesc != -1 && tempfile) {
            CLI_UNPRESULTS("bytecode PE hook", 1, 1, (0));
        }

        break;
    default:
        cli_bytecode_context_destroy(bc_ctx);
    }

    free(exe_sections);

#if HAVE_JSON
    if (cli_json_timeout_cycle_check(ctx, &toval) != CL_SUCCESS)
        return CL_ETIMEOUT;
#endif

    if (SCAN_ALLMATCHES && viruses_found)
        return CL_VIRUS;

    return CL_CLEAN;
}

int cli_peheader(fmap_t *map, struct cli_exe_info *peinfo)
{
    uint16_t e_magic; /* DOS signature ("MZ") */
    uint32_t e_lfanew; /* address of new exe header */
    /* Obsolete - see below
      uint32_t min = 0, max = 0;
    */
    struct pe_image_file_hdr file_hdr;
    union {
        struct pe_image_optional_hdr64 opt64;
        struct pe_image_optional_hdr32 opt32;
    } pe_opt;
    struct pe_image_section_hdr *section_hdr;
    unsigned int i;
    unsigned int err, pe_plus = 0;
    uint32_t valign, falign, hdr_size;
    size_t fsize;
    ssize_t at;
    struct pe_image_data_dir *dirs;

    cli_dbgmsg("in cli_peheader\n");

    fsize = map->len - peinfo->offset;
    if(fmap_readn(map, &e_magic, peinfo->offset, sizeof(e_magic)) != sizeof(e_magic)) {
        cli_dbgmsg("Can't read DOS signature\n");
        return -1;
    }

    if(EC16(e_magic) != PE_IMAGE_DOS_SIGNATURE && EC16(e_magic) != PE_IMAGE_DOS_SIGNATURE_OLD) {
        cli_dbgmsg("Invalid DOS signature\n");
        return -1;
    }

    if(fmap_readn(map, &e_lfanew, peinfo->offset + 58 + sizeof(e_magic), sizeof(e_lfanew)) != sizeof(e_lfanew)) {
        /* truncated header? */
        return -1;
    }

    e_lfanew = EC32(e_lfanew);
    if(!e_lfanew) {
        cli_dbgmsg("Not a PE file\n");
        return -1;
    }

    if(fmap_readn(map, &file_hdr, peinfo->offset + e_lfanew, sizeof(struct pe_image_file_hdr)) != sizeof(struct pe_image_file_hdr)) {
        /* bad information in e_lfanew - probably not a PE file */
        cli_dbgmsg("cli_peheader: Can't read file header\n");
        return -1;
    }

    if(EC32(file_hdr.Magic) != PE_IMAGE_NT_SIGNATURE) {
        cli_dbgmsg("Invalid PE signature (probably NE file)\n");
        return -1;
    }

    if ( (peinfo->nsections = EC16(file_hdr.NumberOfSections)) < 1 || peinfo->nsections > PE_MAXSECTIONS ) return -1;

    if (EC16(file_hdr.SizeOfOptionalHeader) < sizeof(struct pe_image_optional_hdr32)) {
        cli_dbgmsg("SizeOfOptionalHeader too small\n");
        return -1;
    }

    at = peinfo->offset + e_lfanew + sizeof(struct pe_image_file_hdr);
    if(fmap_readn(map, &optional_hdr32, at, sizeof(struct pe_image_optional_hdr32)) != sizeof(struct pe_image_optional_hdr32)) {
        cli_dbgmsg("Can't read optional file header\n");
        return -1;
    }
    at += sizeof(struct pe_image_optional_hdr32);

    if(EC16(optional_hdr64.Magic)==PE32P_SIGNATURE) { /* PE+ */
        if(EC16(file_hdr.SizeOfOptionalHeader)!=sizeof(struct pe_image_optional_hdr64)) {
            cli_dbgmsg("Incorrect SizeOfOptionalHeader for PE32+\n");
            return -1;
        }

        if(fmap_readn(map, &optional_hdr32 + 1, at, sizeof(struct pe_image_optional_hdr64) - sizeof(struct pe_image_optional_hdr32)) != sizeof(struct pe_image_optional_hdr64) - sizeof(struct pe_image_optional_hdr32)) {
            cli_dbgmsg("Can't read optional file header\n");
            return -1;
        }

        at += sizeof(struct pe_image_optional_hdr64) - sizeof(struct pe_image_optional_hdr32);
        hdr_size = EC32(optional_hdr64.SizeOfHeaders);
        pe_plus=1;
    } else { /* PE */
        if (EC16(file_hdr.SizeOfOptionalHeader)!=sizeof(struct pe_image_optional_hdr32)) {
            /* Seek to the end of the long header */
            at += EC16(file_hdr.SizeOfOptionalHeader)-sizeof(struct pe_image_optional_hdr32);
        }

        hdr_size = EC32(optional_hdr32.SizeOfHeaders);
    }

    valign = (pe_plus)?EC32(optional_hdr64.SectionAlignment):EC32(optional_hdr32.SectionAlignment);
    falign = (pe_plus)?EC32(optional_hdr64.FileAlignment):EC32(optional_hdr32.FileAlignment);

    peinfo->hdr_size = hdr_size = PESALIGN(hdr_size, valign);

    peinfo->section = (struct cli_exe_section *) cli_calloc(peinfo->nsections, sizeof(struct cli_exe_section));

    if(!peinfo->section) {
        cli_dbgmsg("Can't allocate memory for section headers\n");
        return -1;
    }

    section_hdr = (struct pe_image_section_hdr *) cli_calloc(peinfo->nsections, sizeof(struct pe_image_section_hdr));

    if(!section_hdr) {
        cli_dbgmsg("Can't allocate memory for section headers\n");
        free(peinfo->section);
        peinfo->section = NULL;
        return -1;
    }

    if(fmap_readn(map, section_hdr, at, peinfo->nsections * sizeof(struct pe_image_section_hdr)) != peinfo->nsections * sizeof(struct pe_image_section_hdr)) {
        cli_dbgmsg("Can't read section header\n");
        cli_dbgmsg("Possibly broken PE file\n");
        free(section_hdr);
        free(peinfo->section);
        peinfo->section = NULL;
        return -1;
    }
    at += sizeof(struct pe_image_section_hdr)*peinfo->nsections;

    for(i = 0; falign!=0x200 && i<peinfo->nsections; i++) {
        /* file alignment fallback mode - blah */
        if (falign && section_hdr[i].SizeOfRawData && EC32(section_hdr[i].PointerToRawData)%falign && !(EC32(section_hdr[i].PointerToRawData)%0x200)) {
            falign = 0x200;
        }
    }

    for(i = 0; i < peinfo->nsections; i++) {
        peinfo->section[i].rva = PEALIGN(EC32(section_hdr[i].VirtualAddress), valign);
        peinfo->section[i].vsz = PESALIGN(EC32(section_hdr[i].VirtualSize), valign);
        peinfo->section[i].raw = PEALIGN(EC32(section_hdr[i].PointerToRawData), falign);
        peinfo->section[i].rsz = PESALIGN(EC32(section_hdr[i].SizeOfRawData), falign);

        if (!peinfo->section[i].vsz && peinfo->section[i].rsz)
            peinfo->section[i].vsz=PESALIGN(EC32(section_hdr[i].SizeOfRawData), valign);

        if (peinfo->section[i].rsz && !CLI_ISCONTAINED(0, (uint32_t) fsize, peinfo->section[i].raw, peinfo->section[i].rsz))
            peinfo->section[i].rsz = (fsize - peinfo->section[i].raw)*(fsize>peinfo->section[i].raw);
    }

    if(pe_plus) {
        peinfo->ep = EC32(optional_hdr64.AddressOfEntryPoint);
        dirs = optional_hdr64.DataDirectory;
    } else {
        peinfo->ep = EC32(optional_hdr32.AddressOfEntryPoint);
        dirs = optional_hdr32.DataDirectory;
    }

    if(!(peinfo->ep = cli_rawaddr(peinfo->ep, peinfo->section, peinfo->nsections, &err, fsize, hdr_size)) && err) {
        cli_dbgmsg("Broken PE file\n");
        free(section_hdr);
        free(peinfo->section);
        peinfo->section = NULL;
        return -1;
    }

    if(EC16(file_hdr.Characteristics) & 0x2000 || !dirs[2].Size)
        peinfo->res_addr = 0;
    else
        peinfo->res_addr = EC32(dirs[2].VirtualAddress);

    while(dirs[2].Size) {
        struct vinfo_list vlist;
        const uint8_t *vptr, *baseptr;
        uint32_t rva, res_sz;

        memset(&vlist, 0, sizeof(vlist));
        findres(0x10, 0xffffffff, EC32(dirs[2].VirtualAddress), map, peinfo->section, peinfo->nsections, hdr_size, versioninfo_cb, &vlist);
        if(!vlist.count)
            break; /* No version_information */

        if(cli_hashset_init(&peinfo->vinfo, 32, 80)) {
            cli_errmsg("cli_peheader: Unable to init vinfo hashset\n");
            free(section_hdr);
            free(peinfo->section);
            peinfo->section = NULL;
            return -1;
        }

        err = 0;
        for(i=0; i<vlist.count; i++) { /* enum all version_information res - RESUMABLE */
            cli_dbgmsg("cli_peheader: parsing version info @ rva %x (%u/%u)\n", vlist.rvas[i], i+1, vlist.count);
            rva = cli_rawaddr(vlist.rvas[i], peinfo->section, peinfo->nsections, &err, fsize, hdr_size);
            if(err)
                continue;

            if(!(vptr = fmap_need_off_once(map, rva, 16)))
                continue;

            baseptr = vptr - rva;
            /* parse resource */
            rva = cli_readint32(vptr); /* ptr to version_info */
            res_sz = cli_readint32(vptr+4); /* sizeof(resource) */
            rva = cli_rawaddr(rva, peinfo->section, peinfo->nsections, &err, fsize, hdr_size);
            if(err)
                continue;
            if(!(vptr = fmap_need_off_once(map, rva, res_sz)))
                continue;
            
            while(res_sz>4) { /* look for version_info - NOT RESUMABLE (expecting exactly one versioninfo) */
                uint32_t vinfo_sz, vinfo_val_sz, got_varfileinfo = 0;

                vinfo_sz = vinfo_val_sz = cli_readint32(vptr);
                vinfo_sz &= 0xffff;
                if(vinfo_sz > res_sz)
                    break; /* the content is larger than the container */

                vinfo_val_sz >>= 16;
                if(vinfo_sz <= 6 + 0x20 + 2 + 0x34 ||
                   vinfo_val_sz != 0x34 || 
                   memcmp(vptr+6, "V\0S\0_\0V\0E\0R\0S\0I\0O\0N\0_\0I\0N\0F\0O\0\0\0", 0x20) ||
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

                while(vinfo_sz > 6) { /* look for stringfileinfo - NOT RESUMABLE (expecting at most one stringfileinfo) */
                    uint32_t sfi_sz = cli_readint32(vptr) & 0xffff;

                    if(sfi_sz > vinfo_sz)
                        break; /* the content is larger than the container */

                    if(!got_varfileinfo && sfi_sz > 6 + 0x18 && !memcmp(vptr+6, "V\0a\0r\0F\0i\0l\0e\0I\0n\0f\0o\0\0\0", 0x18)) {
                        /* skip varfileinfo as it sometimes appear before stringtableinfo */
                        vptr += sfi_sz;
                        vinfo_sz -= sfi_sz;
                        got_varfileinfo = 1;
                        continue;
                    }

                    if(sfi_sz <= 6 + 0x1e || memcmp(vptr+6, "S\0t\0r\0i\0n\0g\0F\0i\0l\0e\0I\0n\0f\0o\0\0\0", 0x1e)) {
                        /* - there should be enough room for the header(6) and the key "StringFileInfo"(1e)
                         * - the key should match */
                        break; /* this is an implicit hard fail: parent is not resumable */
                    }

                    /* move to the end of stringfileinfo where the child elements are located */
                    vptr += 6 + 0x1e;
                    sfi_sz -= 6 + 0x1e;

                    while(sfi_sz > 6) { /* enum all stringtables - RESUMABLE */
                        uint32_t st_sz = cli_readint32(vptr) & 0xffff;
                        const uint8_t *next_vptr = vptr + st_sz;
                        uint32_t next_sfi_sz = sfi_sz - st_sz;

                        if(st_sz > sfi_sz || st_sz <= 24) {
                            /* - the content is larger than the container
                               - there's no room for a stringtables (headers(6) + key(16) + padding(2)) */
                            break; /* this is an implicit hard fail: parent is not resumable */
                        }

                        /* move to the end of stringtable where the child elements are located */
                        vptr += 24;
                        st_sz -= 24;

                        while(st_sz > 6) {  /* enum all strings - RESUMABLE */
                            uint32_t s_sz, s_key_sz, s_val_sz;

                            s_sz = (cli_readint32(vptr) & 0xffff) + 3;
                            s_sz &= ~3;
                            if(s_sz > st_sz || s_sz <= 6 + 2 + 8) {
                                /* - the content is larger than the container
                                 * - there's no room for a minimal string
                                 * - there's no room for the value */
                                st_sz = 0;
                                sfi_sz = 0;
                                break; /* force a hard fail */
                            }

                            /* ~wcstrlen(key) */
                            for(s_key_sz = 6; s_key_sz+1 < s_sz; s_key_sz += 2) {
                                if(vptr[s_key_sz] || vptr[s_key_sz+1])
                                    continue;

                                s_key_sz += 2;
                                break;
                            }

                            s_key_sz += 3;
                            s_key_sz &= ~3;

                            if(s_key_sz >= s_sz) {
                                /* key overflow */
                                vptr += s_sz;
                                st_sz -= s_sz;
                                continue;
                            }

                            s_val_sz = s_sz - s_key_sz;
                            s_key_sz -= 6;

                            if(s_val_sz <= 2) {
                                /* skip unset value */
                                vptr += s_sz;
                                st_sz -= s_sz;
                                continue;
                            }

                            if(cli_hashset_addkey(&peinfo->vinfo, (uint32_t)(vptr - baseptr + 6))) {
                                cli_errmsg("cli_peheader: Unable to add rva to vinfo hashset\n");
                                cli_hashset_destroy(&peinfo->vinfo);
                                free(section_hdr);
                                free(peinfo->section);
                                peinfo->section = NULL;
                                return -1;
                            }

                            if(cli_debug_flag) {
                                char *k, *v, *s;

                                /* FIXME: skip too long strings */
                                k = cli_utf16toascii((const char*)vptr + 6, s_key_sz);
                                if(k) {
                                    v = cli_utf16toascii((const char*)vptr + s_key_sz + 6, s_val_sz);
                                    if(v) {
                                        s = cli_str2hex((const char*)vptr + 6, s_key_sz + s_val_sz);
                                        if(s) {
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
                        vptr = next_vptr;
                        sfi_sz = next_sfi_sz * (sfi_sz != 0);
                    } /* enum all stringtables - RESUMABLE */
                    break;
                } /* look for stringfileinfo - NOT RESUMABLE */
                break;
            } /* look for version_info - NOT RESUMABLE */
        } /* enum all version_information res - RESUMABLE */
        break;
    } /* while(dirs[2].Size) */

    free(section_hdr);
    return 0;
}


static int sort_sects(const void *first, const void *second) {
    const struct cli_exe_section *a = first, *b = second;
    return (a->raw - b->raw);
}

/* Check the given PE file for an authenticode signature and return CL_CLEAN if
 * the signature is valid.  There are two cases that this function should
 * handle:
 * - A PE file has an embedded Authenticode section
 * - The PE file has no embedded Authenticode section but is covered by a
 *   catalog file that was loaded in via a -d 
 * CL_CLEAN will be returned if the file was whitelisted based on its
 * signature.  CL_VIRUS will be returned if the file was blacklisted based on
 * its signature.  Otherwise, an cl_error_t error value will be returned.
 * 
 * Also, this function computes the hashes of each section (sorted based on the
 * RVAs of the sections) if the CL_CHECKFP_PE_FLAG_STATS flag exists in flags
 *
 * TODO The code to compute the section hashes is copied from
 * cli_genhash_pe - we should use that function instead where this
 * functionality is needed, since we no longer need to compute the section
 * hashes as part of the authenticode hash calculation.
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
 *  - TODO Instead of not providing back any hashes when an invalid section is
 *    encountered, would it be better to still compute hashes for the valid
 *    sections? */
cl_error_t cli_checkfp_pe(cli_ctx *ctx, stats_section_t *hashes, uint32_t flags) {
    uint16_t e_magic; /* DOS signature ("MZ") */
    uint16_t nsections;
    uint32_t e_lfanew; /* address of new exe header */
    struct pe_image_file_hdr file_hdr;
    union {
        struct pe_image_optional_hdr64 opt64;
        struct pe_image_optional_hdr32 opt32;
    } pe_opt;
    const struct pe_image_section_hdr *section_hdr;
    ssize_t at;
    unsigned int i, pe_plus = 0, hlen;
    size_t fsize;
    uint32_t valign, falign, hdr_size;
    struct cli_exe_section *exe_sections;
    struct pe_image_data_dir *dirs;
    fmap_t *map = *ctx->fmap;
    void *hashctx=NULL;
    struct pe_certificate_hdr cert_hdr;
    struct cli_mapped_region *regions = NULL;
    unsigned int nregions;
    cl_error_t ret = CL_EVERIFY;
    uint8_t authsha1[SHA1_HASH_SIZE];
    uint32_t sec_dir_offset;
    uint32_t sec_dir_size;

    if (flags == CL_CHECKFP_PE_FLAG_NONE)
        return CL_BREAK;

    if (flags & CL_CHECKFP_PE_FLAG_STATS) {
        if (!(hashes))
            return CL_ENULLARG;
        hashes->sections = NULL;
    }

    // TODO What does this do?
    if(!(DCONF & PE_CONF_CATALOG))
        return CL_EFORMAT;

    if(fmap_readn(map, &e_magic, 0, sizeof(e_magic)) != sizeof(e_magic))
        return CL_EFORMAT;

    if(EC16(e_magic) != PE_IMAGE_DOS_SIGNATURE && EC16(e_magic) != PE_IMAGE_DOS_SIGNATURE_OLD)
        return CL_EFORMAT;

    if(fmap_readn(map, &e_lfanew, 58 + sizeof(e_magic), sizeof(e_lfanew)) != sizeof(e_lfanew))
        return CL_EFORMAT;

    e_lfanew = EC32(e_lfanew);
    if(!e_lfanew)
        return CL_EFORMAT;

    if(fmap_readn(map, &file_hdr, e_lfanew, sizeof(struct pe_image_file_hdr)) != sizeof(struct pe_image_file_hdr))
        return CL_EFORMAT;

    if(EC32(file_hdr.Magic) != PE_IMAGE_NT_SIGNATURE)
        return CL_EFORMAT;

    nsections = EC16(file_hdr.NumberOfSections);
    if(nsections < 1 || nsections > PE_MAXSECTIONS)
        return CL_EFORMAT;

    // TODO the pe_image_optional_hdr32 structure includes space for all 16
    // data directories, but these might not all exist in a given binary.
    // We need to check NumberOfRvaAndSizes instead, and allow through any
    // with at least 5 (the security DataDirectory)
    if(EC16(file_hdr.SizeOfOptionalHeader) < sizeof(struct pe_image_optional_hdr32)) {
        cli_dbgmsg("cli_checkfp_pe: SizeOfOptionalHeader < less than the size expected (%lu)\n", sizeof(struct pe_image_optional_hdr32));
        return CL_EFORMAT;
    }

    at = e_lfanew + sizeof(struct pe_image_file_hdr);
    if(fmap_readn(map, &optional_hdr32, at, sizeof(struct pe_image_optional_hdr32)) != sizeof(struct pe_image_optional_hdr32))
        return CL_EFORMAT;

    at += sizeof(struct pe_image_optional_hdr32);

    /* This will be a chicken and egg problem until we drop 9x */
    if(EC16(optional_hdr64.Magic)==PE32P_SIGNATURE) {
        if(EC16(file_hdr.SizeOfOptionalHeader)!=sizeof(struct pe_image_optional_hdr64))
            return CL_EFORMAT;

        pe_plus = 1;
    }

    if(!pe_plus) { /* PE */
        if (EC16(file_hdr.SizeOfOptionalHeader)!=sizeof(struct pe_image_optional_hdr32)) {
            /* Seek to the end of the long header */
            at += EC16(file_hdr.SizeOfOptionalHeader)-sizeof(struct pe_image_optional_hdr32);
        }

        hdr_size = EC32(optional_hdr32.SizeOfHeaders);
        dirs = optional_hdr32.DataDirectory;
    } else { /* PE+ */
        size_t readlen = sizeof(struct pe_image_optional_hdr64) - sizeof(struct pe_image_optional_hdr32);
        /* read the remaining part of the header */
        if((size_t)fmap_readn(map, &optional_hdr32 + 1, at, readlen) != readlen)
            return CL_EFORMAT;

        at += sizeof(struct pe_image_optional_hdr64) - sizeof(struct pe_image_optional_hdr32);
        hdr_size = EC32(optional_hdr64.SizeOfHeaders);
        dirs = optional_hdr64.DataDirectory;
    }

    sec_dir_offset = EC32(dirs[4].VirtualAddress);
    sec_dir_size = EC32(dirs[4].Size);

    // As an optimization, check the security DataDirectory here and if
    // it's less than 8-bytes (and we aren't relying on this code to compute
    // the section hashes), bail out if we don't have any Authenticode hashes
    // loaded from .cat files
    if (sec_dir_size < 8 && !cli_hm_have_size(ctx->engine->hm_fp, CLI_HASH_SHA1, 2)) {
        if (flags & CL_CHECKFP_PE_FLAG_STATS) {
            /* If stats is enabled, continue parsing the sample */
            flags ^= CL_CHECKFP_PE_FLAG_AUTHENTICODE;
        } else {
            return CL_BREAK;
        }
    }
    fsize = map->len;

    valign = (pe_plus)?EC32(optional_hdr64.SectionAlignment):EC32(optional_hdr32.SectionAlignment);
    falign = (pe_plus)?EC32(optional_hdr64.FileAlignment):EC32(optional_hdr32.FileAlignment);

    section_hdr = fmap_need_off_once(map, at, sizeof(*section_hdr) * nsections);
    if(!section_hdr)
        return CL_EFORMAT;

    at += sizeof(*section_hdr) * nsections;

    exe_sections = (struct cli_exe_section *) cli_calloc(nsections, sizeof(struct cli_exe_section));
    if(!exe_sections)
        return CL_EMEM;

    // TODO I'm not sure why this is necessary since the specification says
    // that PointerToRawData is expected to be a multiple of the file
    // alignment.  Should we report this is as a PE with an error?
    for(i = 0; falign!=0x200 && i<nsections; i++) {
        /* file alignment fallback mode - blah */
        if (falign && section_hdr[i].SizeOfRawData && EC32(section_hdr[i].PointerToRawData)%falign && !(EC32(section_hdr[i].PointerToRawData)%0x200))
            falign = 0x200;
    }

    // TODO Why is this needed?  hdr_size should already be rounded up
    // to a multiple of the file alignment.
    hdr_size = PESALIGN(hdr_size, falign); /* Aligned headers virtual size */

    if (flags & CL_CHECKFP_PE_FLAG_STATS) {
        hashes->nsections = nsections;
        hashes->sections = cli_calloc(nsections, sizeof(struct cli_section_hash));
        if (!(hashes->sections)) {
            free(exe_sections);
            return CL_EMEM;
        }
    }

#define free_section_hashes() \
    do { \
        if (flags & CL_CHECKFP_PE_FLAG_STATS) { \
            free(hashes->sections); \
            hashes->sections = NULL; \
        } \
    } while(0)


    // TODO Why do we fix up these alignments?  This shouldn't be needed?
    for(i = 0; i < nsections; i++) {
        exe_sections[i].rva = PEALIGN(EC32(section_hdr[i].VirtualAddress), valign);
        exe_sections[i].vsz = PESALIGN(EC32(section_hdr[i].VirtualSize), valign);
        exe_sections[i].raw = PEALIGN(EC32(section_hdr[i].PointerToRawData), falign);
        exe_sections[i].rsz = PESALIGN(EC32(section_hdr[i].SizeOfRawData), falign);

        // TODO exe_sections[i].ursz is not assigned to (will always be 0)
        // Figure out what this is meant to do and ensure that happens
        if (!exe_sections[i].vsz && exe_sections[i].rsz)
            exe_sections[i].vsz=PESALIGN(exe_sections[i].ursz, valign);

        if (exe_sections[i].rsz && fsize>exe_sections[i].raw && !CLI_ISCONTAINED(0, (uint32_t) fsize, exe_sections[i].raw, exe_sections[i].rsz)) {
            cli_dbgmsg("cli_checkfp_pe: encountered section not fully contained within the file\n");
            free(exe_sections);
            free_section_hashes();
            return CL_EFORMAT;
        }

        if (exe_sections[i].rsz && exe_sections[i].raw >= fsize) {
            cli_dbgmsg("cli_checkfp_pe: encountered section that doesn't exist within the file\n");
            free(exe_sections);
            free_section_hashes();
            return CL_EFORMAT;
        }

        // TODO These checks aren't needed because the u vars are never assigned (always 0)
        // Figure out what this is meant to do and ensure that happens
        if (exe_sections[i].urva>>31 || exe_sections[i].uvsz>>31 || (exe_sections[i].rsz && exe_sections[i].uraw>>31) || exe_sections[i].ursz>>31) {
            free(exe_sections);
            free_section_hashes();
            return CL_EFORMAT;
        }
    }

    // TODO This likely isn't needed anymore, since we no longer compute
    // the authenticode hash like the 2008 spec doc says (sort sections
    // and use the section info to compute the hash)
    cli_qsort(exe_sections, nsections, sizeof(*exe_sections), sort_sects);

    /* Hash the sections */
    if (flags & CL_CHECKFP_PE_FLAG_STATS) {

        for(i = 0; i < nsections; i++) {
            const uint8_t *hptr;
            void *md5ctx;

            if(!exe_sections[i].rsz)
                continue;

            if(!(hptr = fmap_need_off_once(map, exe_sections[i].raw, exe_sections[i].rsz))){
                free(exe_sections);
                free_section_hashes();
                return CL_EFORMAT;
            }
            md5ctx = cl_hash_init("md5");
            if (md5ctx) {
                cl_update_hash(md5ctx, (void *)hptr, exe_sections[i].rsz);
                cl_finish_hash(md5ctx, hashes->sections[i].md5);
            }
        }
    }

    /* After this point it's the caller's responsibility to free
     * hashes->sections. Also, in the case where we are just computing the
     * stats, we are finished */
    free(exe_sections);

    while (flags & CL_CHECKFP_PE_FLAG_AUTHENTICODE) {

        // We'll build a list of the regions that need to be hashed and pass it to
        // asn1_check_mscat to do hash verification there (the hash algorithm is
        // specified in the PKCS7 structure).  We need to hash up to 4 regions
        regions = (struct cli_mapped_region *) cli_calloc(4, sizeof(struct cli_mapped_region));
        if(!regions) {
            return CL_EMEM;
        }
        nregions = 0;

#define add_chunk_to_hash_list(_offset, _size) \
    do { \
        if (flags & CL_CHECKFP_PE_FLAG_AUTHENTICODE) { \
            regions[nregions].offset = (_offset); \
            regions[nregions].size = (_size); \
            nregions++; \
        } \
    } while(0)

        // Pretty much every case below should return CL_EFORMAT
        ret = CL_EFORMAT;

        /* MZ to checksum */
        at = 0;
        hlen = e_lfanew + sizeof(struct pe_image_file_hdr) + (pe_plus ? offsetof(struct pe_image_optional_hdr64, CheckSum) : offsetof(struct pe_image_optional_hdr32, CheckSum));
        add_chunk_to_hash_list(0, hlen);
        at = hlen + 4;

        /* Checksum to security */
        if(pe_plus)
            hlen = offsetof(struct pe_image_optional_hdr64, DataDirectory[4]) - offsetof(struct pe_image_optional_hdr64, CheckSum) - 4;
        else
            hlen = offsetof(struct pe_image_optional_hdr32, DataDirectory[4]) - offsetof(struct pe_image_optional_hdr32, CheckSum) - 4;
        add_chunk_to_hash_list(at, hlen);
        at += hlen + 8;

        if(at > hdr_size) {
            break;
        }

        /* Security to End of header */
        hlen = hdr_size - at;
        add_chunk_to_hash_list(at, hlen);
        at += hlen;

        if (sec_dir_offset) {

            // Verify that we have all the bytes we expect in the authenticode sig
            // and that the certificate table is the last thing in the file
            // (according to the MS13-098 bulletin, this is a requirement)
            if (fsize != sec_dir_size + sec_dir_offset) {
                cli_dbgmsg("cli_checkfp_pe: expected authenticode data at the end of the file\n");
                break;
            }

            // Hash everything from the end of the header to the start of the
            // security section
            if (at < sec_dir_offset) {
                hlen = sec_dir_offset - at;
                add_chunk_to_hash_list(at, hlen);
            } else {
                cli_dbgmsg("cli_checkfp_pe: security directory offset appears to overlap with the PE header\n");
                break;
            }

            // Parse the security directory header

            if(fmap_readn(map, &cert_hdr, sec_dir_offset, sizeof(cert_hdr)) != sizeof(cert_hdr)) {
                break;
            }

            if (EC16(cert_hdr.revision) != WIN_CERT_REV_2) {
                cli_dbgmsg("cli_checkfp_pe: unsupported authenticode data revision\n");
                break;
            }

            if (EC16(cert_hdr.type) != WIN_CERT_TYPE_PKCS7) {
                cli_dbgmsg("cli_checkfp_pe: unsupported authenticode data type\n");
                break;
            }

            hlen = sec_dir_size;

            if (EC32(cert_hdr.length) != hlen) {
                /* This is the case that MS13-098 aimed to address, but it got
                 * pushback to where the fix (not allowing additional, non-zero
                 * bytes in the security directory) is now opt-in via a registry
                 * key.  Given that most machines will treat these binaries as
                 * valid, we'll still parse the signature and just trust that
                 * our whitelist signatures are tailored enough to where any
                 * instances of this are reasonable (for instance, I saw one
                 * binary that appeared to use this to embed a license key.) */
                cli_dbgmsg("cli_checkfp_pe: MS13-098 violation detected, but continuing on to verify certificate\n");
            }

            at = sec_dir_offset + sizeof(cert_hdr);
            hlen -= sizeof(cert_hdr);

            ret = asn1_check_mscat((struct cl_engine *)(ctx->engine), map, at, hlen, regions, nregions);

            if (CL_CLEAN == ret) {
                // We validated the embedded signature.  Hooray!
                break;
            } else if(CL_VIRUS == ret) {
                // A blacklist rule hit - don't continue on to check hm_fp for a match
                break;
            }

            // Otherwise, we still need to check to see whether this file is
            // covered by a .cat file (it's common these days for driver files
            // to have .cat files covering PEs with embedded signatures)

        } else {

            // Hash everything from the end of the header to the end of the
            // file
            if (at < fsize) {
                hlen = fsize - at;
                add_chunk_to_hash_list(at, hlen);
            }
        }

        // At this point we should compute the SHA1 authenticode hash to see
        // whether we've had any hashes added from external catalog files
        // TODO Is it gauranteed that the hashing algorithm will be SHA1?  If
        // not, figure out how to handle that case
        hashctx = cl_hash_init("sha1");
        if (NULL == hashctx) {
            ret = CL_EMEM;
            break;
        }

        for(i = 0; i < nregions; i++) {
            const uint8_t *hptr;
            if (0 == regions[i].size) {
                continue;
            }
            if(!(hptr = fmap_need_off_once(map, regions[i].offset, regions[i].size))){
                break;
            }

            cl_update_hash(hashctx, hptr, regions[i].size);
        }

        if (i != nregions) {
            break;
        }

        cl_finish_hash(hashctx, authsha1);
        hashctx = NULL;

        if(cli_hm_scan(authsha1, 2, NULL, ctx->engine->hm_fp, CLI_HASH_SHA1) == CL_VIRUS) {
            cli_dbgmsg("cli_checkfp_pe: PE file whitelisted by catalog file\n");
            ret = CL_CLEAN;
            break;
        }

        ret = CL_EVERIFY;
        break;
    } /* while(flags & CL_CHECKFP_PE_FLAG_AUTHENTICODE) */

    if (NULL != hashctx) {
        cl_hash_destroy(hashctx);
    }

    if (NULL != regions) {
        free(regions);
    }
    return ret;
}

int cli_genhash_pe(cli_ctx *ctx, unsigned int class, int type)
{
    uint16_t e_magic; /* DOS signature ("MZ") */
    uint16_t nsections;
    uint32_t e_lfanew; /* address of new exe header */
    union {
        struct pe_image_optional_hdr64 opt64;
        struct pe_image_optional_hdr32 opt32;
    } pe_opt;
    const struct pe_image_section_hdr *section_hdr;
    ssize_t at;
    unsigned int i, pe_plus = 0;
    size_t fsize;
    uint32_t valign, falign, hdr_size;
    struct pe_image_file_hdr file_hdr;
    struct cli_exe_section *exe_sections;
    struct pe_image_data_dir *dirs;
    fmap_t *map = *ctx->fmap;

    unsigned char *hash, *hashset[CLI_HASH_AVAIL_TYPES];
    int genhash[CLI_HASH_AVAIL_TYPES];
    int hlen = 0;

    if (class >= CL_GENHASH_PE_CLASS_LAST)
        return CL_EARG;

    if(fmap_readn(map, &e_magic, 0, sizeof(e_magic)) != sizeof(e_magic))
        return CL_EFORMAT;

    if(EC16(e_magic) != PE_IMAGE_DOS_SIGNATURE && EC16(e_magic) != PE_IMAGE_DOS_SIGNATURE_OLD)
        return CL_EFORMAT;

    if(fmap_readn(map, &e_lfanew, 58 + sizeof(e_magic), sizeof(e_lfanew)) != sizeof(e_lfanew))
        return CL_EFORMAT;

    e_lfanew = EC32(e_lfanew);
    if(!e_lfanew)
        return CL_EFORMAT;

    if(fmap_readn(map, &file_hdr, e_lfanew, sizeof(struct pe_image_file_hdr)) != sizeof(struct pe_image_file_hdr))
        return CL_EFORMAT;

    if(EC32(file_hdr.Magic) != PE_IMAGE_NT_SIGNATURE)
        return CL_EFORMAT;

    nsections = EC16(file_hdr.NumberOfSections);
    if(nsections < 1 || nsections > PE_MAXSECTIONS)
        return CL_EFORMAT;

    if(EC16(file_hdr.SizeOfOptionalHeader) < sizeof(struct pe_image_optional_hdr32))
        return CL_EFORMAT;

    at = e_lfanew + sizeof(struct pe_image_file_hdr);
    if(fmap_readn(map, &optional_hdr32, at, sizeof(struct pe_image_optional_hdr32)) != sizeof(struct pe_image_optional_hdr32))
        return CL_EFORMAT;

    at += sizeof(struct pe_image_optional_hdr32);

    /* This will be a chicken and egg problem until we drop 9x */
    if(EC16(optional_hdr64.Magic)==PE32P_SIGNATURE) {
        if(EC16(file_hdr.SizeOfOptionalHeader)!=sizeof(struct pe_image_optional_hdr64))
            return CL_EFORMAT;

        pe_plus = 1;
    }

    if(!pe_plus) { /* PE */
        if (EC16(file_hdr.SizeOfOptionalHeader)!=sizeof(struct pe_image_optional_hdr32)) {
            /* Seek to the end of the long header */
            at += EC16(file_hdr.SizeOfOptionalHeader)-sizeof(struct pe_image_optional_hdr32);
        }

        hdr_size = EC32(optional_hdr32.SizeOfHeaders);
        dirs = optional_hdr32.DataDirectory;
    } else { /* PE+ */
        size_t readlen = sizeof(struct pe_image_optional_hdr64) - sizeof(struct pe_image_optional_hdr32);
        /* read the remaining part of the header */
        if((size_t)fmap_readn(map, &optional_hdr32 + 1, at, readlen) != readlen)
            return CL_EFORMAT;

        at += sizeof(struct pe_image_optional_hdr64) - sizeof(struct pe_image_optional_hdr32);
        hdr_size = EC32(optional_hdr64.SizeOfHeaders);
        dirs = optional_hdr64.DataDirectory;
    }

    fsize = map->len;

    valign = (pe_plus)?EC32(optional_hdr64.SectionAlignment):EC32(optional_hdr32.SectionAlignment);
    falign = (pe_plus)?EC32(optional_hdr64.FileAlignment):EC32(optional_hdr32.FileAlignment);

    section_hdr = fmap_need_off_once(map, at, sizeof(*section_hdr) * nsections);
    if(!section_hdr)
        return CL_EFORMAT;

    at += sizeof(*section_hdr) * nsections;

    exe_sections = (struct cli_exe_section *) cli_calloc(nsections, sizeof(struct cli_exe_section));
    if(!exe_sections)
        return CL_EMEM;

    for(i = 0; falign!=0x200 && i<nsections; i++) {
        /* file alignment fallback mode - blah */
        if (falign && section_hdr[i].SizeOfRawData && EC32(section_hdr[i].PointerToRawData)%falign && !(EC32(section_hdr[i].PointerToRawData)%0x200))
            falign = 0x200;
    }

    hdr_size = PESALIGN(hdr_size, falign); /* Aligned headers virtual size */

    for(i = 0; i < nsections; i++) {
        exe_sections[i].rva = PEALIGN(EC32(section_hdr[i].VirtualAddress), valign);
        exe_sections[i].vsz = PESALIGN(EC32(section_hdr[i].VirtualSize), valign);
        exe_sections[i].raw = PEALIGN(EC32(section_hdr[i].PointerToRawData), falign);
        exe_sections[i].rsz = PESALIGN(EC32(section_hdr[i].SizeOfRawData), falign);

        if (!exe_sections[i].vsz && exe_sections[i].rsz)
            exe_sections[i].vsz=PESALIGN(exe_sections[i].ursz, valign);

        if (exe_sections[i].rsz && fsize>exe_sections[i].raw && !CLI_ISCONTAINED(0, (uint32_t) fsize, exe_sections[i].raw, exe_sections[i].rsz))
            exe_sections[i].rsz = fsize - exe_sections[i].raw;

        if (exe_sections[i].rsz && exe_sections[i].raw >= fsize) {
            free(exe_sections);
            return CL_EFORMAT;
        }

        if (exe_sections[i].urva>>31 || exe_sections[i].uvsz>>31 || (exe_sections[i].rsz && exe_sections[i].uraw>>31) || exe_sections[i].ursz>>31) {
            free(exe_sections);
            return CL_EFORMAT;
        }
    }

    cli_qsort(exe_sections, nsections, sizeof(*exe_sections), sort_sects);

    /* pick hashtypes to generate */
    memset(genhash, 0, sizeof(genhash));
    memset(hashset, 0, sizeof(hashset));
    switch(type) {
    case 1:
        genhash[CLI_HASH_MD5] = 1;
        hlen = hashlen[CLI_HASH_MD5];
        hash = hashset[CLI_HASH_MD5] = cli_calloc(hlen, sizeof(char));
        break;
    case 2:
        genhash[CLI_HASH_SHA1] = 1;
        hlen = hashlen[CLI_HASH_SHA1];
        hash = hashset[CLI_HASH_SHA1] = cli_calloc(hlen, sizeof(char));
        break;
    default:
        genhash[CLI_HASH_SHA256] = 1;
        hlen = hashlen[CLI_HASH_SHA256];
        hash = hashset[CLI_HASH_SHA256] = cli_calloc(hlen, sizeof(char));
        break;
    }

    if(!hash) {
        cli_errmsg("cli_genhash_pe: cli_malloc failed!\n");
        free(exe_sections);
        return CL_EMEM;
    }

    if (class == CL_GENHASH_PE_CLASS_SECTION) {
        char *dstr = NULL;

        for (i = 0; i < nsections; i++) {
            /* Generate hashes */
            if (cli_hashsect(*ctx->fmap, &exe_sections[i], hashset, genhash, genhash) == 1) {
                dstr = cli_str2hex((char*)hash, hlen);
                cli_dbgmsg("Section{%u}: %u:%s\n", i, exe_sections[i].rsz, dstr ? (char *)dstr : "(NULL)");
                if (dstr != NULL) {
                    free(dstr);
                    dstr = NULL;
                }
            } else {
                cli_dbgmsg("Section{%u}: failed to generate hash for section\n", i);
            }
        }
    } else if (class == CL_GENHASH_PE_CLASS_IMPTBL) {
        char *dstr = NULL;
        uint32_t impsz = 0;
        int ret;

        /* Generate hash */
        ret = hash_imptbl(ctx, hashset, &impsz, genhash, &dirs[1], exe_sections, nsections, hdr_size, pe_plus);
        if (ret == CL_SUCCESS) {
            dstr = cli_str2hex((char*)hash, hlen);
            cli_dbgmsg("Imphash: %s:%u\n", dstr ? (char *)dstr : "(NULL)", impsz);
            if (dstr != NULL) {
                free(dstr);
                dstr = NULL;
            }
        } else {
            cli_dbgmsg("Imphash: failed to generate hash for import table (%d)\n", ret);
        }
    } else {
        cli_dbgmsg("cli_genhash_pe: unknown pe genhash class: %u\n", class);
    }

    if (hash)
        free(hash);
    free(exe_sections);
    return CL_SUCCESS;
}
