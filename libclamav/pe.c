/*
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
 *
 *  Authors: Alberto Wu, Tomasz Kojm
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
#define _XOPEN_SOURCE 500
#include <stdio.h>
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

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libclamav/crypto.h"

#include "cltypes.h"
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

#define DCONF ctx->dconf->pe

#define PE_IMAGE_DOS_SIGNATURE	    0x5a4d	    /* MZ */
#define PE_IMAGE_DOS_SIGNATURE_OLD  0x4d5a          /* ZM */
#define PE_IMAGE_NT_SIGNATURE	    0x00004550
#define PE32_SIGNATURE		    0x010b
#define PE32P_SIGNATURE		    0x020b

#define optional_hdr64 pe_opt.opt64
#define optional_hdr32 pe_opt.opt32

#define UPX_NRV2B "\x11\xdb\x11\xc9\x01\xdb\x75\x07\x8b\x1e\x83\xee\xfc\x11\xdb\x11\xc9\x11\xc9\x75\x20\x41\x01\xdb"
#define UPX_NRV2D "\x83\xf0\xff\x74\x78\xd1\xf8\x89\xc5\xeb\x0b\x01\xdb\x75\x07\x8b\x1e\x83\xee\xfc\x11\xdb\x11\xc9"
#define UPX_NRV2E "\xeb\x52\x31\xc9\x83\xe8\x03\x72\x11\xc1\xe0\x08\x8a\x06\x46\x83\xf0\xff\x74\x75\xd1\xf8\x89\xc5"
#define UPX_LZMA1 "\x56\x83\xc3\x04\x53\x50\xc7\x03\x03\x00\x02\x00\x90\x90\x90\x55\x57\x56\x53\x83"
#define UPX_LZMA2 "\x56\x83\xc3\x04\x53\x50\xc7\x03\x03\x00\x02\x00\x90\x90\x90\x90\x90\x55\x57\x56"

#define EC32(x) ((uint32_t)cli_readint32(&(x))) /* Convert little endian to host */
#define EC16(x) ((uint16_t)cli_readint16(&(x)))
/* lower and upper bondary alignment (size vs offset) */
#define PEALIGN(o,a) (((a))?(((o)/(a))*(a)):(o))
#define PESALIGN(o,a) (((a))?(((o)/(a)+((o)%(a)!=0))*(a)):(o))

#define CLI_UNPSIZELIMITS(NAME,CHK) \
if(cli_checklimits(NAME, ctx, (CHK), 0, 0)!=CL_CLEAN) {	\
    free(exe_sections);					\
    return CL_CLEAN;					\
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
	if(cli_magic_scandesc(ndesc, ctx) == CL_VIRUS) { \
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

#define DETECT_BROKEN_PE (DETECT_BROKEN && !ctx->corrupted_input)

extern const unsigned int hashlen[];

struct offset_list {
    uint32_t offset;
    struct offset_list *next;
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
static int cli_ddump(int desc, int offset, int size, const char *file) {
	int pos, ndesc, bread, sum = 0;
	char buff[FILEBUFF];


    cli_dbgmsg("in ddump()\n");

    if((pos = lseek(desc, 0, SEEK_CUR)) == -1) {
	cli_dbgmsg("Invalid descriptor\n");
	return -1;
    }

    if(lseek(desc, offset, SEEK_SET) == -1) {
	cli_dbgmsg("lseek() failed\n");
	lseek(desc, pos, SEEK_SET);
	return -1;
    }

    if((ndesc = open(file, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
	cli_dbgmsg("Can't create file %s\n", file);
	lseek(desc, pos, SEEK_SET);
	return -1;
    }

    while((bread = cli_readn(desc, buff, FILEBUFF)) > 0) {
	if(sum + bread >= size) {
	    if(write(ndesc, buff, size - sum) == -1) {
		cli_dbgmsg("Can't write to file\n");
		lseek(desc, pos, SEEK_SET);
		close(ndesc);
		cli_unlink(file);
		return -1;
	    }
	    break;
	} else {
	    if(write(ndesc, buff, bread) == -1) {
		cli_dbgmsg("Can't write to file\n");
		lseek(desc, pos, SEEK_SET);
		close(ndesc);
		cli_unlink(file);
		return -1;
	    }
	}
	sum += bread;
    }

    close(ndesc);
    lseek(desc, pos, SEEK_SET);
    return 0;
}
*/


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
            cli_dbgmsg("MDB: %u:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
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
            cli_append_virus(ctx, virname);
            ret = CL_VIRUS;
            if (!SCAN_ALL) {
                break;
            }
       }
       if(foundwild[type] && cli_hm_scan_wild(hashset[type], &virname, mdb_sect, type) == CL_VIRUS) {
            cli_append_virus(ctx, virname);
            ret = CL_VIRUS;
            if (!SCAN_ALL) {
                break;
            }
       }
    }

end:
    for(type = CLI_HASH_AVAIL_TYPES; type > 0;)
        free(hashset[--type]);
    return ret;
}

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
	unsigned int i, found, upx_success = 0, min = 0, max = 0, err, overlays = 0;
	unsigned int ssize = 0, dsize = 0, dll = 0, pe_plus = 0, corrupted_cur;
	int (*upxfn)(const char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t) = NULL;
	const char *src = NULL;
	char *dest = NULL;
	int ndesc, ret = CL_CLEAN, upack = 0, native=0;
	size_t fsize;
	uint32_t valign, falign, hdr_size, j;
	struct cli_exe_section *exe_sections;
	struct cli_matcher *mdb_sect;
	char timestr[32];
	struct pe_image_data_dir *dirs;
	struct cli_bc_ctx *bc_ctx;
	fmap_t *map;
	struct cli_pe_hook_data pedata;
#ifdef HAVE__INTERNAL__SHA_COLLECT
	int sha_collect = ctx->sha_collect;
#endif
	const char * virname = NULL;
	uint32_t viruses_found = 0;

    if(!ctx) {
	cli_errmsg("cli_scanpe: ctx == NULL\n");
	return CL_ENULLARG;
    }
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
	    cli_append_virus(ctx,"Heuristics.Broken.Executable");
	    return CL_VIRUS;
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
	cli_dbgmsg("Can't read file header\n");
	return CL_CLEAN;
    }

    if(EC32(file_hdr.Magic) != PE_IMAGE_NT_SIGNATURE) {
	cli_dbgmsg("Invalid PE signature (probably NE file)\n");
	return CL_CLEAN;
    }

    if(EC16(file_hdr.Characteristics) & 0x2000) {
	cli_dbgmsg("File type: DLL\n");
	dll = 1;
    } else if(EC16(file_hdr.Characteristics) & 0x01) {
	cli_dbgmsg("File type: Executable\n");
    }

    switch(EC16(file_hdr.Machine)) {
	case 0x0:
	    cli_dbgmsg("Machine type: Unknown\n");
	    break;
	case 0x14c:
	    cli_dbgmsg("Machine type: 80386\n");
	    break;
	case 0x14d:
	    cli_dbgmsg("Machine type: 80486\n");
	    break;
	case 0x14e:
	    cli_dbgmsg("Machine type: 80586\n");
	    break;
	case 0x160:
	    cli_dbgmsg("Machine type: R30000 (big-endian)\n");
	    break;
	case 0x162:
	    cli_dbgmsg("Machine type: R3000\n");
	    break;
	case 0x166:
	    cli_dbgmsg("Machine type: R4000\n");
	    break;
	case 0x168:
	    cli_dbgmsg("Machine type: R10000\n");
	    break;
	case 0x184:
	    cli_dbgmsg("Machine type: DEC Alpha AXP\n");
	    break;
	case 0x284:
	    cli_dbgmsg("Machine type: DEC Alpha AXP 64bit\n");
	    break;
	case 0x1f0:
	    cli_dbgmsg("Machine type: PowerPC\n");
	    break;
	case 0x200:
	    cli_dbgmsg("Machine type: IA64\n");
	    break;
	case 0x268:
	    cli_dbgmsg("Machine type: M68k\n");
	    break;
	case 0x266:
	    cli_dbgmsg("Machine type: MIPS16\n");
	    break;
	case 0x366:
	    cli_dbgmsg("Machine type: MIPS+FPU\n");
	    break;
	case 0x466:
	    cli_dbgmsg("Machine type: MIPS16+FPU\n");
	    break;
	case 0x1a2:
	    cli_dbgmsg("Machine type: Hitachi SH3\n");
	    break;
	case 0x1a3:
	    cli_dbgmsg("Machine type: Hitachi SH3-DSP\n");
	    break;
	case 0x1a4:
	    cli_dbgmsg("Machine type: Hitachi SH3-E\n");
	    break;
	case 0x1a6:
	    cli_dbgmsg("Machine type: Hitachi SH4\n");
	    break;
	case 0x1a8:
	    cli_dbgmsg("Machine type: Hitachi SH5\n");
	    break;
	case 0x1c0:
	    cli_dbgmsg("Machine type: ARM\n");
	    break;
	case 0x1c2:
	    cli_dbgmsg("Machine type: THUMB\n");
	    break;
	case 0x1d3:
	    cli_dbgmsg("Machine type: AM33\n");
	    break;
	case 0x520:
	    cli_dbgmsg("Machine type: Infineon TriCore\n");
	    break;
	case 0xcef:
	    cli_dbgmsg("Machine type: CEF\n");
	    break;
	case 0xebc:
	    cli_dbgmsg("Machine type: EFI Byte Code\n");
	    break;
	case 0x9041:
	    cli_dbgmsg("Machine type: M32R\n");
	    break;
	case 0xc0ee:
	    cli_dbgmsg("Machine type: CEE\n");
	    break;
	case 0x8664:
	    cli_dbgmsg("Machine type: AMD64\n");
	    break;
	default:
	    cli_dbgmsg("Machine type: ** UNKNOWN ** (0x%x)\n", EC16(file_hdr.Machine));
    }

    nsections = EC16(file_hdr.NumberOfSections);
    if(nsections < 1 || nsections > 96) {
	if(DETECT_BROKEN_PE) {
	    cli_append_virus(ctx,"Heuristics.Broken.Executable");
	    return CL_VIRUS;
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

    cli_dbgmsg("SizeOfOptionalHeader: %x\n", EC16(file_hdr.SizeOfOptionalHeader));

    if (EC16(file_hdr.SizeOfOptionalHeader) < sizeof(struct pe_image_optional_hdr32)) {
        cli_dbgmsg("SizeOfOptionalHeader too small\n");
	if(DETECT_BROKEN_PE) {
	    cli_append_virus(ctx,"Heuristics.Broken.Executable");
	    return CL_VIRUS;
	}
	return CL_CLEAN;
    }

    at = e_lfanew + sizeof(struct pe_image_file_hdr);
    if(fmap_readn(map, &optional_hdr32, at, sizeof(struct pe_image_optional_hdr32)) != sizeof(struct pe_image_optional_hdr32)) {
        cli_dbgmsg("Can't read optional file header\n");
	if(DETECT_BROKEN_PE) {
	    cli_append_virus(ctx,"Heuristics.Broken.Executable");
	    return CL_VIRUS;
	}
	return CL_CLEAN;
    }
    at += sizeof(struct pe_image_optional_hdr32);

    /* This will be a chicken and egg problem until we drop 9x */
    if(EC16(optional_hdr64.Magic)==PE32P_SIGNATURE) {
        if(EC16(file_hdr.SizeOfOptionalHeader)!=sizeof(struct pe_image_optional_hdr64)) {
	    /* FIXME: need to play around a bit more with xp64 */
	    cli_dbgmsg("Incorrect SizeOfOptionalHeader for PE32+\n");
	    if(DETECT_BROKEN_PE) {
		cli_append_virus(ctx,"Heuristics.Broken.Executable");
		return CL_VIRUS;
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

    } else { /* PE+ */
        /* read the remaining part of the header */
        if(fmap_readn(map, &optional_hdr32 + 1, at, sizeof(struct pe_image_optional_hdr64) - sizeof(struct pe_image_optional_hdr32)) != sizeof(struct pe_image_optional_hdr64) - sizeof(struct pe_image_optional_hdr32)) {
	    cli_dbgmsg("Can't read optional file header\n");
	    if(DETECT_BROKEN_PE) {
		cli_append_virus(ctx,"Heuristics.Broken.Executable");
		return CL_VIRUS;
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
    }


    switch(pe_plus ? EC16(optional_hdr64.Subsystem) : EC16(optional_hdr32.Subsystem)) {
	case 0:
	    cli_dbgmsg("Subsystem: Unknown\n");
	    break;
	case 1:
	    cli_dbgmsg("Subsystem: Native (svc)\n");
	    native = 1;
	    break;
	case 2:
	    cli_dbgmsg("Subsystem: Win32 GUI\n");
	    break;
	case 3:
	    cli_dbgmsg("Subsystem: Win32 console\n");
	    break;
	case 5:
	    cli_dbgmsg("Subsystem: OS/2 console\n");
	    break;
	case 7:
	    cli_dbgmsg("Subsystem: POSIX console\n");
	    break;
	case 8:
	    cli_dbgmsg("Subsystem: Native Win9x driver\n");
	    break;
	case 9:
	    cli_dbgmsg("Subsystem: WinCE GUI\n");
	    break;
	case 10:
	    cli_dbgmsg("Subsystem: EFI application\n");
	    break;
	case 11:
	    cli_dbgmsg("Subsystem: EFI driver\n");
	    break;
	case 12:
	    cli_dbgmsg("Subsystem: EFI runtime driver\n");
	    break;
	case 13:
	    cli_dbgmsg("Subsystem: EFI ROM image\n");
	    break;
	case 14:
	    cli_dbgmsg("Subsystem: Xbox\n");
	    break;
	case 16:
	    cli_dbgmsg("Subsystem: Boot application\n");
	    break;
	default:
	    cli_dbgmsg("Subsystem: ** UNKNOWN ** (0x%x)\n", pe_plus ? EC16(optional_hdr64.Subsystem) : EC16(optional_hdr32.Subsystem));
    }

    cli_dbgmsg("------------------------------------\n");

    if (DETECT_BROKEN_PE && !native && (!(pe_plus?EC32(optional_hdr64.SectionAlignment):EC32(optional_hdr32.SectionAlignment)) || (pe_plus?EC32(optional_hdr64.SectionAlignment):EC32(optional_hdr32.SectionAlignment))%0x1000)) {
        cli_dbgmsg("Bad virtual alignemnt\n");
	cli_append_virus(ctx,"Heuristics.Broken.Executable");
	return CL_VIRUS;
    }

    if (DETECT_BROKEN_PE && !native && (!(pe_plus?EC32(optional_hdr64.FileAlignment):EC32(optional_hdr32.FileAlignment)) || (pe_plus?EC32(optional_hdr64.FileAlignment):EC32(optional_hdr32.FileAlignment))%0x200)) {
        cli_dbgmsg("Bad file alignemnt\n");
	cli_append_virus(ctx, "Heuristics.Broken.Executable");
	return CL_VIRUS;
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
	    cli_append_virus(ctx,"Heuristics.Broken.Executable");
	    return CL_VIRUS;
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

    for(i = 0; i < nsections; i++) {
	strncpy(sname, (char *) section_hdr[i].Name, 8);
	sname[8] = 0;
	exe_sections[i].rva = PEALIGN(EC32(section_hdr[i].VirtualAddress), valign);
	exe_sections[i].vsz = PESALIGN(EC32(section_hdr[i].VirtualSize), valign);
	exe_sections[i].raw = PEALIGN(EC32(section_hdr[i].PointerToRawData), falign);
	exe_sections[i].rsz = PESALIGN(EC32(section_hdr[i].SizeOfRawData), falign);
	exe_sections[i].chr = EC32(section_hdr[i].Characteristics);
	exe_sections[i].urva = EC32(section_hdr[i].VirtualAddress); /* Just in case */
	exe_sections[i].uvsz = EC32(section_hdr[i].VirtualSize);
	exe_sections[i].uraw = EC32(section_hdr[i].PointerToRawData);
	exe_sections[i].ursz = EC32(section_hdr[i].SizeOfRawData);

	if (!exe_sections[i].vsz && exe_sections[i].rsz)
	    exe_sections[i].vsz=PESALIGN(exe_sections[i].ursz, valign);

	if (exe_sections[i].rsz && fsize>exe_sections[i].raw && !CLI_ISCONTAINED(0, (uint32_t) fsize, exe_sections[i].raw, exe_sections[i].rsz))
	    exe_sections[i].rsz = fsize - exe_sections[i].raw;
	
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
	    cli_append_virus(ctx, "Heuristics.Broken.Executable");
	    free(section_hdr);
	    free(exe_sections);
	    return CL_VIRUS;
	}

	if (exe_sections[i].rsz) { /* Don't bother with virtual only sections */
	    if (exe_sections[i].raw >= fsize) { /* really broken */
	      cli_dbgmsg("Broken PE file - Section %d starts beyond the end of file (Offset@ %lu, Total filesize %lu)\n", i, (unsigned long)exe_sections[i].raw, (unsigned long)fsize);
	      cli_dbgmsg("------------------------------------\n");
		free(section_hdr);
		free(exe_sections);
		if(DETECT_BROKEN_PE) {
		    cli_append_virus(ctx, "Heuristics.Broken.Executable");
		    return CL_VIRUS;
		}
		return CL_CLEAN; /* no ninjas to see here! move along! */
	    }

	    if(SCAN_ALGO && (DCONF & PE_CONF_POLIPOS) && !*sname && exe_sections[i].vsz > 40000 && exe_sections[i].vsz < 70000 && exe_sections[i].chr == 0xe0000060) polipos = i;

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
		cli_append_virus(ctx, "Heuristics.Broken.Executable");
		return CL_VIRUS;
	    }
	    return CL_CLEAN;
	}

	if(!i) {
	    if (DETECT_BROKEN_PE && exe_sections[i].urva!=hdr_size) { /* Bad first section RVA */
	        cli_dbgmsg("First section is in the wrong place\n");
		cli_append_virus(ctx, "Heuristics.Broken.Executable");
		free(section_hdr);
		free(exe_sections);
		return CL_VIRUS;
	    }
	    min = exe_sections[i].rva;
	    max = exe_sections[i].rva + exe_sections[i].rsz;
	} else {
	    if (DETECT_BROKEN_PE && exe_sections[i].urva - exe_sections[i-1].urva != exe_sections[i-1].vsz) { /* No holes, no overlapping, no virtual disorder */
	        cli_dbgmsg("Virtually misplaced section (wrong order, overlapping, non contiguous)\n");
		cli_append_virus(ctx, "Heuristics.Broken.Executable");
		free(section_hdr);
		free(exe_sections);
		return CL_VIRUS;
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
	    cli_append_virus(ctx,"Heuristics.Broken.Executable");
	    return CL_VIRUS;
	}
	return CL_CLEAN;
    }

    cli_dbgmsg("EntryPoint offset: 0x%x (%d)\n", ep, ep);

    if(pe_plus) { /* Do not continue for PE32+ files */
	free(exe_sections);
	return CL_CLEAN;
    }

    epsize = fmap_readn(map, epbuff, ep, 4096);


    /* Disasm scan disabled since it's now handled by the bytecode */

    /* CLI_UNPTEMP("DISASM",(exe_sections,0)); */
    /* if(disasmbuf((unsigned char*)epbuff, epsize, ndesc)) */
    /* 	ret = cli_scandesc(ndesc, ctx, CL_TYPE_PE_DISASM, 1, NULL, AC_SCAN_VIR); */
    /* close(ndesc); */
    /* CLI_TMPUNLK(); */
    /* free(tempfile); */
    /* if(ret == CL_VIRUS) { */
    /* 	free(exe_sections); */
    /* 	return ret; */
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
    /* Attempt to detect some popular polymorphic viruses */

    /* W32.Parite.B */
    if(SCAN_ALGO && (DCONF & PE_CONF_PARITE) && !dll && epsize == 4096 && ep == exe_sections[nsections - 1].raw) {
        const char *pt = cli_memstr(epbuff, 4040, "\x47\x65\x74\x50\x72\x6f\x63\x41\x64\x64\x72\x65\x73\x73\x00", 15);
	if(pt) {
	    pt += 15;
	    if((((uint32_t)cli_readint32(pt) ^ (uint32_t)cli_readint32(pt + 4)) == 0x505a4f) && (((uint32_t)cli_readint32(pt + 8) ^ (uint32_t)cli_readint32(pt + 12)) == 0xffffb) && (((uint32_t)cli_readint32(pt + 16) ^ (uint32_t)cli_readint32(pt + 20)) == 0xb8)) {
	        cli_append_virus(ctx,"Heuristics.W32.Parite.B");
		if (!SCAN_ALL) {
		    free(exe_sections);
		    return CL_VIRUS;
		}
		viruses_found++;
	    }
	}
    }

    /* Kriz */
    if(SCAN_ALGO && (DCONF & PE_CONF_KRIZ) && epsize >= 200 && CLI_ISCONTAINED(exe_sections[nsections - 1].raw, exe_sections[nsections - 1].rsz, ep, 0x0fd2) && epbuff[1]=='\x9c' && epbuff[2]=='\x60') {
	enum {KZSTRASH,KZSCDELTA,KZSPDELTA,KZSGETSIZE,KZSXORPRFX,KZSXOR,KZSDDELTA,KZSLOOP,KZSTOP};
	uint8_t kzs[] = {KZSTRASH,KZSCDELTA,KZSPDELTA,KZSGETSIZE,KZSTRASH,KZSXORPRFX,KZSXOR,KZSTRASH,KZSDDELTA,KZSTRASH,KZSLOOP,KZSTOP};
	uint8_t *kzstate = kzs;
	uint8_t *kzcode = (uint8_t *)epbuff + 3;
	uint8_t kzdptr=0xff, kzdsize=0xff;
	int kzlen = 197, kzinitlen=0xffff, kzxorlen=-1;
	cli_dbgmsg("in kriz\n");

	while(*kzstate!=KZSTOP) {
	    uint8_t op;
	    if(kzlen<=6) break;
	    op = *kzcode++;
	    kzlen--;
	    switch (*kzstate) {
	    case KZSTRASH: case KZSGETSIZE: {
		int opsz=0;
		switch(op) {
		case 0x81:
		    kzcode+=5;
		    kzlen-=5;
		    break;
		case 0xb8: case 0xb9: case 0xba: case 0xbb: case 0xbd: case 0xbe: case 0xbf:
		    if(*kzstate==KZSGETSIZE && cli_readint32(kzcode)==0x0fd2) {
			kzinitlen = kzlen-5;
			kzdsize=op-0xb8;
			kzstate++;
			op=4; /* fake the register to avoid breaking out */
			cli_dbgmsg("kriz: using #%d as size counter\n", kzdsize);
		    }
		    opsz=4;
		case 0x48: case 0x49: case 0x4a: case 0x4b: case 0x4d: case 0x4e: case 0x4f:
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
		} else *kzstate=KZSTOP;
		break;
	    case KZSPDELTA:
		if((op&0xf8)==0x58 && (kzdptr=op-0x58)!=4) {
		    kzstate++;
		    cli_dbgmsg("kriz: using #%d as pointer\n", kzdptr);
		} else *kzstate=KZSTOP;
		break;
	    case KZSXORPRFX:
		kzstate++;
		if(op==0x3e) break;
	    case KZSXOR:
		if (op==0x80 && *kzcode==kzdptr+0xb0) {
		    kzxorlen=kzlen;
		    kzcode+=+6;
		    kzlen-=+6;
		    kzstate++;
		} else *kzstate=KZSTOP;
		break;
	    case KZSDDELTA:
		if (op==kzdptr+0x48) kzstate++;
		else *kzstate=KZSTOP;
		break;
	    case KZSLOOP:
		if (op==kzdsize+0x48 && *kzcode==0x75 && kzlen-(int8_t)kzcode[1]-3<=kzinitlen && kzlen-(int8_t)kzcode[1]>=kzxorlen) {
		    cli_append_virus(ctx,"Heuristics.W32.Kriz");
		    if (!SCAN_ALL) {
		        free(exe_sections);
			return CL_VIRUS;
		    }
		    viruses_found++;
		}
		cli_dbgmsg("kriz: loop out of bounds, corrupted sample?\n");
		kzstate++;
	    }
	}
    }

    /* W32.Magistr.A/B */
    if(SCAN_ALGO && (DCONF & PE_CONF_MAGISTR) && !dll && (nsections>1) && (exe_sections[nsections - 1].chr & 0x80000000)) {
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
		    cli_append_virus(ctx, dam ? "Heuristics.W32.Magistr.A.dam" : "Heuristics.W32.Magistr.A");
		    if (!SCAN_ALL) {
		        free(exe_sections);
			return CL_VIRUS;
		    }
		    viruses_found++;
		}
	    }

	} else if(rsize >= 0x7000 && vsize >= 0x7000 && ((vsize & 0xff) == 0xed)) {
		int bw = rsize < 0x8000 ? rsize : 0x8000;
		const char *tbuff;

	    if((tbuff = fmap_need_off_once(map, exe_sections[nsections - 1].raw + rsize - bw, 4096))) {
		if(cli_memstr(tbuff, 4091, "\xe8\x04\x72\x00\x00", 5)) {
		    cli_append_virus(ctx,dam ? "Heuristics.W32.Magistr.B.dam" : "Heuristics.W32.Magistr.B");
		    if (!SCAN_ALL) {
		        free(exe_sections);
			return CL_VIRUS;
		    }
		    viruses_found++;
		} 
	    }
	}
    }

    /* W32.Polipos.A */
    while(polipos && !dll && nsections > 2 && nsections < 13 && e_lfanew <= 0x800 && (EC16(optional_hdr32.Subsystem) == 2 || EC16(optional_hdr32.Subsystem) == 3) && EC16(file_hdr.Machine) == 0x14c && optional_hdr32.SizeOfStackReserve >= 0x80000) {
	uint32_t jump, jold, *jumps = NULL;
	const uint8_t *code;
	unsigned int xsjs = 0;

	if(exe_sections[0].rsz > CLI_MAX_ALLOCATION) break;

	if(!exe_sections[0].rsz) break;
	if(!(code=fmap_need_off_once(map, exe_sections[0].raw, exe_sections[0].rsz))) break;
	for(i=0; i<exe_sections[0].rsz - 5; i++) {
	    if((uint8_t)(code[i]-0xe8) > 1) continue;
	    jump = cli_rawaddr(exe_sections[0].rva+i+5+cli_readint32(&code[i+1]), exe_sections, nsections, &err, fsize, hdr_size);
	    if(err || !CLI_ISCONTAINED(exe_sections[polipos].raw, exe_sections[polipos].rsz, jump, 9)) continue;
	    if(xsjs % 128 == 0) {
		if(xsjs == 1280) break;
		if(!(jumps=(uint32_t *)cli_realloc2(jumps, (xsjs+128)*sizeof(uint32_t)))) {
		    free(exe_sections);
		    return CL_EMEM;
		}
	    }
	    j=0;
	    for(; j<xsjs; j++) {
		if(jumps[j]<jump) continue;
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
	if(!xsjs) break;
	cli_dbgmsg("Polipos: Checking %d xsect jump(s)\n", xsjs);
	for(i=0;i<xsjs;i++) {
	    if(!(code = fmap_need_off_once(map, jumps[i], 9))) continue;
	    if((jump=cli_readint32(code))==0x60ec8b55 || (code[4]==0x0ec && ((jump==0x83ec8b55 && code[6]==0x60) || (jump==0x81ec8b55 && !code[7] && !code[8])))) {
		cli_append_virus(ctx,"Heuristics.W32.Polipos.A");
		if (!SCAN_ALL) {
		    free(jumps);
		    free(exe_sections);
		    return CL_VIRUS;
		}
		viruses_found++;
	    }
	}
	free(jumps);
	break;
    }

    /* Trojan.Swizzor.Gen */
    if (SCAN_ALGO && (DCONF & PE_CONF_SWIZZOR) && nsections > 1 && fsize > 64*1024 && fsize < 4*1024*1024) {
	    if(dirs[2].Size) {
		    struct swizz_stats *stats = cli_calloc(1, sizeof(*stats));
		    unsigned int m = 1000;
		    ret = CL_CLEAN;

		    if (!stats)
			    ret = CL_EMEM;
		    else {
			    cli_parseres_special(EC32(dirs[2].VirtualAddress), EC32(dirs[2].VirtualAddress), map, exe_sections, nsections, fsize, hdr_size, 0, 0, &m, stats);
			    if ((ret = cli_detect_swizz(stats)) == CL_VIRUS) {
				cli_append_virus(ctx,"Heuristics.Trojan.Swizzor.Gen");
			    }
			    free(stats);
		    }
		    if (ret != CL_CLEAN) {
			if (!(ret == CL_VIRUS && SCAN_ALL)) {
			    free(exe_sections);
			    return ret;
			}
			viruses_found++;
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
	    if (fileoffset == 0x154) cli_dbgmsg("MEW: Win9x compatibility was set!\n");
	    else cli_dbgmsg("MEW: Win9x compatibility was NOT set!\n");

	    if((offdiff = cli_readint32(tbuff+1) - EC32(optional_hdr32.ImageBase)) <= exe_sections[i + 1].rva || offdiff >= exe_sections[i + 1].rva + exe_sections[i + 1].raw - 4) {
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
	 * 3 sections:           | 2 sections (one empty, I don't chech found if !upack, since it's in OR above):
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

	    if(fmap_readn(map, dest, 0, ssize) != ssize) {
	        cli_dbgmsg("Upack: Can't read raw data of section 0\n");
		free(dest);
		break;
	    }

	    if(upack) memmove(dest + exe_sections[2].rva - exe_sections[0].rva, dest, ssize);

	    if(fmap_readn(map, dest + exe_sections[1].rva - off, exe_sections[1].uraw, exe_sections[1].ursz) != exe_sections[1].ursz) {
		cli_dbgmsg("Upack: Can't read raw data of section 1\n");
		free(dest);
		break;
	    }

	    CLI_UNPTEMP("Upack",(dest,exe_sections,0));
	    CLI_UNPRESULTS("Upack",(unupack(upack, dest, dsize, epbuff, vma, ep, EC32(optional_hdr32.ImageBase), exe_sections[0].rva, ndesc)),1,(dest,0));
	    break;
	}
    }

    
    while(found  && (DCONF & PE_CONF_FSG) && epbuff[0] == '\x87' && epbuff[1] == '\x25') {
	const char *dst;

	/* FSG v2.0 support - thanks to aCaB ! */

	uint32_t newesi, newedi, newebx, newedx;
	
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

	CLI_UNPTEMP("FSG",(dest,exe_sections,0));
	CLI_UNPRESULTSFSG2("FSG",(unfsg_200(newesi - exe_sections[i + 1].rva + src, dest, ssize + exe_sections[i + 1].rva - newesi, dsize, newedi, EC32(optional_hdr32.ImageBase), newedx, ndesc)),1,(dest,0));
	break;
    }


    while(found && (DCONF & PE_CONF_FSG) && epbuff[0] == '\xbe' && cli_readint32(epbuff + 1) - EC32(optional_hdr32.ImageBase) < min) {

	/* FSG support - v. 1.33 (thx trog for the many samples) */

	int sectcnt = 0;
	const char *support;
	uint32_t newesi, newedi, oldep, gp, t;
	struct cli_exe_section *sections;

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

	    if(rva % 0x1000) cli_dbgmsg("FSG: Original section %d is misaligned\n", sectcnt);

	    if(rva < exe_sections[i].rva || rva - exe_sections[i].rva >= exe_sections[i].vsz) {
		cli_dbgmsg("FSG: Original section %d is out of bounds\n", sectcnt);
		break;
	    }
	}

	if(t >= gp - 4 || cli_readint32(support + t)) {
	    break;
	}

	if((sections = (struct cli_exe_section *) cli_malloc((sectcnt + 1) * sizeof(struct cli_exe_section))) == NULL) {
        cli_errmsg("FSG: Unable to allocate memory for sections %u\n", (sectcnt + 1) * sizeof(struct cli_exe_section));
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

	CLI_UNPTEMP("FSG",(dest,sections,exe_sections,0));
	CLI_UNPRESULTSFSG1("FSG",(unfsg_133(src + newesi - exe_sections[i + 1].rva, dest, ssize + exe_sections[i + 1].rva - newesi, dsize, sections, sectcnt, EC32(optional_hdr32.ImageBase), oldep, ndesc)),1,(dest,sections,0));
	break; /* were done with 1.33 */
    }


    while(found && (DCONF & PE_CONF_FSG) && epbuff[0] == '\xbb' && cli_readint32(epbuff + 1) - EC32(optional_hdr32.ImageBase) < min && epbuff[5] == '\xbf' && epbuff[10] == '\xbe' && vep >= exe_sections[i + 1].rva && vep - exe_sections[i + 1].rva > exe_sections[i + 1].rva - 0xe0 ) {

	/* FSG support - v. 1.31 */

	int sectcnt = 0;
	uint32_t gp, t = cli_rawaddr(cli_readint32(epbuff+1) - EC32(optional_hdr32.ImageBase), NULL, 0 , &err, fsize, hdr_size);
	const char *support;
	uint32_t newesi = cli_readint32(epbuff+11) - EC32(optional_hdr32.ImageBase);
	uint32_t newedi = cli_readint32(epbuff+6) - EC32(optional_hdr32.ImageBase);
	uint32_t oldep = vep - exe_sections[i + 1].rva;
	struct cli_exe_section *sections;

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

	if(t >= gp-10 || cli_readint32(support + t + 6) != 2) {
	    break;
	}

	if((sections = (struct cli_exe_section *) cli_malloc((sectcnt + 1) * sizeof(struct cli_exe_section))) == NULL) {
        cli_errmsg("FSG: Unable to allocate memory for sections %u\n", (sectcnt + 1) * sizeof(struct cli_exe_section));
	    free(exe_sections);
	    return CL_EMEM;
	}

	sections[0].rva = newedi;
	for(t = 0; t <= (uint32_t)sectcnt - 1; t++) {
	    sections[t+1].rva = (((support[t*2]|(support[t*2+1]<<8))-2)<<12)-EC32(optional_hdr32.ImageBase);
	}

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

	CLI_UNPTEMP("FSG",(dest,sections,exe_sections,0));
	CLI_UNPRESULTSFSG1("FSG",(unfsg_133(src + newesi - exe_sections[i + 1].rva, dest, ssize + exe_sections[i + 1].rva - newesi, dsize, sections, sectcnt, EC32(optional_hdr32.ImageBase), oldep, ndesc)),1,(dest,sections,0));
	break; /* were done with 1.31 */
    }


    if(found && (DCONF & PE_CONF_UPX)) {

	/* UPX support */

	/* we assume (i + 1) is UPX1 */
	ssize = exe_sections[i + 1].rsz;
	dsize = exe_sections[i].vsz + exe_sections[i + 1].vsz;

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

	    if(epbuff[1] != '\xbe' || skew <= 0 || skew > 0xfff) { /* FIXME: legit skews?? */
		skew = 0; 
	    } else if (skew > ssize) {
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
		if(skew!=0x15) skew = 0;
	    }
	    if(strictdsize<=dsize)
		upx_success = upx_inflatelzma(src+skew, ssize-skew, dest, &strictdsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep) >=0;
	} else if (cli_memstr(UPX_LZMA1, 20, epbuff + 0x39, 20)) {
	    uint32_t strictdsize=cli_readint32(epbuff+0x2b), skew = 0;
	    if(ssize > 0x15 && epbuff[0] == '\x60' && epbuff[1] == '\xbe') {
		skew = cli_readint32(epbuff+2) - exe_sections[i + 1].rva - optional_hdr32.ImageBase;
		if(skew!=0x15) skew = 0;
	    }
	    if(strictdsize<=dsize)
		upx_success = upx_inflatelzma(src+skew, ssize-skew, dest, &strictdsize, exe_sections[i].rva, exe_sections[i + 1].rva, vep) >=0;
	}

	if(!upx_success) {
	    cli_dbgmsg("UPX: All decompressors failed\n");
	    free(dest);
	}
    }

    if(upx_success) {
	free(exe_sections);

	CLI_UNPTEMP("UPX/FSG",(dest,0));

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
	if((ret = cli_magic_scandesc(ndesc, ctx)) == CL_VIRUS) {
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
		    if(!exe_sections[i].rsz || fmap_readn(map, dest + exe_sections[i].rva - min, exe_sections[i].raw, exe_sections[i].ursz) != exe_sections[i].ursz) {
			free(exe_sections);
			free(dest);
			return CL_CLEAN;
		    }
		}
	    }

	    CLI_UNPTEMP("Petite",(dest,exe_sections,0));
	    CLI_UNPRESULTS("Petite",(petite_inflate2x_1to9(dest, min, max - min, exe_sections, nsections - (found == 1 ? 1 : 0), EC32(optional_hdr32.ImageBase),vep, ndesc, found, EC32(optional_hdr32.DataDirectory[2].VirtualAddress),EC32(optional_hdr32.DataDirectory[2].Size))),0,(dest,0));
	}
    }

    /* PESpin 1.1 */

    if((DCONF & PE_CONF_PESPIN) && nsections > 1 &&
       vep >= exe_sections[nsections - 1].rva &&
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

	    cli_dbgmsg("%d,%d,%d,%d\n", nsections-1, e_lfanew, ecx, offset);
	    CLI_UNPTEMP("yC",(spinned,exe_sections,0));
	    CLI_UNPRESULTS("yC",(yc_decrypt(spinned, fsize, exe_sections, nsections-1, e_lfanew, ndesc, ecx, offset)),0,(spinned,0));
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
	    if(i+1==nsections) break;
	    if(ssize<exe_sections[i].rva+exe_sections[i].vsz)
		ssize=exe_sections[i].rva+exe_sections[i].vsz;
	}
	if(!head || !ssize || head>ssize) break;

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
	    if(!exe_sections[i].rsz) continue;
            if(!CLI_ISCONTAINED(src, ssize, src+exe_sections[i].rva, exe_sections[i].rsz)) break;
            if(fmap_readn(map, src+exe_sections[i].rva, exe_sections[i].raw, exe_sections[i].rsz)!=exe_sections[i].rsz) break;
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

	CLI_UNPTEMP("WWPack",(src,packer,exe_sections,0));
	CLI_UNPRESULTS("WWPack",(wwunpack((uint8_t *)src, ssize, packer, exe_sections, nsections-1, e_lfanew, ndesc)),0,(src,packer,0));
	break;
    }


    /* ASPACK support */
    while((DCONF & PE_CONF_ASPACK) && ep+58+0x70e < fsize && !memcmp(epbuff,"\x60\xe8\x03\x00\x00\x00\xe9\xeb",8)) {
	char *src;

        if(epsize<0x3bf || memcmp(epbuff+0x3b9, "\x68\x00\x00\x00\x00\xc3",6)) break;
	ssize = 0;
	for(i=0 ; i< nsections ; i++)
	    if(ssize<exe_sections[i].rva+exe_sections[i].vsz)
		ssize=exe_sections[i].rva+exe_sections[i].vsz;
	if(!ssize) break;

	CLI_UNPSIZELIMITS("Aspack", ssize);

        if(!(src=(char *)cli_calloc(ssize, sizeof(char)))) {
	    free(exe_sections);
	    return CL_EMEM;
	}
        for(i = 0 ; i < (unsigned int)nsections; i++) {
	    if(!exe_sections[i].rsz) continue;
            if(!CLI_ISCONTAINED(src, ssize, src+exe_sections[i].rva, exe_sections[i].rsz)) break;
            if(fmap_readn(map, src+exe_sections[i].rva, exe_sections[i].raw, exe_sections[i].rsz)!=exe_sections[i].rsz) break;
        }
        if(i!=nsections) {
            cli_dbgmsg("Aspack: Probably hacked/damaged Aspack file.\n");
            free(src);
            break;
        }

	CLI_UNPTEMP("Aspack",(src,exe_sections,0));
	CLI_UNPRESULTS("Aspack",(unaspack212((uint8_t *)src, ssize, exe_sections, nsections, vep-1, EC32(optional_hdr32.ImageBase), ndesc)),1,(src,0));
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
	    if (!(rep = cli_rawaddr(eprva, exe_sections, nsections, &err, fsize, hdr_size)) && err) break;
	    if (!(nbuff = fmap_need_off_once(map, rep, 24))) break;
	    src = nbuff;
	}

	if (memcmp(src, "\x9c\x60\xe8\x00\x00\x00\x00\x5d\xb8\x07\x00\x00\x00", 13)) break;

	nowinldr = 0x54-cli_readint32(src+17);
	cli_dbgmsg("NsPack: Found *start_of_stuff @delta-%x\n", nowinldr);

	if(!(nbuff = fmap_need_off_once(map, rep-nowinldr, 4))) break;
	start_of_stuff=rep+cli_readint32(nbuff);
	if(!(nbuff = fmap_need_off_once(map, start_of_stuff, 20))) break;
	src = nbuff;
	if (!cli_readint32(nbuff)) {
	    start_of_stuff+=4; /* FIXME: more to do */
	    src+=4;
	}

	ssize = cli_readint32(src+5)|0xff;
	dsize = cli_readint32(src+9);

	CLI_UNPSIZELIMITS("NsPack", MAX(ssize,dsize));

	if (!ssize || !dsize || dsize != exe_sections[0].vsz) break;
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
    if (SCAN_ALL && viruses_found)
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
	int i;
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
	cli_dbgmsg("Can't read file header\n");
	return -1;
    }

    if(EC32(file_hdr.Magic) != PE_IMAGE_NT_SIGNATURE) {
	cli_dbgmsg("Invalid PE signature (probably NE file)\n");
	return -1;
    }

    if ( (peinfo->nsections = EC16(file_hdr.NumberOfSections)) < 1 || peinfo->nsections > 96 ) return -1;

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
	if(!vlist.count) break; /* No version_information */
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
		   cli_readint32(vptr + 0x28) != 0xfeef04bd) {
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
				if(vptr[s_key_sz] || vptr[s_key_sz+1]) continue;
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
					s = cli_str2hex((const char*)vptr + 6, s_key_sz + s_val_sz - 6);
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

int cli_checkfp_pe(cli_ctx *ctx, uint8_t *authsha1, stats_section_t *hashes, uint32_t flags) {
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

    if (flags & CL_CHECKFP_PE_FLAG_STATS)
        if (!(hashes))
            return CL_EFORMAT;

    if (flags == CL_CHECKFP_PE_FLAG_NONE)
        return CL_VIRUS;

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
    if(nsections < 1 || nsections > 96)
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
        if(fmap_readn(map, &optional_hdr32 + 1, at, readlen) != readlen)
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

    if (flags & CL_CHECKFP_PE_FLAG_STATS) {
        hashes->nsections = nsections;
        hashes->sections = cli_calloc(nsections, sizeof(struct cli_section_hash));
        if (!(hashes->sections)) {
            free(exe_sections);
            return CL_EMEM;
        }
    }

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
    hashctx = cl_hash_init("sha1");
    if (!(hashctx)) {
        if (flags & CL_CHECKFP_PE_FLAG_AUTHENTICODE)
            flags ^= CL_CHECKFP_PE_FLAG_AUTHENTICODE;
    }

    if (flags & CL_CHECKFP_PE_FLAG_AUTHENTICODE) {
        /* Check to see if we have a security section. */
        if(!cli_hm_have_size(ctx->engine->hm_fp, CLI_HASH_SHA1, 2) && dirs[4].Size < 8) {
            if (flags & CL_CHECKFP_PE_FLAG_STATS) {
                /* If stats is enabled, continue parsing the sample */
                flags ^= CL_CHECKFP_PE_FLAG_AUTHENTICODE;
            } else {
                if (hashctx)
                    cl_hash_destroy(hashctx);
                return CL_BREAK;
            }
        }
    }

#define hash_chunk(where, size, isStatAble, section) \
    do { \
        const uint8_t *hptr; \
        if(!(size)) break; \
        if(!(hptr = fmap_need_off_once(map, where, size))){ \
            free(exe_sections); \
            if (hashctx) \
                cl_hash_destroy(hashctx); \
            return CL_EFORMAT; \
        } \
        if (flags & CL_CHECKFP_PE_FLAG_AUTHENTICODE && hashctx) \
            cl_update_hash(hashctx, hptr, size); \
        if (isStatAble && flags & CL_CHECKFP_PE_FLAG_STATS) { \
            void *md5ctx; \
            md5ctx = cl_hash_init("md5"); \
            if (md5ctx) { \
                cl_update_hash(md5ctx, hptr, size); \
                cl_finish_hash(md5ctx, hashes->sections[section].md5); \
            } \
        } \
    } while(0)

    while (flags & CL_CHECKFP_PE_FLAG_AUTHENTICODE) {
        /* MZ to checksum */
        at = 0;
        hlen = e_lfanew + sizeof(struct pe_image_file_hdr) + (pe_plus ? offsetof(struct pe_image_optional_hdr64, CheckSum) : offsetof(struct pe_image_optional_hdr32, CheckSum));
        hash_chunk(0, hlen, 0, 0);
        at = hlen + 4;

        /* Checksum to security */
        if(pe_plus)
            hlen = offsetof(struct pe_image_optional_hdr64, DataDirectory[4]) - offsetof(struct pe_image_optional_hdr64, CheckSum) - 4;
        else
            hlen = offsetof(struct pe_image_optional_hdr32, DataDirectory[4]) - offsetof(struct pe_image_optional_hdr32, CheckSum) - 4;
        hash_chunk(at, hlen, 0, 0);
        at += hlen + 8;

        if(at > hdr_size) {
            if (flags & CL_CHECKFP_PE_FLAG_STATS) {
                flags ^= CL_CHECKFP_PE_FLAG_AUTHENTICODE;
                break;
            } else {
                free(exe_sections);
                if (hashctx)
                    cl_hash_destroy(hashctx);
                return CL_EFORMAT;
            }
        }

        /* Security to End of header */
        hlen = hdr_size - at;
        hash_chunk(at, hlen, 0, 0);

        at = hdr_size;
        break;
    }

    /* Hash the sections */
    for(i = 0; i < nsections; i++) {
        if(!exe_sections[i].rsz)
            continue;

        hash_chunk(exe_sections[i].raw, exe_sections[i].rsz, 1, i);
        if (flags & CL_CHECKFP_PE_FLAG_AUTHENTICODE)
            at += exe_sections[i].rsz;
    }

    while (flags & CL_CHECKFP_PE_FLAG_AUTHENTICODE) {
        if(at < fsize) {
            hlen = fsize - at;
            if(dirs[4].Size > hlen) {
                if (flags & CL_CHECKFP_PE_FLAG_STATS) {
                    flags ^= CL_CHECKFP_PE_FLAG_AUTHENTICODE;
                    break;
                } else {
                    free(exe_sections);
                    if (hashctx)
                        cl_hash_destroy(hashctx);
                    return CL_EFORMAT;
                }
            }

            hlen -= dirs[4].Size;
            hash_chunk(at, hlen, 0, 0);
            at += hlen;
        }

        break;
    } while (0);

    free(exe_sections);

    if (flags & CL_CHECKFP_PE_FLAG_AUTHENTICODE && hashctx) {
        cl_finish_hash(hashctx, authsha1);

        if(cli_debug_flag) {
            char shatxt[SHA1_HASH_SIZE*2+1];
            for(i=0; i<SHA1_HASH_SIZE; i++)
                sprintf(&shatxt[i*2], "%02x", authsha1[i]);
            cli_dbgmsg("Authenticode: %s\n", shatxt);
        }

        hlen = dirs[4].Size;
        if(hlen < 8)
            return CL_VIRUS;

        hlen -= 8;

        return asn1_check_mscat((struct cl_engine *)(ctx->engine), map, at + 8, hlen, authsha1);
    } else {
        if (hashctx)
            cl_hash_destroy(hashctx);
        return CL_VIRUS;
    }
}
