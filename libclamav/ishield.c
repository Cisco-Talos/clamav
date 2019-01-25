/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>
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

/* common routines to deal with installshield archives and installers */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#include <limits.h>
#if HAVE_STRINGS_H
#include <strings.h>
#endif
#if defined(HAVE_MMAP) && defined(HAVE_SYS_MMAN_H)
#include <sys/mman.h>
#endif
#include <zlib.h>

#include "clamav.h"
#include "scanners.h"
#include "others.h"
#include "fmap.h"
#include "ishield.h"

#ifndef LONG_MAX
#define LONG_MAX ((-1UL)>>1)
#endif

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif
#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif
#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

/* PACKED things go here */

struct IS_HDR {
    uint32_t magic; 
    uint32_t unk1; /* version ??? */
    uint32_t unk2; /* ??? */
    uint32_t data_off;
    uint32_t data_sz; /* ??? */
} __attribute__((packed));

struct IS_FB {
    char fname[0x104]; /* MAX_PATH */
    uint32_t unk1; /* 6 */
    uint32_t unk2;
    uint64_t csize;
    uint32_t unk3;
    uint32_t unk4; /* 1 */
    uint32_t unk5;
    uint32_t unk6;
    uint32_t unk7;
    uint32_t unk8;
    uint32_t unk9;
    uint32_t unk10;
    uint32_t unk11;
} __attribute__((packed));

struct IS_COMPONENT {
    uint32_t str_name_off;
    uint32_t unk_str1_off;
    uint32_t unk_str2_off;
    uint16_t unk_flags;
    uint32_t unk_str3_off;
    uint32_t unk_str4_off;
    uint16_t ordinal_id;
    uint32_t str_shortname_off;
    uint32_t unk_str6_off;
    uint32_t unk_str7_off;
    uint32_t unk_str8_off;
    char guid1[16];
    char guid2[16];
    uint32_t unk_str9_off;
    char unk1[3];
    uint16_t unk_flags2;
    uint32_t unk3[5];
    uint32_t unk_str10_off;
    uint32_t unk4[4];
    uint16_t unk5;
    uint16_t sub_comp_cnt;
    uint32_t sub_comp_offs_array;
    uint32_t next_comp_off;
    uint32_t unk_str11_off;
    uint32_t unk_str12_off;
    uint32_t unk_str13_off;
    uint32_t unk_str14_off;
    uint32_t str_next1_off;
    uint32_t str_next2_off;
} __attribute__((packed));

struct IS_INSTTYPEHDR {
    uint32_t unk1;
    uint32_t cnt;
    uint32_t off;
} __attribute__((packed));

struct IS_INSTTYPEITEM {
    uint32_t str_name1_off;
    uint32_t str_name2_off;
    uint32_t str_name3_off;
    uint32_t cnt;
    uint32_t off;
} __attribute__((packed));


struct IS_OBJECTS {
    /* 200 */ uint32_t strings_off;
    /* 204 */ uint32_t zero1;
    /* 208 */ uint32_t comps_off;
    /* 20c */ uint32_t dirs_off;
    /* 210 */ uint32_t zero2;
    /* 214 */ uint32_t unk1, unk2; /* 0x4a636 304694 uguali - NOT AN OFFSET! */
    /* 21c */ uint32_t dirs_cnt;
    /* 220 */ uint32_t zero3;
    /* 224 */ uint32_t dirs_sz; /* dirs_cnt * 4 */
    /* 228 */ uint32_t files_cnt;
    /* 22c */ uint32_t dir_sz2; /* same as dirs_sz ?? */
    /* 230 */ uint16_t unk5; /* 1 - comp count ?? */
    /* 232 */ uint32_t insttype_off;
    /* 234 */ uint16_t zero4;
    /* 238 */ uint32_t zero5;
    /* 23c */ uint32_t unk7; /* 0xd0 - 208 */
    /* 240 */ uint16_t unk8;
    /* 242 */ uint32_t unk9;
    /* 246 */ uint32_t unk10;   
} __attribute__((packed));


struct IS_FILEITEM {
    uint16_t flags; /* 0 = EXTERNAL | 4 = INTERNAL | 8 = NAME_fuckup_rare | c = name_fuckup_common */
    uint64_t size;
    uint64_t csize;
    uint64_t stream_off;
    uint8_t md5[16];
    uint64_t versioninfo_id;
    uint32_t zero1;
    uint32_t zero2;
    uint32_t str_name_off;
    uint16_t dir_id;
    uint32_t unk13; /* 0, 20, 21 ??? */
    uint32_t unk14; /* timestamp ??? */
    uint32_t unk15; /* begins with 1 then 2 but not the cab# ??? */
    uint32_t prev_dup_id; /* msvcrt #38(0, 97, 2) #97(38, 1181, 3) ... , 0, 1) */
    uint32_t next_dup_id;
    uint8_t flag_has_dup; /* HAS_NEXT = 2 | HAS_BOTH = 3 | HAS_PREV = 1 */
    uint16_t datafile_id;
} __attribute__((packed));


#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif
#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif



static int is_dump_and_scan(cli_ctx *ctx, off_t off, size_t fsize);
static const uint8_t skey[] = { 0xec, 0xca, 0x79, 0xf8 }; /* ~0x13, ~0x35, ~0x86, ~0x07 */

/* Extracts the content of MSI based IS */
int cli_scanishield_msi(cli_ctx *ctx, off_t off) {
    const uint8_t *buf;
    unsigned int fcount, scanned = 0;
    int ret;
    fmap_t *map = *ctx->fmap;

    cli_dbgmsg("in ishield-msi\n");
    if(!(buf = fmap_need_off_once(map, off, 0x20))) {
	cli_dbgmsg("ishield-msi: short read for header\n");
	return CL_CLEAN;
    }
    off += 0x20;
    if(cli_readint32(buf + 8) | cli_readint32(buf + 0xc) | cli_readint32(buf + 0x10) | cli_readint32(buf + 0x14) | cli_readint32(buf + 0x18) | cli_readint32(buf + 0x1c))
	return CL_CLEAN;
    if(!(fcount = cli_readint32(buf))) {
	cli_dbgmsg("ishield-msi: no files?\n");
	return CL_CLEAN;
    }
    while(fcount--) {
	struct IS_FB fb;
	uint8_t obuf[BUFSIZ], *key = (uint8_t *)&fb.fname;
	char *tempfile;
	unsigned int i, lameidx=0, keylen;
	int ofd;
	uint64_t csize;
	z_stream z;

	if(fmap_readn(map, &fb, off, sizeof(fb)) != sizeof(fb)) {
	    cli_dbgmsg("ishield-msi: short read for fileblock\n");
	    return CL_CLEAN;
	}
	off += sizeof(fb);
	fb.fname[sizeof(fb.fname)-1] = '\0';
	csize = le64_to_host(fb.csize);
	if(!CLI_ISCONTAINED(0, map->len, off, csize)) {
	    cli_dbgmsg("ishield-msi: next stream is out of file, giving up\n");
	    return CL_CLEAN;
	}
	if(ctx->engine->maxfilesize && csize > ctx->engine->maxfilesize) {
	    cli_dbgmsg("ishield-msi: skipping stream due to size limits (%lu vs %lu)\n", (unsigned long int) csize, (unsigned long int) ctx->engine->maxfilesize);
	    off += csize;
	    continue;
	}

	keylen = strlen((const char *)key);
	if(!keylen) return CL_CLEAN;
	/* FIXMEISHIELD: cleanup the spam below */
	cli_dbgmsg("ishield-msi: File %s (csize: %llx, unk1:%x unk2:%x unk3:%x unk4:%x unk5:%x unk6:%x unk7:%x unk8:%x unk9:%x unk10:%x unk11:%x)\n", key, (long long)csize, fb.unk1, fb.unk2, fb.unk3, fb.unk4, fb.unk5, fb.unk6, fb.unk7, fb.unk8, fb.unk9, fb.unk10, fb.unk11);
	if(!(tempfile = cli_gentemp(ctx->engine->tmpdir))) return CL_EMEM;
	if((ofd = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRUSR|S_IWUSR)) < 0) {
	    cli_dbgmsg("ishield-msi: failed to create file %s\n", tempfile);
	    free(tempfile);
	    return CL_ECREAT;
	}

	for(i=0; i<keylen; i++)
	    key[i] ^= skey[i & 3];
	memset(&z, 0, sizeof(z));
	inflateInit(&z);
	ret = CL_SUCCESS;
	while(csize) {
	    uint8_t buf2[BUFSIZ];
	    z.avail_in = MIN(csize, sizeof(buf2));
	    if((uInt)fmap_readn(map, buf2, off, z.avail_in) != z.avail_in) {
		cli_dbgmsg("ishield-msi: premature EOS or read fail\n");
		break;
	    }
	    off += z.avail_in;
	    for(i=0; i<z.avail_in; i++, lameidx++) {
		uint8_t c = buf2[i];
		c = (c>>4) | (c<<4);
		c ^= key[(lameidx & 0x3ff) % keylen];
		buf2[i] = c;
	    }
	    csize -= z.avail_in;
	    z.next_in = buf2;
	    do {
		int inf;
		z.avail_out = sizeof(obuf);
		z.next_out = obuf;
		inf = inflate(&z, 0);
		if(inf != Z_OK && inf != Z_STREAM_END && inf != Z_BUF_ERROR) {
		    cli_dbgmsg("ishield-msi: bad stream\n");
		    csize = 0;
		    off += csize;
		    break;
		}
		if (cli_writen(ofd, obuf, sizeof(obuf) - z.avail_out) < 0) {
		    ret = CL_EWRITE;
		    csize = 0;
		    break;
		}
		if(ctx->engine->maxfilesize && z.total_out > ctx->engine->maxfilesize) {
		    cli_dbgmsg("ishield-msi: trimming output file due to size limits (%lu vs %lu)\n", z.total_out, (unsigned long int) ctx->engine->maxfilesize);
		    off += csize;
		    csize = 0;
		    break;
		}
	    } while (!z.avail_out);
	}

	inflateEnd(&z);

	if (ret == CL_SUCCESS) {
	    cli_dbgmsg("ishield-msi: extracted to %s\n", tempfile);

	    if (lseek(ofd, 0, SEEK_SET) == -1) {
            cli_dbgmsg("ishield-msi: call to lseek() failed\n");
            ret = CL_ESEEK;
        }
	    ret = cli_magic_scandesc(ofd, tempfile, ctx);
	}
	close(ofd);

	if(!ctx->engine->keeptmp)
	    if(cli_unlink(tempfile)) ret = CL_EUNLINK;
	free(tempfile);

	if(ret != CL_CLEAN)
	    return ret;

	scanned++;
	if (ctx->engine->maxfiles && scanned>=ctx->engine->maxfiles) {
	    cli_dbgmsg("ishield-msi: File limit reached (max: %u)\n", ctx->engine->maxfiles);
	    return CL_EMAXFILES;
	}
    }
    return CL_CLEAN;
}


struct IS_CABSTUFF {
    struct CABARRAY {
	unsigned int cabno;
	off_t off;
	size_t sz;
    } *cabs;
    off_t hdr;
    size_t hdrsz;
    unsigned int cabcnt;
};

static void md5str(uint8_t *sum);
static int is_parse_hdr(cli_ctx *ctx, struct IS_CABSTUFF *c);
static int is_extract_cab(cli_ctx *ctx, uint64_t off, uint64_t size, uint64_t csize);

/* Extract the content of older (non-MSI) IS */
int cli_scanishield(cli_ctx *ctx, off_t off, size_t sz) {
    const char *fname, *path, *version, *strsz, *data;
    char *eostr;
    int ret = CL_CLEAN;
    long fsize;
    off_t coff = off;
    struct IS_CABSTUFF c = { NULL, -1, 0, 0 };
    fmap_t *map = *ctx->fmap;
    unsigned fc = 0;
    int virus_found = 0;

    while(ret == CL_CLEAN) {
	fname = fmap_need_offstr(map, coff, 2048);
	if(!fname) break;
	coff += strlen(fname) + 1;

	path = fmap_need_offstr(map, coff, 2048);
	if(!path) break;
	coff += strlen(path) + 1;

	version = fmap_need_offstr(map, coff, 2048);
	if(!version) break;
	coff += strlen(version) + 1;

	strsz = fmap_need_offstr(map, coff, 2048);
	if(!strsz) break;
	coff += strlen(strsz) + 1;

	data = &strsz[strlen(strsz) + 1];

	fsize = strtol(strsz, &eostr, 10);
	if(fsize < 0 || fsize == LONG_MAX ||
	   !*strsz || !eostr || eostr == strsz || *eostr ||
	   (unsigned long)fsize >= sz ||
	   (size_t)(data - fname) >= sz - fsize
	) break;

	cli_dbgmsg("ishield: @%lx found file %s (%s) - version %s - size %lu\n", (unsigned long int) coff, fname, path, version, (unsigned long int) fsize);
	if(cli_matchmeta(ctx, fname, fsize, fsize, 0, fc++, 0, NULL) == CL_VIRUS) {
            if (!SCAN_ALLMATCHES) {
                ret = CL_VIRUS;
                break;
            }
            ret = CL_CLEAN;
            virus_found = 1;
	}
	sz -= (data - fname) + fsize;

	if(!strncasecmp(fname, "data", 4)) {
	    long cabno;
	    if(!strcasecmp(fname + 4, "1.hdr")) {
		if(c.hdr == -1) {
		    cli_dbgmsg("ishield: added data1.hdr to array\n");
		    c.hdr = coff;
		    c.hdrsz = fsize;
		    coff += fsize;
		    continue;
		}
		cli_warnmsg("ishield: got multiple header files\n");
	    }
	    cabno = strtol(fname + 4, &eostr, 10);
	    if(cabno > 0 && cabno < 65536 && fname[4] && eostr && eostr != &fname[4] && !strcasecmp(eostr, ".cab")) {
		unsigned int i;
		for(i=0; i<c.cabcnt && i!=c.cabs[i].cabno; i++) { }
		if(i==c.cabcnt) {
		    c.cabcnt++;
		    if(!(c.cabs = cli_realloc2(c.cabs, sizeof(struct CABARRAY) * c.cabcnt))) {
			ret = CL_EMEM;
			break;
		    }
		    cli_dbgmsg("ishield: added data%lu.cab to array\n", cabno);
		    c.cabs[i].cabno = cabno;
		    c.cabs[i].off = coff;
		    c.cabs[i].sz = fsize;
		    coff += fsize;
		    continue;
		}
		cli_warnmsg("ishield: got multiple data%lu.cab files\n", cabno);
	    }
	}

	fmap_unneed_ptr(map, fname, data-fname);
	ret = is_dump_and_scan(ctx, coff, fsize);
	coff += fsize;
    }

    if(ret == CL_CLEAN && (c.cabcnt || c.hdr != -1)) {
      if((ret = is_parse_hdr(ctx, &c)) == CL_CLEAN) {
	    unsigned int i;
	    if(c.hdr != -1) {
		cli_dbgmsg("ishield: scanning data1.hdr\n");
		ret = is_dump_and_scan(ctx, c.hdr, c.hdrsz);
	    }
	    for(i=0; i<c.cabcnt && ret == CL_CLEAN; i++) {
		cli_dbgmsg("ishield: scanning data%u.cab\n", c.cabs[i].cabno);
		ret = is_dump_and_scan(ctx, c.cabs[i].off, c.cabs[i].sz);
	    }
      } else if( ret == CL_BREAK ) ret = CL_CLEAN;
    }
    if(c.cabs) free(c.cabs);

    if (virus_found != 0)
        return CL_VIRUS;
    return ret;
}


/* Utility func to scan a fd @ a given offset and size */
static int is_dump_and_scan(cli_ctx *ctx, off_t off, size_t fsize) {
    char *fname;
    const char *buf;
    int ofd, ret = CL_CLEAN;
    fmap_t *map = *ctx->fmap;

    if(!fsize) {
	cli_dbgmsg("ishield: skipping empty file\n");
	return CL_CLEAN;
    }
    if(!(fname = cli_gentemp(ctx->engine->tmpdir)))
	return CL_EMEM;

    if((ofd = open(fname, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRUSR|S_IWUSR)) < 0) {
	cli_errmsg("ishield: failed to create file %s\n", fname);
	free(fname);
	return CL_ECREAT;
    }
    while(fsize) {
	size_t rd = MIN(fsize, map->pgsz);
	if(!(buf = fmap_need_off_once(map, off, rd))) {
	    cli_dbgmsg("ishield: read error\n");
	    ret = CL_EREAD;
	    break;
	}
	if(cli_writen(ofd, buf, rd) <= 0) {
	    ret = CL_EWRITE;
	    break;
	}
	fsize -= rd;
	off += rd;
    }
    if(!fsize) {
	cli_dbgmsg("ishield: extracted to %s\n", fname);
	if (lseek(ofd, 0, SEEK_SET) == -1) {
        cli_dbgmsg("ishield: call to lseek() failed\n");
        ret = CL_ESEEK;
    }
	ret = cli_magic_scandesc(ofd, fname, ctx);
    }
    close(ofd);
    if(!ctx->engine->keeptmp)
	if(cli_unlink(fname)) ret = CL_EUNLINK;
    free(fname);
    return ret;
}

/* Process data1.hdr and extracts all the available files from dataX.cab */
static int is_parse_hdr(cli_ctx *ctx, struct IS_CABSTUFF *c) { 
    uint32_t h1_data_off, objs_files_cnt, objs_dirs_off;
    unsigned int off, i, scanned = 0;
    int ret = CL_BREAK;
    char hash[33], *hdr;
    fmap_t *map = *ctx->fmap;

    const struct IS_HDR *h1;
    struct IS_OBJECTS *objs;
    /* struct IS_INSTTYPEHDR *typehdr; -- UNUSED */

    if(!c->hdr || !c->hdrsz || !c->cabcnt) {
	cli_dbgmsg("is_parse_hdr: inconsistent hdr, maybe a false match\n");
	return CL_CLEAN;
    }

    if(!(h1 = fmap_need_off(map, c->hdr, c->hdrsz))) {
	cli_dbgmsg("is_parse_hdr: not enough room for H1\n");
	return CL_CLEAN;
    }
    hdr = (char *)h1;
    h1_data_off = le32_to_host(h1->data_off);
    objs = (struct IS_OBJECTS *)fmap_need_ptr(map, hdr + h1_data_off, sizeof(*objs));
    if(!objs) {
        cli_dbgmsg("is_parse_hdr: not enough room for OBJECTS\n");
        return CL_CLEAN;
    }

    cli_dbgmsg("is_parse_hdr: magic %x, unk1 %x, unk2 %x, data_off %x, data_sz %x\n",
               h1->magic, h1->unk1, h1->unk2, h1_data_off, h1->data_sz);
    if(le32_to_host(h1->magic) != 0x28635349) {
        cli_dbgmsg("is_parse_hdr: bad magic. wrong version?\n");
        return CL_CLEAN;
    }

    fmap_unneed_ptr(map, h1, sizeof(*h1));

/*     cli_errmsg("COMPONENTS\n"); */
/*     off = le32_to_host(objs->comps_off) + h1_data_off; */
/*     for(i=1;  ; i++) { */
/* 	struct IS_COMPONENT *cmp = (struct IS_COMPONENT *)(hdr + off); */
/* 	if(!CLI_ISCONTAINED(hdr, c->hdrsz, ((char *)cmp), sizeof(*cmp))) { */
/* 	    cli_dbgmsg("is_extract: not enough room for COMPONENT\n"); */
/* 	    free(hdr); */
/* 	    return CL_CLEAN; */
/* 	} */
/* 	cli_errmsg("%06u\t%s\n", i, &hdr[le32_to_host(cmp->str_name_off) + h1_data_off]); */
/* 	spam_strarray(hdr, h1_data_off + cmp->sub_comp_offs_array, h1_data_off, cmp->sub_comp_cnt); */
/* 	if(!cmp->next_comp_off) break; */
/* 	off = le32_to_host(cmp->next_comp_off) + h1_data_off; */
/*     } */

/*     cli_errmsg("DIRECTORIES (%u)", le32_to_host(objs->dirs_cnt)); */
    objs_dirs_off = le32_to_host(objs->dirs_off);
/*     spam_strarray(hdr, h1_data_off + objs_dirs_off, h1_data_off + objs_dirs_off, objs->dirs_cnt); */

/*     typehdr = (struct INSTTYPEHDR *)&hdr[h1_data_off + le32_to_host(objs->insttype_off)]; */
/*     printf("INSTTYPES (unk1: %d)\n-----------\n", typehdr->unk1); */
/*     off = typehdr->off + h1_data_off; */
/*     for(i=1; i<=typehdr->cnt; i++) { */
/* 	uint32_t x = *(uint32_t *)(&hdr[off]); */
/* 	struct INSTTYPEITEM *item = (struct INSTTYPEITEM *)&hdr[x + h1_data_off]; */
/* 	printf("%06u\t%s\t aka %s\taka %s\n", i, &hdr[item->str_name1_off + h1_data_off], &hdr[item->str_name2_off + h1_data_off], &hdr[item->str_name3_off + h1_data_off]); */
/* 	printf("components:\n"); */
/* 	spam_strarray(hdr, h1_data_off + item->off, h1_data_off, item->cnt); */
/* 	off+=4; */
/*     } */


/* dir = &hdr[*(uint32_t *)(&hdr[h1_data_off + objs_dirs_off + 4 * file->dir_id]) + h1_data_off + objs_dirs_off] */

    objs_files_cnt = le32_to_host(objs->files_cnt);
    off = h1_data_off + objs_dirs_off + le32_to_host(objs->dir_sz2);
    fmap_unneed_ptr(map, objs, sizeof(*objs));
    for(i=0; i<objs_files_cnt ;i++) {
	struct IS_FILEITEM *file = (struct IS_FILEITEM *)fmap_need_off(map, c->hdr + off, sizeof(*file));

	if(file) {
	    const char *emptyname = "", *dir_name = emptyname, *file_name = emptyname;
	    uint32_t dir_rel = h1_data_off + objs_dirs_off + 4 * le32_to_host(file->dir_id); /* rel off of dir entry from array of rel ptrs */
	    uint32_t file_rel = objs_dirs_off + h1_data_off + le32_to_host(file->str_name_off); /* rel off of fname */
	    uint64_t file_stream_off, file_size, file_csize;
	    uint16_t cabno;

	    memcpy(hash, file->md5, 16);
	    md5str((uint8_t *)hash);
	    if(fmap_need_ptr_once(map, &hdr[dir_rel], 4)) {
		dir_rel = cli_readint32(&hdr[dir_rel]) + h1_data_off + objs_dirs_off;
		if(fmap_need_str(map, &hdr[dir_rel], c->hdrsz - dir_rel))
		    dir_name = &hdr[dir_rel];
	    }
	    if(fmap_need_str(map, &hdr[file_rel], c->hdrsz - file_rel))
		file_name = &hdr[file_rel];
		
	    file_stream_off = le64_to_host(file->stream_off);
	    file_size = le64_to_host(file->size);
	    file_csize = le64_to_host(file->csize);
	    cabno = le16_to_host(file->datafile_id);

	    switch(le16_to_host(file->flags)) {
	    case 0:
		/* FIXMEISHIELD: for FS scan ? */
		cli_dbgmsg("is_parse_hdr: skipped external file:%s\\%s (size: %llu csize: %llu md5:%s)\n",
			   dir_name,
			   file_name,
			   (long long)file_size, (long long)file_csize, hash);
		break;
	    case 4:
		cli_dbgmsg("is_parse_hdr: file %s\\%s (size: %llu csize: %llu md5:%s offset:%llx (data%u.cab) 13:%x 14:%x 15:%x)\n",
			   dir_name,
			   file_name,
			   (long long)file_size, (long long)file_csize, hash, (long long)file_stream_off,
			   cabno, file->unk13,  file->unk14,  file->unk15);
		if(file->flag_has_dup & 1)
		    cli_dbgmsg("is_parse_hdr: not scanned (dup)\n");
		else {
		    if(file_size) {
			unsigned int j;
			int cabret = CL_CLEAN;

			if(ctx->engine->maxfilesize && file_csize > ctx->engine->maxfilesize) {
			    cli_dbgmsg("is_parse_hdr: skipping file due to size limits (%lu vs %lu)\n", (unsigned long int) file_csize, (unsigned long int) ctx->engine->maxfilesize);
			    break;
			}

			for(j=0; j<c->cabcnt && c->cabs[j].cabno != cabno; j++) {}
			if(j != c->cabcnt) {
 			    if(CLI_ISCONTAINED(c->cabs[j].off, c->cabs[j].sz, file_stream_off + c->cabs[j].off, file_csize)) {
				scanned++;
				if (ctx->engine->maxfiles && scanned >= ctx->engine->maxfiles) {
				    cli_dbgmsg("is_parse_hdr: File limit reached (max: %u)\n", ctx->engine->maxfiles);
				    if(file_name != emptyname)
					fmap_unneed_ptr(map, (void *)file_name, strlen(file_name)+1);
				    if(dir_name != emptyname)
					fmap_unneed_ptr(map, (void *)dir_name, strlen(dir_name)+1);
				    return CL_EMAXFILES;
				}
				cabret = is_extract_cab(ctx, file_stream_off + c->cabs[j].off, file_size, file_csize);
			    } else {
				ret = CL_CLEAN;
 				cli_dbgmsg("is_parse_hdr: stream out of file\n");
			    }
			} else {
			    ret = CL_CLEAN;
			    cli_dbgmsg("is_parse_hdr: data%u.cab not available\n", cabno);
			}
			if(cabret == CL_BREAK) {
			    ret = CL_CLEAN;
			    cabret = CL_CLEAN;
			}
			if(cabret != CL_CLEAN) {
			    if(file_name != emptyname)
				fmap_unneed_ptr(map, (void *)file_name, strlen(file_name)+1);
			    if(dir_name != emptyname)
				fmap_unneed_ptr(map, (void *)dir_name, strlen(dir_name)+1);
			    return cabret;
			}
		    } else {
			cli_dbgmsg("is_parse_hdr: skipped empty file\n");
		    }
		}
		break;
	    default:
		cli_dbgmsg("is_parse_hdr: skipped unknown file entry %u\n", i);
	    }
	    if(file_name != emptyname)
		fmap_unneed_ptr(map, (void *)file_name, strlen(file_name)+1);
	    if(dir_name != emptyname)
		fmap_unneed_ptr(map, (void *)dir_name, strlen(dir_name)+1);
	    fmap_unneed_ptr(map, file, sizeof(*file));
	} else {
	    ret = CL_CLEAN;
	    cli_dbgmsg("is_parse_hdr: FILEITEM out of bounds\n");
	}
	off += sizeof(*file);
    }
    return ret;
}


static void md5str(uint8_t *sum) {
    int i;
    for(i=15; i>=0; i--) {
	uint8_t lo = (sum[i] & 0xf), hi = (sum[i] >> 4);
	lo += '0' + (lo > 9) * '\'';
	hi += '0' + (hi > 9) * '\'';
	sum[i*2+1] = lo;
	sum[i*2] = hi;
    }
    sum[32] = '\0';
}


#define IS_CABBUFSZ 65536

static int is_extract_cab(cli_ctx *ctx, uint64_t off, uint64_t size, uint64_t csize) {
    const uint8_t *inbuf;
    uint8_t *outbuf;
    char *tempfile;
    int ofd, ret = CL_CLEAN;
    z_stream z;
    uint64_t outsz = 0;
    int success = 0;
    fmap_t *map = *ctx->fmap;

    if(!(outbuf = cli_malloc(IS_CABBUFSZ))) {
        cli_errmsg("is_extract_cab: Unable to allocate memory for outbuf\n");
        return CL_EMEM;
    }

    if(!(tempfile = cli_gentemp(ctx->engine->tmpdir))) {
	free(outbuf);
	return CL_EMEM;
    }
    if((ofd = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRUSR|S_IWUSR)) < 0) {
	cli_errmsg("is_extract_cab: failed to create file %s\n", tempfile);
	free(tempfile);
	free(outbuf);
	return CL_ECREAT;
    }

    while(csize) {
	uint16_t chunksz;
	success = 0;
	if(csize<2) {
	    cli_dbgmsg("is_extract_cab: no room for chunk size\n");
	    break;
	}
	csize -= 2;
	if(!(inbuf = fmap_need_off_once(map, off, 2))) {
	    cli_dbgmsg("is_extract_cab: short read for chunk size\n");
	    break;
	}
	off += 2;
	chunksz = inbuf[0] | (inbuf[1] << 8);
	if(!chunksz) {
	    cli_dbgmsg("is_extract_cab: zero sized chunk\n");
	    continue;
	}
	if(csize < chunksz) {
	    cli_dbgmsg("is_extract_cab: chunk is bigger than csize\n");
	    break;
	}
	csize -= chunksz;
	if(!(inbuf = fmap_need_off_once(map, off, chunksz))) {
	    cli_dbgmsg("is_extract_cab: short read for chunk\n");
	    break;
	}
	off += chunksz;
	memset(&z, 0, sizeof(z));
	inflateInit2(&z, -MAX_WBITS);
	z.next_in = (uint8_t *)inbuf;
	z.avail_in = chunksz;
	while(1) {
	    int zret;
	    z.next_out = outbuf;
	    z.avail_out = IS_CABBUFSZ;
	    zret = inflate(&z, 0);
	    if(zret == Z_OK || zret == Z_STREAM_END || zret == Z_BUF_ERROR) {
		unsigned int umpd = IS_CABBUFSZ - z.avail_out;
		if(cli_writen(ofd, outbuf, umpd) < (ssize_t)umpd)
		    break;
		outsz += umpd;
		if(zret == Z_STREAM_END || z.avail_out == IS_CABBUFSZ /* FIXMEISHIELD: is the latter ok? */) {
		    success = 1;
		    break;
		}
		if(ctx->engine->maxfilesize && z.total_out > ctx->engine->maxfilesize) {
		    cli_dbgmsg("ishield_extract_cab: trimming output file due to size limits (%lu vs %lu)\n", z.total_out, (unsigned long int) ctx->engine->maxfilesize);
		    success = 1;
		    outsz = size;
		    break;
		}
		continue;
	    }
	    cli_dbgmsg("is_extract_cab: file decompression failed with %d\n", zret);
	    break;
	}
	inflateEnd(&z);
	if(!success) break;
    }
    free(outbuf);
    if(success) {
	if (outsz != size)
	    cli_dbgmsg("is_extract_cab: extracted %llu bytes to %s, expected %llu, scanning anyway.\n", (long long)outsz, tempfile, (long long)size);
	else
	    cli_dbgmsg("is_extract_cab: extracted to %s\n", tempfile);
	if (lseek(ofd, 0, SEEK_SET) == -1)
        cli_dbgmsg("is_extract_cab: call to lseek() failed\n");
	ret = cli_magic_scandesc(ofd, tempfile, ctx);
    }

    close(ofd);
    if(!ctx->engine->keeptmp)
	if(cli_unlink(tempfile)) ret = CL_EUNLINK;
    free(tempfile);
    return success ? ret : CL_BREAK;
}
