/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Trog
 *
 *  Summary: Extract component parts of OLE2 files (e.g. MS Office Documents).
 *
 *  Acknowledgements: Some ideas and algorithms were based upon OpenOffice and libgsf.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <conv.h>
#include <zlib.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "clamav.h"
#include "others.h"
#include "hwp.h"
#include "ole2_extract.h"
#include "scanners.h"
#include "fmap.h"
#include "json_api.h"
#if HAVE_JSON
#include "msdoc.h"
#endif

#ifdef DEBUG_OLE2_LIST
#define ole2_listmsg(...) cli_dbgmsg( __VA_ARGS__)
#else
#define ole2_listmsg(...) ;
#endif

#define ole2_endian_convert_16(v) le16_to_host((uint16_t)(v))
#define ole2_endian_convert_32(v) le32_to_host((uint32_t)(v))

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif

#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

typedef struct ole2_header_tag {
    unsigned char   magic[8];   /* should be: 0xd0cf11e0a1b11ae1 */
    unsigned char   clsid[16];
    uint16_t minor_version __attribute__((packed));
    uint16_t dll_version __attribute__((packed));
    int16_t byte_order __attribute__((packed)); /* -2=intel */

    uint16_t log2_big_block_size __attribute__((packed));       /* usually 9 (2^9 = 512) */
    uint32_t log2_small_block_size __attribute__((packed));     /* usually 6 (2^6 = 64) */

    int32_t         reserved[2] __attribute__((packed));
    int32_t bat_count __attribute__((packed));
    int32_t prop_start __attribute__((packed));

    uint32_t signature __attribute__((packed));
    uint32_t sbat_cutoff __attribute__((packed));       /* cutoff for files held
                                                         * in small blocks
                                                         * (4096) */

    int32_t sbat_start __attribute__((packed));
    int32_t sbat_block_count __attribute__((packed));
    int32_t xbat_start __attribute__((packed));
    int32_t xbat_count __attribute__((packed));
    int32_t         bat_array[109] __attribute__((packed));

    /* not part of the ole2 header, but stuff we need in order to decode */

    /*
     * must take account of the size of variables below here when reading the
     * header
     */
    int32_t sbat_root_start __attribute__((packed));
    uint32_t        max_block_no;
    off_t           m_length;
    bitset_t       *bitset;
    struct uniq    *U;
    fmap_t         *map;
    int             has_vba;
    hwp5_header_t  *is_hwp;
}               ole2_header_t;

typedef struct property_tag {
    char            name[64];   /* in unicode */
    uint16_t name_size __attribute__((packed));
    unsigned char   type;       /* 1=dir 2=file 5=root */
    unsigned char   color;      /* black or red */
    uint32_t prev   __attribute__((packed));
    uint32_t next   __attribute__((packed));
    uint32_t child  __attribute__((packed));

    unsigned char   clsid[16];
    uint32_t user_flags __attribute__((packed));

    uint32_t create_lowdate __attribute__((packed));
    uint32_t create_highdate __attribute__((packed));
    uint32_t mod_lowdate __attribute__((packed));
    uint32_t mod_highdate __attribute__((packed));
    uint32_t start_block __attribute__((packed));
    uint32_t size   __attribute__((packed));
    unsigned char   reserved[4];
}               property_t;

struct ole2_list_node;

typedef struct ole2_list_node
{
  uint32_t Val;
  struct ole2_list_node *Next;
} ole2_list_node_t;

typedef struct ole2_list
{
  uint32_t Size;
  ole2_list_node_t *Head;
} ole2_list_t;

int ole2_list_init(ole2_list_t * list);
int ole2_list_is_empty(ole2_list_t * list);
uint32_t ole2_list_size(ole2_list_t * list);
int ole2_list_push(ole2_list_t * list, uint32_t val);
uint32_t ole2_list_pop(ole2_list_t * list);
int ole2_list_delete(ole2_list_t * list);

int
ole2_list_init(ole2_list_t * list)
{
    list->Head = NULL;
    list->Size = 0;
    return CL_SUCCESS;
}

int
ole2_list_is_empty(ole2_list_t * list)
{
    return (list->Head == NULL);
}

uint32_t
ole2_list_size(ole2_list_t * list)
{
    return (list->Size);
}

int
ole2_list_push(ole2_list_t * list, uint32_t val)
{
    //check the cli - malloc ?
    ole2_list_node_t * new_node;

    new_node = (ole2_list_node_t *) cli_malloc(sizeof(ole2_list_node_t));
    if (!new_node) {
        cli_dbgmsg("OLE2: could not allocate new node for worklist!\n");
        return CL_EMEM;
    }
    new_node->Val = val;
    new_node->Next = list->Head;

    list->Head = new_node;
    (list->Size)++;
    return CL_SUCCESS;
}

uint32_t
ole2_list_pop(ole2_list_t * list)
{
    uint32_t        val;
    ole2_list_node_t *next;

    if (ole2_list_is_empty(list)) {
        cli_dbgmsg("OLE2: work list is empty and ole2_list_pop() called!\n");
        return -1;
    }
    val = list->Head->Val;
    next = list->Head->Next;

    free(list->Head);
    list->Head = next;

    (list->Size)--;
    return val;
}

int
ole2_list_delete(ole2_list_t * list)
{
    while (!ole2_list_is_empty(list))
        ole2_list_pop(list);
    return CL_SUCCESS;
}

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

static unsigned char magic_id[] = {0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1};


static char    *
get_property_name2(char *name, int size)
{
    int             i, j;
    char           *newname;

    if (*name == 0 || size <= 0 || size > 128) {
        return NULL;
    }
    newname = (char *)cli_malloc(size * 7);
    if (!newname) {
        cli_errmsg("OLE2 [get_property_name2]: Unable to allocate memory for newname: %u\n", size * 7);
        return NULL;
    }
    j = 0;
    /* size-2 to ignore trailing NULL */
    for (i = 0; i < size - 2; i += 2) {
        if ((!(name[i] & 0x80)) && isprint(name[i])) {
            newname[j++] = tolower(name[i]);
        } else {
            if (name[i] < 10 && name[i] >= 0) {
                newname[j++] = '_';
                newname[j++] = name[i] + '0';
            } else {
                const uint16_t  x = (((uint16_t) name[i]) << 8) | name[i + 1];

                newname[j++] = '_';
                newname[j++] = 'a' + ((x & 0xF));
                newname[j++] = 'a' + ((x >> 4) & 0xF);
                newname[j++] = 'a' + ((x >> 8) & 0xF);
                newname[j++] = 'a' + ((x >> 16) & 0xF);
                newname[j++] = 'a' + ((x >> 24) & 0xF);
            }
            newname[j++] = '_';
        }
    }
    newname[j] = '\0';
    if (strlen(newname) == 0) {
        free(newname);
        return NULL;
    }
    return newname;
}

static char    *
get_property_name(char *name, int size)
{
    const char     *carray = "0123456789abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz._";
    int             csize = size >> 1;
    char           *newname, *cname;
    char           *oname = name;

    if (csize <= 0)
        return NULL;

    newname = cname = (char *)cli_malloc(size);
    if (!newname) {
        cli_errmsg("OLE2 [get_property_name]: Unable to allocate memory for newname %u\n", size);
        return NULL;
    }
    while (--csize) {
        uint16_t        lo, hi, u = cli_readint16(oname) - 0x3800;

        oname += 2;
        if (u > 0x1040) {
            free(newname);
            return get_property_name2(name, size);
        }
        lo = u % 64;
        u >>= 6;
        hi = u % 64;
        *cname++ = carray[lo];
        if (csize != 1 || u != 64)
            *cname++ = carray[hi];
    }
    *cname = '\0';
    return newname;
}


static void
print_ole2_property(property_t * property)
{
    char            spam[128], *buf;

    if (property->name_size > 64) {
        cli_dbgmsg("[err name len: %d]\n", property->name_size);
        return;
    }
    buf = get_property_name(property->name, property->name_size);
    snprintf(spam, sizeof(spam), "OLE2: %s ", buf ? buf : "<noname>");
    spam[sizeof(spam) - 1] = '\0';
    if (buf)
        free(buf);
    switch (property->type) {
    case 2:
        strncat(spam, " [file] ", sizeof(spam) - 1 - strlen(spam));
        break;
    case 1:
        strncat(spam, " [dir ] ", sizeof(spam) - 1 - strlen(spam));
        break;
    case 5:
        strncat(spam, " [root] ", sizeof(spam) - 1 - strlen(spam));
        break;
    default:
        strncat(spam, " [unkn] ", sizeof(spam) - 1 - strlen(spam));
    }
    spam[sizeof(spam) - 1] = '\0';
    switch (property->color) {
    case 0:
        strncat(spam, " r  ", sizeof(spam) - 1 - strlen(spam));
        break;
    case 1:
        strncat(spam, " b  ", sizeof(spam) - 1 - strlen(spam));
        break;
    default:
        strncat(spam, " u  ", sizeof(spam) - 1 - strlen(spam));
    }
    spam[sizeof(spam) - 1] = '\0';
    cli_dbgmsg("%s size:0x%.8x flags:0x%.8x\n", spam, property->size, property->user_flags);
}

static void
print_ole2_header(ole2_header_t * hdr)
{
    if (!hdr || !cli_debug_flag) {
        return;
    }
    cli_dbgmsg("\n");
    cli_dbgmsg("Magic:\t\t\t0x%x%x%x%x%x%x%x%x\n",
               hdr->magic[0], hdr->magic[1], hdr->magic[2], hdr->magic[3],
               hdr->magic[4], hdr->magic[5], hdr->magic[6], hdr->magic[7]);

    cli_dbgmsg("CLSID:\t\t\t{%x%x%x%x-%x%x-%x%x-%x%x-%x%x%x%x%x%x}\n",
               hdr->clsid[0],  hdr->clsid[1],  hdr->clsid[2],  hdr->clsid[3],
               hdr->clsid[4],  hdr->clsid[5],  hdr->clsid[6],  hdr->clsid[7],
               hdr->clsid[8],  hdr->clsid[9],  hdr->clsid[10], hdr->clsid[11],
               hdr->clsid[12], hdr->clsid[13], hdr->clsid[14], hdr->clsid[15]);

    cli_dbgmsg("Minor version:\t\t0x%x\n", hdr->minor_version);
    cli_dbgmsg("DLL version:\t\t0x%x\n", hdr->dll_version);
    cli_dbgmsg("Byte Order:\t\t%d\n", hdr->byte_order);
    cli_dbgmsg("Big Block Size:\t%i\n", hdr->log2_big_block_size);
    cli_dbgmsg("Small Block Size:\t%i\n", hdr->log2_small_block_size);
    cli_dbgmsg("BAT count:\t\t%d\n", hdr->bat_count);
    cli_dbgmsg("Prop start:\t\t%d\n", hdr->prop_start);
    cli_dbgmsg("SBAT cutoff:\t\t%d\n", hdr->sbat_cutoff);
    cli_dbgmsg("SBat start:\t\t%d\n", hdr->sbat_start);
    cli_dbgmsg("SBat block count:\t%d\n", hdr->sbat_block_count);
    cli_dbgmsg("XBat start:\t\t%d\n", hdr->xbat_start);
    cli_dbgmsg("XBat block count:\t%d\n", hdr->xbat_count);
    cli_dbgmsg("\n");
    return;
}

static int
ole2_read_block(ole2_header_t * hdr, void *buff, unsigned int size, int32_t blockno)
{
    off_t           offset, offend;
    const void     *pblock;

    if (blockno < 0) {
        return FALSE;
    }
    /* other methods: (blockno+1) * 512 or (blockno * block_size) + 512; */
    if ((uint64_t) blockno << hdr->log2_big_block_size < INT32_MAX) {
    offset = (blockno << hdr->log2_big_block_size) + MAX(512, 1 << hdr->log2_big_block_size);   /* 512 is header size */
    offend = offset + size;
    } else {
        offset = INT32_MAX - size;
        offend = INT32_MAX;
    }

    if ((offend <= 0) || (offset < 0) || (offset >= hdr->m_length)) {
        return FALSE;
    } else if (offend > hdr->m_length) {
        /* bb#11369 - ole2 files may not be a block multiple in size */
        memset(buff, 0, size);
        size = hdr->m_length - offset;
    }
    if (!(pblock = fmap_need_off_once(hdr->map, offset, size))) {
        return FALSE;
    }
    memcpy(buff, pblock, size);
    return TRUE;
}

static          int32_t
ole2_get_next_bat_block(ole2_header_t * hdr, int32_t current_block)
{
    int32_t         bat_array_index;
    uint32_t        bat[128];

    if (current_block < 0) {
        return -1;
    }
    bat_array_index = current_block / 128;
    if (bat_array_index > hdr->bat_count) {
        cli_dbgmsg("bat_array index error\n");
        return -10;
    }
    if (!ole2_read_block(hdr, &bat, 512,
                 ole2_endian_convert_32(hdr->bat_array[bat_array_index]))) {
        return -1;
    }
    return ole2_endian_convert_32(bat[current_block - (bat_array_index * 128)]);
}

static          int32_t
ole2_get_next_xbat_block(ole2_header_t * hdr, int32_t current_block)
{
    int32_t         xbat_index, xbat_block_index, bat_index, bat_blockno;
    uint32_t        xbat[128], bat[128];

    if (current_block < 0) {
        return -1;
    }
    xbat_index = current_block / 128;

    /*
     * NB:	The last entry in each XBAT points to the next XBAT block.
     * This reduces the number of entries in each block by 1.
     */
    xbat_block_index = (xbat_index - 109) / 127;
    bat_blockno = (xbat_index - 109) % 127;

    bat_index = current_block % 128;

    if (!ole2_read_block(hdr, &xbat, 512, hdr->xbat_start)) {
        return -1;
    }
    /* Follow the chain of XBAT blocks */
    while (xbat_block_index > 0) {
        if (!ole2_read_block(hdr, &xbat, 512,
                             ole2_endian_convert_32(xbat[127]))) {
            return -1;
        }
        xbat_block_index--;
    }

    if (!ole2_read_block(hdr, &bat, 512, ole2_endian_convert_32(xbat[bat_blockno]))) {
        return -1;
    }
    return ole2_endian_convert_32(bat[bat_index]);
}

static          int32_t
ole2_get_next_block_number(ole2_header_t * hdr, int32_t current_block)
{
    if (current_block < 0) {
        return -1;
    }
    if ((current_block / 128) > 108) {
        return ole2_get_next_xbat_block(hdr, current_block);
    } else {
        return ole2_get_next_bat_block(hdr, current_block);
    }
}

static          int32_t
ole2_get_next_sbat_block(ole2_header_t * hdr, int32_t current_block)
{
    int32_t         iter, current_bat_block;
    uint32_t        sbat[128];

    if (current_block < 0) {
        return -1;
    }
    current_bat_block = hdr->sbat_start;
    iter = current_block / 128;
    while (iter > 0) {
        current_bat_block = ole2_get_next_block_number(hdr, current_bat_block);
        iter--;
    }
    if (!ole2_read_block(hdr, &sbat, 512, current_bat_block)) {
        return -1;
    }
    return ole2_endian_convert_32(sbat[current_block % 128]);
}

/* Retrieve the block containing the data for the given sbat index */
static          int32_t
ole2_get_sbat_data_block(ole2_header_t * hdr, void *buff, int32_t sbat_index)
{
    int32_t         block_count, current_block;

    if (sbat_index < 0) {
        return FALSE;
    }
    if (hdr->sbat_root_start < 0) {
        cli_dbgmsg("No root start block\n");
        return FALSE;
    }
    block_count = sbat_index / (1 << (hdr->log2_big_block_size - hdr->log2_small_block_size));
    current_block = hdr->sbat_root_start;
    while (block_count > 0) {
        current_block = ole2_get_next_block_number(hdr, current_block);
        block_count--;
    }

    /*
     * current_block now contains the block number of the sbat array
     * containing the entry for the required small block
     */

    return (ole2_read_block(hdr, buff, 1 << hdr->log2_big_block_size, current_block));
}

static int
ole2_walk_property_tree(ole2_header_t * hdr, const char *dir, int32_t prop_index,
                        int (*handler) (ole2_header_t * hdr, property_t * prop, const char *dir, cli_ctx * ctx),
                        unsigned int rec_level, unsigned int *file_count, cli_ctx * ctx, unsigned long *scansize)
{
    property_t      prop_block[4];
    int32_t         idx, current_block, i, curindex;
    char            *dirname;
    ole2_list_t     node_list;
    int             ret, func_ret;
#if HAVE_JSON
    char *name;
    int toval = 0;
#endif

    ole2_listmsg("ole2_walk_property_tree() called\n");
    func_ret = CL_SUCCESS;
    ole2_list_init(&node_list);

    ole2_listmsg("rec_level: %d\n", rec_level);
    ole2_listmsg("file_count: %d\n", *file_count);

    if ((rec_level > 100) || (*file_count > 100000)) {
        return CL_SUCCESS;
    }
    if (ctx && ctx->engine->maxreclevel && (rec_level > ctx->engine->maxreclevel)) {
        cli_dbgmsg("OLE2: Recursion limit reached (max: %d)\n", ctx->engine->maxreclevel);
        return CL_SUCCESS;
    }
    //push the 'root' node for the level onto the local list
    if ((ret=ole2_list_push(&node_list, prop_index)) != CL_SUCCESS) {
        ole2_list_delete(&node_list);
        return ret;
    }

    while (!ole2_list_is_empty(&node_list)) {
        ole2_listmsg("within working loop, worklist size: %d\n", ole2_list_size(&node_list));
#if HAVE_JSON
        if (cli_json_timeout_cycle_check(ctx, &toval) != CL_SUCCESS) {
            ole2_list_delete(&node_list);
            return CL_ETIMEOUT;
        }
#endif

        current_block = hdr->prop_start;

        //pop off a node to work on
        curindex = ole2_list_pop(&node_list);
        ole2_listmsg("current index: %d\n", curindex);
        if ((curindex < 0) || (curindex > (int32_t) hdr->max_block_no)) {
            continue;
        }
        //read in the sector referenced by the current index
        idx = curindex / 4;
        for (i = 0; i < idx; i++) {
            current_block = ole2_get_next_block_number(hdr, current_block);
            if (current_block < 0) {
                continue;
            }
        }
        idx = curindex % 4;
        if (!ole2_read_block(hdr, prop_block, 512, current_block)) {
            continue;
        }
        if (prop_block[idx].type <= 0) {
            continue;
        }
        ole2_listmsg("reading prop block\n");

        prop_block[idx].name_size = ole2_endian_convert_16(prop_block[idx].name_size);
        prop_block[idx].prev = ole2_endian_convert_32(prop_block[idx].prev);
        prop_block[idx].next = ole2_endian_convert_32(prop_block[idx].next);
        prop_block[idx].child = ole2_endian_convert_32(prop_block[idx].child);
        prop_block[idx].user_flags = ole2_endian_convert_32(prop_block[idx].user_flags);
        prop_block[idx].create_lowdate = ole2_endian_convert_32(prop_block[idx].create_lowdate);
        prop_block[idx].create_highdate = ole2_endian_convert_32(prop_block[idx].create_highdate);
        prop_block[idx].mod_lowdate = ole2_endian_convert_32(prop_block[idx].mod_lowdate);
        prop_block[idx].mod_highdate = ole2_endian_convert_32(prop_block[idx].mod_highdate);
        prop_block[idx].start_block = ole2_endian_convert_32(prop_block[idx].start_block);
        prop_block[idx].size = ole2_endian_convert_32(prop_block[idx].size);

        ole2_listmsg("printing ole2 property\n");
        if (dir)
            print_ole2_property(&prop_block[idx]);

        ole2_listmsg("checking bitset\n");
        /* Check we aren't in a loop */
        if (cli_bitset_test(hdr->bitset, (unsigned long)curindex)) {
            /* Loop in property tree detected */
            cli_dbgmsg("OLE2: Property tree loop detected at index %d\n", curindex);
            ole2_list_delete(&node_list);
            return CL_BREAK;
        }
        ole2_listmsg("setting bitset\n");
        if (!cli_bitset_set(hdr->bitset, (unsigned long)curindex)) {
            continue;
        }
        ole2_listmsg("prev: %d next %d child %d\n", prop_block[idx].prev, prop_block[idx].next, prop_block[idx].child);

        ole2_listmsg("node type: %d\n", prop_block[idx].type);
        switch (prop_block[idx].type) {
        case 5:                /* Root Entry */
            ole2_listmsg("root node\n");
            if ((curindex != 0) || (rec_level != 0) ||
                    (*file_count != 0)) {
                /* Can only have RootEntry as the top */
                cli_dbgmsg("ERROR: illegal Root Entry\n");
                continue;
            }
            hdr->sbat_root_start = prop_block[idx].start_block;
            if ((int)(prop_block[idx].child) != -1) {
                ret = ole2_walk_property_tree(hdr, dir, prop_block[idx].child, handler, rec_level + 1, file_count, ctx, scansize);
                if (ret != CL_SUCCESS) {
                    if (SCAN_ALLMATCHES && (ret == CL_VIRUS)) {
                        func_ret = ret;
                    }
                    else {
                        ole2_list_delete(&node_list);
                        return ret;
                    }
                }
            }
            if ((int)(prop_block[idx].prev) != -1) {
	        if ((ret=ole2_list_push(&node_list, prop_block[idx].prev)) != CL_SUCCESS) {
		    ole2_list_delete(&node_list);
		    return ret;
		}
	    }
	    if ((int)(prop_block[idx].next) != -1) {
	        if ((ret=ole2_list_push(&node_list, prop_block[idx].next)) != CL_SUCCESS) {
		    ole2_list_delete(&node_list);
		    return ret;
		}
	    }
            break;
        case 2:                /* File */
            ole2_listmsg("file node\n");
            if (ctx && ctx->engine->maxfiles && ctx->scannedfiles + *file_count > ctx->engine->maxfiles) {
                cli_dbgmsg("OLE2: files limit reached (max: %u)\n", ctx->engine->maxfiles);
                ole2_list_delete(&node_list);
                return CL_EMAXFILES;
            }
            if (!ctx || !(ctx->engine->maxfilesize) || prop_block[idx].size <= ctx->engine->maxfilesize || prop_block[idx].size <= *scansize) {
                (*file_count)++;
                *scansize -= prop_block[idx].size;
                ole2_listmsg("running file handler\n");
                ret = handler(hdr, &prop_block[idx], dir, ctx);
                if (ret != CL_SUCCESS) {
                    if (SCAN_ALLMATCHES && (ret == CL_VIRUS)) {
                        func_ret = ret;
                    }
                    else {
                        ole2_listmsg("file handler returned %d\n", ret);
                        ole2_list_delete(&node_list);
                        return ret;
                    }
                }
            } else {
                cli_dbgmsg("OLE2: filesize exceeded\n");
            }
            if ((int)(prop_block[idx].child) != -1) {
                ret = ole2_walk_property_tree(hdr, dir, prop_block[idx].child, handler, rec_level, file_count, ctx, scansize);
                if (ret != CL_SUCCESS) {
                    if (SCAN_ALLMATCHES && (ret == CL_VIRUS)) {
                        func_ret = ret;
                    }
                    else {
                        ole2_list_delete(&node_list);
                        return ret;
                    }
                }
            }
            if ((int)(prop_block[idx].prev) != -1) {
	        if ((ret=ole2_list_push(&node_list, prop_block[idx].prev)) != CL_SUCCESS) {
		    ole2_list_delete(&node_list);
		    return ret;
		}
            }
            if ((int)(prop_block[idx].next) != -1) {
                if ((ret=ole2_list_push(&node_list, prop_block[idx].next)) != CL_SUCCESS) {
		    ole2_list_delete(&node_list);
		    return ret;
		}
            }
            break;
        case 1:                /* Directory */
            ole2_listmsg("directory node\n");
            if (dir) {
#if HAVE_JSON
                if (SCAN_COLLECT_METADATA && (ctx->wrkproperty != NULL)) {
                    if (!json_object_object_get_ex(ctx->wrkproperty, "DigitalSignatures", NULL)) {
                        name = get_property_name2(prop_block[idx].name, prop_block[idx].name_size);
                        if (name) {
                            if (!strcmp(name, "_xmlsignatures") || !strcmp(name, "_signatures")) {
                                cli_jsonbool(ctx->wrkproperty, "HasDigitalSignatures", 1);
                            }
                            free(name);
                        }
                    }
                }
#endif
                dirname = (char *)cli_malloc(strlen(dir) + 8);
                if (!dirname) {
		    ole2_listmsg("OLE2: malloc failed for dirname\n");
                    ole2_list_delete(&node_list);
                    return CL_EMEM;
                }
                snprintf(dirname, strlen(dir) + 8, "%s" PATHSEP "%.6d", dir, curindex);
                if (mkdir(dirname, 0700) != 0) {
		    ole2_listmsg("OLE2: mkdir failed for directory %s\n", dirname);
                    free(dirname);
                    ole2_list_delete(&node_list);
                    return CL_BREAK;
                }
                cli_dbgmsg("OLE2 dir entry: %s\n", dirname);
            } else
                dirname = NULL;
            if ((int)(prop_block[idx].child) != -1) {
                ret = ole2_walk_property_tree(hdr, dirname, prop_block[idx].child, handler, rec_level + 1, file_count, ctx, scansize);
                if (ret != CL_SUCCESS) {
                    if (SCAN_ALLMATCHES && (ret == CL_VIRUS)) {
                        func_ret = ret;
                    }
                    else {
                        ole2_list_delete(&node_list);
                            if (dirname)
                                free(dirname);
                        return ret;
                    }
                }
            }
                if (dirname) {
                    free(dirname);
                    dirname = NULL;
                }
            if ((int)(prop_block[idx].prev) != -1) {
	        if ((ret=ole2_list_push(&node_list, prop_block[idx].prev)) != CL_SUCCESS) {
		    ole2_list_delete(&node_list);
		    return ret;
		}
            }
            if ((int)(prop_block[idx].next) != -1) {
                if ((ret=ole2_list_push(&node_list, prop_block[idx].next)) != CL_SUCCESS) {
		    ole2_list_delete(&node_list);
		    return ret;
		}
            }
            break;
        default:
            cli_dbgmsg("ERROR: unknown OLE2 entry type: %d\n", prop_block[idx].type);
            break;
        }
        ole2_listmsg("loop ended: %d %d\n", ole2_list_size(&node_list), ole2_list_is_empty(&node_list));
    }
    ole2_list_delete(&node_list);
    return func_ret;
}

/* Write file Handler - write the contents of the entry to a file */
static int
handler_writefile(ole2_header_t * hdr, property_t * prop, const char *dir, cli_ctx * ctx)
{
    unsigned char  *buff;
    int32_t         current_block, ofd, len, offset;
    char           *name, newname[1024];
    bitset_t       *blk_bitset;
    char           *hash;
    uint32_t        cnt;

    UNUSEDPARAM(ctx);

    if (prop->type != 2) {
        /* Not a file */
        return CL_SUCCESS;
    }
    if (prop->name_size > 64) {
        cli_dbgmsg("OLE2 [handler_writefile]: property name too long: %d\n", prop->name_size);
        return CL_SUCCESS;
    }
    name = get_property_name2(prop->name, prop->name_size);
    if (name) {
        if (CL_SUCCESS != uniq_add(hdr->U, name, strlen(name), &hash, &cnt)) {
            free(name);
            cli_dbgmsg("OLE2 [handler_writefile]: too many property names added to uniq store.\n");
            return CL_BREAK;
        }
    } else {
        if (CL_SUCCESS != uniq_add(hdr->U, NULL, 0, &hash, &cnt)) {
            cli_dbgmsg("OLE2 [handler_writefile]: too many property names added to uniq store.\n");
            return CL_BREAK;
        }
    }
    snprintf(newname, sizeof(newname), "%s" PATHSEP "%s_%u", dir, hash, cnt);
    newname[sizeof(newname) - 1] = '\0';
    cli_dbgmsg("OLE2 [handler_writefile]: Dumping '%s' to '%s'\n", name ? name : "<empty>", newname);
    if (name)
        free(name);

    ofd = open(newname, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, S_IRWXU);
    if (ofd < 0) {
        cli_errmsg("OLE2 [handler_writefile]: failed to create file: %s\n", newname);
        return CL_SUCCESS;
    }
    current_block = prop->start_block;
    len = prop->size;

    buff = (unsigned char *)cli_malloc(1 << hdr->log2_big_block_size);
    if (!buff) {
        cli_errmsg("OLE2 [handler_writefile]: Unable to allocate memory for buff: %u\n", 1 << hdr->log2_big_block_size);
        close(ofd);
        return CL_BREAK;
    }
    blk_bitset = cli_bitset_init();
    if (!blk_bitset) {
        cli_errmsg("OLE2 [handler_writefile]: init bitset failed\n");
        close(ofd);
        free(buff);
        return CL_BREAK;
    }
    while ((current_block >= 0) && (len > 0)) {
        if (current_block > (int32_t) hdr->max_block_no) {
            cli_dbgmsg("OLE2 [handler_writefile]: Max block number for file size exceeded: %d\n", current_block);
            close(ofd);
            free(buff);
            cli_bitset_free(blk_bitset);
            return CL_SUCCESS;
        }
        /* Check we aren't in a loop */
        if (cli_bitset_test(blk_bitset, (unsigned long)current_block)) {
            /* Loop in block list */
            cli_dbgmsg("OLE2 [handler_writefile]: Block list loop detected\n");
            close(ofd);
            free(buff);
            cli_bitset_free(blk_bitset);
            return CL_BREAK;
        }
        if (!cli_bitset_set(blk_bitset, (unsigned long)current_block)) {
            close(ofd);
            free(buff);
            cli_bitset_free(blk_bitset);
            return CL_BREAK;
        }
        if (prop->size < (int64_t) hdr->sbat_cutoff) {
            /* Small block file */
            if (!ole2_get_sbat_data_block(hdr, buff, current_block)) {
                cli_dbgmsg("OLE2 [handler_writefile]: ole2_get_sbat_data_block failed\n");
                close(ofd);
                free(buff);
                cli_bitset_free(blk_bitset);
                return CL_SUCCESS;
            }
            /* buff now contains the block with N small blocks in it */
            offset = (1 << hdr->log2_small_block_size) * (current_block % (1 << (hdr->log2_big_block_size - hdr->log2_small_block_size)));

            if (cli_writen(ofd, &buff[offset], MIN(len, 1 << hdr->log2_small_block_size)) != MIN(len, 1 << hdr->log2_small_block_size)) {
                close(ofd);
                free(buff);
                cli_bitset_free(blk_bitset);
                return CL_BREAK;
            }
            len -= MIN(len, 1 << hdr->log2_small_block_size);
            current_block = ole2_get_next_sbat_block(hdr, current_block);
        } else {
            /* Big block file */
            if (!ole2_read_block(hdr, buff, 1 << hdr->log2_big_block_size, current_block)) {
                close(ofd);
                free(buff);
                cli_bitset_free(blk_bitset);
                return CL_SUCCESS;
            }
            if (cli_writen(ofd, buff, MIN(len, (1 << hdr->log2_big_block_size))) !=
                    MIN(len, (1 << hdr->log2_big_block_size))) {
                close(ofd);
                free(buff);
                cli_bitset_free(blk_bitset);
                return CL_BREAK;
            }
            current_block = ole2_get_next_block_number(hdr, current_block);
            len -= MIN(len, (1 << hdr->log2_big_block_size));
        }
    }
    close(ofd);
    free(buff);
    cli_bitset_free(blk_bitset);
    return CL_SUCCESS;
}

/* enum file Handler - checks for VBA presence */
static int
handler_enum(ole2_header_t * hdr, property_t * prop, const char *dir, cli_ctx * ctx)
{
    char           *name = NULL;
    unsigned char  *hwp_check;
    int32_t        offset;
    int            ret = CL_SUCCESS;
#if HAVE_JSON
    json_object *arrobj, *strmobj;

    name = get_property_name2(prop->name, prop->name_size);
    if (name) {
        if (SCAN_COLLECT_METADATA && ctx->wrkproperty != NULL) {
            arrobj = cli_jsonarray(ctx->wrkproperty, "Streams");
            if (NULL == arrobj) {
                cli_warnmsg("ole2: no memory for streams list or streams is not an array\n");
            }
            else {
                strmobj = json_object_new_string(name);
                json_object_array_add(arrobj, strmobj);
            }

            if (!strcmp(name, "powerpoint document")) {
                cli_jsonstr(ctx->wrkproperty, "FileType", "CL_TYPE_MSPPT");
            }
            if (!strcmp(name, "worddocument")) {
                cli_jsonstr(ctx->wrkproperty, "FileType", "CL_TYPE_MSWORD");
            }
            if (!strcmp(name, "workbook")) {
                cli_jsonstr(ctx->wrkproperty, "FileType", "CL_TYPE_MSXL");
            }

        }
    }
#else
    UNUSEDPARAM(ctx);
#endif
    UNUSEDPARAM(dir);

    if (!hdr->has_vba) {
        if (!name)
            name = get_property_name2(prop->name, prop->name_size);
        if (name) {
            if (!strcmp(name, "_vba_project") || !strcmp(name, "powerpoint document") || !strcmp(name, "worddocument") || !strcmp(name, "_1_ole10native"))
                hdr->has_vba = 1;
        }
    }

    /*
     * if we can find a root entry fileheader, it may be a HWP file
     * identify the HWP signature "HWP Document File" at offset 0 stream
     */
    if (!hdr->is_hwp) {
        if (!name)
            name = get_property_name2(prop->name, prop->name_size);
        if (name) {
            if (!strcmp(name, "fileheader")) {
                hwp_check = (unsigned char *)cli_calloc(1, 1 << hdr->log2_big_block_size);
                if (!hwp_check) {
                    free(name);
                    return CL_EMEM;
                }

                /* reading safety checks; do-while used for breaks */
                do {
                    if (prop->size == 0)
                        break;

                    if (prop->start_block > hdr->max_block_no)
                        break;

                    /* read the header block (~256 bytes) */
                    offset = 0;
                    if (prop->size < (int64_t) hdr->sbat_cutoff) {
                        if (!ole2_get_sbat_data_block(hdr, hwp_check, prop->start_block)) {
                            ret = CL_EREAD;
                            break;
                        }
                        offset = (1 << hdr->log2_small_block_size) *
                            (prop->start_block % (1 << (hdr->log2_big_block_size - hdr->log2_small_block_size)));

                        /* reading safety */
                        if (offset + 40 >= 1 << hdr->log2_big_block_size)
                            break;
                    } else {
                        if (!ole2_read_block(hdr, hwp_check, 1 << hdr->log2_big_block_size, prop->start_block)) {
                            ret = CL_EREAD;
                            break;
                        }
                    }

                    /* compare against HWP signature; we could add the 15 padding NULLs too */
                    if (!memcmp(hwp_check+offset, "HWP Document File", 17)) {
                        hwp5_header_t *hwp_new;
#if HAVE_JSON
                        cli_jsonstr(ctx->wrkproperty, "FileType", "CL_TYPE_HWP5");
#endif
                        hwp_new = cli_calloc(1, sizeof(hwp5_header_t));
                        if (!(hwp_new)) {
                            ret = CL_EMEM;
                            break;
                        }

                        memcpy(hwp_new, hwp_check+offset, sizeof(hwp5_header_t));

                        hwp_new->version = ole2_endian_convert_32(hwp_new->version);
                        hwp_new->flags = ole2_endian_convert_32(hwp_new->flags);

                        hdr->is_hwp = hwp_new;
                    }
                } while(0);

                free(hwp_check);
            }
        }
    }

    if (name)
        free(name);
    return ret;
}

static int
likely_mso_stream(int fd)
{
    off_t fsize;
    unsigned char check[2];

    fsize = lseek(fd, 0, SEEK_END);
    if (fsize == -1) {
        cli_dbgmsg("likely_mso_stream: call to lseek() failed\n");
        return 0;
    } else if (fsize < 6) {
        return 0;
    }

    if (lseek(fd, 4, SEEK_SET) == -1) {
        cli_dbgmsg("likely_mso_stream: call to lseek() failed\n");
        return 0;
    }

    if (cli_readn(fd, check, 2) != 2) {
        cli_dbgmsg("likely_mso_stream: reading from fd failed\n");
        return 0;
    }

    if (check[0] == 0x78 && check[1] == 0x9C)
        return 1;

    return 0;
}

static int
scan_mso_stream(int fd, cli_ctx *ctx)
{
    int zret, ofd, ret = CL_SUCCESS;
    fmap_t *input;
    off_t off_in = 0;
    size_t count, outsize = 0;
    z_stream zstrm;
    char *tmpname;
    uint32_t prefix;
    unsigned char inbuf[FILEBUFF], outbuf[FILEBUFF];

    /* fmap the input file for easier manipulation */
    if (fd < 0) {
        cli_dbgmsg("scan_mso_stream: Invalid file descriptor argument\n");
        return CL_ENULLARG;
    } else {
        STATBUF statbuf;

        if (FSTAT(fd, &statbuf) == -1) {
            cli_dbgmsg("scan_mso_stream: Can't stat file descriptor\n");
            return CL_ESTAT;
        }

        input = fmap(fd, 0, statbuf.st_size);
        if (!input) {
            cli_dbgmsg("scan_mso_stream: Failed to get fmap for input stream\n");
            return CL_EMAP;
        }
    }

    /* reserve tempfile for output and scanning */
    if ((ret = cli_gentempfd(ctx->engine->tmpdir, &tmpname, &ofd)) != CL_SUCCESS) {
        cli_errmsg("scan_mso_stream: Can't generate temporary file\n");
        funmap(input);
        return ret;
    }

    /* initialize zlib inflation stream */
    memset(&zstrm, 0, sizeof(zstrm));
    zstrm.zalloc = Z_NULL;
    zstrm.zfree = Z_NULL;
    zstrm.opaque = Z_NULL;
    zstrm.next_in = inbuf;
    zstrm.next_out = outbuf;
    zstrm.avail_in = 0;
    zstrm.avail_out = FILEBUFF;

    zret = inflateInit(&zstrm);
    if (zret != Z_OK) {
        cli_dbgmsg("scan_mso_stream: Can't initialize zlib inflation stream\n");
        ret = CL_EUNPACK;
        goto mso_end;
    }

    /* extract 32-bit prefix */
    if (fmap_readn(input, &prefix, off_in, sizeof(prefix)) != sizeof(prefix)) {
        cli_dbgmsg("scan_mso_stream: Can't extract 4-byte prefix\n");
        ret = CL_EREAD;
        goto mso_end;
    }

    /* RFC1952 says numbers are stored with least significant byte first */
    prefix = le32_to_host (prefix);

    off_in += sizeof(uint32_t);
    cli_dbgmsg("scan_mso_stream: stream prefix = %08x(%d)\n", prefix, prefix);

    /* inflation loop */
    do {
        if (zstrm.avail_in == 0) {
            zstrm.next_in = inbuf;
            ret = fmap_readn(input, inbuf, off_in, FILEBUFF);
            if (ret < 0) {
                cli_errmsg("scan_mso_stream: Error reading MSO file\n");
                ret = CL_EUNPACK;
                goto mso_end;
            }
            if (!ret)
                break;

            zstrm.avail_in = ret;
            off_in += ret;
        }
        zret = inflate(&zstrm, Z_SYNC_FLUSH);
        count = FILEBUFF - zstrm.avail_out;
        if (count) {
            if (cli_checklimits("MSO", ctx, outsize + count, 0, 0) != CL_SUCCESS)
                break;
            if (cli_writen(ofd, outbuf, count) != (int)count) {
                cli_errmsg("scan_mso_stream: Can't write to file %s\n", tmpname);
                ret = CL_EWRITE;
                goto mso_end;
            }
            outsize += count;
        }
        zstrm.next_out = outbuf;
        zstrm.avail_out = FILEBUFF;
    } while(zret == Z_OK);

    /* post inflation checks */
    if (zret != Z_STREAM_END && zret != Z_OK) {
        if (outsize == 0) {
            cli_infomsg(ctx, "scan_mso_stream: Error decompressing MSO file. No data decompressed.\n");
            ret = CL_EUNPACK;
            goto mso_end;
        }

        cli_infomsg(ctx, "scan_mso_stream: Error decompressing MSO file. Scanning what was decompressed.\n");
    }
    cli_dbgmsg("scan_mso_stream: Decompressed %llu bytes to %s\n", (long long unsigned)outsize, tmpname);

    if (outsize != prefix) {
        cli_warnmsg("scan_mso_stream: declared prefix != inflated stream size, %llu != %llu\n",
                    (long long unsigned)prefix, (long long unsigned)outsize);
    } else {
        cli_dbgmsg("scan_mso_stream: declared prefix == inflated stream size, %llu == %llu\n",
                   (long long unsigned)prefix, (long long unsigned)outsize);
    }

    /* scanning inflated stream */
    ret = cli_magic_scandesc(ofd, tmpname, ctx);

    /* clean-up */
 mso_end:
    zret = inflateEnd(&zstrm);
    if (zret != Z_OK)
        ret = CL_EUNPACK;
    close(ofd);
    if (!ctx->engine->keeptmp)
        if (cli_unlink(tmpname))
            ret = CL_EUNLINK;
    free(tmpname);
    funmap(input);
    return ret;
}

static int
handler_otf(ole2_header_t * hdr, property_t * prop, const char *dir, cli_ctx * ctx)
{
    char           *tempfile, *name = NULL;
    unsigned char  *buff;
    int32_t         current_block, len, offset;
    int             ofd, is_mso, ret;
    bitset_t       *blk_bitset;

    UNUSEDPARAM(dir);

    if (prop->type != 2) {
        /* Not a file */
        return CL_SUCCESS;
    }
    print_ole2_property(prop);

    if (!(tempfile = cli_gentemp(ctx ? ctx->engine->tmpdir : NULL)))
        return CL_EMEM;

    if ((ofd = open(tempfile, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, S_IRWXU)) < 0) {
        cli_dbgmsg("OLE2: Can't create file %s\n", tempfile);
        free(tempfile);
        return CL_ECREAT;
    }
    current_block = prop->start_block;
    len = (int32_t)prop->size;

    if (cli_debug_flag) {
        if (!name)
            name = get_property_name2(prop->name, prop->name_size);
        cli_dbgmsg("OLE2 [handler_otf]: Dumping '%s' to '%s'\n", name, tempfile);
    }

    buff = (unsigned char *)cli_malloc(1 << hdr->log2_big_block_size);
    if (!buff) {
        close(ofd);
        if (name)
            free(name);
        cli_unlink(tempfile);
        free(tempfile);
        return CL_EMEM;
    }
    blk_bitset = cli_bitset_init();

    if (!blk_bitset) {
        cli_errmsg("OLE2: OTF handler init bitset failed\n");
        free(buff);
        close(ofd);
        if (name)
            free(name);
        if (cli_unlink(tempfile)) {
            free(tempfile);
            return CL_EUNLINK;
        }
        free(tempfile);
        return CL_BREAK;
    }
    while ((current_block >= 0) && (len > 0)) {
        if (current_block > (int32_t) hdr->max_block_no) {
            cli_dbgmsg("OLE2: Max block number for file size exceeded: %d\n", current_block);
            break;
        }
        /* Check we aren't in a loop */
        if (cli_bitset_test(blk_bitset, (unsigned long)current_block)) {
            /* Loop in block list */
            cli_dbgmsg("OLE2: Block list loop detected\n");
            break;
        }
        if (!cli_bitset_set(blk_bitset, (unsigned long)current_block)) {
            break;
        }
        if (prop->size < (int64_t) hdr->sbat_cutoff) {
            /* Small block file */
            if (!ole2_get_sbat_data_block(hdr, buff, current_block)) {
                cli_dbgmsg("ole2_get_sbat_data_block failed\n");
                break;
            }
            /* buff now contains the block with N small blocks in it */
            offset = (1 << hdr->log2_small_block_size) * (current_block % (1 << (hdr->log2_big_block_size - hdr->log2_small_block_size)));
            if (cli_writen(ofd, &buff[offset], MIN(len, 1 << hdr->log2_small_block_size)) != MIN(len, 1 << hdr->log2_small_block_size)) {
                close(ofd);
                if (name)
                    free(name);
                free(buff);
                cli_bitset_free(blk_bitset);
                if (cli_unlink(tempfile)) {
                    free(tempfile);
                    return CL_EUNLINK;
                }
                free(tempfile);
                return CL_BREAK;
            }
            len -= MIN(len, 1 << hdr->log2_small_block_size);
            current_block = ole2_get_next_sbat_block(hdr, current_block);
        } else {
            /* Big block file */
            if (!ole2_read_block(hdr, buff, 1 << hdr->log2_big_block_size, current_block)) {
                break;
            }
            if (cli_writen(ofd, buff, MIN(len, (1 << hdr->log2_big_block_size))) !=
                    MIN(len, (1 << hdr->log2_big_block_size))) {
                close(ofd);
                if (name)
                    free(name);
                free(buff);
                cli_bitset_free(blk_bitset);
                if (cli_unlink(tempfile)) {
                    free(tempfile);
                    return CL_EUNLINK;
                }
                free(tempfile);
                return CL_EWRITE;
            }
            current_block = ole2_get_next_block_number(hdr, current_block);
            len -= MIN(len, (1 << hdr->log2_big_block_size));
        }
    }

    /* defragmenting of ole2 stream complete */

    is_mso = likely_mso_stream(ofd);
    if (lseek(ofd, 0, SEEK_SET) == -1) {
        close(ofd);
        if (name)
            free(name);
        if (ctx && !(ctx->engine->keeptmp))
            cli_unlink(tempfile);

        free(tempfile);
        free(buff);
        cli_bitset_free(blk_bitset);
        return CL_ESEEK;
    }

#if HAVE_JSON
    /* JSON Output Summary Information */
    if (SCAN_COLLECT_METADATA && (ctx->properties != NULL)) {
        if (!name)
            name = get_property_name2(prop->name, prop->name_size);
        if (name) {
            if (!strncmp(name, "_5_summaryinformation", 21)) {
                cli_dbgmsg("OLE2: detected a '_5_summaryinformation' stream\n");
                /* JSONOLE2 - what to do if something breaks? */
                if (cli_ole2_summary_json(ctx, ofd, 0) == CL_ETIMEOUT) {
                    free(name);
                    close(ofd);
                    if (ctx && !(ctx->engine->keeptmp))
                        cli_unlink(tempfile);

                    free(tempfile);
                    free(buff);
                    cli_bitset_free(blk_bitset);
                    return CL_ETIMEOUT;
                }
            }
            if (!strncmp(name, "_5_documentsummaryinformation", 29)) {
                cli_dbgmsg("OLE2: detected a '_5_documentsummaryinformation' stream\n");
                /* JSONOLE2 - what to do if something breaks? */
                if (cli_ole2_summary_json(ctx, ofd, 1) == CL_ETIMEOUT) {
                    free(name);
                    close(ofd);
                    if (ctx && !(ctx->engine->keeptmp))
                        cli_unlink(tempfile);

                    free(tempfile);
                    free(buff);
                    cli_bitset_free(blk_bitset);
                    return CL_ETIMEOUT;
                }
            }
        }
    }
#endif

    if (hdr->is_hwp) {
        if (!name)
            name = get_property_name2(prop->name, prop->name_size);
        ret = cli_scanhwp5_stream(ctx, hdr->is_hwp, name, ofd, tempfile);
    } else if (is_mso < 0) {
        ret = CL_ESEEK;
    } else if (is_mso) {
        /* MSO Stream Scan */
        ret = scan_mso_stream(ofd, ctx);
    } else {
        /* Normal File Scan */
        ret = cli_magic_scandesc(ofd, tempfile, ctx);
    }
    if (name)
        free(name);
    close(ofd);
    free(buff);
    cli_bitset_free(blk_bitset);
    if (ctx && !ctx->engine->keeptmp) {
        if (cli_unlink(tempfile)) {
            free(tempfile);
            return CL_EUNLINK;
        }
    }
    free(tempfile);
    return ret == CL_VIRUS ? CL_VIRUS : CL_SUCCESS;

}

#if !defined(HAVE_ATTRIB_PACKED) && !defined(HAVE_PRAGMA_PACK) && !defined(HAVE_PRAGMA_PACK_HPPA)
static int
ole2_read_header(int fd, ole2_header_t * hdr)
{
    int             i;

    if (cli_readn(fd, &hdr->magic, 8) != 8) {
        return FALSE;
    }
    if (cli_readn(fd, &hdr->clsid, 16) != 16) {
        return FALSE;
    }
    if (cli_readn(fd, &hdr->minor_version, 2) != 2) {
        return FALSE;
    }
    if (cli_readn(fd, &hdr->dll_version, 2) != 2) {
        return FALSE;
    }
    if (cli_readn(fd, &hdr->byte_order, 2) != 2) {
        return FALSE;
    }
    if (cli_readn(fd, &hdr->log2_big_block_size, 2) != 2) {
        return FALSE;
    }
    if (cli_readn(fd, &hdr->log2_small_block_size, 4) != 4) {
        return FALSE;
    }
    if (cli_readn(fd, &hdr->reserved, 8) != 8) {
        return FALSE;
    }
    if (cli_readn(fd, &hdr->bat_count, 4) != 4) {
        return FALSE;
    }
    if (cli_readn(fd, &hdr->prop_start, 4) != 4) {
        return FALSE;
    }
    if (cli_readn(fd, &hdr->signature, 4) != 4) {
        return FALSE;
    }
    if (cli_readn(fd, &hdr->sbat_cutoff, 4) != 4) {
        return FALSE;
    }
    if (cli_readn(fd, &hdr->sbat_start, 4) != 4) {
        return FALSE;
    }
    if (cli_readn(fd, &hdr->sbat_block_count, 4) != 4) {
        return FALSE;
    }
    if (cli_readn(fd, &hdr->xbat_start, 4) != 4) {
        return FALSE;
    }
    if (cli_readn(fd, &hdr->xbat_count, 4) != 4) {
        return FALSE;
    }
    for (i = 0; i < 109; i++) {
        if (cli_readn(fd, &hdr->bat_array[i], 4) != 4) {
            return FALSE;
        }
    }
    return TRUE;
}
#endif

int
cli_ole2_extract(const char *dirname, cli_ctx * ctx, struct uniq **vba)
{
    ole2_header_t   hdr;
    int             ret = CL_CLEAN;
    size_t hdr_size;
    unsigned int    file_count = 0;
    unsigned long   scansize, scansize2;
    const void     *phdr;

    cli_dbgmsg("in cli_ole2_extract()\n");
    if (!ctx)
        return CL_ENULLARG;

    hdr.is_hwp = NULL;
    hdr.bitset = NULL;
    if (ctx->engine->maxscansize) {
        if (ctx->engine->maxscansize > ctx->scansize)
            scansize = ctx->engine->maxscansize - ctx->scansize;
        else
            return CL_EMAXSIZE;
    } else
        scansize = -1;

    scansize2 = scansize;

    /* size of header - size of other values in struct */
    hdr_size = sizeof(struct ole2_header_tag) - sizeof(int32_t) - sizeof(uint32_t) -
        sizeof(off_t) - sizeof(bitset_t *) -
        sizeof(struct uniq *) - sizeof(fmap_t *) - sizeof(int) - sizeof(hwp5_header_t *);

    if ((size_t)((*ctx->fmap)->len) < (size_t)(hdr_size)) {
        return CL_CLEAN;
    }
    hdr.map = *ctx->fmap;
    hdr.m_length = hdr.map->len;
    phdr = fmap_need_off_once(hdr.map, 0, hdr_size);
    if (phdr) {
        memcpy(&hdr, phdr, hdr_size);
    } else {
        cli_dbgmsg("cli_ole2_extract: failed to read header\n");
        goto abort;
    }

    hdr.minor_version = ole2_endian_convert_16(hdr.minor_version);
    hdr.dll_version = ole2_endian_convert_16(hdr.dll_version);
    hdr.byte_order = ole2_endian_convert_16(hdr.byte_order);
    hdr.log2_big_block_size = ole2_endian_convert_16(hdr.log2_big_block_size);
    hdr.log2_small_block_size = ole2_endian_convert_32(hdr.log2_small_block_size);
    hdr.bat_count = ole2_endian_convert_32(hdr.bat_count);
    hdr.prop_start = ole2_endian_convert_32(hdr.prop_start);
    hdr.sbat_cutoff = ole2_endian_convert_32(hdr.sbat_cutoff);
    hdr.sbat_start = ole2_endian_convert_32(hdr.sbat_start);
    hdr.sbat_block_count = ole2_endian_convert_32(hdr.sbat_block_count);
    hdr.xbat_start = ole2_endian_convert_32(hdr.xbat_start);
    hdr.xbat_count = ole2_endian_convert_32(hdr.xbat_count);

    hdr.sbat_root_start = -1;

    hdr.bitset = cli_bitset_init();
    if (!hdr.bitset) {
        ret = CL_EMEM;
        goto abort;
    }
    if (memcmp(hdr.magic, magic_id, 8) != 0) {
        cli_dbgmsg("OLE2 magic failed!\n");
        ret = CL_EFORMAT;
        goto abort;
    }
    if (hdr.log2_big_block_size < 6 || hdr.log2_big_block_size > 30) {
        cli_dbgmsg("CAN'T PARSE: Invalid big block size (2^%u)\n", hdr.log2_big_block_size);
        goto abort;
    }
    if (!hdr.log2_small_block_size || hdr.log2_small_block_size > hdr.log2_big_block_size) {
        cli_dbgmsg("CAN'T PARSE: Invalid small block size (2^%u)\n", hdr.log2_small_block_size);
        goto abort;
    }
    if (hdr.sbat_cutoff != 4096) {
        cli_dbgmsg("WARNING: Untested sbat cutoff (%u); data may not extract correctly\n", hdr.sbat_cutoff);
    }

    if (hdr.map->len > INT32_MAX) {
        cli_dbgmsg("OLE2 extract: Overflow detected\n");
        ret = CL_EFORMAT;
        goto abort;
    }
    /* 8 SBAT blocks per file block */
    hdr.max_block_no = (hdr.map->len - MAX(512, 1 << hdr.log2_big_block_size)) / (1 << hdr.log2_small_block_size);

    print_ole2_header(&hdr);
    cli_dbgmsg("Max block number: %lu\n", (unsigned long int)hdr.max_block_no);

    /* PASS 1 : Count files and check for VBA */
    hdr.has_vba = 0;
    ret = ole2_walk_property_tree(&hdr, NULL, 0, handler_enum, 0, &file_count, ctx, &scansize);
    cli_bitset_free(hdr.bitset);
    hdr.bitset = NULL;
    if (!file_count || !(hdr.bitset = cli_bitset_init()))
        goto abort;

    if (hdr.is_hwp) {
        cli_dbgmsg("OLE2: identified HWP document\n");
        cli_dbgmsg("OLE2: HWP signature: %.17s\n", hdr.is_hwp->signature);
        cli_dbgmsg("OLE2: HWP version: 0x%08x\n", hdr.is_hwp->version);
        cli_dbgmsg("OLE2: HWP flags:   0x%08x\n", hdr.is_hwp->flags);

        ret = cli_hwp5header(ctx, hdr.is_hwp);
        if (ret != CL_SUCCESS)
            goto abort;
    }

    /* If there's no VBA we scan OTF */
    if (hdr.has_vba) {
        /* PASS 2/A : VBA scan */
        cli_dbgmsg("OLE2: VBA project found\n");
        if (!(hdr.U = uniq_init(file_count))) {
            cli_dbgmsg("OLE2: uniq_init() failed\n");
            ret = CL_EMEM;
            goto abort;
        }
        file_count = 0;
        ole2_walk_property_tree(&hdr, dirname, 0, handler_writefile, 0, &file_count, ctx, &scansize2);
        ret = CL_CLEAN;
        *vba = hdr.U;
    } else {
        cli_dbgmsg("OLE2: no VBA projects found\n");
        /* PASS 2/B : OTF scan */
        file_count = 0;
        ret = ole2_walk_property_tree(&hdr, NULL, 0, handler_otf, 0, &file_count, ctx, &scansize2);
    }

abort:
    if (hdr.bitset)
        cli_bitset_free(hdr.bitset);

    if (hdr.is_hwp)
        free(hdr.is_hwp);

    return ret == CL_BREAK ? CL_CLEAN : ret;
}
