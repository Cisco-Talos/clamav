/*
 * Extract component parts of OLE2 files (e.g. MS Office Documents)
 * 
 * Copyright (C) 2007-2013 Sourcefire, Inc.
 * 
 * Authors: Trog
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
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
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif

#if HAVE_ICONV
#include <iconv.h>
#endif

#include "clamav.h"
#include "cltypes.h"
#include "others.h"
#include "ole2_extract.h"
#include "scanners.h"
#include "fmap.h"
#include "json_api.h"

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
    int             i;

    if (!hdr || !cli_debug_flag) {
        return;
    }
    cli_dbgmsg("\nMagic:\t\t\t0x");
    for (i = 0; i < 8; i++) {
        cli_dbgmsg("%x", hdr->magic[i]);
    }
    cli_dbgmsg("\n");

    cli_dbgmsg("CLSID:\t\t\t{");
    for (i = 0; i < 16; i++) {
        cli_dbgmsg("%x ", hdr->clsid[i]);
    }
    cli_dbgmsg("}\n");

    cli_dbgmsg("Minor version:\t\t0x%x\n", hdr->minor_version);
    cli_dbgmsg("DLL version:\t\t0x%x\n", hdr->dll_version);
    cli_dbgmsg("Byte Order:\t\t%d\n", hdr->byte_order);
    cli_dbgmsg("Big Block Size:\t\t%i\n", hdr->log2_big_block_size);
    cli_dbgmsg("Small Block Size:\t%i\n", hdr->log2_small_block_size);
    cli_dbgmsg("BAT count:\t\t%d\n", hdr->bat_count);
    cli_dbgmsg("Prop start:\t\t%d\n", hdr->prop_start);
    cli_dbgmsg("SBAT cutoff:\t\t%d\n", hdr->sbat_cutoff);
    cli_dbgmsg("SBat start:\t\t%d\n", hdr->sbat_start);
    cli_dbgmsg("SBat block count:\t%d\n", hdr->sbat_block_count);
    cli_dbgmsg("XBat start:\t\t%d\n", hdr->xbat_start);
    cli_dbgmsg("XBat block count:\t%d\n\n", hdr->xbat_count);
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
    offset = (blockno << hdr->log2_big_block_size) + MAX(512, 1 << hdr->log2_big_block_size);   /* 512 is header size */

    offend = offset + size;
    if ((offend <= 0) || (offend > hdr->m_length)) {
        return FALSE;
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
                    if ((ctx->options & CL_SCAN_ALLMATCHES) && (ret == CL_VIRUS)) {
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
                    if ((ctx->options & CL_SCAN_ALLMATCHES) && (ret == CL_VIRUS)) {
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
                    if ((ctx->options & CL_SCAN_ALLMATCHES) && (ret == CL_VIRUS)) {
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
                if ((ctx->options & CL_SCAN_FILE_PROPERTIES) && (ctx->wrkproperty != NULL)) {
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
                    if ((ctx->options & CL_SCAN_ALLMATCHES) && (ret == CL_VIRUS)) {
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
            if (dirname)
                free(dirname);
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
    if (name)
        cnt = uniq_add(hdr->U, name, strlen(name), &hash);
    else
        cnt = uniq_add(hdr->U, NULL, 0, &hash);
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
#if HAVE_JSON
    json_object *arrobj, *strmobj;

    name = get_property_name2(prop->name, prop->name_size);
    if (name) {
        if (ctx->options & CL_SCAN_FILE_PROPERTIES && ctx->wrkproperty != NULL) {
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

    if (name)
        free(name);
    return CL_SUCCESS;
}


static int
handler_otf(ole2_header_t * hdr, property_t * prop, const char *dir, cli_ctx * ctx)
{
    char           *tempfile;
    unsigned char  *buff;
    int32_t         current_block, len, offset;
    int             ofd, ret;
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
    len = prop->size;

    buff = (unsigned char *)cli_malloc(1 << hdr->log2_big_block_size);
    if (!buff) {
        close(ofd);
        cli_unlink(tempfile);
        free(tempfile);
        return CL_EMEM;
    }
    blk_bitset = cli_bitset_init();

    if (!blk_bitset) {
        cli_errmsg("OLE2: OTF handler init bitset failed\n");
        free(buff);
        close(ofd);
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

    if (lseek(ofd, 0, SEEK_SET) == -1) {
        close(ofd);
        if (ctx && !(ctx->engine->keeptmp))
            cli_unlink(tempfile);

        free(tempfile);
        free(buff);
        cli_bitset_free(blk_bitset);
        return CL_ESEEK;
    }

#if HAVE_JSON
    /* JSON Output Summary Information */
    if (ctx->options & CL_SCAN_FILE_PROPERTIES && ctx->properties != NULL) {
        char *name = get_property_name2(prop->name, prop->name_size);
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
        free(name);
    }
#endif

    /* Normal File Scan */
    ret = cli_magic_scandesc(ofd, ctx);
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
        sizeof(struct uniq *) - sizeof(int) - sizeof(fmap_t *);

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

    return ret == CL_BREAK ? CL_CLEAN : ret;
}

/* Summary and Document Information Parsing to JSON */
#if HAVE_JSON

#define WINUNICODE 0x04B0
#define PROPCNTLIMIT 25
#define PROPSTRLIMIT 128 /* affects property strs, NOT sanitized strs (may result in a buffer allocating PROPSTRLIMIT*6) */

#define sum16_endian_convert(v) le16_to_host((uint16_t)(v))
#define sum32_endian_convert(v) le32_to_host((uint32_t)(v))
#define sum64_endian_convert(v) le64_to_host((uint64_t)(v))

enum summary_pidsi {
    SPID_CODEPAGE   = 0x00000001,
    SPID_TITLE      = 0x00000002,
    SPID_SUBJECT    = 0x00000003,
    SPID_AUTHOR     = 0x00000004,
    SPID_KEYWORDS   = 0x00000005,
    SPID_COMMENTS   = 0x00000006,
    SPID_TEMPLATE   = 0x00000007,
    SPID_LASTAUTHOR = 0x00000008,
    SPID_REVNUMBER  = 0x00000009,
    SPID_EDITTIME   = 0x0000000A,
    SPID_LASTPRINTED  = 0x0000000B,
    SPID_CREATEDTIME  = 0x0000000C,
    SPID_MODIFIEDTIME = 0x0000000D,
    SPID_PAGECOUNT = 0x0000000E,
    SPID_WORDCOUNT = 0x0000000F,
    SPID_CHARCOUNT = 0x00000010,
    SPID_THUMBNAIL = 0x00000011,
    SPID_APPNAME   = 0x00000012,
    SPID_SECURITY  = 0x00000013
};

enum docsum_pidsi {
    DSPID_CODEPAGE    = 0x00000001,
    DSPID_CATEGORY    = 0x00000002,
    DSPID_PRESFORMAT  = 0x00000003,
    DSPID_BYTECOUNT   = 0x00000004,
    DSPID_LINECOUNT   = 0x00000005,
    DSPID_PARCOUNT    = 0x00000006,
    DSPID_SLIDECOUNT  = 0x00000007,
    DSPID_NOTECOUNT   = 0x00000008,
    DSPID_HIDDENCOUNT = 0x00000009,
    DSPID_MMCLIPCOUNT = 0x0000000A,
    DSPID_SCALE       = 0x0000000B,
    DSPID_HEADINGPAIR = 0x0000000C, /* VT_VARIANT | VT_VECTOR */
    DSPID_DOCPARTS    = 0x0000000D, /* VT_VECTOR | VT_LPSTR */
    DSPID_MANAGER     = 0x0000000E,
    DSPID_COMPANY     = 0x0000000F,
    DSPID_LINKSDIRTY  = 0x00000010,
    DSPID_CCHWITHSPACES = 0x00000011,
    DSPID_SHAREDDOC   = 0x00000013, /* must be false */
    DSPID_LINKBASE    = 0x00000014, /* moved to user-defined */
    DSPID_HLINKS      = 0x00000015, /* moved to user-defined */
    DSPID_HYPERLINKSCHANGED = 0x00000016,
    DSPID_VERSION     = 0x00000017,
    DSPID_DIGSIG      = 0x00000018,
    DSPID_CONTENTTYPE   = 0x0000001A,
    DSPID_CONTENTSTATUS = 0x0000001B,
    DSPID_LANGUAGE      = 0x0000001C,
    DSPID_DOCVERSION    = 0x0000001D
};

enum property_type {
    PT_EMPTY    = 0x0000,
    PT_NULL     = 0x0001,
    PT_INT16    = 0x0002,
    PT_INT32    = 0x0003,
    PT_FLOAT32  = 0x0004,
    PT_DOUBLE64 = 0x0005,
    PT_DATE     = 0x0007,
    PT_BSTR     = 0x0008,
    PT_BOOL    = 0x000B,
    PT_INT8v1  = 0x0010,
    PT_UINT8   = 0x0011,
    PT_UINT16  = 0x0012,
    PT_UINT32  = 0x0013,
    PT_INT64   = 0x0014,
    PT_UINT64  = 0x0015,
    PT_INT32v1  = 0x0016,
    PT_UINT32v1 = 0x0017,
    PT_LPSTR  = 0x001E,
    PT_LPWSTR = 0x001F,
    PT_FILETIME = 0x0040,
	
    /* More Types not currently handled */
};

typedef struct summary_stub {
    uint16_t byte_order;
    uint16_t version;
    uint32_t system; /* implementation-specific */
    uint8_t CLSID[16];

    uint32_t num_propsets; /* 1 or 2 */
} summary_stub_t;

typedef struct propset_summary_entry {
    uint8_t FMTID[16];
    uint32_t offset;
} propset_entry_t;

/* error codes */
#define OLE2_SUMMARY_ERROR_TOOSMALL      0x00000001
#define OLE2_SUMMARY_ERROR_OOB           0x00000002
#define OLE2_SUMMARY_ERROR_DATABUF       0x00000004
#define OLE2_SUMMARY_ERROR_INVALID_ENTRY 0x00000008
#define OLE2_SUMMARY_LIMIT_PROPS         0x00000010
#define OLE2_SUMMARY_FLAG_TIMEOUT        0x00000020
#define OLE2_SUMMARY_FLAG_CODEPAGE       0x00000040
#define OLE2_SUMMARY_FLAG_UNKNOWN_PROPID 0x00000080
#define OLE2_SUMMARY_FLAG_UNHANDLED_PROPTYPE 0x00000100
#define OLE2_SUMMARY_FLAG_TRUNC_STR      0x00000200

#define OLE2_CODEPAGE_ERROR_NOTFOUND     0x00000400
#define OLE2_CODEPAGE_ERROR_UNINITED     0x00000800
#define OLE2_CODEPAGE_ERROR_INVALID      0x00001000
#define OLE2_CODEPAGE_ERROR_INCOMPLETE   0x00002000
#define OLE2_CODEPAGE_ERROR_OUTBUFTOOSMALL 0x00002000

/* metadata structures */
typedef struct summary_ctx {
    cli_ctx *ctx;
    int mode;
    fmap_t *sfmap;
    json_object *summary;
    size_t maplen;
    uint32_t flags;

    /* propset metadata */
    uint32_t pssize; /* track from propset start, not tail start */
    int16_t codepage;
    int writecp;

    /* property metadata */
    const char *propname;

    /* timeout meta */
    int toval;
} summary_ctx_t;

/* string conversion */
struct codepage_entry {
    int16_t codepage;
    const char *encoding;
};

#define NUMCODEPAGES 152
static const struct codepage_entry codepage_entries[NUMCODEPAGES] = {
    { 37,    "IBM037" },      /* IBM EBCDIC US-Canada */
    { 437,   "IBM437" },      /* OEM United States */
    { 500,   "IBM500" },      /* IBM EBCDIC International */
    { 708,   "ASMO-708" },    /* Arabic (ASMO 708) */
    { 709,   NULL },          /* Arabic (ASMO-449+, BCON V4) */
    { 710,   NULL },          /* Arabic - Transparent Arabic */
    { 720,   NULL },          /* Arabic (Transparent ASMO); Arabic (DOS) */
    { 737,   NULL },          /* OEM Greek (formerly 437G); Greek (DOS) */
    { 775,   "IBM775" },      /* OEM Baltic; Baltic (DOS) */
    { 850,   "IBM850" },      /* OEM Multilingual Latin 1; Western European (DOS) */
    { 852,   "IBM852" },      /* OEM Latin 2; Central European (DOS) */
    { 855,   "IBM855" },      /* OEM Cyrillic (primarily Russian) */
    { 857,   "IBM857" },      /* OEM Turkish; Turkish (DOS) */
    { 858,   NULL },          /* OEM Multilingual Latin 1 + Euro symbol */
    { 860,   "IBM860" },      /* OEM Portuguese; Portuguese (DOS) */
    { 861,   "IBM861" },      /* OEM Icelandic; Icelandic (DOS) */
    { 862,   NULL },          /* OEM Hebrew; Hebrew (DOS) */
    { 863,   "IBM863" },      /* OEM French Canadian; French Canadian (DOS) */
    { 864,   "IBM864" },      /* OEM Arabic; Arabic (864) */
    { 865,   "IBM865" },      /* OEM Nordic; Nordic (DOS) */
    { 866,   "CP866" },       /* OEM Russian; Cyrillic (DOS) */
    { 869,   "IBM869" },      /* OEM Modern Greek; Greek, Modern (DOS) */
    { 870,   "IBM870" },      /* IBM EBCDIC Multilingual/ROECE (Latin 2); IBM EBCDIC Multilingual Latin 2 */
    { 874,   "WINDOWS-874" }, /* ANSI/OEM Thai (ISO 8859-11); Thai (Windows) */
    { 875,   "CP875" },       /* IBM EBCDIC Greek Modern */
    { 932,   "SHIFT_JIS" },   /* ANSI/OEM Japanese; Japanese (Shift-JIS) */
    { 936,   "GB2312" },      /* ANSI/OEM Simplified Chinese (PRC, Singapore); Chinese Simplified (GB2312) */
    { 949,   NULL },          /* ANSI/OEM Korean (Unified Hangul Code) */
    { 950,   "BIG5" },        /* ANSI/OEM Traditional Chinese (Taiwan; Hong Kong SAR, PRC); Chinese Traditional (Big5) */
    { 1026,  "IBM1026" },     /* IBM EBCDIC Turkish (Latin 5) */
    { 1047,  NULL },          /* IBM EBCDIC Latin 1/Open System */
    { 1140,  NULL },          /* IBM EBCDIC US-Canada (037 + Euro symbol); IBM EBCDIC (US-Canada-Euro) */
    { 1141,  NULL },          /* IBM EBCDIC Germany (20273 + Euro symbol); IBM EBCDIC (Germany-Euro) */
    { 1142,  NULL },          /* IBM EBCDIC Denmark-Norway (20277 + Euro symbol); IBM EBCDIC (Denmark-Norway-Euro) */
    { 1143,  NULL },          /* IBM EBCDIC Finland-Sweden (20278 + Euro symbol); IBM EBCDIC (Finland-Sweden-Euro) */
    { 1144,  NULL },          /* IBM EBCDIC Italy (20280 + Euro symbol); IBM EBCDIC (Italy-Euro) */
    { 1145,  NULL },          /* IBM EBCDIC Latin America-Spain (20284 + Euro symbol); IBM EBCDIC (Spain-Euro) */
    { 1146,  NULL },          /* IBM EBCDIC United Kingdom (20285 + Euro symbol); IBM EBCDIC (UK-Euro) */
    { 1147,  NULL },          /* IBM EBCDIC France (20297 + Euro symbol); IBM EBCDIC (France-Euro) */
    { 1148,  NULL },          /* IBM EBCDIC International (500 + Euro symbol); IBM EBCDIC (International-Euro) */
    { 1149,  NULL },          /* IBM EBCDIC Icelandic (20871 + Euro symbol); IBM EBCDIC (Icelandic-Euro) */
    { 1200,  "UTF-16LE" },    /* Unicode UTF-16, little endian byte order (BMP of ISO 10646); available only to managed applications */
    { 1201,  "UTF-16BE" },    /* Unicode UTF-16, big endian byte order; available only to managed applications */
    { 1250,  "WINDOWS-1250" }, /* ANSI Central European; Central European (Windows) */
    { 1251,  "WINDOWS-1251" }, /* ANSI Cyrillic; Cyrillic (Windows) */
    { 1252,  "WINDOWS-1252" }, /* ANSI Latin 1; Western European (Windows) */
    { 1253,  "WINDOWS-1253" }, /* ANSI Greek; Greek (Windows) */
    { 1254,  "WINDOWS-1254" }, /* ANSI Turkish; Turkish (Windows) */
    { 1255,  "WINDOWS-1255" }, /* ANSI Hebrew; Hebrew (Windows) */
    { 1256,  "WINDOWS-1256" }, /* ANSI Arabic; Arabic (Windows) */
    { 1257,  "WINDOWS-1257" }, /* ANSI Baltic; Baltic (Windows) */
    { 1258,  "WINDOWS-1258" }, /* ANSI/OEM Vietnamese; Vietnamese (Windows) */
    { 1361,  "JOHAB" },       /* Korean (Johab) */
    { 10000, "MACINTOSH" },   /* MAC Roman; Western European (Mac) */
    { 10001, NULL },          /* Japanese (Mac) */
    { 10002, NULL },          /* MAC Traditional Chinese (Big5); Chinese Traditional (Mac) */
    { 10003, NULL },          /* Korean (Mac) */
    { 10004, NULL },          /* Arabic (Mac) */
    { 10005, NULL },          /* Hebrew (Mac) */
    { 10006, NULL },          /* Greek (Mac) */
    { 10007, NULL },          /* Cyrillic (Mac) */
    { 10008, NULL },          /* MAC Simplified Chinese (GB 2312); Chinese Simplified (Mac) */
    { 10010, NULL },          /* Romanian (Mac) */
    { 10017, NULL },          /* Ukrainian (Mac) */
    { 10021, NULL },          /* Thai (Mac) */
    { 10029, NULL },          /* MAC Latin 2; Central European (Mac) */
    { 10079, NULL },          /* Icelandic (Mac) */
    { 10081, NULL },          /* Turkish (Mac) */
    { 10082, NULL },          /* Croatian (Mac) */
    { 12000, "UTF-32LE" },    /* Unicode UTF-32, little endian byte order; available only to managed applications */
    { 12001, "UTF-32BE" },    /* Unicode UTF-32, big endian byte order; available only to managed applications */
    { 20000, NULL },          /* CNS Taiwan; Chinese Traditional (CNS) */
    { 20001, NULL },          /* TCA Taiwan */
    { 20002, NULL },          /* Eten Taiwan; Chinese Traditional (Eten) */
    { 20003, NULL },          /* IBM5550 Taiwan */
    { 20004, NULL },          /* TeleText Taiwan */
    { 20005, NULL },          /* Wang Taiwan */
    { 20105, NULL },          /* IA5 (IRV International Alphabet No. 5, 7-bit); Western European (IA5) */
    { 20106, NULL },          /* IA5 German (7-bit) */
    { 20107, NULL },          /* IA5 Swedish (7-bit) */
    { 20108, NULL },          /* IA5 Norwegian (7-bit) */
    { 20127, "US-ASCII" },    /* US-ASCII (7-bit) */
    { 20261, NULL },          /* T.61 */
    { 20269, NULL },          /* ISO 6937 Non-Spacing Accent */
    { 20273, "IBM273" },      /* IBM EBCDIC Germany */
    { 20277, "IBM277" },      /* IBM EBCDIC Denmark-Norway */
    { 20278, "IBM278" },      /* IBM EBCDIC Finland-Sweden */
    { 20280, "IBM280" },      /* IBM EBCDIC Italy */
    { 20284, "IBM284" },      /* IBM EBCDIC Latin America-Spain */
    { 20285, "IBM285" },      /* IBM EBCDIC United Kingdom */
    { 20290, "IBM290" },      /* IBM EBCDIC Japanese Katakana Extended */
    { 20297, "IBM297" },      /* IBM EBCDIC France */
    { 20420, "IBM420" },      /* IBM EBCDIC Arabic */
    { 20423, "IBM423" },      /* IBM EBCDIC Greek */
    { 20424, "IBM424" },      /* IBM EBCDIC Hebrew */
    { 20833, NULL },          /* IBM EBCDIC Korean Extended */
    { 20838, NULL },          /* IBM EBCDIC Thai */
    { 20866, "KOI8-R" },      /* Russian (KOI8-R); Cyrillic (KOI8-R) */
    { 20871, "IBM871" },      /* IBM EBCDIC Icelandic */
    { 20880, "IBM880" },      /* IBM EBCDIC Cyrillic Russian */
    { 20905, "IBM905" },      /* IBM EBCDIC Turkish */
    { 20924, NULL },          /* IBM EBCDIC Latin 1/Open System (1047 + Euro symbol) */
    { 20932, "EUC-JP" },      /* Japanese (JIS 0208-1990 and 0212-1990) */
    { 20936, NULL },          /* Simplified Chinese (GB2312); Chinese Simplified (GB2312-80) */
    { 20949, NULL },          /* Korean Wansung */
    { 21025, "CP1025" },      /* IBM EBCDIC Cyrillic Serbian-Bulgarian */
    { 21027, NULL },          /* (deprecated) */
    { 21866, "KOI8-U" },      /* Ukrainian (KOI8-U); Cyrillic (KOI8-U) */
    { 28591, "ISO-8859-1" },  /* ISO 8859-1 Latin 1; Western European (ISO) */
    { 28592, "ISO-8859-2" },  /* ISO 8859-2 Central European; Central European (ISO) */
    { 28593, "ISO-8859-3" },  /* ISO 8859-3 Latin 3 */
    { 28594, "ISO-8859-4" },  /* ISO 8859-4 Baltic */
    { 28595, "ISO-8859-5" },  /* ISO 8859-5 Cyrillic */
    { 28596, "ISO-8859-6" },  /* ISO 8859-6 Arabic */
    { 28597, "ISO-8859-7" },  /* ISO 8859-7 Greek */
    { 28598, "ISO-8859-8" },  /* ISO 8859-8 Hebrew; Hebrew (ISO-Visual) */
    { 28599, "ISO-8859-9" },  /* ISO 8859-9 Turkish */
    { 28603, "ISO-8859-13" }, /* ISO 8859-13 Estonian */
    { 28605, "ISO-8859-15" }, /* ISO 8859-15 Latin 9 */
    { 29001, NULL },          /* Europa 3 */
    { 38598, NULL },          /* ISO 8859-8 Hebrew; Hebrew (ISO-Logical) */
    { 50220, "ISO-2022-JP" },   /* ISO 2022 Japanese with no halfwidth Katakana; Japanese (JIS) (guess) */
    { 50221, "ISO-2022-JP-2" }, /* ISO 2022 Japanese with halfwidth Katakana; Japanese (JIS-Allow 1 byte Kana) (guess) */
    { 50222, "ISO-2022-JP-3" }, /* ISO 2022 Japanese JIS X 0201-1989; Japanese (JIS-Allow 1 byte Kana - SO/SI) (guess) */
    { 50225, "ISO-2022-KR" }, /* ISO 2022 Korean */
    { 50227, NULL },          /* ISO 2022 Simplified Chinese; Chinese Simplified (ISO 2022) */
    { 50229, NULL },          /* ISO 2022 Traditional Chinese */
    { 50930, NULL },          /* EBCDIC Japanese (Katakana) Extended */
    { 50931, NULL },          /* EBCDIC US-Canada and Japanese */
    { 50933, NULL },          /* EBCDIC Korean Extended and Korean */
    { 50935, NULL },          /* EBCDIC Simplified Chinese Extended and Simplified Chinese */
    { 50936, NULL },          /* EBCDIC Simplified Chinese */
    { 50937, NULL },          /* EBCDIC US-Canada and Traditional Chinese */
    { 50939, NULL },          /* EBCDIC Japanese (Latin) Extended and Japanese */
    { 51932, "EUC-JP" },      /* EUC Japanese */
    { 51936, "EUC-CN" },      /* EUC Simplified Chinese; Chinese Simplified (EUC) */
    { 51949, "EUC-KR" },      /* EUC Korean */
    { 51950, NULL },          /* EUC Traditional Chinese */
    { 52936, NULL },          /* HZ-GB2312 Simplified Chinese; Chinese Simplified (HZ) */
    { 54936, "GB18030" },     /* Windows XP and later: GB18030 Simplified Chinese (4 byte); Chinese Simplified (GB18030) */
    { 57002, NULL },          /* ISCII Devanagari */
    { 57003, NULL },          /* ISCII Bengali */
    { 57004, NULL },          /* ISCII Tamil */
    { 57005, NULL },          /* ISCII Telugu */
    { 57006, NULL },          /* ISCII Assamese */
    { 57007, NULL },          /* ISCII Oriya */
    { 57008, NULL },          /* ISCII Kannada */
    { 57009, NULL },          /* ISCII Malayalam */
    { 57010, NULL },          /* ISCII Gujarati */
    { 57011, NULL },          /* ISCII Punjabi */
    { 65000, "UTF-7" },       /* Unicode (UTF-7) */
    { 65001, "UTF-8" }        /* Unicode (UTF-8) */
};

static char *
ole2_convert_utf(summary_ctx_t *sctx, char *begin, size_t sz, const char *encoding)
{
#if HAVE_ICONV
    char *res=NULL;
    char *buf, *outbuf, *p1, *p2;
    size_t inlen, outlen, nonrev, sz2;
    int i, try;
    iconv_t cd;

    buf = cli_calloc(1, sz);
    if (!(buf))
        return NULL;

    memcpy(buf, begin, sz);

    outbuf = NULL;
    inlen = sz;

    /* encoding lookup if not specified */
    if (!encoding) {
        for (i = 0; i < NUMCODEPAGES; ++i) {
            if (sctx->codepage == codepage_entries[i].codepage)
                encoding = codepage_entries[i].encoding;
            else if (sctx->codepage < codepage_entries[i].codepage) {
                /* assuming sorted array */
                break;
            }
        }

        if (!encoding) {
            cli_warnmsg("ole2_convert_utf: could not locate codepage encoding for %d\n", sctx->codepage);
            sctx->flags |= OLE2_CODEPAGE_ERROR_NOTFOUND;
            free(buf);
            return NULL;
        }
    }

    cd = iconv_open("UTF-8", encoding);
    if (cd == (iconv_t)(-1)) {
        cli_errmsg("ole2_convert_utf: could not initialize iconv\n");
        sctx->flags |= OLE2_CODEPAGE_ERROR_UNINITED;
    }
    else {
        for (try = 1; try <= 3; ++try) {
            p1 = buf;

            if (outbuf)
                free(outbuf);
            outlen = sz2 = (try*2) * sz;
            p2 = outbuf = cli_calloc(1, sz2);
            if (!outbuf) {
                free(buf);
                return NULL;
            }

            nonrev = iconv(cd, (char **)(&p1), &inlen, &p2, &outlen);

            if (errno == EILSEQ) {
                cli_dbgmsg("ole2_convert_utf: input buffer contains invalid character for its encoding\n");
                sctx->flags |= OLE2_CODEPAGE_ERROR_INVALID;
                break;
            }
            else if (errno == EINVAL && nonrev == (size_t)-1) {
                cli_dbgmsg("ole2_convert_utf: input buffer contains incomplete multibyte character\n");
                sctx->flags |= OLE2_CODEPAGE_ERROR_INCOMPLETE;
                break;
            }
            else if (inlen == 0) {
                //cli_dbgmsg("ole2_convert_utf: input buffer is successfully translated\n");
                break;
            }

            cli_dbgmsg("ole2_convert_utf: outbuf is too small, resizing %llu -> %llu\n",
                       (long long unsigned)((try*2) * sz), (long long unsigned)(((try+1)*2) * sz));
        }

        if (inlen != 0 || (errno == E2BIG && nonrev == (size_t)-1)) {
            cli_dbgmsg("ole2_convert_utf: buffer could not be fully translated\n");
            sctx->flags |= OLE2_CODEPAGE_ERROR_OUTBUFTOOSMALL;
        }

        outbuf[sz2 - outlen] = '\0';
        res = strdup(outbuf);
    }

    iconv_close(cd);
    free(buf);
    free(outbuf);
    return res;
#else
    /* this should force base64 encoding */
    return NULL;
#endif
}

static int
ole2_process_property(summary_ctx_t *sctx, unsigned char *databuf, uint32_t offset)
{
    uint16_t proptype, padding;
    int ret = CL_SUCCESS;

    if (cli_json_timeout_cycle_check(sctx->ctx, &(sctx->toval)) != CL_SUCCESS) {
        sctx->flags |= OLE2_SUMMARY_FLAG_TIMEOUT;
        return CL_ETIMEOUT;
    }

    if (offset+sizeof(proptype)+sizeof(padding) > sctx->pssize) {
        sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
        return CL_EFORMAT;
    }

    memcpy(&proptype, databuf+offset, sizeof(proptype));
    offset+=sizeof(proptype);
    memcpy(&padding, databuf+offset, sizeof(padding));
    offset+=sizeof(padding);
    /* endian conversion */
    proptype = sum16_endian_convert(proptype);

    //cli_dbgmsg("proptype: 0x%04x\n", proptype);
    if (padding != 0) {
        cli_dbgmsg("ole2_process_property: invalid padding value, non-zero\n");
        sctx->flags |= OLE2_SUMMARY_ERROR_INVALID_ENTRY;
        return CL_EFORMAT;
    }

    switch (proptype) {
    case PT_EMPTY:
    case PT_NULL:
        ret = cli_jsonnull(sctx->summary, sctx->propname);
        break;
    case PT_INT16:
	{
            int16_t dout;
            if (offset+sizeof(dout) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&dout, databuf+offset, sizeof(dout));
            offset+=sizeof(dout);
            /* endian conversion */
            dout = sum16_endian_convert(dout);

            if (sctx->writecp)
                sctx->codepage = dout;

            ret = cli_jsonint(sctx->summary, sctx->propname, dout);
            break;
	}
    case PT_INT32:
    case PT_INT32v1:
	{
            int32_t dout;
            if (offset+sizeof(dout) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&dout, databuf+offset, sizeof(dout));
            offset+=sizeof(dout);
            /* endian conversion */
            dout = sum32_endian_convert(dout);

            ret = cli_jsonint(sctx->summary, sctx->propname, dout);
            break;
	}
    case PT_FLOAT32: /* review this please */
	{
            float dout;
            if (offset+sizeof(dout) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&dout, databuf+offset, sizeof(dout));
            offset+=sizeof(dout);
            /* endian conversion */
            dout = sum32_endian_convert(dout);

            ret = cli_jsondouble(sctx->summary, sctx->propname, dout);
            break;
	}
    case PT_DATE:
    case PT_DOUBLE64: /* review this please */
	{
            double dout;
            if (offset+sizeof(dout) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&dout, databuf+offset, sizeof(dout));
            offset+=sizeof(dout);
            /* endian conversion */
            dout = sum64_endian_convert(dout);

            ret = cli_jsondouble(sctx->summary, sctx->propname, dout);
            break;
	}
    case PT_BOOL:
	{
            uint16_t dout;
            if (offset+sizeof(dout) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&dout, databuf+offset, sizeof(dout));
            offset+=sizeof(dout);
            /* no need for endian conversion */

            ret = cli_jsonbool(sctx->summary, sctx->propname, dout);
            break;
	}
    case PT_INT8v1:
	{
            int8_t dout;
            if (offset+sizeof(dout) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&dout, databuf+offset, sizeof(dout));
            offset+=sizeof(dout);
            /* no need for endian conversion */

            ret = cli_jsonint(sctx->summary, sctx->propname, dout);
            break;
	}
    case PT_UINT8:
	{
            uint8_t dout;
            if (offset+sizeof(dout) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&dout, databuf+offset, sizeof(dout));
            offset+=sizeof(dout);
            /* no need for endian conversion */

            ret = cli_jsonint(sctx->summary, sctx->propname, dout);
            break;
	}
    case PT_UINT16:
	{
            uint16_t dout;
            if (offset+sizeof(dout) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&dout, databuf+offset, sizeof(dout));
            offset+=sizeof(dout);
            /* endian conversion */
            dout = sum16_endian_convert(dout);

            if (sctx->writecp)
                sctx->codepage = dout;

            ret = cli_jsonint(sctx->summary, sctx->propname, dout);
            break;
	}
    case PT_UINT32:
    case PT_UINT32v1:
	{
            uint32_t dout;
            if (offset+sizeof(dout) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&dout, databuf+offset, sizeof(dout));
            offset+=sizeof(dout);
            /* endian conversion */
            dout = sum32_endian_convert(dout);

            ret = cli_jsonint(sctx->summary, sctx->propname, dout);
            break;
	}
    case PT_INT64:
	{
            int64_t dout;
            if (offset+sizeof(dout) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&dout, databuf+offset, sizeof(dout));
            offset+=sizeof(dout);
            /* endian conversion */
            dout = sum64_endian_convert(dout);

            ret = cli_jsonint64(sctx->summary, sctx->propname, dout);
            break;
	}
    case PT_UINT64:
	{
            uint64_t dout;
            if (offset+sizeof(dout) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&dout, databuf+offset, sizeof(dout));
            offset+=sizeof(dout);
            /* endian conversion */
            dout = sum64_endian_convert(dout);

            ret = cli_jsonint64(sctx->summary, sctx->propname, dout);
            break;
	}
    case PT_BSTR:
    case PT_LPSTR:
        if (sctx->codepage == 0) {
            cli_dbgmsg("ole2_propset_json: current codepage is unknown, cannot parse char stream\n");
            sctx->flags |= OLE2_SUMMARY_FLAG_CODEPAGE;
            break;
        }
        else if (sctx->codepage != WINUNICODE) {
            uint32_t strsize;
            char *outstr, *outstr2;

            if (offset+sizeof(strsize) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }

            memcpy(&strsize, databuf+offset, sizeof(strsize));
            offset+=sizeof(strsize);
            /* endian conversion */
            strsize = sum32_endian_convert(strsize);

            if (offset+strsize > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }

            /* limitation on string length */
            if (strsize > PROPSTRLIMIT) {
                cli_dbgmsg("ole2_process_property: property string sized %lu truncated to size %lu\n",
                           (unsigned long)strsize, (unsigned long)PROPSTRLIMIT);
                sctx->flags |= OLE2_SUMMARY_FLAG_TRUNC_STR;
                strsize = PROPSTRLIMIT;
            }

            outstr = cli_calloc(strsize+1, 1); /* last char must be NULL */
            if (!outstr) {
                return CL_EMEM;
            }
            strncpy(outstr, (const char *)(databuf+offset), strsize);

            /* conversion of various encodings to UTF-8 */
            outstr2 = ole2_convert_utf(sctx, outstr, strsize, NULL);
            if (!outstr2) {
                /* use base64 encoding when all else fails! */
                char b64jstr[PROPSTRLIMIT];

                outstr2 = cl_base64_encode(outstr, strsize);
                if (!outstr2) {
                    free(outstr);
                    return CL_EMEM;
                }

                snprintf(b64jstr, PROPSTRLIMIT, "%s_base64", sctx->propname);
                ret = cli_jsonbool(sctx->summary, b64jstr, 1);
                if (ret != CL_SUCCESS)
                    return ret;
            }

            ret = cli_jsonstr(sctx->summary, sctx->propname, outstr2);
            free(outstr);
            free(outstr2);
            break;
        }
        /* fall-through for unicode strings */
    case PT_LPWSTR:
	{
            uint32_t strsize;
            char *outstr, *outstr2;

            if (offset+sizeof(strsize) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&strsize, databuf+offset, sizeof(strsize));
            offset+=sizeof(strsize);
            /* endian conversion */
            strsize = sum32_endian_convert(strsize);
            
            if (proptype == PT_LPSTR) { /* fall-through specifics */
                if (strsize % 2) {
                    cli_dbgmsg("ole2_process_property: LPSTR using wchar not sized a multiple of 2\n");
                    sctx->flags |= OLE2_SUMMARY_ERROR_INVALID_ENTRY;
                    return CL_EFORMAT;
                }
            }
            else {
                strsize*=2; /* Unicode strings are by length, not size */
            }

            /* limitation on string length */
            if (strsize > (2*PROPSTRLIMIT)) {
                cli_dbgmsg("ole2_process_property: property string sized %lu truncated to size %lu\n",
                           (unsigned long)strsize, (unsigned long)(2*PROPSTRLIMIT));
                sctx->flags |= OLE2_SUMMARY_FLAG_TRUNC_STR;
                strsize = (2*PROPSTRLIMIT);
            }

            if (offset+strsize > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            outstr = cli_calloc(strsize+2, 1); /* last two chars must be NULL */
            if (!outstr) {
                return CL_EMEM;
            }
            memcpy(outstr, (const char *)(databuf+offset), strsize);
            /* conversion of 16-width char strings to UTF-8 */
            outstr2 = ole2_convert_utf(sctx, outstr, strsize, "UTF-16");
            if (!outstr2) {
                /* use base64 encoding when all else fails! */
                char b64jstr[PROPSTRLIMIT];

                outstr2 = cl_base64_encode(outstr, strsize);
                if (!outstr2) {
                    free(outstr);
                    return CL_EMEM;
                }

                snprintf(b64jstr, PROPSTRLIMIT, "%s_base64", sctx->propname);
                ret = cli_jsonbool(sctx->summary, b64jstr, 1);
                if (ret != CL_SUCCESS)
                    return ret;
            }

            ret = cli_jsonstr(sctx->summary, sctx->propname, outstr2);
            free(outstr);
            free(outstr2);
            break;
	}
    case PT_FILETIME:
	{
            uint32_t ltime, htime;
            uint64_t wtime = 0, utime =0;

            if (offset+sizeof(ltime)+sizeof(htime) > sctx->pssize) {
                sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
                return CL_EFORMAT;
            }
            memcpy(&ltime, databuf+offset, sizeof(ltime));
            offset+=sizeof(ltime);
            memcpy(&htime, databuf+offset, sizeof(htime));
            offset+=sizeof(ltime);
            ltime = sum32_endian_convert(ltime);
            htime = sum32_endian_convert(htime);

            /* UNIX timestamp formatting */
            wtime = htime;
            wtime <<= 32;
            wtime |= ltime;

            utime = wtime / 10000000;
            utime -= 11644473600LL;

            if ((uint32_t)((utime & 0xFFFFFFFF00000000) >> 32)) {
                cli_dbgmsg("ole2_process_property: UNIX timestamp is larger than 32-bit number\n");
            }
            else {
                ret = cli_jsonint(sctx->summary, sctx->propname, (uint32_t)(utime & 0xFFFFFFFF));
            }
            break;
	}
    default:
        cli_dbgmsg("ole2_process_property: unhandled property type 0x%04x for %s property\n", 
                   proptype, sctx->propname);
        sctx->flags |= OLE2_SUMMARY_FLAG_UNHANDLED_PROPTYPE;
    }

    return ret;
}

static void ole2_translate_docsummary_propid(summary_ctx_t *sctx, uint32_t propid)
{
    switch(propid) {
    case DSPID_CODEPAGE:
        sctx->writecp = 1; /* must be set ONLY for codepage */
        sctx->propname = "CodePage";
        break;
    case DSPID_CATEGORY:
        sctx->propname = "Category";
        break;
    case DSPID_PRESFORMAT:
        sctx->propname = "PresentationTarget";
        break;
    case DSPID_BYTECOUNT:
        sctx->propname = "Bytes";
        break;
    case DSPID_LINECOUNT:
        sctx->propname = "Lines";
        break;
    case DSPID_PARCOUNT:
        sctx->propname = "Paragraphs";
        break;
    case DSPID_SLIDECOUNT:
        sctx->propname = "Slides";
        break;
    case DSPID_NOTECOUNT:
        sctx->propname = "Notes";
        break;
    case DSPID_HIDDENCOUNT:
        sctx->propname = "HiddenSlides";
        break;
    case DSPID_MMCLIPCOUNT:
        sctx->propname = "MMClips";
        break;
    case DSPID_SCALE:
        sctx->propname = "Scale";
        break;
    case DSPID_HEADINGPAIR: /* VT_VARIANT | VT_VECTOR */
        sctx->propname = "HeadingPairs";
        break;
    case DSPID_DOCPARTS:    /* VT_VECTOR | VT_LPSTR */
        sctx->propname = "DocPartTitles";
        break;
    case DSPID_MANAGER:
        sctx->propname = "Manager";
        break;
    case DSPID_COMPANY:
        sctx->propname = "Company";
        break;
    case DSPID_LINKSDIRTY:
        sctx->propname = "LinksDirty";
        break;
    case DSPID_CCHWITHSPACES:
        sctx->propname = "Char&WSCount";
        break;
    case DSPID_SHAREDDOC:   /* SHOULD BE FALSE! */
        sctx->propname = "SharedDoc";
        break;
    case DSPID_LINKBASE:    /* moved to user-defined */
        sctx->propname = "LinkBase";
        break;
    case DSPID_HLINKS:      /* moved to user-defined */
        sctx->propname = "HyperLinks";
        break;
    case DSPID_HYPERLINKSCHANGED:
        sctx->propname = "HyperLinksChanged";
        break;
    case DSPID_VERSION:
        sctx->propname = "Version";
        break;
    case DSPID_DIGSIG:
        sctx->propname = "DigitalSig";
        break;
    case DSPID_CONTENTTYPE:
        sctx->propname = "ContentType";
        break;
    case DSPID_CONTENTSTATUS:
        sctx->propname = "ContentStatus";
        break;
    case DSPID_LANGUAGE:
        sctx->propname = "Language";
        break;
    case DSPID_DOCVERSION:
        sctx->propname = "DocVersion";
        break;
    default:
        cli_dbgmsg("ole2_docsum_propset_json: unrecognized propid!\n");
        sctx->flags |= OLE2_SUMMARY_FLAG_UNKNOWN_PROPID;
    }
}

static void ole2_translate_summary_propid(summary_ctx_t *sctx, uint32_t propid)
{
    switch(propid) {
    case SPID_CODEPAGE:
        sctx->writecp = 1; /* must be set ONLY for codepage */
        sctx->propname = "CodePage";
        break;
    case SPID_TITLE:
        sctx->propname = "Title";
        break;
    case SPID_SUBJECT:
        sctx->propname = "Subject";
        break;
    case SPID_AUTHOR:
        sctx->propname = "Author";
        break;
    case SPID_KEYWORDS:
        sctx->propname = "Keywords";
        break;
    case SPID_COMMENTS:
        sctx->propname = "Comments";
        break;
    case SPID_TEMPLATE:
        sctx->propname = "Template";
        break;
    case SPID_LASTAUTHOR:
        sctx->propname = "LastAuthor";
        break;
    case SPID_REVNUMBER:
        sctx->propname = "RevNumber";
        break;
    case SPID_EDITTIME:
        sctx->propname = "EditTime";
        break;
    case SPID_LASTPRINTED:
        sctx->propname = "LastPrinted";
        break;
    case SPID_CREATEDTIME:
        sctx->propname = "CreatedTime";
        break;
    case SPID_MODIFIEDTIME:
        sctx->propname = "ModifiedTime";
        break;
    case SPID_PAGECOUNT:
        sctx->propname = "PageCount";
        break;
    case SPID_WORDCOUNT:
        sctx->propname = "WordCount";
        break;
    case SPID_CHARCOUNT:
        sctx->propname = "CharCount";
        break;
    case SPID_THUMBNAIL:
        sctx->propname = "Thumbnail";
        break;
    case SPID_APPNAME:
        sctx->propname = "AppName";
        break;
    case SPID_SECURITY:
        sctx->propname = "Security";
        break;
    default:
        cli_dbgmsg("ole2_translate_summary_propid: unrecognized propid!\n");
        sctx->flags |= OLE2_SUMMARY_FLAG_UNKNOWN_PROPID;
    }
}

static int ole2_summary_propset_json(summary_ctx_t *sctx, off_t offset)
{
    unsigned char *hdr, *ps;
    uint32_t numprops, limitprops;
    off_t foff = offset, psoff = 0;
    uint32_t poffset;
    int ret;
    unsigned int i;

    cli_dbgmsg("in ole2_summary_propset_json\n");

    /* summary ctx propset-specific setup*/
    sctx->codepage = 0;
    sctx->writecp = 0;
    sctx->propname = NULL;

    /* examine property set metadata */
    if ((foff+(2*sizeof(uint32_t))) > sctx->maplen) {
        sctx->flags |= OLE2_SUMMARY_ERROR_TOOSMALL;
        return CL_EFORMAT;
    }
    hdr = (unsigned char*)fmap_need_off_once(sctx->sfmap, foff, (2*sizeof(uint32_t)));
    if (!hdr) {
        sctx->flags |= OLE2_SUMMARY_ERROR_DATABUF;
        return CL_EREAD;
    }
    //foff+=(2*sizeof(uint32_t)); // keep foff pointing to start of propset segment
    psoff+=(2*sizeof(uint32_t));
    memcpy(&(sctx->pssize), hdr, sizeof(sctx->pssize));
    memcpy(&numprops, hdr+sizeof(sctx->pssize), sizeof(numprops));
    /* endian conversion */
    sctx->pssize = sum32_endian_convert(sctx->pssize);
    numprops = sum32_endian_convert(numprops);
    cli_dbgmsg("ole2_summary_propset_json: pssize: %u, numprops: %u\n", sctx->pssize, numprops);
    if (numprops > PROPCNTLIMIT) {
        sctx->flags |= OLE2_SUMMARY_LIMIT_PROPS;
        limitprops = PROPCNTLIMIT;
    }
    else {
        limitprops = numprops;
    }
    cli_dbgmsg("ole2_summary_propset_json: processing %u of %u (%u max) propeties\n",
               limitprops, numprops, PROPCNTLIMIT);

    /* extract remaining fragment of propset */
    if ((size_t)(foff+(sctx->pssize)) > (size_t)(sctx->maplen)) {
        sctx->flags |= OLE2_SUMMARY_ERROR_TOOSMALL;
        return CL_EFORMAT;
    }
    ps = (unsigned char*)fmap_need_off_once(sctx->sfmap, foff, sctx->pssize);
    if (!ps) {
        sctx->flags |= OLE2_SUMMARY_ERROR_DATABUF;
        return CL_EREAD;
    }

    /* iterate over the properties */
    for (i = 0; i < limitprops; ++i) {
        uint32_t propid, propoff;

        if (psoff+sizeof(propid)+sizeof(poffset) > sctx->pssize) {
            sctx->flags |= OLE2_SUMMARY_ERROR_OOB;
            return CL_EFORMAT;
        }
        memcpy(&propid, ps+psoff, sizeof(propid));
        psoff+=sizeof(propid);
        memcpy(&propoff, ps+psoff, sizeof(propoff));
        psoff+=sizeof(propoff);
        /* endian conversion */
        propid = sum32_endian_convert(propid);
        propoff = sum32_endian_convert(propoff);
        cli_dbgmsg("ole2_summary_propset_json: propid: 0x%08x, propoff: %u\n", propid, propoff);

        sctx->propname = NULL; sctx->writecp = 0;
        if (!sctx->mode)
            ole2_translate_summary_propid(sctx, propid);
        else
            ole2_translate_docsummary_propid(sctx, propid);

        if (sctx->propname != NULL) {
            ret = ole2_process_property(sctx, ps, propoff);
            if (ret != CL_SUCCESS)
                return ret;
        }
        else {
            /* add unknown propid flag */
        }
    }

    return CL_SUCCESS;
}

static int cli_ole2_summary_json_cleanup(summary_ctx_t *sctx, int retcode)
{
    json_object *jarr;

    cli_dbgmsg("in cli_ole2_summary_json_cleanup: %d[%x]\n", retcode, sctx->flags);

    if (sctx->sfmap) {
        funmap(sctx->sfmap);
    }

    if (sctx->flags) {
        jarr = cli_jsonarray(sctx->summary, "ParseErrors");

        /* summary errors */
        if (sctx->flags & OLE2_SUMMARY_ERROR_TOOSMALL) {
            cli_jsonstr(jarr, NULL, "OLE2_SUMMARY_ERROR_TOOSMALL");
        }
        if (sctx->flags & OLE2_SUMMARY_ERROR_OOB) {
            cli_jsonstr(jarr, NULL, "OLE2_SUMMARY_ERROR_OOB");
        }
        if (sctx->flags & OLE2_SUMMARY_ERROR_DATABUF) {
            cli_jsonstr(jarr, NULL, "OLE2_SUMMARY_ERROR_DATABUF");
        }
        if (sctx->flags & OLE2_SUMMARY_ERROR_INVALID_ENTRY) {
            cli_jsonstr(jarr, NULL, "OLE2_SUMMARY_ERROR_INVALID_ENTRY");
        }
        if (sctx->flags & OLE2_SUMMARY_LIMIT_PROPS) {
            cli_jsonstr(jarr, NULL, "OLE2_SUMMARY_LIMIT_PROPS");
        }
        if (sctx->flags & OLE2_SUMMARY_FLAG_TIMEOUT) {
            cli_jsonstr(jarr, NULL, "OLE2_SUMMARY_FLAG_TIMEOUT");
        }
        if (sctx->flags & OLE2_SUMMARY_FLAG_CODEPAGE) {
            cli_jsonstr(jarr, NULL, "OLE2_SUMMARY_FLAG_CODEPAGE");
        }
        if (sctx->flags & OLE2_SUMMARY_FLAG_UNKNOWN_PROPID) {
            cli_jsonstr(jarr, NULL, "OLE2_SUMMARY_FLAG_UNKNOWN_PROPID");
        }
        if (sctx->flags & OLE2_SUMMARY_FLAG_UNHANDLED_PROPTYPE) {
            cli_jsonstr(jarr, NULL, "OLE2_SUMMARY_FLAG_UNHANDLED_PROPTYPE");
        }
        if (sctx->flags & OLE2_SUMMARY_FLAG_TRUNC_STR) {
            cli_jsonstr(jarr, NULL, "OLE2_SUMMARY_FLAG_TRUNC_STR");
        }

        /* codepage translation errors */
        if (sctx->flags & OLE2_CODEPAGE_ERROR_NOTFOUND) {
            cli_jsonstr(jarr, NULL, "OLE2_CODEPAGE_ERROR_NOTFOUND");
        }
        if (sctx->flags & OLE2_CODEPAGE_ERROR_UNINITED) {
            cli_jsonstr(jarr, NULL, "OLE2_CODEPAGE_ERROR_UNINITED");
        }
        if (sctx->flags & OLE2_CODEPAGE_ERROR_INVALID) {
            cli_jsonstr(jarr, NULL, "OLE2_CODEPAGE_ERROR_INVALID");
        }
        if (sctx->flags & OLE2_CODEPAGE_ERROR_INCOMPLETE) {
            cli_jsonstr(jarr, NULL, "OLE2_CODEPAGE_ERROR_INCOMPLETE");
        }
        if (sctx->flags & OLE2_CODEPAGE_ERROR_OUTBUFTOOSMALL) {
            cli_jsonstr(jarr, NULL, "OLE2_CODEPAGE_ERROR_OUTBUFTOOSMALL");
        }
    }

    return retcode;
}


#endif /* HAVE_JSON */

#if HAVE_JSON
int cli_ole2_summary_json(cli_ctx *ctx, int fd, int mode)
{
    summary_ctx_t sctx;
    STATBUF statbuf;
    off_t foff = 0;
    unsigned char *databuf;
    summary_stub_t sumstub;
    propset_entry_t pentry;
    int ret = CL_SUCCESS;

    cli_dbgmsg("in cli_ole2_summary_json\n");

    /* preliminary sanity checks */
    if (ctx == NULL) {
        return CL_ENULLARG;
    }

    if (fd < 0) {
        cli_dbgmsg("ole2_summary_json: invalid file descriptor\n");
        return CL_ENULLARG; /* placeholder */
    }

    if (mode != 0 && mode != 1) {
        cli_dbgmsg("ole2_summary_json: invalid mode specified\n");
        return CL_ENULLARG; /* placeholder */
    }

    /* summary ctx setup */
    memset(&sctx, 0, sizeof(sctx));
    sctx.ctx = ctx;
    sctx.mode = mode;

    if (FSTAT(fd, &statbuf) == -1) {
        cli_dbgmsg("ole2_summary_json: cannot stat file descriptor\n");
        return CL_ESTAT;
    }

    sctx.sfmap = fmap(fd, 0, statbuf.st_size);
    if (!sctx.sfmap) {
        cli_dbgmsg("ole2_summary_json: failed to get fmap\n");
        return CL_EMAP;
    }
    sctx.maplen = sctx.sfmap->len;
    cli_dbgmsg("ole2_summary_json: streamsize: %u\n", sctx.maplen);

    if (!mode)
        sctx.summary = cli_jsonobj(ctx->wrkproperty, "SummaryInfo");
    else
        sctx.summary = cli_jsonobj(ctx->wrkproperty, "DocSummaryInfo");
    if (!sctx.summary) {
        cli_errmsg("ole2_summary_json: no memory for json object.\n");
        return cli_ole2_summary_json_cleanup(&sctx, CL_EMEM);
    }

    sctx.codepage = 0;
    sctx.writecp = 0;

    /* acquire property stream metadata */
    if (sctx.maplen < sizeof(summary_stub_t)) {
        sctx.flags |= OLE2_SUMMARY_ERROR_TOOSMALL;
        return cli_ole2_summary_json_cleanup(&sctx, CL_EFORMAT);
    }
    databuf = (unsigned char*)fmap_need_off_once(sctx.sfmap, foff, sizeof(summary_stub_t));
    if (!databuf) {
        sctx.flags |= OLE2_SUMMARY_ERROR_DATABUF;
        return cli_ole2_summary_json_cleanup(&sctx, CL_EREAD);
    }
    foff += sizeof(summary_stub_t);
    memcpy(&sumstub, databuf, sizeof(summary_stub_t));

    /* endian conversion and checks */
    sumstub.byte_order = le16_to_host(sumstub.byte_order);
    if (sumstub.byte_order != 0xfffe) {
        cli_dbgmsg("ole2_summary_json: byteorder 0x%x is invalid\n", sumstub.byte_order);
        sctx.flags |= OLE2_SUMMARY_ERROR_INVALID_ENTRY;
        return cli_ole2_summary_json_cleanup(&sctx, CL_EFORMAT);;
    }
    sumstub.version = sum16_endian_convert(sumstub.version); /*unused*/
    sumstub.system = sum32_endian_convert(sumstub.system); /*unused*/
    sumstub.num_propsets = sum32_endian_convert(sumstub.num_propsets);
    if (sumstub.num_propsets != 1 && sumstub.num_propsets != 2) {
        cli_dbgmsg("ole2_summary_json: invalid number of property sets\n");
        sctx.flags |= OLE2_SUMMARY_ERROR_INVALID_ENTRY;
        return cli_ole2_summary_json_cleanup(&sctx, CL_EFORMAT);
    }

    cli_dbgmsg("ole2_summary_json: byteorder 0x%x\n", sumstub.byte_order);
    cli_dbgmsg("ole2_summary_json: %u property set(s) detected\n", sumstub.num_propsets);

    /* first property set (index=0) is always SummaryInfo or DocSummaryInfo */
    if ((sctx.maplen-foff) < sizeof(propset_entry_t)) {
        sctx.flags |= OLE2_SUMMARY_ERROR_TOOSMALL;
        return cli_ole2_summary_json_cleanup(&sctx, CL_EFORMAT);
    }
    databuf = (unsigned char*)fmap_need_off_once(sctx.sfmap, foff, sizeof(propset_entry_t));
    if (!databuf) {
        sctx.flags |= OLE2_SUMMARY_ERROR_DATABUF;
        return cli_ole2_summary_json_cleanup(&sctx, CL_EREAD);
    }
    foff += sizeof(propset_entry_t);
    memcpy(&pentry, databuf, sizeof(propset_entry_t));
    /* endian conversion */
    pentry.offset = sum32_endian_convert(pentry.offset);

    if ((ret = ole2_summary_propset_json(&sctx, pentry.offset)) != CL_SUCCESS) {
        return cli_ole2_summary_json_cleanup(&sctx, ret);
    }

    /* second property set (index=1) is always a custom property set (if present) */
    if (sumstub.num_propsets == 2) {
        cli_jsonbool(ctx->wrkproperty, "HasUserDefinedProperties", 1);
    }

    return cli_ole2_summary_json_cleanup(&sctx, CL_SUCCESS);
}
#endif /* HAVE_JSON */
