/*
 *  Copyright (C) 2013-2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdbool.h>

#include "clamav.h"
#include "others.h"
#include "hwp.h"
#include "ole2_extract.h"
#include "xlm_extract.h"
#include "scanners.h"
#include "fmap.h"
#include "json_api.h"
#if HAVE_JSON
#include "msdoc.h"
#endif

#ifdef DEBUG_OLE2_LIST
#define ole2_listmsg(...) cli_dbgmsg(__VA_ARGS__)
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
    unsigned char magic[8]; /* should be: 0xd0cf11e0a1b11ae1 */
    unsigned char clsid[16];
    uint16_t minor_version __attribute__((packed));
    uint16_t dll_version __attribute__((packed));
    int16_t byte_order __attribute__((packed)); /* -2=intel */

    uint16_t log2_big_block_size __attribute__((packed));   /* usually 9 (2^9 = 512) */
    uint32_t log2_small_block_size __attribute__((packed)); /* usually 6 (2^6 = 64) */

    int32_t reserved[2] __attribute__((packed));
    int32_t bat_count __attribute__((packed));
    int32_t prop_start __attribute__((packed));

    uint32_t signature __attribute__((packed));
    uint32_t sbat_cutoff __attribute__((packed)); /* cutoff for files held
                                                         * in small blocks
                                                         * (4096) */

    int32_t sbat_start __attribute__((packed));
    int32_t sbat_block_count __attribute__((packed));
    int32_t xbat_start __attribute__((packed));
    int32_t xbat_count __attribute__((packed));
    int32_t bat_array[109] __attribute__((packed));

    /*
     * The following is not part of the ole2 header, but stuff we need in
     * order to decode.
     *
     * IMPORANT: These must take account of the size of variables below here
     * when calculating hdr_size to read the header.
     *
     * See the top of cli_ole2_extract().
     */
    int32_t sbat_root_start __attribute__((packed));
    uint32_t max_block_no;
    off_t m_length;
    bitset_t *bitset;
    struct uniq *U;
    fmap_t *map;
    bool has_vba;
    bool has_xlm;
    bool has_image;
    hwp5_header_t *is_hwp;
} ole2_header_t;

typedef struct property_tag {
    char name[64]; /* in unicode */
    uint16_t name_size __attribute__((packed));
    unsigned char type;  /* 1=dir 2=file 5=root */
    unsigned char color; /* black or red */
    uint32_t prev __attribute__((packed));
    uint32_t next __attribute__((packed));
    uint32_t child __attribute__((packed));

    unsigned char clsid[16];
    uint32_t user_flags __attribute__((packed));

    uint32_t create_lowdate __attribute__((packed));
    uint32_t create_highdate __attribute__((packed));
    uint32_t mod_lowdate __attribute__((packed));
    uint32_t mod_highdate __attribute__((packed));
    uint32_t start_block __attribute__((packed));
    uint32_t size __attribute__((packed));
    unsigned char reserved[4];
} property_t;

struct ole2_list_node;

typedef struct ole2_list_node {
    uint32_t Val;
    struct ole2_list_node *Next;
} ole2_list_node_t;

typedef struct ole2_list {
    uint32_t Size;
    ole2_list_node_t *Head;
} ole2_list_t;

int ole2_list_init(ole2_list_t *list);
int ole2_list_is_empty(ole2_list_t *list);
uint32_t ole2_list_size(ole2_list_t *list);
int ole2_list_push(ole2_list_t *list, uint32_t val);
uint32_t ole2_list_pop(ole2_list_t *list);
int ole2_list_delete(ole2_list_t *list);

int ole2_list_init(ole2_list_t *list)
{
    list->Head = NULL;
    list->Size = 0;
    return CL_SUCCESS;
}

int ole2_list_is_empty(ole2_list_t *list)
{
    return (list->Head == NULL);
}

uint32_t
ole2_list_size(ole2_list_t *list)
{
    return (list->Size);
}

int ole2_list_push(ole2_list_t *list, uint32_t val)
{
    ole2_list_node_t * new_node = NULL;
    int status = CL_EMEM;

    CLI_MALLOC(new_node, sizeof(ole2_list_node_t), 
            cli_dbgmsg("OLE2: could not allocate new node for worklist!\n"));

    new_node->Val  = val;
    new_node->Next = list->Head;

    list->Head = new_node;
    (list->Size)++;

    status = CL_SUCCESS;
done:
    return status;
}

uint32_t
ole2_list_pop(ole2_list_t *list)
{
    uint32_t val;
    ole2_list_node_t *next;

    if (ole2_list_is_empty(list)) {
        cli_dbgmsg("OLE2: work list is empty and ole2_list_pop() called!\n");
        return -1;
    }
    val  = list->Head->Val;
    next = list->Head->Next;

    free(list->Head);
    list->Head = next;

    (list->Size)--;
    return val;
}

int ole2_list_delete(ole2_list_t *list)
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

char *
cli_ole2_get_property_name2(const char *name, int size)
{
    int i, j;
    char * newname = NULL;

    if ((name[0] == 0 && name[1] == 0) || size <= 0 || size > 128) {
        return NULL;
    }
    CLI_MALLOC(newname, size*7, 
        cli_errmsg("OLE2 [cli_ole2_get_property_name2]: Unable to allocate memory for newname: %u\n", size * 7));

    j = 0;
    /* size-2 to ignore trailing NULL */
    for (i = 0; i < size - 2; i += 2) {
        if ((!(name[i] & 0x80)) && isprint(name[i]) && name[i + 1] == 0) {
            newname[j++] = tolower(name[i]);
        } else {
            if (name[i] < 10 && name[i] >= 0 && name[i + 1] == 0) {
                newname[j++] = '_';
                newname[j++] = name[i] + '0';
            } else {
                const uint16_t x = (((uint16_t)name[i]) << 8) | name[i + 1];

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
        newname = NULL;
    }

done:
    return newname;
}

static char *
get_property_name(char *name, int size)
{
    const char *carray = "0123456789abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz._";
    int csize          = size >> 1;
    char * newname = NULL;
    char * cname = NULL;
    char *oname = name;

    if (csize <= 0) {
        return NULL;
    }

    CLI_MALLOC(newname, size, 
        cli_errmsg("OLE2 [get_property_name]: Unable to allocate memory for newname %u\n", size));
    cname = newname;

    while (--csize) {
        uint16_t lo, hi, u = cli_readint16(oname) - 0x3800;

        oname += 2;
        if (u > 0x1040) {
            FREE(newname);
            return cli_ole2_get_property_name2(name, size);
        }
        lo = u % 64;
        u >>= 6;
        hi       = u % 64;
        *cname++ = carray[lo];
        if (csize != 1 || u != 64) {
            *cname++ = carray[hi];
        }
    }
    *cname = '\0';
done:
    return newname;
}

static void
print_ole2_property(property_t *property)
{
    char spam[128], *buf;

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
print_ole2_header(ole2_header_t *hdr)
{
    if (!hdr || !cli_debug_flag) {
        return;
    }
    cli_dbgmsg("\n");
    cli_dbgmsg("Magic:\t\t\t0x%x%x%x%x%x%x%x%x\n",
               hdr->magic[0], hdr->magic[1], hdr->magic[2], hdr->magic[3],
               hdr->magic[4], hdr->magic[5], hdr->magic[6], hdr->magic[7]);

    cli_dbgmsg("CLSID:\t\t\t{%x%x%x%x-%x%x-%x%x-%x%x-%x%x%x%x%x%x}\n",
               hdr->clsid[0], hdr->clsid[1], hdr->clsid[2], hdr->clsid[3],
               hdr->clsid[4], hdr->clsid[5], hdr->clsid[6], hdr->clsid[7],
               hdr->clsid[8], hdr->clsid[9], hdr->clsid[10], hdr->clsid[11],
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
ole2_read_block(ole2_header_t *hdr, void *buff, unsigned int size, int32_t blockno)
{
    off_t offset, offend;
    const void *pblock;

    if (blockno < 0) {
        return FALSE;
    }
    /* other methods: (blockno+1) * 512 or (blockno * block_size) + 512; */
    if (((uint64_t)blockno << hdr->log2_big_block_size) < (INT32_MAX - MAX(512, (uint64_t)1 << hdr->log2_big_block_size))) {
        /* 512 is header size */
        offset = (blockno << hdr->log2_big_block_size) + MAX(512, 1 << hdr->log2_big_block_size);
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

static int32_t
ole2_get_next_bat_block(ole2_header_t *hdr, int32_t current_block)
{
    int32_t bat_array_index;
    uint32_t bat[128];

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

static int32_t
ole2_get_next_xbat_block(ole2_header_t *hdr, int32_t current_block)
{
    int32_t xbat_index, xbat_block_index, bat_index, bat_blockno;
    uint32_t xbat[128], bat[128];

    if (current_block < 0) {
        return -1;
    }
    xbat_index = current_block / 128;

    /*
     * NB:	The last entry in each XBAT points to the next XBAT block.
     * This reduces the number of entries in each block by 1.
     */
    xbat_block_index = (xbat_index - 109) / 127;
    bat_blockno      = (xbat_index - 109) % 127;

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

static int32_t
ole2_get_next_block_number(ole2_header_t *hdr, int32_t current_block)
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

static int32_t
ole2_get_next_sbat_block(ole2_header_t *hdr, int32_t current_block)
{
    int32_t iter, current_bat_block;
    uint32_t sbat[128];

    if (current_block < 0) {
        return -1;
    }
    current_bat_block = hdr->sbat_start;
    iter              = current_block / 128;
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
static int32_t
ole2_get_sbat_data_block(ole2_header_t *hdr, void *buff, int32_t sbat_index)
{
    int32_t block_count, current_block;

    if (sbat_index < 0) {
        return FALSE;
    }
    if (hdr->sbat_root_start < 0) {
        cli_dbgmsg("No root start block\n");
        return FALSE;
    }
    block_count   = sbat_index / (1 << (hdr->log2_big_block_size - hdr->log2_small_block_size));
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

/**
 * @brief File handler for use when walking ole2 property trees.
 *
 * @param hdr   The ole2 header metadata
 * @param prop  The property
 * @param dir   (optional) directory to write temp files to.
 * @param ctx   The scan context
 * @return cl_error_t
 */
typedef cl_error_t ole2_walk_property_tree_file_handler(ole2_header_t *hdr, property_t *prop, const char *dir, cli_ctx *ctx);

/**
 * @brief Walk an ole2 property tree, calling the handler for each file found
 *
 * @param hdr                   The ole2 header metadata (an ole2-specific context struct)
 * @param dir                   (optional) directory to write temp files to, passed to the handler.
 * @param prop_index            Index of the property being walked, to be recorded with a pointer to the root node in an ole2 node list.
 * @param handler               The file handler to call when a file is found.
 * @param rec_level             The recursion level. Max is 100.
 * @param[in,out] file_count    A running count of the total # of files. Max is 100000.
 * @param ctx                   The scan context
 * @param[in,out] scansize      A running sum of the file sizes processed.
 * @return int
 */
static int ole2_walk_property_tree(ole2_header_t *hdr, const char *dir, int32_t prop_index,
                                   ole2_walk_property_tree_file_handler handler,
                                   unsigned int rec_level, unsigned int *file_count, cli_ctx *ctx, unsigned long *scansize)
{
    property_t prop_block[4];
    int32_t idx, current_block, i, curindex;
    char *dirname;
    ole2_list_t node_list;
    int ret, func_ret;
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
    if ((ret = ole2_list_push(&node_list, prop_index)) != CL_SUCCESS) {
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
        if ((curindex < 0) || (curindex > (int32_t)hdr->max_block_no)) {
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

        prop_block[idx].name_size       = ole2_endian_convert_16(prop_block[idx].name_size);
        prop_block[idx].prev            = ole2_endian_convert_32(prop_block[idx].prev);
        prop_block[idx].next            = ole2_endian_convert_32(prop_block[idx].next);
        prop_block[idx].child           = ole2_endian_convert_32(prop_block[idx].child);
        prop_block[idx].user_flags      = ole2_endian_convert_32(prop_block[idx].user_flags);
        prop_block[idx].create_lowdate  = ole2_endian_convert_32(prop_block[idx].create_lowdate);
        prop_block[idx].create_highdate = ole2_endian_convert_32(prop_block[idx].create_highdate);
        prop_block[idx].mod_lowdate     = ole2_endian_convert_32(prop_block[idx].mod_lowdate);
        prop_block[idx].mod_highdate    = ole2_endian_convert_32(prop_block[idx].mod_highdate);
        prop_block[idx].start_block     = ole2_endian_convert_32(prop_block[idx].start_block);
        prop_block[idx].size            = ole2_endian_convert_32(prop_block[idx].size);

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
            case 5: /* Root Entry */
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
                        } else {
                            ole2_list_delete(&node_list);
                            return ret;
                        }
                    }
                }
                if ((int)(prop_block[idx].prev) != -1) {
                    if ((ret = ole2_list_push(&node_list, prop_block[idx].prev)) != CL_SUCCESS) {
                        ole2_list_delete(&node_list);
                        return ret;
                    }
                }
                if ((int)(prop_block[idx].next) != -1) {
                    if ((ret = ole2_list_push(&node_list, prop_block[idx].next)) != CL_SUCCESS) {
                        ole2_list_delete(&node_list);
                        return ret;
                    }
                }
                break;
            case 2: /* File */
                ole2_listmsg("file node\n");
                if (ctx && ctx->engine->maxfiles && ((*file_count > ctx->engine->maxfiles) || (ctx->scannedfiles > ctx->engine->maxfiles - *file_count))) {
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
                        } else {
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
                        } else {
                            ole2_list_delete(&node_list);
                            return ret;
                        }
                    }
                }
                if ((int)(prop_block[idx].prev) != -1) {
                    if ((ret = ole2_list_push(&node_list, prop_block[idx].prev)) != CL_SUCCESS) {
                        ole2_list_delete(&node_list);
                        return ret;
                    }
                }
                if ((int)(prop_block[idx].next) != -1) {
                    if ((ret = ole2_list_push(&node_list, prop_block[idx].next)) != CL_SUCCESS) {
                        ole2_list_delete(&node_list);
                        return ret;
                    }
                }
                break;
            case 1: /* Directory */
                ole2_listmsg("directory node\n");
                if (dir) {
#if HAVE_JSON
                    if (SCAN_COLLECT_METADATA && (ctx->wrkproperty != NULL)) {
                        if (!json_object_object_get_ex(ctx->wrkproperty, "DigitalSignatures", NULL)) {
                            name = cli_ole2_get_property_name2(prop_block[idx].name, prop_block[idx].name_size);
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
                        } else {
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
                    if ((ret = ole2_list_push(&node_list, prop_block[idx].prev)) != CL_SUCCESS) {
                        ole2_list_delete(&node_list);
                        return ret;
                    }
                }
                if ((int)(prop_block[idx].next) != -1) {
                    if ((ret = ole2_list_push(&node_list, prop_block[idx].next)) != CL_SUCCESS) {
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
static cl_error_t handler_writefile(ole2_header_t *hdr, property_t *prop, const char *dir, cli_ctx *ctx)
{
    cl_error_t ret = CL_BREAK;
    char newname[1024];
    char* name = NULL;
    unsigned char * buff = NULL;
    int32_t current_block = 0;
    size_t len = 0, offset = 0;
    int ofd = -1;
    char* hash = NULL;
    bitset_t* blk_bitset = NULL;
    uint32_t cnt = 0;

    UNUSEDPARAM(ctx);

    if (prop->type != 2) {
        /* Not a file */
        ret = CL_SUCCESS;
        goto done;
    }

    if (prop->name_size > 64) {
        cli_dbgmsg("OLE2 [handler_writefile]: property name too long: %d\n", prop->name_size);
        ret = CL_SUCCESS;
        goto done;
    }

    name = cli_ole2_get_property_name2(prop->name, prop->name_size);
    if (name) {
        cli_dbgmsg("Storing %s in uniq\n", name);
        if (CL_SUCCESS != uniq_add(hdr->U, name, strlen(name), &hash, &cnt)) {
            cli_dbgmsg("OLE2 [handler_writefile]: too many property names added to uniq store.\n");
            goto done;
        }
    } else {
        if (CL_SUCCESS != uniq_add(hdr->U, NULL, 0, &hash, &cnt)) {
            cli_dbgmsg("OLE2 [handler_writefile]: too many property names added to uniq store.\n");
            goto done;
        }
    }

    snprintf(newname, sizeof(newname), "%s" PATHSEP "%s_%u", dir, hash, cnt);
    newname[sizeof(newname) - 1] = '\0';
    cli_dbgmsg("OLE2 [handler_writefile]: Dumping '%s' to '%s'\n", name ? name : "<empty>", newname);

    ofd = open(newname, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR);
    if (ofd < 0) {
        cli_errmsg("OLE2 [handler_writefile]: failed to create file: %s\n", newname);
        ret = CL_SUCCESS;
        goto done;
    }

    current_block = prop->start_block;
    len           = prop->size;

    CLI_MALLOC(buff, 1 << hdr->log2_big_block_size, 
        cli_errmsg("OLE2 [handler_writefile]: Unable to allocate memory for buff: %u\n", 1 << hdr->log2_big_block_size);
        ret = CL_EMEM);

    blk_bitset = cli_bitset_init();
    if (!blk_bitset) {
        cli_errmsg("OLE2 [handler_writefile]: init bitset failed\n");
        goto done;
    }

    while ((current_block >= 0) && (len > 0)) {
        if (current_block > (int32_t)hdr->max_block_no) {
            cli_dbgmsg("OLE2 [handler_writefile]: Max block number for file size exceeded: %d\n", current_block);
            break;
        }

        /* Check we aren't in a loop */
        if (cli_bitset_test(blk_bitset, (unsigned long)current_block)) {
            /* Loop in block list */
            cli_dbgmsg("OLE2 [handler_writefile]: Block list loop detected\n");
            break;
        }

        if (!cli_bitset_set(blk_bitset, (unsigned long)current_block)) {
            break;
        }

        if (prop->size < (int64_t)hdr->sbat_cutoff) {
            /* Small block file */
            if (!ole2_get_sbat_data_block(hdr, buff, current_block)) {
                cli_dbgmsg("OLE2 [handler_writefile]: ole2_get_sbat_data_block failed\n");
                break;
            }

            /* buff now contains the block with N small blocks in it */
            offset = (1 << hdr->log2_small_block_size) * (current_block % (1 << (hdr->log2_big_block_size - hdr->log2_small_block_size)));

            if (cli_writen(ofd, &buff[offset], MIN(len, 1 << hdr->log2_small_block_size)) != MIN(len, 1 << hdr->log2_small_block_size)) {
                goto done;
            }

            len -= MIN(len, 1 << hdr->log2_small_block_size);
            current_block = ole2_get_next_sbat_block(hdr, current_block);
        } else {
            /* Big block file */
            if (!ole2_read_block(hdr, buff, 1 << hdr->log2_big_block_size, current_block)) {
                break;
            }

            if (cli_writen(ofd, buff, MIN(len, (1 << hdr->log2_big_block_size))) != MIN(len, (1 << hdr->log2_big_block_size))) {
                ret = CL_EWRITE;
                goto done;
            }

            current_block = ole2_get_next_block_number(hdr, current_block);
            len -= MIN(len, (1 << hdr->log2_big_block_size));
        }
    }

    /*
     * Unlike w/ handler_otf(), the ole2 summary JSON will be recorded
     * when we re-ingest the files we wrote above when we scan the directory.
     * See cli_ole2_tempdir_scan_vba()
     */

    ret = CL_SUCCESS;

done:
    FREE(name);
    if (-1 != ofd) {
        close(ofd);
    }
    FREE(buff);
    if (NULL != blk_bitset) {
        cli_bitset_free(blk_bitset);
    }

    return ret;
}

enum biff_parser_states {
    BIFF_PARSER_INITIAL,
    BIFF_PARSER_EXPECTING_2ND_TAG_BYTE,
    BIFF_PARSER_EXPECTING_1ST_LENGTH_BYTE,
    BIFF_PARSER_EXPECTING_2ND_LENGTH_BYTE,
    BIFF_PARSER_NAME_RECORD,
    BIFF_PARSER_BOUNDSHEET_RECORD,
    BIFF_PARSER_MSODRAWINGGROUP_RECORD,
    BIFF_PARSER_DATA,
};

struct biff_parser_state {
    enum biff_parser_states state;
    uint16_t opcode;
    uint16_t length;
    uint16_t data_offset;
    uint8_t tmp;
};

/**
 * Scan through a buffer of BIFF records and find PARSERNAME, BOUNDSHEET records (Which indicate XLM  macros).
 * BIFF streams follow the format OOLLDDDDDDDDD..., where OO is the opcode (little endian 16 bit value),
 * LL is the data length (little endian 16 bit value), followed by LL bytes of data. Records are defined in
 * the MICROSOFT OFFICE EXCEL 97-2007 BINARY FILE FORMAT SPECIFICATION.
 *
 * \param state The parser state.
 * \param buff The buffer.
 * \param len The buffer's size in bytes.
 * \param ctx The ClamAV context for emitting JSON about the document.
 * \returns true if a macro has been found, false otherwise.
 */
static cl_error_t scan_biff_for_xlm_macros_and_images(
    struct biff_parser_state *state,
    unsigned char *buff,
    size_t len,
    cli_ctx *ctx,
    bool *found_macro,
    bool *found_image)
{
    cl_error_t status = CL_EFORMAT;
    size_t i;

    for (i = 0; i < len; ++i) {
        switch (state->state) {
            case BIFF_PARSER_INITIAL:
                state->opcode = buff[i];
                state->state  = BIFF_PARSER_EXPECTING_2ND_TAG_BYTE;
                break;
            case BIFF_PARSER_EXPECTING_2ND_TAG_BYTE:
                state->opcode |= buff[i] << 8;
                state->state = BIFF_PARSER_EXPECTING_1ST_LENGTH_BYTE;
                break;
            case BIFF_PARSER_EXPECTING_1ST_LENGTH_BYTE:
                state->length = buff[i];
                state->state  = BIFF_PARSER_EXPECTING_2ND_LENGTH_BYTE;
                break;
            case BIFF_PARSER_EXPECTING_2ND_LENGTH_BYTE:
                state->length |= buff[i] << 8;
                state->data_offset = 0;
                switch (state->opcode) {
                    case OPC_BOUNDSHEET:
                        state->state = BIFF_PARSER_BOUNDSHEET_RECORD;
                        break;
                    case OPC_NAME:
                        state->state = BIFF_PARSER_NAME_RECORD;
                        break;
                    case OPC_MSODRAWINGGROUP:
                        state->state = BIFF_PARSER_MSODRAWINGGROUP_RECORD;
                        break;
                    default:
                        state->state = BIFF_PARSER_DATA;
                        break;
                }
                if (state->length == 0) {
                    state->state = BIFF_PARSER_INITIAL;
                }
                break;
            default:
                switch (state->state) {
                    case BIFF_PARSER_NAME_RECORD:
#if HAVE_JSON
                        if (state->data_offset == 0) {
                            state->tmp = buff[i] & 0x20;
                        } else if ((state->data_offset == 14 || state->data_offset == 15) && state->tmp) {
                            if (buff[i] == 1 || buff[i] == 2) {
                                if (SCAN_COLLECT_METADATA && (ctx->wrkproperty != NULL)) {
                                    json_object *indicators = cli_jsonarray(ctx->wrkproperty, "MacroIndicators");
                                    if (indicators) {
                                        cli_jsonstr(indicators, NULL, "autorun");
                                    } else {
                                        cli_dbgmsg("[scan_biff_for_xlm_macros_and_images] Failed to add \"autorun\" entry to MacroIndicators JSON array\n");
                                    }
                                }
                            }

                            if (buff[i] != 0) {
                                state->tmp = 0;
                            }
                        }
#endif
                        break;
                    case BIFF_PARSER_BOUNDSHEET_RECORD:
                        if (state->data_offset == 4) {
                            state->tmp = buff[i];
                        } else if (state->data_offset == 5 && buff[i] == 1) { //Excel 4.0 macro sheet
                            cli_dbgmsg("[scan_biff_for_xlm_macros_and_images] Found XLM macro sheet\n");
#if HAVE_JSON
                            if (SCAN_COLLECT_METADATA && (ctx->wrkproperty != NULL)) {
                                cli_jsonbool(ctx->wrkproperty, "HasMacros", 1);
                                json_object *macro_languages = cli_jsonarray(ctx->wrkproperty, "MacroLanguages");
                                if (macro_languages) {
                                    cli_jsonstr(macro_languages, NULL, "XLM");
                                } else {
                                    cli_dbgmsg("[scan_biff_for_xlm_macros_and_images] Failed to add \"XLM\" entry to MacroLanguages JSON array\n");
                                }
                                if (state->tmp == 1 || state->tmp == 2) {
                                    json_object *indicators = cli_jsonarray(ctx->wrkproperty, "MacroIndicators");
                                    if (indicators) {
                                        cli_jsonstr(indicators, NULL, "hidden");
                                    } else {
                                        cli_dbgmsg("[scan_biff_for_xlm_macros_and_images] Failed to add \"hidden\" entry to MacroIndicators JSON array\n");
                                    }
                                }
                            }
#endif
                            *found_macro = true;
                        }
                        break;
                    case BIFF_PARSER_DATA:
                        break;
                    case BIFF_PARSER_MSODRAWINGGROUP_RECORD:
                        // Embedded image found
                        if (true != *found_image) {
                            *found_image = true;
                            cli_dbgmsg("[scan_biff_for_xlm_macros_and_images] Found image in sheet\n");
                        }
                        break;
                    default:
                        //Should never arrive here
                        cli_dbgmsg("[scan_biff_for_xlm_macros_and_images] Unexpected state value %d\n", (int)state->state);
                        break;
                }
                state->data_offset += 1;

                if (state->data_offset >= state->length) {
                    state->state = BIFF_PARSER_INITIAL;
                }
        }
    }

    status = CL_SUCCESS;

    return status;
}

/**
 * @brief Scan for XLM (Excel 4.0) macro sheets and images in an OLE2 Workbook stream.
 *
 * The stream should be encoded with <= BIFF8.
 * The found_macro and found_image out-params should be checked even if an error occured.
 *
 * @param hdr
 * @param prop
 * @param ctx
 * @param found_macro [out] If any macros were found
 * @param found_image [out] If any images were found
 * @return cl_error_t CL_EPARSE if an error was encountered
 * @return cl_error_t CL_EMEM if a memory issue was encountered.
 * @return cl_error_t CL_SUCCESS if no errors were encountered.
 */
static cl_error_t scan_for_xlm_macros_and_images(ole2_header_t *hdr, property_t *prop, cli_ctx *ctx, bool *found_macro, bool *found_image)
{
    cl_error_t status   = CL_EPARSE;
    unsigned char * buff = NULL;
    int32_t current_block = 0;
    size_t len = 0, offset = 0;
    bitset_t * blk_bitset = NULL;
    struct biff_parser_state state = {0};

    if (prop->type != 2) {
        /* Not a file */
        goto done;
    }

    memset(&state, 0, sizeof(state));
    state.state   = BIFF_PARSER_INITIAL;
    current_block = prop->start_block;
    len           = prop->size;

    CLI_MALLOC(buff, 1 << hdr->log2_big_block_size, 
        cli_errmsg("OLE2 [scan_for_xlm_macros_and_images]: Unable to allocate memory for buff: %u\n", 1 << hdr->log2_big_block_size);
        status = CL_EMEM);

    blk_bitset = cli_bitset_init();
    if (!blk_bitset) {
        cli_errmsg("OLE2 [scan_for_xlm_macros_and_images]: init bitset failed\n");
        goto done;
    }
    while ((current_block >= 0) && (len > 0)) {
        if (current_block > (int32_t)hdr->max_block_no) {
            cli_dbgmsg("OLE2 [scan_for_xlm_macros_and_images]: Max block number for file size exceeded: %d\n", current_block);
            goto done;
        }
        /* Check we aren't in a loop */
        if (cli_bitset_test(blk_bitset, (unsigned long)current_block)) {
            /* Loop in block list */
            cli_dbgmsg("OLE2 [scan_for_xlm_macros_and_images]: Block list loop detected\n");
            goto done;
        }
        if (!cli_bitset_set(blk_bitset, (unsigned long)current_block)) {
            goto done;
        }
        if (prop->size < (int64_t)hdr->sbat_cutoff) {
            /* Small block file */
            if (!ole2_get_sbat_data_block(hdr, buff, current_block)) {
                cli_dbgmsg("OLE2 [scan_for_xlm_macros_and_images]: ole2_get_sbat_data_block failed\n");
                goto done;
            }
            /* buff now contains the block with N small blocks in it */
            offset = (1 << hdr->log2_small_block_size) * (current_block % (1 << (hdr->log2_big_block_size - hdr->log2_small_block_size)));

            (void)scan_biff_for_xlm_macros_and_images(&state, &buff[offset], MIN(len, 1 << hdr->log2_small_block_size), ctx, found_macro, found_image);
            len -= MIN(len, 1 << hdr->log2_small_block_size);
            current_block = ole2_get_next_sbat_block(hdr, current_block);
        } else {
            /* Big block file */
            if (!ole2_read_block(hdr, buff, 1 << hdr->log2_big_block_size, current_block)) {
                goto done;
            }

            (void)scan_biff_for_xlm_macros_and_images(&state, buff, MIN(len, (1 << hdr->log2_big_block_size)), ctx, found_macro, found_image);
            current_block = ole2_get_next_block_number(hdr, current_block);
            len -= MIN(len, (1 << hdr->log2_big_block_size));
        }
    }

    status = CL_SUCCESS;

done:
    FREE(buff);

    if (blk_bitset) {
        cli_bitset_free(blk_bitset);
    }
    return status;
}


/**
 * @brief enum file Handler - checks for VBA presence
 *
 * @param hdr
 * @param prop
 * @param dir
 * @param ctx   the scan context
 * @return cl_error_t
 */
static cl_error_t handler_enum(ole2_header_t *hdr, property_t *prop, const char *dir, cli_ctx *ctx)
{
    cl_error_t status = CL_EREAD;
    char* name = NULL;
    unsigned char * hwp_check = NULL;
    int32_t offset = 0;
#if HAVE_JSON
    json_object* arrobj = NULL;
    json_object* strmobj = NULL;

    name = cli_ole2_get_property_name2(prop->name, prop->name_size);
    if (name) {
        if (SCAN_COLLECT_METADATA && ctx->wrkproperty != NULL) {
            arrobj = cli_jsonarray(ctx->wrkproperty, "Streams");
            if (NULL == arrobj) {
                cli_warnmsg("ole2: no memory for streams list or streams is not an array\n");
            } else {
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
            name = cli_ole2_get_property_name2(prop->name, prop->name_size);
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
        if (!name) {
            name = cli_ole2_get_property_name2(prop->name, prop->name_size);
        }
        if (name) {
            if (!strcmp(name, "fileheader")) {
                CLI_CALLOC(hwp_check, 1, 1 << hdr->log2_big_block_size, status = CL_EMEM);

                /* reading safety checks; do-while used for breaks */
                do {
                    if (prop->size == 0)
                        break;

                    if (prop->start_block > hdr->max_block_no)
                        break;

                    /* read the header block (~256 bytes) */
                    offset = 0;
                    if (prop->size < (int64_t)hdr->sbat_cutoff) {
                        if (!ole2_get_sbat_data_block(hdr, hwp_check, prop->start_block)) {
                            break;
                        }
                        offset = (1 << hdr->log2_small_block_size) *
                                 (prop->start_block % (1 << (hdr->log2_big_block_size - hdr->log2_small_block_size)));

                        /* reading safety */
                        if (offset + 40 >= 1 << hdr->log2_big_block_size)
                            break;
                    } else {
                        if (!ole2_read_block(hdr, hwp_check, 1 << hdr->log2_big_block_size, prop->start_block)) {
                            break;
                        }
                    }

                    /* compare against HWP signature; we could add the 15 padding NULLs too */
                    if (!memcmp(hwp_check + offset, "HWP Document File", 17)) {
                        hwp5_header_t *hwp_new;
#if HAVE_JSON
                        cli_jsonstr(ctx->wrkproperty, "FileType", "CL_TYPE_HWP5");
#endif
                        CLI_CALLOC(hwp_new, 1, sizeof(hwp5_header_t), status = CL_EMEM);

                        /*
                         * Copy the header information into our header struct.
                         */
                        memcpy(hwp_new, hwp_check + offset, sizeof(hwp5_header_t));

                        hwp_new->version = ole2_endian_convert_32(hwp_new->version);
                        hwp_new->flags   = ole2_endian_convert_32(hwp_new->flags);

                        hdr->is_hwp = hwp_new;
                    }
                } while (0);

            }
        }
    }

    /* If we've already found a macro and an image, we can skip this initial check.
       This scan step is to save a little time so we don't have to fully parse it
       later if never find anything.. */
    if (!hdr->has_xlm || !hdr->has_image) {
        if (!name) {
            name = cli_ole2_get_property_name2(prop->name, prop->name_size);
        }

        if (name && (strcmp(name, "workbook") == 0 || strcmp(name, "book") == 0)) {
            (void)scan_for_xlm_macros_and_images(hdr, prop, ctx, &hdr->has_xlm, &hdr->has_image);
        }
    }

    status = CL_SUCCESS;

done:
    FREE(name);
    FREE(hwp_check);

    return status;
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

static cl_error_t scan_mso_stream(int fd, cli_ctx *ctx)
{
    int zret, ofd;
    cl_error_t ret = CL_SUCCESS;
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

        input = fmap(fd, 0, statbuf.st_size, NULL);
        if (!input) {
            cli_dbgmsg("scan_mso_stream: Failed to get fmap for input stream\n");
            return CL_EMAP;
        }
    }

    /* reserve tempfile for output and scanning */
    if ((ret = cli_gentempfd(ctx->sub_tmpdir, &tmpname, &ofd)) != CL_SUCCESS) {
        cli_errmsg("scan_mso_stream: Can't generate temporary file\n");
        funmap(input);
        return ret;
    }

    /* initialize zlib inflation stream */
    memset(&zstrm, 0, sizeof(zstrm));
    zstrm.zalloc    = Z_NULL;
    zstrm.zfree     = Z_NULL;
    zstrm.opaque    = Z_NULL;
    zstrm.next_in   = inbuf;
    zstrm.next_out  = outbuf;
    zstrm.avail_in  = 0;
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
    prefix = le32_to_host(prefix);

    off_in += sizeof(uint32_t);
    cli_dbgmsg("scan_mso_stream: stream prefix = %08x(%d)\n", prefix, prefix);

    /* inflation loop */
    do {
        if (zstrm.avail_in == 0) {
            size_t bytes_read;

            zstrm.next_in = inbuf;
            bytes_read    = fmap_readn(input, inbuf, off_in, FILEBUFF);
            if (bytes_read == (size_t)-1) {
                cli_errmsg("scan_mso_stream: Error reading MSO file\n");
                ret = CL_EUNPACK;
                goto mso_end;
            }
            if (bytes_read == 0)
                break;

            zstrm.avail_in = bytes_read;
            off_in += bytes_read;
        }
        zret  = inflate(&zstrm, Z_SYNC_FLUSH);
        count = FILEBUFF - zstrm.avail_out;
        if (count) {
            if (cli_checklimits("MSO", ctx, outsize + count, 0, 0) != CL_SUCCESS)
                break;
            if (cli_writen(ofd, outbuf, count) != count) {
                cli_errmsg("scan_mso_stream: Can't write to file %s\n", tmpname);
                ret = CL_EWRITE;
                goto mso_end;
            }
            outsize += count;
        }
        zstrm.next_out  = outbuf;
        zstrm.avail_out = FILEBUFF;
    } while (zret == Z_OK);

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
    ret = cli_magic_scan_desc(ofd, tmpname, ctx, NULL);

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

static cl_error_t handler_otf(ole2_header_t *hdr, property_t *prop, const char *dir, cli_ctx *ctx)
{
    cl_error_t ret      = CL_BREAK;
    char* tempfile = NULL;
    char * name = NULL;
    unsigned char * buff = NULL;
    int32_t current_block = 0;
    size_t len = 0, offset = 0;
    int ofd = -1;
    int is_mso = 0;
    bitset_t * blk_bitset = NULL;

    UNUSEDPARAM(dir);

    if (prop->type != 2) {
        /* Not a file */
        ret = CL_SUCCESS;
        goto done;
    }
    print_ole2_property(prop);

    if (!(tempfile = cli_gentemp(ctx ? ctx->sub_tmpdir : NULL))) {
        ret = CL_EMEM;
        goto done;
    }

    if ((ofd = open(tempfile, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, S_IRUSR | S_IWUSR)) < 0) {
        cli_dbgmsg("OLE2 [handler_otf]: Can't create file %s\n", tempfile);
        ret = CL_ECREAT;
        goto done;
    }

    current_block = prop->start_block;
    len           = prop->size;

    if (cli_debug_flag) {
        if (!name) {
            name = cli_ole2_get_property_name2(prop->name, prop->name_size);
        }
        cli_dbgmsg("OLE2 [handler_otf]: Dumping '%s' to '%s'\n", name, tempfile);
    }

    CLI_MALLOC(buff, 1 << hdr->log2_big_block_size, ret = CL_EMEM);

    blk_bitset = cli_bitset_init();
    if (!blk_bitset) {
        cli_errmsg("OLE2 [handler_otf]: init bitset failed\n");
        goto done;
    }

    while ((current_block >= 0) && (len > 0)) {
        if (current_block > (int32_t)hdr->max_block_no) {
            cli_dbgmsg("OLE2 [handler_otf]: Max block number for file size exceeded: %d\n", current_block);
            break;
        }

        /* Check we aren't in a loop */
        if (cli_bitset_test(blk_bitset, (unsigned long)current_block)) {
            /* Loop in block list */
            cli_dbgmsg("OLE2 [handler_otf]: Block list loop detected\n");
            break;
        }

        if (!cli_bitset_set(blk_bitset, (unsigned long)current_block)) {
            break;
        }

        if (prop->size < (int64_t)hdr->sbat_cutoff) {
            /* Small block file */
            if (!ole2_get_sbat_data_block(hdr, buff, current_block)) {
                cli_dbgmsg("OLE2 [handler_otf]: ole2_get_sbat_data_block failed\n");
                break;
            }

            /* buff now contains the block with N small blocks in it */
            offset = (1 << hdr->log2_small_block_size) * (current_block % (1 << (hdr->log2_big_block_size - hdr->log2_small_block_size)));

            if (cli_writen(ofd, &buff[offset], MIN(len, 1 << hdr->log2_small_block_size)) != MIN(len, 1 << hdr->log2_small_block_size)) {
                goto done;
            }

            len -= MIN(len, 1 << hdr->log2_small_block_size);
            current_block = ole2_get_next_sbat_block(hdr, current_block);
        } else {
            /* Big block file */
            if (!ole2_read_block(hdr, buff, 1 << hdr->log2_big_block_size, current_block)) {
                break;
            }

            if (cli_writen(ofd, buff, MIN(len, (1 << hdr->log2_big_block_size))) != MIN(len, (1 << hdr->log2_big_block_size))) {
                ret = CL_EWRITE;
                goto done;
            }

            current_block = ole2_get_next_block_number(hdr, current_block);
            len -= MIN(len, (1 << hdr->log2_big_block_size));
        }
    }

    /* defragmenting of ole2 stream complete */

    is_mso = likely_mso_stream(ofd);
    if (lseek(ofd, 0, SEEK_SET) == -1) {
        ret = CL_ESEEK;
        goto done;
    }

#if HAVE_JSON
    /* JSON Output Summary Information */
    if (SCAN_COLLECT_METADATA && (ctx->properties != NULL)) {
        if (!name) {
            name = cli_ole2_get_property_name2(prop->name, prop->name_size);
        }
        if (name) {
            if (!strncmp(name, "_5_summaryinformation", 21)) {
                cli_dbgmsg("OLE2: detected a '_5_summaryinformation' stream\n");
                /* JSONOLE2 - what to do if something breaks? */
                if (cli_ole2_summary_json(ctx, ofd, 0) == CL_ETIMEOUT) {
                    ret = CL_ETIMEOUT;
                    goto done;
                }
            }

            if (!strncmp(name, "_5_documentsummaryinformation", 29)) {
                cli_dbgmsg("OLE2: detected a '_5_documentsummaryinformation' stream\n");
                /* JSONOLE2 - what to do if something breaks? */
                if (cli_ole2_summary_json(ctx, ofd, 1) == CL_ETIMEOUT) {
                    ret = CL_ETIMEOUT;
                    goto done;
                }
            }
        }
    }
#endif

    if (hdr->is_hwp) {
        if (!name) {
            name = cli_ole2_get_property_name2(prop->name, prop->name_size);
        }
        ret = cli_scanhwp5_stream(ctx, hdr->is_hwp, name, ofd, tempfile);
    } else if (is_mso < 0) {
        ret = CL_ESEEK;
    } else if (is_mso) {
        /* MSO Stream Scan */
        ret = scan_mso_stream(ofd, ctx);
    } else {
        /* Normal File Scan */
        ret = cli_magic_scan_desc(ofd, tempfile, ctx, NULL);
    }

    ret = ret == CL_VIRUS ? CL_VIRUS : CL_SUCCESS;

done:
    FREE(name);
    if (-1 != ofd) {
        close(ofd);
    }
    FREE(buff);
    if (NULL != blk_bitset) {
        cli_bitset_free(blk_bitset);
    }
    if (NULL != tempfile) {
        if (ctx && !ctx->engine->keeptmp) {
            if (cli_unlink(tempfile)) {
                ret = CL_EUNLINK;
            }
        }
        free(tempfile);
        tempfile = NULL;
    }

    return ret;
}

#if !defined(HAVE_ATTRIB_PACKED) && !defined(HAVE_PRAGMA_PACK) && !defined(HAVE_PRAGMA_PACK_HPPA)
static int
ole2_read_header(int fd, ole2_header_t *hdr)
{
    int i;

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

/**
 * @brief Extract macros and images from an ole2 file
 *
 * @param dirname   A temp directory where we should store extracted content
 * @param ctx       The scan context
 * @param files     [out] A store of file names of extracted things to be processed later.
 * @param has_vba   [out] If the ole2 contained 1 or more VBA macros
 * @param has_xlm   [out] If the ole2 contained 1 or more XLM macros
 * @param has_image [out] If the ole2 contained 1 or more images
 * @return cl_error_t
 */
cl_error_t cli_ole2_extract(const char *dirname, cli_ctx *ctx, struct uniq **files, int *has_vba, int *has_xlm, int *has_image)
{
    ole2_header_t hdr;
    cl_error_t ret = CL_CLEAN;
    size_t hdr_size;
    unsigned int file_count = 0;
    unsigned long scansize, scansize2;
    const void *phdr;

    cli_dbgmsg("in cli_ole2_extract()\n");
    if (!ctx) {
        return CL_ENULLARG;
    }

    hdr.is_hwp = NULL;
    hdr.bitset = NULL;
    if (ctx->engine->maxscansize) {
        if (ctx->engine->maxscansize > ctx->scansize) {
            scansize = ctx->engine->maxscansize - ctx->scansize;
        } else {
            return CL_EMAXSIZE;
        }
    } else {
        scansize = -1;
    }

    scansize2 = scansize;

    /* size of header - size of other values in struct */
    hdr_size = sizeof(struct ole2_header_tag) -
               sizeof(int32_t) -        // sbat_root_start
               sizeof(uint32_t) -       // max_block_no
               sizeof(off_t) -          // m_length
               sizeof(bitset_t *) -     // bitset
               sizeof(struct uniq *) -  // U
               sizeof(fmap_t *) -       // map
               sizeof(bool) -           // has_vba
               sizeof(bool) -           // has_xlm
               sizeof(bool) -           // has_image
               sizeof(hwp5_header_t *); // is_hwp

    if ((size_t)((*ctx->fmap)->len) < (size_t)(hdr_size)) {
        return CL_CLEAN;
    }
    hdr.map      = *ctx->fmap;
    hdr.m_length = hdr.map->len;
    phdr         = fmap_need_off_once(hdr.map, 0, hdr_size);
    if (phdr) {
        memcpy(&hdr, phdr, hdr_size);
    } else {
        cli_dbgmsg("cli_ole2_extract: failed to read header\n");
        goto done;
    }

    hdr.minor_version         = ole2_endian_convert_16(hdr.minor_version);
    hdr.dll_version           = ole2_endian_convert_16(hdr.dll_version);
    hdr.byte_order            = ole2_endian_convert_16(hdr.byte_order);
    hdr.log2_big_block_size   = ole2_endian_convert_16(hdr.log2_big_block_size);
    hdr.log2_small_block_size = ole2_endian_convert_32(hdr.log2_small_block_size);
    hdr.bat_count             = ole2_endian_convert_32(hdr.bat_count);
    hdr.prop_start            = ole2_endian_convert_32(hdr.prop_start);
    hdr.sbat_cutoff           = ole2_endian_convert_32(hdr.sbat_cutoff);
    hdr.sbat_start            = ole2_endian_convert_32(hdr.sbat_start);
    hdr.sbat_block_count      = ole2_endian_convert_32(hdr.sbat_block_count);
    hdr.xbat_start            = ole2_endian_convert_32(hdr.xbat_start);
    hdr.xbat_count            = ole2_endian_convert_32(hdr.xbat_count);

    hdr.sbat_root_start = -1;

    hdr.bitset = cli_bitset_init();
    if (!hdr.bitset) {
        ret = CL_EMEM;
        goto done;
    }
    if (memcmp(hdr.magic, magic_id, 8) != 0) {
        cli_dbgmsg("OLE2 magic failed!\n");
        ret = CL_EFORMAT;
        goto done;
    }
    if (hdr.log2_big_block_size < 6 || hdr.log2_big_block_size > 30) {
        cli_dbgmsg("CAN'T PARSE: Invalid big block size (2^%u)\n", hdr.log2_big_block_size);
        goto done;
    }
    if (!hdr.log2_small_block_size || hdr.log2_small_block_size > hdr.log2_big_block_size) {
        cli_dbgmsg("CAN'T PARSE: Invalid small block size (2^%u)\n", hdr.log2_small_block_size);
        goto done;
    }
    if (hdr.sbat_cutoff != 4096) {
        cli_dbgmsg("WARNING: Untested sbat cutoff (%u); data may not extract correctly\n", hdr.sbat_cutoff);
    }

    if (hdr.map->len > INT32_MAX) {
        cli_dbgmsg("OLE2 extract: Overflow detected\n");
        ret = CL_EFORMAT;
        goto done;
    }
    /* 8 SBAT blocks per file block */
    hdr.max_block_no = (hdr.map->len - MAX(512, 1 << hdr.log2_big_block_size)) / (1 << hdr.log2_small_block_size);

    print_ole2_header(&hdr);
    cli_dbgmsg("Max block number: %lu\n", (unsigned long int)hdr.max_block_no);

    /* PASS 1 : Count files and check for VBA */
    hdr.has_vba   = false;
    hdr.has_xlm   = false;
    hdr.has_image = false;
    ret           = ole2_walk_property_tree(&hdr, NULL, 0, handler_enum, 0, &file_count, ctx, &scansize);
    cli_bitset_free(hdr.bitset);
    hdr.bitset = NULL;
    if (!file_count || !(hdr.bitset = cli_bitset_init())) {
        goto done;
    }

    if (hdr.is_hwp) {
        cli_dbgmsg("OLE2: identified HWP document\n");
        cli_dbgmsg("OLE2: HWP version: 0x%08x\n", hdr.is_hwp->version);
        cli_dbgmsg("OLE2: HWP flags:   0x%08x\n", hdr.is_hwp->flags);

        ret = cli_hwp5header(ctx, hdr.is_hwp);
        if (ret != CL_SUCCESS) {
            goto done;
        }
    }

    /* If there's no VBA we scan OTF */
    if (hdr.has_vba || hdr.has_xlm || hdr.has_image) {
        /* PASS 2/A : VBA scan */
        cli_dbgmsg("OLE2: VBA project found\n");
        if (!(hdr.U = uniq_init(file_count))) {
            cli_dbgmsg("OLE2: uniq_init() failed\n");
            ret = CL_EMEM;
            goto done;
        }
        file_count = 0;
        ole2_walk_property_tree(&hdr, dirname, 0, handler_writefile, 0, &file_count, ctx, &scansize2);
        ret    = CL_CLEAN;
        *files = hdr.U;
        if (has_vba) {
            *has_vba = hdr.has_vba;
        }
        if (has_xlm) {
            *has_xlm = hdr.has_xlm;
        }
        if (has_image) {
            *has_image = hdr.has_image;
        }
    } else {
        cli_dbgmsg("OLE2: no VBA projects found\n");
        /* PASS 2/B : OTF scan */
        file_count = 0;
        ret        = ole2_walk_property_tree(&hdr, NULL, 0, handler_otf, 0, &file_count, ctx, &scansize2);
    }

done:
    if (hdr.bitset) {
        cli_bitset_free(hdr.bitset);
    }
    if (hdr.is_hwp) {
        free(hdr.is_hwp);
    }
    return ret == CL_BREAK ? CL_CLEAN : ret;
}
