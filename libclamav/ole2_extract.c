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
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <stdlib.h>
#include "clamav.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libclamav/crypto.h"

#include "cltypes.h"
#include "others.h"
#include "ole2_extract.h"
#include "scanners.h"
#include "fmap.h"

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

    if (*name == 0 || size <= 0 || size > 64) {
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
    char           *dirname;
    ole2_list_t     node_list;
    int             ret, func_ret;

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
            if (prop_block[idx].child != -1) {
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
            if (prop_block[idx].prev != -1) {
	        if ((ret=ole2_list_push(&node_list, prop_block[idx].prev)) != CL_SUCCESS) {
		    ole2_list_delete(&node_list);
		    return ret;
		}
	    }
	    if (prop_block[idx].next != -1) {
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
            if (prop_block[idx].child != -1) {
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
            if (prop_block[idx].prev != -1) {
	        if ((ret=ole2_list_push(&node_list, prop_block[idx].prev)) != CL_SUCCESS) {
		    ole2_list_delete(&node_list);
		    return ret;
		}
            }
            if (prop_block[idx].next != -1) {
                if ((ret=ole2_list_push(&node_list, prop_block[idx].next)) != CL_SUCCESS) {
		    ole2_list_delete(&node_list);
		    return ret;
		}
            }
            break;
        case 1:                /* Directory */
            ole2_listmsg("directory node\n");
            if (dir) {
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
            if (prop_block[idx].child != -1) {
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
            if (prop_block[idx].prev != -1) {
	        if ((ret=ole2_list_push(&node_list, prop_block[idx].prev)) != CL_SUCCESS) {
		    ole2_list_delete(&node_list);
		    return ret;
		}
            }
            if (prop_block[idx].next != -1) {
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
    char           *name;

    if (!hdr->has_vba) {
        name = get_property_name2(prop->name, prop->name_size);
        if (name) {
            if (!strcmp(name, "_vba_project") || !strcmp(name, "powerpoint document") || !strcmp(name, "worddocument") || !strcmp(name, "_1_ole10native"))
                hdr->has_vba = 1;
            free(name);
        }
    }
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
    int             hdr_size, ret = CL_CLEAN;
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

    if ((*ctx->fmap)->len < hdr_size) {
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
