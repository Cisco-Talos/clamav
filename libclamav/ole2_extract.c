/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#include "msdoc.h"
#include "rijndael.h"
#include "ole2_encryption.h"

#ifdef DEBUG_OLE2_LIST
#define ole2_listmsg(...) cli_dbgmsg(__VA_ARGS__)
#else
#define ole2_listmsg(...) ;
#endif

#define ole2_endian_convert_16(v) le16_to_host((uint16_t)(v))
#define ole2_endian_convert_32(v) le32_to_host((uint32_t)(v))
#define ole2_endian_convert_64(v) le64_to_host((uint64_t)(v))

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif

#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/05060311-bfce-4b12-874d-71fd4ce63aea
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
     * IMPORTANT: These must take account of the size of variables below here
     * when calculating hdr_size to read the header.
     *
     * See the top of cli_ole2_extract().
     */
    int32_t sbat_root_start __attribute__((packed));
    uint32_t max_block_no;
    size_t m_length;
    bitset_t *bitset;
    struct uniq *U;
    fmap_t *map;
    bool has_vba;
    bool has_xlm;
    bool has_image;

    hwp5_header_t *is_hwp; // This value MUST be last in this structure,
                           // otherwise you will get short file reads.

} ole2_header_t;

/*
 * DirectoryEntry
 *
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/60fe8611-66c3-496b-b70d-a504c94c9ace
 */
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

/*
 * File Information Block Base.
 * Naming is consistent with
 * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/26fb6c06-4e5c-4778-ab4e-edbf26a545bb
 * */
typedef struct __attribute__((packed)) fib_base_type {
    uint16_t wIdent;
    uint16_t nFib;
    uint16_t unused;
    uint16_t lid;
    uint16_t pnNext;
    uint16_t ABCDEFGHIJKLM;
    uint16_t nFibBack;
    uint32_t lKey;
    uint8_t envr;
    uint8_t NOPQRS;
    uint16_t reserved3;
    uint16_t reserved4;
    uint32_t reserved5;
    uint32_t reserved6;
} fib_base_t;

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
    ole2_list_node_t *new_node = NULL;
    int status                 = CL_EMEM;

    CLI_MALLOC_OR_GOTO_DONE(new_node, sizeof(ole2_list_node_t),
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

/**
 * @brief Get the property name, converting to lower case and replacing non-printable characters.
 *
 * @param name   The property name
 * @param size   The size of the property name
 * @return char* The new property name
 */
char *cli_ole2_get_property_name2(const char *name, int size)
{
    int i, j;
    char *newname = NULL;

    if ((name[0] == 0 && name[1] == 0) || size <= 0 || size > 128) {
        return NULL;
    }

    // We may need to replace every character with '_XY_' or '_XYZ_' to form a printable name.
    // This is because the name may contain non-printable characters.
    // Allocate 5 times the size of the name to be safe, plus 1 for the NULL terminator.
    CLI_MAX_MALLOC_OR_GOTO_DONE(newname, size * 5 + 1,
                                cli_errmsg("OLE2 [cli_ole2_get_property_name2]: Unable to allocate memory for newname: %u\n", size * 5));

    j = 0;
    /* size-2 to ignore trailing NULL */
    for (i = 0; i < size - 2; i += 2) {
        if ((!(name[i] & 0x80)) &&
            (isprint(name[i])) &&
            (name[i + 1] == 0)) {
            // Printable ASCII
            newname[j++] = tolower(name[i]);
        } else {
            // Non-printable. Expand to something unique and printable.
            if (name[i] < 10 && name[i] >= 0 && name[i + 1] == 0) {
                // Single digit (next byte is NULL)
                newname[j++] = '_';
                newname[j++] = name[i] + '0';
            } else {
                // Two digits (next byte is not NULL)
                const uint16_t x = (((uint16_t)name[i]) << 8) | name[i + 1];

                newname[j++] = '_';
                newname[j++] = 'a' + ((x & 0xF));
                newname[j++] = 'a' + ((x >> 4) & 0xF);
                newname[j++] = 'a' + ((x >> 8) & 0xF);
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
    char *newname      = NULL;
    char *cname        = NULL;
    char *oname        = name;

    if (csize <= 0) {
        return NULL;
    }

    CLI_MAX_MALLOC_OR_GOTO_DONE(newname, size,
                                cli_errmsg("OLE2 [get_property_name]: Unable to allocate memory for newname %u\n", size));
    cname = newname;

    while (--csize) {
        uint16_t lo, hi, u = cli_readint16(oname) - 0x3800;

        oname += 2;
        if (u > 0x1040) {
            CLI_FREE_AND_SET_NULL(newname);
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

static bool ole2_read_block(ole2_header_t *hdr, void *buff, size_t size, int32_t blockno)
{
    size_t offset, offend;
    const void *pblock;

    if (blockno < 0) {
        return false;
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

    if ((offend == 0) || (offset >= hdr->m_length)) {
        return false;
    } else if (offend > hdr->m_length) {
        /* bb#11369 - ole2 files may not be a block multiple in size */
        memset(buff, 0, size);
        size = hdr->m_length - offset;
    }
    if (!(pblock = fmap_need_off_once(hdr->map, offset, size))) {
        return false;
    }
    memcpy(buff, pblock, size);
    return true;
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
static bool ole2_get_sbat_data_block(ole2_header_t *hdr, void *buff, int32_t sbat_index)
{
    int32_t block_count, current_block;

    if (sbat_index < 0) {
        return false;
    }
    if (hdr->sbat_root_start < 0) {
        cli_dbgmsg("No root start block\n");
        return false;
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
 * @param hdr       The ole2 header metadata
 * @param prop      The property
 * @param dir       (optional) directory to write temp files to.
 * @param ctx       The scan context
 * @param ole2_data (optional) Context needed by the handler
 * @return cl_error_t
 */
typedef cl_error_t ole2_walk_property_tree_file_handler(ole2_header_t *hdr,
                                                        property_t *prop, const char *dir, cli_ctx *ctx, void *handler_ctx);

static cl_error_t handler_writefile(ole2_header_t *hdr, property_t *prop, const char *dir, cli_ctx *ctx, void *handler_ctx);
static cl_error_t handler_enum(ole2_header_t *hdr, property_t *prop, const char *dir, cli_ctx *ctx, void *handler_ctx);
static cl_error_t handler_otf_encrypted(ole2_header_t *hdr, property_t *prop, const char *dir, cli_ctx *ctx, void *handler_ctx);
static cl_error_t handler_otf(ole2_header_t *hdr, property_t *prop, const char *dir, cli_ctx *ctx, void *handler_ctx);

/*
 * Compare strings ignoring case.
 * This is a somewhat special case, since name is actually a utf-16 encoded string, stored
 * in a char * with a known size of 64 bytes, so we can avoid a 'alloc since the size is
 * so small.  See https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/60fe8611-66c3-496b-b70d-a504c94c9ace
 *
 * @param name:                     'name' from property_t struct
 * @param name_size:                'name_size' from property_t struct
 * @param keyword:                  Known value we are looking for
 *
 * @return int:                     Return '0' if the values are equivalent, something else otherwise.
 */
static int ole2_cmp_name(const char *const name, uint32_t name_size, const char *const keyword)
{
    char decoded[64];
    uint32_t i = 0, j = 0;

    if (64 < name_size || name_size % 2) {
        return -1;
    }

    memset(decoded, 0, sizeof(decoded));
    for (i = 0, j = 0; i < name_size; i += 2, j++) {
        decoded[j] = ((unsigned char)name[i + 1]) << 4;
        decoded[j] += name[i];
    }

    return strcasecmp(decoded, keyword);
}

static void copy_fib_base(fib_base_t *pFib, const uint8_t *const ptr)
{
    memcpy(pFib, ptr, sizeof(fib_base_t));
    pFib->wIdent = ole2_endian_convert_16(pFib->wIdent);
    pFib->nFib   = ole2_endian_convert_16(pFib->nFib);
    pFib->unused = ole2_endian_convert_16(pFib->unused);
    pFib->lid    = ole2_endian_convert_16(pFib->lid);
    pFib->pnNext = ole2_endian_convert_16(pFib->pnNext);

    /*Don't know whether to do this or not.*/
    pFib->ABCDEFGHIJKLM = ole2_endian_convert_16(pFib->ABCDEFGHIJKLM);

    pFib->nFibBack  = ole2_endian_convert_16(pFib->nFibBack);
    pFib->nFibBack  = ole2_endian_convert_32(pFib->lKey);
    pFib->reserved3 = ole2_endian_convert_16(pFib->reserved3);
    pFib->reserved4 = ole2_endian_convert_16(pFib->reserved4);
    pFib->reserved5 = ole2_endian_convert_32(pFib->reserved5);
    pFib->reserved6 = ole2_endian_convert_32(pFib->reserved6);
}

static inline bool is_encrypted(const fib_base_t *const pFib)
{
    return pFib->ABCDEFGHIJKLM & (1 << 8);
}

// /* Debugging function */
// static void dump_fib_base(fib_base_t *pFib)
// {
//     fprintf(stderr, "%s::%d::%x\n", __FUNCTION__, __LINE__, pFib->wIdent);
// }

/*
 * This is currently unused, but I am leaving it in in case it can be useful in the future.  See
 * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/79dea1e9-4dce-4fa0-8c6b-56ba37b68351
 *
 * I have not looked into it in detail, but if it is a 1-byte xor, it could be possible to brute-force it in some cases.
 *
 */
static inline bool is_obfuscated(const fib_base_t *const pFib)
{
    return pFib->ABCDEFGHIJKLM & (1 << 15);
}

typedef struct {
    bool velvet_sweatshop;

    bool encrypted;

    const char *encryption_type;

} encryption_status_t;

const char *const ENCRYPTED_JSON_KEY = "Encrypted";

const char *const RC4_ENCRYPTION              = "RC4";
const char *const XOR_OBFUSCATION             = "XORObfuscation";
const char *const AES128_ENCRYPTION           = "AES128";
const char *const AES192_ENCRYPTION           = "AES192";
const char *const AES256_ENCRYPTION           = "AES256";
const char *const VELVET_SWEATSHOP_ENCRYPTION = "VelvetSweatshop";
const char *const GENERIC_ENCRYPTED           = "ENCRYPTION_TYPE_UNKNOWN";

const char *const OLE2_HEURISTIC_ENCRYPTED_WARNING = "Heuristics.Encrypted.OLE2";

const uint16_t XLS_XOR_OBFUSCATION    = 0;
const uint16_t XLS_RC4_ENCRYPTION     = 1;
const uint32_t MINISTREAM_CUTOFF_SIZE = 0x1000;

static size_t get_stream_data_offset(ole2_header_t *hdr, const property_t *word_block, uint16_t sector)
{
    size_t offset      = (1 << hdr->log2_big_block_size);
    size_t sector_size = offset;
    size_t fib_offset  = 0;

    if (word_block->size < MINISTREAM_CUTOFF_SIZE) {
        fib_offset = offset + sector_size * hdr->sbat_root_start;
        fib_offset += (word_block->start_block * (1 << hdr->log2_small_block_size));
    } else {
        fib_offset = offset + sector_size * sector;
    }

    return fib_offset;
}

/* See information about the File Information Block here
 * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-doc/26fb6c06-4e5c-4778-ab4e-edbf26a545bb
 * for more information.
 */
static void test_for_encryption(const property_t *word_block, ole2_header_t *hdr, encryption_status_t *pEncryptionStatus)
{

    const uint8_t *ptr = NULL;
    fib_base_t fib     = {0};

    uint32_t fib_offset = get_stream_data_offset(hdr, word_block, word_block->start_block);

    if ((size_t)(hdr->m_length) < (size_t)(fib_offset + sizeof(fib_base_t))) {
        cli_dbgmsg("ERROR: Invalid offset for File Information Block %d (0x%x)\n", fib_offset, fib_offset);
        return;
    }

    ptr = fmap_need_off_once(hdr->map, fib_offset, sizeof(fib_base_t));
    if (NULL == ptr) {
        cli_dbgmsg("ERROR: Invalid offset for File Information Block %d (0x%x)\n", fib_offset, fib_offset);
        return;
    }
    copy_fib_base(&fib, ptr);

#define FIB_BASE_IDENTIFIER 0xa5ec

    if (FIB_BASE_IDENTIFIER != fib.wIdent) {
        cli_dbgmsg("ERROR: Invalid identifier for File Information Block %d (0x%x)\n", fib.wIdent, fib.wIdent);
        return;
    }

    /*TODO: Look into whether or not it's possible to determine the xor key when
     * a document is obfuscated with xor
     * (is_obfuscated function)
     */
    pEncryptionStatus->encrypted = is_encrypted(&fib);

    if (is_obfuscated(&fib)) {
        pEncryptionStatus->encryption_type = XOR_OBFUSCATION;
    }
}

static size_t read_uint16(const uint8_t *const ptr, uint32_t ptr_size, uint32_t *idx, uint16_t *dst)
{
    if (*idx + sizeof(uint16_t) >= ptr_size) {
        return 0;
    }

    memcpy(dst, &(ptr[*idx]), 2);
    *dst = ole2_endian_convert_16(*dst);
    *idx += sizeof(uint16_t);
    return sizeof(uint16_t);
}

/* Search for the FILE_PASS number.  If I don't find it, the next two bytes are
 * a length.  Consume that length of data, and try again.  Go until you either find
 * the number or run out of data.
 */
static bool find_file_pass(const uint8_t *const ptr, uint32_t ptr_size, uint32_t *idx)
{

    uint16_t val, size;

    const uint32_t FILE_PASS_NUM = 47;

    while (true) {
        if (sizeof(uint16_t) != read_uint16(ptr, ptr_size, idx, &val)) {
            return false;
        }

        if (sizeof(uint16_t) != read_uint16(ptr, ptr_size, idx, &size)) {
            return false;
        }

        if (FILE_PASS_NUM == val) {
            return true;
        }

        *idx += size;
    }

    /*Should never get here.*/
    return false;
}

/*
 * Search for the FilePass structure.
 * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/cf9ae8d5-4e8c-40a2-95f1-3b31f16b5529
 */
static void test_for_xls_encryption(const property_t *word_block, ole2_header_t *hdr, encryption_status_t *pEncryptionStatus)
{
    uint16_t tmp16;
    uint32_t idx;

    uint32_t stream_data_offset = get_stream_data_offset(hdr, word_block, word_block->start_block);

    uint32_t block_size      = (1 << hdr->log2_big_block_size);
    const uint8_t *const ptr = fmap_need_off_once(hdr->map, stream_data_offset, block_size);
    if (NULL == ptr) {
        cli_dbgmsg("ERROR: Invalid offset for File Information Block %d (0x%x)\n", stream_data_offset, stream_data_offset);
        return;
    }

    /*Validate keyword*/
    idx = 0;
    if (sizeof(uint16_t) != read_uint16(ptr, block_size, &idx, &tmp16)) {
        return;
    }

    /*Invalid keyword*/
    if (2057 != tmp16) {
        return;
    }

    /*Skip past this size.*/
    if (sizeof(uint16_t) != read_uint16(ptr, block_size, &idx, &tmp16)) {
        return;
    }
    idx += tmp16;

    if (!find_file_pass(ptr, block_size, &idx)) {
        return;
    }

    if (sizeof(uint16_t) != read_uint16(ptr, block_size, &idx, &tmp16)) {
        return;
    }

    if (XLS_RC4_ENCRYPTION == tmp16) {
        pEncryptionStatus->encryption_type = RC4_ENCRYPTION;
        pEncryptionStatus->encrypted       = true;
    } else if (XLS_XOR_OBFUSCATION == tmp16) {
        pEncryptionStatus->encryption_type = XOR_OBFUSCATION;
        pEncryptionStatus->encrypted       = true;
    }
}

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
                                   unsigned int rec_level, unsigned int *file_count,
                                   cli_ctx *ctx, unsigned long *scansize, void *handler_ctx,
                                   encryption_status_t *pEncryptionStatus)
{
    property_t prop_block[4];
    int32_t idx, current_block, i, curindex;
    char *dirname;
    ole2_list_t node_list;
    cl_error_t ret;
    char *name;
    int toval = 0;

    ole2_listmsg("ole2_walk_property_tree() called\n");
    ole2_list_init(&node_list);

    ole2_listmsg("rec_level: %d\n", rec_level);
    ole2_listmsg("file_count: %d\n", *file_count);

    if ((rec_level > 100) || (*file_count > 100000)) {
        return CL_SUCCESS;
    }

    if (ctx && ctx->engine->max_recursion_level && (rec_level > ctx->engine->max_recursion_level)) {
        // Note: engine->max_recursion_level is re-purposed here out of convenience.
        //       ole2 recursion does not leverage the ctx->recursion_stack stack.
        cli_dbgmsg("OLE2: Recursion limit reached (max: %d)\n", ctx->engine->max_recursion_level);
        cli_append_potentially_unwanted_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxRecursion");
        return CL_EMAXREC;
    }

    // push the 'root' node for the level onto the local list
    if ((ret = ole2_list_push(&node_list, prop_index)) != CL_SUCCESS) {
        ole2_list_delete(&node_list);
        return ret;
    }

    while (!ole2_list_is_empty(&node_list)) {
        ole2_listmsg("within working loop, worklist size: %d\n", ole2_list_size(&node_list));

        if (cli_json_timeout_cycle_check(ctx, &toval) != CL_SUCCESS) {
            ole2_list_delete(&node_list);
            return CL_ETIMEOUT;
        }

        current_block = hdr->prop_start;

        // pop off a node to work on
        curindex = ole2_list_pop(&node_list);
        ole2_listmsg("current index: %d\n", curindex);
        if ((curindex < 0) || (curindex > (int32_t)hdr->max_block_no)) {
            continue;
        }
        // read in the sector referenced by the current index
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

        if ((64 < prop_block[idx].name_size) || (prop_block[idx].name_size % 2)) {
            cli_dbgmsg("ERROR: Invalid name_size %d\n", prop_block[idx].name_size);
            continue;
        }

        if (0 == ole2_cmp_name(prop_block[idx].name, prop_block[idx].name_size, "WORDDocument")) {
            test_for_encryption(&(prop_block[idx]), hdr, pEncryptionStatus);
        } else if (0 == ole2_cmp_name(prop_block[idx].name, prop_block[idx].name_size, "WorkBook")) {
            test_for_xls_encryption(&(prop_block[idx]), hdr, pEncryptionStatus);
        } else if (0 == ole2_cmp_name(prop_block[idx].name, prop_block[idx].name_size, "PowerPoint Document")) {
            test_for_encryption(&(prop_block[idx]), hdr, pEncryptionStatus);
        } else if (0 == ole2_cmp_name(prop_block[idx].name, prop_block[idx].name_size, "EncryptionInfo")) {
            pEncryptionStatus->encrypted = true;
        } else if (0 == ole2_cmp_name(prop_block[idx].name, prop_block[idx].name_size, "EncryptedPackage")) {
            pEncryptionStatus->encrypted = true;
        }

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
                    ret = ole2_walk_property_tree(hdr, dir, prop_block[idx].child, handler, rec_level + 1, file_count, ctx, scansize, handler_ctx, pEncryptionStatus);
                    if (ret != CL_SUCCESS) {
                        ole2_list_delete(&node_list);
                        return ret;
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
                    cli_append_potentially_unwanted_if_heur_exceedsmax(ctx, "Heuristics.Limits.Exceeded.MaxFiles");
                    ole2_list_delete(&node_list);
                    return CL_EMAXFILES;
                }
                if (!ctx || !(ctx->engine->maxfilesize) || prop_block[idx].size <= ctx->engine->maxfilesize || prop_block[idx].size <= *scansize) {
                    (*file_count)++;
                    *scansize -= prop_block[idx].size;
                    ole2_listmsg("running file handler\n");
                    ret = handler(hdr, &prop_block[idx], dir, ctx, handler_ctx);
                    if (ret != CL_SUCCESS) {
                        ole2_listmsg("file handler returned %d\n", ret);
                        ole2_list_delete(&node_list);
                        return ret;
                    }
                } else {
                    cli_dbgmsg("OLE2: filesize exceeded\n");
                }
                if ((int)(prop_block[idx].child) != -1) {
                    ret = ole2_walk_property_tree(hdr, dir, prop_block[idx].child, handler, rec_level, file_count, ctx, scansize, handler_ctx, pEncryptionStatus);
                    if (ret != CL_SUCCESS) {
                        ole2_list_delete(&node_list);
                        return ret;
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
                    if (SCAN_COLLECT_METADATA && (ctx->this_layer_metadata_json != NULL)) {
                        if (!json_object_object_get_ex(ctx->this_layer_metadata_json, "DigitalSignatures", NULL)) {
                            name = cli_ole2_get_property_name2(prop_block[idx].name, prop_block[idx].name_size);
                            if (name) {
                                if (!strcmp(name, "_xmlsignatures") || !strcmp(name, "_signatures")) {
                                    cli_jsonbool(ctx->this_layer_metadata_json, "HasDigitalSignatures", 1);
                                }
                                free(name);
                            }
                        }
                    }

                    dirname = (char *)cli_max_malloc(strlen(dir) + 8);
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
                    ret = ole2_walk_property_tree(hdr, dirname, prop_block[idx].child, handler, rec_level + 1, file_count, ctx, scansize, handler_ctx, pEncryptionStatus);
                    if (ret != CL_SUCCESS) {
                        ole2_list_delete(&node_list);
                        if (dirname) {
                            free(dirname);
                        }
                        return ret;
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
    return CL_SUCCESS;
}

/* Write file Handler - write the contents of the entry to a file */
static cl_error_t handler_writefile(ole2_header_t *hdr, property_t *prop, const char *dir, cli_ctx *ctx, void *handler_ctx)
{
    cl_error_t ret = CL_BREAK;
    char newname[1024];
    char *name            = NULL;
    unsigned char *buff   = NULL;
    int32_t current_block = 0;
    size_t len = 0, offset = 0;
    int ofd              = -1;
    char *hash           = NULL;
    bitset_t *blk_bitset = NULL;
    uint32_t cnt         = 0;

    UNUSEDPARAM(ctx);
    UNUSEDPARAM(handler_ctx);

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

    CLI_MAX_MALLOC_OR_GOTO_DONE(buff, 1 << hdr->log2_big_block_size,
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
            offset = (((size_t)1) << hdr->log2_small_block_size) * (((size_t)current_block) % (((size_t)1) << (hdr->log2_big_block_size - hdr->log2_small_block_size)));

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
    CLI_FREE_AND_SET_NULL(name);
    if (-1 != ofd) {
        close(ofd);
    }
    CLI_FREE_AND_SET_NULL(buff);
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
                        if (state->data_offset == 0) {
                            state->tmp = buff[i] & 0x20;
                        } else if ((state->data_offset == 14 || state->data_offset == 15) && state->tmp) {
                            if (buff[i] == 1 || buff[i] == 2) {
                                if (SCAN_COLLECT_METADATA && (ctx->this_layer_metadata_json != NULL)) {
                                    json_object *indicators = cli_jsonarray(ctx->this_layer_metadata_json, "MacroIndicators");
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
                        break;
                    case BIFF_PARSER_BOUNDSHEET_RECORD:
                        if (state->data_offset == 4) {
                            state->tmp = buff[i];
                        } else if (state->data_offset == 5 && buff[i] == 1) { // Excel 4.0 macro sheet
                            cli_dbgmsg("[scan_biff_for_xlm_macros_and_images] Found XLM macro sheet\n");

                            if (SCAN_COLLECT_METADATA && (ctx->this_layer_metadata_json != NULL)) {
                                cli_jsonbool(ctx->this_layer_metadata_json, "HasMacros", 1);
                                json_object *macro_languages = cli_jsonarray(ctx->this_layer_metadata_json, "MacroLanguages");
                                if (macro_languages) {
                                    cli_jsonstr(macro_languages, NULL, "XLM");
                                } else {
                                    cli_dbgmsg("[scan_biff_for_xlm_macros_and_images] Failed to add \"XLM\" entry to MacroLanguages JSON array\n");
                                }
                                if (state->tmp == 1 || state->tmp == 2) {
                                    json_object *indicators = cli_jsonarray(ctx->this_layer_metadata_json, "MacroIndicators");
                                    if (indicators) {
                                        cli_jsonstr(indicators, NULL, "hidden");
                                    } else {
                                        cli_dbgmsg("[scan_biff_for_xlm_macros_and_images] Failed to add \"hidden\" entry to MacroIndicators JSON array\n");
                                    }
                                }
                            }

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
                        // Should never arrive here
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
 * The found_macro and found_image out-params should be checked even if an error occurred.
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
    cl_error_t status     = CL_EPARSE;
    unsigned char *buff   = NULL;
    int32_t current_block = 0;
    size_t len = 0, offset = 0;
    bitset_t *blk_bitset           = NULL;
    struct biff_parser_state state = {0};

    if (prop->type != 2) {
        /* Not a file */
        goto done;
    }

    memset(&state, 0, sizeof(state));
    state.state   = BIFF_PARSER_INITIAL;
    current_block = prop->start_block;
    len           = prop->size;

    CLI_MAX_MALLOC_OR_GOTO_DONE(buff, 1 << hdr->log2_big_block_size,
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
    CLI_FREE_AND_SET_NULL(buff);

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
static cl_error_t handler_enum(ole2_header_t *hdr, property_t *prop, const char *dir, cli_ctx *ctx, void *handler_ctx)
{
    cl_error_t status        = CL_EREAD;
    char *name               = NULL;
    unsigned char *hwp_check = NULL;
    int32_t offset           = 0;

    json_object *arrobj  = NULL;
    json_object *strmobj = NULL;

    UNUSEDPARAM(handler_ctx);
    UNUSEDPARAM(dir);

    name = cli_ole2_get_property_name2(prop->name, prop->name_size);
    if (name) {
        if (SCAN_COLLECT_METADATA && ctx->this_layer_metadata_json != NULL) {
            arrobj = cli_jsonarray(ctx->this_layer_metadata_json, "Streams");
            if (NULL == arrobj) {
                cli_warnmsg("ole2: no memory for streams list or streams is not an array\n");
            } else {
                strmobj = json_object_new_string(name);
                json_object_array_add(arrobj, strmobj);
            }

            if (!strcmp(name, "powerpoint document")) {
                cli_jsonstr(ctx->this_layer_metadata_json, "FileType", "CL_TYPE_MSPPT");
            }
            if (!strcmp(name, "worddocument")) {
                cli_jsonstr(ctx->this_layer_metadata_json, "FileType", "CL_TYPE_MSWORD");
            }
            if (!strcmp(name, "workbook")) {
                cli_jsonstr(ctx->this_layer_metadata_json, "FileType", "CL_TYPE_MSXL");
            }
        }
    }

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
                CLI_MAX_CALLOC_OR_GOTO_DONE(hwp_check, 1, 1 << hdr->log2_big_block_size, status = CL_EMEM);

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

                        cli_jsonstr(ctx->this_layer_metadata_json, "FileType", "CL_TYPE_HWP5");

                        CLI_CALLOC_OR_GOTO_DONE(hwp_new, 1, sizeof(hwp5_header_t), status = CL_EMEM);

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
    CLI_FREE_AND_SET_NULL(name);
    CLI_FREE_AND_SET_NULL(hwp_check);

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

static cl_error_t scan_mso_stream(int fd, const char *filepath, cli_ctx *ctx)
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

        input = fmap_new(fd, 0, statbuf.st_size, NULL, filepath);
        if (!input) {
            cli_dbgmsg("scan_mso_stream: Failed to get fmap for input stream\n");
            return CL_EMAP;
        }
    }

    /* reserve tempfile for output and scanning */
    if ((ret = cli_gentempfd(ctx->this_layer_tmpdir, &tmpname, &ofd)) != CL_SUCCESS) {
        cli_errmsg("scan_mso_stream: Can't generate temporary file\n");
        fmap_free(input);
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
    ret = cli_magic_scan_desc(ofd, tmpname, ctx, NULL, LAYER_ATTRIBUTES_NONE);

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
    fmap_free(input);
    return ret;
}

static cl_error_t handler_otf(ole2_header_t *hdr, property_t *prop, const char *dir, cli_ctx *ctx, void *handler_ctx)
{
    cl_error_t ret        = CL_BREAK;
    char *tempfile        = NULL;
    char *name            = NULL;
    unsigned char *buff   = NULL;
    int32_t current_block = 0;
    size_t len = 0, offset = 0;
    int ofd              = -1;
    int is_mso           = 0;
    bitset_t *blk_bitset = NULL;

    UNUSEDPARAM(dir);
    UNUSEDPARAM(handler_ctx);

    if (prop->type != 2) {
        /* Not a file */
        ret = CL_SUCCESS;
        goto done;
    }
    print_ole2_property(prop);

    if (!(tempfile = cli_gentemp(ctx->this_layer_tmpdir))) {
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

    CLI_MAX_MALLOC_OR_GOTO_DONE(buff, 1 << hdr->log2_big_block_size, ret = CL_EMEM);

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

    /* JSON Output Summary Information */
    if (SCAN_COLLECT_METADATA && (ctx->metadata_json != NULL)) {
        if (!name) {
            name = cli_ole2_get_property_name2(prop->name, prop->name_size);
        }
        if (name) {
            if (!strncmp(name, "_5_summaryinformation", 21)) {
                cli_dbgmsg("OLE2: detected a '_5_summaryinformation' stream\n");
                /* JSONOLE2 - what to do if something breaks? */
                if (cli_ole2_summary_json(ctx, ofd, 0, tempfile) == CL_ETIMEOUT) {
                    ret = CL_ETIMEOUT;
                    goto done;
                }
            }

            if (!strncmp(name, "_5_documentsummaryinformation", 29)) {
                cli_dbgmsg("OLE2: detected a '_5_documentsummaryinformation' stream\n");
                /* JSONOLE2 - what to do if something breaks? */
                if (cli_ole2_summary_json(ctx, ofd, 1, tempfile) == CL_ETIMEOUT) {
                    ret = CL_ETIMEOUT;
                    goto done;
                }
            }
        }
    }

    if (hdr->is_hwp) {
        if (!name) {
            name = cli_ole2_get_property_name2(prop->name, prop->name_size);
        }
        ret = cli_scanhwp5_stream(ctx, hdr->is_hwp, name, ofd, tempfile);
    } else if (is_mso < 0) {
        ret = CL_ESEEK;
    } else if (is_mso) {
        /* MSO Stream Scan */
        ret = scan_mso_stream(ofd, tempfile, ctx);
    } else {
        /* Normal File Scan */
        ret = cli_magic_scan_desc(ofd, tempfile, ctx, NULL, LAYER_ATTRIBUTES_NONE);
    }

    ret = ret == CL_VIRUS ? CL_VIRUS : CL_SUCCESS;

done:
    CLI_FREE_AND_SET_NULL(name);
    if (-1 != ofd) {
        close(ofd);
    }
    CLI_FREE_AND_SET_NULL(buff);
    if (NULL != blk_bitset) {
        cli_bitset_free(blk_bitset);
    }
    if (NULL != tempfile) {
        if (!ctx->engine->keeptmp) {
            if (cli_unlink(tempfile)) {
                ret = CL_EUNLINK;
            }
        }
        free(tempfile);
        tempfile = NULL;
    }

    return ret;
}

/*
 * @brief               Extracts encrypted files.
 * @param hdr           ole2_header_t structure
 * @param prop          property_t structure (DirectoryEntry)
 * @param dir           dir pointer.  Unused by this function
 * @param ctx           cli_ctx
 * @param handler_ctx   handler context.  For this function, it is the encryption key
 *                      initialized by 'initialize_encryption_key'
 * @return              Success or failure depending on whether validation was successful.
 *
 * For more information, see below
 * https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/e5ad39b8-9bc1-4a19-bad3-44e6246d21e6
 */
static cl_error_t handler_otf_encrypted(ole2_header_t *hdr, property_t *prop, const char *dir, cli_ctx *ctx, void *handler_ctx)
{
    cl_error_t ret        = CL_BREAK;
    char *tempfile        = NULL;
    char *name            = NULL;
    uint8_t *buff         = NULL;
    int32_t current_block = 0;
    size_t len            = 0;
    size_t offset         = 0;
    int ofd               = -1;
    int is_mso            = 0;
    bitset_t *blk_bitset  = NULL;
    int nrounds           = 0;
    uint8_t *decryptDst   = NULL;
    encryption_key_t *key = (encryption_key_t *)handler_ctx;
    uint32_t *rk          = NULL;
    uint32_t bytesRead    = 0;
    uint64_t actualFileLength;
    uint64_t bytesWritten = 0;
    uint32_t leftover     = 0;
    uint32_t readIdx      = 0;

    UNUSEDPARAM(dir);

    if (NULL == key) {
        cli_errmsg("%s::%d::key NULL\n", __FUNCTION__, __LINE__);
        goto done;
    }

    if (prop->type != 2) {
        /* Not a file */
        ret = CL_SUCCESS;
        goto done;
    }

    CLI_MAX_MALLOC_OR_GOTO_DONE(rk, RKLENGTH(key->key_length_bits) * sizeof(uint32_t), ret = CL_EMEM);

    print_ole2_property(prop);

    nrounds = rijndaelSetupDecrypt(rk, key->key, key->key_length_bits);

    if (!(tempfile = cli_gentemp(ctx->this_layer_tmpdir))) {
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

    uint32_t blockSize = 1 << hdr->log2_big_block_size;
    CLI_MAX_MALLOC_OR_GOTO_DONE(buff, blockSize + sizeof(uint64_t), ret = CL_EMEM);
    CLI_MAX_MALLOC_OR_GOTO_DONE(decryptDst, blockSize, ret = CL_EMEM);

    blk_bitset = cli_bitset_init();
    if (!blk_bitset) {
        cli_errmsg("OLE2 [handler_otf]: init bitset failed\n");
        goto done;
    }

    while (bytesRead < len) {
        if (current_block > (int32_t)hdr->max_block_no) {
            cli_dbgmsg("OLE2 [handler_otf]: Max block number for file size exceeded: %d\n", current_block);
            break;
        }

        /* Check we aren't in a loop */
        if (cli_bitset_test(blk_bitset, (uint64_t)current_block)) {
            /* Loop in block list */
            cli_dbgmsg("OLE2 [handler_otf]: Block list loop detected\n");
            break;
        }

        if (!cli_bitset_set(blk_bitset, (uint64_t)current_block)) {
            break;
        }

        if (prop->size < (int64_t)hdr->sbat_cutoff) {
            /* Small block file */
            if (!ole2_get_sbat_data_block(hdr, buff, current_block)) {
                cli_dbgmsg("OLE2 [handler_otf]: ole2_get_sbat_data_block failed\n");
                break;
            }

            /* buff now contains the block with N small blocks in it */
            offset = (((size_t)1) << hdr->log2_small_block_size) * (((size_t)current_block) % (((size_t)1) << (hdr->log2_big_block_size - hdr->log2_small_block_size)));

            if (cli_writen(ofd, &buff[offset], MIN(len, 1 << hdr->log2_small_block_size)) != MIN(len, 1 << hdr->log2_small_block_size)) {
                goto done;
            }

            len -= MIN(len, 1 << hdr->log2_small_block_size);
            current_block = ole2_get_next_sbat_block(hdr, current_block);

            // These small block files don't seem to be encrypted.
        } else {
            uint32_t bytesToWrite  = MIN(len - bytesRead, blockSize);
            uint32_t writeIdx      = 0;
            uint32_t decryptDstIdx = 0;

            if (!ole2_read_block(hdr, &(buff[readIdx]), blockSize, current_block)) {
                break;
            }
            if (0 == bytesRead) {
                // first block.  account for size of file.

                writeIdx += sizeof(uint64_t);
                memcpy(&actualFileLength, buff, sizeof(actualFileLength));
                actualFileLength = ole2_endian_convert_64(actualFileLength);
            }
            bytesRead += blockSize;

            for (; writeIdx + 16 <= leftover + bytesToWrite; writeIdx += 16, decryptDstIdx += 16) {
                rijndaelDecrypt(rk, nrounds, &(buff[writeIdx]), &(decryptDst[decryptDstIdx]));
            }

            /*Since our buffer size is a power of 2, leftover should always be
             * either 0 or 8, but we have to decrypt in multiples of 16.*/
            if (((leftover + bytesToWrite) - writeIdx) > 8) {
                goto done;
            }

            /*Make sure we don't write more data than the file is actually supposed to be.*/
            if ((decryptDstIdx + bytesWritten) > actualFileLength) {
                decryptDstIdx = actualFileLength - bytesWritten;
            }
            if (cli_writen(ofd, decryptDst, decryptDstIdx) != decryptDstIdx) {
                cli_errmsg("ole2: Error writing to file '%s'\n", tempfile);
                goto done;
            }
            bytesWritten += decryptDstIdx;

            leftover = (leftover + bytesToWrite) - writeIdx;
            if (leftover) {
                memmove(buff, &(buff[writeIdx]), leftover);
            }
            readIdx = leftover;

            current_block = ole2_get_next_block_number(hdr, current_block);
        }
    }

    /* defragmenting of ole2 stream complete */

    is_mso = likely_mso_stream(ofd);
    if (lseek(ofd, 0, SEEK_SET) == -1) {
        ret = CL_ESEEK;
        goto done;
    }

    /* JSON Output Summary Information */
    if (SCAN_COLLECT_METADATA && (ctx->metadata_json != NULL)) {
        if (!name) {
            name = cli_ole2_get_property_name2(prop->name, prop->name_size);
        }
        if (name) {
            if (!strncmp(name, "_5_summaryinformation", 21)) {
                cli_dbgmsg("OLE2: detected a '_5_summaryinformation' stream\n");
                /* JSONOLE2 - what to do if something breaks? */
                if (cli_ole2_summary_json(ctx, ofd, 0, tempfile) == CL_ETIMEOUT) {
                    ret = CL_ETIMEOUT;
                    goto done;
                }
            }

            if (!strncmp(name, "_5_documentsummaryinformation", 29)) {
                cli_dbgmsg("OLE2: detected a '_5_documentsummaryinformation' stream\n");
                /* JSONOLE2 - what to do if something breaks? */
                if (cli_ole2_summary_json(ctx, ofd, 1, tempfile) == CL_ETIMEOUT) {
                    ret = CL_ETIMEOUT;
                    goto done;
                }
            }
        }
    }

    if (hdr->is_hwp) {
        if (!name) {
            name = cli_ole2_get_property_name2(prop->name, prop->name_size);
        }
        ret = cli_scanhwp5_stream(ctx, hdr->is_hwp, name, ofd, tempfile);
    } else if (is_mso < 0) {
        ret = CL_ESEEK;
    } else if (is_mso) {
        /* MSO Stream Scan */
        ret = scan_mso_stream(ofd, tempfile, ctx);
    } else {
        /* Normal File Scan */
        ret = cli_magic_scan_desc(ofd, tempfile, ctx, NULL, LAYER_ATTRIBUTES_NONE);
    }

    ret = ret == CL_VIRUS ? CL_VIRUS : CL_SUCCESS;

done:
    CLI_FREE_AND_SET_NULL(name);
    if (-1 != ofd) {
        close(ofd);
    }
    CLI_FREE_AND_SET_NULL(buff);
    if (NULL != blk_bitset) {
        cli_bitset_free(blk_bitset);
    }
    if (NULL != tempfile) {
        if (!ctx->engine->keeptmp) {
            if (cli_unlink(tempfile)) {
                ret = CL_EUNLINK;
            }
        }
        free(tempfile);
        tempfile = NULL;
    }
    CLI_FREE_AND_SET_NULL(decryptDst);
    CLI_FREE_AND_SET_NULL(rk);

    return ret;
}

#if !defined(HAVE_ATTRIB_PACKED) && !defined(HAVE_PRAGMA_PACK) && !defined(HAVE_PRAGMA_PACK_HPPA)
static bool ole2_read_header(int fd, ole2_header_t *hdr)
{
    int i;

    if (cli_readn(fd, &hdr->magic, 8) != 8) {
        return false;
    }
    if (cli_readn(fd, &hdr->clsid, 16) != 16) {
        return false;
    }
    if (cli_readn(fd, &hdr->minor_version, 2) != 2) {
        return false;
    }
    if (cli_readn(fd, &hdr->dll_version, 2) != 2) {
        return false;
    }
    if (cli_readn(fd, &hdr->byte_order, 2) != 2) {
        return false;
    }
    if (cli_readn(fd, &hdr->log2_big_block_size, 2) != 2) {
        return false;
    }
    if (cli_readn(fd, &hdr->log2_small_block_size, 4) != 4) {
        return false;
    }
    if (cli_readn(fd, &hdr->reserved, 8) != 8) {
        return false;
    }
    if (cli_readn(fd, &hdr->bat_count, 4) != 4) {
        return false;
    }
    if (cli_readn(fd, &hdr->prop_start, 4) != 4) {
        return false;
    }
    if (cli_readn(fd, &hdr->signature, 4) != 4) {
        return false;
    }
    if (cli_readn(fd, &hdr->sbat_cutoff, 4) != 4) {
        return false;
    }
    if (cli_readn(fd, &hdr->sbat_start, 4) != 4) {
        return false;
    }
    if (cli_readn(fd, &hdr->sbat_block_count, 4) != 4) {
        return false;
    }
    if (cli_readn(fd, &hdr->xbat_start, 4) != 4) {
        return false;
    }
    if (cli_readn(fd, &hdr->xbat_count, 4) != 4) {
        return false;
    }
    for (i = 0; i < 109; i++) {
        if (cli_readn(fd, &hdr->bat_array[i], 4) != 4) {
            return false;
        }
    }
    return true;
}
#endif

void copy_encryption_info_stream_standard(encryption_info_stream_standard_t *dst, const uint8_t *src)
{
    memcpy(dst, src, sizeof(encryption_info_stream_standard_t));
    dst->version_major = ole2_endian_convert_16(dst->version_major);
    dst->version_minor = ole2_endian_convert_16(dst->version_minor);

    dst->flags = ole2_endian_convert_32(dst->flags);
    dst->size  = ole2_endian_convert_32(dst->size);

    dst->encryptionInfo.flags           = ole2_endian_convert_32(dst->encryptionInfo.flags);
    dst->encryptionInfo.sizeExtra       = ole2_endian_convert_32(dst->encryptionInfo.sizeExtra);
    dst->encryptionInfo.algorithmID     = ole2_endian_convert_32(dst->encryptionInfo.algorithmID);
    dst->encryptionInfo.algorithmIDHash = ole2_endian_convert_32(dst->encryptionInfo.algorithmIDHash);
    dst->encryptionInfo.keySize         = ole2_endian_convert_32(dst->encryptionInfo.keySize);
    dst->encryptionInfo.providerType    = ole2_endian_convert_32(dst->encryptionInfo.providerType);
    dst->encryptionInfo.reserved1       = ole2_endian_convert_32(dst->encryptionInfo.reserved1);
    dst->encryptionInfo.reserved2       = ole2_endian_convert_32(dst->encryptionInfo.reserved2);
}

void copy_encryption_verifier(encryption_verifier_t *dst, const uint8_t *src)
{
    memcpy(dst, src, sizeof(encryption_verifier_t));
    dst->salt_size          = ole2_endian_convert_32(dst->salt_size);
    dst->verifier_hash_size = ole2_endian_convert_32(dst->verifier_hash_size);
}

static inline bool key_length_valid_aes_bits(const uint32_t keyLength)
{
    switch (keyLength) {
        case SE_HEADER_EI_AES128_KEYSIZE:
            /* fall-through */
        case SE_HEADER_EI_AES192_KEYSIZE:
            /* fall-through */
        case SE_HEADER_EI_AES256_KEYSIZE:
            return true;
    }
    return false;
}

/*Definitions for generate_key_aes*/
#define GENERATE_KEY_AES_ITERATIONS 50000

/*
 * @brief           Generate the key for aes encryption based on the password
 * @param password  Password to generate the key from
 * @param key       [out] location to store the key
 * @param verifier  encryption_verifier_t from the header.  Contains information necessary to generate the key
 *
 * @return          Error code based on whether or not the key was generated.  This function
 *                  does NOT validate the key, you must call 'verify_key' for that.
 */
static cl_error_t generate_key_aes(const char *const password, encryption_key_t *key,
                                   encryption_verifier_t *verifier)
{
    uint8_t *buffer                                                    = NULL;
    size_t bufLen                                                      = 0;
    cl_error_t ret                                                     = CL_ERROR;
    uint32_t i                                                         = 0;
    uint8_t sha1[sizeof(uint32_t) + SHA1_HASH_SIZE + sizeof(uint32_t)] = {0};
    uint8_t *sha1Dst                                                   = &(sha1[sizeof(uint32_t)]);
    uint8_t buf1[64];
    uint8_t buf2[64];
    uint8_t doubleSha[SHA1_HASH_SIZE * 2];
    uint32_t tmp = 0;

    if (!key_length_valid_aes_bits(key->key_length_bits)) {
        cli_errmsg("ole2: Invalid key length '0x%x'\n", key->key_length_bits / 8);
        goto done;
    }

    memset(key->key, 0, key->key_length_bits / 8);

    bufLen = verifier->salt_size + (strlen(password) * 2);

    buffer = calloc(bufLen, 1);
    if (NULL == buffer) {
        cli_errmsg("ole2: calloc failed\n");
        ret = CL_EMEM;
        goto done;
    }

    tmp = verifier->salt_size;
    if (verifier->salt_size > sizeof(verifier->salt)) {
        cli_dbgmsg("ole2: Invalid salt length '0x%x'\n", verifier->salt_size);
        tmp = sizeof(verifier->salt);
    }
    memcpy(buffer, verifier->salt, tmp);

    /*Convert to UTF16-LE*/
    for (i = 0; i < (uint32_t)strlen(password); i++) {
        buffer[verifier->salt_size + (i * 2)] = password[i];
    }

    (void)cl_sha1(buffer, bufLen, sha1Dst, NULL);

    for (i = 0; i < GENERATE_KEY_AES_ITERATIONS; i++) {
        uint32_t eye = ole2_endian_convert_32(i);

        memcpy(sha1, &eye, sizeof(eye));
        (void)cl_sha1(sha1, SHA1_HASH_SIZE + sizeof(uint32_t), sha1Dst, NULL);
    }

    memset(&(sha1Dst[SHA1_HASH_SIZE]), 0, sizeof(uint32_t));

    (void)cl_sha1(sha1Dst, SHA1_HASH_SIZE + sizeof(uint32_t), sha1Dst, NULL);

    memset(buf1, 0x36, sizeof(buf1));
    for (i = 0; i < SHA1_HASH_SIZE; i++) {
        buf1[i] = buf1[i] ^ sha1Dst[i];
    }

    // now sha1 buf1
    (void)cl_sha1(buf1, sizeof(buf1), doubleSha, NULL);

    memset(buf2, 0x5c, sizeof(buf2));
    for (i = 0; i < SHA1_HASH_SIZE; i++) {
        buf2[i] = buf2[i] ^ sha1Dst[i];
    }

    (void)cl_sha1(buf2, sizeof(buf2), &(doubleSha[SHA1_HASH_SIZE]), NULL);

    tmp = key->key_length_bits / 8;
    if (tmp > sizeof(key->key)) {
        cli_warnmsg("ole2: Invalid key length 0x%x\n", key->key_length_bits / 8);
        tmp = sizeof(key->key);
    }

    memcpy(key->key, doubleSha, tmp);
    ret = CL_SUCCESS;
done:
    CLI_FREE_AND_SET_NULL(buffer);

    return ret;
}

static bool aes_128ecb_decrypt(const unsigned char *in, size_t length, unsigned char *out, const encryption_key_t *const key)
{
    uint32_t rk[RKLENGTH(128)];
    int nrounds;
    size_t i;
    bool bRet = false;

    if (SE_HEADER_EI_AES128_KEYSIZE != key->key_length_bits) {
        cli_dbgmsg("ole2: Unsupported AES key length in aes_128ecb_decrypt\n");
        goto done;
    }

    nrounds = rijndaelSetupDecrypt(rk, (const unsigned char *)key->key, key->key_length_bits);

    if (!nrounds) {
        cli_errmsg("ole2: Unable to initialize decryption.\n");
        goto done;
    } else {
        for (i = 0; i < length; i += 16) {
            rijndaelDecrypt(rk, nrounds, &(in[i]), &(out[i]));
        }
    }

    bRet = true;
done:

    return bRet;
}

/*Definitions for verify_key_aes*/
#define AES_VERIFIER_HASH_LEN 32
/*
 * @brief           Returns true if it is actually encrypted with the key.
 * @param key       encryption_key_t to attempt validation
 * @param verifier  encryption_verifier_t to attempt validation.
 * @return          Success or failure depending on whether validation was successful.
 *
 * For more information, see below
 * https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/e5ad39b8-9bc1-4a19-bad3-44e6246d21e6
 */
static bool verify_key_aes(const encryption_key_t *const key, encryption_verifier_t *verifier)
{

    bool bRet = false;
    uint8_t sha[SHA1_HASH_SIZE];
    uint8_t decrypted[AES_VERIFIER_HASH_LEN] = {0};
    uint32_t actual_hash_size                = 0;

    // The hash size should be 20 bytes, even though the buffer is 32 bytes.
    // If it claims to be LARGER than 32 bytes, we have a problem - because the buffer isn't that big.
    actual_hash_size = verifier->verifier_hash_size;
    if (actual_hash_size > sizeof(verifier->encrypted_verifier_hash)) {
        cli_dbgmsg("ole2: Invalid encrypted verifier hash length 0x%x\n", verifier->verifier_hash_size);
        actual_hash_size = sizeof(verifier->encrypted_verifier_hash);
    }

    switch (key->key_length_bits) {
        case SE_HEADER_EI_AES128_KEYSIZE:
            // Decrypt the verifier, which is a randomly generated Verifier value encrypted using
            // the algorithm chosen by the implementation.
            if (!aes_128ecb_decrypt(verifier->encrypted_verifier, sizeof(verifier->encrypted_verifier), decrypted, key)) {
                goto done;
            }

            // Get hash of decrypted verifier.
            // The hash type is from the encryption header, but in this case should always be SHA1.
            (void)cl_sha1(decrypted, sizeof(verifier->encrypted_verifier), sha, NULL);

            // Decrypt the verifier hash, which, for contains the encrypted form of the hash of the randomly generated Verifier value
            if (!aes_128ecb_decrypt(verifier->encrypted_verifier_hash, actual_hash_size, decrypted, key)) {
                goto done;
            }

            break;
        case SE_HEADER_EI_AES192_KEYSIZE:
            // not implemented
            goto done;
        case SE_HEADER_EI_AES256_KEYSIZE:
            // not implemented
            goto done;
        default:
            // unsupported/invalid key size
            goto done;
    }

    // Compare our (20-byte) SHA1 with the decrypted hash, which should be the same.
    // Note: the hash size is different then ... what are we gonna do?  We only support SHA1 hashes for this algorithm.
    // So we'll just assume they're the same for this comparison.
    bRet = (0 == memcmp(sha, decrypted, SHA1_HASH_SIZE));

done:

    return bRet;
}

/*Definitions for initialize_encryption_key*/
#define SE_HEADER_FCRYPTOAPI (1 << 2)
#define SE_HEADER_FEXTERNAL (1 << 4)
#define SE_HEADER_FDOCPROPS (1 << 3)
#define SE_HEADER_FAES (1 << 5)
#define SE_HEADER_EI_AES128 0x0000660e
#define SE_HEADER_EI_AES192 0x0000660f
#define SE_HEADER_EI_AES256 0x00006610
#define SE_HEADER_EI_RC4 0x00006801
#define SE_HEADER_EI_SHA1 0x00008004
#define SE_HEADER_EI_AES_PROVIDERTYPE 0x00000018
/**
 * @brief               Initialize encryption key, if the encryption validation passes.
 *
 * @param encryptionInfo     Pointer to the encryption header.
 * @param encryptionKey [out] Pointer to encryption_key_t structure to be initialized by this function.
 * @return              Success or failure depending on whether or not the
 *                      encryption verifier was successful with the
 *                      standard password (VelvetSweatshop).
 *
 * Information about the encryption keys is here
 * https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/dca653b5-b93b-48df-8e1e-0fb9e1c83b0f
 * https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/2895eba1-acb1-4624-9bde-2cdad3fea015
 *
 */
static bool initialize_encryption_key(
    const uint8_t *encryptionInfoStreamPtr,
    size_t remainingBytes,
    encryption_key_t *encryptionKey,
    encryption_status_t *pEncryptionStatus)
{
    bool bRet  = false;
    size_t idx = 0;
    encryption_key_t key;
    bool bAES = false;

    encryption_info_stream_standard_t encryptionInfo = {0};
    uint16_t *encryptionInfo_CSPName                 = NULL;
    size_t CSPName_length                            = 0;
    const uint8_t *encryptionVerifierPtr             = NULL;
    encryption_verifier_t encryptionVerifier         = {0};

    // Populate the encryption_info_stream_standard_t structure
    copy_encryption_info_stream_standard(&encryptionInfo, encryptionInfoStreamPtr);

    memset(encryptionKey, 0, sizeof(encryption_key_t));
    memset(&key, 0, sizeof(encryption_key_t));

    cli_dbgmsg("Major Version   = 0x%x\n", encryptionInfo.version_major);
    cli_dbgmsg("Minor Version   = 0x%x\n", encryptionInfo.version_minor);
    cli_dbgmsg("Flags           = 0x%x\n", encryptionInfo.flags);

    /*Bit 0 and 1 must be 0*/
    if (1 & encryptionInfo.flags) {
        cli_dbgmsg("ole2: Invalid first bit, must be 0\n");
        goto done;
    }

    if ((1 << 1) & encryptionInfo.flags) {
        cli_dbgmsg("ole2: Invalid second bit, must be 0\n");
        goto done;
    }

    // https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/200a3d61-1ab4-4402-ae11-0290b28ab9cb
    if ((SE_HEADER_FDOCPROPS & encryptionInfo.flags)) {
        cli_dbgmsg("ole2: Unsupported document properties encrypted\n");
        goto done;
    }

    if ((SE_HEADER_FEXTERNAL & encryptionInfo.flags) &&
        (SE_HEADER_FEXTERNAL != encryptionInfo.flags)) {
        cli_dbgmsg("ole2: Invalid fExternal flags.  If fExternal bit is set, nothing else can be\n");
        goto done;
    }

    if (SE_HEADER_FAES & encryptionInfo.flags) {
        if (!(SE_HEADER_FCRYPTOAPI & encryptionInfo.flags)) {
            cli_dbgmsg("ole2: Invalid combo of fAES and fCryptoApi flags\n");
            goto done;
        }

        cli_dbgmsg("Flags           = AES\n");
    }

    cli_dbgmsg("Size            = 0x%x\n", encryptionInfo.size);

    if (encryptionInfo.flags != encryptionInfo.encryptionInfo.flags) {
        cli_dbgmsg("ole2: Flags must match\n");
        goto done;
    }

    if (0 != encryptionInfo.encryptionInfo.sizeExtra) {
        cli_dbgmsg("ole2: Size Extra must be 0\n");
        goto done;
    }

    switch (encryptionInfo.encryptionInfo.algorithmID) {
        case SE_HEADER_EI_AES128:
            if (SE_HEADER_EI_AES128_KEYSIZE != encryptionInfo.encryptionInfo.keySize) {
                cli_dbgmsg("ole2: Key length does not match algorithm id\n");
                goto done;
            }
            bAES                               = true;
            pEncryptionStatus->encryption_type = AES128_ENCRYPTION;
            break;
        case SE_HEADER_EI_AES192:
            // not implemented
            if (SE_HEADER_EI_AES192_KEYSIZE != encryptionInfo.encryptionInfo.keySize) {
                cli_dbgmsg("ole2: Key length does not match algorithm id\n");
                goto done;
            }
            bAES                               = true;
            pEncryptionStatus->encryption_type = AES192_ENCRYPTION;
            goto done;
        case SE_HEADER_EI_AES256:
            // not implemented
            if (SE_HEADER_EI_AES256_KEYSIZE != encryptionInfo.encryptionInfo.keySize) {
                cli_dbgmsg("ole2: Key length does not match algorithm id\n");
                goto done;
            }
            bAES                               = true;
            pEncryptionStatus->encryption_type = AES256_ENCRYPTION;
            goto done;
        case SE_HEADER_EI_RC4:
            // not implemented
            pEncryptionStatus->encryption_type = RC4_ENCRYPTION;
            goto done;
        default:
            cli_dbgmsg("ole2: Invalid Algorithm ID: 0x%x\n", encryptionInfo.encryptionInfo.algorithmID);
            goto done;
    }

    if (SE_HEADER_EI_SHA1 != encryptionInfo.encryptionInfo.algorithmIDHash) {
        cli_dbgmsg("ole2: Invalid Algorithm ID Hash: 0x%x\n", encryptionInfo.encryptionInfo.algorithmIDHash);
        goto done;
    }

    if (!key_length_valid_aes_bits(encryptionInfo.encryptionInfo.keySize)) {
        cli_dbgmsg("ole2: Invalid key size: 0x%x\n", encryptionInfo.encryptionInfo.keySize);
        goto done;
    }

    cli_dbgmsg("KeySize         = 0x%x\n", encryptionInfo.encryptionInfo.keySize);

    if (SE_HEADER_EI_AES_PROVIDERTYPE != encryptionInfo.encryptionInfo.providerType) {
        cli_dbgmsg("ole2: WARNING: Provider Type should be '0x%x', is '0x%x'\n",
                   SE_HEADER_EI_AES_PROVIDERTYPE, encryptionInfo.encryptionInfo.providerType);
        goto done;
    }

    cli_dbgmsg("Reserved1       = 0x%x\n", encryptionInfo.encryptionInfo.reserved1);

    if (0 != encryptionInfo.encryptionInfo.reserved2) {
        cli_dbgmsg("ole2: Reserved 2 must be zero, is 0x%x\n", encryptionInfo.encryptionInfo.reserved2);
        goto done;
    }

    /* The encryption info is at the end of the CPSName string.
     * Find the end, and we'll have the index of the EncryptionVerifier.
     * The CPSName string *should* always be either
     * 'Microsoft Enhanced RSA and AES Cryptographic Provider'
     * or
     * 'Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)'
     */
    encryptionInfo_CSPName = (uint16_t *)(encryptionInfoStreamPtr + sizeof(encryption_info_stream_standard_t));
    remainingBytes -= sizeof(encryption_info_stream_standard_t);

    if (0 == remainingBytes) {
        cli_dbgmsg("ole2: No CSPName or encryption_verifier_t\n");
        goto done;
    }

    while (true) {
        // Check if we've gone past the end of the buffer without finding the end of the CSPName string.
        if ((idx + 1) * sizeof(uint16_t) > remainingBytes) {
            cli_dbgmsg("ole2: CSPName is missing null terminator before end of buffer.\n");
            goto done;
        }
        // Check if we've found the end of the CSPName string.
        if (encryptionInfo_CSPName[idx] == 0) {
            break;
        }
        // Found another character in the CSPName string, keep going.
        idx++;
    }

    CSPName_length = (idx + 1) * sizeof(uint16_t);

    encryptionVerifierPtr = (uint8_t *)encryptionInfo_CSPName + CSPName_length;
    remainingBytes -= CSPName_length;

    if (remainingBytes < sizeof(encryption_verifier_t)) {
        cli_dbgmsg("ole2: No encryption_verifier_t\n");
        goto done;
    }
    copy_encryption_verifier(&encryptionVerifier, encryptionVerifierPtr);

    key.key_length_bits = encryptionInfo.encryptionInfo.keySize;
    if (!bAES) {
        cli_dbgmsg("ole2: Unsupported encryption algorithm\n");
        goto done;
    }

    if (CL_SUCCESS != generate_key_aes("VelvetSweatshop", &key, &encryptionVerifier)) {
        /*Error message printed by generate_key_aes*/
        goto done;
    }

    if (!verify_key_aes(&key, &encryptionVerifier)) {
        cli_dbgmsg("ole2: Key verification for '%s' failed, unable to decrypt.\n", "VelvetSweatshop");
        goto done;
    }

    memcpy(encryptionKey, &key, sizeof(encryption_key_t));
    bRet                               = true;
    pEncryptionStatus->encryption_type = VELVET_SWEATSHOP_ENCRYPTION;
done:

    if (pEncryptionStatus->encryption_type) {
        pEncryptionStatus->encrypted = true;
    }
    pEncryptionStatus->velvet_sweatshop = bRet;

    return bRet;
}

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
    encryption_key_t key;
    bool bEncrypted                       = false;
    size_t encryption_offset              = 0;
    encryption_status_t encryption_status = {0};

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

    if ((size_t)(ctx->fmap->len) < (size_t)(hdr_size)) {
        return CL_CLEAN;
    }
    hdr.map      = ctx->fmap;
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
    if (hdr.log2_big_block_size < 6 || hdr.log2_big_block_size > 28) {
        // The big block size (aka Sector Shift) is expected to be:
        //  - 9   for Major Version 3
        //  - 12  for Major Version 4
        //  - TBD for Major Version 5?
        // To allow for future changes, and prevent overflowing an int32_t, we're limiting to 28.
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

    /* determine if encrypted with VelvetSweatshop password */
    encryption_offset = 4 * (1 << hdr.log2_big_block_size);
    if ((encryption_offset + sizeof(encryption_info_stream_standard_t)) <= hdr.m_length) {

        bEncrypted = initialize_encryption_key(
            &(((const uint8_t *)phdr)[encryption_offset]),
            hdr.m_length - encryption_offset,
            &key, &encryption_status);
    }

    /* 8 SBAT blocks per file block */
    hdr.max_block_no = (hdr.map->len - MAX(512, 1 << hdr.log2_big_block_size)) / (1 << hdr.log2_small_block_size);

    print_ole2_header(&hdr);
    cli_dbgmsg("Max block number: %lu\n", (unsigned long int)hdr.max_block_no);

    /* PASS 1 : Count files and check for VBA */
    hdr.has_vba   = false;
    hdr.has_xlm   = false;
    hdr.has_image = false;
    ret           = ole2_walk_property_tree(&hdr, NULL, 0, handler_enum, 0, &file_count, ctx, &scansize, NULL, &encryption_status);
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
        ole2_walk_property_tree(&hdr, dirname, 0, handler_writefile, 0, &file_count, ctx, &scansize2, NULL, &encryption_status);
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
        if (bEncrypted) {
            ret = ole2_walk_property_tree(&hdr, NULL, 0, handler_otf_encrypted, 0, &file_count, ctx, &scansize2, &key, &encryption_status);
        } else {
            ret = ole2_walk_property_tree(&hdr, NULL, 0, handler_otf, 0, &file_count, ctx, &scansize2, NULL, &encryption_status);
        }
    }

    if (SCAN_COLLECT_METADATA && (ctx->this_layer_metadata_json != NULL)) {
        if (encryption_status.encrypted) {
            if (encryption_status.encryption_type) {
                cli_jsonstr(ctx->this_layer_metadata_json, ENCRYPTED_JSON_KEY, encryption_status.encryption_type);
            } else {
                cli_jsonstr(ctx->this_layer_metadata_json, ENCRYPTED_JSON_KEY, GENERIC_ENCRYPTED);
            }
        }
    }

    if (SCAN_HEURISTIC_ENCRYPTED_DOC && encryption_status.encrypted && (!encryption_status.velvet_sweatshop)) {
        cl_error_t status = cli_append_potentially_unwanted(ctx, OLE2_HEURISTIC_ENCRYPTED_WARNING);
        if (CL_SUCCESS != status) {
            cli_errmsg("OLE2 : Unable to warn potentially unwanted signature '%s'\n", "Heuristics.Encrypted.OLE2");
            ret = status;
        }
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
