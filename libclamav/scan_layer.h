/*
 *  Copyright (C) 2021-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Authors: Valerie Snyder
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

#ifndef __SCAN_LAYER_H_LC
#define __SCAN_LAYER_H_LC

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clamav.h"
#include "filetypes.h"
#include "other_types.h"

#include "json.h"

typedef struct cli_scan_layer {
    cli_file_t type;
    size_t size;
    cl_fmap_t *fmap;                      /* The fmap for this layer. This used to be in an array in the ctx. */
    uint32_t recursion_level;             /* The recursion level of this layer in the scan stack. */
    uint32_t recursion_level_buffer;      /* Which buffer layer in scan recursion. */
    uint32_t recursion_level_buffer_fmap; /* Which fmap layer in this buffer. */
    uint32_t attributes;                  /* layer attributes. */
    image_fuzzy_hash_t image_fuzzy_hash;  /* Used for image/graphics files to store a fuzzy hash. */
    bool calculated_image_fuzzy_hash;     /* Used for image/graphics files to store a fuzzy hash. */
    size_t object_id;                     /* Unique ID for this object. */
    json_object *metadata_json;           /* JSON object for this recursion level, e.g. for JSON metadata. */
    evidence_t evidence;                  /* Store signature matches for this layer and its children. */
    cl_verdict_t verdict;                 /* Verdict for this layer, e.g. CL_VERDICT_STRONG_INDICATOR, CL_VERDICT_NOTHING_FOUND, CL_VERDICT_TRUSTED. */
    char *tmpdir;                         /* The directory to store tmp files created when processing this layer. */
    struct cli_scan_layer *parent;        /* Pointer to the parent layer, if any. */
} cli_scan_layer_t;

#endif /* __SCAN_LAYER_H_LC */
