/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2011-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB
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

#ifndef __ASN1_H
#define __ASN1_H

#include "others.h"
#include "fmap.h"

struct cli_mapped_region {
    unsigned int offset;
    unsigned int size;
};

int asn1_load_mscat(fmap_t *map, struct cl_engine *engine);
cl_error_t asn1_check_mscat(struct cl_engine *engine, fmap_t *map, size_t offset, unsigned int size, struct cli_mapped_region *regions, uint32_t nregions);

#endif
