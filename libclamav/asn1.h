/*
 *  Copyright (C) 2011 Sourcefire, Inc.
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

int asn1_load_mscat(fmap_t *map, struct cl_engine *engine);
int asn1_check_mscat(struct cl_engine *engine, fmap_t *map, size_t offset, unsigned int size, uint8_t *computed_sha1);

#endif
