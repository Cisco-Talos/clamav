/*
 *  Copyright (C) 2006 Sensory Networks, Inc.
 *	      Written by Tomasz Kojm
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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

#ifndef __SIS_H
#define __SIS_H

#include "clamav.h"
#include "others.h"

struct sis_file_hdr {
    uint32_t uid1;
    uint32_t uid2;
    uint32_t uid3;
    uint32_t uid4;
    uint16_t checksum;
    uint16_t nlangs;
    uint16_t nfiles;
    uint16_t nreqs;
    uint16_t ilang;
    uint16_t ifiles;
    uint16_t idrive;
    uint16_t ncaps;
    uint32_t iver;
    uint16_t options;
    uint16_t type;
    uint16_t majorver;
    uint16_t minorver;
    uint16_t variant;
    uint32_t plangs;
    uint32_t pfiles;
    uint32_t preqs;
    uint32_t pcerts;
    uint32_t pname;
};

struct sis_file_hdr6 {
    uint32_t psig;
    uint32_t pcaps;
    uint32_t ispace;
    uint32_t maxispace;
    uint32_t reserved[4];
};

int cli_scansis(int desc, cli_ctx *ctx);

#endif
