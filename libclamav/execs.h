/*
 *  Copyright (C) 2005 Tomasz Kojm <tkojm@clamav.net>
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef __EXECS_H
#define __EXECS_H

#include "cltypes.h"

struct cli_exe_section {
    uint32_t rva;
    uint32_t vsz;
    uint32_t raw;
    uint32_t rsz;
};

struct cli_exe_info {
    uint32_t ep;
    uint16_t nsections;
    struct cli_exe_section *section;
};

#endif
