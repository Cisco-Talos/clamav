/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2013 Sourcefire, Inc.
 *
 *  Authors: Steven Morgan <smorgan@sourcefire.com>
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

#include "../libclamav/clamav.h"
#include "../libclamav/fpu.h"

/* Helper command line interface to determine fpu endianness in unit test scripts.
 *   parameters: none
 *   returns:
 *     1 - fpu big endian
 *     2 - fpu little endian
 *     3 - fpu endian unknown
 */

int main (int argc, char **argv)
{
    UNUSEDPARAM(argc);
    UNUSEDPARAM(argv);
    return  get_fpu_endian();
}
