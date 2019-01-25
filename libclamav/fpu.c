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

#include "others.h"
#include "fpu.h"

/* the character representation of the double below is "elleemme" or "emmeelle" upon depending
   whether floating point little endian or big endian(IEEE-754) is in effect. */
int get_fpu_endian(void)
{
#ifdef _WIN32
  return FPU_ENDIAN_LITTLE;
#else
    const char * fpu_le = "elleemme";
    const char * fpu_be = "emmeelle";
    const union sd {
        double d;
        char mem[8];
    } u_md = {3815911171354501045744583353695226502220105394563506259449467213186125718792664588210662403287568710818873279842508553551908601408568128557088985172985437412593385138085986771664896.0};
    if (!memcmp(u_md.mem, fpu_le, 8)) {
        cli_dbgmsg("fpu: Floating point little endian detected.\n");
        return FPU_ENDIAN_LITTLE;
    } else if (!memcmp(u_md.mem, fpu_be, 8)) {
        cli_dbgmsg("fpu: Floating point big endian detected.\n");
        return FPU_ENDIAN_BIG;
    } else {
        cli_dbgmsg("fpu: Floating point endian detection failed. "
                   "Bytes: %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x \n",
                   u_md.mem[0], u_md.mem[1], u_md.mem[2], u_md.mem[3], 
                   u_md.mem[4], u_md.mem[5], u_md.mem[6], u_md.mem[7]);
    }
    return FPU_ENDIAN_UNKNOWN;
#endif
}
