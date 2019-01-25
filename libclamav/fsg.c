/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Alberto Wu
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

/*
** defsg.c
** 
** 02/08/2k4 - Dumped and reversed
** 02/08/2k4 - Done coding
** 03/08/2k4 - Cleaning and securing
** 04/08/2k4 - Done porting
** 07/08/2k4 - Started adding support for 1.33
*/

/*
** Unpacks an FSG compressed section.
**
** Czesc bart, good asm, nice piece of code ;)
*/

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdlib.h>

#include "clamav.h"
#include "rebuildpe.h"
#include "others.h"
#include "packlibs.h"
#include "fsg.h"

int unfsg_200(const char *source, char *dest, int ssize, int dsize, uint32_t rva, uint32_t base, uint32_t ep, int file) {
  struct cli_exe_section section; /* Yup, just one ;) */
  
  if ( cli_unfsg(source, dest, ssize, dsize, NULL, NULL) ) return -1;
  
  section.raw=0;
  section.rsz = dsize;
  section.vsz = dsize;
  section.rva = rva;

  if (!cli_rebuildpe(dest, &section, 1, base, ep, 0, 0, file)) {
    cli_dbgmsg("FSG: Rebuilding failed\n");
    return 0;
  }
  return 1;
}


int unfsg_133(const char *source, char *dest, int ssize, int dsize, struct cli_exe_section *sections, int sectcount, uint32_t base, uint32_t ep, int file) {
  const char *tsrc=source;
  char *tdst=dest;
  int i, upd=1, offs=0, lastsz=dsize;

  for (i = 0 ; i <= sectcount ; i++) {
    char *startd=tdst;
    if ( cli_unfsg(tsrc, tdst, ssize - (tsrc - source), dsize - (tdst - dest), &tsrc, &tdst) == -1 )
      return -1;

    /* RVA has been filled already in pe.c */
    sections[i].raw=offs;
    sections[i].rsz=tdst-startd;
    /*    cli_dbgmsg("Unpacked section %d @%x size %x Vsize =%x \n", i, offs, tdst-startd, dsize - (startd - dest)); */
    offs+=tdst-startd;
  }

  /* Sort out the sections */
  while ( upd ) {
    upd = 0;
    for (i = 0; i < sectcount  ; i++) {
      uint32_t trva,trsz,traw;
      
      if ( sections[i].rva <= sections[i+1].rva )
	continue;
      trva = sections[i].rva;
      traw = sections[i].raw;
      trsz = sections[i].rsz;
      sections[i].rva = sections[i+1].rva;
      sections[i].rsz = sections[i+1].rsz;
      sections[i].raw = sections[i+1].raw;
      sections[i+1].rva = trva;
      sections[i+1].raw = traw;
      sections[i+1].rsz = trsz;
      upd = 1;
    }
  }

  /* Cure Vsizes and debugspam */
  for (i = 0; i <= sectcount ; i++) {
    if ( i != sectcount ) {
      sections[i].vsz = sections[i+1].rva - sections[i].rva;
      lastsz-= sections[i+1].rva - sections[i].rva;
    }
    else 
      sections[i].vsz = lastsz;

    cli_dbgmsg("FSG: .SECT%d RVA:%x VSize:%x ROffset: %x, RSize:%x\n", i, sections[i].rva, sections[i].vsz, sections[i].raw, sections[i].rsz);
  }

  if (!cli_rebuildpe(dest, sections, sectcount+1, base, ep, 0, 0, file)) {
    cli_dbgmsg("FSG: Rebuilding failed\n");
    return 0;
  }
  return 1;
}
