/*
 *  Copyright (C) 2006 Sensory Networks, Inc.
 *             Written by aCaB <acab@clamav.net>
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
** suecrypt.c
**
** 05/08/2k6 - Quick RCE, started coding.
** 06/08/2k6 - There were large drops of black rain.
** 07/08/2k6 - Found more versions, back to reversing.
** 11/08/2k6 - Generic and special cases handler. Release. 
**
*/

/*
** Unpacks and rebuilds suecrypt(*)
**
** Not sure at all what this stuff is, couldn't find any reference to it
** Seems to be popular in dialers, can't say more except...
** Christoph asked for it and that's enough :)
**
** (*) some versions or maybe only some samples
*/

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <string.h>

#include "cltypes.h"
#include "others.h"
#include "pe.h"
#include "suecrypt.h"

#define EC32(x) le32_to_host(x) /* Convert little endian to host */
#define EC16(x) le16_to_host(x)

char *sudecrypt(int desc, size_t fsize, struct cli_exe_section *sections, uint16_t sects, char *buff, uint32_t bkey, uint32_t pkey, uint32_t e_lfanew) {
  char *file, *hunk;
  uint32_t va,sz,key;
  int i, j;

  cli_dbgmsg("in suecrypt\n");

  if (!(file=cli_calloc(fsize, 1))) return 0;
  lseek(desc, 0, SEEK_SET);
  if((size_t) cli_readn(desc, file, fsize) != fsize) {
    cli_dbgmsg("SUE: Can't read %d bytes\n", fsize);
    free(file);
    return 0;
  }

  va=(bkey>>16)|(bkey<<16);
  key=((sz=cli_readint32(buff+0x3e))^va);
  if (!key || key==0x208 || key==0x3bc) key=((sz=cli_readint32(buff+0x46))^va); /* FIXME: black magic */

  if (key!=pkey) {
    cli_dbgmsg("SUE: Key seems not (entirely) encrypted\n\tpossible key: 0%08x\n\tcrypted key:  0%08x\n\tplain key:    0%08x\n", pkey, key, sz);
    va=0;
    for (i=0; i<4; i++) {
      va=(va<<8)|0xff;
      if (((key&va)|(sz&(~va)))==pkey) {
	key=pkey;
	break;
      }
    }
    if (i==4) cli_dbgmsg("SUE: let's roll the dice...\n");
  }
  cli_dbgmsg("SUE: Decrypting with 0%08x\n", key);

  i=0;
  while(1) {
    if (!CLI_ISCONTAINED(buff-0x74, 0xbe, buff-0x58+i*8, 8)) {
      free(file);
      return 0;
    }
    va=(cli_readint32(buff-0x58+i*8)^bkey);
    sz=(cli_readint32(buff-0x58+4+i*8)^bkey);
    if (!va) break;
    cli_dbgmsg("SUE: Hunk #%d RVA:%x size:%d\n", i, va, sz);
    for (j=0; j<sects; j++) {
      if(!CLI_ISCONTAINED(sections[j].rva, sections[j].rsz, va, sz)) continue;
      hunk=file+sections[j].rva-va+sections[j].raw;
      while(sz>=4) {
	cli_writeint32(hunk, cli_readint32(hunk)^key);
	hunk+=4;
	sz-=4;
      }
      break;
    }
    if (j==sects) {
      cli_dbgmsg("SUE: Hunk out of file or cross sections\n");
      free(file);
      return 0;
    }
    i++;
  }
  va=(cli_readint32(buff-0x74)^bkey);
  cli_dbgmsg("SUE: found OEP: @%x\n", va);

  hunk=file+e_lfanew;
  hunk[6]=sects&0xff;
  hunk[7]=sects>>8;
  cli_writeint32(hunk+0x28, va);
  hunk+=0x18+(cli_readint32(hunk+0x14)&0xffff); /* size of PE + size of OPT */
  memset(hunk+0x28*sects, 0, 0x28);

  return file;
}
