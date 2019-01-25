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
** unsp.c
**
** 11/10/2k6 - Merge started.
**
*/

/*
** Plays around with NsPack compressed executables
**
** This piece of code is dedicated to Damian Put
** who I made a successful and wealthy man.
**
** Damian, you owe me a pint!
*/

/*
** TODO:
**
** - Investigate the "unused" code in NsPack
** - Fetch all the nspacked samples from the zoo and run extensive testing
** - Add bound checks
** - Test against the zoo again
** - Perform regression testing against the full zoo 
** - check nested
** - look at the 64bit version (one of these days)
**
*/

/* 

   FIXME: clean this rubbish


init_and_check_dll_loadflags();

nsp1:004359FE                 add     edi, [ebp-28Dh]
nsp1:00435A04                 mov     ebx, edi
nsp1:00435A06                 cmp     dword ptr [edi], 0
nsp1:00435A09                 jnz     short loc_435A15
nsp1:00435A0B                 add     edi, 4
nsp1:00435A0E                 mov     ecx, 0
nsp1:00435A13                 jmp     short loc_435A2B
nsp1:00435A15 ; ---------------------------------------------------------------------------
nsp1:00435A15
nsp1:00435A15 loc_435A15:                             ; CODE XREF: start+349EEj
nsp1:00435A15                 mov     ecx, 1
nsp1:00435A1A                 add     edi, [ebx]
nsp1:00435A1C                 add     ebx, 4
nsp1:00435A1F
nsp1:00435A1F loc_435A1F:                             ; CODE XREF: start+34A3Dj
nsp1:00435A1F                 cmp     dword ptr [ebx], 0
nsp1:00435A22                 jz      short loc_435A5A
nsp1:00435A24                 add     [ebx], edx
nsp1:00435A26                 mov     esi, [ebx]
nsp1:00435A28                 add     edi, [ebx+4]
nsp1:00435A2B
nsp1:00435A2B loc_435A2B:                             ; CODE XREF: start+349F8j
nsp1:00435A2B                 push    edi
nsp1:00435A2C                 push    ecx
nsp1:00435A2D                 push    edx
nsp1:00435A2E                 push    ebx
nsp1:00435A2F                 push    dword ptr [ebp-1D1h] ; VirtualFree
nsp1:00435A35                 push    dword ptr [ebp-1D5h] ; alloc
nsp1:00435A3B                 mov     edx, esi
nsp1:00435A3D                 mov     ecx, edi
nsp1:00435A3F                 mov     eax, offset get_byte
nsp1:00435A44                 int     3               ; Trap to Debugger
nsp1:00435A45                 add     eax, 5A9h
nsp1:00435A4A                 call    eax ; real_unpack ; edx=401000
nsp1:00435A4A                                         ; ecx=436282
nsp1:00435A4C                 pop     ebx
nsp1:00435A4D                 pop     edx
nsp1:00435A4E                 pop     ecx
nsp1:00435A4F                 pop     edi
nsp1:00435A50                 cmp     ecx, 0
nsp1:00435A53                 jz      short loc_435A5A
nsp1:00435A55                 add     ebx, 8
nsp1:00435A58                 jmp     short loc_435A1F
nsp1:00435A5A ; ---------------------------------------------------------------------------
nsp1:00435A5A
nsp1:00435A5A loc_435A5A:                             ; CODE XREF: start+34A07j
nsp1:00435A5A                                         ; start+34A38j
nsp1:00435A5A                 push    8000h

*/

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdlib.h>

#include "clamav.h"
#include "others.h"
#include "rebuildpe.h"
#include "execs.h"
#include "unsp.h"


/* real_unpack(start_of_stuff, dest, malloc, free); */
uint32_t unspack(const char *start_of_stuff, char *dest, cli_ctx *ctx, uint32_t rva, uint32_t base, uint32_t ep, int file) {
  uint8_t c = *start_of_stuff;
  uint32_t i,firstbyte,tre,allocsz,tablesz,dsize,ssize;
  uint16_t *table;
  char *dst = dest;
  const char *src = start_of_stuff+0xd;
  struct cli_exe_section section;
  
  if (c>=0xe1) return 1;

  if (c>=0x2d) {
    firstbyte = i = c/0x2d;
    do {c+=0xd3;} while (--i);
  } else firstbyte = 0;

  if (c>=9) {
    allocsz = i = c/9;
    do {c+=0xf7;} while (--i);
  } else allocsz = 0;
  
  tre = c;
  i = allocsz;
  c = (tre+i)&0xff;
  tablesz = ((0x300<<c)+0x736)*sizeof(uint16_t);

  if(cli_checklimits("nspack", ctx, tablesz, 0, 0)!=CL_CLEAN)
    return 1; /* Should be ~15KB, if it's so big it's prolly just not nspacked */
    
  cli_dbgmsg("unsp: table size = %d\n", tablesz);
  if (!(table = cli_malloc(tablesz))) {
      cli_dbgmsg("unspack: Unable to allocate memory for table\n");
      return 1;
  }
  
  dsize = cli_readint32(start_of_stuff+9);
  ssize = cli_readint32(start_of_stuff+5);
  if (ssize <= 13) {
  	free(table);
  	return 1;
  }

  tre = very_real_unpack(table,tablesz,tre,allocsz,firstbyte,src,ssize,dst,dsize);
  free(table);
  if (tre) return 1;

  section.raw=0;
  section.rsz = dsize;
  section.vsz = dsize;
  section.rva = rva;
  return !cli_rebuildpe(dest, &section, 1, base, ep, 0, 0, file);
}


uint32_t very_real_unpack(uint16_t *table, uint32_t tablesz, uint32_t tre, uint32_t allocsz, uint32_t firstbyte, const char *src, uint32_t ssize, char *dst, uint32_t dsize) {
  struct UNSP read_struct;
  uint32_t i = (0x300<<((allocsz+tre)&0xff)) + 0x736;

  uint32_t previous_bit = 0;
  uint32_t unpacked_so_far = 0;
  uint32_t backbytes = 1;
  uint32_t oldbackbytes = 1;
  uint32_t old_oldbackbytes = 1;
  uint32_t old_old_oldbackbytes = 1;

  uint32_t damian = 0;
  uint32_t put = (1<<(allocsz&0xff))-1;

  uint32_t bielle = 0;

  firstbyte = (1<<(firstbyte&0xff))-1;

  if (tablesz < i*sizeof(uint16_t)) return 2;

  /* init table */
  while (i) table[--i]=0x400;

  /* table noinit */

  /* get_five - inlined */
  read_struct.error = 0;
  read_struct.oldval = 0;
  read_struct.src_curr = src;
  read_struct.bitmap = 0xffffffff;
  read_struct.src_end = src + ssize - 13;
  read_struct.table = (char *)table;
  read_struct.tablesz = tablesz;

  for ( i = 0; i<5 ; i++) read_struct.oldval = (read_struct.oldval<<8) | get_byte(&read_struct);
  if (read_struct.error) return 1;
  /* if (!dsize) return 0; - checked in pe.c */


  /* very_unpacking_loop */

  while (1) {
    uint32_t backsize = firstbyte&unpacked_so_far;
    uint32_t tpos;
    uint32_t temp = damian;

    if (read_struct.error) return 1; /* checked once per mainloop, keeps the code readable and it's still safe */
    
    if (!getbit_from_table(&table[(damian<<4) + backsize], &read_struct)) { /* no_mainbit */

      uint32_t shft = 8 - (tre&0xff);
      shft &= 0xff;
      tpos = (bielle>>shft) + ((put&unpacked_so_far)<<(tre&0xff));
      tpos *=3;
      tpos<<=8;

      if ((int32_t)damian>=4) { /* signed */
	if ((int32_t)damian>=0xa) { /* signed */
	  damian -= 6;
	} else {
	  damian -= 3;
	}
      } else {
	damian=0;
      }

      /* 44847E */
      if (previous_bit) {
	if (!CLI_ISCONTAINED(dst, dsize, &dst[unpacked_so_far - backbytes], 1)) return 1;
	ssize = (ssize&0xffffff00) | (uint8_t)dst[unpacked_so_far - backbytes]; /* FIXME! ssize is not static */
	bielle = get_100_bits_from_tablesize(&table[tpos+0x736], &read_struct, ssize);
	previous_bit=0;
      } else {
	bielle = get_100_bits_from_table(&table[tpos+0x736], &read_struct);
      }

      /* unpack_one_byte - duplicated */
      if (!CLI_ISCONTAINED(dst, dsize, &dst[unpacked_so_far], 1)) return 1;
      dst[unpacked_so_far] = bielle;
      unpacked_so_far++;
      if (unpacked_so_far>=dsize) return 0;
      continue;

    } else { /* got_mainbit */

      bielle = previous_bit = 1;

      if (getbit_from_table(&table[damian+0xc0], &read_struct)) {
	if (!getbit_from_table(&table[damian+0xcc], &read_struct)) {
	  tpos = damian+0xf;
	  tpos <<=4;
	  tpos += backsize;
	  if (!getbit_from_table(&table[tpos], &read_struct)) {
	    if (!unpacked_so_far) return bielle; /* FIXME: WTF?! */
	    
	    damian = 2*((int32_t)damian>=7)+9; /* signed */
	    if (!CLI_ISCONTAINED(dst, dsize, &dst[unpacked_so_far - backbytes], 1)) return 1;
	    bielle = (uint8_t)dst[unpacked_so_far - backbytes];
	    /* unpack_one_byte - real */
	    dst[unpacked_so_far] = bielle;
	    unpacked_so_far++;
	    if (unpacked_so_far>=dsize) return 0;
	    continue;
	    
	  } else { /* gotbit_tre */
	    backsize = get_n_bits_from_tablesize(&table[0x534], &read_struct, backsize);
	    damian = ((int32_t)damian>=7); /* signed */
	    damian = ((damian-1) & 0xfffffffd)+0xb;
	    /* jmp checkloop_and_backcopy (uses edx) */
	  } /* gotbit_uno ends */
	} else { /* gotbit_due */
	  if (!getbit_from_table(&table[damian+0xd8], &read_struct)) {
	    tpos = oldbackbytes;
	  } else {
	    if (!getbit_from_table(&table[damian+0xe4], &read_struct)) {
	      tpos = old_oldbackbytes;
	    } else {
	      /* set_old_old_oldback */
	      tpos = old_old_oldbackbytes;
	      old_old_oldbackbytes = old_oldbackbytes;
	    }
	    /* set_old_oldback */
	    old_oldbackbytes = oldbackbytes;
	  }
	  /* set_oldback */
	  oldbackbytes = backbytes;
	  backbytes = tpos;
	  
	  backsize = get_n_bits_from_tablesize(&table[0x534], &read_struct, backsize);
	  damian = ((int32_t)damian>=7); /* signed */
	  damian = ((damian-1) & 0xfffffffd)+0xb;
	  /* jmp checkloop_and_backcopy (uses edx) */
	} /* gotbit_due ends */
      } else { /* gotbit_uno */
	
	old_old_oldbackbytes = old_oldbackbytes;
	old_oldbackbytes = oldbackbytes;
	oldbackbytes = backbytes;
	
	damian = ((int32_t)damian>=7); /* signed */
	damian = ((damian-1) & 0xfffffffd)+0xa;

	backsize = get_n_bits_from_tablesize(&table[0x332], &read_struct, backsize);

	tpos = ((int32_t)backsize>=4)?3:backsize; /* signed */
	tpos<<=6;
	tpos = get_n_bits_from_table(&table[0x1b0+tpos], 6, &read_struct);

	if (tpos>=4) { /* signed */

	  uint32_t s = tpos;
	  s>>=1;
	  s--;

	  temp = (tpos & bielle) | 2;
	  temp<<=(s&0xff);


	  if ((int32_t)tpos<0xe) {
	    temp += get_bb(&table[(temp-tpos)+0x2af], s, &read_struct);
	  } else {
	    s += 0xfffffffc;
	    tpos = get_bitmap(&read_struct, s);
	    tpos <<=4;
	    temp += tpos;
	    temp += get_bb(&table[0x322], 4, &read_struct);
	  }
	} else {
	  /* gotbit_uno_out1 */
	  backbytes = temp = tpos;
	}
	/* gotbit_uno_out2 */
	backbytes = temp+1;
	/* jmp checkloop_and_backcopy (uses edx) */
      } /* gotbit_uno ends */

      /* checkloop_and_backcopy */
      if (!backbytes) return 0; /* very_real_unpack_end */
      if (backbytes > unpacked_so_far) return bielle; /* FIXME: WTF?! */

      backsize +=2;

      if (!CLI_ISCONTAINED(dst, dsize, &dst[unpacked_so_far], backsize) ||
	  !CLI_ISCONTAINED(dst, dsize, &dst[unpacked_so_far - backbytes], backsize)
	  ) {
	cli_dbgmsg("%p %x %p %x\n", dst, dsize, &dst[unpacked_so_far], backsize);
	return 1;
      }
      
      do {
	dst[unpacked_so_far] = dst[unpacked_so_far - backbytes];
	unpacked_so_far++;
      } while (--backsize && unpacked_so_far<dsize);
      bielle = (uint8_t)dst[unpacked_so_far - 1];

      if (unpacked_so_far>=dsize) return 0;

    } /* got_mainbit ends */

  } /* while true ends */
}



uint32_t get_byte(struct UNSP *read_struct) {

  uint32_t ret;

  if (read_struct->src_curr >= read_struct->src_end) {
    read_struct->error = 1;
    return 0xff;
  }
  ret = *(read_struct->src_curr);
  read_struct->src_curr++;
  return ret&0xff;
}


int getbit_from_table(uint16_t *intable, struct UNSP *read_struct) {
  
  uint32_t nval;
  if (!CLI_ISCONTAINED((char *)read_struct->table, read_struct->tablesz, (char *)intable, sizeof(uint16_t))) {
    read_struct->error = 1;
    return 0xff;
  }
  nval = *intable * (read_struct->bitmap>>0xb);

  if (read_struct->oldval<nval) { /* unsigned */
    uint32_t sval;
    read_struct->bitmap = nval;
    nval = *intable;
    sval = 0x800 - nval;
    sval = CLI_SRS((int32_t)sval,5); /* signed */
    sval += nval;
    *intable=sval;
    if (read_struct->bitmap<0x1000000) { /* unsigned */
      read_struct->oldval = (read_struct->oldval<<8) | get_byte(read_struct);
      read_struct->bitmap<<=8;
    }
    return 0;
  }

  read_struct->bitmap -= nval;
  read_struct->oldval -= nval;

  nval = *intable;
  nval -= (nval>>5); /* word, unsigned */
  *intable=nval;

  if (read_struct->bitmap<0x1000000) { /* unsigned */
    read_struct->oldval = (read_struct->oldval<<8) | get_byte(read_struct);
    read_struct->bitmap<<=8;
  }

  return 1;
}


uint32_t get_100_bits_from_tablesize(uint16_t *intable, struct UNSP *read_struct, uint32_t ssize) {
  
  uint32_t count = 1;
  
  while (count<0x100) {
    uint32_t lpos, tpos;
    lpos = ssize&0xff;
    ssize=(ssize&0xffffff00)|((lpos<<1)&0xff);
    lpos>>=7;
    tpos = lpos+1;
    tpos<<=8;
    tpos+=count;
    tpos = getbit_from_table(&intable[tpos], read_struct);
    count=(count*2)|tpos;
    if (lpos!=tpos) {
      /* second loop */
      while (count<0x100)
	count = (count*2)|getbit_from_table(&intable[count], read_struct);
    }
  } 
  return count&0xff;
}


uint32_t get_100_bits_from_table(uint16_t *intable, struct UNSP *read_struct) {
  uint32_t count = 1;
  
  while (count<0x100)
    count = (count*2)|getbit_from_table(&intable[count], read_struct);
  return count&0xff;
}


uint32_t get_n_bits_from_table(uint16_t *intable, uint32_t bits, struct UNSP *read_struct) {
  uint32_t count = 1;
  uint32_t bitcounter;

  /*  if (bits) { always set! */
  bitcounter = bits;
  while (bitcounter--)
    count = count*2 + getbit_from_table(&intable[count], read_struct);
  /*  } */
  
  return count-(1<<(bits&0xff));
}


uint32_t get_n_bits_from_tablesize(uint16_t *intable, struct UNSP *read_struct, uint32_t backsize) {
  
  if (!getbit_from_table(intable, read_struct))
    return get_n_bits_from_table(&intable[(backsize<<3)+2], 3, read_struct);
  
  if (!getbit_from_table(&intable[1], read_struct))
    return 8+get_n_bits_from_table(&intable[(backsize<<3)+0x82], 3, read_struct);

  return 0x10+get_n_bits_from_table(&intable[0x102], 8, read_struct);
}


uint32_t get_bb(uint16_t *intable, uint32_t back, struct UNSP *read_struct) {
  uint32_t pos = 1;
  uint32_t bb = 0;
  uint32_t i;

  if ((int32_t)back<=0) /* signed */
    return 0;
  
  for (i=0;i<back;i++) {
    uint32_t bit = getbit_from_table(&intable[pos], read_struct);
    pos=(pos*2) + bit;
    bb|=(bit<<i);
  }
  return bb;
}


uint32_t get_bitmap(struct UNSP *read_struct, uint32_t bits) {
  uint32_t retv = 0;

  if ((int32_t)bits<=0) return 0; /* signed */

  while (bits--) {
    read_struct->bitmap>>=1; /* unsigned */
    retv<<=1;
    if (read_struct->oldval>=read_struct->bitmap) { /* unsigned */
      read_struct->oldval-=read_struct->bitmap;
      retv|=1;
    }
    if (read_struct->bitmap<0x1000000) {
      read_struct->bitmap<<=8;
      read_struct->oldval = (read_struct->oldval<<8) | get_byte(read_struct);
    }
  }
  return retv;
}
