/*
 *  Copyright (C) 2006 aCaB <acab@clamav.net>
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


#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "others.h"
#include "execs.h"
#include "pe.h"
#include "rebuildpe.h"

static int doubledl(char **scur, uint8_t *mydlptr, char *buffer, uint32_t buffersize)
{
  unsigned char mydl = *mydlptr;
  unsigned char olddl = mydl;

  mydl*=2;
  if ( !(olddl & 0x7f)) {
    if ( *scur < buffer || *scur >= buffer+buffersize-1 )
      return -1;
    olddl = **scur;
    mydl = olddl*2+1;
    *scur=*scur + 1;
  }
  *mydlptr = mydl;
  return (olddl>>7)&1;
}


int cli_unfsg(char *source, char *dest, int ssize, int dsize, char **endsrc, char **enddst) {
  uint8_t mydl=0x80;
  uint32_t backbytes, backsize, oldback = 0;
  char *csrc = source, *cdst = dest;
  int oob, lostbit = 1;

  /* I assume buffers size is >0 - No checking! */
  *cdst++=*csrc++;

  while ( 1 ) {
    if ((oob=doubledl(&csrc, &mydl, source, ssize))) {
      if (oob == -1)
	return -1;
      /* 164 */
      backsize = 0;
      if ((oob=doubledl(&csrc, &mydl, source, ssize))) {
	if (oob == -1)
	  return -1;
	/* 16a */
	backbytes = 0;
	if ((oob=doubledl(&csrc, &mydl, source, ssize))) {
	  if (oob == -1)
	    return -1;
	  /* 170 */
	  lostbit = 1;
	  backsize++;
	  backbytes = 0x10;
	  while ( backbytes < 0x100 ) {
	    if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	      return -1;
	    backbytes = backbytes*2+oob;
	  }
	  backbytes &= 0xff;
	  if ( ! backbytes ) {
	    if (cdst >= dest+dsize)
	      return -1;
	    *cdst++=0x00;
	    continue;
	  }
	} else {
	  /* 18f */
	  if (csrc >= source+ssize)
	    return -1;
	  backbytes = *(unsigned char*)csrc;
	  backsize = backsize * 2 + (backbytes & 1);
	  backbytes = (backbytes & 0xff)>>1;
	  csrc++;
	  if (! backbytes)
	    break;
	  backsize+=2;
	  oldback = backbytes;
	  lostbit = 0;
	}
      } else {
	/* 180 */
	backsize = 1;
	do {
	  if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	    return -1;
	  backsize = backsize*2+oob;
	  if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	    return -1;
	} while (oob);

	backsize = backsize - 1 - lostbit;
	if (! backsize) {
	  /* 18a */
	  backsize = 1;
	  do {
	    if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	      return -1;
	    backsize = backsize*2+oob;
	    if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	      return -1;
	  } while (oob);

	  backbytes = oldback;
	} else {
	  /* 198 */
	  if (csrc >= source+ssize)
	    return -1;
	  backbytes = *(unsigned char*)csrc;
	  backbytes += (backsize-1)<<8;
	  backsize = 1;
	  csrc++;
	  do {
	    if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	      return -1;
	    backsize = backsize*2+oob;
	    if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	      return -1;
	  } while (oob);

          if (backbytes >= 0x7d00)
            backsize++;
          if (backbytes >= 0x500)
            backsize++;
          if (backbytes <= 0x7f)
            backsize += 2;

	  oldback = backbytes;
	}
	lostbit = 0;
      }
      if (!CLI_ISCONTAINED(dest, dsize, cdst, backsize) || !CLI_ISCONTAINED(dest, dsize, cdst-backbytes, backsize))
	return -1;
      while(backsize--) {
	*cdst=*(cdst-backbytes);
	cdst++;
      }

    } else {
      /* 15d */
      if (cdst < dest || cdst >= dest+dsize || csrc < source || csrc >= source+ssize)
	return -1;
      *cdst++=*csrc++;
      lostbit=1;
    }
  }

  if (endsrc) *endsrc = csrc;
  if (enddst) *enddst = cdst;
  return 0;
}

#ifdef CL_EXPERIMENTAL
static int unmew(char *source, char *dest, int ssize, int dsize, char **endsrc, char **enddst) {
  uint8_t mydl=0x80;
  uint32_t myeax_backbytes, myecx_backsize, oldback = 0;
  char *csrc = source, *cdst = dest;
  int oob, lostbit = 1;

  *cdst++=*csrc++;

  while ( 1 ) {
    if ((oob=doubledl(&csrc, &mydl, source, ssize))) {
      if (oob == -1)
	return -1;
      /* 164 */
      myecx_backsize = 0;
      if ((oob=doubledl(&csrc, &mydl, source, ssize))) {
	if (oob == -1)
	  return -1;
	/* 16a */
	myeax_backbytes = 0;
	if ((oob=doubledl(&csrc, &mydl, source, ssize))) {
	  if (oob == -1)
	    return -1;
	  /* 170 */
	  lostbit = 1;
	  myecx_backsize++;
	  myeax_backbytes = 0x10;
	  while ( myeax_backbytes < 0x100 ) {
	    if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	      return -1;
	    myeax_backbytes = myeax_backbytes*2+oob;
	  }
	  myeax_backbytes &= 0xff;
	  if ( ! myeax_backbytes ) {
	    if (cdst >= dest+dsize)
	      return -1;
	    *cdst++=0x00;
	    /*cli_dbgmsg("X%02x  ", *(cdst-1)&0xff);*/
	    continue;
	  }
	} else {
	  /* 18f */
	  if (csrc >= source+ssize)
	    return -1;
	  myeax_backbytes = *(unsigned char*)csrc;
	  myecx_backsize = myecx_backsize * 2 + (myeax_backbytes & 1);
	  myeax_backbytes = (myeax_backbytes & 0xff)>>1;
	  csrc++;
	  if (! myeax_backbytes)
	  {
	    /* cli_dbgmsg("\nBREAK \n"); */
	    break;
	  }
	  myecx_backsize+=2;
	  oldback = myeax_backbytes;
	  lostbit = 0;
	}
      } else {
	/* 180 */
	myecx_backsize = 1;
	do {
	  if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	    return -1;
	  myecx_backsize = myecx_backsize*2+oob;
	  if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	    return -1;
	} while (oob);

	myecx_backsize = myecx_backsize - 1 - lostbit;
	if (! myecx_backsize) {
	  /* 18a */
	  myecx_backsize = 1;
	  do {
	    if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	      return -1;
	    myecx_backsize = myecx_backsize*2+oob;
	    if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	      return -1;
	  } while (oob);

	  myeax_backbytes = oldback;
	} else {
	  /* 198 */
	  if (csrc >= source+ssize)
	    return -1;
	  myeax_backbytes = *(unsigned char*)csrc;
	  myeax_backbytes += (myecx_backsize-1)<<8;
	  myecx_backsize = 1;
	  csrc++;
	  do {
	    if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	      return -1;
	    myecx_backsize = myecx_backsize*2+oob;
	    if ((oob=doubledl(&csrc, &mydl, source, ssize)) == -1)
	      return -1;
	  } while (oob);

          if (myeax_backbytes >= 0x7d00)
            myecx_backsize++;
          if (myeax_backbytes >= 0x500)
            myecx_backsize++;
          if (myeax_backbytes <= 0x7f)
            myecx_backsize += 2;

	  oldback = myeax_backbytes;
	}
	lostbit = 0;
      }
      if (!CLI_ISCONTAINED(dest, dsize, cdst, myecx_backsize) || !CLI_ISCONTAINED(dest, dsize, cdst-myeax_backbytes, myecx_backsize))
      {
	cli_dbgmsg("MEW: rete: %d %d %d %d %d || %d %d %d %d %d\n", dest, dsize, cdst, myecx_backsize,
			CLI_ISCONTAINED(dest, dsize, cdst, myecx_backsize),
			dest, dsize, cdst-myeax_backbytes, myecx_backsize,
      			CLI_ISCONTAINED(dest, dsize, cdst-myeax_backbytes, myecx_backsize) );
	return -1;
      }
      while(myecx_backsize--) {
	*cdst=*(cdst-myeax_backbytes);
	cdst++;
      }

    } else {
      /* 15d */
      if (cdst < dest || cdst >= dest+dsize || csrc < source || csrc >= source+ssize)
      {
	cli_dbgmsg("MEW: retf %08x %08x+%08x=%08x, %08x %08x+%08x=%08x\n",
			cdst, dest, dsize, dest+dsize, csrc, source, ssize, source+ssize);
	return -1;
      }
      *cdst++=*csrc++;
      /* cli_dbgmsg("Z%02x  ", *(cdst-1)&0xff); */
      lostbit=1;
    }
  }

  *endsrc = csrc;
  *enddst = cdst;
  return 0;
}


int unmew11(struct pe_image_section_hdr *section_hdr, int sectnum, char *src, int off, int ssize, int dsize, uint32_t base, uint32_t vadd, int uselzma, char **endsrc, char **enddst, int filedesc)
{
	uint32_t entry_point, newedi, loc_ds=dsize, loc_ss=ssize;
	char *source = src + dsize + off; /*EC32(section_hdr[sectnum].VirtualSize) + off;*/
	char *lesi = source + 12, *ledi;
	char *f1, *f2;
	int i;
	struct cli_exe_section *section = NULL;
	uint32_t vma = base + vadd, size_sum = ssize + dsize;

	entry_point  = cli_readint32(source + 4); /* 2vGiM: ate these safe enough?
						   * yup, if (EC32(section_hdr[i + 1].SizeOfRawData) < ...
						   * ~line #879 in pe.c
						   */
	newedi = cli_readint32(source + 8);
	ledi = src + (newedi - vma);

	i = 0;
	ssize -= 12;
	while (1)
	{
  		cli_dbgmsg("MEW unpacking section %d (%08x->%08x)\n", i, lesi, ledi);
		if (!CLI_ISCONTAINED(src, size_sum, lesi, 4) || !CLI_ISCONTAINED(src, size_sum, ledi, 4))
		{
			cli_dbgmsg("Possibly programmer error or hand-crafted PE file, report to clamav team\n");
			return -1;
		}
		if (unmew(lesi, ledi, loc_ss, loc_ds, &f1, &f2))
		{
			free(section);
			return -1;
		}

		/* we don't need last section in sections since this is information for fixing imptbl */
		if (!CLI_ISCONTAINED(src, size_sum, f1, 4))
		{
			free(section);
			return -1;
		}

		/* XXX */
		loc_ss -= (f1+4-lesi);
		loc_ds -= (f2-ledi);
		ledi = src + (cli_readint32(f1) - vma);
		lesi = f1+4;

		if (!uselzma)
		{
			uint32_t val = f2 - src;
			/* round-up to 4k boundary, I'm not sure of this XXX */
			val >>= 12;
			val <<= 12;
			val += 0x1000;

			/* eeevil XXX */
			section = cli_realloc(section, (i+2)*sizeof(struct cli_exe_section));
			section[0].raw = 0; section[0].rva = vadd;
			section[i+1].raw = val;
			section[i+1].rva = val + vadd;
			section[i].rsz = section[i].vsz = i?val - section[i].raw:val;
		}
		i++;

		if (!cli_readint32(f1))
			break;
	}

	/* LZMA stuff */
	if (uselzma) {
		/* put everything in one section */
		i = 1;
		if (!CLI_ISCONTAINED(src, size_sum, src+uselzma+8, 1))
		{
			cli_dbgmsg("MEW: couldn't access lzma 'special' tag\n");
			free(section);
			return -1;
		}
		/* 0x50 -> push eax */
		cli_dbgmsg("MEW: lzma %swas used, unpacking\n", (*(src + uselzma+8) == '\x50')?"special ":"");
		if (!CLI_ISCONTAINED(src, size_sum, f1+4, 20 + 4 + 5))
		{
			cli_dbgmsg("MEW: lzma initialization data not available!\n");
			free(section);
			return -1;
		}
		if(mew_lzma(&(section_hdr[sectnum]), src, f1+4, size_sum, vma, *(src + uselzma+8) == '\x50'))
		{
			free(section);
			return -1;
		}
		loc_ds >>= 12; loc_ds <<= 12; loc_ds += 0x1000;
		/* I have EP but no section's information, so I weren't sure what to do with that */ /* 2vGiM: sounds fair */
		section = cli_calloc(1, sizeof(struct cli_exe_section));
		section[0].raw = 0; section[0].rva = vadd;
		section[0].rsz = section[0].vsz = dsize;
	}
	if ((f1 = cli_rebuildpe(src, section, i, base, entry_point - base, 0, 0, filedesc)))
	{
		if (cli_writen(filedesc, f1, 0x148+0x80+0x28*i+dsize) == -1) {
			free(f1);
			return -1;
		}
	} else {
		cli_dbgmsg("MEW: Rebuilding failed\n");
		return -1;
	}

	return 1;
}
#endif

