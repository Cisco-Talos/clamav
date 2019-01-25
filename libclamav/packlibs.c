/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Alberto Wu, Michal 'GiM' Spadlinski
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clamav.h"
#include "others.h"
#include "execs.h"
#include "pe.h"
#include "packlibs.h"

static int doubledl(const char **scur, uint8_t *mydlptr, const char *buffer, uint32_t buffersize)
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


int cli_unfsg(const char *source, char *dest, int ssize, int dsize, const char **endsrc, char **enddst) {
  uint8_t mydl=0x80;
  uint32_t backbytes, backsize, oldback = 0;
  const char *csrc = source;
  char *cdst = dest;
  int oob, lostbit = 1;

  if (ssize<=0 || dsize<=0) return -1;
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

int unmew(const char *source, char *dest, int ssize, int dsize, const char **endsrc, char **enddst) {
  uint8_t mydl=0x80;
  uint32_t myeax_backbytes, myecx_backsize, oldback = 0;
  const char *csrc = source;
  char *cdst = dest;
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
	cli_dbgmsg("MEW: rete: %p %d %p %d %d || %p %d %p %d %d\n", dest, dsize, cdst, myecx_backsize,
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
	cli_dbgmsg("MEW: retf %p %p+%08x=%p, %p %p+%08x=%p\n",
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
