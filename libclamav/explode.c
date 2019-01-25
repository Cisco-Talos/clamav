/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
 *
 *  Authors: Alberto Wu
 * 
 *  Acknowledgements: Written from scratch based on specs from PKWARE:
 *                    http://www.pkware.com/documents/casestudies/APPNOTE.TXT
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
 * Written from scratch based on specs from PKWARE:
 * see www.pkware.com/documents/casestudies/APPNOTE.TXT
 *
 * To the best of my knowledge, it's patent free:
 * http://www.unisys.com/about__unisys/lzw
*/


/* To Cami and Dario, the only lawyers I can stand */


#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#if HAVE_STRING_H
#include <string.h>
#endif

#include "clamav.h"
#include "explode.h"
#include "others.h"

/* NOTE: sorting algo must be stable! */
static void bs(uint8_t *k, uint8_t *v, unsigned int elements) {
  uint8_t tmp;
  unsigned int i=0, l=0, stop=0, r=elements;
  
  while(!stop) {
    stop=1;
    for(; i<r; i++) {
      if(v[k[i]]>v[k[i+1]]) {
	tmp=k[i];
	k[i]=k[i+1];
	k[i+1]=tmp;
	stop=0;
      }
    }
    if(stop) break;
    r--;
    i--;
    for(; i>l; i--) {
      if(v[k[i]]<v[k[i-1]]) {
	tmp=k[i];
	k[i]=k[i-1];
	k[i-1]=tmp;
	stop=0;
      }
    }
    l++;
    i++;
  }
}


static int unpack_tree(struct xplstate *X, uint32_t *tree, unsigned int expected) {
  uint8_t temptree[256], order[256], *ttree=temptree;
  uint8_t *cur=X->window;
  uint8_t packsz;
  unsigned int i;
  uint16_t code=0, codeinc=0, lastlen=0;

  packsz=*cur++;

  for(i=0; i<expected; i++) order[i]=i;

  i=expected;

  do {
    uint8_t values, len;
    values = *cur++;
    len = (values&15) + 1;
    values = (values>>4) + 1;
    if(values>i) return 1;
    i-=values;
    while(values--)
      *ttree++ = len;
  } while(packsz--);

  if(i) return 1;

  bs(order, temptree, expected-1);

  i=expected-1;
  do {
    code=code+codeinc;
    if(temptree[order[i]]!=lastlen) {
      lastlen=temptree[order[i]];
      codeinc=1<<(16-lastlen);
    }
    tree[order[i]]=code | ((uint32_t)lastlen<<16);
  } while(i--);

  return 0;
}

/* bit lame of a lookup, but prolly not worth optimizing */
static int lookup_tree(uint32_t *tree, unsigned int size, uint16_t code, uint8_t len) {
  uint32_t lookup=((uint32_t)(len+1))<<16 | code;
  unsigned int i;
  for(i=0; i<size; i++)
    if(tree[i]==lookup) return i;
  return -1;
}

int explode_init(struct xplstate *X, uint16_t flags) {
  X->bits = X->cur = 0;
  if(flags&2) {
    X->largewin = 1;
    X->mask = 0x1fff;
  } else {
    X->largewin = 0;
    X->mask = 0xfff;
  }
  if(flags&4) {
    X->state = GRABLITS;
    X->litcodes = 1;
    X->minlen=3;
  } else {
    X->state = GRABLENS;
    X->litcodes = 0;
    X->minlen=2;
  }
  X->got=0;
  return EXPLODE_OK;
}

#define GETBIT					\
  if(X->bits) {					\
    X->bits--;					\
    val=X->bitmap&1;				\
    X->bitmap>>=1;				\
  } else {					\
    if(!X->avail_in) return EXPLODE_EBUFF;	\
    if(X->avail_in>=4) {			\
      X->bitmap=cli_readint32(X->next_in);	\
      X->bits=31;				\
      X->next_in+=4;				\
      X->avail_in-=4;				\
    } else {					\
      X->bitmap=*X->next_in;			\
      X->bits=7;				\
      X->next_in++;				\
      X->avail_in--;				\
    }						\
    val=X->bitmap&1;				\
    X->bitmap>>=1;				\
  }


#define GETBITS(NUM)						\
  if(X->bits>=(NUM)) {						\
    val=X->bitmap&((1<<(NUM))-1);				\
    X->bitmap>>=(NUM);						\
    X->bits-=(NUM);						\
  } else {							\
    if(X->avail_in*8+X->bits<(NUM)) return EXPLODE_EBUFF;	\
    val=X->bitmap;						\
    if(X->avail_in>=4) {					\
      X->bitmap=cli_readint32(X->next_in);			\
      X->next_in+=4;						\
      X->avail_in-=4;						\
      val|=(X->bitmap&((1<<((NUM)-X->bits))-1))<<X->bits;	\
      X->bitmap>>=(NUM)-X->bits;				\
      X->bits=32-((NUM)-X->bits);				\
    } else {							\
      X->bitmap=*X->next_in;					\
      X->next_in++;						\
      X->avail_in--;						\
      val|=(X->bitmap&((1<<((NUM)-X->bits))-1))<<X->bits;	\
      X->bitmap>>=(NUM)-X->bits;				\
      X->bits=8-((NUM)-X->bits);				\
    }								\
  }


#define GETCODES(CASE, WHICH, HOWMANY)					\
  case CASE: {								\
    if(!X->avail_in) return EXPLODE_EBUFF;				\
    if(!X->got) need = *X->next_in;					\
    else need = X->window[0];						\
    if(need > HOWMANY - 1) return EXPLODE_ESTREAM; /* too many codes */ \
    need = need + 2 - X->got; /* bytes remaining */			\
    if(need>X->avail_in) { /* if not enuff */				\
      /* just copy what's avail... */					\
      memcpy(&X->window[X->got], X->next_in, X->avail_in);		\
      X->got += X->avail_in;						\
      X->next_in += X->avail_in;					\
      X->avail_in = 0;							\
      return EXPLODE_EBUFF; /* ...and beg for more */			\
    }									\
    /* else fetch what's needed */					\
    memcpy(&X->window[X->got], X->next_in, need);			\
    X->avail_in -= need;						\
    X->next_in += need;							\
    if(unpack_tree(X, X->WHICH, HOWMANY )) return EXPLODE_ESTREAM;	\
    /* and move on */							\
    X->got=0;								\
    X->state++;								\
  }

#define SETCASE(CASE) \
  X->state = (CASE);  \
 case(CASE): \
 {/* FAKE */}

int explode(struct xplstate *X) {
  unsigned int val, need;
  int temp=-1;
  
  switch(X->state) {
    /* grab compressed coded literals, if present */
    GETCODES(GRABLITS, lit_tree, 256);
    /* grab compressed coded lens */
    GETCODES(GRABLENS, len_tree, 64);
    /* grab compressed coded dists */
    GETCODES(GRABDISTS, dist_tree, 64);
    
  case EXPLODE:
    while(X->avail_in || X->bits) {
      GETBIT; /* can't fail */
      if(val) {
	if(X->litcodes) {
	  X->backsize=0;
	  X->state=EXPLODE_LITCODES;
	  for(X->got=0; X->got<=15; X->got++) {
	  case EXPLODE_LITCODES:
	    GETBIT;
	    X->backsize|=val<<(15-X->got);
	    if((temp=lookup_tree(X->lit_tree, 256, X->backsize, X->got))!=-1) break;
	  }
	  if(temp==-1) return EXPLODE_ESTREAM;
	  X->got=temp;
	} else {
	  SETCASE(EXPLODE_LITS);
	  GETBITS(8);
	  X->got=val;
	}
	SETCASE(EXPLODE_WBYTE);
	if(!X->avail_out) return EXPLODE_EBUFF;
	X->avail_out--;
	*X->next_out = X->window[X->cur & X->mask] = X->got;
	X->cur++;
	X->next_out++;
      } else {
	SETCASE(EXPLODE_BASEDIST);
	GETBITS(6u+X->largewin);
	X->backbytes=val;
	X->backsize=0;
	X->state=EXPLODE_DECODEDISTS;
	for(X->got=0; X->got<=15; X->got++) {
	case EXPLODE_DECODEDISTS:
	  GETBIT;
	  X->backsize|=val<<(15-X->got);
	  if((temp=lookup_tree(X->dist_tree, 64, X->backsize, X->got))!=-1) break;
	}
	if(temp==-1) return EXPLODE_ESTREAM;
	X->backbytes|=temp<<(6+X->largewin);
	X->backbytes++;
	X->backsize=0;
	X->state=EXPLODE_DECODELENS;
	for(X->got=0; X->got<=15; X->got++) {
	case EXPLODE_DECODELENS:
	  GETBIT;
	  X->backsize|=val<<(15-X->got);
	  if((temp=lookup_tree(X->len_tree, 64, X->backsize, X->got))!=-1) break;
	}
	if(temp==-1) return EXPLODE_ESTREAM;

	if(temp==63) {
	  SETCASE(EXPLODE_DECODEEXTRA);
	  GETBITS(8);
	  temp=63+val;
	}
	X->backsize=temp+X->minlen;
	X->state=EXPLODE_BACKCOPY;
	while(X->backsize--) {
	case EXPLODE_BACKCOPY:
	  if(!X->avail_out) return EXPLODE_EBUFF;
	  X->avail_out--;
	  if (X->cur>=X->backbytes)
	    *X->next_out = X->window[X->cur & X->mask] = X->window[(X->cur-X->backbytes) & X->mask];
	  else
	    *X->next_out = X->window[X->cur & X->mask] = 0;
	  X->cur++;
	  X->next_out++;
	}
      }
      X->state=EXPLODE;
    }
  }
  return EXPLODE_EBUFF;
}

void explode_shutdown(void) {}
