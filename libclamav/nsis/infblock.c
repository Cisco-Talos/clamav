/*
 * This file is a part of the zlib compression module for NSIS.
 * 
 * Copyright and license information can be found below.
 * Modifications Copyright (C) 1999-2007 Nullsoft and Contributors
 * 
 * The original zlib source code is available at
 * http://www.zlib.net/
 * 
 * This software is provided 'as-is', without any express or implied
 * warranty.
 */

/*
 * Copyright (C) 1995-1998 Jean-loup Gailly.
 * For conditions of distribution and use, see copyright notice in COPYING.nsis
 */

#include "nsis_zutil.h"
#include <string.h>

#ifndef min
#  define min(x,y) ((x<y)?x:y)
#endif

/* defines for inflate input/output */
/*   update pointers and return */
#define UPDBITS {s->bitb=b;s->bitk=k;}
#define UPDIN {z->avail_in=n;z->next_in=p;}
#define UPDOUT {s->write=q;}
#define UPDATE {UPDBITS UPDIN UPDOUT}
#define LEAVE(r) {UPDATE inflate_flush(z); return r;}

/*   get bytes and bits */
#define LOADIN {p=z->next_in;n=z->avail_in;b=s->bitb;k=s->bitk;}


#define NEEDBYTE {if(!n)LEAVE(Z_OK)}
#define NEXTBYTE (n--,*p++)
#define NEEDBITS(j) {while(k<(j)){NEEDBYTE;b|=((uLong)NEXTBYTE)<<k;k+=8;}}

#define DUMPBITS(j) {b>>=(j);k-=(j);}
/*   output bytes */
#define WAVAIL (uInt)(q<s->read?s->read-q-1:s->end-q)
#define LOADOUT {q=s->write;m=(uInt)WAVAIL;}
#define WRAP {if(q==s->end&&s->read!=s->window){q=s->window;m=(uInt)WAVAIL;}}
#define FLUSH {UPDOUT inflate_flush(z); LOADOUT}
#define NEEDOUT {if(m==0){WRAP if(m==0){FLUSH WRAP if(m==0) LEAVE(Z_OK)}}}
#define OUTBYTE(a) {*q++=(Byte)(a);m--;}
/*   load local pointers */
#define LOAD {LOADIN LOADOUT}

#define LAST (s->last == DRY)


typedef struct inflate_blocks_state FAR inflate_blocks_statef;
#define exop word.what.Exop
#define bits word.what.Bits

/* And'ing with mask[n] masks the lower n bits */
local const unsigned short inflate_mask[17] = {
    0x0000,
    0x0001, 0x0003, 0x0007, 0x000f, 0x001f, 0x003f, 0x007f, 0x00ff,
    0x01ff, 0x03ff, 0x07ff, 0x0fff, 0x1fff, 0x3fff, 0x7fff, 0xffff
}; /* use to reduce .data #define INFLATE_MASK(x, n) (x & (~((unsigned short) 0xFFFF << n))) */
local const char border[] = { /* Order of the bit length code lengths */
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

/* Tables for deflate from PKZIP's appnote.txt. */
local const unsigned short  cplens[31] = { /* Copy lengths for literal codes 257..285 */
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
        35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258, 0, 0};
        /* see note #13 above about 258 */
local const unsigned short  cplext[31] = { /* Extra bits for literal codes 257..285 */
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
        3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0, 112, 112}; /* 112==invalid */
local const unsigned short  cpdist[30] = { /* Copy offsets for distance codes 0..29 */
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
        257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
        8193, 12289, 16385, 24577};
local const unsigned short  cpdext[30] = { /* Extra bits for distance codes */
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
        7, 7, 8, 8, 9, 9, 10, 10, 11, 11,
        12, 12, 13, 13};

/* build fixed tables only once--keep them here */
/* local char fixed_built = 0; */
/* local inflate_huft fixed_mem[FIXEDH]; */
/* local uInt fixed_bl=9; */
/* local uInt fixed_bd=5; */
/* local inflate_huft *fixed_tl; */
/* local inflate_huft *fixed_td; */


/* copy as much as possible from the sliding window to the output area */
local void ZEXPORT inflate_flush(nsis_z_streamp z)
{
  inflate_blocks_statef *s = &z->blocks;
  uInt n;
  Bytef *q;

  /* local copies of source and destination pointers */
  q = s->read;

again:
  /* compute number of bytes to copy as far as end of window */
  n = (uInt)((q <= s->write ? s->write : s->end) - q);
  n = min(n, z->avail_out);

  /* update counters */
  z->avail_out -= n;
  /* z->total_out += n; */

  /* copy as far as end of window */
  zmemcpy(z->next_out, q, n);
  z->next_out += n;
  q += n;

  /* see if more to copy at beginning of window */
  if (q == s->end)
  {
    /* wrap pointers */
    q = s->window;
    if (s->write == s->end)
      s->write = s->window;

    /* do the same for the beginning of the window */
    goto again;
  }

  /* update pointers */
  s->read = q;
}

#define BMAX 15         /* maximum bit length of any code */

local int ZEXPORT huft_build(
uIntf *b,               /* code lengths in bits (all assumed <= BMAX) */
uInt n,                 /* number of codes (assumed <= 288) */
uInt s,                 /* number of simple-valued codes (0..s-1) */
const unsigned short *d,         /* list of base values for non-simple codes */
const unsigned short *e,         /* list of extra bits for non-simple codes */
inflate_huft * FAR *t,  /* result: starting table */
uIntf *m,               /* maximum lookup bits, returns actual */
inflate_huft *hp,       /* space for trees */
uInt *hn,               /* working area: values in order of bit length */
uIntf *v)             /* work area for huft_build */
{
  uInt a;                       /* counter for codes of length k */
  uInt c[BMAX+1];               /* bit length count table */
  uInt f;                       /* i repeats in table every f entries */
  int g;                        /* maximum code length */
  int h;                        /* table level */
  uInt i;              /* counter, current code */
  uInt j;              /* counter */
  int k;               /* number of bits in current code */
  int l;                        /* bits per table (returned in m) */
  uIntf *p;            /* pointer into c[], b[], or v[] */
  inflate_huft *q;              /* points to current table */
  struct inflate_huft_s r;      /* table entry for structure assignment */
  inflate_huft *u[BMAX];        /* table stack */
  int w;               /* bits before this table == (l * h) */
  uInt x[BMAX+1];               /* bit offsets, then code stack */
  uIntf *xp;                    /* pointer into x */
  int y;                        /* number of dummy codes added */
  uInt z;                       /* number of entries in current table */


  /* Generate counts for each bit length */
  p=c;
  y=16; while (y--) *p++ = 0;
  p = b;
  i = n;
  do {
    c[*p++]++;                  /* assume all entries <= BMAX */
  } while (--i);
  if (c[0] == n)                /* null input--all zero length codes */
  {
    *t = (inflate_huft *)Z_NULL;
    *m = 0;
    return Z_OK;
  }


  /* Find minimum and maximum length, bound *m by those */
  l = *m;
  for (j = 1; j <= BMAX; j++)
    if (c[j])
      break;
  k = j;                        /* minimum code length */
  if ((uInt)l < j)
    l = j;
  for (i = BMAX; i; i--)
    if (c[i])
      break;
  g = i;                        /* maximum code length */
  if ((uInt)l > i)
    l = i;
  *m = l;


  /* Adjust last length count to fill out codes, if needed */
  for (y = 1 << j; j < i; j++, y <<= 1)
    if ((y -= c[j]) < 0)
      return Z_DATA_ERROR;
  if ((y -= c[i]) < 0)
    return Z_DATA_ERROR;
  c[i] += y;


  /* Generate starting offsets into the value table for each length */
  x[1] = j = 0;
  p = c + 1;  xp = x + 2;
  while (--i) {                 /* note that i == g from above */
    *xp++ = (j += *p++);
  }


  /* Make a table of values in order of bit lengths */
  p = b;  i = 0;
  do {
    if ((j = *p++) != 0)
      v[x[j]++] = i;
  } while (++i < n);
  n = x[g];                     /* set n to length of v */


  /* Generate the Huffman codes and for each, make the table entries */
  x[0] = i = 0;                 /* first Huffman code is zero */
  p = v;                        /* grab values in bit order */
  h = -1;                       /* no tables yet--level -1 */
  w = -l;                       /* bits decoded == (l * h) */
  u[0] = (inflate_huft *)Z_NULL;        /* just to keep compilers happy */
  q = (inflate_huft *)Z_NULL;   /* ditto */
  z = 0;                        /* ditto */

  r.base = 0;

  /* go through the bit lengths (k already is bits in shortest code) */
  for (; k <= g; k++)
  {
    a = c[k];
    while (a--)
    {
      int nextw=w;
      /* here i is the Huffman code of length k bits for value *p */
      /* make tables up to required level */
      while (k > (nextw=w + l))
      {
        h++;

        /* compute minimum size table less than or equal to l bits */
        z = g - nextw;
        z = z > (uInt)l ? (uInt)l : z;        /* table size upper limit */
        if ((f = 1 << (j = k - nextw)) > a + 1)     /* try a k-w bit table */
        {                       /* too few codes for k-w bit table */
          f -= a + 1;           /* deduct codes from patterns left */
          xp = c + k;
          if (j < z)
            while (++j < z && (f <<= 1) > *++xp)     /* try smaller tables up to z bits */
            {
              f -= *xp;         /* else deduct codes from patterns */
            }
        }
        z = 1 << j;             /* table entries for j-bit table */

        /* allocate new table */
        if (*hn + z > MANY)     /* (note: doesn't matter for fixed) */
          return Z_MEM_ERROR;   /* not enough memory */
        u[h] = q = hp + *hn;
        *hn += z;

        /* connect to last table, if there is one */
        if (h)
        {
          x[h] = i;             /* save pattern for backing up */
          r.bits = (Byte)l;     /* bits to dump before this table */
          r.exop = (Byte)j;     /* bits in this table */
          j = i >> w;
          r.base = (uInt)(q - u[h-1] - j);   /* offset to this table */
          u[h-1][j] = r;        /* connect to last table */
        }
        else
          *t = q;               /* first table is returned result */
        w=nextw;                 /* previous table always l bits */
      }

      /* set up table entry in r */
      r.bits = (Byte)(k - w);
      if (p >= v + n)
        r.exop = 128 + 64;      /* out of values--invalid code */
      else if (*p < s)
      {
        r.exop = (Byte)(*p < 256 ? 0 : 32 + 64);     /* 256 is end-of-block */
        r.base = *p++;          /* simple code is just the value */
      }
      else
      {
        r.exop = (Byte)(e[*p - s] + 16 + 64);/* non-simple--look up in lists */
        r.base = d[*p++ - s];
      }

      /* fill code-like entries with r */
      f = 1 << (k - w);
      for (j = i >> w; j < z; j += f)
        q[j] = r;

      /* backwards increment the k-bit code i */
      for (j = 1 << (k - 1); i & j; j >>= 1)
        i ^= j;
      i ^= j;

      /* backup over finished tables */
      while ((i & ((1 << w) - 1)) != x[h])
      {
        h--;                    /* don't need to update q */
        w -= l;
      }
    }
  }


  /* Return Z_BUF_ERROR if we were given an incomplete table */
  return (y != 0 && g != 1) ? Z_BUF_ERROR : Z_OK;
}

int ZEXPORT nsis_inflate(nsis_z_streamp z)
{
  inflate_blocks_statef *s = &z->blocks;
  inflate_codes_statef *c = &s->sub.decode.t_codes;  /* codes state */

  /* lousy two bytes saved by doing this */
  struct
  {
    uInt t;               /* temporary storage */
    uLong b;              /* bit buffer */
    uInt k;               /* bits in bit buffer */
    Bytef *p;             /* input data pointer */
    uInt n;               /* bytes available there */
    Bytef *q;             /* output window write pointer */
    uInt m;               /* bytes to end of window or read pointer */

    /* CODES variables */

    inflate_huft *j;      /* temporary pointer */
    uInt e;               /* extra bits or operation */
    Bytef *f;             /* pointer to copy strings from */
  } _state;

#define t _state.t
#define b _state.b
#define k _state.k
#define p _state.p
#define n _state.n
#define q _state.q
#define m _state.m

  /* copy input/output information to locals (UPDATE macro restores) */
  LOAD

  /* process input based on current state */
  for (;;) switch (s->mode)
  {
    case TYPE:
      NEEDBITS(3)
      t = (uInt)b & 7;
      DUMPBITS(3)
      s->last = (t & 1) ? DRY : TYPE;
      switch (t >> 1)
      {
        case 0:                         /* stored */
          Tracev((stderr, "inflate:     stored block%s\n",
                 LAST ? " (last)" : ""));
          DUMPBITS(k&7)
          s->mode = LENS;               /* get length of stored block */
          break;
        case 1:                         /* fixed */
          Tracev((stderr, "inflate:     fixed codes block%s\n",
                 LAST ? " (last)" : ""));
          {
            if (!s->zs.fixed_built)
            {
              int _k;              /* temporary variable */
              uInt f = 0;         /* number of hufts used in fixed_mem */
              
              /* literal table */
              for (_k = 0; _k < 288; _k++)
              {
                char v=8;
                if (_k > 143)
                {
                  if (_k < 256) v++;
                  else if (_k < 280) v--;
                }
                s->zs.lc[_k] = v;
              }

              huft_build(s->zs.lc, 288, 257, cplens, cplext, &s->zs.fixed_tl, &s->zs.fixed_bl, s->zs.fixed_mem, &f, s->zs.v);

              /* distance table */
              for (_k = 0; _k < 30; _k++) s->zs.lc[_k] = 5;

              huft_build(s->zs.lc, 30, 0, cpdist, cpdext, &s->zs.fixed_td, &s->zs.fixed_bd, s->zs.fixed_mem, &f, s->zs.v);

              /* done */
              s->zs.fixed_built++;
            }

            /* s->sub.decode.t_codes.mode = CODES_START; */
            s->sub.decode.t_codes.lbits = (Byte)s->zs.fixed_bl;
            s->sub.decode.t_codes.dbits = (Byte)s->zs.fixed_bd;
            s->sub.decode.t_codes.ltree = s->zs.fixed_tl;
            s->sub.decode.t_codes.dtree = s->zs.fixed_td;
          }
          s->mode = CODES_START;
          break;
        case 2:                         /* dynamic */
          Tracev((stderr, "inflate:     dynamic codes block%s\n",
                 LAST ? " (last)" : ""));
          s->mode = TABLE;
          break;
        case 3:                         /* illegal */
          /* the only illegal value possible is 3 because we check only 2 bits */
          goto bad;
      }
      break;
    case LENS:
      NEEDBITS(16)
      s->sub.left = (uInt)b & 0xffff;
      b = k = 0;                      /* dump bits */
      Tracev((stderr, "inflate:       stored length %u\n", s->sub.left));
      s->mode = s->sub.left ? STORED : (inflate_mode)s->last;
      break;
    case STORED:
    {
      uInt mn;

      if (n == 0)
        LEAVE(Z_OK)
      NEEDOUT
      mn = min(m, n);
      t = min(s->sub.left, mn);
      zmemcpy(q, p, t);
      p += t;  n -= t;
      q += t;  m -= t;
      if (!(s->sub.left -= t))
        s->mode = (inflate_mode)s->last;
      break;
    }
    case TABLE:
      NEEDBITS(14)
      s->sub.trees.table = t = (uInt)b & 0x3fff;
      if ((t & 0x1f) > 29 || ((t >> 5) & 0x1f) > 29)
      {
        s->mode = NZ_BAD;
        LEAVE(Z_DATA_ERROR);
      }
      /* t = 258 + (t & 0x1f) + ((t >> 5) & 0x1f); */
      DUMPBITS(14)
      s->sub.trees.index = 0;
      Tracev((stderr, "inflate:       table sizes ok\n"));
      s->mode = BTREE;
    case BTREE:
      while (s->sub.trees.index < 4 + (s->sub.trees.table >> 10))
      {
        NEEDBITS(3)
        s->sub.trees.t_blens[(int)border[s->sub.trees.index++]] = (uInt)b & 7;
        DUMPBITS(3)
      }
      while (s->sub.trees.index < 19)
        s->sub.trees.t_blens[(int)border[s->sub.trees.index++]] = 0;
      s->sub.trees.bb = 7;

      {
        uInt hn = 0;          /* hufts used in space */

        t = huft_build(s->sub.trees.t_blens, 19, 19, Z_NULL, Z_NULL,
		       &s->sub.trees.tb, &s->sub.trees.bb, s->hufts, &hn, s->zs.v);
        if (t != Z_OK || !s->sub.trees.bb)
        {
          s->mode = NZ_BAD;
          break;
        }
      }

      s->sub.trees.index = 0;
      Tracev((stderr, "inflate:       bits tree ok\n"));
      s->mode = DTREE;
    case DTREE:
      while (t = s->sub.trees.table,
             s->sub.trees.index < 258 + (t & 0x1f) + ((t >> 5) & 0x1f))
      {
        inflate_huft *h;
        uInt i, j, d;

        t = s->sub.trees.bb;
        NEEDBITS(t)
        h = s->sub.trees.tb + ((uInt)b & (uInt)inflate_mask[t]);
        t = h->bits;
        d = h->base;
        if (d < 16)
        {
          DUMPBITS(t)
          s->sub.trees.t_blens[s->sub.trees.index++] = d;
        }
        else /* d == 16..18 */
        {
          if (d == 18)
          {
            i=7;
            j=11;
          }
          else
          {
            i=d-14;
            j=3;
          }
          NEEDBITS(t+i)
          DUMPBITS(t)
          j += (uInt)b & (uInt)inflate_mask[i];
          DUMPBITS(i)
          i = s->sub.trees.index;
          t = s->sub.trees.table;
          if (i + j > 258 + (t & 0x1f) + ((t >> 5) & 0x1f) ||
              (d == 16 && i < 1))
          {
            s->mode = NZ_BAD;
            LEAVE(Z_DATA_ERROR);
          }
          d = d == 16 ? s->sub.trees.t_blens[i - 1] : 0;
          do {
            s->sub.trees.t_blens[i++] = d;
          } while (--j);
          s->sub.trees.index = i;
        }
      }
      s->sub.trees.tb = Z_NULL;
      {
        uInt hn = 0;          /* hufts used in space */
        uInt bl, bd;
        inflate_huft *tl, *td;
        int nl,nd;
        t = s->sub.trees.table;

        nl = 257 + (t & 0x1f);
        nd = 1 + ((t >> 5) & 0x1f);
        bl = 9;         /* must be <= 9 for lookahead assumptions */
        bd = 6;         /* must be <= 9 for lookahead assumptions */

        t = huft_build(s->sub.trees.t_blens, nl, 257, cplens, cplext, &tl, &bl, s->hufts, &hn, s->zs.v);
        if (bl == 0) t = Z_DATA_ERROR;
        if (t == Z_OK)
        {
          /* build distance tree */
          t = huft_build(s->sub.trees.t_blens + nl, nd, 0, cpdist, cpdext, &td, &bd, s->hufts, &hn, s->zs.v);
        }
        if (t != Z_OK || (bd == 0 && nl > 257))
        {
          s->mode = NZ_BAD;
          LEAVE(Z_DATA_ERROR);
        }
        Tracev((stderr, "inflate:       trees ok\n"));

        /* s->sub.decode.t_codes.mode = CODES_START; */
        s->sub.decode.t_codes.lbits = (Byte)bl;
        s->sub.decode.t_codes.dbits = (Byte)bd;
        s->sub.decode.t_codes.ltree = tl;
        s->sub.decode.t_codes.dtree = td;
      }
      s->mode = CODES_START;

#define j (_state.j)
#define e (_state.e)
#define f (_state.f)

    /* waiting for "i:"=input, "o:"=output, "x:"=nothing */

    case CODES_START:         /* x: set up for LEN */
      c->sub.code.need = c->lbits;
      c->sub.code.tree = c->ltree;
      s->mode = CODES_LEN;
    case CODES_LEN:           /* i: get length/literal/eob next */
      t = c->sub.code.need;
      NEEDBITS(t)
      j = c->sub.code.tree + ((uInt)b & (uInt)inflate_mask[t]);
      DUMPBITS(j->bits)
      e = (uInt)(j->exop);
      if (e == 0)               /* literal */
      {
        c->sub.lit = j->base;
        s->mode = CODES_LIT;
        break;
      }
      if (e & 16)               /* length */
      {
        c->sub.copy.get = e & 15;
        c->len = j->base;
        s->mode = CODES_LENEXT;
        break;
      }
      if ((e & 64) == 0)        /* next table */
      {
        c->sub.code.need = e;
        c->sub.code.tree = j + j->base;
        break;
      }
      if (e & 32)               /* end of block */
      {
        s->mode = CODES_WASH;
        break;
      }
    goto bad;
    case CODES_LENEXT:        /* i: getting length extra (have base) */
      t = c->sub.copy.get;
      NEEDBITS(t)
      c->len += (uInt)b & (uInt)inflate_mask[t];
      DUMPBITS(t)
      c->sub.code.need = c->dbits;
      c->sub.code.tree = c->dtree;
      s->mode = CODES_DIST;
    case CODES_DIST:          /* i: get distance next */
      t = c->sub.code.need;
      NEEDBITS(t)
      j = c->sub.code.tree + ((uInt)b & (uInt)inflate_mask[t]);
      DUMPBITS(j->bits)
      e = (uInt)(j->exop);
      if (e & 16)               /* distance */
      {
        c->sub.copy.get = e & 15;
        c->sub.copy.dist = j->base;
        s->mode = CODES_DISTEXT;
        break;
      }
      if ((e & 64) == 0)        /* next table */
      {
        c->sub.code.need = e;
        c->sub.code.tree = j + j->base;
        break;
      }
      goto bad;        /* invalid code */
    case CODES_DISTEXT:       /* i: getting distance extra */
      t = c->sub.copy.get;
      NEEDBITS(t)
      c->sub.copy.dist += (uInt)b & (uInt)inflate_mask[t];
      DUMPBITS(t)
      s->mode = CODES_COPY;
    case CODES_COPY:          /* o: copying bytes in window, waiting for space */
      f = (uInt)(q - s->window) < c->sub.copy.dist ?
          s->end - (c->sub.copy.dist - (q - s->window)) :
          q - c->sub.copy.dist;

      while (c->len)
      {
        NEEDOUT
        OUTBYTE(*f++)
        if (f == s->end)
          f = s->window;
        c->len--;
      }
      s->mode = CODES_START;
      break;
    case CODES_LIT:           /* o: got literal, waiting for output space */
      NEEDOUT
      OUTBYTE(c->sub.lit)
      s->mode = CODES_START;
      break;
    case CODES_WASH:          /* o: got eob, possibly more output */
      if (k > 7)        /* return unused byte, if any */
      {
        k -= 8;
        n++;
        p--;            /* can always return one */
      }
      /* flushing will be done in DRY */

#undef j
#undef e
#undef f

    case DRY:
      FLUSH
      if (s->write != s->read)
        LEAVE(Z_OK)
      if (s->mode == CODES_WASH)
      {
        Tracev((stderr, "inflate:       codes end, %lu total out\n",
               z->total_out + (q >= s->read ? q - s->read :
               (s->end - s->read) + (q - s->window))));
      }
      /* DRY if last, TYPE if not */
      s->mode = (inflate_mode)s->last;
      if (s->mode == TYPE)
        break;
      LEAVE(Z_STREAM_END)
    /*case BAD:
      r = Z_DATA_ERROR;
      LEAVE
    */
    default: /* we'll call Z_STREAM_ERROR if BAD anyway */
    bad:
      s->mode = NZ_BAD;
      LEAVE(Z_STREAM_ERROR)
  }
}

#undef t
#undef b
#undef k
#undef p
#undef n
#undef q
#undef m
