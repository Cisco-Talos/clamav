/*
 * LZMADecode.c
 * 
 * This file is a part of LZMA compression module for NSIS.
 * 
 * Original LZMA SDK Copyright (C) 1999-2006 Igor Pavlov
 * Modifications Copyright (C) 2003-2007 Amir Szekely <kichik@netvision.net.il>
 * 
 * Licensed under the Common Public License version 1.0 (the "License");
 * you may not use this file except in compliance with the License.
 * 
 * Licence details can be found in the file COPYING.nsis.
 * 
 * This software is provided 'as-is', without any express or implied
 * warranty.
 */

#include <stdlib.h>
#include "LZMADecode.h"

#define LEAVE { goto saveStateAndReturn; }
#define NEED_BYTE(c) case c: if (!avail_in) { mode = c; LEAVE; }
#define NEED_BYTE_ if (!avail_in) LEAVE;
#define NEXT_BYTE (avail_in--, *next_in++)
#define NEED_OUT(c) case c: if (!avail_out) { mode = c; LEAVE; }
#define PUT_BYTE_(b) { *next_out = b; next_out++; avail_out--; }
#define PUT_BYTE(b) { totalOut++; PUT_BYTE_(b) }
#define DECODE_BIT(c, x) prob = x; last = c; goto _LZMA_C_RDBD; case c:
#define DECODE_LEN(c, x) probs = x; last2 = c; goto _LZMA_C_LEND; case c:
#define DECODE_BIT_TREE(c, x, y) probs = x; numLevels = y; last3 = c; goto _LZMA_C_BTD; case c:

enum {
  /*  0 */ LZMA_C_INIT = 0,
  /*  1 */ LZMA_C_GETDICT,
  /*  2 */ LZMA_C_BLOCK,
  /*  3 */ LZMA_C_RDI, /* RangeDecoderInit */
  /*  4 */ LZMA_C_RDBD, /* RangeDecoderBitDecode */
  /*  5 */ LZMA_C_RDBD_IN, /* RangeDecoderBitDecode */
  /*  6 */ LZMA_C_TYPE,
  /*  7 */ LZMA_C_ISREP,
  /*  8 */ LZMA_C_ISREPG0,
  /*  9 */ LZMA_C_ISREP0LONG,
  /* 10 */ LZMA_C_ISREPG1,
  /* 11 */ LZMA_C_ISREPG2,
  /* 12 */ LZMA_C_NORM,
  /* 13 */ LZMA_C_LITDM1, /* LzmaLiteralDecodeMatch */
  /* 14 */ LZMA_C_LITDM2, /* LzmaLiteralDecodeMatch */
  /* 15 */ LZMA_C_LITD, /* LzmaLiteralDecode */
  /* 16 */ LZMA_C_RDRBTD, /* RangeDecoderReverseBitTreeDecode */
  /* 17 */ LZMA_C_LEND, /* LzmaLenDecode */
  /* 18 */ LZMA_C_LEND1, /* LzmaLenDecode */
  /* 19 */ LZMA_C_LEND2, /* LzmaLenDecode */
  /* 20 */ LZMA_C_LEND_RES, /* LzmaLenDecode */
  /* 21 */ LZMA_C_LEND_C1,
  /* 22 */ LZMA_C_LEND_C2,
  /* 23 */ LZMA_C_BTD, /* RangeDecoderBitTreeDecode */
  /* 24 */ LZMA_C_BTD_LOOP,
  /* 25 */ LZMA_C_BTD_C1,
  /* 26 */ LZMA_C_OUTPUT_1,
  /* 27 */ LZMA_C_OUTPUT_2,
  /* 28 */ LZMA_C_OUTPUT_3
};

#define kNumTopBits 24
#define kTopValue ((UInt32)1 << kNumTopBits)

#define kNumBitModelTotalBits 11
#define kBitModelTotal (1 << kNumBitModelTotalBits)
#define kNumMoveBits 5

#define RC_NORMALIZE(c) if (range < kTopValue) { NEED_BYTE(c); range <<= 8; code = (code << 8) | NEXT_BYTE; }

#define RC_GET_BIT2(c, prob, mi, A0, A1) { \
  UInt32 bound = (range >> kNumBitModelTotalBits) * *prob; \
  if (code < bound) \
    { A0; range = bound; *prob += (kBitModelTotal - *prob) >> kNumMoveBits; mi <<= 1; } \
  else \
    { A1; range -= bound; code -= bound; *prob -= (*prob) >> kNumMoveBits; mi = (mi + mi) + 1; } \
  RC_NORMALIZE(c) \
}

#define RC_GET_BIT(c, prob, mi) RC_GET_BIT2(c, prob, mi, ; , ;)

#define kNumPosBitsMax 4
#define kNumPosStatesMax (1 << kNumPosBitsMax)

#define kLenNumLowBits 3
#define kLenNumLowSymbols (1 << kLenNumLowBits)
#define kLenNumMidBits 3
#define kLenNumMidSymbols (1 << kLenNumMidBits)
#define kLenNumHighBits 8
#define kLenNumHighSymbols (1 << kLenNumHighBits)

#define LenChoice 0
#define LenChoice2 (LenChoice + 1)
#define LenLow (LenChoice2 + 1)
#define LenMid (LenLow + (kNumPosStatesMax << kLenNumLowBits))
#define LenHigh (LenMid + (kNumPosStatesMax << kLenNumMidBits))
#define kNumLenProbs (LenHigh + kLenNumHighSymbols)

#define kNumStates 12

#define kStartPosModelIndex 4
#define kEndPosModelIndex 14
#define kNumFullDistances (1 << (kEndPosModelIndex >> 1))

#define kNumPosSlotBits 6
#define kNumLenToPosStates 4

#define kNumAlignBits 4
#define kAlignTableSize (1 << kNumAlignBits)

#define kMatchMinLen 2

#define IsMatch 0
#define IsRep (IsMatch + (kNumStates << kNumPosBitsMax))
#define IsRepG0 (IsRep + kNumStates)
#define IsRepG1 (IsRepG0 + kNumStates)
#define IsRepG2 (IsRepG1 + kNumStates)
#define IsRep0Long (IsRepG2 + kNumStates)
#define PosSlot (IsRep0Long + (kNumStates << kNumPosBitsMax))
#define SpecPos (PosSlot + (kNumLenToPosStates << kNumPosSlotBits))
#define Align (SpecPos + kNumFullDistances - kEndPosModelIndex)
#define LenCoder (Align + kAlignTableSize)
#define RepLenCoder (LenCoder + kNumLenProbs)
#define Literal (RepLenCoder + kNumLenProbs)

#define LZMA_BASE_SIZE 1846
#define LZMA_LIT_SIZE 768

#if Literal != LZMA_BASE_SIZE
StopCompilingDueBUG
#endif

void lzmaInit(lzma_stream *s)
{
  /* size of lzma_stream minus the size of the two allocated buffer pointers.
     we don't want to lose to pointer or else we won't be able to free them. */
  size_t i = sizeof(lzma_stream) - (sizeof(unsigned char *) * 2);
  while (i--)
    ((lzByte *)s)[i] = 0;

  s->rep0 = s->rep1 = s->rep2 = s->rep3 = 1;
  s->range = (0xFFFFFFFF);
}

int lzmaDecode(lzma_stream *s)
{
  /* restore decoder state */
  lzma_stream _s = *s;

#define mode _s.mode
#define last _s.last
#define last2 _s.last2
#define last3 _s.last3

#define p (*(CProb **) &_s.dynamicData)
#define dynamicDataSize _s.dynamicDataSize

#define state _s.state
#define isPreviousMatch _s.isPreviousMatch
#define previousByte _s.previousByte
#define rep0 _s.rep0
#define rep1 _s.rep1
#define rep2 _s.rep2
#define rep3 _s.rep3
#define lc _s.lc
#define len _s.len
#define totalOut _s.totalOut

#define dictionary _s.dictionary
#define dictionarySize _s.dictionarySize
#define dictionaryPos _s.dictionaryPos

#define posStateMask _s.posStateMask
#define literalPosMask _s.literalPosMask

#define avail_in _s.avail_in
#define next_in _s.next_in
#define avail_out _s.avail_out
#define next_out _s.next_out

#define range _s.range
#define code _s.code

#define probs _s.probs
#define prob _s.prob

#define symbol _s.temp2
#define bit _s.temp3
#define matchBit _s.temp1
#define i _s.temp1
#define result _s.temp2
#define numLevels _s.temp3
#define posSlot _s.temp2
#define newDictionarySize (*(UInt32*) &_s.temp3)

#define matchByte _s.matchByte
#define mi _s.mi
#define posState _s.posState

  if (len == -1)
    return LZMA_STREAM_END;

  for (;;) switch (mode)
  {
  case LZMA_C_INIT:
    {
      lzByte firstByte;
      UInt32 newDynamicDataSize;
      UInt32 numProbs;
      int lp;
      int pb;

      NEED_BYTE_;

      firstByte = NEXT_BYTE;

      if (firstByte > (9*5*5))
        return LZMA_DATA_ERROR;

      pb = firstByte / (9*5);
      firstByte %= (9*5);
      lp = firstByte / 9;
      firstByte %= 9;
      lc = firstByte;

      posStateMask = (1 << (pb)) - 1;
      literalPosMask = (1 << (lp)) - 1;

      numProbs = Literal + (LZMA_LIT_SIZE << (lc + pb));
      newDynamicDataSize = numProbs * sizeof(CProb);

      if (newDynamicDataSize != dynamicDataSize)
      {
        if (p)
          lzmafree(p);
        p = lzmaalloc(newDynamicDataSize);
        if (!p)
          return LZMA_NOT_ENOUGH_MEM;
        dynamicDataSize = newDynamicDataSize;
      }

      while (numProbs--)
        p[numProbs] = kBitModelTotal >> 1;

      for (i = 0, newDictionarySize = 0; i < 4; i++)
      {
        NEED_BYTE(LZMA_C_GETDICT);
        newDictionarySize |= NEXT_BYTE << (i * 8);
      }

      if (newDictionarySize != dictionarySize)
      {
        dictionarySize = newDictionarySize;
        if (dictionary)
          lzmafree(dictionary);
        dictionary = lzmaalloc(dictionarySize);
        if (!dictionary)
          return LZMA_NOT_ENOUGH_MEM;
      }

      dictionary[dictionarySize - 1] = 0;

      i = 5;
      while (i--)
      {
        NEED_BYTE(LZMA_C_RDI);
        code = (code << 8) | NEXT_BYTE;
      }
    }
  case LZMA_C_BLOCK:
    posState = (int)(totalOut & posStateMask);
    DECODE_BIT(LZMA_C_TYPE, p + IsMatch + (state << kNumPosBitsMax) + posState);
    if (bit == 0)
    {
      probs = p + Literal + (LZMA_LIT_SIZE *
        (((totalOut & literalPosMask) << lc) + (previousByte >> (8 - lc))));

      if (state < 4) state = 0;
      else if (state < 10) state -= 3;
      else state -= 6;
      if (isPreviousMatch)
      {
        UInt32 pos = dictionaryPos - rep0;
        if (pos >= dictionarySize)
          pos += dictionarySize;
        matchByte = dictionary[pos];
        {
          symbol = 1;
          do
          {
            matchBit = (matchByte >> 7) & 1;
            matchByte <<= 1;
            {
              prob = probs + ((1 + matchBit) << 8) + symbol;
              RC_GET_BIT2(LZMA_C_LITDM1, prob, symbol, bit = 0, bit = 1)
            }
            if (matchBit != bit)
            {
              while (symbol < 0x100)
              {
                prob = probs + symbol;
                RC_GET_BIT(LZMA_C_LITDM2, prob, symbol)
              }
              break;
            }
          }
          while (symbol < 0x100);
          previousByte = symbol;
        }
        isPreviousMatch = 0;
      }
      else
      {
        symbol = 1;
        do
        {
          prob = probs + symbol;
          RC_GET_BIT(LZMA_C_LITD, prob, symbol)
        }
        while (symbol < 0x100);
        previousByte = symbol;
      }
      NEED_OUT(LZMA_C_OUTPUT_1);
      PUT_BYTE(previousByte);
      dictionary[dictionaryPos] = previousByte;
      dictionaryPos = (dictionaryPos + 1) % dictionarySize;
    }
    /* bit == 1 */
    else
    {
      isPreviousMatch = 1;
      DECODE_BIT(LZMA_C_ISREP, p + IsRep + state);
      if (bit == 1)
      {
        DECODE_BIT(LZMA_C_ISREPG0, p + IsRepG0 + state);
        if (bit == 0)
        {
          DECODE_BIT(LZMA_C_ISREP0LONG, p + IsRep0Long + (state << kNumPosBitsMax) + posState);
          if (bit == 0)
          {
            UInt32 pos;
            if (totalOut == 0)
              return LZMA_DATA_ERROR;
            state = state < 7 ? 9 : 11;
            NEED_OUT(LZMA_C_OUTPUT_2);
            pos = dictionaryPos - rep0;
            if (pos >= dictionarySize)
              pos += dictionarySize;
            previousByte = dictionary[pos];
            dictionary[dictionaryPos] = previousByte;
            dictionaryPos = (dictionaryPos + 1) % dictionarySize;
            PUT_BYTE(previousByte);
            mode = LZMA_C_BLOCK;
            break;
          }
        }
        else
        {
          UInt32 distance;
          DECODE_BIT(LZMA_C_ISREPG1, p + IsRepG1 + state);
          if (bit == 0)
          {
            distance = rep1;
          }
          else
          {
            DECODE_BIT(LZMA_C_ISREPG2, p + IsRepG2 + state);
            if (bit == 0)
              distance = rep2;
            else
            {
              distance = rep3;
              rep3 = rep2;
            }
            rep2 = rep1;
          }
          rep1 = rep0;
          rep0 = distance;
        }
        DECODE_LEN(LZMA_C_LEND_C1, p + RepLenCoder);
        state = state < 7 ? 8 : 11;
      }
      else
      {
        rep3 = rep2;
        rep2 = rep1;
        rep1 = rep0;
        state = state < 7 ? 7 : 10;
        DECODE_LEN(LZMA_C_LEND_C2, p + LenCoder);
        DECODE_BIT_TREE(
          LZMA_C_BTD_C1,
          p + PosSlot + ((len < kNumLenToPosStates ? len : kNumLenToPosStates - 1) << kNumPosSlotBits),
          kNumPosSlotBits
        );
        if (posSlot >= kStartPosModelIndex)
        {
          int numDirectBits = ((posSlot >> 1) - 1);
          rep0 = ((2 | ((UInt32)posSlot & 1)) << numDirectBits);
          if (posSlot < kEndPosModelIndex)
          {
            probs = p + SpecPos + rep0 - posSlot - 1;
            numLevels = numDirectBits;
          }
          else
          {
            int numTotalBits = numDirectBits - kNumAlignBits;
            result = 0;
            for (i = numTotalBits; i > 0; i--)
            {
              /* UInt32 t; */
              range >>= 1;

              result <<= 1;
              if (code >= range)
              {
                code -= range;
                result |= 1;
              }
              /*
              t = (code - range) >> 31;
              t &= 1;
              code -= range & (t - 1);
              result = (result + result) | (1 - t);
              */
              RC_NORMALIZE(LZMA_C_NORM)
            }
            rep0 += result << kNumAlignBits;
            probs = p + Align;
            numLevels = kNumAlignBits;
          }
          mi = 1;
          symbol = 0;
          for(i = 0; i < numLevels; i++)
          {
            prob = probs + mi;
            RC_GET_BIT2(LZMA_C_RDRBTD, prob, mi, ; , symbol |= (1 << i));
          }
          rep0 += symbol;
        }
        else
          rep0 = posSlot;
        rep0++;
      }
      if (rep0 == (UInt32)(0))
      {
        len = -1;
        LEAVE;
      }
      if (rep0 > totalOut)
      {
        return LZMA_DATA_ERROR;
      }
      len += kMatchMinLen;
      totalOut += len;
      do
      {
        UInt32 pos;
        NEED_OUT(LZMA_C_OUTPUT_3);
        pos = dictionaryPos - rep0;
        if (pos >= dictionarySize)
          pos += dictionarySize;
        previousByte = dictionary[pos];
        dictionary[dictionaryPos] = previousByte;
        dictionaryPos = (dictionaryPos + 1) % dictionarySize;
        PUT_BYTE_(previousByte);
        len--;
      }
      while(len > 0);
    }
    mode = LZMA_C_BLOCK;
    break;
  case LZMA_C_RDBD:
  _LZMA_C_RDBD:
    {
      UInt32 bound = (range >> kNumBitModelTotalBits) * *prob;
      if (code < bound)
      {
        range = bound;
        *prob += (kBitModelTotal - *prob) >> kNumMoveBits;
        bit = 0;
      }
      else
      {
        range -= bound;
        code -= bound;
        *prob -= (*prob) >> kNumMoveBits;
        bit = 1;
      }
      RC_NORMALIZE(LZMA_C_RDBD_IN);
    }
    mode = last;
    break;
  case LZMA_C_LEND:
  _LZMA_C_LEND:
      DECODE_BIT(LZMA_C_LEND1, probs + LenChoice);
      if (bit == 0)
      {
        len = 0;
        probs += LenLow + (posState << kLenNumLowBits);
        numLevels = kLenNumLowBits;
      }
      else {
        DECODE_BIT(LZMA_C_LEND2, probs + LenChoice2);
        if (bit == 0)
        {
          len = kLenNumLowSymbols;
          probs += + LenMid + (posState << kLenNumMidBits);
          numLevels = kLenNumMidBits;
        }
        else
        {
          len = kLenNumLowSymbols + kLenNumMidSymbols;
          probs += LenHigh;
          numLevels = kLenNumHighBits;
        }
      }

      last3 = LZMA_C_LEND_RES;
  case LZMA_C_BTD:
  _LZMA_C_BTD:
    mi = 1;
    for(i = numLevels; i > 0; i--)
    {
      prob = probs + mi;
      RC_GET_BIT(LZMA_C_BTD_LOOP, prob, mi)
    }
    result = mi - (1 << numLevels);
    mode = last3;
    break;
  case LZMA_C_LEND_RES:
    len += result;
    mode = last2;
    break;
  default:
    return LZMA_DATA_ERROR;
  }

saveStateAndReturn:

  /* save decoder state */
  *s = _s;

  return LZMA_OK;
}


/* aCaB */
void lzmaShutdown(lzma_stream *s) {
  lzma_stream _s = *s;
  if (p) lzmafree(p);
  if (dictionary) lzmafree(dictionary);
  p = NULL;
  dictionary = NULL;
  *s = _s;
}
