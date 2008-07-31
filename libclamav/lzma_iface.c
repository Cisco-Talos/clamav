/*
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
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

/* a cleaner state interface to LZMA */


#include "lzma_iface.h"
#include "LzmaStateDecode.h"
#include "cltypes.h"

/* we don't need zlib, and zlib defines Byte, that lzma also defines.
 * Enabling prefixes for zlib types avoids problems, and since
 * we don't call any zlib functions here avoids unresolved symbols too */
#define Z_PREFIX
#include "others.h"

struct CLI_LZMA_tag {
  CLzmaDecoderState state;
  unsigned char *next_in;
  SizeT avail_in;
  unsigned char *next_out;
  SizeT avail_out;
  int initted;
  uint64_t usize;
};

int cli_LzmaInit(CLI_LZMA **Lp, uint64_t size_override) {
  CLI_LZMA *L = *Lp;

  if(!L) {
	  *Lp = L = cli_calloc(sizeof(*L), 1);
	  if(!L) {
		  return CL_EMEM;
	  }
  }

  L->initted = 0;
  if(size_override) L->usize=size_override;

  if (!L->next_in || L->avail_in < LZMA_PROPERTIES_SIZE + 8) return LZMA_RESULT_OK;
  if (LzmaDecodeProperties(&L->state.Properties, L->next_in, LZMA_PROPERTIES_SIZE) != LZMA_RESULT_OK)
    return LZMA_RESULT_DATA_ERROR;

  L->next_in += LZMA_PROPERTIES_SIZE;
  L->avail_in -= LZMA_PROPERTIES_SIZE;

  if (!L->usize) {
    L->usize=(uint64_t)cli_readint32(L->next_in) + ((uint64_t)cli_readint32(L->next_in+4)<<32);
    L->next_in += 8;
    L->avail_in -= 8;
  }
    
  if (!(L->state.Probs = (CProb *)cli_malloc(LzmaGetNumProbs(&L->state.Properties) * sizeof(CProb))))
    return LZMA_RESULT_DATA_ERROR;

  if (!(L->state.Dictionary = (unsigned char *)cli_malloc(L->state.Properties.DictionarySize))) {
    free(L->state.Probs);
    return LZMA_RESULT_DATA_ERROR;
  }

  L->initted = 1;

  LzmaDecoderInit(&L->state);
  return LZMA_RESULT_OK;
}

void cli_LzmaShutdown(CLI_LZMA **Lp) {
  CLI_LZMA *L;

  if(!Lp) return;
  L = *Lp;
  if(L->initted) {
    if(L->state.Probs) free(L->state.Probs);
    if(L->state.Dictionary) free(L->state.Dictionary);
  }
  free(L);
  *Lp = NULL;
  return;
}

int cli_LzmaDecode(CLI_LZMA **Lp, struct stream_state* state) {
  int res;
  SizeT processed_in, processed_out;
  CLI_LZMA* L = *Lp;

  if(L) {
	  L->avail_in = state->avail_in;
	  L->next_in = state->next_in;
	  L->avail_out = state->avail_out;
	  L->next_out = state->next_out;
  }

  if (!L || !L->initted) {
	  if(cli_LzmaInit(Lp, 0) != LZMA_RESULT_OK)
		  return LZMA_RESULT_DATA_ERROR;
	  L = *Lp;
  }


  res = LzmaDecode(&L->state, L->next_in, L->avail_in, &processed_in, L->next_out, L->avail_out, &processed_out, (L->avail_in==0));

  L->next_in += processed_in;
  L->avail_in -= processed_in;
  L->next_out += processed_out;
  L->avail_out -= processed_out;

  state->avail_in = L->avail_in;
  state->next_in = L->next_in;
  state->avail_out = L->avail_out;
  state->next_out = L->next_out;

  return res;
}

int cli_LzmaInitUPX(CLI_LZMA **Lp, uint32_t dictsz) {
  CLI_LZMA *L = *Lp;

  if(!L) {
    *Lp = L = cli_calloc(sizeof(*L), 1);
    if(!L) {
      return LZMA_RESULT_DATA_ERROR;
    }
  }

  L->state.Properties.pb = 2; /* FIXME: these  */
  L->state.Properties.lp = 0; /* values may    */
  L->state.Properties.lc = 3; /* not be static */

  L->state.Properties.DictionarySize = dictsz;

  if (!(L->state.Probs = (CProb *)cli_malloc(LzmaGetNumProbs(&L->state.Properties) * sizeof(CProb))))
    return LZMA_RESULT_DATA_ERROR;

  if (!(L->state.Dictionary = (unsigned char *)cli_malloc(L->state.Properties.DictionarySize))) {
    free(L->state.Probs);
    return LZMA_RESULT_DATA_ERROR;
  }

  L->initted = 1;

  LzmaDecoderInit(&L->state);
  return LZMA_RESULT_OK;
}
