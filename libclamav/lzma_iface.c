/*
 *  Copyright (C) 2007 Sourcefire Inc.
 *  Author: aCaB <acab@clamav.net>
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
#include "cltypes.h"
#include "others.h"

int cli_LzmaInit(CLI_LZMA *L, uint64_t size_override) {
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

void cli_LzmaShutdown(CLI_LZMA *L) {
  if(!L->initted) return;
  if(L->state.Probs) free(L->state.Probs);
  if(L->state.Dictionary) free(L->state.Dictionary);
  return;
}

int cli_LzmaDecode(CLI_LZMA *L) {
  int res;
  SizeT processed_in, processed_out;

  if (!L->initted && cli_LzmaInit(L, 0) != LZMA_RESULT_OK) 
    return LZMA_RESULT_DATA_ERROR;

  res = LzmaDecode(&L->state, L->next_in, L->avail_in, &processed_in, L->next_out, L->avail_out, &processed_out, (L->avail_in==0));

  L->next_in += processed_in;
  L->avail_in -= processed_in;
  L->next_out += processed_out;
  L->avail_out -= processed_out;

  return res;
}
