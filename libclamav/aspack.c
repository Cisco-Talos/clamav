/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Luciano Giuseppe 'Pnluck', Alberto Wu
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

#include <string.h>

#include "clamav.h"
#include "execs.h"
#include "others.h"
#include "rebuildpe.h"
#include "aspack.h"


#define ASPACK_BLOCKS_OFFSET_212          0x57c
#define ASPACK_BLOCKS_OFFSET_OTHER        0x5d8
#define ASPACK_BLOCKS_OFFSET_242          0x5e4

#define ASPACK_STR_INIT_MLT_OFFSET_212    0x70e
#define ASPACK_STR_INIT_MLT_OFFSET_OTHER  0x76a
#define ASPACK_STR_INIT_MLT_OFFSET_242    0x776

#define ASPACK_COMP_BLOCK_OFFSET_212      0x6d6
#define ASPACK_COMP_BLOCK_OFFSET_OTHER    0x732
#define ASPACK_COMP_BLOCK_OFFSET_242      0x73e

#define ASPACK_WRKBUF_OFFSET_212          0x148
#define ASPACK_WRKBUF_OFFSET_OTHER        0x13a
#define ASPACK_WRKBUF_OFFSET_242          0x148

struct DICT_HELPER {
  uint32_t *starts;
  uint8_t *ends;
  uint32_t size;
};

struct ASPK {
  uint32_t bitpos;
  uint32_t hash;
  uint32_t init_array[58];
  struct DICT_HELPER dict_helper[4];
  uint8_t *input;
  uint8_t *iend;
  uint8_t *decrypt_dict;
  uint32_t decarray3[4][24];
  uint32_t decarray4[4][24];
  int dict_ok;
  uint8_t array2[758];
  uint8_t array1[19];
};


static inline int readstream(struct ASPK *stream) {
  while (stream->bitpos >= 8) {
    if (stream->input>=stream->iend) return 0;
    stream->hash = (stream->hash << 8) | *stream->input;
    stream->input++;
    stream->bitpos -= 8;
  }
  return 1;
}

static uint32_t getdec(struct ASPK *stream, uint8_t which, int *err) {
  uint32_t ret;
  uint8_t pos;
  uint32_t *d3 = stream->decarray3[which];
  uint32_t *d4 = stream->decarray4[which];

  *err=1;

  if (!readstream(stream)) return 0;

  ret = (stream->hash >> (8 - stream->bitpos)) & 0xfffe00;

  if (ret < d3[8]) {
    if ((ret>>16) >= 0x100) return 0;
    if (!(pos=stream->dict_helper[which].ends[ret>>16]) || pos>= 24) return 0; /* 0<pos<24 */
  } else {
    if (ret < d3[10]) {
      if (ret < d3[9]) pos = 9;
      else pos = 10;
    } else {
      if (ret < d3[11] ) pos = 11;
      else {
	if (ret < d3[12]) pos = 12;
	else {
	  if (ret < d3[13]) pos = 13;
	  else {
	    if (ret < d3[14]) pos = 14;
	    else pos = 15;
	  }
	}
      }
    }
  }

  stream->bitpos += pos;
  ret = ((ret - d3[pos-1]) >> (24 - pos)) + d4[pos];

  if (ret >= stream->dict_helper[which].size) return 0;
  ret = stream->dict_helper[which].starts[ret];

  *err=0;
  return ret;
}


static uint8_t build_decrypt_array(struct ASPK *stream, uint8_t* array, uint8_t which) {
  uint32_t sum = 0, counter = 23, i, endoff = 0, bus[18], dict[18];

  uint32_t *d3 = stream->decarray3[which];
  uint32_t *d4 = stream->decarray4[which];

  memset(bus,0,sizeof(bus));
  memset(dict,0,sizeof(dict));

  for (i = 0; i < stream->dict_helper[which].size; i++) {
    /* within bounds - see comments in build_decrypt_dictionaries */
    if (array[i] > 17) return 0;
    bus[array[i]]++;
  }

  d3[0] = 0;
  d4[0] = 0;

  i = 0;
  while (counter >= 9) { /* 0<=i<=14 */
    sum += (bus[i+1] << counter);
    if (sum > 0x1000000) return 0;

    d3[i+1] = sum;
    d4[i+1] = dict[i+1] = bus[i] + d4[i];
      
    if (counter >= 0x10) {
      uint32_t old = endoff;
      endoff = d3[i+1] >> 0x10;
      if (endoff-old) {
	if (!CLI_ISCONTAINED(stream->dict_helper[which].ends, 0x100, stream->dict_helper[which].ends+old, endoff-old)) return 0;
	memset((stream->dict_helper[which].ends + old), i+1, endoff-old);
      }
    }

    i++;
    counter--;
  }

  if (sum != 0x1000000) return 0;

  i = 0;
  for (i=0; i < stream->dict_helper[which].size; i++) {
    if (array[i]) { /* within bounds - see above */
      if (array[i] > 17) return 0;
      if (dict[array[i]]>=stream->dict_helper[which].size) return 0;
      stream->dict_helper[which].starts[dict[array[i]]] = i;
      dict[array[i]]++;
    }
  }

  return 1;
}


static uint8_t getbits(struct ASPK *stream, uint32_t num, int *err) {
  uint8_t retvalue;

  if (!readstream(stream)) {
    *err=1;
    return 0;
  }

  *err = 0;
  retvalue = ((stream->hash >> (8 - stream->bitpos))&0xffffff) >> (24 - num);
  stream->bitpos += num;

  return retvalue;
}


static int build_decrypt_dictionaries(struct ASPK *stream) {
  unsigned int counter;
  uint32_t ret;
  int oob;

  if (!getbits(stream, 1, &oob)) memset(stream->decrypt_dict, 0, 0x2f5);
  if (oob) return 0;

  for (counter = 0; counter < 19; counter++) {
    stream->array1[counter]=getbits(stream, 4, &oob);
    if (oob) return 0;
  }

  if (!build_decrypt_array(stream, stream->array1, 3)) return 0; /* array1[19] - [3].size=19 */

  counter = 0;
  while (counter < 757) {
    ret = getdec(stream, 3, &oob);
    if (oob) return 0;
    if (ret >= 16) {
      if (ret != 16) {
	if (ret == 17) ret = 3 + getbits(stream, 3, &oob);
	else ret = 11 + getbits(stream, 7, &oob);
	if (oob) return 0;
	while (ret) {
	  if (counter >= 757) break;
	  stream->array2[1+counter] = 0;
	  counter++;
	  ret--;
	}
      } else {
	ret = 3 + getbits(stream, 2, &oob);
	if (oob) return 0;
	while (ret) {
	  if (counter >= 757) break;
	  stream->array2[1+counter] = stream->array2[counter];
	  counter++;
	  ret--;
	}
      }
    } else {
      stream->array2[1+counter] = (stream->decrypt_dict[counter] + ret) & 0xF;
      counter++;
    }
  }
  
  if (!build_decrypt_array(stream, &stream->array2[1], 0) /* array2[758-1=757] - [0].size=721 */ || !build_decrypt_array(stream, &stream->array2[722], 1) /* array2[758-722=36] - [1].size=28 */ || !build_decrypt_array(stream, &stream->array2[750], 2) /* array2[758-750=8] - [2].size=8 */ ) return 0;
  
  stream->dict_ok = 0;
  for (counter = 0; counter < 8; counter++) {
    if (stream->array2[750+counter] != 3) {
      stream->dict_ok = 1;
      break;
    }
  }

  memcpy(stream->decrypt_dict,&stream->array2[1],757);

  return 1;
}


static int decrypt(struct ASPK *stream, uint8_t *stuff, uint32_t size, uint8_t *output) {
  /* ep+6d6 -> ep+748  = 0x72*/
  uint32_t gen, backsize, backbytes, useold, counter = 0;
  uint32_t hist[4]={0,0,0,0};
  int oob;

  cli_dbgmsg("Aspack: decrypt size:%x\n", size);
  while (counter < size) {
    gen = getdec(stream, 0, &oob);
    if (oob) return 0;
    if (gen < 256) { /* implied within bounds */
      output[counter] = (uint8_t)gen;
      counter++;
      continue;
    }
    if (gen >= 720) {
      if (!build_decrypt_dictionaries(stream)) return 0;
      continue;
    }
    if ((backbytes = (gen - 256) >> 3)>=58) return 0; /* checks init_array + stuff */
    backsize =  ((gen - 256) & 7) + 2;
    if ((backsize-2)==7) {
      uint8_t hlp;
      gen = getdec(stream, 1, &oob);
      if (oob || gen>=0x56) return 0;
      hlp = stuff[gen + 0x1c];
      if (!readstream(stream)) return 0;
      backsize += stuff[gen] + (( (stream->hash >> (8 - stream->bitpos)) & 0xffffff ) >> (0x18 - hlp));
      stream->bitpos += hlp;
    }

    useold = stream->init_array[backbytes];
    gen = stuff[backbytes + 0x38];

    if (!stream->dict_ok || gen < 3) {
      if (!readstream(stream)) return 0;
      useold += ((stream->hash >> ( 8 - stream->bitpos) ) & 0xffffff) >> (24 - gen);
      stream->bitpos += gen;
    } else {
      gen -= 3;
      if (!readstream(stream)) return 0;
      useold += ((((stream->hash >> ( 8 - stream->bitpos)) & 0xffffff) >> (24 - gen)) * 8);
      stream->bitpos += gen;
      useold += getdec(stream, 2, &oob);
      if (oob) return 0;
    }
    
    if (useold < 3) {
      backbytes = hist[useold];
      if (useold != 0) {
	hist[useold] = hist[0];
	hist[0] = backbytes;
      }
    } else {
      hist[2] = hist[1];
      hist[1] = hist[0];
      hist[0] = backbytes = useold-3;
    }

    backbytes++;

    if (!backbytes || backbytes>counter || backsize>size-counter) return 0;
    while (backsize--) {
      output[counter] = output[counter-backbytes];
      counter++;
    }
  }

  return 1;
}


static int decomp_block(struct ASPK *stream, uint32_t size, uint8_t *stuff, uint8_t *output) {
  memset(stream->decarray3,0,sizeof(stream->decarray3));
  memset(stream->decarray4,0,sizeof(stream->decarray4));
  memset(stream->decrypt_dict, 0, 757);
  stream->bitpos = 0x20;
  if (!build_decrypt_dictionaries(stream)) return 0;
  return decrypt(stream, stuff, size, output);
}

#define INIT_DICT_HELPER(n,sz)					\
  stream.dict_helper[n].starts = (uint32_t *)wrkbuf;		\
  stream.dict_helper[n].ends = &wrkbuf[sz * sizeof(uint32_t)];	\
  stream.dict_helper[n].size = sz;				\
  wrkbuf = &wrkbuf[sz * sizeof(uint32_t) + 0x100];

int unaspack(uint8_t *image, unsigned int size, struct cli_exe_section *sections, uint16_t sectcount, uint32_t ep, uint32_t base, int f, aspack_version_t version)
{
  struct ASPK stream;
  uint32_t i=0, j=0;
  uint8_t *blocks = NULL, *wrkbuf;
  uint32_t block_rva = 1, block_size;
  struct cli_exe_section *outsects;

  uint32_t blocks_offset, stream_init_multiplier_offset, comp_block_offset, wrkbuf_offset;

  switch (version) {
    case ASPACK_VER_212:
      cli_dbgmsg("Aspack: Attempting to unpack Aspack 2.12.\n");
      blocks_offset = ASPACK_BLOCKS_OFFSET_212;
      stream_init_multiplier_offset = ASPACK_STR_INIT_MLT_OFFSET_212;
      comp_block_offset = ASPACK_COMP_BLOCK_OFFSET_212;
      wrkbuf_offset = ASPACK_WRKBUF_OFFSET_212;
      break;
    case ASPACK_VER_OTHER:
      cli_dbgmsg("Aspack: Attempting to unpack Aspack >2.12, <2.42.\n");
      blocks_offset = ASPACK_BLOCKS_OFFSET_OTHER;
      stream_init_multiplier_offset = ASPACK_STR_INIT_MLT_OFFSET_OTHER;
      comp_block_offset = ASPACK_COMP_BLOCK_OFFSET_OTHER;
      wrkbuf_offset = ASPACK_WRKBUF_OFFSET_OTHER;
      break;
    case ASPACK_VER_242:
      cli_dbgmsg("Aspack: Attempting to unpack Aspack 2.42.\n");
      blocks_offset = ASPACK_BLOCKS_OFFSET_242;
      stream_init_multiplier_offset = ASPACK_STR_INIT_MLT_OFFSET_242;
      comp_block_offset = ASPACK_COMP_BLOCK_OFFSET_242;
      wrkbuf_offset = ASPACK_WRKBUF_OFFSET_242;
      break;
    default:
      cli_dbgmsg("Aspack: Unexpected/Unknown version number.\n");
      return 0;
  }

  blocks = image+ep+blocks_offset;

  if (!(wrkbuf = cli_calloc(0x1800, sizeof(uint8_t)))) {
    cli_dbgmsg("Aspack: Unable to allocate dictionary\n");
    return 0;
  }

  INIT_DICT_HELPER(0, 721); /* dictionary -> dictionary + b44 */
  INIT_DICT_HELPER(1, 28);  /* dictionary + c44 -> dictionary + cb4 */
  INIT_DICT_HELPER(2, 8);   /* dictionary + db4 -> dictionary + dd4 */
  INIT_DICT_HELPER(3, 19);  /* dictionary + ed4 -> dictionary + f20 */
  stream.decrypt_dict = wrkbuf;

  stream.hash = 0x10000;

  for (i = 0; i < 58; i++) {
    stream.init_array[i] = j;
        if (ep + i + stream_init_multiplier_offset < size) {
            j += (1 << image[ep + i + stream_init_multiplier_offset]);
        }
  }

  memset(stream.array1,0,sizeof(stream.array1));
  memset(stream.array2,0,sizeof(stream.array2));

  i=0;
  while (CLI_ISCONTAINED(image, size, blocks, 8) && (block_rva = cli_readint32(blocks)) && (block_size = cli_readint32(blocks+4)) && CLI_ISCONTAINED(image, size, image+block_rva, block_size)) {

    cli_dbgmsg("Aspack: unpacking block rva:%x - sz:%x\n", block_rva, block_size);
    wrkbuf = (uint8_t *)cli_calloc(block_size+0x10e, sizeof(uint8_t));

    if (!wrkbuf) {
      cli_dbgmsg("Aspack: Null work buff\n");
      break;
    }
    stream.input = wrkbuf;
    stream.iend = &wrkbuf[block_size+0x10e];

    memcpy(wrkbuf, image + block_rva, block_size);

    if (!decomp_block(&stream, block_size, &image[ep+comp_block_offset], image + block_rva)) {
      cli_dbgmsg("Aspack: decomp_block failed\n");
      free(wrkbuf);
      break;
    }
    else
      cli_dbgmsg("Aspack: decomp block succeed\n");

    free(wrkbuf);
    
    if (i==0 && block_size>7) { /* first sect j/c unrolling */
      while (i < block_size - 6) {
        uint8_t curbyte = image[block_rva+i];
        if (curbyte == 0xe8 || curbyte == 0xe9) {
          wrkbuf = &image[block_rva+i+1];
          if (*wrkbuf == image[ep+wrkbuf_offset]) {
            uint32_t target = cli_readint32(wrkbuf) & 0xffffff00;
            CLI_ROL(target, 0x18);
            cli_writeint32(wrkbuf, target - i);
            i+=4;
          }
        }
        i++;
      }
    }
    if (version == ASPACK_VER_212) {
      blocks+=8;
    } else {
      blocks += 12;
      block_size = cli_readint32(blocks+4);
      while (!((block_size +0x10e) & 0xffffffff))
      {	
        blocks += 12;
        block_size = cli_readint32(blocks+4);
      }
    }
  }

  cli_dbgmsg("Aspack: leaving loop all uncompressed\n");

  free(stream.dict_helper[0].starts);
  if (block_rva) {
    cli_dbgmsg("Aspack: unpacking failure\n");
    return 0;
  }

  if(sectcount>2 && ep == sections[sectcount-2].rva && !sections[sectcount-1].rsz) {
    sectcount-=2;
  }
  if(!(outsects=cli_malloc(sizeof(struct cli_exe_section)*sectcount))) {
    cli_dbgmsg("Aspack: OOM - rebuild failed\n");
    cli_writen(f, image, size);
    return 1; /* No whatsoheader - won't infloop in pe.c */
  }
  memcpy(outsects, sections, sizeof(struct cli_exe_section)*sectcount);
  for(i=0; i<sectcount; i++) {
    outsects[i].raw=outsects[i].rva;
    outsects[i].rsz=outsects[i].vsz;
  }
  if (!cli_rebuildpe((char *)image, outsects, sectcount, base, cli_readint32(image + ep + 0x39b), 0, 0, f)) {
    cli_dbgmsg("Aspack: rebuild failed\n");
    cli_writen(f, image, size);
  } else {
    cli_dbgmsg("Aspack: successfully rebuilt\n");
  }
  free(outsects);
  return 1;
}

