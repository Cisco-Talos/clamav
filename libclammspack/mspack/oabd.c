/* This file is part of libmspack.
 * © 2013 Intel Corporation
 *
 * libmspack is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License (LGPL) version 2.1
 *
 * For further details, see the file COPYING.LIB distributed with libmspack
 */

/* The Exchange Online Addressbook (OAB or sometimes OAL) is distributed
 * as a .LZX file in one of two forms. Either a "full download" containing
 * the entire address list, or an incremental binary patch which should be
 * applied to a previous version of the full decompressed data.
 *
 * The contents and format of the decompressed OAB are not handled here.
 *
 * For a complete description of the format, see the MSDN site:
 *
 * http://msdn.microsoft.com/en-us/library/cc463914 - [MS-OXOAB].pdf
 * http://msdn.microsoft.com/en-us/library/cc483133 - [MS-PATCH].pdf
 */

/* OAB decompression implementation */

#include <system.h>
#include <oab.h>
#include <lzx.h>
#include <crc32.h>

/* prototypes */
static int oabd_decompress(struct msoab_decompressor *self, const char *input,
			   const char *output);
static int oabd_decompress_incremental(struct msoab_decompressor *self,
				       const char *input, const char *base,
				       const char *output);

struct msoab_decompressor *
  mspack_create_oab_decompressor(struct mspack_system *sys)
{
  struct msoab_decompressor_p *self = NULL;

  if (!sys) sys = mspack_default_system;
  if (!mspack_valid_system(sys)) return NULL;

  if ((self = (struct msoab_decompressor_p *) sys->alloc(sys, sizeof(struct msoab_decompressor_p)))) {
    self->base.decompress             = &oabd_decompress;
    self->base.decompress_incremental = &oabd_decompress_incremental;
    self->system                      = sys;
  }
  return (struct msoab_decompressor *) self;
}

void mspack_destroy_oab_decompressor(struct msoab_decompressor *base) {
  struct msoab_decompressor_p *self = (struct msoab_decompressor_p *)base;
  if (self) {
    struct mspack_system *sys = self->system;
    sys->free(self);
  }
}

struct oabd_file {
  struct mspack_system *orig_sys;
  struct mspack_file *orig_file;
  unsigned int crc;
  size_t available;
};


static int oabd_sys_read (struct mspack_file *base_file, void *buf, int size)
{
  struct oabd_file *file = (struct oabd_file *)base_file;
  int bytes_read;

  if ((size_t)size > file->available)
    size = file->available;

  bytes_read = file->orig_sys->read(file->orig_file, buf, size);
  if (bytes_read < 0)
    return bytes_read;

  file->available -= bytes_read;
  return bytes_read;
}

static int oabd_sys_write (struct mspack_file *base_file, void *buf, int size)
{
  struct oabd_file *file = (struct oabd_file *)base_file;
  int bytes_written = file->orig_sys->write(file->orig_file, buf, size);

  if (bytes_written > 0)
    file->crc = crc32(file->crc, buf, bytes_written);

  return bytes_written;
}

static int oabd_decompress(struct msoab_decompressor *_self, const char *input,
			   const char *output)
{
  struct msoab_decompressor_p *self = (struct msoab_decompressor_p *) _self;
  struct mspack_system *sys;
  struct mspack_file *infh = NULL;
  struct mspack_file *outfh = NULL;
  unsigned char *buf = NULL;
  unsigned char hdrbuf[oabhead_SIZEOF];
  unsigned int block_max, target_size;
  struct lzxd_stream *lzx = NULL;
  struct mspack_system oabd_sys;
  struct oabd_file in_ofh, out_ofh;
  unsigned int window_bits;
  int ret = MSPACK_ERR_OK;

  if (!self) return MSPACK_ERR_ARGS;
  sys = self->system;

  infh = sys->open(sys, input, MSPACK_SYS_OPEN_READ);
  if (!infh) {
    ret = MSPACK_ERR_OPEN;
    goto out;
  }

  if (sys->read(infh, hdrbuf, oabhead_SIZEOF) != oabhead_SIZEOF) {
    ret = MSPACK_ERR_READ;
    goto out;
  }

  if (EndGetI32(&hdrbuf[oabhead_VersionHi]) != 3 ||
      EndGetI32(&hdrbuf[oabhead_VersionLo]) != 1) {
    ret = MSPACK_ERR_SIGNATURE;
    goto out;
  }

  block_max   = EndGetI32(&hdrbuf[oabhead_BlockMax]);
  target_size = EndGetI32(&hdrbuf[oabhead_TargetSize]);

  /* We use it for reading block headers too */
  if (block_max < oabblk_SIZEOF)
    block_max = oabblk_SIZEOF;

  outfh = sys->open(sys, output, MSPACK_SYS_OPEN_WRITE);
  if (!outfh) {
    ret = MSPACK_ERR_OPEN;
    goto out;
  }

  buf = sys->alloc(sys, block_max);
  if (!buf) {
    ret = MSPACK_ERR_NOMEMORY;
    goto out;
  }

  oabd_sys = *sys;
  oabd_sys.read = oabd_sys_read;
  oabd_sys.write = oabd_sys_write;

  in_ofh.orig_sys = sys;
  in_ofh.orig_file = infh;

  out_ofh.orig_sys = sys;
  out_ofh.orig_file = outfh;

  while (target_size) {
    unsigned int blk_csize, blk_dsize, blk_crc, blk_flags;

    if (sys->read(infh, buf, oabblk_SIZEOF) != oabblk_SIZEOF) {
      ret = MSPACK_ERR_READ;
      goto out;
    }
    blk_flags = EndGetI32(&buf[oabblk_Flags]);
    blk_csize = EndGetI32(&buf[oabblk_CompSize]);
    blk_dsize = EndGetI32(&buf[oabblk_UncompSize]);
    blk_crc   = EndGetI32(&buf[oabblk_CRC]);

    if (blk_dsize > block_max || blk_dsize > target_size || blk_flags > 1) {
      ret = MSPACK_ERR_DATAFORMAT;
      goto out;
    }

    if (!blk_flags) {
      /* Uncompressed block */
      if (blk_dsize != blk_csize) {
	ret = MSPACK_ERR_DATAFORMAT;
	goto out;
      }
      if (sys->read(infh, buf, blk_dsize) != (int)blk_dsize) {
	ret = MSPACK_ERR_READ;
	goto out;
      }
      if (sys->write(outfh, buf, blk_dsize) != (int)blk_dsize) {
	ret = MSPACK_ERR_WRITE;
	goto out;
      }
    } else {
      /* LZX compressed block */
      window_bits = 17;

      while (window_bits < 25 && (1U << window_bits) < blk_dsize)
	window_bits++;

      in_ofh.available = blk_csize;
      out_ofh.crc = 0xffffffff;

      lzx = lzxd_init(&oabd_sys, (void *)&in_ofh, (void *)&out_ofh, window_bits,
		      0, 4096, blk_dsize, 1);
      if (!lzx) {
	ret = MSPACK_ERR_NOMEMORY;
	goto out;
      }

      ret = lzxd_decompress(lzx, blk_dsize);
      if (ret != MSPACK_ERR_OK)
	goto out;

      lzxd_free(lzx);
      lzx = NULL;

      /* Consume any trailing padding bytes before the next block */
      while (in_ofh.available) {
	int count = block_max;
	if ((size_t)count > in_ofh.available)
	  count = in_ofh.available;

	count = sys->read(infh, buf, count);
	if (count < 0) {
	  ret = MSPACK_ERR_READ;
	  goto out;
	}
	in_ofh.available -= count;
      }

      if (out_ofh.crc != blk_crc) {
	ret = MSPACK_ERR_CHECKSUM;
	goto out;
      }
    }
    target_size -= blk_dsize;
  }

 out:
  if (lzx) lzxd_free(lzx);
  if (outfh) sys->close(outfh);
  if (infh) sys->close(infh);
  sys->free(buf);

  return ret;
}

static int oabd_decompress_incremental(struct msoab_decompressor *_self,
				       const char *input, const char *base,
				       const char *output)
{
  struct msoab_decompressor_p *self = (struct msoab_decompressor_p *) _self;
  struct mspack_system *sys;
  struct mspack_file *infh = NULL;
  struct mspack_file *basefh = NULL;
  struct mspack_file *outfh = NULL;
  unsigned char *buf = NULL;
  unsigned char hdrbuf[patchhead_SIZEOF];
  unsigned int block_max, target_size;
  struct lzxd_stream *lzx = NULL;
  struct mspack_system oabd_sys;
  struct oabd_file in_ofh, out_ofh;
  unsigned int window_bits, window_size;
  int ret = MSPACK_ERR_OK;

  if (!self) return MSPACK_ERR_ARGS;
  sys = self->system;

  infh = sys->open(sys, input, MSPACK_SYS_OPEN_READ);
  if (!infh) {
    ret = MSPACK_ERR_OPEN;
    goto out;
  }

  if (sys->read(infh, hdrbuf, patchhead_SIZEOF) != patchhead_SIZEOF) {
    ret = MSPACK_ERR_READ;
    goto out;
  }

  if (EndGetI32(&hdrbuf[patchhead_VersionHi]) != 3 ||
      EndGetI32(&hdrbuf[patchhead_VersionLo]) != 2) {
    ret = MSPACK_ERR_SIGNATURE;
    goto out;
  }

  block_max = EndGetI32(&hdrbuf[patchhead_BlockMax]);
  target_size = EndGetI32(&hdrbuf[patchhead_TargetSize]);

  /* We use it for reading block headers too */
  if (block_max < patchblk_SIZEOF)
    block_max = patchblk_SIZEOF;

  basefh = sys->open(sys, base, MSPACK_SYS_OPEN_READ);
  if (!basefh) {
    ret = MSPACK_ERR_OPEN;
    goto out;
  }

  outfh = sys->open(sys, output, MSPACK_SYS_OPEN_WRITE);
  if (!outfh) {
    ret = MSPACK_ERR_OPEN;
    goto out;
  }

  buf = sys->alloc(sys, block_max);
  if (!buf) {
    ret = MSPACK_ERR_NOMEMORY;
    goto out;
  }

  oabd_sys = *sys;
  oabd_sys.read = oabd_sys_read;
  oabd_sys.write = oabd_sys_write;

  in_ofh.orig_sys = sys;
  in_ofh.orig_file = infh;

  out_ofh.orig_sys = sys;
  out_ofh.orig_file = outfh;

  while (target_size) {
    unsigned int blk_csize, blk_dsize, blk_ssize, blk_crc;

    if (sys->read(infh, buf, patchblk_SIZEOF) != patchblk_SIZEOF) {
      ret = MSPACK_ERR_READ;
      goto out;
    }
    blk_csize = EndGetI32(&buf[patchblk_PatchSize]);
    blk_dsize = EndGetI32(&buf[patchblk_TargetSize]);
    blk_ssize = EndGetI32(&buf[patchblk_SourceSize]);
    blk_crc   = EndGetI32(&buf[patchblk_CRC]);

    if (blk_dsize > block_max || blk_dsize > target_size ||
	blk_ssize > block_max) {
      ret = MSPACK_ERR_DATAFORMAT;
      goto out;
    }


    window_size = (blk_ssize + 32767) & ~32767;
    window_size += blk_dsize;
    window_bits = 17;

    while (window_bits < 25 && (1U << window_bits) < window_size)
      window_bits++;

    in_ofh.available = blk_csize;
    out_ofh.crc = 0xffffffff;

    lzx = lzxd_init(&oabd_sys, (void *)&in_ofh, (void *)&out_ofh, window_bits,
		    0, 4096, blk_dsize, 1);
    if (!lzx) {
      ret = MSPACK_ERR_NOMEMORY;
      goto out;
    }
    ret = lzxd_set_reference_data(lzx, sys, basefh, blk_ssize);
    if (ret != MSPACK_ERR_OK)
      goto out;

    ret = lzxd_decompress(lzx, blk_dsize);
    if (ret != MSPACK_ERR_OK)
      goto out;

    lzxd_free(lzx);
    lzx = NULL;

    /* Consume any trailing padding bytes before the next block */
    while (in_ofh.available) {
      int count = block_max;
      if ((size_t)count > in_ofh.available)
	count = in_ofh.available;

      count = sys->read(infh, buf, count);
      if (count < 0) {
	ret = MSPACK_ERR_READ;
	goto out;
      }
      in_ofh.available -= count;
    }

    if (out_ofh.crc != blk_crc) {
      ret = MSPACK_ERR_CHECKSUM;
      goto out;
    }

    target_size -= blk_dsize;
  }

 out:
  if (lzx) lzxd_free(lzx);
  if (outfh) sys->close(outfh);
  if (basefh) sys->close(basefh);
  if (infh) sys->close(infh);
  sys->free(buf);

  return ret;
}
