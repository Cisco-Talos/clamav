/* This file is part of libmspack.
 * (C) 2003-2010 Stuart Caie.
 *
 * SZDD is a format used in the MS-DOS commands COMPRESS.EXE and
 * EXPAND.EXE. The compression method is attributed to Steven Zeck,
 * however it's pretty much identical to LZSS.
 *
 * libmspack is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License (LGPL) version 2.1
 *
 * For further details, see the file COPYING.LIB distributed with libmspack
 */

/* SZDD decompression implementation */

#include <system.h>
#include <szdd.h>

/* prototypes */
static struct msszddd_header *szddd_open(
    struct msszdd_decompressor *base, const char *filename);
static void szddd_close(
    struct msszdd_decompressor *base, struct msszddd_header *hdr);
static int szddd_read_headers(
    struct mspack_system *sys, struct mspack_file *fh,
    struct msszddd_header *hdr);
static int szddd_extract(
    struct msszdd_decompressor *base, struct msszddd_header *hdr,
    const char *filename);
static int szddd_decompress(
    struct msszdd_decompressor *base, const char *input, const char *output);
static int szddd_error(
    struct msszdd_decompressor *base);

/***************************************
 * MSPACK_CREATE_SZDD_DECOMPRESSOR
 ***************************************
 * constructor
 */
struct msszdd_decompressor *
    mspack_create_szdd_decompressor(struct mspack_system *sys)
{
  struct msszdd_decompressor_p *self = NULL;

  if (!sys) sys = mspack_default_system;
  if (!mspack_valid_system(sys)) return NULL;

  if ((self = (struct msszdd_decompressor_p *) sys->alloc(sys, sizeof(struct msszdd_decompressor_p)))) {
    self->base.open       = &szddd_open;
    self->base.close      = &szddd_close;
    self->base.extract    = &szddd_extract;
    self->base.decompress = &szddd_decompress;
    self->base.last_error = &szddd_error;
    self->system          = sys;
    self->error           = MSPACK_ERR_OK;
  }
  return (struct msszdd_decompressor *) self;
}

/***************************************
 * MSPACK_DESTROY_SZDD_DECOMPRESSOR
 ***************************************
 * destructor
 */
void mspack_destroy_szdd_decompressor(struct msszdd_decompressor *base)
{
    struct msszdd_decompressor_p *self = (struct msszdd_decompressor_p *) base;
    if (self) {
        struct mspack_system *sys = self->system;
        sys->free(self);
    }
}

/***************************************
 * SZDDD_OPEN
 ***************************************
 * opens an SZDD file without decompressing, reads header
 */
static struct msszddd_header *szddd_open(struct msszdd_decompressor *base,
                                         const char *filename)
{
    struct msszdd_decompressor_p *self = (struct msszdd_decompressor_p *) base;
    struct msszddd_header *hdr;
    struct mspack_system *sys;
    struct mspack_file *fh;

    if (!self) return NULL;
    sys = self->system;

    fh  = sys->open(sys, filename, MSPACK_SYS_OPEN_READ);
    hdr = (struct msszddd_header *) sys->alloc(sys, sizeof(struct msszddd_header_p));
    if (fh && hdr) {
        ((struct msszddd_header_p *) hdr)->fh = fh;
        self->error = szddd_read_headers(sys, fh, hdr);
    }
    else {
        if (!fh)  self->error = MSPACK_ERR_OPEN;
        if (!hdr) self->error = MSPACK_ERR_NOMEMORY;
    }
    
    if (self->error) {
        if (fh) sys->close(fh);
        sys->free(hdr);
        hdr = NULL;
    }

    return hdr;
}

/***************************************
 * SZDDD_CLOSE
 ***************************************
 * closes an SZDD file
 */
static void szddd_close(struct msszdd_decompressor *base,
                        struct msszddd_header *hdr)
{
    struct msszdd_decompressor_p *self = (struct msszdd_decompressor_p *) base;
    struct msszddd_header_p *hdr_p = (struct msszddd_header_p *) hdr;

    if (!self || !self->system) return;

    /* close the file handle associated */
    self->system->close(hdr_p->fh);

    /* free the memory associated */
    self->system->free(hdr);

    self->error = MSPACK_ERR_OK;
}

/***************************************
 * SZDDD_READ_HEADERS
 ***************************************
 * reads the headers of an SZDD format file
 */
static unsigned char szdd_signature_expand[8] = {
    0x53, 0x5A, 0x44, 0x44, 0x88, 0xF0, 0x27, 0x33
};
static unsigned char szdd_signature_qbasic[8] = {
    0x53, 0x5A, 0x20, 0x88, 0xF0, 0x27, 0x33, 0xD1
};

static int szddd_read_headers(struct mspack_system *sys,
                              struct mspack_file *fh,
                              struct msszddd_header *hdr)
{
    unsigned char buf[8];

    /* read and check signature */
    if (sys->read(fh, buf, 8) != 8) return MSPACK_ERR_READ;

    if ((memcmp(buf, szdd_signature_expand, 8) == 0)) {
        /* common SZDD */
        hdr->format = MSSZDD_FMT_NORMAL;

        /* read the rest of the header */
        if (sys->read(fh, buf, 6) != 6) return MSPACK_ERR_READ;
        if (buf[0] != 0x41) return MSPACK_ERR_DATAFORMAT;
        hdr->missing_char = buf[1];
        hdr->length = EndGetI32(&buf[2]);
    }
    else if ((memcmp(buf, szdd_signature_qbasic, 8) == 0)) {
        /* special QBasic SZDD */
        hdr->format = MSSZDD_FMT_QBASIC;
        if (sys->read(fh, buf, 4) != 4) return MSPACK_ERR_READ;
        hdr->missing_char = '\0';
        hdr->length = EndGetI32(buf);
    }
    else {
        return MSPACK_ERR_SIGNATURE;
    }
    return MSPACK_ERR_OK;
}

/***************************************
 * SZDDD_EXTRACT
 ***************************************
 * decompresses an SZDD file
 */
static int szddd_extract(struct msszdd_decompressor *base,
                         struct msszddd_header *hdr, const char *filename)
{
    struct msszdd_decompressor_p *self = (struct msszdd_decompressor_p *) base;
    struct mspack_file *fh, *outfh;
    struct mspack_system *sys;
    off_t data_offset;

    if (!self) return MSPACK_ERR_ARGS;
    if (!hdr)  return self->error = MSPACK_ERR_ARGS;
    sys = self->system;

    fh = ((struct msszddd_header_p *) hdr)->fh;

    /* seek to the compressed data */
    data_offset = (hdr->format == MSSZDD_FMT_NORMAL) ? 14 : 12;
    if (sys->seek(fh, data_offset, MSPACK_SYS_SEEK_START)) {
        return self->error = MSPACK_ERR_SEEK;
    }

    /* open file for output */
    if (!(outfh = sys->open(sys, filename, MSPACK_SYS_OPEN_WRITE))) {
        return self->error = MSPACK_ERR_OPEN;
    }

    /* decompress the data */
    self->error = lzss_decompress(sys, fh, outfh, SZDD_INPUT_SIZE,
                                  hdr->format == MSSZDD_FMT_NORMAL
                                  ? LZSS_MODE_EXPAND
                                  : LZSS_MODE_QBASIC);

    /* close output file */
    sys->close(outfh);

    return self->error;
}

/***************************************
 * SZDDD_DECOMPRESS
 ***************************************
 * unpacks directly from input to output
 */
static int szddd_decompress(struct msszdd_decompressor *base,
                            const char *input, const char *output)
{
    struct msszdd_decompressor_p *self = (struct msszdd_decompressor_p *) base;
    struct msszddd_header *hdr;
    int error;

    if (!self) return MSPACK_ERR_ARGS;

    if (!(hdr = szddd_open(base, input))) return self->error;
    error = szddd_extract(base, hdr, output);
    szddd_close(base, hdr);
    return self->error = error;
}

/***************************************
 * SZDDD_ERROR
 ***************************************
 * returns the last error that occurred
 */
static int szddd_error(struct msszdd_decompressor *base)
{
    struct msszdd_decompressor_p *self = (struct msszdd_decompressor_p *) base;
    return (self) ? self->error : MSPACK_ERR_ARGS;
}
