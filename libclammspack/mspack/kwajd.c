/* This file is part of libmspack.
 * (C) 2003-2011 Stuart Caie.
 *
 * KWAJ is a format very similar to SZDD. KWAJ method 3 (LZH) was
 * written by Jeff Johnson.
 *
 * libmspack is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License (LGPL) version 2.1
 *
 * For further details, see the file COPYING.LIB distributed with libmspack
 */

/* KWAJ decompression implementation */

#include <system.h>
#include <kwaj.h>
#include <mszip.h>

/* prototypes */
static struct mskwajd_header *kwajd_open(
    struct mskwaj_decompressor *base, const char *filename);
static void kwajd_close(
    struct mskwaj_decompressor *base, struct mskwajd_header *hdr);
static int kwajd_read_headers(
    struct mspack_system *sys, struct mspack_file *fh,
    struct mskwajd_header *hdr);
static int kwajd_extract(
    struct mskwaj_decompressor *base, struct mskwajd_header *hdr,
    const char *filename);
static int kwajd_decompress(
    struct mskwaj_decompressor *base, const char *input, const char *output);
static int kwajd_error(
    struct mskwaj_decompressor *base);

static struct kwajd_stream *lzh_init(
    struct mspack_system *sys, struct mspack_file *in, struct mspack_file *out);
static int lzh_decompress(
    struct kwajd_stream *kwaj);
static void lzh_free(
    struct kwajd_stream *kwaj);
static int lzh_read_lens(
    struct kwajd_stream *kwaj,
    unsigned int type, unsigned int numsyms,
    unsigned char *lens);
static int lzh_read_input(
    struct kwajd_stream *kwaj);


/***************************************
 * MSPACK_CREATE_KWAJ_DECOMPRESSOR
 ***************************************
 * constructor
 */
struct mskwaj_decompressor *
    mspack_create_kwaj_decompressor(struct mspack_system *sys)
{
  struct mskwaj_decompressor_p *self = NULL;

  if (!sys) sys = mspack_default_system;
  if (!mspack_valid_system(sys)) return NULL;

  if ((self = (struct mskwaj_decompressor_p *) sys->alloc(sys, sizeof(struct mskwaj_decompressor_p)))) {
    self->base.open       = &kwajd_open;
    self->base.close      = &kwajd_close;
    self->base.extract    = &kwajd_extract;
    self->base.decompress = &kwajd_decompress;
    self->base.last_error = &kwajd_error;
    self->system          = sys;
    self->error           = MSPACK_ERR_OK;
  }
  return (struct mskwaj_decompressor *) self;
}

/***************************************
 * MSPACK_DESTROY_KWAJ_DECOMPRESSOR
 ***************************************
 * destructor
 */
void mspack_destroy_kwaj_decompressor(struct mskwaj_decompressor *base)
{
    struct mskwaj_decompressor_p *self = (struct mskwaj_decompressor_p *) base;
    if (self) {
        struct mspack_system *sys = self->system;
        sys->free(self);
    }
}

/***************************************
 * KWAJD_OPEN
 ***************************************
 * opens a KWAJ file without decompressing, reads header
 */
static struct mskwajd_header *kwajd_open(struct mskwaj_decompressor *base,
                                         const char *filename)
{
    struct mskwaj_decompressor_p *self = (struct mskwaj_decompressor_p *) base;
    struct mskwajd_header *hdr;
    struct mspack_system *sys;
    struct mspack_file *fh;

    if (!self) return NULL;
    sys = self->system;

    fh  = sys->open(sys, filename, MSPACK_SYS_OPEN_READ);
    hdr = (struct mskwajd_header *) sys->alloc(sys, sizeof(struct mskwajd_header_p));
    if (fh && hdr) {
        ((struct mskwajd_header_p *) hdr)->fh = fh;
        self->error = kwajd_read_headers(sys, fh, hdr);
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
 * KWAJD_CLOSE
 ***************************************
 * closes a KWAJ file
 */
static void kwajd_close(struct mskwaj_decompressor *base,
                        struct mskwajd_header *hdr)
{
    struct mskwaj_decompressor_p *self = (struct mskwaj_decompressor_p *) base;
    struct mskwajd_header_p *hdr_p = (struct mskwajd_header_p *) hdr;

    if (!self || !self->system) return;

    /* close the file handle associated */
    self->system->close(hdr_p->fh);

    /* free the memory associated */
    self->system->free(hdr);

    self->error = MSPACK_ERR_OK;
}

/***************************************
 * KWAJD_READ_HEADERS
 ***************************************
 * reads the headers of a KWAJ format file
 */
static int kwajd_read_headers(struct mspack_system *sys,
                              struct mspack_file *fh,
                              struct mskwajd_header *hdr)
{
    unsigned char buf[16];
    int i;

    /* read in the header */
    if (sys->read(fh, &buf[0], kwajh_SIZEOF) != kwajh_SIZEOF) {
        return MSPACK_ERR_READ;
    }

    /* check for "KWAJ" signature */
    if (((unsigned int) EndGetI32(&buf[kwajh_Signature1]) != 0x4A41574B) ||
        ((unsigned int) EndGetI32(&buf[kwajh_Signature2]) != 0xD127F088))
    {
        return MSPACK_ERR_SIGNATURE;
    }

    /* basic header fields */
    hdr->comp_type    = EndGetI16(&buf[kwajh_CompMethod]);
    hdr->data_offset  = EndGetI16(&buf[kwajh_DataOffset]);
    hdr->headers      = EndGetI16(&buf[kwajh_Flags]);
    hdr->length       = 0;
    hdr->filename     = NULL;
    hdr->extra        = NULL;
    hdr->extra_length = 0;

    /* optional headers */

    /* 4 bytes: length of unpacked file */
    if (hdr->headers & MSKWAJ_HDR_HASLENGTH) {
        if (sys->read(fh, &buf[0], 4) != 4) return MSPACK_ERR_READ;
        hdr->length = EndGetI32(&buf[0]);
    }

    /* 2 bytes: unknown purpose */
    if (hdr->headers & MSKWAJ_HDR_HASUNKNOWN1) {
        if (sys->read(fh, &buf[0], 2) != 2) return MSPACK_ERR_READ;
    }

    /* 2 bytes: length of section, then [length] bytes: unknown purpose */
    if (hdr->headers & MSKWAJ_HDR_HASUNKNOWN2) {
        if (sys->read(fh, &buf[0], 2) != 2) return MSPACK_ERR_READ;
        i = EndGetI16(&buf[0]);
        if (sys->seek(fh, (off_t)i, MSPACK_SYS_SEEK_CUR)) return MSPACK_ERR_SEEK;
    }

    /* filename and extension */
    if (hdr->headers & (MSKWAJ_HDR_HASFILENAME | MSKWAJ_HDR_HASFILEEXT)) {
        int len;
        /* allocate memory for maximum length filename */
        char *fn = (char *) sys->alloc(sys, (size_t) 13);
        if (!(hdr->filename = fn)) return MSPACK_ERR_NOMEMORY;

        /* copy filename if present */
        if (hdr->headers & MSKWAJ_HDR_HASFILENAME) {
            /* read and copy up to 9 bytes of a null terminated string */
            if ((len = sys->read(fh, &buf[0], 9)) < 2) return MSPACK_ERR_READ;
            for (i = 0; i < len; i++) if (!(*fn++ = buf[i])) break;
            /* if string was 9 bytes with no null terminator, reject it */
            if (i == 9 && buf[8] != '\0') return MSPACK_ERR_DATAFORMAT;
            /* seek to byte after string ended in file */
            if (sys->seek(fh, (off_t)(i + 1 - len), MSPACK_SYS_SEEK_CUR))
                return MSPACK_ERR_SEEK;
            fn--; /* remove the null terminator */
        }

        /* copy extension if present */
        if (hdr->headers & MSKWAJ_HDR_HASFILEEXT) {
            *fn++ = '.';
            /* read and copy up to 4 bytes of a null terminated string */
            if ((len = sys->read(fh, &buf[0], 4)) < 2) return MSPACK_ERR_READ;
            for (i = 0; i < len; i++) if (!(*fn++ = buf[i])) break;
            /* if string was 4 bytes with no null terminator, reject it */
            if (i == 4 && buf[3] != '\0') return MSPACK_ERR_DATAFORMAT;
            /* seek to byte after string ended in file */
            if (sys->seek(fh, (off_t)(i + 1 - len), MSPACK_SYS_SEEK_CUR))
                return MSPACK_ERR_SEEK;
            fn--; /* remove the null terminator */
        }
        *fn = '\0';
    }

    /* 2 bytes: extra text length then [length] bytes of extra text data */
    if (hdr->headers & MSKWAJ_HDR_HASEXTRATEXT) {
        if (sys->read(fh, &buf[0], 2) != 2) return MSPACK_ERR_READ;
        i = EndGetI16(&buf[0]);
        hdr->extra = (char *) sys->alloc(sys, (size_t)i+1);
        if (! hdr->extra) return MSPACK_ERR_NOMEMORY;
        if (sys->read(fh, hdr->extra, i) != i) return MSPACK_ERR_READ;
        hdr->extra[i] = '\0';
        hdr->extra_length = i;
    }
    return MSPACK_ERR_OK;
}

/***************************************
 * KWAJD_EXTRACT
 ***************************************
 * decompresses a KWAJ file
 */
static int kwajd_extract(struct mskwaj_decompressor *base,
                         struct mskwajd_header *hdr, const char *filename)
{
    struct mskwaj_decompressor_p *self = (struct mskwaj_decompressor_p *) base;
    struct mspack_system *sys;
    struct mspack_file *fh, *outfh;

    if (!self) return MSPACK_ERR_ARGS;
    if (!hdr) return self->error = MSPACK_ERR_ARGS;

    sys = self->system;
    fh = ((struct mskwajd_header_p *) hdr)->fh;

    /* seek to the compressed data */
    if (sys->seek(fh, hdr->data_offset, MSPACK_SYS_SEEK_START)) {
        return self->error = MSPACK_ERR_SEEK;
    }

    /* open file for output */
    if (!(outfh = sys->open(sys, filename, MSPACK_SYS_OPEN_WRITE))) {
        return self->error = MSPACK_ERR_OPEN;
    }

    self->error = MSPACK_ERR_OK;

    /* decompress based on format */
    if (hdr->comp_type == MSKWAJ_COMP_NONE ||
        hdr->comp_type == MSKWAJ_COMP_XOR)
    {
        /* NONE is a straight copy. XOR is a copy xored with 0xFF */
        unsigned char *buf = (unsigned char *) sys->alloc(sys, (size_t) KWAJ_INPUT_SIZE);
        if (buf) {
            int read, i;
            while ((read = sys->read(fh, buf, KWAJ_INPUT_SIZE)) > 0) {
                if (hdr->comp_type == MSKWAJ_COMP_XOR) {
                    for (i = 0; i < read; i++) buf[i] ^= 0xFF;
                }
                if (sys->write(outfh, buf, read) != read) {
                    self->error = MSPACK_ERR_WRITE;
                    break;
                }
            }
            if (read < 0) self->error = MSPACK_ERR_READ;
            sys->free(buf);
        }
        else {
            self->error = MSPACK_ERR_NOMEMORY;
        }
    }
    else if (hdr->comp_type == MSKWAJ_COMP_SZDD) {
        self->error = lzss_decompress(sys, fh, outfh, KWAJ_INPUT_SIZE,
                                      LZSS_MODE_EXPAND);
    }
    else if (hdr->comp_type == MSKWAJ_COMP_LZH) {
        struct kwajd_stream *lzh = lzh_init(sys, fh, outfh);
        self->error = (lzh) ? lzh_decompress(lzh) : MSPACK_ERR_NOMEMORY;
        lzh_free(lzh);
    }
    else if (hdr->comp_type == MSKWAJ_COMP_MSZIP) {
        struct mszipd_stream *zip = mszipd_init(sys,fh,outfh,KWAJ_INPUT_SIZE,0);
        self->error = (zip) ? mszipd_decompress_kwaj(zip) : MSPACK_ERR_NOMEMORY;
        mszipd_free(zip);
    }
    else {
        self->error = MSPACK_ERR_DATAFORMAT;
    }

    /* close output file */
    sys->close(outfh);

    return self->error;
}

/***************************************
 * KWAJD_DECOMPRESS
 ***************************************
 * unpacks directly from input to output
 */
static int kwajd_decompress(struct mskwaj_decompressor *base,
                            const char *input, const char *output)
{
    struct mskwaj_decompressor_p *self = (struct mskwaj_decompressor_p *) base;
    struct mskwajd_header *hdr;
    int error;

    if (!self) return MSPACK_ERR_ARGS;

    if (!(hdr = kwajd_open(base, input))) return self->error;
    error = kwajd_extract(base, hdr, output);
    kwajd_close(base, hdr);
    return self->error = error;
}

/***************************************
 * KWAJD_ERROR
 ***************************************
 * returns the last error that occurred
 */
static int kwajd_error(struct mskwaj_decompressor *base)
{
    struct mskwaj_decompressor_p *self = (struct mskwaj_decompressor_p *) base;
    return (self) ? self->error : MSPACK_ERR_ARGS;
}

/***************************************
 * LZH_INIT, LZH_DECOMPRESS, LZH_FREE
 ***************************************
 * unpacks KWAJ method 3 files
 */

/* import bit-reading macros and code */
#define BITS_TYPE struct kwajd_stream
#define BITS_VAR lzh
#define BITS_ORDER_MSB
#define BITS_NO_READ_INPUT
#define READ_BYTES do {                                 \
    if (i_ptr >= i_end) {                               \
        if ((err = lzh_read_input(lzh))) return err;    \
        i_ptr = lzh->i_ptr;                             \
        i_end = lzh->i_end;                             \
    }                                                   \
    INJECT_BITS(*i_ptr++, 8);                           \
} while (0)
#include <readbits.h>

/* import huffman-reading macros and code */
#define TABLEBITS(tbl)      KWAJ_TABLEBITS
#define MAXSYMBOLS(tbl)     KWAJ_##tbl##_SYMS
#define HUFF_TABLE(tbl,idx) lzh->tbl##_table[idx]
#define HUFF_LEN(tbl,idx)   lzh->tbl##_len[idx]
#define HUFF_ERROR          return MSPACK_ERR_DATAFORMAT
#include <readhuff.h>

/* In the KWAJ LZH format, there is no special 'eof' marker, it just
 * ends. Depending on how many bits are left in the final byte when
 * the stream ends, that might be enough to start another literal or
 * match. The only easy way to detect that we've come to an end is to
 * guard all bit-reading. We allow fake bits to be read once we reach
 * the end of the stream, but we check if we then consumed any of
 * those fake bits, after doing the READ_BITS / READ_HUFFSYM. This
 * isn't how the default readbits.h read_input() works (it simply lets
 * 2 fake bytes in then stops), so we implement our own.
 */
#define READ_BITS_SAFE(val, n) do {                     \
    READ_BITS(val, n);                                  \
    if (lzh->input_end && bits_left < lzh->input_end)   \
        return MSPACK_ERR_OK;                           \
} while (0)

#define READ_HUFFSYM_SAFE(tbl, val) do {                \
    READ_HUFFSYM(tbl, val);                             \
    if (lzh->input_end && bits_left < lzh->input_end)   \
        return MSPACK_ERR_OK;                           \
} while (0)

#define BUILD_TREE(tbl, type)                                           \
    STORE_BITS;                                                         \
    err = lzh_read_lens(lzh, type, MAXSYMBOLS(tbl), &HUFF_LEN(tbl,0));  \
    if (err) return err;                                                \
    RESTORE_BITS;                                                       \
    if (make_decode_table(MAXSYMBOLS(tbl), TABLEBITS(tbl),              \
        &HUFF_LEN(tbl,0), &HUFF_TABLE(tbl,0)))                          \
        return MSPACK_ERR_DATAFORMAT;

#define WRITE_BYTE do {                                                 \
    if (lzh->sys->write(lzh->output, &lzh->window[pos], 1) != 1)        \
        return MSPACK_ERR_WRITE;                                        \
} while (0)

static struct kwajd_stream *lzh_init(struct mspack_system *sys,
    struct mspack_file *in, struct mspack_file *out)
{
    struct kwajd_stream *lzh;

    if (!sys || !in || !out) return NULL;
    if (!(lzh = (struct kwajd_stream *) sys->alloc(sys, sizeof(struct kwajd_stream)))) return NULL;

    lzh->sys    = sys;
    lzh->input  = in;
    lzh->output = out;
    return lzh;
}

static int lzh_decompress(struct kwajd_stream *lzh)
{
    register unsigned int bit_buffer;
    register int bits_left, i;
    register unsigned short sym;
    unsigned char *i_ptr, *i_end, lit_run = 0;
    int j, pos = 0, len, offset, err;
    unsigned int types[6];

    /* reset global state */
    INIT_BITS;
    RESTORE_BITS;
    memset(&lzh->window[0], LZSS_WINDOW_FILL, (size_t) LZSS_WINDOW_SIZE);

    /* read 6 encoding types (for byte alignment) but only 5 are needed */
    for (i = 0; i < 6; i++) READ_BITS_SAFE(types[i], 4);

    /* read huffman table symbol lengths and build huffman trees */
    BUILD_TREE(MATCHLEN1, types[0]);
    BUILD_TREE(MATCHLEN2, types[1]);
    BUILD_TREE(LITLEN,    types[2]);
    BUILD_TREE(OFFSET,    types[3]);
    BUILD_TREE(LITERAL,   types[4]);

    while (!lzh->input_end) {
        if (lit_run) READ_HUFFSYM_SAFE(MATCHLEN2, len);
        else         READ_HUFFSYM_SAFE(MATCHLEN1, len);

        if (len > 0) {
            len += 2;
            lit_run = 0; /* not the end of a literal run */
            READ_HUFFSYM_SAFE(OFFSET, j); offset = j << 6;
            READ_BITS_SAFE(j, 6);         offset |= j;

            /* copy match as output and into the ring buffer */
            while (len-- > 0) {
                lzh->window[pos] = lzh->window[(pos+4096-offset) & 4095];
                WRITE_BYTE;
                pos++; pos &= 4095;
            }
        }
        else {
            READ_HUFFSYM_SAFE(LITLEN, len); len++;
            lit_run = (len == 32) ? 0 : 1; /* end of a literal run? */
            while (len-- > 0) {
                READ_HUFFSYM_SAFE(LITERAL, j);
                /* copy as output and into the ring buffer */
                lzh->window[pos] = j;
                WRITE_BYTE;
                pos++; pos &= 4095;
            }
        }
    }
    return MSPACK_ERR_OK;
}

static void lzh_free(struct kwajd_stream *lzh)
{
    struct mspack_system *sys;
    if (!lzh || !lzh->sys) return;
    sys = lzh->sys;
    sys->free(lzh);
}

static int lzh_read_lens(struct kwajd_stream *lzh,
                         unsigned int type, unsigned int numsyms,
                         unsigned char *lens)
{
    register unsigned int bit_buffer;
    register int bits_left;
    unsigned char *i_ptr, *i_end;
    unsigned int i, c, sel;
    int err;

    RESTORE_BITS;
    switch (type) {
    case 0:
        i = numsyms; c = (i==16)?4: (i==32)?5: (i==64)?6: (i==256)?8 :0;
        for (i = 0; i < numsyms; i++) lens[i] = c;
        break;

    case 1:
        READ_BITS_SAFE(c, 4); lens[0] = c;
        for (i = 1; i < numsyms; i++) {
                   READ_BITS_SAFE(sel, 1); if (sel == 0)  lens[i] = c;
            else { READ_BITS_SAFE(sel, 1); if (sel == 0)  lens[i] = ++c;
            else { READ_BITS_SAFE(c, 4);                  lens[i] = c; }}
        }
        break;

    case 2:
        READ_BITS_SAFE(c, 4); lens[0] = c;
        for (i = 1; i < numsyms; i++) {
            READ_BITS_SAFE(sel, 2);
            if (sel == 3) READ_BITS_SAFE(c, 4); else c += (char) sel-1;
            lens[i] = c;
        }
        break;

    case 3:
        for (i = 0; i < numsyms; i++) {
            READ_BITS_SAFE(c, 4); lens[i] = c;
        }
        break;
    }
    STORE_BITS;
    return MSPACK_ERR_OK;
}

static int lzh_read_input(struct kwajd_stream *lzh) {
    int read;
    if (lzh->input_end) {
        lzh->input_end += 8;
        lzh->inbuf[0] = 0;
        read = 1;
    }
    else {
        read = lzh->sys->read(lzh->input, &lzh->inbuf[0], KWAJ_INPUT_SIZE);
        if (read < 0) return MSPACK_ERR_READ;
        if (read == 0) {
            lzh->input_end = 8;
            lzh->inbuf[0] = 0;
            read = 1;
        }
    }

    /* update i_ptr and i_end */
    lzh->i_ptr = &lzh->inbuf[0];
    lzh->i_end = &lzh->inbuf[read];
    return MSPACK_ERR_OK;
}
