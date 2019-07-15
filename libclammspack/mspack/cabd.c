/* This file is part of libmspack.
 * (C) 2003-2018 Stuart Caie.
 *
 * libmspack is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License (LGPL) version 2.1
 *
 * For further details, see the file COPYING.LIB distributed with libmspack
 */

/* Cabinet (.CAB) files are a form of file archive. Each cabinet contains
 * "folders", which are compressed spans of data. Each cabinet has
 * "files", whose metadata is in the cabinet header, but whose actual data
 * is stored compressed in one of the "folders". Cabinets can span more
 * than one physical file on disk, in which case they are a "cabinet set",
 * and usually the last folder of each cabinet extends into the next
 * cabinet.
 *
 * For a complete description of the format, see the MSDN site:
 *   http://msdn.microsoft.com/en-us/library/bb267310.aspx
 */

/* CAB decompression implementation */

#include <system.h>
#include <cab.h>
#include <mszip.h>
#include <lzx.h>
#include <qtm.h>

/* Notes on compliance with cabinet specification:
 *
 * One of the main changes between cabextract 0.6 and libmspack's cab
 * decompressor is the move from block-oriented decompression to
 * stream-oriented decompression.
 *
 * cabextract would read one data block from disk, decompress it with the
 * appropriate method, then write the decompressed data. The CAB
 * specification is specifically designed to work like this, as it ensures
 * compression matches do not span the maximum decompressed block size
 * limit of 32kb.
 *
 * However, the compression algorithms used are stream oriented, with
 * specific hacks added to them to enforce the "individual 32kb blocks"
 * rule in CABs. In other file formats, they do not have this limitation.
 *
 * In order to make more generalised decompressors, libmspack's CAB
 * decompressor has moved from being block-oriented to more stream
 * oriented. This also makes decompression slightly faster.
 *
 * However, this leads to incompliance with the CAB specification. The
 * CAB controller can no longer ensure each block of input given to the
 * decompressors is matched with their output. The "decompressed size" of
 * each individual block is thrown away.
 *
 * Each CAB block is supposed to be seen as individually compressed. This
 * means each consecutive data block can have completely different
 * "uncompressed" sizes, ranging from 1 to 32768 bytes. However, in
 * reality, all data blocks in a folder decompress to exactly 32768 bytes,
 * excepting the final block. 
 *
 * Given this situation, the decompression algorithms are designed to
 * realign their input bitstreams on 32768 output-byte boundaries, and
 * various other special cases have been made. libmspack will not
 * correctly decompress LZX or Quantum compressed folders where the blocks
 * do not follow this "32768 bytes until last block" pattern. It could be
 * implemented if needed, but hopefully this is not necessary -- it has
 * not been seen in over 3Gb of CAB archives.
 */

/* prototypes */
static struct mscabd_cabinet * cabd_open(
  struct mscab_decompressor *base, const char *filename);
static void cabd_close(
  struct mscab_decompressor *base, struct mscabd_cabinet *origcab);
static int cabd_read_headers(
  struct mspack_system *sys, struct mspack_file *fh,
  struct mscabd_cabinet_p *cab, off_t offset, int salvage, int quiet);
static char *cabd_read_string(
  struct mspack_system *sys, struct mspack_file *fh, int *error);

static struct mscabd_cabinet *cabd_search(
  struct mscab_decompressor *base, const char *filename);
static int cabd_find(
  struct mscab_decompressor_p *self, unsigned char *buf,
  struct mspack_file *fh, const char *filename, off_t flen,
  off_t *firstlen, struct mscabd_cabinet_p **firstcab);

static int cabd_prepend(
  struct mscab_decompressor *base, struct mscabd_cabinet *cab,
  struct mscabd_cabinet *prevcab);
static int cabd_append(
  struct mscab_decompressor *base, struct mscabd_cabinet *cab,
  struct mscabd_cabinet *nextcab);
static int cabd_merge(
  struct mscab_decompressor *base, struct mscabd_cabinet *lcab,
  struct mscabd_cabinet *rcab);
static int cabd_can_merge_folders(
  struct mspack_system *sys, struct mscabd_folder_p *lfol,
  struct mscabd_folder_p *rfol);

static int cabd_extract(
  struct mscab_decompressor *base, struct mscabd_file *file,
  const char *filename);
static int cabd_init_decomp(
  struct mscab_decompressor_p *self, unsigned int ct);
static void cabd_free_decomp(
  struct mscab_decompressor_p *self);
static int cabd_sys_read(
  struct mspack_file *file, void *buffer, int bytes);
static int cabd_sys_write(
  struct mspack_file *file, void *buffer, int bytes);
static int cabd_sys_read_block(
  struct mspack_system *sys, struct mscabd_decompress_state *d, int *out,
  int ignore_cksum, int ignore_blocksize);
static unsigned int cabd_checksum(
  unsigned char *data, unsigned int bytes, unsigned int cksum);
static struct noned_state *noned_init(
  struct mspack_system *sys, struct mspack_file *in, struct mspack_file *out,
  int bufsize);

static int noned_decompress(
  struct noned_state *s, off_t bytes);
static void noned_free(
  struct noned_state *state);

static int cabd_param(
  struct mscab_decompressor *base, int param, int value);

static int cabd_error(
  struct mscab_decompressor *base);


/***************************************
 * MSPACK_CREATE_CAB_DECOMPRESSOR
 ***************************************
 * constructor
 */
struct mscab_decompressor *
  mspack_create_cab_decompressor(struct mspack_system *sys)
{
  struct mscab_decompressor_p *self = NULL;

  if (!sys) sys = mspack_default_system;
  if (!mspack_valid_system(sys)) return NULL;

  if ((self = (struct mscab_decompressor_p *) sys->alloc(sys, sizeof(struct mscab_decompressor_p)))) {
    self->base.open       = &cabd_open;
    self->base.close      = &cabd_close;
    self->base.search     = &cabd_search;
    self->base.extract    = &cabd_extract;
    self->base.prepend    = &cabd_prepend;
    self->base.append     = &cabd_append;
    self->base.set_param  = &cabd_param;
    self->base.last_error = &cabd_error;
    self->system          = sys;
    self->d               = NULL;
    self->error           = MSPACK_ERR_OK;

    self->searchbuf_size  = 32768;
    self->fix_mszip       = 0;
    self->buf_size        = 4096;
    self->salvage         = 0;
  }
  return (struct mscab_decompressor *) self;
}

/***************************************
 * MSPACK_DESTROY_CAB_DECOMPRESSOR
 ***************************************
 * destructor
 */
void mspack_destroy_cab_decompressor(struct mscab_decompressor *base) {
  struct mscab_decompressor_p *self = (struct mscab_decompressor_p *) base;
  if (self) {
    struct mspack_system *sys = self->system;
    if (self->d) {
      if (self->d->infh) sys->close(self->d->infh);
      cabd_free_decomp(self);
      sys->free(self->d);
    }
    sys->free(self);
  }
}


/***************************************
 * CABD_OPEN
 ***************************************
 * opens a file and tries to read it as a cabinet file
 */
static struct mscabd_cabinet *cabd_open(struct mscab_decompressor *base,
                                        const char *filename)
{
  struct mscab_decompressor_p *self = (struct mscab_decompressor_p *) base;
  struct mscabd_cabinet_p *cab = NULL;
  struct mspack_system *sys;
  struct mspack_file *fh;
  int error;

  if (!base) return NULL;
  sys = self->system;

  if ((fh = sys->open(sys, filename, MSPACK_SYS_OPEN_READ))) {
    if ((cab = (struct mscabd_cabinet_p *) sys->alloc(sys, sizeof(struct mscabd_cabinet_p)))) {
      cab->base.filename = filename;
      error = cabd_read_headers(sys, fh, cab, (off_t) 0, self->salvage, 0);
      if (error) {
        cabd_close(base, (struct mscabd_cabinet *) cab);
        cab = NULL;
      }
      self->error = error;
    }
    else {
      self->error = MSPACK_ERR_NOMEMORY;
    }
    sys->close(fh);
  }
  else {
    self->error = MSPACK_ERR_OPEN;
  }
  return (struct mscabd_cabinet *) cab;
}

/***************************************
 * CABD_CLOSE
 ***************************************
 * frees all memory associated with a given mscabd_cabinet.
 */
static void cabd_close(struct mscab_decompressor *base,
                       struct mscabd_cabinet *origcab)
{
  struct mscab_decompressor_p *self = (struct mscab_decompressor_p *) base;
  struct mscabd_folder_data *dat, *ndat;
  struct mscabd_cabinet *cab, *ncab;
  struct mscabd_folder *fol, *nfol;
  struct mscabd_file *fi, *nfi;
  struct mspack_system *sys;

  if (!base) return;
  sys = self->system;

  self->error = MSPACK_ERR_OK;

  while (origcab) {
    /* free files */
    for (fi = origcab->files; fi; fi = nfi) {
      nfi = fi->next;
      sys->free(fi->filename);
      sys->free(fi);
    }

    /* free folders */
    for (fol = origcab->folders; fol; fol = nfol) {
      nfol = fol->next;

      /* free folder decompression state if it has been decompressed */
      if (self->d && (self->d->folder == (struct mscabd_folder_p *) fol)) {
        if (self->d->infh) sys->close(self->d->infh);
        cabd_free_decomp(self);
        sys->free(self->d);
        self->d = NULL;
      }

      /* free folder data segments */
      for (dat = ((struct mscabd_folder_p *)fol)->data.next; dat; dat = ndat) {
        ndat = dat->next;
        sys->free(dat);
      }
      sys->free(fol);
    }

    /* free predecessor cabinets (and the original cabinet's strings) */
    for (cab = origcab; cab; cab = ncab) {
      ncab = cab->prevcab;
      sys->free(cab->prevname);
      sys->free(cab->nextname);
      sys->free(cab->previnfo);
      sys->free(cab->nextinfo);
      if (cab != origcab) sys->free(cab);
    }

    /* free successor cabinets */
    for (cab = origcab->nextcab; cab; cab = ncab) {
      ncab = cab->nextcab;
      sys->free(cab->prevname);
      sys->free(cab->nextname);
      sys->free(cab->previnfo);
      sys->free(cab->nextinfo);
      sys->free(cab);
    }

    /* free actual cabinet structure */
    cab = origcab->next;
    sys->free(origcab);

    /* repeat full procedure again with the cab->next pointer (if set) */
    origcab = cab;
  }
}

/***************************************
 * CABD_READ_HEADERS
 ***************************************
 * reads the cabinet file header, folder list and file list.
 * fills out a pre-existing mscabd_cabinet structure, allocates memory
 * for folders and files as necessary
 */
static int cabd_read_headers(struct mspack_system *sys,
                             struct mspack_file *fh,
                             struct mscabd_cabinet_p *cab,
                             off_t offset, int salvage, int quiet)
{
  int num_folders, num_files, folder_resv, i, x, err, fidx;
  struct mscabd_folder_p *fol, *linkfol = NULL;
  struct mscabd_file *file, *linkfile = NULL;
  unsigned char buf[64];

  /* initialise pointers */
  cab->base.next     = NULL;
  cab->base.files    = NULL;
  cab->base.folders  = NULL;
  cab->base.prevcab  = cab->base.nextcab  = NULL;
  cab->base.prevname = cab->base.nextname = NULL;
  cab->base.previnfo = cab->base.nextinfo = NULL;

  cab->base.base_offset = offset;

  /* seek to CFHEADER */
  if (sys->seek(fh, offset, MSPACK_SYS_SEEK_START)) {
    return MSPACK_ERR_SEEK;
  }

  /* read in the CFHEADER */
  if (sys->read(fh, &buf[0], cfhead_SIZEOF) != cfhead_SIZEOF) {
    return MSPACK_ERR_READ;
  }

  /* check for "MSCF" signature */
  if (EndGetI32(&buf[cfhead_Signature]) != 0x4643534D) {
    return MSPACK_ERR_SIGNATURE;
  }

  /* some basic header fields */
  cab->base.length    = EndGetI32(&buf[cfhead_CabinetSize]);
  cab->base.set_id    = EndGetI16(&buf[cfhead_SetID]);
  cab->base.set_index = EndGetI16(&buf[cfhead_CabinetIndex]);

  /* get the number of folders */
  num_folders = EndGetI16(&buf[cfhead_NumFolders]);
  if (num_folders == 0) {
    if (!quiet) sys->message(fh, "no folders in cabinet.");
    return MSPACK_ERR_DATAFORMAT;
  }

  /* get the number of files */
  num_files = EndGetI16(&buf[cfhead_NumFiles]);
  if (num_files == 0) {
    if (!quiet) sys->message(fh, "no files in cabinet.");
    return MSPACK_ERR_DATAFORMAT;
  }

  /* check cabinet version */
  if ((buf[cfhead_MajorVersion] != 1) && (buf[cfhead_MinorVersion] != 3)) {
    if (!quiet) sys->message(fh, "WARNING; cabinet version is not 1.3");
  }

  /* read the reserved-sizes part of header, if present */
  cab->base.flags = EndGetI16(&buf[cfhead_Flags]);

  if (cab->base.flags & cfheadRESERVE_PRESENT) {
    if (sys->read(fh, &buf[0], cfheadext_SIZEOF) != cfheadext_SIZEOF) {
      return MSPACK_ERR_READ;
    }
    cab->base.header_resv = EndGetI16(&buf[cfheadext_HeaderReserved]);
    folder_resv           = buf[cfheadext_FolderReserved];
    cab->block_resv       = buf[cfheadext_DataReserved];

    if (cab->base.header_resv > 60000) {
      if (!quiet) sys->message(fh, "WARNING; reserved header > 60000.");
    }

    /* skip the reserved header */
    if (cab->base.header_resv) {
      if (sys->seek(fh, (off_t) cab->base.header_resv, MSPACK_SYS_SEEK_CUR)) {
        return MSPACK_ERR_SEEK;
      }
    }
  }
  else {
    cab->base.header_resv = 0;
    folder_resv           = 0; 
    cab->block_resv       = 0;
  }

  /* read name and info of preceeding cabinet in set, if present */
  if (cab->base.flags & cfheadPREV_CABINET) {
    cab->base.prevname = cabd_read_string(sys, fh, &err);
    if (err) return err;
    cab->base.previnfo = cabd_read_string(sys, fh, &err);
    if (err) return err;
  }

  /* read name and info of next cabinet in set, if present */
  if (cab->base.flags & cfheadNEXT_CABINET) {
    cab->base.nextname = cabd_read_string(sys, fh, &err);
    if (err) return err;
    cab->base.nextinfo = cabd_read_string(sys, fh, &err);
    if (err) return err;
  }

  /* read folders */
  for (i = 0; i < num_folders; i++) {
    if (sys->read(fh, &buf[0], cffold_SIZEOF) != cffold_SIZEOF) {
      return MSPACK_ERR_READ;
    }
    if (folder_resv) {
      if (sys->seek(fh, (off_t) folder_resv, MSPACK_SYS_SEEK_CUR)) {
        return MSPACK_ERR_SEEK;
      }
    }

    if (!(fol = (struct mscabd_folder_p *) sys->alloc(sys, sizeof(struct mscabd_folder_p)))) {
      return MSPACK_ERR_NOMEMORY;
    }
    fol->base.next       = NULL;
    fol->base.comp_type  = EndGetI16(&buf[cffold_CompType]);
    fol->base.num_blocks = EndGetI16(&buf[cffold_NumBlocks]);
    fol->data.next       = NULL;
    fol->data.cab        = (struct mscabd_cabinet_p *) cab;
    fol->data.offset     = offset + (off_t)
      ( (unsigned int) EndGetI32(&buf[cffold_DataOffset]) );
    fol->merge_prev      = NULL;
    fol->merge_next      = NULL;

    /* link folder into list of folders */
    if (!linkfol) cab->base.folders = (struct mscabd_folder *) fol;
    else linkfol->base.next = (struct mscabd_folder *) fol;
    linkfol = fol;
  }

  /* read files */
  for (i = 0; i < num_files; i++) {
    if (sys->read(fh, &buf[0], cffile_SIZEOF) != cffile_SIZEOF) {
      return MSPACK_ERR_READ;
    }

    if (!(file = (struct mscabd_file *) sys->alloc(sys, sizeof(struct mscabd_file)))) {
      return MSPACK_ERR_NOMEMORY;
    }

    file->next     = NULL;
    file->length   = EndGetI32(&buf[cffile_UncompressedSize]);
    file->attribs  = EndGetI16(&buf[cffile_Attribs]);
    file->offset   = EndGetI32(&buf[cffile_FolderOffset]);

    /* set folder pointer */
    fidx = EndGetI16(&buf[cffile_FolderIndex]);
    if (fidx < cffileCONTINUED_FROM_PREV) {
      /* normal folder index; count up to the correct folder */
      if (fidx < num_folders) {
        struct mscabd_folder *ifol = cab->base.folders;
        while (fidx--) if (ifol) ifol = ifol->next;
        file->folder = ifol;
      }
      else {
        D(("invalid folder index"))
        file->folder = NULL;
      }
    }
    else {
      /* either CONTINUED_TO_NEXT, CONTINUED_FROM_PREV or
       * CONTINUED_PREV_AND_NEXT */
      if ((fidx == cffileCONTINUED_TO_NEXT) ||
          (fidx == cffileCONTINUED_PREV_AND_NEXT))
      {
        /* get last folder */
        struct mscabd_folder *ifol = cab->base.folders;
        while (ifol->next) ifol = ifol->next;
        file->folder = ifol;

        /* set "merge next" pointer */
        fol = (struct mscabd_folder_p *) ifol;
        if (!fol->merge_next) fol->merge_next = file;
      }

      if ((fidx == cffileCONTINUED_FROM_PREV) ||
          (fidx == cffileCONTINUED_PREV_AND_NEXT))
      {
        /* get first folder */
        file->folder = cab->base.folders;

        /* set "merge prev" pointer */
        fol = (struct mscabd_folder_p *) file->folder;
        if (!fol->merge_prev) fol->merge_prev = file;
      }
    }

    /* get time */
    x = EndGetI16(&buf[cffile_Time]);
    file->time_h = x >> 11;
    file->time_m = (x >> 5) & 0x3F;
    file->time_s = (x << 1) & 0x3E;

    /* get date */
    x = EndGetI16(&buf[cffile_Date]);
    file->date_d = x & 0x1F;
    file->date_m = (x >> 5) & 0xF;
    file->date_y = (x >> 9) + 1980;

    /* get filename */
    file->filename = cabd_read_string(sys, fh, &err);

    /* if folder index or filename are bad, either skip it or fail */
    if (err || !file->folder) {
      sys->free(file->filename);
      sys->free(file);
      if (salvage) continue;
      return err ? err : MSPACK_ERR_DATAFORMAT;
    }

    /* link file entry into file list */
    if (!linkfile) cab->base.files = file;
    else linkfile->next = file;
    linkfile = file;
  }

  if (cab->base.files == NULL) {
    /* We never actually added any files to the file list.  Something went wrong.
     * The file header may have been invalid */
    D(("No files found, even though header claimed to have %d files", num_files))
    return MSPACK_ERR_DATAFORMAT;
  }

  return MSPACK_ERR_OK;
}

static char *cabd_read_string(struct mspack_system *sys,
                              struct mspack_file *fh, int *error)
{
  off_t base = sys->tell(fh);
  char buf[256], *str;
  int len, i, ok;

  /* read up to 256 bytes */
  if ((len = sys->read(fh, &buf[0], 256)) <= 0) {
    *error = MSPACK_ERR_READ;
    return NULL;
  }

  /* search for a null terminator in the buffer */
  for (i = 0, ok = 0; i < len; i++) if (!buf[i]) { ok = 1; break; }
  /* reject empty strings */
  if (i == 0) ok = 0;

  if (!ok) {
    *error = MSPACK_ERR_DATAFORMAT;
    return NULL;
  }

  len = i + 1;

  /* set the data stream to just after the string and return */
  if (sys->seek(fh, base + (off_t)len, MSPACK_SYS_SEEK_START)) {
    *error = MSPACK_ERR_SEEK;
    return NULL;
  }

  if (!(str = (char *) sys->alloc(sys, len))) {
    *error = MSPACK_ERR_NOMEMORY;
    return NULL;
  }

  sys->copy(&buf[0], str, len);
  *error = MSPACK_ERR_OK;
  return str;
}
    
/***************************************
 * CABD_SEARCH, CABD_FIND
 ***************************************
 * cabd_search opens a file, finds its extent, allocates a search buffer,
 * then reads through the whole file looking for possible cabinet headers.
 * if it finds any, it tries to read them as real cabinets. returns a linked
 * list of results
 *
 * cabd_find is the inner loop of cabd_search, to make it easier to
 * break out of the loop and be sure that all resources are freed
 */
static struct mscabd_cabinet *cabd_search(struct mscab_decompressor *base,
                                          const char *filename)
{
  struct mscab_decompressor_p *self = (struct mscab_decompressor_p *) base;
  struct mscabd_cabinet_p *cab = NULL;
  struct mspack_system *sys;
  unsigned char *search_buf;
  struct mspack_file *fh;
  off_t filelen, firstlen = 0;

  if (!base) return NULL;
  sys = self->system;

  /* allocate a search buffer */
  search_buf = (unsigned char *) sys->alloc(sys, (size_t) self->searchbuf_size);
  if (!search_buf) {
    self->error = MSPACK_ERR_NOMEMORY;
    return NULL;
  }

  /* open file and get its full file length */
  if ((fh = sys->open(sys, filename, MSPACK_SYS_OPEN_READ))) {
    if (!(self->error = mspack_sys_filelen(sys, fh, &filelen))) {
      self->error = cabd_find(self, search_buf, fh, filename,
                              filelen, &firstlen, &cab);
    }

    /* truncated / extraneous data warning: */
    if (firstlen && (firstlen != filelen) &&
        (!cab || (cab->base.base_offset == 0)))
    {
      if (firstlen < filelen) {
        sys->message(fh, "WARNING; possible %" LD
                     " extra bytes at end of file.",
                     filelen - firstlen);
      }
      else {
        sys->message(fh, "WARNING; file possibly truncated by %" LD " bytes.",
                     firstlen - filelen);
      }
    }
    
    sys->close(fh);
  }
  else {
    self->error = MSPACK_ERR_OPEN;
  }

  /* free the search buffer */
  sys->free(search_buf);

  return (struct mscabd_cabinet *) cab;
}

static int cabd_find(struct mscab_decompressor_p *self, unsigned char *buf,
                     struct mspack_file *fh, const char *filename, off_t flen,
                     off_t *firstlen, struct mscabd_cabinet_p **firstcab)
{
  struct mscabd_cabinet_p *cab, *link = NULL;
  off_t caboff, offset, length;
  struct mspack_system *sys = self->system;
  unsigned char *p, *pend, state = 0;
  unsigned int cablen_u32 = 0, foffset_u32 = 0;
  int false_cabs = 0;

#if !LARGEFILE_SUPPORT
  /* detect 32-bit off_t overflow */
  if (flen < 0) {
    sys->message(fh, largefile_msg);
    return MSPACK_ERR_OK;
  }
#endif

  /* search through the full file length */
  for (offset = 0; offset < flen; offset += length) {
    /* search length is either the full length of the search buffer, or the
     * amount of data remaining to the end of the file, whichever is less. */
    length = flen - offset;
    if (length > self->searchbuf_size) {
      length = self->searchbuf_size;
    }

    /* fill the search buffer with data from disk */
    if (sys->read(fh, &buf[0], (int) length) != (int) length) {
      return MSPACK_ERR_READ;
    }

    /* FAQ avoidance strategy */
    if ((offset == 0) && (EndGetI32(&buf[0]) == 0x28635349)) {
      sys->message(fh, "WARNING; found InstallShield header. Use unshield "
                   "(https://github.com/twogood/unshield) to unpack this file"); 
    }

    /* read through the entire buffer. */
    for (p = &buf[0], pend = &buf[length]; p < pend; ) {
      switch (state) {
        /* starting state */
      case 0:
        /* we spend most of our time in this while loop, looking for
         * a leading 'M' of the 'MSCF' signature */
        while (p < pend && *p != 0x4D) p++;
        /* if we found tht 'M', advance state */
        if (p++ < pend) state = 1;
        break;

      /* verify that the next 3 bytes are 'S', 'C' and 'F' */
      case 1: state = (*p++ == 0x53) ? 2 : 0; break;
      case 2: state = (*p++ == 0x43) ? 3 : 0; break;
      case 3: state = (*p++ == 0x46) ? 4 : 0; break;

      /* we don't care about bytes 4-7 (see default: for action) */

      /* bytes 8-11 are the overall length of the cabinet */
      case 8:  cablen_u32  = *p++;       state++; break;
      case 9:  cablen_u32 |= *p++ << 8;  state++; break;
      case 10: cablen_u32 |= *p++ << 16; state++; break;
      case 11: cablen_u32 |= *p++ << 24; state++; break;

      /* we don't care about bytes 12-15 (see default: for action) */

      /* bytes 16-19 are the offset within the cabinet of the filedata */
      case 16: foffset_u32  = *p++;       state++; break;
      case 17: foffset_u32 |= *p++ << 8;  state++; break;
      case 18: foffset_u32 |= *p++ << 16; state++; break;
      case 19: foffset_u32 |= *p++ << 24;
        /* now we have recieved 20 bytes of potential cab header. work out
         * the offset in the file of this potential cabinet */
        caboff = offset + (p - &buf[0]) - 20;

        /* should reading cabinet fail, restart search just after 'MSCF' */
        offset = caboff + 4;

        /* capture the "length of cabinet" field if there is a cabinet at
         * offset 0 in the file, regardless of whether the cabinet can be
         * read correctly or not */
        if (caboff == 0) *firstlen = (off_t) cablen_u32;

        /* check that the files offset is less than the alleged length of
         * the cabinet, and that the offset + the alleged length are
         * 'roughly' within the end of overall file length. In salvage
         * mode, don't check the alleged length, allow it to be garbage */
        if ((foffset_u32 < cablen_u32) &&
            ((caboff + (off_t) foffset_u32) < (flen + 32)) &&
            (((caboff + (off_t) cablen_u32)  < (flen + 32)) || self->salvage))
        {
          /* likely cabinet found -- try reading it */
          if (!(cab = (struct mscabd_cabinet_p *) sys->alloc(sys, sizeof(struct mscabd_cabinet_p)))) {
            return MSPACK_ERR_NOMEMORY;
          }
          cab->base.filename = filename;
          if (cabd_read_headers(sys, fh, cab, caboff, self->salvage, 1)) {
            /* destroy the failed cabinet */
            cabd_close((struct mscab_decompressor *) self,
                       (struct mscabd_cabinet *) cab);
            false_cabs++;
          }
          else {
            /* cabinet read correctly! */

            /* link the cab into the list */
            if (!link) *firstcab = cab;
            else link->base.next = (struct mscabd_cabinet *) cab;
            link = cab;

            /* cause the search to restart after this cab's data. */
            offset = caboff + (off_t) cablen_u32;

#if !LARGEFILE_SUPPORT
            /* detect 32-bit off_t overflow */
            if (offset < caboff) {
              sys->message(fh, largefile_msg);
              return MSPACK_ERR_OK;
            }
#endif        
          }
        }

        /* restart search */
        if (offset >= flen) return MSPACK_ERR_OK;
        if (sys->seek(fh, offset, MSPACK_SYS_SEEK_START)) {
          return MSPACK_ERR_SEEK;
        }
        length = 0;
        p = pend;
        state = 0;
        break;

      /* for bytes 4-7 and 12-15, just advance state/pointer */
      default:
        p++, state++;
      } /* switch(state) */
    } /* for (... p < pend ...) */
  } /* for (... offset < length ...) */

  if (false_cabs) {
    D(("%d false cabinets found", false_cabs))
  }

  return MSPACK_ERR_OK;
}
                                             
/***************************************
 * CABD_MERGE, CABD_PREPEND, CABD_APPEND
 ***************************************
 * joins cabinets together, also merges split folders between these two
 * cabinets only. This includes freeing the duplicate folder and file(s)
 * and allocating a further mscabd_folder_data structure to append to the
 * merged folder's data parts list.
 */
static int cabd_prepend(struct mscab_decompressor *base,
                        struct mscabd_cabinet *cab,
                        struct mscabd_cabinet *prevcab)
{
  return cabd_merge(base, prevcab, cab);
}

static int cabd_append(struct mscab_decompressor *base,
                        struct mscabd_cabinet *cab,
                        struct mscabd_cabinet *nextcab)
{
  return cabd_merge(base, cab, nextcab);
}

static int cabd_merge(struct mscab_decompressor *base,
                      struct mscabd_cabinet *lcab,
                      struct mscabd_cabinet *rcab)
{
  struct mscab_decompressor_p *self = (struct mscab_decompressor_p *) base;
  struct mscabd_folder_data *data, *ndata;
  struct mscabd_folder_p *lfol, *rfol;
  struct mscabd_file *fi, *rfi, *lfi;
  struct mscabd_cabinet *cab;
  struct mspack_system *sys;

  if (!self) return MSPACK_ERR_ARGS;
  sys = self->system;

  /* basic args check */
  if (!lcab || !rcab || (lcab == rcab)) {
    D(("lcab NULL, rcab NULL or lcab = rcab"))
    return self->error = MSPACK_ERR_ARGS;
  }

  /* check there's not already a cabinet attached */
  if (lcab->nextcab || rcab->prevcab) {
    D(("cabs already joined"))
    return self->error = MSPACK_ERR_ARGS;
  }

  /* do not create circular cabinet chains */
  for (cab = lcab->prevcab; cab; cab = cab->prevcab) {
    if (cab == rcab) {D(("circular!")) return self->error = MSPACK_ERR_ARGS;}
  }
  for (cab = rcab->nextcab; cab; cab = cab->nextcab) {
    if (cab == lcab) {D(("circular!")) return self->error = MSPACK_ERR_ARGS;}
  }

  /* warn about odd set IDs or indices */
  if (lcab->set_id != rcab->set_id) {
    sys->message(NULL, "WARNING; merged cabinets with differing Set IDs.");
  }

  if (lcab->set_index > rcab->set_index) {
    sys->message(NULL, "WARNING; merged cabinets with odd order.");
  }

  /* merging the last folder in lcab with the first folder in rcab */
  lfol = (struct mscabd_folder_p *) lcab->folders;
  rfol = (struct mscabd_folder_p *) rcab->folders;
  while (lfol->base.next) lfol = (struct mscabd_folder_p *) lfol->base.next;

  /* do we need to merge folders? */
  if (!lfol->merge_next && !rfol->merge_prev) {
    /* no, at least one of the folders is not for merging */

    /* attach cabs */
    lcab->nextcab = rcab;
    rcab->prevcab = lcab;

    /* attach folders */
    lfol->base.next = (struct mscabd_folder *) rfol;

    /* attach files */
    fi = lcab->files;
    while (fi->next) fi = fi->next;
    fi->next = rcab->files;
  }
  else {
    /* folder merge required - do the files match? */
    if (! cabd_can_merge_folders(sys, lfol, rfol)) {
      return self->error = MSPACK_ERR_DATAFORMAT;
    }

    /* allocate a new folder data structure */
    if (!(data = (struct mscabd_folder_data *) sys->alloc(sys, sizeof(struct mscabd_folder_data)))) {
      return self->error = MSPACK_ERR_NOMEMORY;
    }

    /* attach cabs */
    lcab->nextcab = rcab;
    rcab->prevcab = lcab;

    /* append rfol's data to lfol */
    ndata = &lfol->data;
    while (ndata->next) ndata = ndata->next;
    ndata->next = data;
    *data = rfol->data;
    rfol->data.next = NULL;

    /* lfol becomes rfol.
     * NOTE: special case, don't merge if rfol is merge prev and next,
     * rfol->merge_next is going to be deleted, so keep lfol's version
     * instead */
    lfol->base.num_blocks += rfol->base.num_blocks - 1;
    if ((rfol->merge_next == NULL) ||
        (rfol->merge_next->folder != (struct mscabd_folder *) rfol))
    {
      lfol->merge_next = rfol->merge_next;
    }

    /* attach the rfol's folder (except the merge folder) */
    while (lfol->base.next) lfol = (struct mscabd_folder_p *) lfol->base.next;
    lfol->base.next = rfol->base.next;

    /* free disused merge folder */
    sys->free(rfol);

    /* attach rfol's files */
    fi = lcab->files;
    while (fi->next) fi = fi->next;
    fi->next = rcab->files;

    /* delete all files from rfol's merge folder */
    lfi = NULL;
    for (fi = lcab->files; fi ; fi = rfi) {
      rfi = fi->next;
      /* if file's folder matches the merge folder, unlink and free it */
      if (fi->folder == (struct mscabd_folder *) rfol) {
        if (lfi) lfi->next = rfi; else lcab->files = rfi;
        sys->free(fi->filename);
        sys->free(fi);
      }
      else lfi = fi;
    }
  }

  /* all done! fix files and folders pointers in all cabs so they all
   * point to the same list  */
  for (cab = lcab->prevcab; cab; cab = cab->prevcab) {
    cab->files   = lcab->files;
    cab->folders = lcab->folders;
  }

  for (cab = lcab->nextcab; cab; cab = cab->nextcab) {
    cab->files   = lcab->files;
    cab->folders = lcab->folders;
  }

  return self->error = MSPACK_ERR_OK;
}

/* decides if two folders are OK to merge */
static int cabd_can_merge_folders(struct mspack_system *sys,
                                  struct mscabd_folder_p *lfol,
                                  struct mscabd_folder_p *rfol)
{
    struct mscabd_file *lfi, *rfi, *l, *r;
    int matching = 1;

    /* check that both folders use the same compression method/settings */
    if (lfol->base.comp_type != rfol->base.comp_type) {
        D(("folder merge: compression type mismatch"))
        return 0;
    }

    /* check there are not too many data blocks after merging */
    if ((lfol->base.num_blocks + rfol->base.num_blocks) > CAB_FOLDERMAX) {
        D(("folder merge: too many data blocks in merged folders"))
        return 0;
    }

    if (!(lfi = lfol->merge_next) || !(rfi = rfol->merge_prev)) {
        D(("folder merge: one cabinet has no files to merge"))
        return 0;
    }

    /* for all files in lfol (which is the last folder in whichever cab and
     * only has files to merge), compare them to the files from rfol. They
     * should be identical in number and order. to verify this, check the
     * offset and length of each file. */
    for (l=lfi, r=rfi; l; l=l->next, r=r->next) {
        if (!r || (l->offset != r->offset) || (l->length != r->length)) {
            matching = 0;
            break;
        }
    }

    if (matching) return 1;

    /* if rfol does not begin with an identical copy of the files in lfol, make
     * make a judgement call; if at least ONE file from lfol is in rfol, allow
     * the merge with a warning about missing files. */
    matching = 0;
    for (l = lfi; l; l = l->next) {
        for (r = rfi; r; r = r->next) {
            if (l->offset == r->offset && l->length == r->length) break;
        }
        if (r) matching = 1; else sys->message(NULL,
            "WARNING; merged file %s not listed in both cabinets", l->filename);
    }
    return matching;
}


/***************************************
 * CABD_EXTRACT
 ***************************************
 * extracts a file from a cabinet
 */
static int cabd_extract(struct mscab_decompressor *base,
                        struct mscabd_file *file, const char *filename)
{
  struct mscab_decompressor_p *self = (struct mscab_decompressor_p *) base;
  struct mscabd_folder_p *fol;
  struct mspack_system *sys;
  struct mspack_file *fh;
  off_t filelen;

  if (!self) return MSPACK_ERR_ARGS;
  if (!file) return self->error = MSPACK_ERR_ARGS;

  sys = self->system;
  fol = (struct mscabd_folder_p *) file->folder;

  /* if offset is beyond 2GB, nothing can be extracted */
  if (file->offset > CAB_LENGTHMAX) {
    return self->error = MSPACK_ERR_DATAFORMAT;
  }

  /* if file claims to go beyond 2GB either error out,
   * or in salvage mode reduce file length so it fits 2GB limit
   */
  filelen = file->length;
  if (filelen > CAB_LENGTHMAX || (file->offset + filelen) > CAB_LENGTHMAX) {
    if (self->salvage) {
      filelen = CAB_LENGTHMAX - file->offset;
    }
    else {
      return self->error = MSPACK_ERR_DATAFORMAT;
    }
  }

  /* extraction impossible if no folder, or folder needs predecessor */
  if (!fol || fol->merge_prev) {
    sys->message(NULL, "ERROR; file \"%s\" cannot be extracted, "
                 "cabinet set is incomplete", file->filename);
    return self->error = MSPACK_ERR_DECRUNCH;
  }

  /* if file goes beyond what can be decoded, given an error.
   * In salvage mode, don't assume block sizes, just try decoding
   */
  if (!self->salvage) {
    off_t maxlen = fol->base.num_blocks * CAB_BLOCKMAX;
    if ((file->offset + filelen) > maxlen) {
      sys->message(NULL, "ERROR; file \"%s\" cannot be extracted, "
                   "cabinet set is incomplete", file->filename);
      return self->error = MSPACK_ERR_DECRUNCH;
    }
  }

  /* allocate generic decompression state */
  if (!self->d) {
    self->d = (struct mscabd_decompress_state *) sys->alloc(sys, sizeof(struct mscabd_decompress_state));
    if (!self->d) return self->error = MSPACK_ERR_NOMEMORY;
    self->d->folder     = NULL;
    self->d->data       = NULL;
    self->d->sys        = *sys;
    self->d->sys.read   = &cabd_sys_read;
    self->d->sys.write  = &cabd_sys_write;
    self->d->state      = NULL;
    self->d->infh       = NULL;
    self->d->incab      = NULL;
  }

  /* do we need to change folder or reset the current folder? */
  if ((self->d->folder != fol) || (self->d->offset > file->offset) ||
      !self->d->state)
  {
    /* free any existing decompressor */
    cabd_free_decomp(self);

    /* do we need to open a new cab file? */
    if (!self->d->infh || (fol->data.cab != self->d->incab)) {
      /* close previous file handle if from a different cab */
      if (self->d->infh) sys->close(self->d->infh);
      self->d->incab = fol->data.cab;
      self->d->infh = sys->open(sys, fol->data.cab->base.filename,
                                MSPACK_SYS_OPEN_READ);
      if (!self->d->infh) return self->error = MSPACK_ERR_OPEN;
    }
    /* seek to start of data blocks */
    if (sys->seek(self->d->infh, fol->data.offset, MSPACK_SYS_SEEK_START)) {
      return self->error = MSPACK_ERR_SEEK;
    }

    /* set up decompressor */
    if (cabd_init_decomp(self, (unsigned int) fol->base.comp_type)) {
      return self->error;
    }

    /* initialise new folder state */
    self->d->folder = fol;
    self->d->data   = &fol->data;
    self->d->offset = 0;
    self->d->block  = 0;
    self->d->outlen = 0;
    self->d->i_ptr = self->d->i_end = &self->d->input[0];

    /* read_error lasts for the lifetime of a decompressor */
    self->read_error = MSPACK_ERR_OK;
  }

  /* open file for output */
  if (!(fh = sys->open(sys, filename, MSPACK_SYS_OPEN_WRITE))) {
    return self->error = MSPACK_ERR_OPEN;
  }

  self->error = MSPACK_ERR_OK;

  /* if file has more than 0 bytes */
  if (filelen) {
    off_t bytes;
    int error;
    /* get to correct offset.
     * - use NULL fh to say 'no writing' to cabd_sys_write()
     * - if cabd_sys_read() has an error, it will set self->read_error
     *   and pass back MSPACK_ERR_READ
     */
    self->d->outfh = NULL;
    if ((bytes = file->offset - self->d->offset)) {
        error = self->d->decompress(self->d->state, bytes);
        self->error = (error == MSPACK_ERR_READ) ? self->read_error : error;
    }

    /* if getting to the correct offset was error free, unpack file */
    if (!self->error) {
      self->d->outfh = fh;
      error = self->d->decompress(self->d->state, filelen);
      self->error = (error == MSPACK_ERR_READ) ? self->read_error : error;
    }
  }

  /* close output file */
  sys->close(fh);
  self->d->outfh = NULL;

  return self->error;
}

/***************************************
 * CABD_INIT_DECOMP, CABD_FREE_DECOMP
 ***************************************
 * cabd_init_decomp initialises decompression state, according to which
 * decompression method was used. relies on self->d->folder being the same
 * as when initialised.
 *
 * cabd_free_decomp frees decompression state, according to which method
 * was used.
 */
static int cabd_init_decomp(struct mscab_decompressor_p *self, unsigned int ct)
{
  struct mspack_file *fh = (struct mspack_file *) self;

  self->d->comp_type = ct;

  switch (ct & cffoldCOMPTYPE_MASK) {
  case cffoldCOMPTYPE_NONE:
    self->d->decompress = (int (*)(void *, off_t)) &noned_decompress;
    self->d->state = noned_init(&self->d->sys, fh, fh, self->buf_size);
    break;
  case cffoldCOMPTYPE_MSZIP:
    self->d->decompress = (int (*)(void *, off_t)) &mszipd_decompress;
    self->d->state = mszipd_init(&self->d->sys, fh, fh, self->buf_size,
                                 self->fix_mszip);
    break;
  case cffoldCOMPTYPE_QUANTUM:
    self->d->decompress = (int (*)(void *, off_t)) &qtmd_decompress;
    self->d->state = qtmd_init(&self->d->sys, fh, fh, (int) (ct >> 8) & 0x1f,
                               self->buf_size);
    break;
  case cffoldCOMPTYPE_LZX:
    self->d->decompress = (int (*)(void *, off_t)) &lzxd_decompress;
    self->d->state = lzxd_init(&self->d->sys, fh, fh, (int) (ct >> 8) & 0x1f, 0,
                               self->buf_size, (off_t)0,0);
    break;
  default:
    return self->error = MSPACK_ERR_DATAFORMAT;
  }
  return self->error = (self->d->state) ? MSPACK_ERR_OK : MSPACK_ERR_NOMEMORY;
}

static void cabd_free_decomp(struct mscab_decompressor_p *self) {
  if (!self || !self->d || !self->d->state) return;

  switch (self->d->comp_type & cffoldCOMPTYPE_MASK) {
  case cffoldCOMPTYPE_NONE:    noned_free((struct noned_state *) self->d->state);   break;
  case cffoldCOMPTYPE_MSZIP:   mszipd_free((struct mszipd_stream *) self->d->state);  break;
  case cffoldCOMPTYPE_QUANTUM: qtmd_free((struct qtmd_stream *) self->d->state);    break;
  case cffoldCOMPTYPE_LZX:     lzxd_free((struct lzxd_stream *) self->d->state);    break;
  }
  self->d->decompress = NULL;
  self->d->state      = NULL;
}

/***************************************
 * CABD_SYS_READ, CABD_SYS_WRITE
 ***************************************
 * cabd_sys_read is the internal reader function which the decompressors
 * use. will read data blocks (and merge split blocks) from the cabinet
 * and serve the read bytes to the decompressors
 *
 * cabd_sys_write is the internal writer function which the decompressors
 * use. it either writes data to disk (self->d->outfh) with the real
 * sys->write() function, or does nothing with the data when
 * self->d->outfh == NULL. advances self->d->offset
 */
static int cabd_sys_read(struct mspack_file *file, void *buffer, int bytes) {
  struct mscab_decompressor_p *self = (struct mscab_decompressor_p *) file;
  unsigned char *buf = (unsigned char *) buffer;
  struct mspack_system *sys = self->system;
  int avail, todo, outlen, ignore_cksum, ignore_blocksize;

  ignore_cksum = self->salvage ||
    (self->fix_mszip && 
     ((self->d->comp_type & cffoldCOMPTYPE_MASK) == cffoldCOMPTYPE_MSZIP));
  ignore_blocksize = self->salvage;

  todo = bytes;
  while (todo > 0) {
    avail = self->d->i_end - self->d->i_ptr;

    /* if out of input data, read a new block */
    if (avail) {
      /* copy as many input bytes available as possible */
      if (avail > todo) avail = todo;
      sys->copy(self->d->i_ptr, buf, (size_t) avail);
      self->d->i_ptr += avail;
      buf  += avail;
      todo -= avail;
    }
    else {
      /* out of data, read a new block */

      /* check if we're out of input blocks, advance block counter */
      if (self->d->block++ >= self->d->folder->base.num_blocks) {
        if (!self->salvage) {
          self->read_error = MSPACK_ERR_DATAFORMAT;
        }
        else {
          D(("Ran out of CAB input blocks prematurely"))
        }
        break;
      }

      /* read a block */
      self->read_error = cabd_sys_read_block(sys, self->d, &outlen,
        ignore_cksum, ignore_blocksize);
      if (self->read_error) return -1;
      self->d->outlen += outlen;

      /* special Quantum hack -- trailer byte to allow the decompressor
       * to realign itself. CAB Quantum blocks, unlike LZX blocks, can have
       * anything from 0 to 4 trailing null bytes. */
      if ((self->d->comp_type & cffoldCOMPTYPE_MASK)==cffoldCOMPTYPE_QUANTUM) {
        *self->d->i_end++ = 0xFF;
      }

      /* is this the last block? */
      if (self->d->block >= self->d->folder->base.num_blocks) {
        if ((self->d->comp_type & cffoldCOMPTYPE_MASK) == cffoldCOMPTYPE_LZX) {
          /* special LZX hack -- on the last block, inform LZX of the
           * size of the output data stream. */
          lzxd_set_output_length((struct lzxd_stream *) self->d->state, self->d->outlen);
        }
      }
    } /* if (avail) */
  } /* while (todo > 0) */
  return bytes - todo;
}

static int cabd_sys_write(struct mspack_file *file, void *buffer, int bytes) {
  struct mscab_decompressor_p *self = (struct mscab_decompressor_p *) file;
  self->d->offset += bytes;
  if (self->d->outfh) {
    return self->system->write(self->d->outfh, buffer, bytes);
  }
  return bytes;
}

/***************************************
 * CABD_SYS_READ_BLOCK
 ***************************************
 * reads a whole data block from a cab file. the block may span more than
 * one cab file, if it does then the fragments will be reassembled
 */
static int cabd_sys_read_block(struct mspack_system *sys,
                               struct mscabd_decompress_state *d,
                               int *out, int ignore_cksum,
                               int ignore_blocksize)
{
  unsigned char hdr[cfdata_SIZEOF];
  unsigned int cksum;
  int len, full_len;

  /* reset the input block pointer and end of block pointer */
  d->i_ptr = d->i_end = &d->input[0];

  do {
    /* read the block header */
    if (sys->read(d->infh, &hdr[0], cfdata_SIZEOF) != cfdata_SIZEOF) {
      return MSPACK_ERR_READ;
    }

    /* skip any reserved block headers */
    if (d->data->cab->block_resv &&
        sys->seek(d->infh, (off_t) d->data->cab->block_resv,
                  MSPACK_SYS_SEEK_CUR))
    {
      return MSPACK_ERR_SEEK;
    }

    /* blocks must not be over CAB_INPUTMAX in size */
    len = EndGetI16(&hdr[cfdata_CompressedSize]);
    full_len = (d->i_end - d->i_ptr) + len; /* include cab-spanning blocks */
    if (full_len > CAB_INPUTMAX) {
      D(("block size %d > CAB_INPUTMAX", full_len));
      /* in salvage mode, blocks can be 65535 bytes but no more than that */
      if (!ignore_blocksize || full_len > CAB_INPUTMAX_SALVAGE) {
          return MSPACK_ERR_DATAFORMAT;
      }
    }

     /* blocks must not expand to more than CAB_BLOCKMAX */
    if (EndGetI16(&hdr[cfdata_UncompressedSize]) > CAB_BLOCKMAX) {
      D(("block size > CAB_BLOCKMAX"))
      if (!ignore_blocksize) return MSPACK_ERR_DATAFORMAT;
    }

    /* read the block data */
    if (sys->read(d->infh, d->i_end, len) != len) {
      return MSPACK_ERR_READ;
    }

    /* perform checksum test on the block (if one is stored) */
    if ((cksum = EndGetI32(&hdr[cfdata_CheckSum]))) {
      unsigned int sum2 = cabd_checksum(d->i_end, (unsigned int) len, 0);
      if (cabd_checksum(&hdr[4], 4, sum2) != cksum) {
        if (!ignore_cksum) return MSPACK_ERR_CHECKSUM;
        sys->message(d->infh, "WARNING; bad block checksum found");
      }
    }

    /* advance end of block pointer to include newly read data */
    d->i_end += len;

    /* uncompressed size == 0 means this block was part of a split block
     * and it continues as the first block of the next cabinet in the set.
     * otherwise, this is the last part of the block, and no more block
     * reading needs to be done.
     */
    /* EXIT POINT OF LOOP -- uncompressed size != 0 */
    if ((*out = EndGetI16(&hdr[cfdata_UncompressedSize]))) {
      return MSPACK_ERR_OK;
    }

    /* otherwise, advance to next cabinet */

    /* close current file handle */
    sys->close(d->infh);
    d->infh = NULL;

    /* advance to next member in the cabinet set */
    if (!(d->data = d->data->next)) {
      sys->message(d->infh, "WARNING; ran out of cabinets in set. Are any missing?");
      return MSPACK_ERR_DATAFORMAT;
    }

    /* open next cab file */
    d->incab = d->data->cab;
    if (!(d->infh = sys->open(sys, d->incab->base.filename,
                              MSPACK_SYS_OPEN_READ)))
    {
      return MSPACK_ERR_OPEN;
    }

    /* seek to start of data blocks */
    if (sys->seek(d->infh, d->data->offset, MSPACK_SYS_SEEK_START)) {
      return MSPACK_ERR_SEEK;
    }
  } while (1);

  /* not reached */
  return MSPACK_ERR_OK;
}

static unsigned int cabd_checksum(unsigned char *data, unsigned int bytes,
                                  unsigned int cksum)
{
  unsigned int len, ul = 0;

  for (len = bytes >> 2; len--; data += 4) {
    cksum ^= ((data[0]) | (data[1]<<8) | (data[2]<<16) | (data[3]<<24));
  }

  switch (bytes & 3) {
  case 3: ul |= *data++ << 16; /*@fallthrough@*/
  case 2: ul |= *data++ <<  8; /*@fallthrough@*/
  case 1: ul |= *data;
  }
  cksum ^= ul;

  return cksum;
}

/***************************************
 * NONED_INIT, NONED_DECOMPRESS, NONED_FREE
 ***************************************
 * the "not compressed" method decompressor
 */
struct noned_state {
  struct mspack_system *sys;
  struct mspack_file *i;
  struct mspack_file *o;
  unsigned char *buf;
  int bufsize;
};

static struct noned_state *noned_init(struct mspack_system *sys,
                                      struct mspack_file *in,
                                      struct mspack_file *out,
                                      int bufsize)
{
  struct noned_state *state = (struct noned_state *) sys->alloc(sys, sizeof(struct noned_state));
  unsigned char *buf = (unsigned char *) sys->alloc(sys, (size_t) bufsize);
  if (state && buf) {
    state->sys     = sys;
    state->i       = in;
    state->o       = out;
    state->buf     = buf;
    state->bufsize = bufsize;
  }
  else {
    sys->free(buf);
    sys->free(state);
    state = NULL;
  }
  return state;
}

static int noned_decompress(struct noned_state *s, off_t bytes) {
  int run;
  while (bytes > 0) {
    run = (bytes > s->bufsize) ? s->bufsize : (int) bytes;
    if (s->sys->read(s->i, &s->buf[0], run) != run) return MSPACK_ERR_READ;
    if (s->sys->write(s->o, &s->buf[0], run) != run) return MSPACK_ERR_WRITE;
    bytes -= run;
  }
  return MSPACK_ERR_OK;
}

static void noned_free(struct noned_state *state) {
  struct mspack_system *sys;
  if (state) {
    sys = state->sys;
    sys->free(state->buf);
    sys->free(state);
  }
}


/***************************************
 * CABD_PARAM
 ***************************************
 * allows a parameter to be set
 */
static int cabd_param(struct mscab_decompressor *base, int param, int value) {
  struct mscab_decompressor_p *self = (struct mscab_decompressor_p *) base;
  if (!self) return MSPACK_ERR_ARGS;

  switch (param) {
  case MSCABD_PARAM_SEARCHBUF:
    if (value < 4) return MSPACK_ERR_ARGS;
    self->searchbuf_size = value;
    break;
  case MSCABD_PARAM_FIXMSZIP:
    self->fix_mszip = value;
    break;
  case MSCABD_PARAM_DECOMPBUF:
    if (value < 4) return MSPACK_ERR_ARGS;
    self->buf_size = value;
    break;
  case MSCABD_PARAM_SALVAGE:
    self->salvage = value;
    break;
  default:
    return MSPACK_ERR_ARGS;
  }
  return MSPACK_ERR_OK;
}

/***************************************
 * CABD_ERROR
 ***************************************
 * returns the last error that occurred
 */
static int cabd_error(struct mscab_decompressor *base) {
  struct mscab_decompressor_p *self = (struct mscab_decompressor_p *) base;
  return (self) ? self->error : MSPACK_ERR_ARGS;
}
