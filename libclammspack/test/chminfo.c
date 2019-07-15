#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <mspack.h>
#include <system.h>

#define FILENAME ".chminfo-temp"

unsigned char *load_sys_data(struct mschm_decompressor *chmd,
                             struct mschmd_header *chm,
                             const char *filename,
                             off_t *length_ptr)
{
  struct mschmd_file *file;
  unsigned char *data;
  FILE *fh;

  for (file = chm->sysfiles; file; file = file->next) {
    if (strcmp(file->filename, filename) == 0) break;
  }
  if (!file || file->section->id != 0) return NULL;
  if (chmd->extract(chmd, file, FILENAME)) return NULL;
  if (length_ptr) *length_ptr = file->length;
  if (!(data = (unsigned char *) malloc((size_t) file->length))) return NULL;
  if ((fh = fopen(FILENAME, "rb"))) {
    fread(data, (size_t) file->length, 1, fh);
    fclose(fh);
  }
  else {
    free(data);
    data = NULL;
  }
  unlink(FILENAME);
  return data;
}

char *guid(unsigned char *data) {
  static char result[43];
  snprintf(result, sizeof(result),
           "{%08X-%04X-%04X-%04X-%02X%02X%02X%02X%02X%02X%02X%02X}",
           EndGetI32(&data[0]),
           data[4] | (data[5] << 8),
           data[6] | (data[7] << 8),
           data[8] | (data[9] << 8),
           data[10], data[11], data[12], data[13],
           data[14], data[15], data[16], data[17]);
  return result;
}

#define READ_ENCINT(var, label) do {                    \
    (var) = 0;                                          \
    do {                                                \
        if (p > &chunk[chm->chunk_size-2]) goto label;  \
        (var) = ((var) << 7) | (*p & 0x7F);             \
    } while (*p++ & 0x80);                              \
} while (0)

void print_dir(struct mschmd_header *chm, char *filename) {
  unsigned char dir[0x54], *chunk;
  unsigned int i;
  FILE *fh;

  if (!(chunk = (unsigned char *) malloc(chm->chunk_size))) return;
  
  if ((fh = fopen(filename, "rb"))) {
#if HAVE_FSEEKO
    fseeko(fh, chm->dir_offset - 84, SEEK_SET);
#else
    fseek(fh, chm->dir_offset - 84, SEEK_SET);
#endif
    fread(&dir[0], 84, 1, fh);
    printf("  chmhs1_Signature  = %4.4s\n", &dir[0]);
    printf("  chmhs1_Version    = %d\n", EndGetI32(&dir[4]));
    printf("  chmhs1_HeaderLen  = %d\n", EndGetI32(&dir[8]));
    printf("  chmhs1_Unknown1   = %d\n", EndGetI32(&dir[12]));
    printf("  chmhs1_ChunkSize  = %d\n", EndGetI32(&dir[16]));
    printf("  chmhs1_Density    = %d\n", EndGetI32(&dir[20]));
    printf("  chmhs1_Depth      = %d\n", EndGetI32(&dir[24]));
    printf("  chmhs1_IndexRoot  = %d\n", EndGetI32(&dir[28]));
    printf("  chmhs1_FirstPMGL  = %d\n", EndGetI32(&dir[32]));
    printf("  chmhs1_LastPMGL   = %d\n", EndGetI32(&dir[36]));
    printf("  chmhs1_Unknown2   = %d\n", EndGetI32(&dir[40]));
    printf("  chmhs1_NumChunks  = %d\n", EndGetI32(&dir[44]));
    printf("  chmhs1_LanguageID = %d\n", EndGetI32(&dir[48]));
    printf("  chmhs1_GUID       = %s\n", guid(&dir[52]));
    printf("  chmhs1_Unknown3   = %d\n", EndGetI32(&dir[68]));
    printf("  chmhs1_Unknown4   = %d\n", EndGetI32(&dir[72]));
    printf("  chmhs1_Unknown5   = %d\n", EndGetI32(&dir[76]));
    printf("  chmhs1_Unknown6   = %d\n", EndGetI32(&dir[80]));

    for (i = 0; i < chm->num_chunks; i++) {
      unsigned int num_entries, quickref_size, j, k;
      unsigned char *p, *name;
      printf("  CHUNK %u:\n", i);
      fread(chunk, chm->chunk_size, 1, fh);

      if ((chunk[0] == 'P') && (chunk[1] == 'M') &&
          (chunk[2] == 'G') && (chunk[3] == 'L'))
      {
        k = chm->chunk_size - 2;
        num_entries = chunk[k] | (chunk[k+1] << 8);
        quickref_size = EndGetI32(&chunk[4]);
        if (quickref_size > (chm->chunk_size - 20)) {
            printf("    QR size of %d too large (max is %d)\n",
                   quickref_size, chm->chunk_size - 20);
            quickref_size = chm->chunk_size - 20;
        }
        printf("    PMGL entries=%u qrsize=%u zero=%u prev=%d next=%d\n",
               num_entries, quickref_size, EndGetI32(&chunk[8]),
               EndGetI32(&chunk[12]), EndGetI32(&chunk[16]));

        printf("    QR: entry %4u = offset %u\n", 0, 20);
        j = (1 << chm->density) + 1;
        while (j < num_entries) {
          k -= 2;
          if (k < (chm->chunk_size - quickref_size)) break;
          printf("    QR: entry %4u = offset %u\n",
                 j, (chunk[k] | (chunk[k+1] << 8)) + 20);
          j += (1 << chm->density) + 1;
        }

        p = &chunk[20];
        for (j = 0; j < num_entries; j++) {
          unsigned int name_len = 0, section = 0, offset = 0, length = 0;
          printf("    %4d: ", (int) (p - &chunk[0]));
          READ_ENCINT(name_len, PMGL_end); name = p; p += name_len;
          READ_ENCINT(section, PMGL_end);
          READ_ENCINT(offset, PMGL_end);
          READ_ENCINT(length, PMGL_end);
          printf("sec=%u off=%-10u len=%-10u name=\"",section,offset,length);
          if (name_len) fwrite(name, 1, name_len, stdout);
          printf("\"\n");
        }
      PMGL_end:
        if (j != num_entries) printf("premature end of chunk\n");

      }
      else if  ((chunk[0] == 'P') && (chunk[1] == 'M') &&
                (chunk[2] == 'G') && (chunk[3] == 'I'))
      {
        k = chm->chunk_size - 2;
        num_entries = chunk[k] | (chunk[k+1] << 8);
        quickref_size = EndGetI32(&chunk[4]);
        printf("    PMGI entries=%u free=%u\n", num_entries, quickref_size);

        printf("    QR: entry %4u = offset %u\n", 0, 8);
        j = (1 << chm->density) + 1;
        while (j < num_entries) {
          k -= 2;
          printf("    QR: entry %4u = offset %u\n",
                 j, (chunk[k] | (chunk[k+1] << 8)) + 8);
          j += (1 << chm->density) + 1;
        }

        p = &chunk[8];
        for (j = 0; j < num_entries; j++) {
          unsigned int name_len, section;
          printf("    %4d: ", (int) (p - &chunk[0]));
          READ_ENCINT(name_len, PMGI_end); name = p; p += name_len;
          READ_ENCINT(section, PMGI_end);
          printf("chunk=%-4u name=\"",section);
          if (name_len) fwrite(name, 1, name_len, stdout);
          printf("\"\n");
        }
      PMGI_end: 
        if (j != num_entries) printf("premature end of chunk\n");
      }
      else {
        printf("    unknown format\n");
      }
    }

    fclose(fh);
  }
}


int main(int argc, char *argv[]) {
  struct mschm_decompressor *chmd;
  struct mschmd_header *chm;
  struct mschmd_file *file;
  unsigned int numf, i;
  unsigned char *data;
  off_t pos, len;

  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  MSPACK_SYS_SELFTEST(i);
  if (i) return 0;

  if ((chmd = mspack_create_chm_decompressor(NULL))) {
    for (argv++; *argv; argv++) {
      printf("%s\n", *argv);
      if ((chm = chmd->open(chmd, *argv))) {
        printf("  chmhead_Version     %u\n",      chm->version);
        printf("  chmhead_Timestamp   %u\n",      chm->timestamp);
        printf("  chmhead_LanguageID  %u\n",      chm->language);
        printf("  chmhs0_FileLen      %" LD "\n", chm->length);
        printf("  chmhst_OffsetHS1    %" LD "\n", chm->dir_offset);
        printf("  chmhst3_OffsetCS0   %" LD "\n", chm->sec0.offset);

        print_dir(chm, *argv);

        if ((data = load_sys_data(chmd, chm,
             "::DataSpace/Storage/MSCompressed/ControlData", &len)))
        {
          printf("  lzxcd_Length        %u\n",    EndGetI32(&data[0]));
          printf("  lzxcd_Signature     %4.4s\n", &data[4]);
          printf("  lzxcd_Version       %u\n",    EndGetI32(&data[8]));
          printf("  lzxcd_ResetInterval %u\n",    EndGetI32(&data[12]));
          printf("  lzxcd_WindowSize    %u\n",    EndGetI32(&data[16]));
          printf("  lzxcd_CacheSize     %u\n",    EndGetI32(&data[20]));
          printf("  lzxcd_Unknown1      %u\n",    EndGetI32(&data[24]));
          free(data);
        }

        if ((data = load_sys_data(chmd, chm,
             "::DataSpace/Storage/MSCompressed/Transform/{7FC28940-"
             "9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/ResetTable", &len)))
        {
          off_t contents = chm->sec0.offset;
          printf("  lzxrt_Unknown1      %u\n",   EndGetI32(&data[0]));
          printf("  lzxrt_NumEntries    %u\n",   EndGetI32(&data[4]));
          printf("  lzxrt_EntrySize     %u\n",   EndGetI32(&data[8]));
          printf("  lzxrt_TableOffset   %u\n",   EndGetI32(&data[12]));
          printf("  lzxrt_UncompLen     %llu\n", EndGetI64(&data[16]));
          printf("  lzxrt_CompLen       %llu\n", EndGetI64(&data[24]));
          printf("  lzxrt_FrameLen      %u\n",   EndGetI32(&data[32]));

          for (file = chm->sysfiles; file; file = file->next) {
            if (strcmp(file->filename,
                       "::DataSpace/Storage/MSCompressed/Content") == 0)
            {
              contents += file->offset;
              break;
            }
          }

          printf("  - reset table (uncomp offset -> stream offset "
                 "[real offset, length in file]\n");

          numf = EndGetI32(&data[4]);
          pos = ((unsigned int) EndGetI32(&data[12]));
          switch (EndGetI32(&data[8])) {
          case 4:
            for (i = 0; i < numf && pos < len; i++, pos += 4) {
              unsigned int rtdata = EndGetI32(&data[pos]);
              printf("    %-10u -> %-10u [ %" LU " %u ]\n",
                     i * EndGetI32(&data[32]),
                     rtdata,
                     contents + rtdata,
                     (i == (numf-1))
                     ? (EndGetI32(&data[24]) - rtdata)
                     : (EndGetI32(&data[pos + 4]) - rtdata)
                     );
            }
            break;
          case 8:
            for (i = 0; i < numf && pos < len; i++, pos += 8) {
              unsigned long long int rtdata = EndGetI64(&data[pos]);
              printf("    %-10llu -> %-10llu [ %llu %llu ]\n",
                     i * EndGetI64(&data[32]), rtdata, contents + rtdata,
                     (i == (numf-1))
                     ? (EndGetI64(&data[24]) - rtdata)
                     : (EndGetI64(&data[pos + 8]) - rtdata)
                     );
            }
            break;
          }
          free(data);
        }
        chmd->close(chmd, chm);
      }
    }
    mspack_destroy_chm_decompressor(chmd);
  }
  return 0;
}
