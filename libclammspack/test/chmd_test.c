/* CHM regression test suite */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <mspack.h>
#include <md5_fh.h>

#define __tf3(x) #x
#define __tf2(x) __tf3(x)
#define TESTFILE(fname) (__tf2(TEST_FILES) "/" fname)

unsigned int test_count = 0;
#define TEST(x) do {\
    test_count++; \
    if (!(x)) {printf("%s:%d FAILED %s\n",__func__,__LINE__,#x);exit(1);} \
} while (0)

/* check opening bad files is rejected */
void chmd_open_test_01() {
    struct mschm_decompressor *chmd;
    unsigned int i;
    const char *files[] = {
        TESTFILE("cve-2017-6419-lzx-negative-spaninfo.chm"),
    };

    TEST(chmd = mspack_create_chm_decompressor(NULL));
    for (i = 0; i < (sizeof(files)/sizeof(char *)); i++) {
        TEST(!chmd->open(chmd, files[i]));
    }
    mspack_destroy_chm_decompressor(chmd);
}

/* check no files are returned with blank filenames */
void chmd_open_test_02() {
    struct mschm_decompressor *chmd;
    struct mschmd_header *chm;
    struct mschmd_file *f;
    unsigned int i;
    const char *files[] = {
        TESTFILE("cve-2018-14680-blank-filenames.chm"),
        TESTFILE("cve-2018-18585-blank-filenames.chm"),
    };

    TEST(chmd = mspack_create_chm_decompressor(NULL));
    for (i = 0; i < (sizeof(files)/sizeof(char *)); i++) {
        TEST(chm = chmd->open(chmd, files[i]));
        for (f = chm->files; f; f = f->next) {
            TEST(f->filename && f->filename[0]);
        }
        for (f = chm->sysfiles; f; f = f->next) {
            TEST(f->filename && f->filename[0]);
        }
        chmd->close(chmd, chm);
    }
    mspack_destroy_chm_decompressor(chmd);
}

/* check that files with a mix of normal and over-long ENCINTs for offsets
 * and lengths can be opened and all offsets/lengths are non-negative */
void chmd_open_test_03() {
    struct mschm_decompressor *chmd;
    struct mschmd_header *chm;
    struct mschmd_file *f;
    unsigned int i;
    const char *files[] = {
#if SIZEOF_OFF_T >= 8
        TESTFILE("encints-64bit-offsets.chm"),
        TESTFILE("encints-64bit-lengths.chm"),
        TESTFILE("encints-64bit-both.chm"),
#else
        TESTFILE("encints-32bit-offsets.chm"),
        TESTFILE("encints-32bit-lengths.chm"),
        TESTFILE("encints-32bit-both.chm"),
#endif
    };

    TEST(chmd = mspack_create_chm_decompressor(NULL));
    for (i = 0; i < (sizeof(files)/sizeof(char *)); i++) {
        TEST(chm = chmd->open(chmd, files[i]));
        for (f = chm->files; f; f = f->next) {
            TEST(f->offset >= 0);
            TEST(f->length >= 0);
        }
        chmd->close(chmd, chm);
    }
    mspack_destroy_chm_decompressor(chmd);
}

/* check searching bad files doesn't crash */
void chmd_search_test_01() {
    struct mschm_decompressor *chmd;
    struct mschmd_header *chm1, *chm2;
    struct mschmd_file *f, result;
    unsigned int i;
    const char *files[] = {
        TESTFILE("cve-2015-4468-namelen-bounds.chm"),
        TESTFILE("cve-2015-4469-namelen-bounds.chm"),
        TESTFILE("cve-2015-4472-namelen-bounds.chm"),
        TESTFILE("cve-2018-14679-off-by-one.chm"),
        TESTFILE("cve-2018-14682-unicode-u100.chm"),
        TESTFILE("cve-2019-1010305-name-overread.chm"),
    };

    TEST(chmd = mspack_create_chm_decompressor(NULL));
    for (i = 0; i < (sizeof(files)/sizeof(char *)); i++) {
        TEST(chm1 = chmd->open(chmd, files[i]));
        TEST(chm2 = chmd->fast_open(chmd, files[i]));
        for (f = chm1->files; f; f = f->next) {
            if (!chmd->fast_find(chmd, chm2, f->filename, &result, sizeof(result))) {
                TEST(f->offset == result.offset);
                TEST(f->length == result.length);
            }
        }
        chmd->close(chmd, chm2);
        chmd->close(chmd, chm1);
    }
    mspack_destroy_chm_decompressor(chmd);
}

static int read_xor(struct mspack_file *file, void *buffer, int bytes) {
  int read = read_files_write_md5.read(file, buffer, bytes);
  if (read > 0) {
      char *p = (char *) buffer, *end = &p[read];
      while (p < end) *p++ ^= 0xFF;
  }
  return read;
}

/* check extracting bad files doesn't crash */
void chmd_extract_test_01() {
    struct mschm_decompressor *chmd;
    struct mschmd_header *chm;
    struct mschmd_file *f;

    /* create an mspack_system that XORs the files it reads */
    struct mspack_system xor_files = read_files_write_md5;
    xor_files.read = &read_xor;

    /* source file is obfuscated with XOR because clamav calls it
     * "BC.Legacy.Exploit.CVE_2012_1458-1" and blocks distributing libmspack
     * https://github.com/kyz/libmspack/issues/17#issuecomment-411583917 */
    TEST(chmd = mspack_create_chm_decompressor(&xor_files));
    TEST(chm = chmd->open(chmd, TESTFILE("cve-2015-4467-reset-interval-zero.chm.xor")));
    for (f = chm->files; f; f = f->next) {
        chmd->extract(chmd, f, NULL);
    }
    chmd->close(chmd, chm);
    mspack_destroy_chm_decompressor(chmd);
}


int main() {
  int selftest;

  MSPACK_SYS_SELFTEST(selftest);
  TEST(selftest == MSPACK_ERR_OK);

  chmd_open_test_01();
  chmd_open_test_02();
  chmd_open_test_03();
  chmd_search_test_01();
  chmd_extract_test_01();

  printf("ALL %d TESTS PASSED.\n", test_count);
  return 0;
}
