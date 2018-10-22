/* CHM regression test suite */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mspack.h>
#include <system.h>

unsigned int test_count = 0;
#define TEST(x) do {\
    test_count++; \
    if (!(x)) {printf("%s:%d FAILED %s\n",__func__,__LINE__,#x);exit(1);} \
} while (0)

/* check opening bad files is rejected */
void chmd_open_test_01() {
    struct mschm_decompressor *chmd;
    struct mschmd_header *chm;
    unsigned int i;
    const char *files[] = {
        "test_files/chmd/cve-2017-6419-lzx-negative-spaninfo.chm"
    };

    chmd =  mspack_create_chm_decompressor(NULL);
    TEST(chmd != NULL);
    for (i = 0; i < (sizeof(files)/sizeof(char *)); i++) {
        chm = chmd->open(chmd, files[i]);
        TEST(chm == NULL);
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
        "test_files/chmd/blank-filenames.chm"
    };

    chmd =  mspack_create_chm_decompressor(NULL);
    TEST(chmd != NULL);
    for (i = 0; i < (sizeof(files)/sizeof(char *)); i++) {
        chm = chmd->open(chmd, files[i]);
        TEST(chm != NULL);
        for (f = chm->files; f; f = f->next) {
            TEST(f->filename && f->filename[0]);
        }
        for (f = chm->sysfiles; f; f = f->next) {
            TEST(f->filename && f->filename[0]);
        }
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
        "test_files/chmd/cve-2015-4468-namelen-bounds.chm",
        "test_files/chmd/cve-2015-4469-namelen-bounds.chm",
        "test_files/chmd/cve-2015-4472-namelen-bounds.chm"
    };

    chmd =  mspack_create_chm_decompressor(NULL);
    TEST(chmd != NULL);
    for (i = 0; i < (sizeof(files)/sizeof(char *)); i++) {
        chm1 = chmd->open(chmd, files[i]);
        TEST(chm1 != NULL);
        chm2 = chmd->fast_open(chmd, files[i]);
        TEST(chm2 != NULL);
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

/* check extracting bad files doesn't crash */
void chmd_extract_test_01() {
    struct mschm_decompressor *chmd;
    struct mschmd_header *chm;
    struct mschmd_file *f;
    unsigned int i;
    const char *files[] = {
        "test_files/chmd/cve-2015-4467-reset-interval-zero.chm",
    };

    chmd = mspack_create_chm_decompressor(NULL);
    TEST(chmd != NULL);
    for (i = 0; i < (sizeof(files)/sizeof(char *)); i++) {
        chm = chmd->open(chmd, files[i]);
        TEST(chm != NULL);
        for (f = chm->files; f; f = f->next) {
            chmd->extract(chmd, f, "/dev/null");
        }
        chmd->close(chmd, chm);
    }
    mspack_destroy_chm_decompressor(chmd);
}

int main() {
  int selftest;

  MSPACK_SYS_SELFTEST(selftest);
  TEST(selftest == MSPACK_ERR_OK);

  chmd_open_test_01();
  chmd_open_test_02();
  chmd_search_test_01();
  chmd_extract_test_01();

  printf("ALL %d TESTS PASSED.\n", test_count);
  return 0;
}
