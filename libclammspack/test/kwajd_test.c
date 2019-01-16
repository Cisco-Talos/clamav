/* KWAJ regression test suite */

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

/* test parsing of KWAJ filename/extension headers */
void kwajd_open_test_01() {
    struct mskwaj_decompressor *kwajd;
    struct mskwajd_header *hdr;

    kwajd = mspack_create_kwaj_decompressor(NULL);
    TEST(kwajd != NULL);

    hdr = kwajd->open(kwajd, "test_files/kwajd/f00.kwj");
    TEST(hdr != NULL);
    TEST(hdr->filename == NULL);
    kwajd->close(kwajd, hdr);

#define TEST_FNAME(testfile, fname)      \
    hdr = kwajd->open(kwajd, testfile);  \
    TEST(hdr != NULL);                   \
    TEST(hdr->filename != NULL);         \
    TEST(!strcmp(fname, hdr->filename)); \
    kwajd->close(kwajd, hdr)
#define TEST_FNAME_BAD(testfile)         \
    hdr = kwajd->open(kwajd, testfile);  \
    TEST(hdr == NULL);                   \
    TEST(kwajd->last_error(kwajd) == MSPACK_ERR_DATAFORMAT)

    TEST_FNAME("test_files/kwajd/f01.kwj", ".1");
    TEST_FNAME("test_files/kwajd/f02.kwj", ".12");
    TEST_FNAME("test_files/kwajd/f03.kwj", ".123");

    TEST_FNAME("test_files/kwajd/f10.kwj", "1");
    TEST_FNAME("test_files/kwajd/f11.kwj", "1.1");
    TEST_FNAME("test_files/kwajd/f12.kwj", "1.12");
    TEST_FNAME("test_files/kwajd/f13.kwj", "1.123");

    TEST_FNAME("test_files/kwajd/f20.kwj", "12");
    TEST_FNAME("test_files/kwajd/f21.kwj", "12.1");
    TEST_FNAME("test_files/kwajd/f22.kwj", "12.12");
    TEST_FNAME("test_files/kwajd/f23.kwj", "12.123");

    TEST_FNAME("test_files/kwajd/f30.kwj", "123");
    TEST_FNAME("test_files/kwajd/f31.kwj", "123.1");
    TEST_FNAME("test_files/kwajd/f32.kwj", "123.12");
    TEST_FNAME("test_files/kwajd/f33.kwj", "123.123");

    TEST_FNAME("test_files/kwajd/f40.kwj", "1234");
    TEST_FNAME("test_files/kwajd/f41.kwj", "1234.1");
    TEST_FNAME("test_files/kwajd/f42.kwj", "1234.12");
    TEST_FNAME("test_files/kwajd/f43.kwj", "1234.123");

    TEST_FNAME("test_files/kwajd/f50.kwj", "12345");
    TEST_FNAME("test_files/kwajd/f51.kwj", "12345.1");
    TEST_FNAME("test_files/kwajd/f52.kwj", "12345.12");
    TEST_FNAME("test_files/kwajd/f53.kwj", "12345.123");

    TEST_FNAME("test_files/kwajd/f60.kwj", "123456");
    TEST_FNAME("test_files/kwajd/f61.kwj", "123456.1");
    TEST_FNAME("test_files/kwajd/f62.kwj", "123456.12");
    TEST_FNAME("test_files/kwajd/f63.kwj", "123456.123");

    TEST_FNAME("test_files/kwajd/f70.kwj", "1234567");
    TEST_FNAME("test_files/kwajd/f71.kwj", "1234567.1");
    TEST_FNAME("test_files/kwajd/f72.kwj", "1234567.12");
    TEST_FNAME("test_files/kwajd/f73.kwj", "1234567.123");

    TEST_FNAME("test_files/kwajd/f80.kwj", "12345678");
    TEST_FNAME("test_files/kwajd/f81.kwj", "12345678.1");
    TEST_FNAME("test_files/kwajd/f82.kwj", "12345678.12");
    TEST_FNAME("test_files/kwajd/f83.kwj", "12345678.123");

    TEST_FNAME_BAD("test_files/kwajd/f04.kwj");
    TEST_FNAME_BAD("test_files/kwajd/f14.kwj");
    TEST_FNAME_BAD("test_files/kwajd/f24.kwj");
    TEST_FNAME_BAD("test_files/kwajd/f34.kwj");
    TEST_FNAME_BAD("test_files/kwajd/f44.kwj");
    TEST_FNAME_BAD("test_files/kwajd/f54.kwj");
    TEST_FNAME_BAD("test_files/kwajd/f64.kwj");
    TEST_FNAME_BAD("test_files/kwajd/f74.kwj");
    TEST_FNAME_BAD("test_files/kwajd/f84.kwj");

    TEST_FNAME_BAD("test_files/kwajd/f90.kwj");
    TEST_FNAME_BAD("test_files/kwajd/f91.kwj");
    TEST_FNAME_BAD("test_files/kwajd/f92.kwj");
    TEST_FNAME_BAD("test_files/kwajd/f93.kwj");
    TEST_FNAME_BAD("test_files/kwajd/f94.kwj");


    mspack_destroy_kwaj_decompressor(kwajd);
}

int main() {
  int selftest;

  MSPACK_SYS_SELFTEST(selftest);
  TEST(selftest == MSPACK_ERR_OK);

  kwajd_open_test_01();

  printf("ALL %d TESTS PASSED.\n", test_count);
  return 0;
}
