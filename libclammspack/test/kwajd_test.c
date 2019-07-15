/* KWAJ regression test suite */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mspack.h>
#include <system.h>

#define __tf3(x) #x
#define __tf2(x) __tf3(x)
#define TESTFILE(fname) (__tf2(TEST_FILES) "/" fname)

unsigned int test_count = 0;
#define TEST(x) do {\
    test_count++; \
    if (!(x)) {printf("%s:%d FAILED %s\n",__func__,__LINE__,#x);exit(1);} \
} while (0)

/* test parsing of KWAJ filename/extension headers */
void kwajd_open_test_01() {
    struct mskwaj_decompressor *kwajd;
    struct mskwajd_header *hdr;

    TEST(kwajd = mspack_create_kwaj_decompressor(NULL));

    TEST(hdr = kwajd->open(kwajd, TESTFILE("f00.kwj")));
    TEST(hdr->filename == NULL);
    kwajd->close(kwajd, hdr);

#define GOOD(testfile, fname)                             \
    TEST(hdr = kwajd->open(kwajd, testfile));             \
    TEST(hdr->filename && !strcmp(fname, hdr->filename)); \
    kwajd->close(kwajd, hdr)

#define BAD(testfile)                    \
    TEST(!kwajd->open(kwajd, testfile)); \
    TEST(kwajd->last_error(kwajd) == MSPACK_ERR_DATAFORMAT)

    GOOD(TESTFILE("f01.kwj"), ".1");
    GOOD(TESTFILE("f02.kwj"), ".12");
    GOOD(TESTFILE("f03.kwj"), ".123");

    GOOD(TESTFILE("f10.kwj"), "1");
    GOOD(TESTFILE("f11.kwj"), "1.1");
    GOOD(TESTFILE("f12.kwj"), "1.12");
    GOOD(TESTFILE("f13.kwj"), "1.123");

    GOOD(TESTFILE("f20.kwj"), "12");
    GOOD(TESTFILE("f21.kwj"), "12.1");
    GOOD(TESTFILE("f22.kwj"), "12.12");
    GOOD(TESTFILE("f23.kwj"), "12.123");

    GOOD(TESTFILE("f30.kwj"), "123");
    GOOD(TESTFILE("f31.kwj"), "123.1");
    GOOD(TESTFILE("f32.kwj"), "123.12");
    GOOD(TESTFILE("f33.kwj"), "123.123");

    GOOD(TESTFILE("f40.kwj"), "1234");
    GOOD(TESTFILE("f41.kwj"), "1234.1");
    GOOD(TESTFILE("f42.kwj"), "1234.12");
    GOOD(TESTFILE("f43.kwj"), "1234.123");

    GOOD(TESTFILE("f50.kwj"), "12345");
    GOOD(TESTFILE("f51.kwj"), "12345.1");
    GOOD(TESTFILE("f52.kwj"), "12345.12");
    GOOD(TESTFILE("f53.kwj"), "12345.123");

    GOOD(TESTFILE("f60.kwj"), "123456");
    GOOD(TESTFILE("f61.kwj"), "123456.1");
    GOOD(TESTFILE("f62.kwj"), "123456.12");
    GOOD(TESTFILE("f63.kwj"), "123456.123");

    GOOD(TESTFILE("f70.kwj"), "1234567");
    GOOD(TESTFILE("f71.kwj"), "1234567.1");
    GOOD(TESTFILE("f72.kwj"), "1234567.12");
    GOOD(TESTFILE("f73.kwj"), "1234567.123");

    GOOD(TESTFILE("f80.kwj"), "12345678");
    GOOD(TESTFILE("f81.kwj"), "12345678.1");
    GOOD(TESTFILE("f82.kwj"), "12345678.12");
    GOOD(TESTFILE("f83.kwj"), "12345678.123");

    BAD(TESTFILE("f04.kwj"));
    BAD(TESTFILE("f14.kwj"));
    BAD(TESTFILE("f24.kwj"));
    BAD(TESTFILE("f34.kwj"));
    BAD(TESTFILE("f44.kwj"));
    BAD(TESTFILE("f54.kwj"));
    BAD(TESTFILE("f64.kwj"));
    BAD(TESTFILE("f74.kwj"));
    BAD(TESTFILE("f84.kwj"));

    BAD(TESTFILE("f90.kwj"));
    BAD(TESTFILE("f91.kwj"));
    BAD(TESTFILE("f92.kwj"));
    BAD(TESTFILE("f93.kwj"));
    BAD(TESTFILE("f94.kwj"));

#undef GOOD
#undef BAD

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
