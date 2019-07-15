/* cabinet decompression regression test suite */

#ifdef HAVE_CONFIG_H
# include <config.h>
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

/* open where cab file doesn't exist */
void cabd_open_test_01() {
    struct mscab_decompressor *cabd;

    TEST(cabd = mspack_create_cab_decompressor(NULL));
    TEST(!cabd->open(cabd, "!!!FILE_WHICH_DOES_NOT_EXIST"));
    TEST(cabd->last_error(cabd) == MSPACK_ERR_OPEN);

    mspack_destroy_cab_decompressor(cabd);
}

/* normal cab file with 2 files and one folder.
 * check ALL headers are read correctly */
void cabd_open_test_02() {
    struct mscab_decompressor *cabd;
    struct mscabd_cabinet *cab;
    struct mscabd_folder *folder;
    struct mscabd_file *file;

    TEST(cabd = mspack_create_cab_decompressor(NULL));
    TEST(cab = cabd->open(cabd, TESTFILE("normal_2files_1folder.cab")));

    TEST(cab->next == NULL);
    TEST(cab->base_offset == 0);
    TEST(cab->length == 253);
    TEST(cab->prevcab == NULL); TEST(cab->nextcab == NULL);
    TEST(cab->prevname == NULL); TEST(cab->nextname == NULL);
    TEST(cab->previnfo == NULL); TEST(cab->nextinfo == NULL);
    TEST(cab->set_id = 1570); TEST(cab->set_index == 0);
    TEST(cab->header_resv == 0);
    TEST(cab->flags == 0);

    TEST(folder = cab->folders);
    TEST(folder->next == NULL);
    TEST(folder->comp_type == 0);
    TEST(folder->num_blocks == 1);

    file = cab->files;
    TEST(file && !strcmp(file->filename, "hello.c"));
    TEST(file->length == 77);
    TEST(file->attribs == 0x20);
    TEST(file->time_h == 11);TEST(file->time_m == 13);TEST(file->time_s == 52);
    TEST(file->date_d == 12);TEST(file->date_m == 3);TEST(file->date_y == 1997);
    TEST(file->folder == folder); TEST(file->offset == 0);

    file = file->next;
    TEST(file && !strcmp(file->filename, "welcome.c"));
    TEST(file->length == 74);
    TEST(file->attribs == 0x20);
    TEST(file->time_h == 11);TEST(file->time_m == 15);TEST(file->time_s == 14);
    TEST(file->date_d == 12);TEST(file->date_m == 3);TEST(file->date_y == 1997);
    TEST(file->folder == folder); TEST(file->offset == 77);

    TEST(file->next == NULL);

    cabd->close(cabd, cab);
    mspack_destroy_cab_decompressor(cabd);
}

/* cabs with reserve headers set, ensure they all load correctly */
void cabd_open_test_03() {
    struct mscab_decompressor *cabd;
    struct mscabd_cabinet *cab;
    unsigned int i;
    const char *files[] = {
        TESTFILE("reserve_---.cab"),
        TESTFILE("reserve_--D.cab"),
        TESTFILE("reserve_-F-.cab"),
        TESTFILE("reserve_-FD.cab"),
        TESTFILE("reserve_H--.cab"),
        TESTFILE("reserve_H-D.cab"),
        TESTFILE("reserve_HF-.cab"),
        TESTFILE("reserve_HFD.cab"),
    };

    TEST(cabd = mspack_create_cab_decompressor(NULL));

    for (i = 0; i < (sizeof(files)/sizeof(char *)); i++) {
        TEST(cab = cabd->open(cabd, files[i]));
        TEST(cab->files && !strcmp(cab->files->filename, "test1.txt"));
        TEST(cab->files->next && !strcmp(cab->files->next->filename, "test2.txt"));
        cabd->close(cabd, cab);
    }

    mspack_destroy_cab_decompressor(cabd);
}

/* some bad cabs, should not load */
void cabd_open_test_04() {
    struct mscab_decompressor *cabd;

    TEST(cabd = mspack_create_cab_decompressor(NULL));

    /* cab has enough data for a header, but does not contain real cab data
     * result should be MSPACK_ERR_SIGNATURE */
    TEST(!cabd->open(cabd, TESTFILE("bad_signature.cab")));
    TEST(cabd->last_error(cabd) == MSPACK_ERR_SIGNATURE);

    /* cab has 0 folders */
    TEST(!cabd->open(cabd, TESTFILE("bad_nofolders.cab")));

    /* cab has 0 files */
    TEST(!cabd->open(cabd, TESTFILE("bad_nofiles.cab")));

    /* second file in the cab has a folder index for a non-existant folder */
    TEST(!cabd->open(cabd, TESTFILE("bad_folderindex.cab")));

    /* cab has one file with empty filename */
    TEST(!cabd->open(cabd, TESTFILE("filename-read-violation-1.cab")));

    mspack_destroy_cab_decompressor(cabd);
}

/* cabs which have been cut short
 * result should be MSPACK_ERR_READ for missing headers or
 * MSPACK_ERR_DATAFORMAT for missing/partial strings.
 * If only data blocks are missing, the cab should open()
 */
void cabd_open_test_05() {
    struct mscab_decompressor *cabd;
    struct mscabd_cabinet *cab;
    unsigned int i;
    const char *files[] = {
        TESTFILE("partial_shortheader.cab"),
        TESTFILE("partial_shortextheader.cab"),
        TESTFILE("partial_nofolder.cab"),
        TESTFILE("partial_shortfolder.cab"),
        TESTFILE("partial_nofiles.cab"),
        TESTFILE("partial_shortfile1.cab"),
        TESTFILE("partial_shortfile2.cab"),
    };
    const char *str_files[] = {
        TESTFILE("partial_str_nopname.cab"),
        TESTFILE("partial_str_shortpname.cab"),
        TESTFILE("partial_str_nopinfo.cab"),
        TESTFILE("partial_str_shortpinfo.cab"),
        TESTFILE("partial_str_nonname.cab"),
        TESTFILE("partial_str_shortnname.cab"),
        TESTFILE("partial_str_noninfo.cab"),
        TESTFILE("partial_str_shortninfo.cab"),
        TESTFILE("partial_str_nofname.cab"),
        TESTFILE("partial_str_shortfname.cab"),
    };

    TEST(cabd = mspack_create_cab_decompressor(NULL));

    for (i = 0; i < (sizeof(files)/sizeof(char *)); i++) {
        TEST(!cabd->open(cabd, files[i]));
        TEST(cabd->last_error(cabd) == MSPACK_ERR_READ);
    }

    for (i = 0; i < (sizeof(str_files)/sizeof(char *)); i++) {
        TEST(!cabd->open(cabd, str_files[i]));
        TEST(cabd->last_error(cabd) == MSPACK_ERR_DATAFORMAT ||
             cabd->last_error(cabd) == MSPACK_ERR_READ);
    }

    /* lack of data blocks should NOT be a problem for merely reading */
    TEST(cab = cabd->open(cabd, TESTFILE("partial_nodata.cab")));
    cabd->close(cabd, cab);
    mspack_destroy_cab_decompressor(cabd);
}

/* open cab with 255 character filename (maximum allowed) */
void cabd_open_test_06() {
    struct mscab_decompressor *cabd;
    struct mscabd_cabinet *cab;

    TEST(cabd = mspack_create_cab_decompressor(NULL));
    TEST(cab = cabd->open(cabd, TESTFILE("normal_255c_filename.cab")));

    cabd->close(cabd, cab);
    mspack_destroy_cab_decompressor(cabd);
}


/* open where search file doesn't exist */
void cabd_search_test_01() {
    struct mscab_decompressor *cabd;

    TEST(cabd = mspack_create_cab_decompressor(NULL));
    TEST(!cabd->search(cabd, "!!!FILE_WHICH_DOES_NOT_EXIST"));
    TEST(cabd->last_error(cabd) == MSPACK_ERR_OPEN);

    mspack_destroy_cab_decompressor(cabd);
}
  
/* search file using 1-byte buffer */
void cabd_search_test_02() {
    struct mscab_decompressor *cabd;
    struct mscabd_cabinet *cab;

    TEST(cabd = mspack_create_cab_decompressor(NULL));
    cabd->set_param(cabd, MSCABD_PARAM_SEARCHBUF, 1);
    TEST(cab = cabd->search(cabd, TESTFILE("search_basic.cab")));

    TEST(cab->base_offset == 6);
    TEST(cab->files && !strcmp(cab->files->filename, "hello.c"));
    TEST(cab->files->next && !strcmp(cab->files->next->filename, "welcome.c"));

    TEST(cab->next != NULL);
    TEST(cab->next->base_offset == 265);
    TEST(cab->next->files && !strcmp(cab->next->files->filename, "hello.c"));
    TEST(cab->next->files->next && !strcmp(cab->next->files->next->filename, "welcome.c"));

    TEST(cab->next->next == NULL);

    cabd->close(cabd, cab);
    mspack_destroy_cab_decompressor(cabd);
}

/* tricky searches */
void cabd_search_test_03() {
    struct mscab_decompressor *cabd;
    struct mscabd_cabinet *cab;

    TEST(cabd = mspack_create_cab_decompressor(NULL));

    /* there is only ONE cab in this file. it is prepended by 4 bytes, "MSCF"
     * (heh) and reserved fields in the real cab are filled in so the fake one
     * looks real to the scanner but not the real reader
     */
    TEST(cab = cabd->search(cabd, TESTFILE("search_tricky1.cab")));
    TEST(cab->next == NULL);
    TEST(cab->base_offset == 4);
    TEST(cab->files && !strcmp(cab->files->filename, "hello.c"));
    TEST(cab->files->next && !strcmp(cab->files->next->filename, "welcome.c"));

    cabd->close(cabd, cab);
    mspack_destroy_cab_decompressor(cabd);
}

/* basic parameter failures */
void cabd_merge_test_01() {
    struct mscab_decompressor *cabd;
    struct mscabd_cabinet *cab1, *cab2;

    TEST(cabd = mspack_create_cab_decompressor(NULL));
    TEST(cab1 = cabd->open(cabd, TESTFILE("multi_basic_pt1.cab")));
    TEST(cab2 = cabd->open(cabd, TESTFILE("multi_basic_pt2.cab")));

    TEST(cabd->append(cabd,  cab1, NULL) != MSPACK_ERR_OK);
    TEST(cabd->append(cabd,  NULL, cab1) != MSPACK_ERR_OK);
    TEST(cabd->append(cabd,  cab1, cab1) != MSPACK_ERR_OK);
    TEST(cabd->prepend(cabd, cab1, NULL) != MSPACK_ERR_OK);
    TEST(cabd->prepend(cabd, NULL, cab1) != MSPACK_ERR_OK);
    TEST(cabd->prepend(cabd, cab1, cab1) != MSPACK_ERR_OK);

    /* merge cabs, then try merging again every other way */
    TEST(cabd->append(cabd,  cab1, cab2) == MSPACK_ERR_OK);
    TEST(cabd->append(cabd,  cab2, cab1) != MSPACK_ERR_OK);
    TEST(cabd->prepend(cabd, cab1, cab2) != MSPACK_ERR_OK);
    TEST(cabd->prepend(cabd, cab2, cab1) != MSPACK_ERR_OK);
    TEST(cabd->append(cabd,  cab1, cab2) != MSPACK_ERR_OK);

    cabd->close(cabd, cab1);
    mspack_destroy_cab_decompressor(cabd);
}
  
/* test merging a normal 5 part single folder cabinet set with slightly
 * haphazard ordering.  should still merge fine */
void cabd_merge_test_02() {
    struct mscab_decompressor *cabd;
    struct mscabd_cabinet *cab[5];

    TEST(cabd = mspack_create_cab_decompressor(NULL));
    TEST(cab[0] = cabd->open(cabd, TESTFILE("multi_basic_pt1.cab")));
    TEST(cab[1] = cabd->open(cabd, TESTFILE("multi_basic_pt2.cab")));
    TEST(cab[2] = cabd->open(cabd, TESTFILE("multi_basic_pt3.cab")));
    TEST(cab[3] = cabd->open(cabd, TESTFILE("multi_basic_pt4.cab")));
    TEST(cab[4] = cabd->open(cabd, TESTFILE("multi_basic_pt5.cab")));

    TEST(cabd->append(cabd,  cab[0], cab[1]) == MSPACK_ERR_OK);
    TEST(cabd->prepend(cabd, cab[2], cab[1]) == MSPACK_ERR_OK);
    TEST(cabd->append(cabd,  cab[3], cab[4]) == MSPACK_ERR_OK);
    TEST(cabd->prepend(cabd, cab[3], cab[2]) == MSPACK_ERR_OK);

    TEST(cab[0]->files != NULL);
    TEST(cab[0]->files->next != NULL);
    TEST(cab[0]->files->next->next != NULL);
    TEST(cab[0]->files->next->next->next == NULL);
    TEST(cab[0]->files == cab[1]->files);
    TEST(cab[1]->files == cab[2]->files);
    TEST(cab[2]->files == cab[3]->files);
    TEST(cab[3]->files == cab[4]->files);

    TEST(cab[0]->folders != NULL);
    TEST(cab[0]->folders->next == NULL);
    TEST(cab[0]->folders == cab[1]->folders);
    TEST(cab[1]->folders == cab[2]->folders);
    TEST(cab[2]->folders == cab[3]->folders);
    TEST(cab[3]->folders == cab[4]->folders);

    cabd->close(cabd, cab[0]);
    mspack_destroy_cab_decompressor(cabd);
}

/* test bad cabinets cannot be extracted */
void cabd_extract_test_01() {
    struct mscab_decompressor *cabd;
    struct mscabd_cabinet *cab;
    struct mscabd_file *file;
    unsigned int i;
    const char *files[] = {
        TESTFILE("cve-2010-2800-mszip-infinite-loop.cab"),
        TESTFILE("cve-2014-9556-qtm-infinite-loop.cab"),
        TESTFILE("cve-2015-4470-mszip-over-read.cab"),
        TESTFILE("cve-2015-4471-lzx-under-read.cab"),
        TESTFILE("filename-read-violation-2.cab"),
        TESTFILE("filename-read-violation-3.cab"),
        TESTFILE("filename-read-violation-4.cab"),
        TESTFILE("lzx-main-tree-no-lengths.cab"),
        TESTFILE("lzx-premature-matches.cab"),
        TESTFILE("qtm-max-size-block.cab"),
    };

    TEST(cabd = mspack_create_cab_decompressor(NULL));

    for (i = 0; i < (sizeof(files)/sizeof(char *)); i++) {
        TEST(cab = cabd->open(cabd, files[i]));
        TEST(cab->files != NULL);
        for (file = cab->files; file; file = file->next) {
            int err = cabd->extract(cabd, file, "/dev/null");
            TEST(err == MSPACK_ERR_DATAFORMAT || err == MSPACK_ERR_DECRUNCH);
        }
        cabd->close(cabd, cab);
    }
    mspack_destroy_cab_decompressor(cabd);
}

/* test that CVE-2014-9732 is fixed */
void cabd_extract_test_02() {
    struct mscab_decompressor *cabd;
    struct mscabd_cabinet *cab;
    int err;

    /* the first file in this cabinet belongs to a valid folder. The
     * second belongs to an invalid folder. Unpacking files 1, 2, 1
     * caused cabd.c to try and free the invalid folder state left by
     * extracting from folder 2, which caused a jump to NULL / segfault
     */
    TEST(cabd = mspack_create_cab_decompressor(NULL));
    TEST(cab = cabd->open(cabd, TESTFILE("cve-2014-9732-folders-segfault.cab")));
    err = cabd->extract(cabd, cab->files, "/dev/null");
    TEST(err == MSPACK_ERR_OK);
    err = cabd->extract(cabd, cab->files->next, "/dev/null");
    TEST(err == MSPACK_ERR_DATAFORMAT || err == MSPACK_ERR_DECRUNCH);
    err = cabd->extract(cabd, cab->files, "/dev/null");
    TEST(err == MSPACK_ERR_OK);
    cabd->close(cabd, cab);
    mspack_destroy_cab_decompressor(cabd);
}

#include <md5_fh.h>

/* test that extraction works with all compression methods */
void cabd_extract_test_03() {
    struct mscab_decompressor *cabd;
    struct mscabd_cabinet *cab;

    cabd = mspack_create_cab_decompressor(&read_files_write_md5);
    TEST(cabd != NULL);
    cab = cabd->open(cabd, TESTFILE("mszip_lzx_qtm.cab"));
    TEST(cab != NULL);

    /* extract mszip.txt */
    TEST(cabd->extract(cabd, cab->files, NULL) == MSPACK_ERR_OK);
    TEST(memcmp(md5_string, "940cba86658fbceb582faecd2b5975d1", 33) == 0);
    /* extract lzx.txt */
    TEST(cabd->extract(cabd, cab->files->next, NULL) == MSPACK_ERR_OK);
    TEST(memcmp(md5_string, "703474293b614e7110b3eb8ac2762b53", 33) == 0);
    /* extract qtm.txt */
    TEST(cabd->extract(cabd, cab->files->next->next, NULL) == MSPACK_ERR_OK);
    TEST(memcmp(md5_string, "98fcfa4962a0f169a3c7fdbcb445cf17", 33) == 0);

    cabd->close(cabd, cab);
    mspack_destroy_cab_decompressor(cabd);
}


/* test that extraction works with multiple compression methods in any order */
void cabd_extract_test_04() {
    struct mscab_decompressor *cabd;
    struct mscabd_cabinet *cab;
    struct mscabd_file *f, *files[4];
    char file_md5s[4][33];
    int i, err;

    cabd = mspack_create_cab_decompressor(&read_files_write_md5);
    TEST(cabd != NULL);
    cab = cabd->open(cabd, TESTFILE("normal_2files_2folders.cab"));
    TEST(cab != NULL);

    /* extract each file once, in order, keep its md5 checksum */
    for (f = cab->files, i = 0; i < 4 && f; i++, f=f->next) {
        files[i] = f;
        err = cabd->extract(cabd, files[i], NULL);
        TEST(err == MSPACK_ERR_OK);
        memcpy(file_md5s[i], md5_string, 33);
    }
    TEST(i == 4);

    /* check extracting in any other permutation gives same result */
#define T1(i) TEST(cabd->extract(cabd, files[i], NULL) == MSPACK_ERR_OK); \
              TEST(memcmp(file_md5s[i], md5_string, 33) == 0)
#define T(a,b,c,d) T1(a); T1(b); T1(c); T1(d)
    /*------*/  T(0,1,3,2); T(0,2,1,3); T(0,2,3,1); T(0,3,1,2); T(0,3,2,1);
    T(1,0,2,3); T(1,0,3,2); T(1,2,0,3); T(1,2,3,0); T(1,3,0,2); T(1,3,2,0);
    T(2,0,1,3); T(2,0,3,1); T(2,1,0,3); T(2,1,3,0); T(2,3,0,1); T(2,3,1,0);
    T(3,0,1,2); T(3,0,2,1); T(3,1,0,2); T(3,1,2,0); T(3,2,0,1); T(3,2,1,0);
#undef T
#undef T1

    cabd->close(cabd, cab);
    mspack_destroy_cab_decompressor(cabd);
}

int main() {
    int selftest;

    MSPACK_SYS_SELFTEST(selftest);
    TEST(selftest == MSPACK_ERR_OK);

    cabd_open_test_01();
    cabd_open_test_02();
    cabd_open_test_03();
    cabd_open_test_04();
    cabd_open_test_05();
    cabd_open_test_06();

    cabd_search_test_01();
    cabd_search_test_02();
    cabd_search_test_03();

    cabd_merge_test_01();
    cabd_merge_test_02();

    cabd_extract_test_01();
    cabd_extract_test_02();
    cabd_extract_test_03();
    cabd_extract_test_04();

    printf("ALL %d TESTS PASSED.\n", test_count);
    return 0;
}
