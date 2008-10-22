#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>

#include <stdlib.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <check.h>
#include "../libclamav/clamav.h"
#include "../libclamav/others.h"
#include "../libclamav/matcher.h"
#include "../libclamav/version.h"
#include "checks.h"

/* extern void cl_free(struct cl_engine *engine); */
START_TEST (test_cl_free)
/*
    struct cl_engine *engine = NULL;
    cl_free(NULL);
*/
END_TEST

/* extern struct cl_engine *cl_dup(struct cl_engine *engine); */
START_TEST (test_cl_dup)
    /*
    struct cl_engine *engine;
    fail_unless(NULL == cl_dup(NULL), "cl_dup null pointer");
    */
END_TEST

/* extern int cl_build(struct cl_engine *engine); */
START_TEST (test_cl_build)
    /*
    struct cl_engine *engine;
    fail_unless(CL_ENULLARG == cl_build(NULL), "cl_build null pointer");
    engine = calloc(sizeof(struct cl_engine),1);
    fail_unless(engine, "cl_build calloc");
    fail_unless(CL_ENULLARG == cl_build(engine), "cl_build(engine) with null ->root");
    */
/*    engine->root = cli_calloc(CL_TARGET_TABLE_SIZE, sizeof(struct cli_matcher *)); */
END_TEST

/* extern void cl_debug(void); */
START_TEST (test_cl_debug)
{
    int old_status = cli_debug_flag;
    cli_debug_flag = 0;
    cl_debug();
    fail_unless(1 == cli_debug_flag, "cl_debug failed to set cli_debug_flag");

    cli_debug_flag = 1;
    cl_debug();
    fail_unless(1 == cli_debug_flag, "cl_debug failed when flag was already set");
    cli_debug_flag = old_status;
}
END_TEST

/* extern const char *cl_retdbdir(void); */
START_TEST (test_cl_retdbdir)
    fail_unless(!strcmp(DATADIR, cl_retdbdir()), "cl_retdbdir");
END_TEST

#ifndef REPO_VERSION
#define REPO_VERSION VERSION
#endif

/* extern const char *cl_retver(void); */
START_TEST (test_cl_retver)
{
    const char *ver = cl_retver();
    fail_unless(!strcmp(REPO_VERSION""VERSION_SUFFIX, ver),"cl_retver");
    fail_unless(strcspn(ver,"012345789") < strlen(ver),
		    "cl_retver must have a number");
}
END_TEST

/* extern void cl_cvdfree(struct cl_cvd *cvd); */
START_TEST (test_cl_cvdfree)
/*
    struct cl_cvd *cvd1, *cvd2;

    cvd1 = malloc(sizeof(struct cl_cvd));
    fail_unless(cvd1, "cvd malloc");
    cl_cvdfree(cvd1);

    cvd2 = malloc(sizeof(struct cl_cvd));
    cvd2->time = malloc(1);
    cvd2->md5 = malloc(1);
    cvd2->dsig= malloc(1);
    cvd2->builder = malloc(1);
    fail_unless(cvd2, "cvd malloc");
    fail_unless(cvd2->time, "cvd malloc");
    fail_unless(cvd2->md5, "cvd malloc");
    fail_unless(cvd2->dsig, "cvd malloc");
    fail_unless(cvd2->builder, "cvd malloc");
    cl_cvdfree(cvd2);
    cl_cvdfree(NULL);
*/
END_TEST

/* extern int cl_statfree(struct cl_stat *dbstat); */
START_TEST (test_cl_statfree)
/*
    struct cl_stat *stat;
    fail_unless(CL_ENULLARG == cl_statfree(NULL), "cl_statfree(NULL)");
    
    stat = malloc(sizeof(struct cl_stat));
    fail_unless(NULL != stat, "malloc");
    fail_unless(CL_SUCCESS == cl_statfree(stat), "cl_statfree(empty_struct)");
    
    stat = malloc(sizeof(struct cl_stat));
    fail_unless(NULL != stat, "malloc");
    stat->stattab = strdup("test");
    fail_unless(NULL != stat->stattab, "strdup");
    fail_unless(CL_SUCCESS == cl_statfree(stat), "cl_statfree(stat with stattab)");

    stat = malloc(sizeof(struct cl_stat));
    fail_unless(NULL != stat, "malloc");
    stat->stattab = NULL;
    fail_unless(CL_SUCCESS == cl_statfree(stat), "cl_statfree(stat with stattab) set to NULL");
*/
END_TEST

/* extern unsigned int cl_retflevel(void); */
START_TEST (test_cl_retflevel)
END_TEST    

/* extern struct cl_cvd *cl_cvdhead(const char *file); */
START_TEST (test_cl_cvdhead)
/*
    fail_unless(NULL == cl_cvdhead(NULL), "cl_cvdhead(null)");
    fail_unless(NULL == cl_cvdhead("input/cl_cvdhead/1.txt"), "cl_cvdhead(515 byte file, all nulls)");
*/
    /* the data read from the file is passed to cl_cvdparse, test cases for that are separate */
END_TEST

/* extern struct cl_cvd *cl_cvdparse(const char *head); */
START_TEST (test_cl_cvdparse)
END_TEST

/* int cl_scandesc(int desc, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, const struct cl_limits *limits, unsigned int options) */
START_TEST (test_cl_scandesc)
END_TEST

/* int cl_scanfile(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, const struct cl_limits *limits, unsigned int options) */
START_TEST (test_cl_scanfile)
END_TEST

/* int cl_load(const char *path, struct cl_engine **engine, unsigned int *signo, unsigned int options) */
START_TEST (test_cl_load)
END_TEST

/* int cl_cvdverify(const char *file) */
START_TEST (test_cl_cvdverify)
END_TEST

/* int cl_statinidir(const char *dirname, struct cl_stat *dbstat) */
START_TEST (test_cl_statinidir)
END_TEST

/* int cl_statchkdir(const struct cl_stat *dbstat) */
START_TEST (test_cl_statchkdir)
END_TEST

/* void cl_settempdir(const char *dir, short leavetemps) */
START_TEST (test_cl_settempdir)
END_TEST

/* const char *cl_strerror(int clerror) */
START_TEST (test_cl_strerror)
END_TEST

static Suite *test_cl_suite(void)
{
    Suite *s = suite_create("cl_api");
    TCase *tc_cl = tcase_create("cl_dup");

    suite_add_tcase (s, tc_cl);
    tcase_add_test(tc_cl, test_cl_free);
    tcase_add_test(tc_cl, test_cl_dup);
    tcase_add_test(tc_cl, test_cl_build);
    tcase_add_test(tc_cl, test_cl_debug);
    tcase_add_test(tc_cl, test_cl_retdbdir);
    tcase_add_test(tc_cl, test_cl_retver);
    tcase_add_test(tc_cl, test_cl_cvdfree);
    tcase_add_test(tc_cl, test_cl_statfree);
    tcase_add_test(tc_cl, test_cl_retflevel);
    tcase_add_test(tc_cl, test_cl_cvdhead);
    tcase_add_test(tc_cl, test_cl_cvdparse);
    tcase_add_test(tc_cl, test_cl_scandesc);
    tcase_add_test(tc_cl, test_cl_scanfile);
    tcase_add_test(tc_cl, test_cl_load);
    tcase_add_test(tc_cl, test_cl_cvdverify);
    tcase_add_test(tc_cl, test_cl_statinidir);
    tcase_add_test(tc_cl, test_cl_statchkdir);
    tcase_add_test(tc_cl, test_cl_settempdir);
    tcase_add_test(tc_cl, test_cl_strerror);

    return s;
}

static uint8_t le_data[4] = {0x67,0x45,0x23,0x01};
static int32_t le_expected[4] = { 0x01234567, 0x67012345, 0x45670123, 0x23456701};
uint8_t *data = NULL;
uint8_t *data2 = NULL;
#define DATA_REP 100

static void data_setup(void)
{
        uint8_t *p;
        size_t i;

	data = malloc(sizeof(le_data)*DATA_REP);
	data2 = malloc(sizeof(le_data)*DATA_REP);
	fail_unless(!!data, "unable to allocate memory for fixture");
        fail_unless(!!data2, "unable to allocate memory for fixture");
        p = data;
        /* make multiple copies of le_data, we need to run readint tests in a loop, so we need
         * to give it some data to run it on */
        for(i=0; i<DATA_REP;i++) {
                memcpy(p, le_data, sizeof(le_data));
                p += sizeof(le_data);
        }
        memset(data2, 0, DATA_REP*sizeof(le_data));
}

static void data_teardown(void)
{
        free(data);
	free(data2);
}

#ifdef CHECK_HAVE_LOOPS
/* test reading with different alignments, _i is parameter from tcase_add_loop_test */
START_TEST (test_cli_readint16)
{
    size_t j;
    int16_t value;
    /* read 2 bytes apart, start is not always aligned*/
    for(j=_i;j <= DATA_REP*sizeof(le_data)-2;j += 2) {
        value = le_expected[j&3];
        fail_unless(cli_readint16(&data[j]) == value, "(1) data read must be little endian");
    }
    /* read 2 bytes apart, always aligned*/
    for(j=0;j <= DATA_REP*sizeof(le_data)-2;j += 2) {
        value = le_expected[j&3];
        fail_unless(cli_readint16(&data[j]) == value, "(2) data read must be little endian");
    }
}
END_TEST

/* test reading with different alignments, _i is parameter from tcase_add_loop_test */
START_TEST (test_cli_readint32)
{
    size_t j;
    int32_t value = le_expected[_i&3];
    /* read 4 bytes apart, start is not always aligned*/
    for(j=_i;j < DATA_REP*sizeof(le_data)-4;j += 4) {
        fail_unless(cli_readint32(&data[j]) == value, "(1) data read must be little endian");
    }
    value = le_expected[0];
    /* read 4 bytes apart, always aligned*/
    for(j=0;j < DATA_REP*sizeof(le_data)-4;j += 4) {
        fail_unless(cli_readint32(&data[j]) == value, "(2) data read must be little endian");
    }
}
END_TEST

/* test writing with different alignments, _i is parameter from tcase_add_loop_test */
START_TEST (test_cli_writeint32)
{
    size_t j;
    /* write 4 bytes apart, start is not always aligned*/
    for(j=_i;j < DATA_REP*sizeof(le_data) - 4;j += 4) {
        cli_writeint32(&data2[j], 0x12345678);
    }
    for(j=_i;j < DATA_REP*sizeof(le_data) - 4;j += 4) {
        fail_unless(cli_readint32(&data2[j]) == 0x12345678, "write/read mismatch");
    }
    /* write 4 bytes apart, always aligned*/
    for(j=0;j < DATA_REP*sizeof(le_data) - 4;j += 4) {
        cli_writeint32(&data2[j], 0x12345678);
    }
    for(j=0;j < DATA_REP*sizeof(le_data) - 4;j += 4) {
        fail_unless(cli_readint32(&data2[j]) == 0x12345678, "write/read mismatch");
    }
}
END_TEST

static Suite *test_cli_suite(void)
{
    Suite *s = suite_create("cli");
    TCase *tc_cli_others = tcase_create("byteorder_macros");

    suite_add_tcase (s, tc_cli_others);
    tcase_add_checked_fixture (tc_cli_others, data_setup, data_teardown);
    tcase_add_loop_test(tc_cli_others, test_cli_readint32, 0, 15);
    tcase_add_loop_test(tc_cli_others, test_cli_readint16, 0, 15);
    tcase_add_loop_test(tc_cli_others, test_cli_writeint32, 0, 15);

    return s;
}
#endif /* CHECK_HAVE_LOOPS */

void errmsg_expected(void)
{
	fputs("cli_errmsg() expected here\n", stderr);
}

int open_testfile(const char *name)
{
	int fd;
	const char * srcdir = getenv("srcdir");
	char *str;

	if(!srcdir) {
		/* when run from automake srcdir is set, but if run manually then not */
		srcdir = SRCDIR;
	}

	str = cli_malloc(strlen(name)+strlen(srcdir)+2);
	fail_unless(!!str, "cli_malloc");
	sprintf(str, "%s/%s", srcdir, name);

	fd = open(str, O_RDONLY);
	fail_unless_fmt(fd >= 0, "open() failed: %s", str);
	free(str);
	return fd;
}

void diff_file_mem(int fd, const char *ref, size_t len)
{
	char c1,c2;
	size_t p, reflen = len;
	char *buf = cli_malloc(len);

	fail_unless_fmt(!!buf, "unable to malloc buffer: %d", len);
	p = read(fd, buf, len);
	fail_unless_fmt(p == len,  "file is smaller: %lu, expected: %lu", p, len);
	p = 0;
	while(len > 0) {
		c1 = ref[p];
		c2 = buf[p];
		if(c1 != c2)
			break;
		p++;
		len--;
	}
	if (len > 0)
		fail_unless_fmt(c1 == c2, "file contents mismatch at byte: %lu, was: %c, expected: %c", p, c2, c1);
	free(buf);
	p = lseek(fd, 0, SEEK_END);
        fail_unless_fmt(p == reflen, "trailing garbage, file size: %ld, expected: %ld", p, reflen);
	close(fd);
}

void diff_files(int fd, int ref_fd)
{
	char *ref;
	ssize_t nread;
	off_t siz = lseek(ref_fd, 0, SEEK_END);
	fail_unless_fmt(siz != -1, "lseek failed");

	ref = cli_malloc(siz);
	fail_unless_fmt(!!ref, "unable to malloc buffer: %d", siz);

	fail_unless_fmt(lseek(ref_fd, 0, SEEK_SET) == 0,"lseek failed");
	nread = read(ref_fd, ref, siz);
        fail_unless_fmt(nread == siz, "short read, expected: %ld, was: %ld", siz, nread);
	close(ref_fd);
	diff_file_mem(fd, ref, siz);
	free(ref);
}

int main(int argc, char **argv)
{
    int nf;
    Suite *s = test_cl_suite();
    SRunner *sr = srunner_create(s);
#ifdef CHECK_HAVE_LOOPS
    srunner_add_suite(sr, test_cli_suite());
#else
    printf("*** Warning ***: your check version is too old,\nseveral important tests will not execute\n");
#endif
    srunner_add_suite(sr, test_jsnorm_suite());
    srunner_add_suite(sr, test_str_suite());
    srunner_add_suite(sr, test_regex_suite());
    srunner_add_suite(sr, test_disasm_suite());
    srunner_add_suite(sr, test_uniq_suite());
    srunner_add_suite(sr, test_matchers_suite());
    srunner_add_suite(sr, test_htmlnorm_suite());

    srunner_set_log(sr, "test.log");
    if(freopen("test-stderr.log","w+",stderr) == NULL) {
	    fputs("Unable to redirect stderr!\n",stderr);
    }
    cl_debug();

    srunner_run_all(sr, CK_NORMAL);
    nf = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (nf == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
