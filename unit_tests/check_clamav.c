#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>

#include <stdlib.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <check.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/mman.h>

#if HAVE_LIBXML2
#include <libxml/parser.h>
#endif

#include "../libclamav/clamav.h"
#include "../libclamav/others.h"
#include "../libclamav/matcher.h"
#include "../libclamav/version.h"
#include "../libclamav/dsig.h"
#include "../libclamav/fpu.h"
#include "../platform.h"
#include "checks.h"

static int fpu_words = FPU_ENDIAN_INITME;
#define NO_FPU_ENDIAN (fpu_words == FPU_ENDIAN_UNKNOWN)
#define EA06_SCAN strstr(file, "clam.ea06.exe")
#define FALSE_NEGATIVE (EA06_SCAN && NO_FPU_ENDIAN)

/* extern void cl_free(struct cl_engine *engine); */
START_TEST(test_cl_free)
/*
    struct cl_engine *engine = NULL;
    cl_free(NULL);
*/
END_TEST

/* extern struct cl_engine *cl_dup(struct cl_engine *engine); */
START_TEST(test_cl_dup)
/*
    struct cl_engine *engine;
    fail_unless(NULL == cl_dup(NULL), "cl_dup null pointer");
    */
END_TEST

/* extern int cl_build(struct cl_engine *engine); */
START_TEST(test_cl_build)
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
START_TEST(test_cl_debug)
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
START_TEST(test_cl_retdbdir)
fail_unless(!strcmp(DATADIR, cl_retdbdir()), "cl_retdbdir");
END_TEST

#ifndef REPO_VERSION
#define REPO_VERSION VERSION
#endif

/* extern const char *cl_retver(void); */
START_TEST(test_cl_retver)
{
    const char* ver = cl_retver();
    fail_unless(!strcmp(REPO_VERSION "" VERSION_SUFFIX, ver), "cl_retver");
    fail_unless(strcspn(ver, "012345789") < strlen(ver),
                "cl_retver must have a number");
}
END_TEST

/* extern void cl_cvdfree(struct cl_cvd *cvd); */
START_TEST(test_cl_cvdfree)
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
START_TEST(test_cl_statfree)
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
START_TEST(test_cl_retflevel)
END_TEST

/* extern struct cl_cvd *cl_cvdhead(const char *file); */
START_TEST(test_cl_cvdhead)
/*
    fail_unless(NULL == cl_cvdhead(NULL), "cl_cvdhead(null)");
    fail_unless(NULL == cl_cvdhead("input/cl_cvdhead/1.txt"), "cl_cvdhead(515 byte file, all nulls)");
*/
/* the data read from the file is passed to cl_cvdparse, test cases for that are separate */
END_TEST

/* extern struct cl_cvd *cl_cvdparse(const char *head); */
START_TEST(test_cl_cvdparse)
END_TEST

static int get_test_file(int i, char* file, unsigned fsize, unsigned long* size);
static struct cl_engine* g_engine;

#ifdef CHECK_HAVE_LOOPS
/* int cl_scandesc(int desc, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, const struct cl_limits *limits, struct cl_scan_options* options) */
START_TEST(test_cl_scandesc)
{
    const char* virname = NULL;
    char file[256];
    unsigned long size;
    unsigned long int scanned = 0;
    int ret;
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;

    int fd = get_test_file(_i, file, sizeof(file), &size);
    cli_dbgmsg("scanning (scandesc) %s\n", file);
    ret = cl_scandesc(fd, file, &virname, &scanned, g_engine, &options);
    cli_dbgmsg("scan end (scandesc) %s\n", file);

    if(!FALSE_NEGATIVE) {
        fail_unless_fmt(ret == CL_VIRUS, "cl_scandesc failed for %s: %s", file, cl_strerror(ret));
        fail_unless_fmt(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s", virname);
    }
    close(fd);
}
END_TEST

START_TEST(test_cl_scandesc_allscan)
{
    const char* virname = NULL;
    char file[256];
    unsigned long size;
    unsigned long int scanned = 0;
    int ret;
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;
    options.general |= CL_SCAN_GENERAL_ALLMATCHES;

    int fd = get_test_file(_i, file, sizeof(file), &size);
    cli_dbgmsg("scanning (scandesc) %s\n", file);
    ret = cl_scandesc(fd, file, &virname, &scanned, g_engine, &options);

    cli_dbgmsg("scan end (scandesc) %s\n", file);

    if(!FALSE_NEGATIVE) {
        fail_unless_fmt(ret == CL_VIRUS, "cl_scandesc_allscan failed for %s: %s", file, cl_strerror(ret));
        fail_unless_fmt(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s", virname);
    }
    close(fd);
}
END_TEST

//* int cl_scanfile(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, const struct cl_limits *limits, unsigned int options) */
START_TEST(test_cl_scanfile)
{
    const char* virname = NULL;
    char file[256];
    unsigned long size;
    unsigned long int scanned = 0;
    int ret;
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;

    int fd = get_test_file(_i, file, sizeof(file), &size);
    close(fd);

    cli_dbgmsg("scanning (scanfile) %s\n", file);
    ret = cl_scanfile(file, &virname, &scanned, g_engine, &options);
    cli_dbgmsg("scan end (scanfile) %s\n", file);

    if(!FALSE_NEGATIVE) {
        fail_unless_fmt(ret == CL_VIRUS, "cl_scanfile failed for %s: %s", file, cl_strerror(ret));
        fail_unless_fmt(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s", virname);
    }
}
END_TEST

START_TEST(test_cl_scanfile_allscan)
{
    const char* virname = NULL;
    char file[256];
    unsigned long size;
    unsigned long int scanned = 0;
    int ret;
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;
    options.general |= CL_SCAN_GENERAL_ALLMATCHES;

    int fd = get_test_file(_i, file, sizeof(file), &size);
    close(fd);

    cli_dbgmsg("scanning (scanfile_allscan) %s\n", file);
    ret = cl_scanfile(file, &virname, &scanned, g_engine, &options);
    cli_dbgmsg("scan end (scanfile_allscan) %s\n", file);

    if(!FALSE_NEGATIVE) {
        fail_unless_fmt(ret == CL_VIRUS, "cl_scanfile_allscan failed for %s: %s", file, cl_strerror(ret));
        fail_unless_fmt(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s", virname);
    }
}
END_TEST

START_TEST(test_cl_scanfile_callback)
{
    const char* virname = NULL;
    char file[256];
    unsigned long size;
    unsigned long int scanned = 0;
    int ret;
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;

    int fd = get_test_file(_i, file, sizeof(file), &size);
    close(fd);

    cli_dbgmsg("scanning (scanfile_cb) %s\n", file);
    /* TODO: test callbacks */
    ret = cl_scanfile_callback(file, &virname, &scanned, g_engine, &options, NULL);
    cli_dbgmsg("scan end (scanfile_cb) %s\n", file);

    if(!FALSE_NEGATIVE) {
        fail_unless_fmt(ret == CL_VIRUS, "cl_scanfile_cb failed for %s: %s", file, cl_strerror(ret));
        fail_unless_fmt(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s", virname);
    }
}
END_TEST

START_TEST(test_cl_scanfile_callback_allscan)
{
    const char* virname = NULL;
    char file[256];
    unsigned long size;
    unsigned long int scanned = 0;
    int ret;
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;
    options.general |= CL_SCAN_GENERAL_ALLMATCHES;

    int fd = get_test_file(_i, file, sizeof(file), &size);
    close(fd);

    cli_dbgmsg("scanning (scanfile_cb_allscan) %s\n", file);
    /* TODO: test callbacks */
    ret = cl_scanfile_callback(file, &virname, &scanned, g_engine, &options, NULL);
    cli_dbgmsg("scan end (scanfile_cb_allscan) %s\n", file);

    if(!FALSE_NEGATIVE) {
        fail_unless_fmt(ret == CL_VIRUS, "cl_scanfile_cb_allscan failed for %s: %s", file, cl_strerror(ret));
        fail_unless_fmt(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s", virname);
    }
}
END_TEST

START_TEST(test_cl_scandesc_callback)
{
    const char* virname = NULL;
    char file[256];
    unsigned long size;
    unsigned long int scanned = 0;
    int ret;
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;

    int fd = get_test_file(_i, file, sizeof(file), &size);

    cli_dbgmsg("scanning (scandesc_cb) %s\n", file);
    /* TODO: test callbacks */
    ret = cl_scandesc_callback(fd, file, &virname, &scanned, g_engine, &options, NULL);
    cli_dbgmsg("scan end (scandesc_cb) %s\n", file);

    if(!FALSE_NEGATIVE) {
        fail_unless_fmt(ret == CL_VIRUS, "cl_scanfile failed for %s: %s", file, cl_strerror(ret));
        fail_unless_fmt(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s", virname);
    }
    close(fd);
}
END_TEST

START_TEST(test_cl_scandesc_callback_allscan)
{
    const char* virname = NULL;
    char file[256];
    unsigned long size;
    unsigned long int scanned = 0;
    int ret;
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;
    options.general |= CL_SCAN_GENERAL_ALLMATCHES;

    int fd = get_test_file(_i, file, sizeof(file), &size);

    cli_dbgmsg("scanning (scandesc_cb_allscan) %s\n", file);
    /* TODO: test callbacks */
    ret = cl_scandesc_callback(fd, file, &virname, &scanned, g_engine, &options, NULL);
    cli_dbgmsg("scan end (scandesc_cb_allscan) %s\n", file);

    if(!FALSE_NEGATIVE) {
        fail_unless_fmt(ret == CL_VIRUS, "cl_scanfile_allscan failed for %s: %s", file, cl_strerror(ret));
        fail_unless_fmt(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s", virname);
    }
    close(fd);
}
END_TEST

#endif

/* int cl_load(const char *path, struct cl_engine **engine, unsigned int *signo, unsigned int options) */
START_TEST(test_cl_load)
END_TEST

/* int cl_cvdverify(const char *file) */
START_TEST(test_cl_cvdverify)
END_TEST

/* int cl_statinidir(const char *dirname, struct cl_stat *dbstat) */
START_TEST(test_cl_statinidir)
END_TEST

/* int cl_statchkdir(const struct cl_stat *dbstat) */
START_TEST(test_cl_statchkdir)
END_TEST

/* void cl_settempdir(const char *dir, short leavetemps) */
START_TEST(test_cl_settempdir)
END_TEST

/* const char *cl_strerror(int clerror) */
START_TEST(test_cl_strerror)
END_TEST

static char** testfiles     = NULL;
static unsigned testfiles_n = 0;

static const int expected_testfiles = 48;

static unsigned skip_files(void)
{
    unsigned skipped = 0;

    /* skip .rar files if unrar is disabled */
    const char* s = getenv("unrar_disabled");
    if(s && !strcmp(s, "1")) {
        skipped += 2;
    }

    /* skip .bz2 files if bzip is disabled */
#if HAVE_BZLIB_H
#else
    skipped += 2;
#endif

    /* skip [placeholder] files if xml is disabled */
#if HAVE_LIBXML2
#else
    skipped += 0;
#endif

    return skipped;
}

static void init_testfiles(void)
{
    struct dirent* dirent;
    unsigned i = 0;
    int expect = expected_testfiles;

    DIR* d = opendir(OBJDIR "/../test");
    fail_unless(!!d, "opendir");
    if(!d)
        return;
    testfiles   = NULL;
    testfiles_n = 0;
    while((dirent = readdir(d))) {
        if(strncmp(dirent->d_name, "clam", 4))
            continue;
        i++;
        testfiles = cli_realloc(testfiles, i * sizeof(*testfiles));
        fail_unless(!!testfiles, "cli_realloc");
        testfiles[i - 1] = strdup(dirent->d_name);
    }
    testfiles_n = i;
    if(get_fpu_endian() == FPU_ENDIAN_UNKNOWN)
        expect--;
    expect -= skip_files();
    fail_unless_fmt(testfiles_n == expect, "testfiles: %d != %d", testfiles_n, expect);

    closedir(d);
}

static void free_testfiles(void)
{
    unsigned i;
    for(i = 0; i < testfiles_n; i++) {
        free(testfiles[i]);
    }
    free(testfiles);
    testfiles   = NULL;
    testfiles_n = 0;
}

static int inited = 0;

static void engine_setup(void)
{
    unsigned int sigs = 0;
    const char* hdb   = OBJDIR "/clamav.hdb";

    init_testfiles();
    if(!inited)
        fail_unless(cl_init(CL_INIT_DEFAULT) == 0, "cl_init");
    inited   = 1;
    g_engine = cl_engine_new();
    fail_unless(!!g_engine, "engine");
    fail_unless_fmt(cl_load(hdb, g_engine, &sigs, CL_DB_STDOPT) == 0, "cl_load %s", hdb);
    fail_unless(sigs == 1, "sigs");
    fail_unless(cl_engine_compile(g_engine) == 0, "cl_engine_compile");
}

static void engine_teardown(void)
{
    free_testfiles();
    cl_engine_free(g_engine);
}

static int get_test_file(int i, char* file, unsigned fsize, unsigned long* size)
{
    int fd;
    STATBUF st;

    fail_unless(i < testfiles_n, "%i < %i %s", i, testfiles_n, file);
    snprintf(file, fsize, OBJDIR "/../test/%s", testfiles[i]);

    fd = open(file, O_RDONLY);
    fail_unless(fd > 0, "open");
    fail_unless(FSTAT(fd, &st) == 0, "fstat");
    *size = st.st_size;
    return fd;
}
#ifdef CHECK_HAVE_LOOPS

static off_t pread_cb(void* handle, void* buf, size_t count, off_t offset)
{
    return pread(*((int*)handle), buf, count, offset);
}

START_TEST(test_cl_scanmap_callback_handle)
{
    const char* virname       = NULL;
    unsigned long int scanned = 0;
    cl_fmap_t* map;
    int ret;
    char file[256];
    unsigned long size;
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;

    int fd = get_test_file(_i, file, sizeof(file), &size);
    /* intentionally use different way than scanners.c for testing */
    map = cl_fmap_open_handle(&fd, 0, size, pread_cb, 1);
    fail_unless(!!map, "cl_fmap_open_handle");

    cli_dbgmsg("scanning (handle) %s\n", file);
    ret = cl_scanmap_callback(map, file, &virname, &scanned, g_engine, &options, NULL);
    cli_dbgmsg("scan end (handle) %s\n", file);

    if(!FALSE_NEGATIVE) {
        fail_unless_fmt(ret == CL_VIRUS, "cl_scanmap_callback failed for %s: %s", file, cl_strerror(ret));
        fail_unless_fmt(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s", virname);
    }
    close(fd);
}
END_TEST

START_TEST(test_cl_scanmap_callback_handle_allscan)
{
    const char* virname       = NULL;
    unsigned long int scanned = 0;
    cl_fmap_t* map;
    int ret;
    char file[256];
    unsigned long size;
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;
    options.general |= CL_SCAN_GENERAL_ALLMATCHES;

    int fd = get_test_file(_i, file, sizeof(file), &size);
    /* intentionally use different way than scanners.c for testing */
    map = cl_fmap_open_handle(&fd, 0, size, pread_cb, 1);
    fail_unless(!!map, "cl_fmap_open_handle %s");

    cli_dbgmsg("scanning (handle) allscan %s\n", file);
    ret = cl_scanmap_callback(map, file, &virname, &scanned, g_engine, &options, NULL);
    cli_dbgmsg("scan end (handle) allscan %s\n", file);

    if(!FALSE_NEGATIVE) {
        fail_unless_fmt(ret == CL_VIRUS, "cl_scanmap_callback allscan failed for %s: %s", file, cl_strerror(ret));
        fail_unless_fmt(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s", virname);
    }
    close(fd);
}
END_TEST

START_TEST(test_cl_scanmap_callback_mem)
{
    const char* virname       = NULL;
    unsigned long int scanned = 0;
    cl_fmap_t* map;
    int ret;
    void* mem;
    unsigned long size;
    char file[256];
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;

    int fd = get_test_file(_i, file, sizeof(file), &size);

    mem = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    fail_unless(mem != MAP_FAILED, "mmap");

    /* intentionally use different way than scanners.c for testing */
    map = cl_fmap_open_memory(mem, size);
    fail_unless(!!map, "cl_fmap_open_mem");

    cli_dbgmsg("scanning (mem) %s\n", file);
    ret = cl_scanmap_callback(map, file, &virname, &scanned, g_engine, &options, NULL);
    cli_dbgmsg("scan end (mem) %s\n", file);
    if(!FALSE_NEGATIVE) {
        fail_unless_fmt(ret == CL_VIRUS, "cl_scanmap_callback failed for %s: %s", file, cl_strerror(ret));
        fail_unless_fmt(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s for %s", virname, file);
    }
    close(fd);
    cl_fmap_close(map);

    munmap(mem, size);
}
END_TEST

START_TEST(test_cl_scanmap_callback_mem_allscan)
{
    const char* virname       = NULL;
    unsigned long int scanned = 0;
    cl_fmap_t* map;
    int ret;
    void* mem;
    unsigned long size;
    char file[256];
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;
    options.general |= CL_SCAN_GENERAL_ALLMATCHES;

    int fd = get_test_file(_i, file, sizeof(file), &size);

    mem = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    fail_unless(mem != MAP_FAILED, "mmap");

    /* intentionally use different way than scanners.c for testing */
    map = cl_fmap_open_memory(mem, size);
    fail_unless(!!map, "cl_fmap_open_mem %s");

    cli_dbgmsg("scanning (mem) allscan %s\n", file);
    ret = cl_scanmap_callback(map, file, &virname, &scanned, g_engine, &options, NULL);
    cli_dbgmsg("scan end (mem) allscan %s\n", file);
    if(!FALSE_NEGATIVE) {
        fail_unless_fmt(ret == CL_VIRUS, "cl_scanmap_callback allscan failed for %s: %s", file, cl_strerror(ret));
        fail_unless_fmt(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s for %s", virname, file);
    }
    close(fd);
    cl_fmap_close(map);
    munmap(mem, size);
}
END_TEST
#endif

static Suite* test_cl_suite(void)
{
    Suite* s           = suite_create("cl_api");
    TCase* tc_cl       = tcase_create("cl_dup");
    TCase* tc_cl_scan  = tcase_create("cl_scan");
    char* user_timeout = NULL;
    int expect         = expected_testfiles;
    suite_add_tcase(s, tc_cl);
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
    tcase_add_test(tc_cl, test_cl_load);
    tcase_add_test(tc_cl, test_cl_cvdverify);
    tcase_add_test(tc_cl, test_cl_statinidir);
    tcase_add_test(tc_cl, test_cl_statchkdir);
    tcase_add_test(tc_cl, test_cl_settempdir);
    tcase_add_test(tc_cl, test_cl_strerror);

    suite_add_tcase(s, tc_cl_scan);
    tcase_add_checked_fixture(tc_cl_scan, engine_setup, engine_teardown);
#ifdef CHECK_HAVE_LOOPS
    if(get_fpu_endian() == FPU_ENDIAN_UNKNOWN)
        expect--;
    expect -= skip_files();
    tcase_add_loop_test(tc_cl_scan, test_cl_scandesc, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_cl_scandesc_allscan, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_cl_scanfile, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_cl_scanfile_allscan, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_cl_scandesc_callback, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_cl_scandesc_callback_allscan, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_cl_scanfile_callback, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_cl_scanfile_callback_allscan, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_cl_scanmap_callback_handle, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_cl_scanmap_callback_handle_allscan, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_cl_scanmap_callback_mem, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_cl_scanmap_callback_mem_allscan, 0, expect);

    user_timeout = getenv("T");
    if(user_timeout) {
        int timeout = atoi(user_timeout);
        tcase_set_timeout(tc_cl_scan, timeout);
        printf("Using test case timeout of %d seconds set by user\n", timeout);
    } else {
        printf("Using default test timeout; alter by setting 'T' env var (in seconds)\n");
    }
#endif
    return s;
}

static uint8_t le_data[4]     = {0x67, 0x45, 0x23, 0x01};
static int32_t le_expected[4] = {0x01234567, 0x67012345, 0x45670123, 0x23456701};
uint8_t* data                 = NULL;
uint8_t* data2                = NULL;
#define DATA_REP 100

static void data_setup(void)
{
    uint8_t* p;
    size_t i;

    data  = malloc(sizeof(le_data) * DATA_REP);
    data2 = malloc(sizeof(le_data) * DATA_REP);
    fail_unless(!!data, "unable to allocate memory for fixture");
    fail_unless(!!data2, "unable to allocate memory for fixture");
    p = data;
    /* make multiple copies of le_data, we need to run readint tests in a loop, so we need
         * to give it some data to run it on */
    for(i = 0; i < DATA_REP; i++) {
        memcpy(p, le_data, sizeof(le_data));
        p += sizeof(le_data);
    }
    memset(data2, 0, DATA_REP * sizeof(le_data));
}

static void data_teardown(void)
{
    free(data);
    free(data2);
}

#ifdef CHECK_HAVE_LOOPS
/* test reading with different alignments, _i is parameter from tcase_add_loop_test */
START_TEST(test_cli_readint16)
{
    size_t j;
    int16_t value;
    /* read 2 bytes apart, start is not always aligned*/
    for(j = _i; j <= DATA_REP * sizeof(le_data) - 2; j += 2) {
        value = le_expected[j & 3];
        fail_unless(cli_readint16(&data[j]) == value, "(1) data read must be little endian");
    }
    /* read 2 bytes apart, always aligned*/
    for(j = 0; j <= DATA_REP * sizeof(le_data) - 2; j += 2) {
        value = le_expected[j & 3];
        fail_unless(cli_readint16(&data[j]) == value, "(2) data read must be little endian");
    }
}
END_TEST

/* test reading with different alignments, _i is parameter from tcase_add_loop_test */
START_TEST(test_cli_readint32)
{
    size_t j;
    int32_t value = le_expected[_i & 3];
    /* read 4 bytes apart, start is not always aligned*/
    for(j = _i; j < DATA_REP * sizeof(le_data) - 4; j += 4) {
        fail_unless(cli_readint32(&data[j]) == value, "(1) data read must be little endian");
    }
    value = le_expected[0];
    /* read 4 bytes apart, always aligned*/
    for(j = 0; j < DATA_REP * sizeof(le_data) - 4; j += 4) {
        fail_unless(cli_readint32(&data[j]) == value, "(2) data read must be little endian");
    }
}
END_TEST

/* test writing with different alignments, _i is parameter from tcase_add_loop_test */
START_TEST(test_cli_writeint32)
{
    size_t j;
    /* write 4 bytes apart, start is not always aligned*/
    for(j = _i; j < DATA_REP * sizeof(le_data) - 4; j += 4) {
        cli_writeint32(&data2[j], 0x12345678);
    }
    for(j = _i; j < DATA_REP * sizeof(le_data) - 4; j += 4) {
        fail_unless(cli_readint32(&data2[j]) == 0x12345678, "write/read mismatch");
    }
    /* write 4 bytes apart, always aligned*/
    for(j = 0; j < DATA_REP * sizeof(le_data) - 4; j += 4) {
        cli_writeint32(&data2[j], 0x12345678);
    }
    for(j = 0; j < DATA_REP * sizeof(le_data) - 4; j += 4) {
        fail_unless(cli_readint32(&data2[j]) == 0x12345678, "write/read mismatch");
    }
}
END_TEST

static struct dsig_test {
    const char* md5;
    const char* dsig;
    int result;
} dsig_tests[] = {
    {"ae307614434715274c60854c931a26de", "60uhCFmiN48J8r6c7coBv9Q1mehAWEGh6GPYA+60VhQcuXfb0iV1O+sCEyMiRXt/iYF6vXtPXHVd6DiuZ4Gfrry7sVQqNTt3o1/KwU1rc0l5FHgX/nC99fdr/fjaFtinMtRnUXHLeu0j8e6HK+7JLBpD37fZ60GC9YY86EclYGe",
     CL_SUCCESS},
    {"96b7feb3b2a863846438809fe481906f", "Zh5gmf09Zfj6V4gmRKu/NURzhFiE9VloI7w1G33BgDdGSs0Xhscx6sjPUpFSCPsjOalyS4L8q7RS+NdGvNCsLymiIH6RYItlOZsygFhcGuH4jt15KAaAkvEg2TwmqR8z41nUaMlZ0c8q1MXYCLvQJyFARsfzIxS3PAoN2Y3HPoe",
     CL_SUCCESS},
    {"ae307614434715274c60854c931a26de", "Zh5gmf09Zfj6V4gmRKu/NURzhFiE9VloI7w1G33BgDdGSs0Xhscx6sjPUpFSCPsjOalyS4L8q7RS+NdGvNCsLymiIH6RYItlOZsygFhcGuH4jt15KAaAkvEg2TwmqR8z41nUaMlZ0c8q1MXYCLvQJyFARsfzIxS3PAoN2Y3HPoe",
     CL_EVERIFY},
    {"96b7feb3b2a863846438809fe481906f", "60uhCFmiN48J8r6c7coBv9Q1mehAWEGh6GPYA+60VhQcuXfb0iV1O+sCEyMiRXt/iYF6vXtPXHVd6DiuZ4Gfrry7sVQqNTt3o1/KwU1rc0l5FHgX/nC99fdr/fjaFtinMtRnUXHLeu0j8e6HK+7JLBpD37fZ60GC9YY86EclYGe",
     CL_EVERIFY},
    {"ae307614434715274060854c931a26de", "60uhCFmiN48J8r6c7coBv9Q1mehAWEGh6GPYA+60VhQcuXfb0iV1O+sCEyMiRXt/iYF6vXtPXHVd6DiuZ4Gfrry7sVQqNTt3o1/KwU1rc0l5FHgX/nC99fdr/fjaFtinMtRnUXHLeu0j8e6HK+7JLBpD37fZ60GC9YY86EclYGe",
     CL_EVERIFY},
    {"ae307614434715274c60854c931a26de", "60uhCFmiN48J8r6c7coBv9Q1mehAWEGh6GPYA+60VhQcuXfb0iV1O+sCEyMiRXt/iYF6vXtPXHVd6DiuZ4Gfrry7sVQqNTt3o1/KwU1rc0l5FHgX/nC99fdr/fjaatinMtRnUXHLeu0j8e6HK+7JLBpD37fZ60GC9YY86EclYGe",
     CL_EVERIFY},
    {"96b7feb3b2a863846438809fe481906f", "Zh5gmf09Zfj6V4gmRKu/NURzhFiE9VloI7w1G33BgDdGSs0Xhscx6sjPUpFSCPsjOalyS4L8q7RS+NdGvNCsLymiIH6RYItlOZsygFhcGuH4jt15KAaAkvEg2TwmqR8z41nUaMlZ0c8q1MYYCLvQJyFARsfzIxS3PAoN2Y3HPoe",
     CL_EVERIFY},
    {"ge307614434715274c60854c931a26dee", "60uhCFmiN48J8r6c7coBv9Q1mehAWEGh6GPYA+60VhQcuXfb0iV1O+sCEyMiRXt/iYF6vXtPXHVd6DiuZ4Gfrry7sVQqNTt3o1/KwU1rc0l5FHgX/nC99fdr/fjaFtinMtRnUXHLeu0j8e6HK+7JLBpD37fZ60GC9YY86EclYGe",
     CL_EVERIFY},
    {"ae307614434715274c60854c931a26de", "60uhCFmiN48J8r6c7coBv9Q1mehAWEGh6GPYA+60VhQcuXfb0iV1O+sCEyMiRXt/iYF6vXtPXHVd6DiuZ4Gfrry7sVQqNTt3o1/KwU1rc0l5FHgX/nC99fdr/fjaFtinMtRnUXHLeu0j8e6HK+7JLBpD37fZ60GC9YY86EclYGee",
     CL_EVERIFY},
    {"ae307614434715274c60854c931a26de", "60uhCFmiN48J8r6c7coBv9Q1mehAWEGh6GPYA+",
     CL_EVERIFY}};

static const size_t dsig_tests_cnt = sizeof(dsig_tests) / sizeof(dsig_tests[0]);

START_TEST(test_cli_dsig)
{
    fail_unless(cli_versig(dsig_tests[_i].md5, dsig_tests[_i].dsig) == dsig_tests[_i].result,
                "digital signature verification test failed");
}
END_TEST

static uint8_t tv1[3] = {
    0x61, 0x62, 0x63};

static uint8_t tv2[56] = {
    0x61, 0x62, 0x63, 0x64, 0x62, 0x63, 0x64, 0x65,
    0x63, 0x64, 0x65, 0x66, 0x64, 0x65, 0x66, 0x67,
    0x65, 0x66, 0x67, 0x68, 0x66, 0x67, 0x68, 0x69,
    0x67, 0x68, 0x69, 0x6a, 0x68, 0x69, 0x6a, 0x6b,
    0x69, 0x6a, 0x6b, 0x6c, 0x6a, 0x6b, 0x6c, 0x6d,
    0x6b, 0x6c, 0x6d, 0x6e, 0x6c, 0x6d, 0x6e, 0x6f,
    0x6d, 0x6e, 0x6f, 0x70, 0x6e, 0x6f, 0x70, 0x71};

static uint8_t res256[3][SHA256_HASH_SIZE] = {
    {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
     0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
     0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad},
    {0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93,
     0x0c, 0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
     0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1},
    {0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7, 0xe2,
     0x84, 0xd7, 0x3e, 0x67, 0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e,
     0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0}};

START_TEST(test_sha256)
{
    void* sha256;
    uint8_t hsha256[SHA256_HASH_SIZE];
    uint8_t buf[1000];
    int i;

    memset(buf, 0x61, sizeof(buf));

    cl_sha256(tv1, sizeof(tv1), hsha256, NULL);
    fail_unless(!memcmp(hsha256, res256[0], sizeof(hsha256)), "sha256 test vector #1 failed");

    cl_sha256(tv2, sizeof(tv2), hsha256, NULL);
    fail_unless(!memcmp(hsha256, res256[1], sizeof(hsha256)), "sha256 test vector #2 failed");

    sha256 = cl_hash_init("sha256");
    fail_unless(sha256 != NULL, "Could not create EVP_MD_CTX for sha256");

    for(i = 0; i < 1000; i++)
        cl_update_hash(sha256, buf, sizeof(buf));
    cl_finish_hash(sha256, hsha256);
    fail_unless(!memcmp(hsha256, res256[2], sizeof(hsha256)), "sha256 test vector #3 failed");
}
END_TEST

START_TEST(test_sanitize_path)
{
    char* sanitized         = NULL;
    const char* unsanitized = NULL;

    unsanitized = "";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized));
    fail_if(NULL != sanitized, "sanitize_path: Empty path test failed");

    unsanitized = NULL;
    sanitized   = cli_sanitize_filepath(unsanitized, 0);
    fail_if(NULL != sanitized, "sanitize_path: NULL path #1 test failed");

    unsanitized = NULL;
    sanitized   = cli_sanitize_filepath(unsanitized, 50);
    fail_if(NULL != sanitized, "sanitize_path: NULL path #2 test failed");

    unsanitized = "badlen";
    sanitized   = cli_sanitize_filepath(unsanitized, 0);
    fail_if(NULL != sanitized, "sanitize_path: Zero/bad path length test failed");

    unsanitized = ".." PATHSEP;
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized));
    fail_if(NULL != sanitized, "sanitize_path: sanitized path should have been NULL");

    unsanitized = "." PATHSEP;
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized));
    fail_if(NULL != sanitized, "sanitize_path: sanitized path should have been NULL (2)");

    unsanitized = PATHSEP;
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized));
    fail_if(NULL != sanitized, "sanitize_path: sanitized path should have been NULL (3)");

    unsanitized = ".." PATHSEP "relative_bad_1";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized));
    fail_if(NULL == sanitized);
    fail_unless(!strcmp(sanitized, "relative_bad_1"), "sanitize_path: bad relative path test #1 failed");
    free(sanitized);

    unsanitized = "relative" PATHSEP ".." PATHSEP "good";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized));
    fail_if(NULL == sanitized);
    fail_unless(!strcmp(sanitized, "relative" PATHSEP ".." PATHSEP "good"), "sanitize_path: good relative path test failed");
    free(sanitized);

    unsanitized = "relative" PATHSEP ".." PATHSEP ".." PATHSEP "bad_2";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized));
    fail_if(NULL == sanitized);
    fail_unless(!strcmp(sanitized, "relative" PATHSEP ".." PATHSEP "bad_2"), "sanitize_path: bad relative path test failed");
    free(sanitized);

    unsanitized = "relative" PATHSEP "." PATHSEP ".." PATHSEP ".." PATHSEP "bad_current";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized));
    fail_if(NULL == sanitized);
    fail_unless(!strcmp(sanitized, "relative" PATHSEP ".." PATHSEP "bad_current"), "sanitize_path: bad relative current path test failed");
    free(sanitized);

    unsanitized = "relative/../../bad_win_posix_path";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized));
    fail_if(NULL == sanitized);
    fail_unless(!strcmp(sanitized, "relative/../bad_win_posix_path"), "sanitize_path: bad relative win posix path test failed");
    free(sanitized);

    unsanitized = "" PATHSEP "absolute" PATHSEP ".." PATHSEP ".." PATHSEP "bad";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized));
    fail_if(NULL == sanitized);
    fail_unless(!strcmp(sanitized, "absolute" PATHSEP ".." PATHSEP "bad"), "sanitize_path: bad absolute path test failed");
    free(sanitized);

    unsanitized = "" PATHSEP "absolute" PATHSEP ".." PATHSEP "good";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized));
    fail_if(NULL == sanitized);
    fail_unless(!strcmp(sanitized, "absolute" PATHSEP ".." PATHSEP "good"), "sanitize_path: good absolute path test failed");
    free(sanitized);

    unsanitized = "relative" PATHSEP "normal";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized));
    fail_if(NULL == sanitized);
    fail_unless(!strcmp(sanitized, "relative" PATHSEP "normal"), "sanitize_path: relative normal path test failed");
    free(sanitized);

    unsanitized = "relative" PATHSEP PATHSEP "doublesep";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized));
    fail_if(NULL == sanitized);
    fail_unless(!strcmp(sanitized, "relative" PATHSEP "doublesep"), "sanitize_path: relative double sep path test failed");
    free(sanitized);

    unsanitized = "relative" PATHSEP "shortname" PATHSEP "1";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized));
    fail_if(NULL == sanitized);
    fail_unless(!strcmp(sanitized, "relative" PATHSEP "shortname" PATHSEP "1"), "sanitize_path: relative short name path test failed");
    free(sanitized);
}
END_TEST

static Suite* test_cli_suite(void)
{
    Suite* s               = suite_create("cli");
    TCase* tc_cli_others   = tcase_create("byteorder_macros");
    TCase* tc_cli_dsig     = tcase_create("digital signatures");
    TCase* tc_cli_assorted = tcase_create("assorted functions");

    suite_add_tcase(s, tc_cli_others);
    tcase_add_checked_fixture(tc_cli_others, data_setup, data_teardown);
    tcase_add_loop_test(tc_cli_others, test_cli_readint32, 0, 16);
    tcase_add_loop_test(tc_cli_others, test_cli_readint16, 0, 16);
    tcase_add_loop_test(tc_cli_others, test_cli_writeint32, 0, 16);

    suite_add_tcase(s, tc_cli_dsig);
    tcase_add_loop_test(tc_cli_dsig, test_cli_dsig, 0, dsig_tests_cnt);
    tcase_add_test(tc_cli_dsig, test_sha256);

    suite_add_tcase(s, tc_cli_assorted);
    tcase_add_test(tc_cli_assorted, test_sanitize_path);

    return s;
}
#endif /* CHECK_HAVE_LOOPS */

void errmsg_expected(void)
{
    fputs("cli_errmsg() expected here\n", stderr);
}

int open_testfile(const char* name)
{
    int fd;
    const char* srcdir = getenv("srcdir");
    char* str;

    if(!srcdir) {
        /* when run from automake srcdir is set, but if run manually then not */
        srcdir = SRCDIR;
    }

    str = cli_malloc(strlen(name) + strlen(srcdir) + 2);
    fail_unless(!!str, "cli_malloc");
    sprintf(str, "%s/%s", srcdir, name);

    fd = open(str, O_RDONLY);
    fail_unless_fmt(fd >= 0, "open() failed: %s", str);
    free(str);
    return fd;
}

void diff_file_mem(int fd, const char* ref, size_t len)
{
    char c1, c2;
    size_t p, reflen = len;
    char* buf = cli_malloc(len);

    fail_unless_fmt(!!buf, "unable to malloc buffer: %d", len);
    p = read(fd, buf, len);
    fail_unless_fmt(p == len, "file is smaller: %lu, expected: %lu", p, len);
    p = 0;
    while(len > 0) {
        c1 = ref[p];
        c2 = buf[p];
        if(c1 != c2)
            break;
        p++;
        len--;
    }
    if(len > 0)
        fail_unless_fmt(c1 == c2, "file contents mismatch at byte: %lu, was: %c, expected: %c", p, c2, c1);
    free(buf);
    p = lseek(fd, 0, SEEK_END);
    fail_unless_fmt(p == reflen, "trailing garbage, file size: %ld, expected: %ld", p, reflen);
    close(fd);
}

void diff_files(int fd, int ref_fd)
{
    char* ref;
    ssize_t nread;
    off_t siz = lseek(ref_fd, 0, SEEK_END);
    fail_unless_fmt(siz != -1, "lseek failed");

    ref = cli_malloc(siz);
    fail_unless_fmt(!!ref, "unable to malloc buffer: %d", siz);

    fail_unless_fmt(lseek(ref_fd, 0, SEEK_SET) == 0, "lseek failed");
    nread = read(ref_fd, ref, siz);
    fail_unless_fmt(nread == siz, "short read, expected: %ld, was: %ld", siz, nread);
    close(ref_fd);
    diff_file_mem(fd, ref, siz);
    free(ref);
}

#ifdef USE_MPOOL
static mpool_t* pool;
#else
static void* pool;
#endif
struct cli_dconf* dconf;

void dconf_setup(void)
{
    pool  = NULL;
    dconf = NULL;
#ifdef USE_MPOOL
    pool = mpool_create();
    fail_unless(!!pool, "unable to create pool");
#endif
    dconf = cli_mpool_dconf_init(pool);
    fail_unless(!!dconf, "failed to init dconf");
}

void dconf_teardown(void)
{
    mpool_free(pool, dconf);
#ifdef USE_MPOOL
    if(pool)
        mpool_destroy(pool);
#endif
}

static void check_version_compatible()
{
    /* check 0.9.8 is not ABI compatible with 0.9.6,
     * if by accident you compile with check 0.9.6 header
     * and link with 0.9.8 then check will hang/crash. */
    if((check_major_version != CHECK_MAJOR_VERSION) ||
       (check_minor_version != CHECK_MINOR_VERSION) ||
       (check_micro_version != CHECK_MICRO_VERSION)) {
        fprintf(stderr, "ERROR: check version mismatch!\n"
                        "\tVersion from header: %u.%u.%u\n"
                        "\tVersion from library: %u.%u.%u\n"
                        "\tMake sure check.h and -lcheck are same version!\n",
                CHECK_MAJOR_VERSION,
                CHECK_MINOR_VERSION,
                CHECK_MICRO_VERSION,
                check_major_version,
                check_minor_version,
                check_micro_version);
        exit(EXIT_FAILURE);
    }
}

int main(void)
{
    int nf;
    Suite* s;
    SRunner* sr;

    cl_initialize_crypto();

    fpu_words = get_fpu_endian();

    check_version_compatible();
    s  = test_cl_suite();
    sr = srunner_create(s);
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
    srunner_add_suite(sr, test_bytecode_suite());

    srunner_set_log(sr, "test.log");
    if(freopen("test-stderr.log", "w+", stderr) == NULL) {
        fputs("Unable to redirect stderr!\n", stderr);
    }
    cl_debug();

    srunner_run_all(sr, CK_NORMAL);
    nf = srunner_ntests_failed(sr);
    if(nf)
        printf("NOTICE: Use the 'T' environment variable to adjust testcase timeout\n");
    srunner_free(sr);

#if HAVE_LIBXML2
    xmlCleanupParser();
#endif
    cl_cleanup_crypto();

    return (nf == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
