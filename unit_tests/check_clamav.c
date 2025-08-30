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
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#include <libxml/parser.h>

#include "platform.h"

// libclamav
#include "clamav.h"
#include "others.h"
#include "matcher.h"
#include "version.h"
#include "dsig.h"
#include "fpu.h"
#include "entconv.h"

#include "checks.h"

static int fpu_words = FPU_ENDIAN_INITME;
#define NO_FPU_ENDIAN (fpu_words == FPU_ENDIAN_UNKNOWN)
#define EA06_SCAN strstr(file, "clam.ea06.exe")
#define FALSE_NEGATIVE (EA06_SCAN && NO_FPU_ENDIAN)

// Define SRCDIR and OBJDIR when not defined, for the sake of the IDE.
#ifndef SRCDIR
#define SRCDIR " should be defined by CMake "
#endif
#ifndef OBJDIR
#define OBJDIR " should be defined by CMake "
#endif

static char *tmpdir;

static void cl_setup(void)
{
    tmpdir = cli_gentemp(NULL);
    mkdir(tmpdir, 0700);
    ck_assert_msg(!!tmpdir, "cli_gentemp failed");
}

static void cl_teardown(void)
{
    /* can't call fail() functions in teardown, it can cause SEGV */
    cli_rmdirs(tmpdir);
    free(tmpdir);
    tmpdir = NULL;
}

/* extern void cl_free(struct cl_engine *engine); */
START_TEST(test_cl_free)
{
    // struct cl_engine *engine = NULL;
    // cl_free(NULL);
}
END_TEST

/* extern int cl_build(struct cl_engine *engine); */
START_TEST(test_cl_build)
{
    // struct cl_engine *engine;
    // ck_assert_msg(CL_ENULLARG == cl_build(NULL), "cl_build null pointer");
    // engine = calloc(sizeof(struct cl_engine),1);
    // ck_assert_msg(engine, "cl_build calloc");
    // ck_assert_msg(CL_ENULLARG == cl_build(engine), "cl_build(engine) with null ->root");

    // engine->root = calloc(CL_TARGET_TABLE_SIZE, sizeof(struct cli_matcher *));
}
END_TEST

/* extern void cl_debug(void); */
START_TEST(test_cl_debug)
{
    int old_status = cli_set_debug_flag(0);

    cl_debug();
    ck_assert_msg(1 == cli_get_debug_flag(), "cl_debug failed to set cli_debug_flag");

    (void)cli_set_debug_flag(1);

    cl_debug();
    ck_assert_msg(1 == cli_get_debug_flag(), "cl_debug failed when flag was already set");

    (void)cli_set_debug_flag(old_status);
}
END_TEST

#ifndef _WIN32
/* extern const char *cl_retdbdir(void); */
START_TEST(test_cl_retdbdir)
{
    ck_assert_msg(!strcmp(DATADIR, cl_retdbdir()), "cl_retdbdir");
}
END_TEST
#endif

#ifndef REPO_VERSION
#define REPO_VERSION VERSION
#endif

/* extern const char *cl_retver(void); */
START_TEST(test_cl_retver)
{
    const char *ver = cl_retver();
    ck_assert_msg(!strcmp(REPO_VERSION "" VERSION_SUFFIX, ver), "cl_retver");
    ck_assert_msg(strcspn(ver, "012345789") < strlen(ver),
                  "cl_retver must have a number");
}
END_TEST

/* extern void cl_cvdfree(struct cl_cvd *cvd); */
START_TEST(test_cl_cvdfree)
{
    // struct cl_cvd *cvd1, *cvd2;

    // cvd1 = malloc(sizeof(struct cl_cvd));
    // ck_assert_msg(cvd1, "cvd malloc");
    // cl_cvdfree(cvd1);

    // cvd2 = malloc(sizeof(struct cl_cvd));
    // cvd2->time = malloc(1);
    // cvd2->md5 = malloc(1);
    // cvd2->dsig= malloc(1);
    // cvd2->builder = malloc(1);
    // ck_assert_msg(cvd2, "cvd malloc");
    // ck_assert_msg(cvd2->time, "cvd malloc");
    // ck_assert_msg(cvd2->md5, "cvd malloc");
    // ck_assert_msg(cvd2->dsig, "cvd malloc");
    // ck_assert_msg(cvd2->builder, "cvd malloc");
    // cl_cvdfree(cvd2);
    // cl_cvdfree(NULL);
}
END_TEST

/* extern int cl_statfree(struct cl_stat *dbstat); */
START_TEST(test_cl_statfree)
{
    // struct cl_stat *stat;
    // ck_assert_msg(CL_ENULLARG == cl_statfree(NULL), "cl_statfree(NULL)");

    // stat = malloc(sizeof(struct cl_stat));
    // ck_assert_msg(NULL != stat, "malloc");
    // ck_assert_msg(CL_SUCCESS == cl_statfree(stat), "cl_statfree(empty_struct)");

    // stat = malloc(sizeof(struct cl_stat));
    // ck_assert_msg(NULL != stat, "malloc");
    // stat->stattab = strdup("test");
    // ck_assert_msg(NULL != stat->stattab, "strdup");
    // ck_assert_msg(CL_SUCCESS == cl_statfree(stat), "cl_statfree(stat with stattab)");

    // stat = malloc(sizeof(struct cl_stat));
    // ck_assert_msg(NULL != stat, "malloc");
    // stat->stattab = NULL;
    // ck_assert_msg(CL_SUCCESS == cl_statfree(stat), "cl_statfree(stat with stattab) set to NULL");
}
END_TEST

/* extern unsigned int cl_retflevel(void); */
START_TEST(test_cl_retflevel)
{
}
END_TEST

/* extern struct cl_cvd *cl_cvdhead(const char *file); */
START_TEST(test_cl_cvdhead)
{
    // ck_assert_msg(NULL == cl_cvdhead(NULL), "cl_cvdhead(null)");
    // ck_assert_msg(NULL == cl_cvdhead("input" PATHSEP "cl_cvdhead" PATHSEP "1.txt"), "cl_cvdhead(515 byte file, all nulls)");
    /* the data read from the file is passed to cl_cvdparse, test cases for that are separate */
}
END_TEST

/* extern struct cl_cvd *cl_cvdparse(const char *head); */
START_TEST(test_cl_cvdparse)
{
}
END_TEST

static int get_test_file(int i, char *file, unsigned fsize, unsigned long *size);
static struct cl_engine *g_engine;

/* cl_error_t cl_scandesc(int desc, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, const struct cl_limits *limits, struct cl_scan_options* options) */
START_TEST(test_cl_scandesc)
{
    const char *virname = NULL;
    char file[256];
    unsigned long size;
    unsigned long int scanned = 0;
    cl_error_t ret;
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;

    int fd = get_test_file(_i, file, sizeof(file), &size);
    cli_dbgmsg("scanning (scandesc) %s\n", file);
    ret = cl_scandesc(fd, file, &virname, &scanned, g_engine, &options);
    cli_dbgmsg("scan end (scandesc) %s\n", file);

    if (!FALSE_NEGATIVE) {
        ck_assert_msg(ret == CL_VIRUS, "cl_scandesc failed for %s: %s", file, cl_strerror(ret));
        ck_assert_msg(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s", virname);
    }
    close(fd);
}
END_TEST

START_TEST(test_cl_scandesc_allscan)
{
    const char *virname = NULL;
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

    if (!FALSE_NEGATIVE) {
        ck_assert_msg(ret == CL_VIRUS, "cl_scandesc_allscan failed for %s: %s", file, cl_strerror(ret));
        ck_assert_msg(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s", virname);
    }
    close(fd);
}
END_TEST

//* int cl_scanfile(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, const struct cl_limits *limits, unsigned int options) */
START_TEST(test_cl_scanfile)
{
    const char *virname = NULL;
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

    if (!FALSE_NEGATIVE) {
        ck_assert_msg(ret == CL_VIRUS, "cl_scanfile failed for %s: %s", file, cl_strerror(ret));
        ck_assert_msg(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s", virname);
    }
}
END_TEST

START_TEST(test_cl_scanfile_allscan)
{
    const char *virname = NULL;
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

    if (!FALSE_NEGATIVE) {
        ck_assert_msg(ret == CL_VIRUS, "cl_scanfile_allscan failed for %s: %s", file, cl_strerror(ret));
        ck_assert_msg(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s", virname);
    }
}
END_TEST

START_TEST(test_cl_scanfile_callback)
{
    const char *virname = NULL;
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

    if (!FALSE_NEGATIVE) {
        ck_assert_msg(ret == CL_VIRUS, "cl_scanfile_cb failed for %s: %s", file, cl_strerror(ret));
        ck_assert_msg(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s", virname);
    }
}
END_TEST

START_TEST(test_cl_scanfile_callback_allscan)
{
    const char *virname = NULL;
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

    if (!FALSE_NEGATIVE) {
        ck_assert_msg(ret == CL_VIRUS, "cl_scanfile_cb_allscan failed for %s: %s", file, cl_strerror(ret));
        ck_assert_msg(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s", virname);
    }
}
END_TEST

START_TEST(test_cl_scandesc_callback)
{
    const char *virname = NULL;
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

    if (!FALSE_NEGATIVE) {
        ck_assert_msg(ret == CL_VIRUS, "cl_scanfile failed for %s: %s", file, cl_strerror(ret));
        ck_assert_msg(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s", virname);
    }
    close(fd);
}
END_TEST

START_TEST(test_cl_scandesc_callback_allscan)
{
    const char *virname = NULL;
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

    if (!FALSE_NEGATIVE) {
        ck_assert_msg(ret == CL_VIRUS, "cl_scanfile_allscan failed for %s: %s", file, cl_strerror(ret));
        ck_assert_msg(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s", virname);
    }
    close(fd);
}
END_TEST

/* cl_error_t cl_load(const char *path, struct cl_engine **engine, unsigned int *signo, unsigned int options) */
START_TEST(test_cl_load)
{
    cl_error_t ret;
    struct cl_engine *engine;
    unsigned int sigs = 0;
    const char *testfile;
    const char *cvdcertsdir;

    ret = cl_init(CL_INIT_DEFAULT);
    ck_assert_msg(ret == CL_SUCCESS, "cl_init failed: %s", cl_strerror(ret));

    engine = cl_engine_new();
    ck_assert_msg(engine != NULL, "cl_engine_new failed");

    /* load test cvd */
    testfile = SRCDIR PATHSEP "input" PATHSEP "freshclam_testfiles" PATHSEP "test-5.cvd";
    ret      = cl_load(testfile, engine, &sigs, CL_DB_STDOPT);
    ck_assert_msg(ret == CL_SUCCESS, "cl_load failed for: %s -- %s", testfile, cl_strerror(ret));
    ck_assert_msg(sigs > 0, "No signatures loaded");

    cl_engine_free(engine);
}
END_TEST

/* cl_error_t cl_cvdverify_ex(const char *file, const char *certs_directory, uint32_t dboptions) */
START_TEST(test_cl_cvdverify)
{
    cl_error_t ret;
    const char *testfile;
    char newtestfile[PATH_MAX];
    FILE *orig_fs;
    FILE *new_fs;
    char cvd_bytes[5000];
    const char *cvdcertsdir;

    cvdcertsdir = getenv("CVD_CERTS_DIR");
    ck_assert_msg(cvdcertsdir != NULL, "CVD_CERTS_DIR not set");

    // Should be able to verify this cvd
    testfile = SRCDIR "/input/freshclam_testfiles/test-1.cvd";
    ret      = cl_cvdverify_ex(testfile, cvdcertsdir, 0);
    ck_assert_msg(CL_SUCCESS == ret, "cl_cvdverify_ex failed for: %s -- %s", testfile, cl_strerror(ret));

    // Can't verify a cvd that doesn't exist
    testfile = SRCDIR "/input/freshclam_testfiles/test-na.cvd";
    ret      = cl_cvdverify_ex(testfile, cvdcertsdir, 0);
    ck_assert_msg(CL_ECVD == ret, "cl_cvdverify_ex should have failed for: %s -- %s", testfile, cl_strerror(ret));

    // A cdiff is not a cvd. Cannot verify with cl_cvdverify_ex!
    testfile = SRCDIR "/input/freshclam_testfiles/test-2.cdiff";
    ret      = cl_cvdverify_ex(testfile, cvdcertsdir, 0);
    ck_assert_msg(CL_ECVD == ret, "cl_cvdverify_ex should have failed for: %s -- %s", testfile, cl_strerror(ret));

    // Can't verify an hdb file
    testfile = SRCDIR "/input/clamav.hdb";
    ret      = cl_cvdverify_ex(testfile, cvdcertsdir, 0);
    ck_assert_msg(CL_ECVD == ret, "cl_cvdverify_ex should have failed for: %s -- %s", testfile, cl_strerror(ret));

    // Modify the cvd to make it invalid
    sprintf(newtestfile, "%s/modified.cvd", tmpdir);

    orig_fs = fopen(SRCDIR "/input/freshclam_testfiles/test-1.cvd", "rb");
    ck_assert_msg(orig_fs != NULL, "Failed to open %s", testfile);

    new_fs = fopen(newtestfile, "wb");
    ck_assert_msg(new_fs != NULL, "Failed to open %s", newtestfile);

    // Copy the first 5000 bytes
    fread(cvd_bytes, 1, 5000, orig_fs);
    fwrite(cvd_bytes, 1, 5000, new_fs);

    fclose(orig_fs);
    fclose(new_fs);

    // Now verify the modified cvd
    ret = cl_cvdverify_ex(newtestfile, cvdcertsdir, 0);
    ck_assert_msg(CL_EVERIFY == ret, "cl_cvdverify_ex should have failed for: %s -- %s", newtestfile, cl_strerror(ret));
}
END_TEST

/* cl_error_t cl_cvdunpack_ex(const char *file, const char *dir, const char *certs_directory, uint32_t dboptions) */
START_TEST(test_cl_cvdunpack_ex)
{
    cl_error_t ret;
    char *utf8       = NULL;
    size_t utf8_size = 0;
    const char *testfile;

    testfile = SRCDIR "/input/freshclam_testfiles/test-1.cvd";
    ret      = cl_cvdunpack_ex(testfile, tmpdir, NULL, CL_DB_UNSIGNED);
    ck_assert_msg(CL_SUCCESS == ret, "cl_cvdunpack_ex: failed for: %s -- %s", testfile, cl_strerror(ret));

    // Can't unpack a cdiff
    testfile = SRCDIR "/input/freshclam_testfiles/test-2.cdiff";
    ret      = cl_cvdunpack_ex(testfile, tmpdir, NULL, CL_DB_UNSIGNED);
    ck_assert_msg(CL_ECVD == ret, "cl_cvdunpack_ex: should have failed for: %s -- %s", testfile, cl_strerror(ret));
}
END_TEST

/* int cl_statinidir(const char *dirname, struct cl_stat *dbstat) */
START_TEST(test_cl_statinidir)
{
}
END_TEST

/* int cl_statchkdir(const struct cl_stat *dbstat) */
START_TEST(test_cl_statchkdir)
{
}
END_TEST

/* void cl_settempdir(const char *dir, short leavetemps) */
START_TEST(test_cl_settempdir)
{
}
END_TEST

/* const char *cl_strerror(int clerror) */
START_TEST(test_cl_strerror)
{
}
END_TEST

static char **testfiles     = NULL;
static unsigned testfiles_n = 0;

static const int expected_testfiles = 53;

static unsigned skip_files(void)
{
    unsigned skipped = 0;

    /* skip .rar files if unrar is disabled */
#if HAVE_UNRAR
#else
    skipped += 2;
#endif

    return skipped;
}

static void init_testfiles(void)
{
    struct dirent *dirent;
    unsigned i = 0;
    int expect = expected_testfiles;

    DIR *d = opendir(OBJDIR PATHSEP "input" PATHSEP "clamav_hdb_scanfiles");
    ck_assert_msg(!!d, "opendir");
    if (!d)
        return;
    testfiles   = NULL;
    testfiles_n = 0;
    while ((dirent = readdir(d))) {
        if (strncmp(dirent->d_name, "clam", 4))
            continue;
        i++;
        testfiles = cli_safer_realloc(testfiles, i * sizeof(*testfiles));
        ck_assert_msg(!!testfiles, "cli_safer_realloc");
        testfiles[i - 1] = strdup(dirent->d_name);
    }
    testfiles_n = i;
    if (get_fpu_endian() == FPU_ENDIAN_UNKNOWN)
        expect--;
    expect -= skip_files();
    ck_assert_msg(testfiles_n == expect, "testfiles: %d != %d", testfiles_n, expect);

    closedir(d);
}

static void free_testfiles(void)
{
    unsigned i;
    for (i = 0; i < testfiles_n; i++) {
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
    const char *hdb   = OBJDIR PATHSEP "input" PATHSEP "clamav.hdb";

    init_testfiles();
    if (!inited)
        ck_assert_msg(cl_init(CL_INIT_DEFAULT) == 0, "cl_init");
    inited   = 1;
    g_engine = cl_engine_new();
    ck_assert_msg(!!g_engine, "engine");
    ck_assert_msg(cl_load(hdb, g_engine, &sigs, CL_DB_STDOPT) == 0, "cl_load %s", hdb);
    ck_assert_msg(sigs == 1, "sigs");
    ck_assert_msg(cl_engine_compile(g_engine) == 0, "cl_engine_compile");
}

static void engine_teardown(void)
{
    free_testfiles();
    cl_engine_free(g_engine);
}

static int get_test_file(int i, char *file, unsigned fsize, unsigned long *size)
{
    int fd;
    STATBUF st;

    ck_assert_msg(i < testfiles_n, "%i < %i %s", i, testfiles_n, file);
    snprintf(file, fsize, OBJDIR PATHSEP "input" PATHSEP "clamav_hdb_scanfiles" PATHSEP "%s", testfiles[i]);

    fd = open(file, O_RDONLY | O_BINARY);
    ck_assert_msg(fd > 0, "open");
    ck_assert_msg(FSTAT(fd, &st) == 0, "fstat");
    *size = st.st_size;
    return fd;
}

#ifndef _WIN32
static off_t pread_cb(void *handle, void *buf, size_t count, off_t offset)
{
    return pread(*((int *)handle), buf, count, offset);
}

START_TEST(test_cl_scanmap_callback_handle)
{
    const char *virname       = NULL;
    unsigned long int scanned = 0;
    cl_fmap_t *map;
    int ret;
    char file[256];
    unsigned long size;
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;

    int fd = get_test_file(_i, file, sizeof(file), &size);
    /* intentionally use different way than scanners.c for testing */
    map = cl_fmap_open_handle(&fd, 0, size, pread_cb, 1);
    ck_assert_msg(!!map, "cl_fmap_open_handle");

    cli_dbgmsg("scanning (handle) %s\n", file);
    ret = cl_scanmap_callback(map, file, &virname, &scanned, g_engine, &options, NULL);
    cli_dbgmsg("scan end (handle) %s\n", file);

    if (!FALSE_NEGATIVE) {
        ck_assert_msg(ret == CL_VIRUS, "cl_scanmap_callback failed for %s: %s", file, cl_strerror(ret));
        ck_assert_msg(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s", virname);
    }
    cl_fmap_close(map);
    close(fd);
}
END_TEST

START_TEST(test_cl_scanmap_callback_handle_allscan)
{
    const char *virname       = NULL;
    unsigned long int scanned = 0;
    cl_fmap_t *map;
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
    ck_assert(!!map);

    cli_dbgmsg("scanning (handle) allscan %s\n", file);
    ret = cl_scanmap_callback(map, file, &virname, &scanned, g_engine, &options, NULL);
    cli_dbgmsg("scan end (handle) allscan %s\n", file);

    if (!FALSE_NEGATIVE) {
        ck_assert_msg(ret == CL_VIRUS, "cl_scanmap_callback allscan failed for %s: %s", file, cl_strerror(ret));
        ck_assert_msg(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s", virname);
    }
    cl_fmap_close(map);
    close(fd);
}
END_TEST
#endif

#ifdef HAVE_SYS_MMAN_H
START_TEST(test_cl_scanmap_callback_mem)
{
    const char *virname       = NULL;
    unsigned long int scanned = 0;
    cl_fmap_t *map;
    int ret;
    void *mem;
    unsigned long size;
    char file[256];
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;

    int fd = get_test_file(_i, file, sizeof(file), &size);

    mem = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    ck_assert_msg(mem != MAP_FAILED, "mmap");

    /* intentionally use different way than scanners.c for testing */
    map = cl_fmap_open_memory(mem, size);
    ck_assert_msg(!!map, "cl_fmap_open_mem");

    cli_dbgmsg("scanning (mem) %s\n", file);
    ret = cl_scanmap_callback(map, file, &virname, &scanned, g_engine, &options, NULL);
    cli_dbgmsg("scan end (mem) %s\n", file);
    if (!FALSE_NEGATIVE) {
        ck_assert_msg(ret == CL_VIRUS, "cl_scanmap_callback failed for %s: %s", file, cl_strerror(ret));
        ck_assert_msg(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s for %s", virname, file);
    }
    close(fd);
    cl_fmap_close(map);

    munmap(mem, size);
}
END_TEST

START_TEST(test_cl_scanmap_callback_mem_allscan)
{
    const char *virname       = NULL;
    unsigned long int scanned = 0;
    cl_fmap_t *map;
    int ret;
    void *mem;
    unsigned long size;
    char file[256];
    struct cl_scan_options options;

    memset(&options, 0, sizeof(struct cl_scan_options));
    options.parse |= ~0;
    options.general |= CL_SCAN_GENERAL_ALLMATCHES;

    int fd = get_test_file(_i, file, sizeof(file), &size);

    mem = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    ck_assert_msg(mem != MAP_FAILED, "mmap");

    /* intentionally use different way than scanners.c for testing */
    map = cl_fmap_open_memory(mem, size);
    ck_assert(!!map);

    cli_dbgmsg("scanning (mem) allscan %s\n", file);
    ret = cl_scanmap_callback(map, file, &virname, &scanned, g_engine, &options, NULL);
    cli_dbgmsg("scan end (mem) allscan %s\n", file);
    if (!FALSE_NEGATIVE) {
        ck_assert_msg(ret == CL_VIRUS, "cl_scanmap_callback allscan failed for %s: %s", file, cl_strerror(ret));
        ck_assert_msg(virname && !strcmp(virname, "ClamAV-Test-File.UNOFFICIAL"), "virusname: %s for %s", virname, file);
    }
    close(fd);
    cl_fmap_close(map);
    munmap(mem, size);
}
END_TEST
#endif

START_TEST(test_fmap_duplicate)
{
    cl_fmap_t *map;
    cl_fmap_t *dup_map     = NULL;
    cl_fmap_t *dup_dup_map = NULL;
    char map_data[6]       = {'a', 'b', 'c', 'd', 'e', 'f'};
    char tmp[6];
    size_t bread = 0;

    map = cl_fmap_open_memory(map_data, sizeof(map_data));
    ck_assert_msg(!!map, "cl_fmap_open_handle failed");

    /*
     * Test duplicate of entire map
     */
    cli_dbgmsg("duplicating complete map\n");
    dup_map = fmap_duplicate(map, 0, map->len, "complete duplicate");
    ck_assert_msg(!!dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_map->nested_offset == 0, "dup_map nested_offset is incorrect: %zu", dup_map->nested_offset);
    ck_assert_msg(dup_map->len == map->len, "dup_map len is incorrect: %zu", dup_map->len);
    ck_assert_msg(dup_map->real_len == map->len, "dup_map real len is incorrect: %zu", dup_map->real_len);

    bread = fmap_readn(dup_map, tmp, 0, 6);
    ck_assert(bread == 6);
    ck_assert(0 == memcmp(map_data, tmp, 6));

    cli_dbgmsg("freeing dup_map\n");
    free_duplicate_fmap(dup_map);
    dup_map = NULL;

    /*
     * Test duplicate of map at offset 2
     */
    cli_dbgmsg("duplicating 2 bytes into map\n");
    dup_map = fmap_duplicate(map, 2, map->len, "offset duplicate");
    ck_assert_msg(!!dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_map->nested_offset == 2, "dup_map nested_offset is incorrect: %zu", dup_map->nested_offset);
    ck_assert_msg(dup_map->len == 4, "dup_map len is incorrect: %zu", dup_map->len);
    ck_assert_msg(dup_map->real_len == 6, "dup_map real len is incorrect: %zu", dup_map->real_len);

    bread = fmap_readn(dup_map, tmp, 0, 6);
    ck_assert(bread == 4);
    ck_assert(0 == memcmp(map_data + 2, tmp, 4));

    /*
     * Test duplicate of duplicate map, also at offset 2 (total 4 bytes in)
     */
    cli_dbgmsg("duplicating 2 bytes into dup_map\n");
    dup_dup_map = fmap_duplicate(dup_map, 2, dup_map->len, "double offset duplicate");
    ck_assert_msg(!!dup_dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_dup_map->nested_offset == 4, "dup_dup_map nested_offset is incorrect: %zu", dup_dup_map->nested_offset);
    ck_assert_msg(dup_dup_map->len == 2, "dup_dup_map len is incorrect: %zu", dup_dup_map->len);
    ck_assert_msg(dup_dup_map->real_len == 6, "dup_dup_map real len is incorrect: %zu", dup_dup_map->real_len);

    bread = fmap_readn(dup_dup_map, tmp, 0, 6);
    ck_assert(bread == 2);
    ck_assert(0 == memcmp(map_data + 4, tmp, 2));

    cli_dbgmsg("freeing dup_dup_map\n");
    free_duplicate_fmap(dup_dup_map);
    dup_dup_map = NULL;
    cli_dbgmsg("freeing dup_map\n");
    free_duplicate_fmap(dup_map);
    dup_map = NULL;

    /*
     * Test duplicate of map omitting the last 2 bytes
     */
    cli_dbgmsg("duplicating map with shorter len\n");
    dup_map = fmap_duplicate(map, 0, map->len - 2, "short duplicate");
    ck_assert_msg(!!dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_map->nested_offset == 0, "dup_map nested_offset is incorrect: %zu", dup_map->nested_offset);
    ck_assert_msg(dup_map->len == 4, "dup_map len is incorrect: %zu", dup_map->len);
    ck_assert_msg(dup_map->real_len == 4, "dup_map real len is incorrect: %zu", dup_map->real_len);

    bread = fmap_readn(dup_map, tmp, 0, 6);
    ck_assert(bread == 4);
    ck_assert(0 == memcmp(map_data, tmp, 4));

    /*
     * Test duplicate of the duplicate omitting the last 2 bytes again (so just the first 2 bytes)
     */
    cli_dbgmsg("duplicating dup_map with shorter len\n");
    dup_dup_map = fmap_duplicate(dup_map, 0, dup_map->len - 2, "double short duplicate");
    ck_assert_msg(!!dup_dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_dup_map->nested_offset == 0, "dup_dup_map nested_offset is incorrect: %zu", dup_dup_map->nested_offset);
    ck_assert_msg(dup_dup_map->len == 2, "dup_dup_map len is incorrect: %zu", dup_dup_map->len);
    ck_assert_msg(dup_dup_map->real_len == 2, "dup_dup_map real len is incorrect: %zu", dup_dup_map->real_len);

    bread = fmap_readn(dup_dup_map, tmp, 0, 6);
    ck_assert(bread == 2);
    ck_assert(0 == memcmp(map_data, tmp, 2));

    cli_dbgmsg("freeing dup_dup_map\n");
    free_duplicate_fmap(dup_dup_map);
    dup_dup_map = NULL;
    cli_dbgmsg("freeing dup_map\n");
    free_duplicate_fmap(dup_map);
    dup_map = NULL;

    /*
     * Test duplicate of map at offset 2
     */
    cli_dbgmsg("duplicating 2 bytes into map\n");
    dup_map = fmap_duplicate(map, 2, map->len, "offset duplicate");
    ck_assert_msg(!!dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_map->nested_offset == 2, "dup_map nested_offset is incorrect: %zu", dup_map->nested_offset);
    ck_assert_msg(dup_map->len == 4, "dup_map len is incorrect: %zu", dup_map->len);
    ck_assert_msg(dup_map->real_len == 6, "dup_map real len is incorrect: %zu", dup_map->real_len);

    bread = fmap_readn(dup_map, tmp, 0, 6);
    ck_assert(bread == 4);
    ck_assert(0 == memcmp(map_data + 2, tmp, 4));

    /*
     * Test duplicate of the duplicate omitting the last 2 bytes again (so just the middle 2 bytes)
     */
    cli_dbgmsg("duplicating dup_map with shorter len\n");
    dup_dup_map = fmap_duplicate(dup_map, 0, dup_map->len - 2, "offset short duplicate");
    ck_assert_msg(!!dup_dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_dup_map->nested_offset == 2, "dup_dup_map nested_offset is incorrect: %zu", dup_map->nested_offset);
    ck_assert_msg(dup_dup_map->len == 2, "dup_dup_map len is incorrect: %zu", dup_map->len);
    ck_assert_msg(dup_dup_map->real_len == 4, "dup_dup_map real len is incorrect: %zu", dup_map->real_len);

    bread = fmap_readn(dup_dup_map, tmp, 0, 6);
    ck_assert(bread == 2);
    ck_assert(0 == memcmp(map_data + 2, tmp, 2));

    cli_dbgmsg("freeing dup_dup_map\n");
    free_duplicate_fmap(dup_dup_map);
    dup_dup_map = NULL;
    cli_dbgmsg("freeing dup_map\n");
    free_duplicate_fmap(dup_map);
    dup_map = NULL;

    cli_dbgmsg("freeing map\n");
    cl_fmap_close(map);
}
END_TEST

START_TEST(test_fmap_duplicate_out_of_bounds)
{
    cl_fmap_t *map;
    cl_fmap_t *dup_map     = NULL;
    cl_fmap_t *dup_dup_map = NULL;
    char map_data[6]       = {'a', 'b', 'c', 'd', 'e', 'f'};
    char tmp[6];
    size_t bread = 0;

    map = cl_fmap_open_memory(map_data, sizeof(map_data));
    ck_assert_msg(!!map, "cl_fmap_open_memory failed");

    /*
     * Test 0-byte duplicate
     */
    cli_dbgmsg("duplicating 0 bytes of map\n");
    dup_map = fmap_duplicate(map, 0, 0, "zero-byte dup");
    ck_assert_msg(!!dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_map->nested_offset == 0, "dup_map nested_offset is incorrect: %zu", dup_map->nested_offset);
    ck_assert_msg(dup_map->len == 0, "dup_map len is incorrect: %zu", dup_map->len);
    ck_assert_msg(dup_map->real_len == 0, "dup_map real len is incorrect: %zu", dup_map->real_len);

    bread = fmap_readn(dup_map, tmp, 0, 6);
    ck_assert(bread == 0);

    cli_dbgmsg("freeing dup_map\n");
    free_duplicate_fmap(dup_map);
    dup_map = NULL;

    /*
     * Test duplicate of entire map + 1
     */
    cli_dbgmsg("duplicating complete map + 1 byte\n");
    dup_map = fmap_duplicate(map, 0, map->len + 1, "duplicate + 1");
    ck_assert_msg(!!dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_map->nested_offset == 0, "dup_map nested_offset is incorrect: %zu", dup_map->nested_offset);
    ck_assert_msg(dup_map->len == map->len, "dup_map len is incorrect: %zu", dup_map->len);
    ck_assert_msg(dup_map->real_len == map->len, "dup_map real len is incorrect: %zu", dup_map->real_len);

    bread = fmap_readn(dup_map, tmp, 0, 6);
    ck_assert(bread == 6);
    ck_assert(0 == memcmp(map_data, tmp, 6));

    cli_dbgmsg("freeing dup_map\n");
    free_duplicate_fmap(dup_map);
    dup_map = NULL;

    /*
     * Test duplicate of map at offset 4
     */
    cli_dbgmsg("duplicating 4 bytes into map\n");
    dup_map = fmap_duplicate(map, 4, map->len, "offset duplicate");
    ck_assert_msg(!!dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_map->nested_offset == 4, "dup_map nested_offset is incorrect: %zu", dup_map->nested_offset);
    ck_assert_msg(dup_map->len == 2, "dup_map len is incorrect: %zu", dup_map->len);
    ck_assert_msg(dup_map->real_len == 6, "dup_map real len is incorrect: %zu", dup_map->real_len);

    bread = fmap_readn(dup_map, tmp, 0, 6);
    ck_assert(bread == 2);
    ck_assert(0 == memcmp(map_data + 4, tmp, 2));

    /*
     * Test duplicate of duplicate map, also at offset 4 (total 8 bytes in, which is 2 bytes too far)
     */
    cli_dbgmsg("duplicating 4 bytes into dup_map\n");
    dup_dup_map = fmap_duplicate(dup_map, 4, dup_map->len, "out of bounds offset duplicate");
    ck_assert_msg(NULL == dup_dup_map, "fmap_duplicate should have failed!");

    cli_dbgmsg("freeing dup_map\n");
    free_duplicate_fmap(dup_map);
    dup_map = NULL;

    /*
     * Test duplicate just 2 bytes of the original
     */
    cli_dbgmsg("duplicating map with shorter len\n");
    dup_map = fmap_duplicate(map, 0, 2, "short duplicate");
    ck_assert_msg(!!dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_map->nested_offset == 0, "dup_map nested_offset is incorrect: %zu", dup_map->nested_offset);
    ck_assert_msg(dup_map->len == 2, "dup_map len is incorrect: %zu", dup_map->len);
    ck_assert_msg(dup_map->real_len == 2, "dup_map real len is incorrect: %zu", dup_map->real_len);

    bread = fmap_readn(dup_map, tmp, 0, 6);
    ck_assert(bread == 2);
    ck_assert(0 == memcmp(map_data, tmp, 2));

    /* Note: Keeping the previous dup_map around for a sequence of double-dup tests. */

    /*
     * Test duplicate 1 bytes into the 2-byte duplicate, requesting 2 bytes
     * This should result in a 1-byte double-dup
     */
    cli_dbgmsg("duplicating 1 byte in, 1 too many\n");
    dup_dup_map = fmap_duplicate(dup_map, 1, 2, "1 byte in, 1 too many");
    ck_assert_msg(!!dup_dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_dup_map->nested_offset == 1, "dup_dup_map nested_offset is incorrect: %zu", dup_dup_map->nested_offset);
    ck_assert_msg(dup_dup_map->len == 1, "dup_dup_map len is incorrect: %zu", dup_dup_map->len);
    ck_assert_msg(dup_dup_map->real_len == 2, "dup_dup_map real len is incorrect: %zu", dup_dup_map->real_len);

    bread = fmap_readn(dup_dup_map, tmp, 0, 6);
    ck_assert(bread == 1);
    ck_assert(0 == memcmp(map_data + 1, tmp, 1));

    cli_dbgmsg("freeing dup_dup_map\n");
    free_duplicate_fmap(dup_dup_map);
    dup_dup_map = NULL;

    /*
     * Test duplicate 2 bytes into the 2-byte duplicate, requesting 2 bytes
     * This should result in a 0-byte double-dup
     */
    cli_dbgmsg("duplicating 2 bytes in, 2 bytes too many\n");
    dup_dup_map = fmap_duplicate(dup_map, 2, 2, "2 bytes in, 2 bytes too many");
    ck_assert_msg(!!dup_dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_dup_map->nested_offset == 2, "dup_dup_map nested_offset is incorrect: %zu", dup_dup_map->nested_offset);
    ck_assert_msg(dup_dup_map->len == 0, "dup_dup_map len is incorrect: %zu", dup_dup_map->len);
    ck_assert_msg(dup_dup_map->real_len == 2, "dup_dup_map real len is incorrect: %zu", dup_dup_map->real_len);

    bread = fmap_readn(dup_dup_map, tmp, 0, 6);
    ck_assert(bread == 0);

    cli_dbgmsg("freeing dup_dup_map\n");
    free_duplicate_fmap(dup_dup_map);
    dup_dup_map = NULL;

    /*
     * Test duplicate 3 bytes into the 2-byte duplicate, requesting 2 bytes
     */
    cli_dbgmsg("duplicating 0-byte of duplicate\n");
    dup_dup_map = fmap_duplicate(dup_map, 3, 2, "2 bytes in, 3 bytes too many");
    ck_assert_msg(NULL == dup_dup_map, "fmap_duplicate should have failed!");

    /* Ok, we're done with this dup_map */
    cli_dbgmsg("freeing dup_map\n");
    free_duplicate_fmap(dup_map);
    dup_map = NULL;

    cli_dbgmsg("freeing map\n");
    cl_fmap_close(map);
}
END_TEST

#define FMAP_TEST_STRING_PART_1 "Hello, World!\0"
#define FMAP_TEST_STRING_PART_2 "Don't be a stranger!\nBe my friend!\0"
#define FMAP_TEST_STRING FMAP_TEST_STRING_PART_1 FMAP_TEST_STRING_PART_2

/**
 * @brief convenience function for testing
 *
 * the map data should:
 *  - be at least 6 bytes long
 *  - include a '\n' in the middle.
 *  - plus one '\0' after that.
 *  - and end with '\0'.
 *
 * @param map           The map.
 * @param map_data      A copy of the expected map data.
 * @param map_data_len  The length of the expected map data.
 */
static void fmap_api_tests(cl_fmap_t *map, const char *map_data, size_t map_data_len, const char *msg)
{
    char *tmp    = NULL;
    size_t bread = 0;
    const char *ptr, *ptr_2;
    size_t at;
    size_t lenout;
    const char *ptr_after_newline;
    size_t offset_after_newline;

    tmp = calloc(map_data_len + 1, 1);
    ck_assert_msg(tmp != NULL, "%s", msg);

    /*
     * Test fmap_readn()
     */
    bread = fmap_readn(map, tmp, 0, 5);
    ck_assert_msg(bread == 5, "%s: unexpected # bytes read: %zu", msg, bread);
    ck_assert_msg(0 == memcmp(map_data, tmp, 5), "%s: %s != %s", msg, map_data, tmp);

    /*
     * Test fmap_need_offstr()
     */
    ptr = fmap_need_offstr(map, 0, 5);
    ck_assert_msg(ptr == NULL, "%s: fmap_need_offstr should not have found a string terminator in the first 6 bytes: %s", msg, ptr);

    /*
     * Test fmap_need_offstr()
     */
    // This API must find a NULL-terminating byte
    ptr = fmap_need_offstr(map, 0, map_data_len + 5); // request at least as much as exists.
    ck_assert_msg(ptr != NULL, "%s: fmap_need_offstr failed to find a string.", msg);
    ck_assert_msg(*ptr == map_data[0], "%s: %c != %c", msg, *ptr, map_data[0]);

    /*
     * Test fmap_gets()
     */
    // first lets find the offset of the '\n' in this data.
    ptr_after_newline = memchr(map_data, '\n', map_data_len);
    ck_assert_msg(ptr_after_newline != NULL, "%s", msg);
    offset_after_newline = (size_t)ptr_after_newline - (size_t)map_data + 1;

    // This API will stop after newline or EOF, but not a NULL byte.
    memset(tmp, 0xff, map_data_len + 1); // pre-load `tmp` with 0xff so our NULL check later is guaranteed to be meaningful.
    at  = 3;                             // start at offset 3
    ptr = fmap_gets(map, tmp, &at, map_data_len + 1);
    ck_assert_msg(ptr == tmp, "%s: %zu != %zu", msg, (size_t)ptr, (size_t)tmp);
    ck_assert_msg(at == offset_after_newline, "%s: %zu != %zu", msg, at, offset_after_newline); // at should point to the character after '\n'
    ck_assert_msg(0 == memcmp(map_data + 3, tmp, offset_after_newline - 3), "%s: fmap_gets read: %s", msg, tmp);
    ck_assert_msg(tmp[offset_after_newline - 3] == '\0', "%s: data read by fmap_gets, but that value is '0x%02x'", msg, tmp[offset_after_newline - 3]); // should have a null terminator afterwards.

    memset(tmp, 0xff, map_data_len + 1); // pre-load `tmp` with 0xff so our NULL check later is guaranteed to be meaningful.
    // continue from previous read, ..
    ptr = fmap_gets(map, tmp, &at, map_data_len + 1); // read the rest of the string
    ck_assert_msg(ptr == tmp, "%s: fmap_gets should return dst pointer but returned: %zu", msg, (size_t)ptr);
    ck_assert_msg(at == map_data_len, "%s: %zu != %zu", msg, at, map_data_len); // at should point just past end of string
    ck_assert_msg(0 == memcmp(map_data + offset_after_newline, tmp, map_data_len - offset_after_newline), "%s", msg);
    ck_assert_msg(tmp[map_data_len - offset_after_newline] == '\0', "%s: data read by fmap_gets, but that value is '0x%02x'", msg, tmp[map_data_len - offset_after_newline]); // should have a null terminator afterwards.

    /*
     * Test fmap_need_off_once_len()
     */
    ptr = fmap_need_off_once_len(map, 0, map_data_len + 50, &lenout); // request more bytes than is available
    ck_assert_msg(ptr != NULL, "%s: failed to get pointer into map :(", msg);
    ck_assert_msg(lenout == map_data_len, "%s: %zu != %zu", msg, lenout, map_data_len);
    ck_assert_msg(0 == memcmp(ptr, map_data, offset_after_newline), "%s", msg);

    /*
     * Test fmap_need_off_once()
     */
    ptr = fmap_need_off_once(map, 0, map_data_len + 50); // request more bytes than is available
    ck_assert_msg(ptr == NULL, "%s: should have failed to get pointer into map :(", msg);

    ptr = fmap_need_off_once(map, 0, offset_after_newline);
    ck_assert_msg(ptr != NULL, "%s: failed to get pointer into map :(", msg);
    ck_assert_msg(0 == memcmp(ptr, map_data, offset_after_newline), "%s", msg);

    /*
     * Test fmap_need_ptr_once()
     */
    ptr_2 = fmap_need_ptr_once(map, ptr, map_data_len + 50); // request more bytes than is available
    ck_assert_msg(ptr_2 == NULL, "%s: should have failed to get pointer into map :(", msg);

    ptr_2 = fmap_need_ptr_once(map, ptr, offset_after_newline);
    ck_assert_msg(ptr_2 != NULL, "%s: failed to get pointer into map :(", msg);
    ck_assert_msg(0 == memcmp(ptr_2, map_data, offset_after_newline), "%s", msg);

    free(tmp);
}

START_TEST(test_fmap_assorted_api)
{
    cl_fmap_t *mem_based_map     = NULL;
    cl_fmap_t *fd_based_map      = NULL;
    cl_fmap_t *fd_based_dup_map  = NULL;
    cl_fmap_t *dup_map           = NULL;
    char *fmap_dump_filepath     = NULL;
    int fmap_dump_fd             = -1;
    char *dup_fmap_dump_filepath = NULL;
    int dup_fmap_dump_fd         = -1;

    mem_based_map = cl_fmap_open_memory(FMAP_TEST_STRING, sizeof(FMAP_TEST_STRING));
    ck_assert_msg(!!mem_based_map, "cl_fmap_open_memory failed");
    cli_dbgmsg("created fmap from memory/buffer\n");

    /*
     * Test a few things on the original map.
     */
    fmap_api_tests(mem_based_map, FMAP_TEST_STRING, sizeof(FMAP_TEST_STRING), "mem map");

    /*
     * Test fmap_dump_to_file()
     */
    fmap_dump_to_file(mem_based_map, NULL, NULL, &fmap_dump_filepath, &fmap_dump_fd, 0, mem_based_map->len);
    ck_assert_msg(fmap_dump_fd != -1, "fmap_dump_fd failed");
    cli_dbgmsg("dumped map to %s\n", fmap_dump_filepath);

    fd_based_map = fmap_new(fmap_dump_fd, 0, 0, NULL, NULL); // using fmap_new() instead of cl_fmap_open_handle() because I don't want to have to stat the file to figure out the len. fmap_new() does that for us.
    ck_assert_msg(!!fd_based_map, "cl_fmap_open_handle failed");
    cli_dbgmsg("created fmap from file descriptor\n");

    /*
     * Test those same things on an fmap created with an fd that is a dumped copy of the original map.
     */
    fmap_api_tests(fd_based_map, FMAP_TEST_STRING, sizeof(FMAP_TEST_STRING), "handle map");

    /*
     * Test duplicate of mem-based map at an offset
     */
    cli_dbgmsg("duplicating part way into mem-based fmap\n");
    dup_map = fmap_duplicate(
        mem_based_map,
        sizeof(FMAP_TEST_STRING_PART_1) - 1, // minus automatic null terminator
        mem_based_map->len - (sizeof(FMAP_TEST_STRING_PART_1) - 1),
        "offset duplicate");
    ck_assert_msg(!!dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_map->nested_offset == sizeof(FMAP_TEST_STRING_PART_1) - 1, "%zu != %zu", dup_map->nested_offset, sizeof(FMAP_TEST_STRING_PART_1) - 1);
    ck_assert_msg(dup_map->len == sizeof(FMAP_TEST_STRING_PART_2), "%zu != %zu", dup_map->len, sizeof(FMAP_TEST_STRING_PART_2));
    ck_assert_msg(dup_map->real_len == sizeof(FMAP_TEST_STRING), "%zu != %zu", dup_map->real_len, sizeof(FMAP_TEST_STRING));

    /*
     * Test those same things on an fmap created with an fd that is a dumped copy of the original map.
     */
    fmap_api_tests(dup_map, FMAP_TEST_STRING_PART_2, sizeof(FMAP_TEST_STRING_PART_2), "nested mem map");

    /* Ok, we're done with this dup_map */
    cli_dbgmsg("freeing dup_map\n");
    free_duplicate_fmap(dup_map);
    dup_map = NULL;

    /*
     * Test duplicate of handle-based map at an offset
     */
    cli_dbgmsg("duplicating part way into handle-based fmap\n");
    dup_map = fmap_duplicate(
        fd_based_map,
        sizeof(FMAP_TEST_STRING_PART_1) - 1, // minus automatic null terminator
        fd_based_map->len - (sizeof(FMAP_TEST_STRING_PART_1) - 1),
        "offset duplicate");
    ck_assert_msg(!!dup_map, "fmap_duplicate failed");
    ck_assert_msg(dup_map->nested_offset == sizeof(FMAP_TEST_STRING_PART_1) - 1, "%zu != %zu", dup_map->nested_offset, sizeof(FMAP_TEST_STRING_PART_1) - 1);
    ck_assert_msg(dup_map->len == sizeof(FMAP_TEST_STRING_PART_2), "%zu != %zu", dup_map->len, sizeof(FMAP_TEST_STRING_PART_2));
    ck_assert_msg(dup_map->real_len == sizeof(FMAP_TEST_STRING), "%zu != %zu", dup_map->real_len, sizeof(FMAP_TEST_STRING));

    /*
     * Test those same things on an fmap created with an fd that is a dumped copy of the original map.
     */
    fmap_api_tests(dup_map, FMAP_TEST_STRING_PART_2, sizeof(FMAP_TEST_STRING_PART_2), "nested handle map");

    /*
     * Test fmap_dump_to_file() on a nested fmap
     */
    fmap_dump_to_file(dup_map, NULL, NULL, &dup_fmap_dump_filepath, &dup_fmap_dump_fd, 0, dup_map->len);
    ck_assert_msg(dup_fmap_dump_fd != -1, "fmap_dump_fd failed");
    cli_dbgmsg("dumped map to %s\n", dup_fmap_dump_filepath);

    /* Ok, we're done with this dup_map */
    cli_dbgmsg("freeing dup_map\n");
    free_duplicate_fmap(dup_map);
    dup_map = NULL;

    /* We can close the fd-based map now that we're done with its duplicate */
    cl_fmap_close(fd_based_map);
    fd_based_map = NULL;

    close(fmap_dump_fd);
    fmap_dump_fd = -1;

    cli_unlink(fmap_dump_filepath);
    free(fmap_dump_filepath);
    fmap_dump_filepath = NULL;

    /* And we can close the original mem-based map as well */
    cl_fmap_close(mem_based_map);
    mem_based_map = NULL;

    /*
     * Let's make an fmap of the dumped nested map, and run the tests to verify that everything is as expected.
     */
    fd_based_dup_map = fmap_new(dup_fmap_dump_fd, 0, 0, NULL, NULL); // using fmap_new() instead of cl_fmap_open_handle() because I don't want to have to stat the file to figure out the len. fmap_new() does that for us.
    ck_assert_msg(!!fd_based_dup_map, "cl_fmap_open_handle failed");
    cli_dbgmsg("created fmap from file descriptor\n");

    /*
     * Test those same things on an fmap created with an fd that is a dumped copy of the original map.
     */
    fmap_api_tests(fd_based_dup_map, FMAP_TEST_STRING_PART_2, sizeof(FMAP_TEST_STRING_PART_2), "dumped nested handle map");

    /* Ok, we're done with the fmap based on the dumped dup_map */
    cli_dbgmsg("freeing fmap of dumped dup_map\n");
    cl_fmap_close(fd_based_dup_map);
    fd_based_dup_map = NULL;

    close(dup_fmap_dump_fd);
    dup_fmap_dump_fd = -1;

    cli_unlink(dup_fmap_dump_filepath);
    free(dup_fmap_dump_filepath);
    dup_fmap_dump_filepath = NULL;
}
END_TEST

static Suite *test_cl_suite(void)
{
    Suite *s           = suite_create("cl_suite");
    TCase *tc_cl       = tcase_create("cl_api");
    TCase *tc_cl_scan  = tcase_create("cl_scan_api");
    char *user_timeout = NULL;
    int expect         = expected_testfiles;
    suite_add_tcase(s, tc_cl);
    tcase_add_checked_fixture(tc_cl, cl_setup, cl_teardown);
    tcase_add_test(tc_cl, test_cl_free);
    tcase_add_test(tc_cl, test_cl_build);
    tcase_add_test(tc_cl, test_cl_debug);
#ifndef _WIN32
    tcase_add_test(tc_cl, test_cl_retdbdir);
#endif
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

    if (get_fpu_endian() == FPU_ENDIAN_UNKNOWN)
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
#ifndef _WIN32
    tcase_add_loop_test(tc_cl_scan, test_cl_scanmap_callback_handle, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_cl_scanmap_callback_handle_allscan, 0, expect);
#endif
#ifdef HAVE_SYS_MMAN_H
    tcase_add_loop_test(tc_cl_scan, test_cl_scanmap_callback_mem, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_cl_scanmap_callback_mem_allscan, 0, expect);
#endif
    tcase_add_loop_test(tc_cl_scan, test_fmap_duplicate, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_fmap_duplicate_out_of_bounds, 0, expect);
    tcase_add_loop_test(tc_cl_scan, test_fmap_assorted_api, 0, expect);

    user_timeout = getenv("T");
    if (user_timeout) {
        int timeout = atoi(user_timeout);
        tcase_set_timeout(tc_cl_scan, timeout);
        printf("Using test case timeout of %d seconds set by user\n", timeout);
    } else {
        printf("Using default test timeout; alter by setting 'T' env var (in seconds)\n");
    }
    return s;
}

static uint8_t le_data[4]     = {0x67, 0x45, 0x23, 0x01};
static int32_t le_expected[4] = {0x01234567, 0x67012345, 0x45670123, 0x23456701};
uint8_t *data                 = NULL;
uint8_t *data2                = NULL;
#define DATA_REP 100

static void data_setup(void)
{
    uint8_t *p;
    size_t i;

    data  = malloc(sizeof(le_data) * DATA_REP);
    data2 = malloc(sizeof(le_data) * DATA_REP);
    ck_assert_msg(!!data, "unable to allocate memory for fixture");
    ck_assert_msg(!!data2, "unable to allocate memory for fixture");
    p = data;
    /* make multiple copies of le_data, we need to run readint tests in a loop, so we need
     * to give it some data to run it on */
    for (i = 0; i < DATA_REP; i++) {
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

/* test reading with different alignments, _i is parameter from tcase_add_loop_test */
START_TEST(test_cli_readint16)
{
    size_t j;
    int16_t value;
    /* read 2 bytes apart, start is not always aligned*/
    for (j = _i; j <= DATA_REP * sizeof(le_data) - 2; j += 2) {
        value = le_expected[j & 3];
        ck_assert_msg(cli_readint16(&data[j]) == value, "(1) data read must be little endian");
    }
    /* read 2 bytes apart, always aligned*/
    for (j = 0; j <= DATA_REP * sizeof(le_data) - 2; j += 2) {
        value = le_expected[j & 3];
        ck_assert_msg(cli_readint16(&data[j]) == value, "(2) data read must be little endian");
    }
}
END_TEST

/* test reading with different alignments, _i is parameter from tcase_add_loop_test */
START_TEST(test_cli_readint32)
{
    size_t j;
    int32_t value = le_expected[_i & 3];
    /* read 4 bytes apart, start is not always aligned*/
    for (j = _i; j < DATA_REP * sizeof(le_data) - 4; j += 4) {
        ck_assert_msg(cli_readint32(&data[j]) == value, "(1) data read must be little endian");
    }
    value = le_expected[0];
    /* read 4 bytes apart, always aligned*/
    for (j = 0; j < DATA_REP * sizeof(le_data) - 4; j += 4) {
        ck_assert_msg(cli_readint32(&data[j]) == value, "(2) data read must be little endian");
    }
}
END_TEST

/* test writing with different alignments, _i is parameter from tcase_add_loop_test */
START_TEST(test_cli_writeint32)
{
    size_t j;
    /* write 4 bytes apart, start is not always aligned*/
    for (j = _i; j < DATA_REP * sizeof(le_data) - 4; j += 4) {
        cli_writeint32(&data2[j], 0x12345678);
    }
    for (j = _i; j < DATA_REP * sizeof(le_data) - 4; j += 4) {
        ck_assert_msg(cli_readint32(&data2[j]) == 0x12345678, "write/read mismatch");
    }
    /* write 4 bytes apart, always aligned*/
    for (j = 0; j < DATA_REP * sizeof(le_data) - 4; j += 4) {
        cli_writeint32(&data2[j], 0x12345678);
    }
    for (j = 0; j < DATA_REP * sizeof(le_data) - 4; j += 4) {
        ck_assert_msg(cli_readint32(&data2[j]) == 0x12345678, "write/read mismatch");
    }
}
END_TEST

static struct dsig_test {
    const char *md5;
    const char *dsig;
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
    ck_assert_msg(cli_versig(dsig_tests[_i].md5, dsig_tests[_i].dsig) == dsig_tests[_i].result,
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

START_TEST(test_sha2_256)
{
    void *sha2_256;
    uint8_t h_sha2_256[SHA256_HASH_SIZE];
    uint8_t buf[1000];
    int i;

    memset(buf, 0x61, sizeof(buf));

    cl_sha256(tv1, sizeof(tv1), h_sha2_256, NULL);
    ck_assert_msg(!memcmp(h_sha2_256, res256[0], sizeof(h_sha2_256)), "sha2-256 test vector #1 failed");

    cl_sha256(tv2, sizeof(tv2), h_sha2_256, NULL);
    ck_assert_msg(!memcmp(h_sha2_256, res256[1], sizeof(h_sha2_256)), "sha2-256 test vector #2 failed");

    sha2_256 = cl_hash_init("sha2-256");
    ck_assert_msg(sha2_256 != NULL, "Could not create EVP_MD_CTX for sha2-256");

    for (i = 0; i < 1000; i++)
        cl_update_hash(sha2_256, buf, sizeof(buf));
    cl_finish_hash(sha2_256, h_sha2_256);
    ck_assert_msg(!memcmp(h_sha2_256, res256[2], sizeof(h_sha2_256)), "sha2-256 test vector #3 failed");
}
END_TEST

START_TEST(test_sanitize_path)
{
    const char *unsanitized   = NULL;
    char *sanitized           = NULL;
    char *sanitized_base      = NULL;
    const char *expected      = NULL;
    const char *expected_base = NULL;

    unsanitized = "";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);

    unsanitized = "";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);
    ck_assert_msg(NULL == sanitized_base, "Expected: NULL, Found: \"%s\"", sanitized_base);

    unsanitized = NULL;
    sanitized   = cli_sanitize_filepath(unsanitized, 0, NULL);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);

    unsanitized = NULL;
    sanitized   = cli_sanitize_filepath(unsanitized, 0, &sanitized_base);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);
    ck_assert_msg(NULL == sanitized_base, "Expected: NULL, Found: \"%s\"", sanitized_base);

    unsanitized = NULL;
    sanitized   = cli_sanitize_filepath(unsanitized, 50, NULL);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);

    unsanitized = NULL;
    sanitized   = cli_sanitize_filepath(unsanitized, 50, &sanitized_base);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);
    ck_assert_msg(NULL == sanitized_base, "Expected: NULL, Found: \"%s\"", sanitized_base);

    unsanitized = "badlen";
    sanitized   = cli_sanitize_filepath(unsanitized, 0, NULL);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);

    unsanitized = "badlen";
    sanitized   = cli_sanitize_filepath(unsanitized, 0, &sanitized_base);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);
    ck_assert_msg(NULL == sanitized_base, "Expected: NULL, Found: \"%s\"", sanitized_base);

    unsanitized = ".." PATHSEP;
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);

    unsanitized = ".." PATHSEP;
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);
    ck_assert_msg(NULL == sanitized_base, "Expected: NULL, Found: \"%s\"", sanitized_base);

    unsanitized = "." PATHSEP;
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);

    unsanitized = "." PATHSEP;
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);
    ck_assert_msg(NULL == sanitized_base, "Expected: NULL, Found: \"%s\"", sanitized_base);

    unsanitized = PATHSEP;
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert_msg(NULL == sanitized, "sanitize_path: sanitized path should have been NULL (3)");

    unsanitized = PATHSEP;
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert_msg(NULL == sanitized, "Expected: NULL, Found: \"%s\"", sanitized);
    ck_assert_msg(NULL == sanitized_base, "Expected: NULL, Found: \"%s\"", sanitized_base);

    unsanitized = ".." PATHSEP "relative_bad_1";
    expected    = "relative_bad_1";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert(NULL != sanitized);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    free(sanitized);

    unsanitized   = ".." PATHSEP "relative_bad_1";
    expected      = "relative_bad_1";
    expected_base = "relative_bad_1";
    sanitized     = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert(NULL != sanitized);
    ck_assert(NULL != sanitized_base);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    ck_assert_msg(!strcmp(expected_base, sanitized_base), "Expected: \"%s\", Found: \"%s\"", expected_base, sanitized_base);
    free(sanitized);

    unsanitized = "relative" PATHSEP ".." PATHSEP "good";
    expected    = "relative" PATHSEP ".." PATHSEP "good";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert(NULL != sanitized);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    free(sanitized);

    unsanitized   = "relative" PATHSEP ".." PATHSEP "good";
    expected      = "relative" PATHSEP ".." PATHSEP "good";
    expected_base = "good";
    sanitized     = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert(NULL != sanitized);
    ck_assert(NULL != sanitized_base);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    ck_assert_msg(!strcmp(expected_base, sanitized_base), "Expected: \"%s\", Found: \"%s\"", expected_base, sanitized_base);
    free(sanitized);

    unsanitized = "relative" PATHSEP ".." PATHSEP ".." PATHSEP "bad_2";
    expected    = "relative" PATHSEP ".." PATHSEP "bad_2";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert(NULL != sanitized);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    free(sanitized);

    unsanitized   = "relative" PATHSEP ".." PATHSEP ".." PATHSEP "bad_2";
    expected      = "relative" PATHSEP ".." PATHSEP "bad_2";
    expected_base = "bad_2";
    sanitized     = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert(NULL != sanitized);
    ck_assert(NULL != sanitized_base);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    ck_assert_msg(!strcmp(expected_base, sanitized_base), "Expected: \"%s\", Found: \"%s\"", expected_base, sanitized_base);
    free(sanitized);

    unsanitized = "relative" PATHSEP "." PATHSEP ".." PATHSEP ".." PATHSEP "bad_current";
    expected    = "relative" PATHSEP ".." PATHSEP "bad_current";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert(NULL != sanitized);
    ck_assert_msg(!strcmp(sanitized, "relative" PATHSEP ".." PATHSEP "bad_current"), "sanitize_path: bad relative current path test failed");
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    free(sanitized);

    unsanitized   = "relative" PATHSEP "." PATHSEP ".." PATHSEP ".." PATHSEP "bad_current";
    expected      = "relative" PATHSEP ".." PATHSEP "bad_current";
    expected_base = "bad_current";
    sanitized     = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert(NULL != sanitized);
    ck_assert(NULL != sanitized_base);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    ck_assert_msg(!strcmp(expected_base, sanitized_base), "Expected: \"%s\", Found: \"%s\"", expected_base, sanitized_base);
    free(sanitized);

    unsanitized = "relative/../../bad_win_posix_path"; // <-- posix paths intentionally specified -- should still work on Windows)
    expected    = "relative" PATHSEP ".." PATHSEP "bad_win_posix_path";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert(NULL != sanitized);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    free(sanitized);

    unsanitized   = "relative/../../bad_win_posix_path"; // <-- posix paths intentionally specified -- should still work on Windows)
    expected      = "relative" PATHSEP ".." PATHSEP "bad_win_posix_path";
    expected_base = "bad_win_posix_path";
    sanitized     = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert(NULL != sanitized);
    ck_assert(NULL != sanitized_base);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    ck_assert_msg(!strcmp(expected_base, sanitized_base), "Expected: \"%s\", Found: \"%s\"", expected_base, sanitized_base);
    free(sanitized);

    unsanitized = "" PATHSEP "absolute" PATHSEP ".." PATHSEP ".." PATHSEP "bad";
    expected    = "absolute" PATHSEP ".." PATHSEP "bad";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert(NULL != sanitized);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    free(sanitized);

    unsanitized   = "" PATHSEP "absolute" PATHSEP ".." PATHSEP ".." PATHSEP "bad";
    expected      = "absolute" PATHSEP ".." PATHSEP "bad";
    expected_base = "bad";
    sanitized     = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert(NULL != sanitized);
    ck_assert(NULL != sanitized_base);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    ck_assert_msg(!strcmp(expected_base, sanitized_base), "Expected: \"%s\", Found: \"%s\"", expected_base, sanitized_base);
    free(sanitized);

    unsanitized = "" PATHSEP "absolute" PATHSEP ".." PATHSEP "good";
    expected    = "absolute" PATHSEP ".." PATHSEP "good";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert(NULL != sanitized);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    free(sanitized);

    unsanitized   = "" PATHSEP "absolute" PATHSEP ".." PATHSEP "good";
    expected      = "absolute" PATHSEP ".." PATHSEP "good";
    expected_base = "good";
    sanitized     = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert(NULL != sanitized);
    ck_assert(NULL != sanitized_base);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    ck_assert_msg(!strcmp(expected_base, sanitized_base), "Expected: \"%s\", Found: \"%s\"", expected_base, sanitized_base);
    free(sanitized);

    unsanitized = "relative" PATHSEP "normal";
    expected    = "relative" PATHSEP "normal";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert(NULL != sanitized);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    free(sanitized);

    unsanitized   = "relative" PATHSEP "normal";
    expected      = "relative" PATHSEP "normal";
    expected_base = "normal";
    sanitized     = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert(NULL != sanitized);
    ck_assert(NULL != sanitized_base);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    ck_assert_msg(!strcmp(expected_base, sanitized_base), "Expected: \"%s\", Found: \"%s\"", expected_base, sanitized_base);
    free(sanitized);

    unsanitized = "relative" PATHSEP PATHSEP "doublesep";
    expected    = "relative" PATHSEP "doublesep";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert(NULL != sanitized);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    free(sanitized);

    unsanitized   = "relative" PATHSEP PATHSEP "doublesep";
    expected      = "relative" PATHSEP "doublesep";
    expected_base = "doublesep";
    sanitized     = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert(NULL != sanitized);
    ck_assert(NULL != sanitized_base);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    ck_assert_msg(!strcmp(expected_base, sanitized_base), "Expected: \"%s\", Found: \"%s\"", expected_base, sanitized_base);
    free(sanitized);

    unsanitized = "relative" PATHSEP "shortname" PATHSEP "1";
    expected    = "relative" PATHSEP "shortname" PATHSEP "1";
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert(NULL != sanitized);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    free(sanitized);

    unsanitized   = "relative" PATHSEP "shortname" PATHSEP "1";
    expected      = "relative" PATHSEP "shortname" PATHSEP "1";
    expected_base = "1";
    sanitized     = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert(NULL != sanitized);
    ck_assert(NULL != sanitized_base);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    ck_assert_msg(!strcmp(expected_base, sanitized_base), "Expected: \"%s\", Found: \"%s\"", expected_base, sanitized_base);
    free(sanitized);

    unsanitized = "relative" PATHSEP "noname" PATHSEP;
    expected    = "relative" PATHSEP "noname" PATHSEP;
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), NULL);
    ck_assert(NULL != sanitized);
    ck_assert_msg(!strcmp(sanitized, "relative" PATHSEP "noname" PATHSEP), "sanitize_path: relative no name path test failed");
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    free(sanitized);

    unsanitized = "relative" PATHSEP "noname" PATHSEP;
    expected    = "relative" PATHSEP "noname" PATHSEP;
    sanitized   = cli_sanitize_filepath(unsanitized, strlen(unsanitized), &sanitized_base);
    ck_assert(NULL != sanitized);
    ck_assert(NULL == sanitized_base);
    ck_assert_msg(!strcmp(expected, sanitized), "Expected: \"%s\", Found: \"%s\"", expected, sanitized);
    free(sanitized);
}
END_TEST

START_TEST(test_cli_codepage_to_utf8_jis)
{
    cl_error_t ret;
    char *utf8       = NULL;
    size_t utf8_size = 0;

    ret = cli_codepage_to_utf8("\x82\xB1\x82\xF1\x82\xC9\x82\xBF\x82\xCD", 10, CODEPAGE_JAPANESE_SHIFT_JIS, &utf8, &utf8_size);
    ck_assert_msg(CL_SUCCESS == ret, "test_cli_codepage_to_utf8: Failed to convert CODEPAGE_JAPANESE_SHIFT_JIS to UTF8: ret != SUCCESS!");
    ck_assert_msg(NULL != utf8, "sanitize_path: Failed to convert CODEPAGE_JAPANESE_SHIFT_JIS to UTF8: utf8 pointer is NULL!");
    ck_assert_msg(0 == strcmp(utf8, "こんにちは"), "sanitize_path: '%s' doesn't match '%s'", utf8, "こんにちは");

    if (NULL != utf8) {
        free(utf8);
        utf8 = NULL;
    }
}
END_TEST

START_TEST(test_cli_codepage_to_utf8_utf16be_null_term)
{
    cl_error_t ret;
    char *utf8       = NULL;
    size_t utf8_size = 0;

    ret = cli_codepage_to_utf8("\x00\x48\x00\x65\x00\x6c\x00\x6c\x00\x6f\x00\x20\x00\x77\x00\x6f\x00\x72\x00\x6c\x00\x64\x00\x21\x00\x00", 26, CODEPAGE_UTF16_BE, &utf8, &utf8_size);
    ck_assert_msg(CL_SUCCESS == ret, "test_cli_codepage_to_utf8: Failed to convert CODEPAGE_UTF16_BE to UTF8: ret != SUCCESS!");
    ck_assert_msg(NULL != utf8, "sanitize_path: Failed to convert CODEPAGE_UTF16_BE to UTF8: utf8 pointer is NULL!");
    ck_assert_msg(0 == strcmp(utf8, "Hello world!"), "sanitize_path: '%s' doesn't match '%s'", utf8, "Hello world!");

    if (NULL != utf8) {
        free(utf8);
        utf8 = NULL;
    }
}
END_TEST

START_TEST(test_cli_codepage_to_utf8_utf16be_no_null_term)
{
    cl_error_t ret;
    char *utf8       = NULL;
    size_t utf8_size = 0;

    ret = cli_codepage_to_utf8("\x00\x48\x00\x65\x00\x6c\x00\x6c\x00\x6f\x00\x20\x00\x77\x00\x6f\x00\x72\x00\x6c\x00\x64\x00\x21", 24, CODEPAGE_UTF16_BE, &utf8, &utf8_size);
    ck_assert_msg(CL_SUCCESS == ret, "test_cli_codepage_to_utf8: Failed to convert CODEPAGE_UTF16_BE to UTF8: ret != SUCCESS!");
    ck_assert_msg(NULL != utf8, "sanitize_path: Failed to convert CODEPAGE_UTF16_BE to UTF8: utf8 pointer is NULL!");
    ck_assert_msg(0 == strcmp(utf8, "Hello world!"), "sanitize_path: '%s' doesn't match '%s'", utf8, "Hello world!");

    if (NULL != utf8) {
        free(utf8);
        utf8 = NULL;
    }
}
END_TEST

START_TEST(test_cli_codepage_to_utf8_utf16le)
{
    cl_error_t ret;
    char *utf8       = NULL;
    size_t utf8_size = 0;

    ret = cli_codepage_to_utf8("\x48\x00\x65\x00\x6c\x00\x6c\x00\x6f\x00\x20\x00\x77\x00\x6f\x00\x72\x00\x6c\x00\x64\x00\x21\x00\x00\x00", 26, CODEPAGE_UTF16_LE, &utf8, &utf8_size);
    ck_assert_msg(CL_SUCCESS == ret, "test_cli_codepage_to_utf8: Failed to convert CODEPAGE_UTF16_LE to UTF8: ret != SUCCESS!");
    ck_assert_msg(NULL != utf8, "sanitize_path: Failed to convert CODEPAGE_UTF16_LE to UTF8: utf8 pointer is NULL!");
    ck_assert_msg(0 == strcmp(utf8, "Hello world!"), "sanitize_path: '%s' doesn't match '%s'", utf8, "Hello world!");

    if (NULL != utf8) {
        free(utf8);
        utf8 = NULL;
    }
}
END_TEST

static Suite *test_cli_suite(void)
{
    Suite *s               = suite_create("cli");
    TCase *tc_cli_others   = tcase_create("byteorder_macros");
    TCase *tc_cli_dsig     = tcase_create("digital signatures");
    TCase *tc_cli_assorted = tcase_create("assorted functions");

    suite_add_tcase(s, tc_cli_others);
    tcase_add_checked_fixture(tc_cli_others, data_setup, data_teardown);
    tcase_add_loop_test(tc_cli_others, test_cli_readint32, 0, 16);
    tcase_add_loop_test(tc_cli_others, test_cli_readint16, 0, 16);
    tcase_add_loop_test(tc_cli_others, test_cli_writeint32, 0, 16);

    suite_add_tcase(s, tc_cli_dsig);
    tcase_add_loop_test(tc_cli_dsig, test_cli_dsig, 0, dsig_tests_cnt);
    tcase_add_test(tc_cli_dsig, test_sha2_256);

    suite_add_tcase(s, tc_cli_assorted);
    tcase_add_test(tc_cli_assorted, test_sanitize_path);
    tcase_add_test(tc_cli_assorted, test_cli_codepage_to_utf8_jis);
    tcase_add_test(tc_cli_assorted, test_cli_codepage_to_utf8_utf16be_null_term);
    tcase_add_test(tc_cli_assorted, test_cli_codepage_to_utf8_utf16be_no_null_term);
    tcase_add_test(tc_cli_assorted, test_cli_codepage_to_utf8_utf16le);

    return s;
}

void errmsg_expected(void)
{
    fputs("cli_errmsg() expected here\n", stderr);
}

int open_testfile(const char *name, int flags)
{
    int fd;
    char *str;

    str = malloc(strlen(name) + strlen(SRCDIR) + 2);
    ck_assert_msg(!!str, "malloc");
    sprintf(str, "%s" PATHSEP "%s", SRCDIR, name);

    fd = open(str, flags);
    ck_assert_msg(fd >= 0, "open() failed: %s", str);
    free(str);
    return fd;
}

void diff_file_mem(int fd, const char *ref, size_t len)
{
    char c1, c2;
    size_t p, reflen = len;
    char *buf = malloc(len);

    ck_assert_msg(!!buf, "unable to malloc buffer: %zu", len);
    p = read(fd, buf, len);
    ck_assert_msg(p == len, "file is smaller: %lu, expected: %lu", p, len);
    p = 0;
    while (len > 0) {
        c1 = ref[p];
        c2 = buf[p];
        if (c1 != c2)
            break;
        p++;
        len--;
    }
    if (len > 0)
        ck_assert_msg(c1 == c2, "file contents mismatch at byte: %lu, was: %c, expected: %c", p, c2, c1);
    free(buf);
    p = lseek(fd, 0, SEEK_END);
    ck_assert_msg(p == reflen, "trailing garbage, file size: %ld, expected: %ld", p, reflen);
    close(fd);
}

void diff_files(int fd, int ref_fd)
{
    char *ref;
    ssize_t nread;
    off_t siz = lseek(ref_fd, 0, SEEK_END);
    ck_assert_msg(siz != -1, "lseek failed");

    ref = malloc(siz);
    ck_assert_msg(!!ref, "unable to malloc buffer: " STDi64, (int64_t)siz);

    ck_assert_msg(lseek(ref_fd, 0, SEEK_SET) == 0, "lseek failed");
    nread = read(ref_fd, ref, siz);
    ck_assert_msg(nread == siz, "short read, expected: %ld, was: %ld", siz, nread);
    close(ref_fd);
    diff_file_mem(fd, ref, siz);
    free(ref);
}

#ifdef USE_MPOOL
static mpool_t *pool;
#else
static void *pool;
#endif
struct cli_dconf *dconf;

void dconf_setup(void)
{
    pool  = NULL;
    dconf = NULL;
#ifdef USE_MPOOL
    pool = mpool_create();
    ck_assert_msg(!!pool, "unable to create pool");
#endif
    dconf = cli_mpool_dconf_init(pool);
    ck_assert_msg(!!dconf, "failed to init dconf");
}

void dconf_teardown(void)
{
    MPOOL_FREE(pool, dconf);
#ifdef USE_MPOOL
    if (pool)
        mpool_destroy(pool);
#endif
}

#ifndef _WIN32
static void check_version_compatible()
{
    /* check 0.9.8 is not ABI compatible with 0.9.6,
     * if by accident you compile with check 0.9.6 header
     * and link with 0.9.8 then check will hang/crash. */
    if ((check_major_version != CHECK_MAJOR_VERSION) ||
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
#endif

int main(int argc, char **argv)
{
    int nf;
    Suite *s;
    SRunner *sr;
    FILE *log_file = NULL;

    UNUSEDPARAM(argc);
    UNUSEDPARAM(argv);

    cl_initialize_crypto();

    fpu_words = get_fpu_endian();

#ifndef _WIN32
    check_version_compatible();
#endif
    s  = test_cl_suite();
    sr = srunner_create(s);

    srunner_add_suite(sr, test_cli_suite());
    srunner_add_suite(sr, test_jsnorm_suite());
    srunner_add_suite(sr, test_str_suite());
    srunner_add_suite(sr, test_regex_suite());
    srunner_add_suite(sr, test_disasm_suite());
    srunner_add_suite(sr, test_uniq_suite());
    srunner_add_suite(sr, test_matchers_suite());
    srunner_add_suite(sr, test_htmlnorm_suite());
    srunner_add_suite(sr, test_bytecode_suite());

    srunner_set_log(sr, OBJDIR PATHSEP "test.log");
    log_file = freopen(OBJDIR PATHSEP "test-stderr.log", "w+", stderr);
    if (log_file == NULL) {
        // The stderr FILE pointer may be closed by `freopen()` even if redirecting to the log file files.
        // So we will output the error message to stdout instead.
        fputs("Unable to redirect stderr!\n", stdout);
    }
    cl_debug();

    srunner_run_all(sr, CK_NORMAL);
    nf = srunner_ntests_failed(sr);
    if (nf)
        printf("NOTICE: Use the 'T' environment variable to adjust testcase timeout\n");
    srunner_free(sr);

    xmlCleanupParser();

    if (log_file) {
        fclose(log_file);
    }

    return (nf == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
