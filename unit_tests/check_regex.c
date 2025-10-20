/*
 *  Unit tests for regular expression processing.
 *
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */
#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <check.h>
#include <fcntl.h>

// libclamav
#include "clamav.h"
#include "others.h"
#include "mbox.h"
#include "message.h"
#include "htmlnorm.h"
#include "phishcheck.h"
#include "regex_suffix.h"
#include "regex_list.h"
#include "phish_domaincheck_db.h"
#include "phish_allow_list.h"

#include "clamav_rust.h"

#include "checks.h"

static size_t cb_called = 0;

static cl_error_t cb_fail(void *cbdata, const char *suffix, size_t len, const struct regex_list *regex)
{
    UNUSEDPARAM(cbdata);
    UNUSEDPARAM(suffix);
    UNUSEDPARAM(len);
    UNUSEDPARAM(regex);

    ck_abort_msg("this pattern is not supposed to have a suffix");
    return CL_EMEM;
}

static cl_error_t cb_expect_single(void *cbdata, const char *suffix, size_t len, const struct regex_list *regex)
{
    const char *expected = cbdata;

    UNUSEDPARAM(len);
    UNUSEDPARAM(regex);

    cb_called++;
    ck_assert_msg(suffix && strcmp(suffix, expected) == 0,
                  "suffix mismatch, was: %s, expected: %s\n", suffix, expected);
    return CL_SUCCESS;
}

static struct regex_list regex;
START_TEST(empty)
{
    const char pattern[] = "";
    cl_error_t rc;
    regex_t *preg;

    errmsg_expected();
    preg = malloc(sizeof(*regex.preg));
    ck_assert_msg(!!preg, "malloc");
    rc = cli_regex2suffix(pattern, preg, cb_fail, NULL);
    free(preg);
    ck_assert_msg(rc == REG_EMPTY, "empty pattern");
    ck_assert_msg(cb_called == 0, "callback shouldn't be called");
}
END_TEST

START_TEST(one)
{
    char pattern[] = "a";
    cl_error_t rc;
    regex_t *preg;

    preg = malloc(sizeof(*regex.preg));
    ck_assert_msg(!!preg, "malloc");
    rc = cli_regex2suffix(pattern, preg, cb_expect_single, pattern);
    ck_assert_msg(rc == CL_SUCCESS, "single character pattern");
    cli_regfree(preg);
    free(preg);
    ck_assert_msg(cb_called == 1, "callback should be called once");
}
END_TEST

static const char *ex1[] =
    {"com|de", "moc", "ed", NULL};
static const char *ex2[] =
    {"xd|(a|e)bc", "dx", "cba", "cbe", NULL};

static const char **tests[] = {
    ex1,
    ex2};

static cl_error_t cb_expect_multi(void *cbdata, const char *suffix, size_t len, const struct regex_list *r)
{
    const char **exp = cbdata;

    UNUSEDPARAM(r);

    ck_assert_msg(!!exp, "expected data");
    exp++;
    ck_assert_msg(!!*exp, "expected no suffix, got: %s\n", suffix);
    ck_assert_msg(!!exp[cb_called], "expected less suffixes, but already got: %zu\n", cb_called);
    ck_assert_msg(strcmp(exp[cb_called], suffix) == 0,
                  "suffix mismatch, was: %s, expected: %s\n", suffix, exp[cb_called]);
    ck_assert_msg(strlen(suffix) == len, "incorrect suffix len, expected: %zu, got: %zu\n", strlen(suffix), len);
    cb_called++;
    return CL_SUCCESS;
}

START_TEST(test_suffix)
{
    cl_error_t rc;
    regex_t *preg;
    const char *pattern = tests[_i][0];
    size_t n            = 0;
    const char **p      = tests[_i];

    ck_assert_msg(!!pattern, "test pattern");
    preg = malloc(sizeof(*regex.preg));
    ck_assert_msg(!!preg, "malloc");
    rc = cli_regex2suffix(pattern, preg, cb_expect_multi, (void *)tests[_i]);
    ck_assert_msg(rc == CL_SUCCESS, "single character pattern");
    cli_regfree(preg);
    free(preg);
    p++;
    while (*p++) n++;
    ck_assert_msg(cb_called == n,
                  "suffix number mismatch, expected: %zu, was: %zu\n", n, cb_called);
}
END_TEST

static void setup(void)
{
    cb_called = 0;
}

static void teardown(void)
{
}

static struct regex_matcher matcher;

static void rsetup(void)
{
    cl_error_t rc;
#ifdef USE_MPOOL
    matcher.mempool = mpool_create();
#endif
    rc = init_regex_list(&matcher, 1);
    ck_assert_msg(rc == CL_SUCCESS, "init_regex_list");
}

static void rteardown(void)
{
    regex_list_done(&matcher);
#ifdef USE_MPOOL
    mpool_destroy(matcher.mempool);
#endif
}

typedef enum rtest_result {
    RTR_PHISH,
    RTR_ALLOWED,
    RTR_CLEAN,
    RTR_BLOCKED, // if 2nd db is loaded
    RTR_INVALID_REGEX
} rtr_t;

static const struct rtest {
    const char *pattern; /* NULL if not meant for allow list testing */
    const char *realurl;
    const char *displayurl;
    rtr_t result;
} rtests[] = {
    {NULL, "http://fake.example.com", "http://foo@key.com/", RTR_PHISH},
    {NULL, "http://fake.example.com", "foo.example.com@key.com", RTR_PHISH},
    {NULL, "http://fake.example.com", "foo@key.com", RTR_CLEAN},
    {NULL, "http://fake.example.com", "&#61;&#61;&#61;&#61;&#61;key.com", RTR_PHISH},
    {NULL, "http://key.com", "&#61;&#61;&#61;&#61;&#61;key.com", RTR_CLEAN},
    {NULL, " http://key.com", "&#61;&#61;&#61;&#61;&#61;key.com", RTR_CLEAN},
    {NULL, "http://key.com@fake.example.com", "key.com", RTR_PHISH},
    {NULL, " http://key.com@fake.example.com", "key.com", RTR_PHISH},
    {NULL, " http://key.com@fake.example.com ", "key.com", RTR_PHISH},
    /* entry taken from .wdb with a / appended */
    {".+\\.ebayrtm\\.com([/?].*)?:.+\\.ebay\\.(de|com|co\\.uk)([/?].*)?/",
     "http://srx.main.ebayrtm.com",
     "pages.ebay.de",
     RTR_ALLOWED /* should be allowed */},
    {".+\\.ebayrtm\\.com([/?].*)?:.+\\.ebay\\.(de|com|co\\.uk)([/?].*)?/",
     "http://srx.main.ebayrtm.com.evil.example.com",
     "pages.ebay.de",
     RTR_PHISH},
    {".+\\.ebayrtm\\.com([/?].*)?:.+\\.ebay\\.(de|com|co\\.uk)([/?].*)?/",
     "www.www.ebayrtm.com?somecgi",
     "www.ebay.com/something", RTR_ALLOWED},
    {NULL,
     "http://key.com", "go to key.com", RTR_CLEAN},
    {":.+\\.paypal\\.(com|de|fr|it)([/?].*)?:.+\\.ebay\\.(at|be|ca|ch|co\\.uk|de|es|fr|ie|in|it|nl|ph|pl|com(\\.(au|cn|hk|my|sg))?)([/?].*)?/",
     "http://www.paypal.com", "pics.ebay.com", RTR_INVALID_REGEX},
    {NULL, "http://somefakeurl.example.com", "someotherdomain-key.com", RTR_CLEAN},
    {NULL, "http://somefakeurl.example.com", "someotherdomain.key.com", RTR_PHISH},
    {NULL, "http://malware-test.example.com/something", "test", RTR_BLOCKED},
    {NULL, "http://phishing-test.example.com/something", "test", RTR_BLOCKED},
    {NULL, "http://sub.malware-test.example.com/2", "test", RTR_BLOCKED},
    {NULL, "http://sub.phishing-test.example.com/2", "test", RTR_BLOCKED},
    {NULL, "http://user@malware-test.example.com/2", "test", RTR_BLOCKED},
    {NULL, "http://user@phishing-test.example.com/2", "test", RTR_BLOCKED},
    {NULL, "http://user@malware-test.example.com/2/test", "test", RTR_BLOCKED},
    {NULL, "http://user@phishing-test.example.com/2/test", "test", RTR_BLOCKED},
    {NULL, "http://user@malware-test.example.com/", "test", RTR_BLOCKED},
    {NULL, "http://user@phishing-test.example.com/", "test", RTR_BLOCKED},
    {NULL, "http://x.exe", "http:///x.exe", RTR_CLEAN},
    {".+\\.ebayrtm\\.com([/?].*)?:[^.]+\\.ebay\\.(de|com|co\\.uk)/",
     "http://srx.main.ebayrtm.com",
     "pages.ebay.de",
     RTR_ALLOWED /* should be allowed */},
    {".+\\.ebayrtm\\.com([/?].*)?:.+[r-t]\\.ebay\\.(de|com|co\\.uk)/",
     "http://srx.main.ebayrtm.com",
     "pages.ebay.de",
     RTR_ALLOWED /* should be allowed */},
    {".+\\.ebayrtm\\.com([/?].*)?:.+[r-t]\\.ebay\\.(de|com|co\\.uk)/",
     "http://srx.main.ebayrtm.com",
     "pages.ebay.de",
     RTR_ALLOWED /* should be allowed */},
    {"[t-", "", "", RTR_INVALID_REGEX},
    {NULL, "http://co.uk", "http:// co.uk", RTR_CLEAN},
    {NULL, "http://co.uk", "     ", RTR_CLEAN},
    {NULL, "127.0.0.1", "pages.ebay.de", RTR_CLEAN},
    {".+\\.ebayrtm\\.com([/?].*)?:.+\\.ebay\\.(de|com|co\\.uk)([/?].*)?/",
     "http://pages.ebay.de@fake.example.com", "pages.ebay.de", RTR_PHISH},
    {NULL, "http://key.com", "https://key.com", RTR_PHISH},
    {NULL, "http://key.com%00fake.example.com", "https://key.com", RTR_PHISH},
    {NULL, "http://key.com.example.com", "key.com.invalid", RTR_PHISH}};

START_TEST(regex_list_match_test)
{
    const char *info;
    const struct rtest *rtest = &rtests[_i];
    char *pattern, *realurl;
    cl_error_t rc;

    if (!rtest->pattern) {
        ck_assert_msg(rtest->result != RTR_ALLOWED,
                      "Allow list test must have pattern set");
        /* this test entry is not meant for allow_list testing */
        return;
    }

    ck_assert_msg(rtest->result == RTR_PHISH || rtest->result == RTR_ALLOWED || rtest->result == RTR_INVALID_REGEX,
                  "Allow list test result must be either RTR_PHISH or RTR_ALLOWED or RTR_INVALID_REGEX");
    pattern = cli_safer_strdup(rtest->pattern);
    ck_assert_msg(!!pattern, "cli_safer_strdup");

    rc = regex_list_add_pattern(&matcher, pattern);
    if (rtest->result == RTR_INVALID_REGEX) {
        ck_assert_msg(rc, "regex_list_add_pattern should return error");
        free(pattern);
        return;
    } else
        ck_assert_msg(rc == CL_SUCCESS, "regex_list_add_pattern");
    free(pattern);

    matcher.list_loaded = 1;

    rc = cli_build_regex_list(&matcher);
    ck_assert_msg(rc == CL_SUCCESS, "cli_build_regex_list");

    ck_assert_msg(is_regex_ok(&matcher), "is_regex_ok");

    realurl = cli_safer_strdup(rtest->realurl);
    rc      = regex_list_match(&matcher, realurl, rtest->displayurl, NULL, 1, &info, 1);
    ck_assert_msg(rc == rtest->result, "regex_list_match");
    /* regex_list_match is not supposed to modify realurl in this case */
    ck_assert_msg(!strcmp(realurl, rtest->realurl), "realurl altered");
    free(realurl);
}
END_TEST

static struct cl_engine *engine;
static int loaded_2 = 0;

static void psetup_impl(int load2)
{
    FILE *f;
    cl_error_t rc;
    unsigned signo = 0;

    engine = cl_engine_new();
    ck_assert_msg(!!engine, "cl_engine_new");

    phishing_init(engine);
    ck_assert_msg(!!engine->phishcheck, "phishing_init");

    rc = init_domain_list(engine);
    ck_assert_msg(rc == CL_SUCCESS, "init_domain_list");

    f = fdopen(open_testfile("input" PATHSEP "other_sigs" PATHSEP "daily.pdb", O_RDONLY | O_BINARY), "r");
    ck_assert_msg(!!f, "fopen daily.pdb");

    rc = load_regex_matcher(engine, engine->domain_list_matcher, f, &signo, 0, 0, NULL, 1);
    ck_assert_msg(rc == CL_SUCCESS, "load_regex_matcher");
    fclose(f);

    ck_assert_msg(signo == 201, "Incorrect number of signatures: %u, expected %u", signo, 201);

    if (load2) {
        f = fdopen(open_testfile("input" PATHSEP "other_sigs" PATHSEP "daily.gdb", O_RDONLY | O_BINARY), "r");
        ck_assert_msg(!!f, "fopen daily.gdb");

        signo = 0;
        rc    = load_regex_matcher(engine, engine->domain_list_matcher, f, &signo, 0, 0, NULL, 1);
        ck_assert_msg(rc == CL_SUCCESS, "load_regex_matcher");
        fclose(f);

        ck_assert_msg(signo == 4, "Incorrect number of signatures: %u, expected %u", signo, 4);
    }
    loaded_2 = load2;

    rc = init_allow_list(engine);
    ck_assert_msg(rc == CL_SUCCESS, "init_allow_list");

    f     = fdopen(open_testfile("input" PATHSEP "other_sigs" PATHSEP "daily.wdb", O_RDONLY | O_BINARY), "r");
    signo = 0;
    rc    = load_regex_matcher(engine, engine->allow_list_matcher, f, &signo, 0, 1, NULL, 1);
    ck_assert_msg(rc == CL_SUCCESS, "load_regex_matcher");
    fclose(f);

    ck_assert_msg(signo == 31, "Incorrect number of signatures: %u, expected %u", signo, 31);

    rc = cli_build_regex_list(engine->allow_list_matcher);
    ck_assert_msg(rc == CL_SUCCESS, "cli_build_regex_list");

    rc = cli_build_regex_list(engine->domain_list_matcher);
    ck_assert_msg(rc == CL_SUCCESS, "cli_build_regex_list");

    ck_assert_msg(is_regex_ok(engine->allow_list_matcher), "is_regex_ok");
    ck_assert_msg(is_regex_ok(engine->domain_list_matcher), "is_regex_ok");
}

static void psetup(void)
{
    psetup_impl(0);
}

static void psetup2(void)
{
    psetup_impl(1);
}

static void pteardown(void)
{
    if (engine) {
        cl_engine_free(engine);
    }
    engine = NULL;
}

static void do_phishing_test(const struct rtest *rtest)
{
    char *realurl;
    cli_ctx ctx;
    struct cl_scan_options options;
    const char *virname = NULL;
    tag_arguments_t hrefs;
    cl_error_t rc;

    memset(&ctx, 0, sizeof(ctx));
    memset(&options, 0, sizeof(struct cl_scan_options));
    ctx.options = &options;

    realurl = cli_safer_strdup(rtest->realurl);
    ck_assert_msg(!!realurl, "cli_safer_strdup");

    hrefs.count = 1;
    hrefs.value = malloc(sizeof(*hrefs.value));
    ck_assert_msg(!!hrefs.value, "malloc");
    hrefs.value[0] = (unsigned char *)realurl;
    hrefs.contents = malloc(sizeof(*hrefs.contents));
    ck_assert_msg(!!hrefs.contents, "malloc");
    hrefs.tag = malloc(sizeof(*hrefs.tag));
    ck_assert_msg(!!hrefs.tag, "malloc");
    hrefs.tag[0]      = (unsigned char *)cli_safer_strdup("href");
    hrefs.contents[0] = (unsigned char *)cli_safer_strdup(rtest->displayurl);

    ctx.engine = engine;

    ctx.recursion_stack_size = ctx.engine->max_recursion_level;
    ctx.recursion_stack      = calloc(sizeof(cli_scan_layer_t), ctx.recursion_stack_size);
    ck_assert_msg(!!ctx.recursion_stack, "calloc() for recursion_stack failed");

    rc = phishingScan(&ctx, &hrefs);

    html_tag_arg_free(&hrefs);
    ck_assert_msg(rc == CL_CLEAN, "phishingScan");
    switch (rtest->result) {
        case RTR_PHISH:
            ck_assert_msg(evidence_num_indicators_type(ctx.this_layer_evidence, IndicatorType_PotentiallyUnwanted),
                          "this should be phishing, realURL: %s, displayURL: %s",
                          rtest->realurl, rtest->displayurl);
            break;
        case RTR_ALLOWED:
            ck_assert_msg(!evidence_num_indicators_type(ctx.this_layer_evidence, IndicatorType_PotentiallyUnwanted),
                          "this should be allowed, realURL: %s, displayURL: %s",
                          rtest->realurl, rtest->displayurl);
            break;
        case RTR_CLEAN:
            ck_assert_msg(!evidence_num_indicators_type(ctx.this_layer_evidence, IndicatorType_PotentiallyUnwanted),
                          "this should be clean, realURL: %s, displayURL: %s",
                          rtest->realurl, rtest->displayurl);
            break;
        case RTR_BLOCKED:
            if (!loaded_2)
                ck_assert_msg(!evidence_num_indicators_type(ctx.this_layer_evidence, IndicatorType_PotentiallyUnwanted),
                              "this should be clean, realURL: %s, displayURL: %s",
                              rtest->realurl, rtest->displayurl);
            else {
                const char *viruname = NULL;

                ck_assert_msg(evidence_num_indicators_type(ctx.this_layer_evidence, IndicatorType_PotentiallyUnwanted),
                              "this should be blocked, realURL: %s, displayURL: %s",
                              rtest->realurl, rtest->displayurl);

                virname = cli_get_last_virus_str(&ctx);
                if (NULL != virname) {
                    char *phishingFound = NULL;
                    char *detectionName = NULL;
                    if (strstr(rtest->realurl, "malware-test")) {
                        detectionName = "Heuristics.Safebrowsing.Suspected-malware_safebrowsing.clamav.net";

                    } else if (strstr(rtest->realurl, "phishing-test")) {
                        detectionName = "Heuristics.Safebrowsing.Suspected-phishing_safebrowsing.clamav.net";
                    }
                    ck_assert_msg(detectionName != NULL, "\n\t Block list test case error - malware-test or phishing-test not found in: %s\n", rtest->realurl);
                    phishingFound = strstr((const char *)virname, detectionName);
                    ck_assert_msg(phishingFound != NULL, "\n\t should be: %s,\n\t but is:    %s\n", detectionName, virname);
                }
            }
            break;
        case RTR_INVALID_REGEX:
            /* don't worry about it, this was tested in regex_list_match_test() */
            break;
    }

    if (ctx.recursion_stack) {
        if (NULL != ctx.recursion_stack[ctx.recursion_level].evidence) {
            evidence_free(ctx.recursion_stack[ctx.recursion_level].evidence);
        }
        free(ctx.recursion_stack);
    }
}

static void do_phishing_test_allscan(const struct rtest *rtest)
{
    char *realurl;
    cli_ctx ctx;
    const char *virname = NULL;
    tag_arguments_t hrefs;
    cl_error_t rc;
    cl_error_t verdict = CL_CLEAN;
    struct cl_scan_options options;

    memset(&ctx, 0, sizeof(ctx));
    memset(&options, 0, sizeof(struct cl_scan_options));
    ctx.options = &options;

    realurl = cli_safer_strdup(rtest->realurl);
    ck_assert_msg(!!realurl, "cli_safer_strdup");

    hrefs.count = 1;
    hrefs.value = malloc(sizeof(*hrefs.value));
    ck_assert_msg(!!hrefs.value, "malloc");
    hrefs.value[0] = (unsigned char *)realurl;
    hrefs.contents = malloc(sizeof(*hrefs.contents));
    ck_assert_msg(!!hrefs.contents, "malloc");
    hrefs.tag = malloc(sizeof(*hrefs.tag));
    ck_assert_msg(!!hrefs.tag, "malloc");
    hrefs.tag[0]      = (unsigned char *)cli_safer_strdup("href");
    hrefs.contents[0] = (unsigned char *)cli_safer_strdup(rtest->displayurl);

    ctx.engine = engine;

    ctx.recursion_stack_size = ctx.engine->max_recursion_level;
    ctx.recursion_stack      = calloc(sizeof(cli_scan_layer_t), ctx.recursion_stack_size);
    ck_assert_msg(!!ctx.recursion_stack, "calloc() for recursion_stack failed");

    rc = phishingScan(&ctx, &hrefs);
    ck_assert_msg(rc == CL_SUCCESS || rc == CL_VIRUS, "phishingScan failed with error code: %s (%u)",
                  cl_strerror(rc),
                  rc);

    // phishingScan() doesn't check the number of alerts. When using CL_SCAN_GENERAL_ALLMATCHES
    // or if using `CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE` and `cli_append_potentially_unwanted()`
    // we need to count the number of alerts manually to determine the verdict.
    if (0 < evidence_num_alerts(ctx.this_layer_evidence)) {
        verdict = CL_VIRUS;
    }

    if (rtest->result == RTR_PHISH || (loaded_2 != 0 && rtest->result == RTR_BLOCKED)) {
        ck_assert_msg(verdict == CL_VIRUS, "phishingScan returned \"%s\", expected \"%s\". \n\trealURL: %s \n\tdisplayURL: %s",
                      cl_strerror(verdict),
                      cl_strerror(CL_VIRUS),
                      rtest->realurl, rtest->displayurl);
    } else {
        ck_assert_msg(verdict == CL_CLEAN, "phishingScan returned \"%s\", expected \"%s\". \n\trealURL: %s \n\tdisplayURL: %s",
                      cl_strerror(verdict),
                      cl_strerror(CL_CLEAN),
                      rtest->realurl, rtest->displayurl);
    }

    switch (rtest->result) {
        case RTR_PHISH:
            ck_assert_msg(evidence_num_alerts(ctx.this_layer_evidence),
                          "this should be phishing, realURL: %s, displayURL: %s",
                          rtest->realurl, rtest->displayurl);
            break;
        case RTR_ALLOWED:
            ck_assert_msg(!evidence_num_alerts(ctx.this_layer_evidence),
                          "this should be allowed, realURL: %s, displayURL: %s",
                          rtest->realurl, rtest->displayurl);
            break;
        case RTR_CLEAN:
            ck_assert_msg(!evidence_num_alerts(ctx.this_layer_evidence),
                          "this should be clean, realURL: %s, displayURL: %s",
                          rtest->realurl, rtest->displayurl);
            break;
        case RTR_BLOCKED:
            if (!loaded_2) {
                ck_assert_msg(!evidence_num_alerts(ctx.this_layer_evidence),
                              "this should be clean, realURL: %s, displayURL: %s",
                              rtest->realurl, rtest->displayurl);
            } else {
                const char *viruname = NULL;

                ck_assert_msg(evidence_num_alerts(ctx.this_layer_evidence),
                              "this should be blocked, realURL: %s, displayURL: %s",
                              rtest->realurl, rtest->displayurl);

                virname = cli_get_last_virus_str(&ctx);
                if (NULL != virname) {
                    char *phishingFound = NULL;
                    char *detectionName = NULL;
                    if (strstr(rtest->realurl, "malware-test")) {
                        detectionName = "Heuristics.Safebrowsing.Suspected-malware_safebrowsing.clamav.net";

                    } else if (strstr(rtest->realurl, "phishing-test")) {
                        detectionName = "Heuristics.Safebrowsing.Suspected-phishing_safebrowsing.clamav.net";
                    }
                    ck_assert_msg(detectionName != NULL, "\n\t Block list test case error - malware-test or phishing-test not found in: %s\n", rtest->realurl);
                    phishingFound = strstr(virname, detectionName);
                    ck_assert_msg(phishingFound != NULL, "\n\t should be: %s,\n\t but is:    %s\n", detectionName, virname);
                }
            }
            break;
        case RTR_INVALID_REGEX:
            /* don't worry about it, this was tested in regex_list_match_test() */
            break;
    }

    html_tag_arg_free(&hrefs);

    if (ctx.recursion_stack) {
        if (NULL != ctx.recursion_stack[ctx.recursion_level].evidence) {
            evidence_free(ctx.recursion_stack[ctx.recursion_level].evidence);
        }
        free(ctx.recursion_stack);
    }
}

START_TEST(phishingScan_test)
{
    do_phishing_test(&rtests[_i]);
}
END_TEST

START_TEST(phishingScan_test_allscan)
{
    do_phishing_test_allscan(&rtests[_i]);
}
END_TEST

static struct uc {
    const char *in;
    const char *host;
    const char *path;
} uc[] = {
    {":example/%25%32%35", "example/", "%25"},
    {":example/%25%32%35%25%32%35", "example/", "%25%25"},
    {":example/abc%25%32%35asd", "example/", "abc%25asd"},
    {":www.example.com/", "www.example.com/", ""},
    {":%31%32%37%2e%30%2e%30%2e%31/%2E%73%65%63%75%72%65/%77%77%77%2e%65%78%61%6d%70%6c%65%2e%63%6f%6d/",
     "127.0.0.1/", ".secure/www.example.com/"},
    {":127.0.0.1/uploads/%20%20%20%20/.verify/.blah=abcd-ef=gh/",
     "127.0.0.1/", "uploads/%20%20%20%20/.verify/.blah=abcd-ef=gh/"},
    {"http://example%23.com/%61%40%62%252B",
     "example%23.com/", "a@b+"},
    {"http://example.com/blah/..", "example.com/", ""},
    {"http://example.com/blah/../x", "example.com/", "x"},
    {"http://example.com/./a", "example.com/", "a"}};

START_TEST(test_url_canon)
{
    char urlbuff[1024 + 3];
    char *host       = NULL;
    const char *path = NULL;
    size_t host_len, path_len;
    struct uc *u = &uc[_i];

    cli_url_canon(u->in, strlen(u->in), urlbuff, sizeof(urlbuff), &host, &host_len, &path, &path_len);
    ck_assert_msg(!!host && !!path, "null results\n");
    ck_assert_msg(!strcmp(u->host, host), "host incorrect: %s\n", host);
    ck_assert_msg(!strcmp(u->path, path), "path incorrect: %s\n", path);
}
END_TEST

static struct regex_test {
    const char *regex;
    const char *text;
    int match;
} rg[] = {
    {"\\.exe$", "test.exe", 1},
    {"\\.exe$", "test.eXe", 0},
    {"(?i)\\.exe$", "test.exe", 1},
    {"(?i)\\.exe$", "test.eXe", 1}};

START_TEST(test_regexes)
{
    regex_t reg;
    struct regex_test *tst = &rg[_i];
    int match;

    ck_assert_msg(cli_regcomp(&reg, tst->regex, REG_EXTENDED | REG_NOSUB) == 0, "cli_regcomp");
    match = (cli_regexec(&reg, tst->text, 0, NULL, 0) == REG_NOMATCH) ? 0 : 1;
    ck_assert_msg(match == tst->match, "cli_regexec failed for %s and %s\n", tst->regex, tst->text);
    cli_regfree(&reg);
}
END_TEST

START_TEST(phishing_fake_test)
{
    char buf[4096];
    FILE *f = fdopen(open_testfile("input" PATHSEP "other_sigs" PATHSEP "daily.pdb", O_RDONLY | O_BINARY), "r");
    ck_assert_msg(!!f, "fopen daily.pdb");
    while (fgets(buf, sizeof(buf), f)) {
        struct rtest rtest;
        const char *pdb = strchr(buf, ':');
        ck_assert_msg(!!pdb, "missing : in pdb");
        rtest.realurl    = pdb;
        rtest.displayurl = pdb;
        rtest.result     = RTR_CLEAN;
        do_phishing_test(&rtest);
        rtest.realurl = "http://fake.example.com";
        rtest.result  = 0;
        do_phishing_test(&rtest);
    }
    fclose(f);
}
END_TEST

START_TEST(phishing_fake_test_allscan)
{
    char buf[4096];
    FILE *f = fdopen(open_testfile("input" PATHSEP "other_sigs" PATHSEP "daily.pdb", O_RDONLY | O_BINARY), "r");
    ck_assert_msg(!!f, "fopen daily.pdb");
    while (fgets(buf, sizeof(buf), f)) {
        struct rtest rtest;
        const char *pdb = strchr(buf, ':');
        ck_assert_msg(!!pdb, "missing : in pdb");
        rtest.realurl    = pdb;
        rtest.displayurl = pdb;
        rtest.result     = RTR_CLEAN;
        do_phishing_test_allscan(&rtest);
        rtest.realurl = "http://fake.example.com";
        rtest.result  = 0;
        do_phishing_test_allscan(&rtest);
    }
    fclose(f);
}
END_TEST

Suite *test_regex_suite(void)
{
    Suite *s = suite_create("regex");
    TCase *tc_api, *tc_matching, *tc_phish, *tc_phish2, *tc_regex;

    tc_api = tcase_create("cli_regex2suffix");
    suite_add_tcase(s, tc_api);
    tcase_add_checked_fixture(tc_api, setup, teardown);
    tcase_add_test(tc_api, empty);
    tcase_add_test(tc_api, one);

    tcase_add_loop_test(tc_api, test_suffix, 0, sizeof(tests) / sizeof(tests[0]));

    tc_matching = tcase_create("regex_list");
    suite_add_tcase(s, tc_matching);
    tcase_add_checked_fixture(tc_matching, rsetup, rteardown);

    tcase_add_loop_test(tc_matching, regex_list_match_test, 0, sizeof(rtests) / sizeof(rtests[0]));

    tc_phish = tcase_create("phishingScan");
    suite_add_tcase(s, tc_phish);
    tcase_add_unchecked_fixture(tc_phish, psetup, pteardown);

    tcase_add_loop_test(tc_phish, phishingScan_test, 0, sizeof(rtests) / sizeof(rtests[0]));
    tcase_add_loop_test(tc_phish, phishingScan_test_allscan, 0, sizeof(rtests) / sizeof(rtests[0]));

    tcase_add_test(tc_phish, phishing_fake_test);
    tcase_add_test(tc_phish, phishing_fake_test_allscan);

    tc_phish2 = tcase_create("phishingScan with 2 dbs");
    suite_add_tcase(s, tc_phish2);
    tcase_add_unchecked_fixture(tc_phish2, psetup2, pteardown);

    tcase_add_loop_test(tc_phish2, phishingScan_test, 0, sizeof(rtests) / sizeof(rtests[0]));
    tcase_add_loop_test(tc_phish2, phishingScan_test_allscan, 0, sizeof(rtests) / sizeof(rtests[0]));

    tcase_add_test(tc_phish2, phishing_fake_test);
    tcase_add_test(tc_phish2, phishing_fake_test_allscan);

    tcase_add_loop_test(tc_phish, test_url_canon, 0, sizeof(uc) / sizeof(uc[0]));

    tc_regex = tcase_create("cli_regcomp/execute");
    suite_add_tcase(s, tc_regex);

    tcase_add_loop_test(tc_regex, test_regexes, 0, sizeof(rg) / sizeof(rg[0]));

    return s;
}
