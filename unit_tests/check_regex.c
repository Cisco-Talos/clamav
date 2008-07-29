/*
 *  Unit tests for regular expression processing.
 *
 *  Copyright (C) 2008 Sourcefire, Inc.
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
#ifdef HAVE_CHECK
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <check.h>
#include "../libclamav/clamav.h"
#include "../libclamav/others.h"
#include "../libclamav/regex_suffix.h"
#include "../libclamav/regex_list.h"
#include "../libclamav/htmlnorm.h"
#include "../libclamav/mbox.h"
#include "../libclamav/message.h"
#include "../libclamav/phishcheck.h"
#include "checks.h"

static int cb_called = 0;

static int cb_fail(void *cbdata, const char *suffix, size_t len, struct regex_list *regex)
{
	fail("this pattern is not supposed to have a suffix");
	return -1;
}

static int cb_expect_single(void *cbdata, const char *suffix, size_t len, struct regex_list *regex)
{
	const char *expected = cbdata;
	cb_called++;
	fail_unless(suffix && strcmp(suffix, expected) == 0,
			"suffix mismatch, was: %s, expected: %s\n", suffix, expected);
}

static struct regex_list regex;
START_TEST (empty)
{
	const char pattern[] = "";
	int rc;
	errmsg_expected();
	regex.preg = malloc(sizeof(*regex.preg));
	fail_unless(!!regex.preg, "malloc");
	rc = cli_regex2suffix(pattern, &regex, cb_fail, NULL);
	free(regex.preg);
	fail_unless(rc == REG_EMPTY, "empty pattern");
	fail_unless(cb_called == 0, "callback shouldn't be called");
}
END_TEST

START_TEST (one)
{
	const char pattern[] = "a";
	int rc;
	regex.preg = malloc(sizeof(*regex.preg));
	fail_unless(!!regex.preg, "malloc");
	rc = cli_regex2suffix(pattern, &regex, cb_expect_single, "a");
	fail_unless(rc == 0, "single character pattern");
	cli_regfree(regex.preg);
	free(regex.preg);
	fail_unless(cb_called == 1, "callback should be called once");
}
END_TEST


static const char *exp1[] =
 {"com|de","moc","ed",NULL};
static const char *exp2[] =
 {"xd|(a|e)bc","dx","cba","cbe",NULL};

static const char **tests[] = {
	exp1,
	exp2
};


static int cb_expect_multi(void *cbdata, const char *suffix, size_t len, struct regex_list *regex)
{
	const char **exp = cbdata;
	fail_unless(!!exp, "expected data");
	exp++;
	fail_unless(!!*exp, "expected no suffix, got: %s\n",suffix);
	fail_unless(!!exp[cb_called], "expected less suffixes, but already got: %d\n", cb_called);
	fail_unless(strcmp(exp[cb_called], suffix) == 0,
			"suffix mismatch, was: %s, expected: %s\n",suffix, exp[cb_called]);
	fail_unless(strlen(suffix) == len, "incorrect suffix len, expected: %d, got: %d\n", strlen(suffix), len);
	cb_called++;
}

START_TEST (test_suffix)
{
	int rc;
	const char *pattern = tests[_i][0];
	size_t n=0;
	const char **p=tests[_i];

	fail_unless(!!pattern, "test pattern");
	regex.preg = malloc(sizeof(*regex.preg));
	fail_unless(!!regex.preg, "malloc");
	rc = cli_regex2suffix(pattern, &regex, cb_expect_multi, tests[_i]);
	fail_unless(rc == 0, "single character pattern");
	cli_regfree(regex.preg);
	free(regex.preg);
	p++;
	while(*p++) n++;
	fail_unless(cb_called == n,
			"suffix number mismatch, expected: %d, was: %d\n", n, cb_called);
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
	int rc = init_regex_list(&matcher);
	fail_unless(rc == 0, "init_regex_list");
}

static void rteardown(void)
{
	regex_list_done(&matcher);
}

static const struct rtest {
	const char *pattern;/* NULL if not meant for whitelist testing */
	const char *realurl;
	const char *displayurl;
	int result;/* 0 - phish, 1 - whitelisted, 2 - clean */
} rtests[] = {
	/* entry taken from .wdb with a / appended */
	{".+\\.ebayrtm\\.com([/?].*)?:.+\\.ebay\\.(de|com|co\\.uk)([/?].*)?/",
		"http://srx.main.ebayrtm.com",
		"pages.ebay.de",
		1 /* should be whitelisted */},
	{".+\\.ebayrtm\\.com([/?].*)?:.+\\.ebay\\.(de|com|co\\.uk)([/?].*)?/",
		"http://srx.main.ebayrtm.com.evil.example.com",
		"pages.ebay.de",
		0}
};

START_TEST (regex_list_match_test)
{
	const char *info;
	const struct rtest *rtest = &rtests[_i];
	char *pattern;

	if(!rtest->pattern) {
		fail_unless(rtest->result != 1,
				"whitelist test must have pattern set");
		/* this test entry is not meant for whitelist testing */
		return;
	}

	fail_unless(rtest->result == 0 || rtest->result == 1,
			"whitelist test result must be either 0 or 1");
	pattern = cli_strdup(rtest->pattern);
	fail_unless(!!pattern, "cli_strdup");

	int rc = regex_list_add_pattern(&matcher, pattern);
	fail_unless(rc == 0,"regex_list_add_pattern");
	free(pattern);

	matcher.list_loaded = 1;

	rc = cli_build_regex_list(&matcher);
	fail_unless(rc == 0,"cli_build_regex_list");

	fail_unless(is_regex_ok(&matcher),"is_regex_ok");

	/* regex_list_match is not supposed to modify realurl in this case */
	rc = regex_list_match(&matcher, (char*)rtest->realurl, rtest->displayurl, NULL, 1, &info, 1);
	fail_unless(rc == rtest->result,"regex_list_match");
}
END_TEST

static struct cl_engine *engine;
static void psetup(void)
{
	FILE *f;
	struct phishcheck *pchk;
	int rc;
	rc = cli_initengine(&engine, 0);
	fail_unless(rc == 0, "cl_initengine");

	rc = phishing_init(engine);
	fail_unless(rc == 0,"phishing_init");
	pchk = engine->phishcheck;
	fail_unless(!!pchk, "engine->phishcheck");

	rc = init_domainlist(engine);
	fail_unless(rc == 0,"init_domainlist");

	f = fdopen(open_testfile("input/daily.pdb"),"r");
	fail_unless(!!f, "fopen daily.pdb");

	rc = load_regex_matcher(engine->domainlist_matcher,  f, 0, 0, NULL);
	fail_unless(rc == 0, "load_regex_matcher");
	fclose(f);

	rc = init_whitelist(engine);
	fail_unless(rc == 0,"init_whitelist");

	f = fdopen(open_testfile("input/daily.wdb"),"r");
	rc = load_regex_matcher(engine->whitelist_matcher, f, 0, 1, NULL);
	fail_unless(rc == 0,"load_regex_matcher");
	fclose(f);

	rc = cli_build_regex_list(engine->whitelist_matcher);
	fail_unless(rc == 0,"cli_build_regex_list");

	rc = cli_build_regex_list(engine->domainlist_matcher);
	fail_unless(rc == 0,"cli_build_regex_list");

	fail_unless(is_regex_ok(engine->whitelist_matcher),"is_regex_ok");
	fail_unless(is_regex_ok(engine->domainlist_matcher),"is_regex_ok");
}

static void pteardown(void)
{
	phishing_done(engine);
	cl_free(engine);
	engine = NULL;
}

START_TEST (phishingScan_test)
{
	const char *info;
	const struct rtest *rtest = &rtests[_i];
	char *realurl;
	cli_ctx ctx;
	const char *virname;
	tag_arguments_t hrefs;
	int rc;

	memset(&ctx, 0, sizeof(ctx));

	realurl = cli_strdup(rtest->realurl);
	fail_unless(!!realurl, "cli_strdup");

	hrefs.count = 1;
	hrefs.value = cli_malloc(sizeof(*hrefs.value));
	fail_unless(!!hrefs.value, "cli_malloc");
	hrefs.value[0] = realurl;
	hrefs.contents = cli_malloc(sizeof(*hrefs.contents));
	fail_unless(!!hrefs.contents, "cli_malloc");
	hrefs.contents[0] = blobCreate();
	hrefs.tag = cli_malloc(sizeof(*hrefs.tag));
	fail_unless(!!hrefs.tag, "cli_malloc");
	hrefs.tag[0] = cli_strdup("href");
	blobAddData(hrefs.contents[0], rtest->displayurl, strlen(rtest->displayurl)+1);

	ctx.engine = engine;
	ctx.virname = &virname;
	rc = phishingScan(NULL, NULL, &ctx, &hrefs);
	fail_unless(rc == CL_CLEAN,"phishingScan");
	fail_unless(!!ctx.found_possibly_unwanted == !rtest->result ,
			"found unwanted: %d, expected: %d\n", ctx.found_possibly_unwanted, !rtest->result);
	html_tag_arg_free(&hrefs);
}
END_TEST


Suite *test_regex_suite(void)
{
	cl_debug();
	Suite *s = suite_create("regex");
	TCase *tc_static, *tc_simple, *tc_api, *tc_matching, *tc_phish;

	tc_api = tcase_create("cli_regex2suffix");
	suite_add_tcase(s, tc_api);
	tcase_add_checked_fixture (tc_api, setup, teardown);
	tcase_add_test(tc_api, empty);
	tcase_add_test(tc_api, one);
	tcase_add_loop_test(tc_api, test_suffix, 0, sizeof(tests)/sizeof(tests[0]));

	tc_matching = tcase_create("regex_list");
	suite_add_tcase(s, tc_matching);
	tcase_add_checked_fixture (tc_matching, rsetup, rteardown);
	tcase_add_loop_test(tc_matching, regex_list_match_test, 0, sizeof(rtests)/sizeof(rtests[0]));

	tc_phish = tcase_create("phishingScan");
	suite_add_tcase(s, tc_phish);
	tcase_add_checked_fixture(tc_phish, psetup, pteardown);
	tcase_add_loop_test(tc_phish, phishingScan_test, 0, sizeof(rtests)/sizeof(rtests[0]));

	return s;
}

#endif
