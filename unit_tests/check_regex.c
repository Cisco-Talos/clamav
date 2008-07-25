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
	rc = cli_regex2suffix(pattern, &regex, cb_fail, NULL);
	fail_unless(rc == REG_EMPTY, "empty pattern");
	fail_unless(cb_called == 0, "callback shouldn't be called");
}
END_TEST

START_TEST (one)
{
	const char pattern[] = "a";
	int rc;
	rc = cli_regex2suffix(pattern, &regex, cb_expect_single, "a");
	fail_unless(rc == 0, "single character pattern");
	cli_regfree(&regex.preg);
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
	rc = cli_regex2suffix(pattern, &regex, cb_expect_multi, tests[_i]);
	fail_unless(rc == 0, "single character pattern");
	cli_regfree(&regex.preg);
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
	free(regex.pattern);
}

Suite *test_regex_suite(void)
{
	Suite *s = suite_create("regex");
	TCase *tc_static, *tc_simple, *tc_api;

	tc_api = tcase_create("cli_regex2suffix");
	tcase_add_checked_fixture (tc_api, setup, teardown);
	suite_add_tcase(s, tc_api);
	tcase_add_test(tc_api, empty);
	tcase_add_test(tc_api, one);
	tcase_add_loop_test(tc_api, test_suffix, 0, sizeof(tests)/sizeof(tests[0]));
	return s;
}

#endif
