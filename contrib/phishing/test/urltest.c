/*
 *  Phishing module test.
 *
 *  Copyright (C) 2006 Török Edvin <edwintorok@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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
 *
 *  $Log $
 */
#include <stdlib.h>
#include <stdio.h>
#include <check.h>
#include "urltest.h"
static struct url_test {
	const char* input;
	int output;
} url_tests[] = {
	{"www.google.com",1},
	{"virus.zip",0}
};
/*static int url_tests_cnt = sizeof(url_tests)/sizeof(url_tests[0]);*/
static int url_tests_i=-1;

struct cl_engine engine;
static void url_tests_setup(void)
{
	phishing_init(&engine);
	url_tests_i=0;
}

static void url_tests_teardown(void)
{
	phishing_done(&engine);
}

static int url_test_function(const char* input)
{
	return isURL(engine.phishcheck,input);
}

START_TEST(url_test_create)
{
	fail_unless( url_test_function("")!=-1,
			"Initialization failed");
}
END_TEST
/* standard cruft */
#define URL_TEST(x) \
START_TEST(url_test_##x)\
{\
	const int url_test_nr = (x);\
	struct url_test test = url_tests[url_test_nr];\
	const int output = url_test_function(test.input);\
	const int expectedoutput = test.output;\
	char failed_msg[512];\
	snprintf(failed_msg,sizeof(failed_msg),"Failed at test:%d",url_test_nr);\
	fail_unless(output==expectedoutput,failed_msg);\
}\
END_TEST


URL_TEST(0)
URL_TEST(1)

#define ADD_URL_TEST(x) 	tcase_add_test(tc_core, url_test_##x)

TCase* create_url_testcase(void)
{
	TCase* tc_core = tcase_create("Core");
	tcase_add_test(tc_core, url_test_create);
	ADD_URL_TEST(0);
	ADD_URL_TEST(1);

	tcase_add_checked_fixture(tc_core, url_tests_setup, url_tests_teardown);
	return tc_core;
}
