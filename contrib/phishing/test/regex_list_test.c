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
#include <test-config.h>
#include "regex_list_test.h"
#include <regex_list.h>
static struct regex_list_test {
	const char* inputReal;
	const char* inputDisp;
	int output;
} regex_list_tests[] = {
	{"www.google.com","www.google.com",0},
	{"http://abcdef","jj",0},
	{"http://abcdefj","jj",1},
	{"http://ab.f.com","jj",0},
	{"http://a.f.com","jj",1},
	{"http://b.f.com","jj",1},
	{"http://c.f.com","jj",1},
	{"http://d.f.com","jj",1},
	{"http://f.f.com","jj",0},
	{"http://e.f.com","jj",1},
	{"http://ae.f.net","jj",1},
	{"http://cb.f.com","jj",0},
	{"http://abcf","jj",0},
	{"virus.zip","viiirii.zip",0}
};
/*static int regex_list_tests_cnt = sizeof(regex_list_tests)/sizeof(regex_list_tests[0]);*/
static int regex_list_tests_i=-1;
static struct regex_matcher matcher;

static void regex_list_tests_setup(void)
{
	FILE* f = fopen(REGEXTEST_FILE,"r");
	int rc;
	fail_unless(f!=NULL);
	init_regex_list(&matcher);
	load_regex_matcher(&matcher,f,0);
	fclose(f);
	regex_list_cleanup(&matcher);
	rc=is_regex_ok(&matcher);
	fail_unless(rc);
	regex_list_tests_i=0;
}

static void regex_list_tests_teardown(void)
{
	regex_list_done(&matcher);
}


static int regex_list_test_function(const char* input1,const char* input2)
{
	const char* info;
	fail_unless(is_regex_ok(&matcher));
	return regex_list_match(&matcher,input1,input2,0,&info);
}

START_TEST(regex_list_test_create)
{
	fail_unless( regex_list_test_function("","")!=-1,
			"Initialization failed");
}
END_TEST
/* standard cruft */
#define REGEX_LIST_TEST(x) \
START_TEST(regex_list_test_##x)\
{\
	const int regex_list_test_nr = (x);\
	struct regex_list_test test = regex_list_tests[regex_list_test_nr];\
	const int output = regex_list_test_function(test.inputReal,test.inputDisp);\
	const int expectedoutput = test.output;\
	char failed_msg[512];\
	snprintf(failed_msg,sizeof(failed_msg),"Failed at test:%d (input: %s %s;expected:%d, got:%d)",\
			regex_list_test_nr,test.inputReal,test.inputDisp,expectedoutput,output);\
	fail_unless(output==expectedoutput,failed_msg);\
}\
END_TEST


REGEX_LIST_TEST(0)
REGEX_LIST_TEST(1)
REGEX_LIST_TEST(2)
REGEX_LIST_TEST(3)
REGEX_LIST_TEST(4)
REGEX_LIST_TEST(5)
REGEX_LIST_TEST(6)
REGEX_LIST_TEST(7)
REGEX_LIST_TEST(8)
REGEX_LIST_TEST(9)
REGEX_LIST_TEST(10)
REGEX_LIST_TEST(11)
REGEX_LIST_TEST(12)
REGEX_LIST_TEST(13)
#define ADD_REGEX_LIST_TEST(x) 	tcase_add_test(tc_core, regex_list_test_##x)


TCase* create_regex_testcase(void)
{
	TCase* tc_core = tcase_create("Regex List");
	tcase_add_test(tc_core, regex_list_test_create);
	ADD_REGEX_LIST_TEST(0);
	ADD_REGEX_LIST_TEST(1);
	ADD_REGEX_LIST_TEST(2);
	ADD_REGEX_LIST_TEST(3);
	ADD_REGEX_LIST_TEST(4);
	ADD_REGEX_LIST_TEST(5);
	ADD_REGEX_LIST_TEST(6);
	ADD_REGEX_LIST_TEST(7);
	ADD_REGEX_LIST_TEST(8);
	ADD_REGEX_LIST_TEST(9);
	ADD_REGEX_LIST_TEST(10);
	ADD_REGEX_LIST_TEST(11);
	ADD_REGEX_LIST_TEST(12);
	ADD_REGEX_LIST_TEST(13);
	tcase_add_checked_fixture(tc_core, regex_list_tests_setup, regex_list_tests_teardown);
	return tc_core;
}





