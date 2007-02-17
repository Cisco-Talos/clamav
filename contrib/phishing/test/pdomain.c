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
#include <clamav.h>
#include <clamav-config.h>
#include "pdomain.h"
#include <phish_domaincheck_db.h>
#define FULLFLAG 0xFFFF
static struct regex_list_test {
	const char* inputReal;
	const char* inputDisp;
	int output;
	unsigned short flags;
} regex_list_tests[] = {
	{"www.google.com","www.google.com",0,FULLFLAG},
	{"http://abcdef","jj",0,FULLFLAG},
	{"http://abcdefj","jj",1,FULLFLAG},
	{"http://ab.f.com","jj",0,FULLFLAG},
	{"http://a.f.com","jj",1,FULLFLAG},
	{"http://b.f.com","jj",1,FULLFLAG},
	{"http://c.f.com","jj",1,FULLFLAG},
	{"http://d.f.com","jj",1,FULLFLAG},
	{"http://f.f.com","jj",0,FULLFLAG},
	{"http://e.f.com","jj",1,FULLFLAG},
	{"http://ae.f.net","jj",1,FULLFLAG},
	{"http://cb.f.com","jj",0,FULLFLAG},
	{"http://abcf","jj",0,FULLFLAG},
	{"virus.zip","viiirii.zip",0,FULLFLAG},
	{"http://zztest.com","jj",1,0xFEF7}
};
/*static int regex_list_tests_cnt = sizeof(regex_list_tests)/sizeof(regex_list_tests[0]);*/
static int regex_list_tests_i=-1;
static struct cl_engine* engine;

static void regex_list_tests_setup(void)
{
	int rc;
	unsigned int signo;
	engine=NULL;
	rc = cl_loaddb(REGEXTEST_FILE,&engine,&signo);
	fail_unless(rc==0,cl_strerror(rc));
	fail_unless(is_domainlist_ok(engine));
	regex_list_tests_i=0;
}

static void regex_list_tests_teardown(void)
{
	cl_free(engine);
	engine=NULL;
}


static int regex_list_test_function(const char* input1,const char* input2,const unsigned short flag_expected)
{
	unsigned short flags=FULLFLAG;
	int rc;
	fail_unless(is_domainlist_ok(engine));
	rc = domainlist_match(engine,input1,input2,0,&flags);
	fail_unless(flags == flag_expected);
	return rc;
}

START_TEST(regex_list_test_create)
{
	fail_unless( regex_list_test_function("","",FULLFLAG)!=-1,
			"Initialization failed");
}
END_TEST
/* standard cruft */
#define REGEX_LIST_TEST(x) \
START_TEST(regex_list_test_##x)\
{\
	const int regex_list_test_nr = (x);\
	struct regex_list_test test = regex_list_tests[regex_list_test_nr];\
	const int output = regex_list_test_function(test.inputReal,test.inputDisp,test.flags);\
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
REGEX_LIST_TEST(14)
#define ADD_REGEX_LIST_TEST(x) 	tcase_add_test(tc_core, regex_list_test_##x)


TCase* create_pdomain_testcase(void)
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
	ADD_REGEX_LIST_TEST(14);
	tcase_add_checked_fixture(tc_core, regex_list_tests_setup, regex_list_tests_teardown);
	return tc_core;
}





