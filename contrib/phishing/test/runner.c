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
#include <check.h>
#include "urltest.h"
#include "regex_list_test.h"

static Suite* create_suite(void)
{
	Suite* s = suite_create("Phishing module");
	suite_add_tcase (s, create_regex_testcase());
	suite_add_tcase (s, create_url_testcase());
	suite_add_tcase (s, create_pdomain_testcase());
	return s;
}


int main (int argc,char* argv[])
{
	int nf;
	Suite* s = create_suite();
	SRunner *sr = srunner_create(s);
/*enable this if you want to put breakpoints:
srunner_set_fork_status(sr, CK_NOFORK);*/
/*	srunner_set_xml(sr,"phishtest_output.xml");*/
	srunner_run_all (sr, CK_VERBOSE);
	nf = srunner_ntests_failed(sr);
srunner_free(sr);
	return (nf == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
