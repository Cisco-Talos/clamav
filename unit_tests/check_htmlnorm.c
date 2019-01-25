/*
 *  Unit tests for HTML normalizer;
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#include <check.h>
#include <fcntl.h>
#include <string.h>

#include "checks.h"
#include "../libclamav/clamav.h"
#include "../libclamav/fmap.h"
#include "../libclamav/dconf.h"
#include "../libclamav/htmlnorm.h"
#include "../libclamav/others.h"
#include "../libclamav/fmap.h"

static char *dir;

static void htmlnorm_setup(void)
{
        cl_init(CL_INIT_DEFAULT);
	dconf_setup();
	dir = cli_gentemp(NULL);
	fail_unless(!!dir, "cli_gentemp failed");
}

static void htmlnorm_teardown(void)
{
	dconf_teardown();
	/* can't call fail() functions in teardown, it can cause SEGV */
	cli_rmdirs(dir);
	free(dir);
	dir = NULL;
}

static struct test {
	const char *input;
	const char *nocommentref;
	const char *notagsref;
	const char *jsref;
} tests[] = {
	/* NULL means don't test it */
	{"input/htmlnorm_buf.html","buf.nocomment.ref","buf.notags.ref",NULL},
	{"input/htmlnorm_encode.html","encode.nocomment.ref",NULL,"encode.js.ref"},
	{"input/htmlnorm_js_test.html","js.nocomment.ref",NULL,"js.js.ref"},
	{"input/htmlnorm_test.html","test.nocomment.ref","test.notags.ref",NULL},
	{"input/htmlnorm_urls.html","urls.nocomment.ref","urls.notags.ref",NULL}
};

#ifdef CHECK_HAVE_LOOPS

static void check_dir(const char *dire, const struct test *test)
{
	char filename[4096];
	int fd, reffd;

	if (test->nocommentref) {
		snprintf(filename, sizeof(filename), "%s/nocomment.html", dire);
		fd = open(filename, O_RDONLY);
		fail_unless(fd > 0,"unable to open: %s", filename);
		reffd = open_testfile(test->nocommentref);

		diff_files(fd, reffd);

		close(reffd);
		close(fd);
	}
	if (test->notagsref) {
		snprintf(filename, sizeof(filename), "%s/notags.html", dire);
		fd = open(filename, O_RDONLY);
		fail_unless(fd > 0,"unable to open: %s", filename);
		reffd = open_testfile(test->notagsref);

		diff_files(fd, reffd);

		close(reffd);
		close(fd);
	}
	if (test->jsref) {
		snprintf(filename, sizeof(filename), "%s/javascript", dire);
		fd = open(filename, O_RDONLY);
		fail_unless(fd > 0,"unable to open: %s", filename);
		reffd = open_testfile(test->jsref);

		diff_files(fd, reffd);

		close(reffd);
		close(fd);
	}
}

START_TEST (test_htmlnorm_api)
{
	int fd;
	tag_arguments_t hrefs;
	fmap_t *map;

	memset(&hrefs, 0, sizeof(hrefs));

	fd = open_testfile(tests[_i].input);
	fail_unless(fd > 0,"open_testfile failed");

	map = fmap(fd, 0, 0);
	fail_unless(!!map, "fmap failed");

	fail_unless(mkdir(dir, 0700) == 0,"mkdir failed");
	fail_unless(html_normalise_map(map, dir, NULL, dconf) == 1, "html_normalise_map failed");
	check_dir(dir, &tests[_i]);
	fail_unless(cli_rmdirs(dir) == 0, "rmdirs failed");

	fail_unless(mkdir(dir, 0700) == 0,"mkdir failed");
	fail_unless(html_normalise_map(map, dir, NULL, NULL) == 1, "html_normalise_map failed");
	fail_unless(cli_rmdirs(dir) == 0, "rmdirs failed");

	fail_unless(mkdir(dir, 0700) == 0,"mkdir failed");
	fail_unless(html_normalise_map(map, dir, &hrefs, dconf) == 1, "html_normalise_map failed");
	fail_unless(cli_rmdirs(dir) == 0, "rmdirs failed");
	html_tag_arg_free(&hrefs);

	memset(&hrefs, 0, sizeof(hrefs));
	hrefs.scanContents = 1;
	fail_unless(mkdir(dir, 0700) == 0,"mkdir failed");
	fail_unless(html_normalise_map(map, dir, &hrefs, dconf) == 1, "html_normalise_map failed");
	fail_unless(cli_rmdirs(dir) == 0, "rmdirs failed");
	html_tag_arg_free(&hrefs);

	funmap(map);

	close(fd);
}
END_TEST
#endif

START_TEST(test_screnc_nullterminate)
{
	int fd = open_testfile("input/screnc_test");
	fmap_t *map;

	fail_unless(mkdir(dir, 0700) == 0,"mkdir failed");
	map = fmap(fd, 0, 0);
	fail_unless(!!map, "fmap failed");
	fail_unless(html_screnc_decode(map, dir) == 1, "html_screnc_decode failed");
	funmap(map);
	fail_unless(cli_rmdirs(dir) == 0, "rmdirs failed");
	close(fd);
}
END_TEST

Suite *test_htmlnorm_suite(void)
{
	Suite *s = suite_create("htmlnorm");
	TCase *tc_htmlnorm_api;

	tc_htmlnorm_api = tcase_create("htmlnorm api");
	suite_add_tcase (s, tc_htmlnorm_api);
#ifdef CHECK_HAVE_LOOPS	
	tcase_add_loop_test(tc_htmlnorm_api, test_htmlnorm_api, 0, sizeof(tests)/sizeof(tests[0]));
#endif
	tcase_add_unchecked_fixture(tc_htmlnorm_api,
					htmlnorm_setup, htmlnorm_teardown);
	tcase_add_test(tc_htmlnorm_api, test_screnc_nullterminate);

	return s;
}
