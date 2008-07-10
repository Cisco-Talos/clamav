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
#include "../libclamav/str.h"
#include "../libclamav/jsparse/textbuf.h"

START_TEST (test_unescape_simple)
{
	char *str = cli_unescape("");
	fail_unless(str && strlen(str) == 0, "cli_unescape empty string");
	free(str);

	str = cli_unescape("1");
	fail_unless(str && !strcmp(str,"1"), "cli_unescape one char");
	free(str);

	str = cli_unescape("tesT");
	fail_unless(str && !strcmp(str,"tesT"), "cli_unescape simple string");
	free(str);
}
END_TEST

START_TEST (test_unescape_hex)
{
	char *str = cli_unescape("%5a");
	fail_unless(str && !strcmp(str,"\x5a"), "cli_unescape hex");
	free(str);

	str = cli_unescape("%b5%8");
	fail_unless(str && !strcmp(str,"\xb5%8"), "cli_unescape truncated");
	free(str);

	str = cli_unescape("%b5%");
	fail_unless(str && !strcmp(str,"\xb5%"), "cli_unescape truncated/2");
	free(str);

	str = cli_unescape("%00");
	fail_unless(str && !strcmp(str,"\x1"), "cli_unescape %00");
	free(str);
}
END_TEST

START_TEST (test_unescape_unicode)
{
	char *str = cli_unescape("%u05D0");
	/* unicode is converted to utf-8 representation */
	fail_unless(str && !strcmp(str,"\xd7\x90"), "cli_unescape unicode aleph");
	free(str);

	str = cli_unescape("%u00a2%u007f%u0080%u07ff%u0800%ue000");
	fail_unless(str && !strcmp(str,"\xc2\xa2\x7f\xc2\x80\xdf\xbf\xe0\xa0\x80\xee\x80\x80"), 
			"cli_unescape utf-8 test");
	free(str);

	str = cli_unescape("%%u123%u12%u1%u%u1234");
	fail_unless(str && !strcmp(str,"%%u123%u12%u1%u\xe1\x88\xb4"),
			"cli_unescape unicode truncated");

	free(str);
}
END_TEST

static struct text_buffer buf;

static void buf_setup(void)
{
	memset(&buf, 0, sizeof(buf));
}

static void buf_teardown(void)
{
	if(buf.data)
		free(buf.data);
	memset(&buf, 0, sizeof(buf));
}

START_TEST (test_append_len)
{
	fail_unless(textbuffer_append_len(&buf, "test",3) != -1, "tbuf append");
	fail_unless(buf.data && !strncmp(buf.data,"tes",3), "textbuffer_append_len");
}
END_TEST

START_TEST (test_append)
{
	fail_unless(textbuffer_append(&buf, "test") != -1, "tbuf append");
	fail_unless(textbuffer_putc(&buf, '\0') != -1, "tbuf putc");
	fail_unless(buf.data && !strcmp(buf.data,"test"), "textbuffer_append");
}
END_TEST

START_TEST (test_putc)
{
	fail_unless(textbuffer_putc(&buf, '\x5a') != -1, "tbuf putc");
	fail_unless(buf.data && buf.data[0] == '\x5a', "textbuffer_putc");
}
END_TEST

START_TEST (test_normalize)
{
	const char *str = "test\\0\\b\\t\\n\\v\\f\\r\\z\\x2a\\u1234test";
	const char *expected ="test\x1\b\t\n\v\f\rz\x2a\xe1\x88\xb4test";
	int rc;

	rc = cli_textbuffer_append_normalize(&buf, str, strlen(str));
	fail_unless(rc != -1, "normalize");

	fail_unless(textbuffer_putc(&buf, '\0') != -1, "putc \\0");
	fail_unless(buf.data && !strcmp(buf.data, expected), "normalized text");
}
END_TEST

Suite *test_str_suite(void);
Suite *test_str_suite(void)
{
    Suite *s = suite_create("str");
    TCase *tc_cli_unescape, *tc_tbuf;

    tc_cli_unescape = tcase_create("cli_unescape");
    suite_add_tcase (s, tc_cli_unescape);
    tcase_add_test(tc_cli_unescape, test_unescape_simple);
    tcase_add_test(tc_cli_unescape, test_unescape_unicode);
    tcase_add_test(tc_cli_unescape, test_unescape_hex);

    tc_tbuf = tcase_create("jsnorm textbuf functions");
    suite_add_tcase (s, tc_tbuf);
    tcase_add_checked_fixture (tc_tbuf, buf_setup, buf_teardown);
    tcase_add_test(tc_tbuf, test_append_len);
    tcase_add_test(tc_tbuf, test_append);
    tcase_add_test(tc_tbuf, test_putc);
    tcase_add_test(tc_tbuf, test_normalize);

    return s;
}
#endif
