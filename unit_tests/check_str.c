/*
 *  Unit tests for string functions. 
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
#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>

#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <check.h>

#include "../libclamav/clamav.h"
#include "../libclamav/others.h"
#include "../libclamav/str.h"
#include "../libclamav/mbox.h"
#include "../libclamav/message.h"
#include "../libclamav/jsparse/textbuf.h"
#include "checks.h"

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
	errmsg_expected();
	fail_unless(textbuffer_append_len(&buf, "test",CLI_MAX_ALLOCATION) == -1, "tbuf append");
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

START_TEST (hex2str)
{
	char *r;
	const char inp1[] = "a00026";
	const char out1[] = "\xa0\x00\x26";
	const char inp2[] = "ag0026";

	r = cli_hex2str(inp1);
	fail_unless(!!r, "cli_hex2str NULL");
	fail_unless(!memcmp(r, out1, sizeof(out1)-1) ,
			"cli_hex2str invalid output");
	free(r);

	r = cli_hex2str(inp2);
	fail_unless(!r, "cli_hex2str on invalid input");
}
END_TEST

#ifdef CHECK_HAVE_LOOPS
static struct base64lines {
    const char *line;
    const char *decoded;
    unsigned int   len;
} base64tests[] = {
    {"", "", 0},
    {"Zg==", "f", 1},
    {"Zm8=", "fo", 2},
    {"Zm9v", "foo", 3},
    {"Zm9vYg==", "foob", 4},
    {"Zm9vYmFy", "foobar", 6},
    /* with missing padding */
    {"Zg","f", 1},
    {"Zm8", "fo", 2},
    {"Zm9vYg", "foob", 4}
};

START_TEST (test_base64)
{
    unsigned char *ret, *ret2;
    unsigned len;
    unsigned char buf[1024];
    const struct base64lines *test = &base64tests[_i];
    message *m = messageCreate();
    fail_unless(!!m, "Unable to create message");

    ret = decodeLine(m, BASE64, test->line, buf, sizeof(buf));
    fail_unless(!!ret, "unable to decode line");

    ret2 = base64Flush(m, ret);

    if (!ret2)
	ret2 = ret;
    *ret2 = '\0';
    len = ret2 - buf;
    fail_unless_fmt(len == test->len, "invalid base64 decoded length: %u expected %u (%s)\n",
		    len, test->len, buf);
    fail_unless_fmt(!memcmp(buf, test->decoded, test->len),
		    "invalid base64 decoded data: %s, expected:%s\n",
		    buf, test->decoded);
    messageDestroy(m);
}
END_TEST

static struct {
    const char* u16;
    const char* u8;
} u16_tests[] = {
    {"\x74\x00\x65\x00\x73\x00\x74\x00\x00\x00", "test"},
    {"\xff\xfe\x00",""},
    {"\x80\x00\x00","\xc2\x80"},
    {"\xff\x07\x00","\xdf\xbf"},
    {"\x00\x08\x00","\xe0\xa0\x80"},
    {"\xff\x0f\x00","\xe0\xbf\xbf"},
    {"\x00\x10\x00","\xe1\x80\x80"},
    {"\xff\xcf\x00","\xec\xbf\xbf"},
    {"\x00\xd0\x00","\xed\x80\x80"},
    {"\xff\xd7\x00","\xed\x9f\xbf"},
    {"\x00\xe0\x00","\xee\x80\x80"},
    {"\xff\xff\x00","\xef\xbf\xbf"},
    {"\x00\xd8\x00\xdc\x00","\xf0\x90\x80\x80"},
    {"\xbf\xd8\xff\xdf\x00","\xf0\xbf\xbf\xbf"},
    {"\xc0\xd8\x00\xdc\x00","\xf1\x80\x80\x80"},
    {"\xbf\xdb\xff\xdf\x00","\xf3\xbf\xbf\xbf"},
    {"\xc0\xdb\x00\xdc\x00","\xf4\x80\x80\x80"},
    {"\xff\xdb\xff\xdf\x00","\xf4\x8f\xbf\xbf"},
    {"\x00\xdc\x00\xd8\x00","\xef\xbf\xbd\xef\xbf\xbd"}
};

static unsigned u16_len(const char *s)
{
    unsigned i;
    for (i=0;s[i] || s[i+1];i+=2) {}
    return i;
}

START_TEST(test_u16_u8)
{
    char *result = cli_utf16_to_utf8(u16_tests[_i].u16, u16_len(u16_tests[_i].u16), UTF16_LE);
    fail_unless(!!result, "cli_utf16_to_utf8 non-null");
    fail_unless_fmt(!strcmp(result, u16_tests[_i].u8), "utf16_to_8 %d failed, expected: %s, got %s", _i, u16_tests[_i].u8, result);
    free(result);
}
END_TEST

#endif

Suite *test_str_suite(void)
{
    Suite *s = suite_create("str");
    TCase *tc_cli_unescape, *tc_tbuf, *tc_str, *tc_decodeline;

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

    tc_str = tcase_create("str functions");
    suite_add_tcase (s, tc_str);
    tcase_add_test(tc_str, hex2str);
#ifdef CHECK_HAVE_LOOPS
    tcase_add_loop_test(tc_str, test_u16_u8, 0, sizeof(u16_tests)/sizeof(u16_tests[0]));
#endif

    tc_decodeline = tcase_create("decodeline");
    suite_add_tcase (s, tc_decodeline);
#ifdef CHECK_HAVE_LOOPS
    tcase_add_loop_test(tc_decodeline, test_base64, 0, sizeof(base64tests)/sizeof(base64tests[0]));
#endif
    return s;
}

