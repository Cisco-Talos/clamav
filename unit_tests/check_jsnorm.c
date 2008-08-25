/*
 *  Unit tests for JS normalizer.
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
#include <fcntl.h>
#include "../libclamav/clamav.h"
#include "../libclamav/others.h"
#include "../libclamav/dconf.h"
#include "../libclamav/htmlnorm.h"
#include "../libclamav/jsparse/js-norm.h"
#include "../libclamav/jsparse/lexglobal.h"
#include "../libclamav/jsparse/textbuf.h"
#include "../libclamav/jsparse/generated/keywords.h"
#include "../libclamav/jsparse/generated/operators.h"
#include "checks.h"

struct test {
	const char *str;
	int is;
};

static struct test kw_test[] = {
	{"new",1},
	{"eval",0},
	{"function",1},
	{"eval1",0},
	{"ne",0}
};

static struct test op_test[] = {
	{"-",1},
	{"---",0}
};

#ifdef CHECK_HAVE_LOOPS
START_TEST (test_keywords)
{
    const struct keyword *kw = in_word_set(kw_test[_i].str, strlen(kw_test[_i].str));
    if(kw_test[_i].is) {
	    fail_unless(kw && !strcmp(kw->name, kw_test[_i].str), "keyword mismatch");
    } else {
	    fail_unless(!kw, "non-keyword detected as keyword");
    }
}
END_TEST

START_TEST (test_operators)
{
    const struct operator *op = in_op_set(op_test[_i].str, strlen(op_test[_i].str));
    if(op_test[_i].is)
	    fail_unless(op && !strcmp(op->name, op_test[_i].str), "operator mismatch");
    else
	    fail_unless(!op, "non-operator detected as operator");
}
END_TEST
#endif /* CHECK_HAVE_LOOPS */

START_TEST (test_token_string)
{
	char str[] = "test";
	yystype tok;
	memset(&tok, 0, sizeof(tok));

	TOKEN_SET(&tok, string, str);
	fail_unless(TOKEN_GET(&tok, string) == str, "token string get/set");
	fail_unless(TOKEN_GET(&tok, cstring) == str, "token string->cstring");
	fail_unless(TOKEN_GET(&tok, scope) == NULL, "token string->scope");
	fail_unless(TOKEN_GET(&tok, ival) == -1, "token string->ival");
}
END_TEST

START_TEST (test_token_cstring)
{
	const char *str = "test";
	yystype tok;
	memset(&tok, 0, sizeof(tok));

	TOKEN_SET(&tok, cstring, str);
	fail_unless(TOKEN_GET(&tok, string) == NULL, "token cstring->string");
	fail_unless(TOKEN_GET(&tok, cstring) == str, "token string->cstring");
	fail_unless(TOKEN_GET(&tok, scope) == NULL, "token string->scope");
	fail_unless(TOKEN_GET(&tok, ival) == -1, "token string->ival");
}
END_TEST

START_TEST (test_token_scope)
{
	struct scope *sc = (struct scope*)0xdeadbeef;
	yystype tok;
	memset(&tok, 0, sizeof(tok));

	TOKEN_SET(&tok, scope, sc);
	fail_unless(TOKEN_GET(&tok, string) == NULL, "token scope->string");
	fail_unless(TOKEN_GET(&tok, cstring) == NULL, "token scope->cstring");
	fail_unless(TOKEN_GET(&tok, scope) == sc, "token scope->scope");
	fail_unless(TOKEN_GET(&tok, ival) == -1, "token scope->ival");
}
END_TEST

START_TEST (test_token_ival)
{
	int val = 0x1234567;
	yystype tok;
	memset(&tok, 0, sizeof(tok));

	TOKEN_SET(&tok, ival, val);
	fail_unless(TOKEN_GET(&tok, string) == NULL, "token ival->string");
	fail_unless(TOKEN_GET(&tok, cstring) == NULL, "token ival->cstring");
	fail_unless(TOKEN_GET(&tok, scope) == NULL, "token ival->scope");
	fail_unless(TOKEN_GET(&tok, dval) - -1 < 1e-9, "token ival->dval");
	fail_unless(TOKEN_GET(&tok, ival) == val, "token ival->ival");
}
END_TEST

START_TEST (test_token_dval)
{
	int val = 0.12345;
	yystype tok;
	memset(&tok, 0, sizeof(tok));

	TOKEN_SET(&tok, dval, val);
	fail_unless(TOKEN_GET(&tok, string) == NULL, "token dval->string");
	fail_unless(TOKEN_GET(&tok, cstring) == NULL, "token dval->cstring");
	fail_unless(TOKEN_GET(&tok, scope) == NULL, "token dval->scope");
	fail_unless(TOKEN_GET(&tok, dval) - val < 1e-9, "token dval->dval");
	fail_unless(TOKEN_GET(&tok, ival) == -1, "token dval->ival");
}
END_TEST

START_TEST (test_init_destroy)
{
	struct parser_state *state = cli_js_init();
	fail_unless(!!state, "cli_js_init()");
	cli_js_destroy(state);
	cli_js_destroy(NULL);
}
END_TEST

START_TEST (test_init_parse_destroy)
{
	const char buf[] = "function (p) { return \"anonymous\";}";
	struct parser_state *state = cli_js_init();
	fail_unless(!!state, "cli_js_init()");
	cli_js_process_buffer(state, buf, strlen(buf));
	cli_js_process_buffer(state, buf, strlen(buf));
	cli_js_parse_done(state);
	cli_js_destroy(state);
}
END_TEST

START_TEST (js_begin_end)
{
	char buf[16384] = "</script>";
	size_t p;
	struct cli_dconf *dconf = cli_dconf_init();

	fail_unless(!!dconf, "failed to init dconf");
	for(p=strlen(buf); p < 8191; p++) {
		buf[p++] = 'a';
		buf[p] = ' ';
	}
	strncpy(buf + 8192, " stuff stuff <script language='javascript'> function () {}", 8192);
	fail_unless(html_normalise_mem((unsigned char*)buf, sizeof(buf), NULL, NULL, dconf) == 1, "normalise");
	free(dconf);
}
END_TEST

START_TEST (multiple_scripts)
{
	char buf[] = "</script> stuff"\
			    "<script language='Javascript'> function foo() {} </script>"\
			    "<script language='Javascript'> function bar() {} </script>";
	struct cli_dconf *dconf = cli_dconf_init();

	fail_unless(!!dconf, "failed to init dconf");
	fail_unless(html_normalise_mem((unsigned char*)buf, sizeof(buf), NULL, NULL, dconf) == 1, "normalise");
	/* TODO: test that both had been normalized */
	free(dconf);
}
END_TEST

static struct parser_state *state;
static char *tmpdir = NULL;

static void jstest_setup(void)
{
	state = cli_js_init();
	fail_unless(!!state, "js init");
	tmpdir = cli_gentemp(NULL);
	fail_unless(!!tmpdir,"js tmp dir");
	fail_unless(mkdir(tmpdir, 0700) == 0, "tempdir mkdir");
}

static void jstest_teardown(void)
{
	if(tmpdir) {
		cli_rmdirs(tmpdir);
		free(tmpdir);
	}
	cli_js_destroy(state);
	state = NULL;
}

static void tokenizer_test(const char *in, const char *expected, int split)
{
	char filename[1024];
	char *buf;
	int fd;
	ssize_t len = strlen(expected);
	size_t inlen = strlen(in);
	ssize_t p, p2;

	if(split) {
		cli_js_process_buffer(state, in, inlen/2);
		cli_js_process_buffer(state, in + inlen/2, inlen - inlen/2);
	} else {
		cli_js_process_buffer(state, in, inlen);
	}

	cli_js_parse_done(state);
	cli_js_output(state, tmpdir);
	snprintf(filename, 1023, "%s/javascript", tmpdir);

	buf = cli_malloc(len + 1);
	if(!buf) {
		jstest_teardown();
		fail("malloc buffer");
	}

	fd = open(filename, O_RDONLY);
	if(fd < 0) {
		jstest_teardown();
		fail("failed to open output file: %s", filename);
	}

	p = read(fd, buf, len);
	if(p != len) {
		close(fd);
		jstest_teardown();
		fail("file is smaller: %lu, expected: %lu", p, len);
	}
	p = lseek(fd, 0, SEEK_CUR);
	fail_unless(p == len, "lseek position incorrect: %ld != %ld", p, len);
	p = 0;
	while(len > 0) {
		char c1 = expected[p];
		char c2 = buf[p];
		if(c1 != c2) {
			close(fd);
			jstest_teardown();
			fail("file contents mismatch at byte: %lu, was: %c, expected: %c", p, c2, c1);
		}
		p++;
		len--;
	}
	free(buf);
	p2 = lseek(fd, 0, SEEK_END);
	if(p != p2) {
		close(fd);
		jstest_teardown();
		fail("trailing garbage, file size: %ld, expected: %ld", p2, p);
	}
	close(fd);
}

static const char jstest_buf0[] =
"function foo(a, b) {\n"\
"var x = 1.9e2*2*a/ 4.;\n"\
"var y = 'test\\'tst';//var foo=5\n"\
"x=b[5],/* multiline\nvar z=6;\nsome*some/other**/"\
"z=x/y;/* multiline oneline */var t=z/a;\n"\
"z=[test;testi];"\
"document.writeln('something');}";

static const char jstest_expected0[] =
"function n000(n001,n002){"\
"var n003=190*2*n001/4;"\
"var n004=\"test\'tst\";"\
"n003=n002[5],"\
"z=n003/n004;var n005=z/n001;"\
"z=[test;testi];"\
"document.writeln(\"something\");}";

static const char jstest_buf1[] =
"function () { var id\\u1234tx;}";

static const char jstest_expected1[] =
"function(){var n000;}";

static const char jstest_buf2[] =
"function () { var tst=\"a\"+'bc'+     'd'; }";

static const char jstest_expected2[] =
"function(){var n000=\"abcd\";}";

static const char jstest_buf3[] =
"dF('bmfsu%2639%2638x11u%2638%263%3A%264C1');";

static const char jstest_expected3[] =
"alert(\"w00t\");";

#define B64 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

/* TODO: document.write should be normalized too */
static const char jstest_buf4[] =
"document.write(unescape('%3C%73%63%72%69%70%74%20%6C%61%6E%67%75%61%67%65%3D%22%6A%61%76%61%73%63%72%69%70%74%22%3E%66%75%6E%63%74%69%6F%6E%20%64%46%28%73%29%7B%76%61%72%20%73%31%3D%75%6E%65%73%63%61%70%65%28%73%2E%73%75%62%73%74%72%28%30%2C%73%2E%6C%65%6E%67%74%68%2D%31%29%29%3B%20%76%61%72%20%74%3D%27%27%3B%66%6F%72%28%69%3D%30%3B%69%3C%73%31%2E%6C%65%6E%67%74%68%3B%69%2B%2B%29%74%2B%3D%53%74%72%69%6E%67%2E%66%72%6F%6D%43%68%61%72%43%6F%64%65%28%73%31%2E%63%68%61%72%43%6F%64%65%41%74%28%69%29%2D%73%2E%73%75%62%73%74%72%28%73%2E%6C%65%6E%67%74%68%2D%31%2C%31%29%29%3B%64%6F%63%75%6D%65%6E%74%2E%77%72%69%74%65%28%75%6E%65%73%63%61%70%65%28%74%29%29%3B%7D%3C%2F%73%63%72%69%70%74%3E'));eval(dF('gI%285%3B%285%3Afqjwy%28585%3A7%28586D%28585%3A7%3C%7C55y%28585%3A7%3C%28585%3A7%28586E%28585%3A8G5%285%3A%285%3C%286E3'));";

static const char jstest_expected4[] =
"document.write(\"<script language=\"javascript\">function df(s){var s1=unescape(s.substr(0,s.length-1)); var t='';for(i=0;i<s1.length;i++)t+=string.fromcharcode(s1.charcodeat(i)-s.substr(s.length-1,1));document.write(unescape(t));}</script>\");eval();alert(\"w00t\");";

static const char jstest_buf5[] =
"function (p,a,c,k,e,r){}('0(\\'1\\');',2,2,'alert|w00t'.split('|'),0,{});";

static const char jstest_expected5[] =
"function(n000,n001,n002,n003,n004,n005){}(alert(\"w00t\"););";

static const char jstest_buf6[] =
"function $(p,a,c,k,e,d){} something(); $('0(\\'1\\');',2,2,'alert|w00t'.split('|'),0,{});";

static const char jstest_expected6[] =
"function n000(n001,n002,n003,n004,n005,n006){}something();$(alert(\"w00t\"););";

static const char jstest_buf7[] =
"var z=\"tst" B64 "tst\";";

static const char jstest_expected7[] =
"var n000=\"tst" B64 "tst\";";

static const char jstest_buf8[] =
"var z=\'tst" B64 "tst\';";

static const char jstest_expected8[] =
"var n000=\"tst" B64 "tst\";";

static const char jstest_buf9[] =
"eval(unescape('%61%6c%65%72%74%28%27%74%65%73%74%27%29%3b'));";

static const char jstest_expected9[] =
"alert(\"test\");";

static const char jstest_buf10[] =
"function $ $() dF(x); function (p,a,c,k,e,r){function $(){}";

static const char jstest_expected10[] =
"function n000 n000()n001(x);function(n002,n003,n004,n005,n006,n007){function n008(){}";

static const char jstest_buf11[] =
"var x=123456789 ;";

static const char jstest_expected11[] =
"var n000=123456789;";

static const char jstest_buf12[] =
"var x='test\\u0000test';";

static const char jstest_expected12[] =
"var n000=\"test\x1test\";";

static const char jstest_buf13[] =
"var x\\s12345";

static const char jstest_expected13[] =
"var n000";


static struct {
	const char *in;
	const char *expected;
} js_tests[] = {
	{jstest_buf0, jstest_expected0},
	{jstest_buf1, jstest_expected1},
	{jstest_buf2, jstest_expected2},
	{jstest_buf3, jstest_expected3},
	{jstest_buf4, jstest_expected4},
	{jstest_buf5, jstest_expected5},
	{jstest_buf6, jstest_expected6},
	{jstest_buf7, jstest_expected7},
	{jstest_buf8, jstest_expected8},
	{jstest_buf9, jstest_expected9},
	{jstest_buf10, jstest_expected10},
	{jstest_buf11, jstest_expected11},
	{jstest_buf12, jstest_expected12},
	{jstest_buf13, jstest_expected13}
};

#ifdef CHECK_HAVE_LOOPS
START_TEST (tokenizer_basic)
{
	tokenizer_test(js_tests[_i].in, js_tests[_i].expected, 0);
}
END_TEST

START_TEST (tokenizer_split)
{
	tokenizer_test(js_tests[_i].in, js_tests[_i].expected, 1);
}
END_TEST
#endif /* CHECK_HAVE_LOOPS */

START_TEST (js_buffer)
{
	const size_t len = 512*1024;
	const char s[] = "x=\"";
	const char e[] = "\"";
	char *tst = malloc(len);

	fail_unless(!!tst, "malloc");

	memset(tst, 'a', len);
	strncpy(tst, s, strlen(s));
	strncpy(tst + len - sizeof(e), e, sizeof(e));

	tokenizer_test(tst,tst,1);
	free(tst);
}
END_TEST

START_TEST (screnc_infloop)
{
	char buf[24700] = "<%@ language='jscript.encode'>";
	struct cli_dconf *dconf = cli_dconf_init();
	size_t p;

	fail_unless(!!dconf, "failed to init dconf");
	for(p = strlen(buf); p < 16384; p++) {
		buf[p] = ' ';
	}
	for(; p < 24625; p++) {
		buf[p] = 'a';
	}
	strncpy(buf+24626,"#@~^ ", 10);
	fail_unless(html_normalise_mem((unsigned char*)buf, sizeof(buf), NULL, NULL, dconf) == 1, "normalise");
	free(dconf);
}
END_TEST

Suite *test_jsnorm_suite(void)
{
    Suite *s = suite_create("jsnorm");
    TCase *tc_jsnorm_gperf, *tc_jsnorm_token, *tc_jsnorm_api,
	  *tc_jsnorm_tokenizer, *tc_jsnorm_bugs, *tc_screnc_infloop;

    tc_jsnorm_gperf = tcase_create("jsnorm gperf");
    suite_add_tcase (s, tc_jsnorm_gperf);
#ifdef CHECK_HAVE_LOOPS
    tcase_add_loop_test(tc_jsnorm_gperf, test_keywords, 0, sizeof(kw_test)/sizeof(kw_test[0]));
    tcase_add_loop_test(tc_jsnorm_gperf, test_operators, 0, sizeof(op_test)/sizeof(op_test[0]));
#endif
    tc_jsnorm_token = tcase_create("jsnorm token functions");
    suite_add_tcase (s, tc_jsnorm_token);
    tcase_add_test(tc_jsnorm_token, test_token_string);
    tcase_add_test(tc_jsnorm_token, test_token_cstring);
    tcase_add_test(tc_jsnorm_token, test_token_scope);
    tcase_add_test(tc_jsnorm_token, test_token_ival);
    tcase_add_test(tc_jsnorm_token, test_token_dval);

    tc_jsnorm_api = tcase_create("jsnorm api functions");
    suite_add_tcase (s, tc_jsnorm_api);
    tcase_add_test(tc_jsnorm_api, test_init_destroy);
    tcase_add_test(tc_jsnorm_api, test_init_parse_destroy);

    tc_jsnorm_tokenizer = tcase_create("jsnorm tokenizer");
    suite_add_tcase (s, tc_jsnorm_tokenizer);
    tcase_add_checked_fixture (tc_jsnorm_tokenizer, jstest_setup, jstest_teardown);
#ifdef CHECK_HAVE_LOOPS
    tcase_add_loop_test(tc_jsnorm_tokenizer, tokenizer_basic, 0, sizeof(js_tests)/sizeof(js_tests[0]));
    tcase_add_loop_test(tc_jsnorm_tokenizer, tokenizer_split, 0, sizeof(js_tests)/sizeof(js_tests[0]));
#endif
    tcase_add_test(tc_jsnorm_tokenizer, js_buffer);

    tc_jsnorm_bugs = tcase_create("jsnorm bugs");
    suite_add_tcase (s, tc_jsnorm_bugs);
    tcase_add_test(tc_jsnorm_bugs, js_begin_end);
    tcase_add_test(tc_jsnorm_bugs, multiple_scripts);

    tc_screnc_infloop = tcase_create("screnc infloop bug");
    suite_add_tcase (s, tc_screnc_infloop);
    tcase_add_test(tc_screnc_infloop, screnc_infloop);

    return s;
}

#endif
