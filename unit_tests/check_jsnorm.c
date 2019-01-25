/*
 *  Unit tests for JS normalizer.
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
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>

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
	double val = 0.12345;
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

	for(p=strlen(buf); p < 8191; p++) {
		buf[p++] = 'a';
		buf[p] = ' ';
	}
	strncpy(buf + 8192, " stuff stuff <script language='javascript'> function () {}", 8192);
	fail_unless(html_normalise_mem((unsigned char*)buf, sizeof(buf), NULL, NULL, dconf) == 1, "normalise");
}
END_TEST

START_TEST (multiple_scripts)
{
	char buf[] = "</script> stuff"\
			    "<script language='Javascript'> function foo() {} </script>"\
			    "<script language='Javascript'> function bar() {} </script>";

	fail_unless(!!dconf, "failed to init dconf");
	fail_unless(html_normalise_mem((unsigned char*)buf, sizeof(buf), NULL, NULL, dconf) == 1, "normalise");
	/* TODO: test that both had been normalized */
}
END_TEST

static struct parser_state *state;
static char *tmpdir = NULL;

static void jstest_setup(void)
{
        cl_init(CL_INIT_DEFAULT);
	state = cli_js_init();
	fail_unless(!!state, "js init");
	tmpdir = cli_gentemp(NULL);
	fail_unless(!!tmpdir,"js tmp dir");
	fail_unless_fmt(mkdir(tmpdir, 0700) == 0, "tempdir mkdir of %s failed: %s", tmpdir, strerror(errno));
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
	int fd;
	ssize_t len = strlen(expected);
	size_t inlen = strlen(in);

	if(split) {
		cli_js_process_buffer(state, in, inlen/2);
		cli_js_process_buffer(state, in + inlen/2, inlen - inlen/2);
	} else {
		cli_js_process_buffer(state, in, inlen);
	}

	cli_js_parse_done(state);
	cli_js_output(state, tmpdir);
	snprintf(filename, 1023, "%s/javascript", tmpdir);

	fd = open(filename, O_RDONLY);
	if(fd < 0) {
		jstest_teardown();
		fail_fmt("failed to open output file: %s", filename);
	}

	diff_file_mem(fd, expected, len);
}

static const char jstest_buf0[] =
"function foo(a, b) {\n"\
"var x = 1.9e2*2*a/ 4.;\n"\
"var y = 'test\\'tst';//var\n"\
"x=b[5],/* multiline\nvar z=6;\nsome*some/other**/"\
"z=x/y;/* multiline oneline */var t=z/a;\n"\
"z=[test;testi];"\
"document.writeln('something\n');}";

static const char jstest_expected0[] =
"<script>function n000(n001,n002){"\
"var n003=190*2*n001/4;"\
"var n004=\"test\'tst\";"\
"n003=n002[5],"\
"z=n003/n004;var n005=z/n001;"\
"z=[test;testi];"\
"document.writeln(\"something \");}</script>";

static const char jstest_buf1[] =
"function () { var id\\u1234tx;}";

static const char jstest_expected1[] =
"<script>function(){var n000;}</script>";

static const char jstest_buf2[] =
"function () { var tst=\"a\"+'bc'+     'd'; }";

static const char jstest_expected2[] =
"<script>function(){var n000=\"abcd\";}</script>";

static const char jstest_buf3[] =
"dF('bmfsu%2639%2638x11u%2638%263%3A%264C1');";

static const char jstest_expected3[] =
"<script>alert(\"w00t\");</script>";

#define B64 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

/* TODO: document.write should be normalized too */
static char jstest_buf4[] =
"qbphzrag.jevgr(harfpncr('%3P%73%63%72%69%70%74%20%6P%61%6R%67%75%61%67%65%3Q%22%6N%61%76%61%73%63%72%69%70%74%22%3R%66%75%6R%63%74%69%6S%6R%20%64%46%28%73%29%7O%76%61%72%20%73%31%3Q%75%6R%65%73%63%61%70%65%28%73%2R%73%75%62%73%74%72%28%30%2P%73%2R%6P%65%6R%67%74%68%2Q%31%29%29%3O%20%76%61%72%20%74%3Q%27%27%3O%66%6S%72%28%69%3Q%30%3O%69%3P%73%31%2R%6P%65%6R%67%74%68%3O%69%2O%2O%29%74%2O%3Q%53%74%72%69%6R%67%2R%66%72%6S%6Q%43%68%61%72%43%6S%64%65%28%73%31%2R%63%68%61%72%43%6S%64%65%41%74%28%69%29%2Q%73%2R%73%75%62%73%74%72%28%73%2R%6P%65%6R%67%74%68%2Q%31%2P%31%29%29%3O%64%6S%63%75%6Q%65%6R%74%2R%77%72%69%74%65%28%75%6R%65%73%63%61%70%65%28%74%29%29%3O%7Q%3P%2S%73%63%72%69%70%74%3R'));riny(qS('tV%285%3O%285%3Nsdwjl%28585%3N7%28586Q%28585%3N7%3P%7P55l%28585%3N7%3P%28585%3N7%28586R%28585%3N8T5%285%3N%285%3P%286R3'));";

static char jstest_expected4[] =
"<fpevcg>qbphzrag.jevgr(\"<fpevcg ynathntr=\"wninfpevcg\">shapgvba qs(f){ine f1=harfpncr(f.fhofge(0,f.yratgu-1)); ine g='';sbe(v=0;v<f1.yratgu;v++)g+=fgevat.sebzpunepbqr(f1.punepbqrng(v)-f.fhofge(f.yratgu-1,1));qbphzrag.jevgr(harfpncr(g));}</fpevcg>\");riny();nyreg(\"j00g\");</fpevcg>";

static char jstest_buf5[] =
"shapgvba (c,n,p,x,r,e){}('0(\\'1\\');',2,2,'nyreg|j00g'.fcyvg('|'),0,{});";

static const char jstest_expected5[] =
"<script>function(n000,n001,n002,n003,n004,n005){}(alert(\"w00t\"););</script>";

static const char jstest_buf6[] =
"function $(p,a,c,k,e,d){} something(); $('0(\\'1\\');',2,2,'alert|w00t'.split('|'),0,{});";

static const char jstest_expected6[] =
"<script>function n000(n001,n002,n003,n004,n005,n006){}something();$(alert(\"w00t\"););</script>";

static const char jstest_buf7[] =
"var z=\"tst" B64 "tst\";";

static const char jstest_expected7[] =
"<script>var n000=\"tst" B64 "tst\";</script>";

static const char jstest_buf8[] =
"var z=\'tst" B64 "tst\';";

static const char jstest_expected8[] =
"<script>var n000=\"tst" B64 "tst\";</script>";

static char jstest_buf9[] =
"riny(harfpncr('%61%6p%65%72%74%28%27%74%65%73%74%27%29%3o'));";

static const char jstest_expected9[] =
"<script>alert(\"test\");</script>";

static const char jstest_buf10[] =
"function $ $() dF(x); function (p,a,c,k,e,r){function $(){}";

static const char jstest_expected10[] =
"<script>function n000 n000()n001(x);function(n002,n003,n004,n005,n006,n007){function n008(){}</script>";

static const char jstest_buf11[] =
"var x=123456789 ;";

static const char jstest_expected11[] =
"<script>var n000=123456789;</script>";

static const char jstest_buf12[] =
"var x='test\\u0000test';";

static const char jstest_expected12[] =
"<script>var n000=\"test\x1test\";</script>";

static const char jstest_buf13[] =
"var x\\s12345";

static const char jstest_expected13[] =
"<script>var n000</script>";

static const char jstest_buf14[] =
"document.write(unescape('test%20test";

static const char jstest_expected14[] =
"<script>document.write(\"test test\")</script>";

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
	{jstest_buf13, jstest_expected13},
	{jstest_buf14, jstest_expected14}
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
	const char s_exp[] = "<script>";
	const char e_exp[] = "</script>";
	char *tst = malloc(len);
	char *exp = malloc(len + sizeof(s_exp) + sizeof(e_exp) - 2);

	fail_unless(!!tst, "malloc");
	fail_unless(!!exp, "malloc");

	memset(tst, 'a', len);
	strncpy(tst, s, strlen(s));
	strncpy(tst + len - sizeof(e), e, sizeof(e));

	strncpy(exp, s_exp, len);
	strncpy(exp + sizeof(s_exp) - 1, tst, len-1);
	strncpy(exp + sizeof(s_exp) + len - 2, e_exp, sizeof(e_exp));

	tokenizer_test(tst,exp,1);
	free(exp);
	free(tst);
}
END_TEST

START_TEST (screnc_infloop)
{
	char buf[24700] = "<%@ language='jscript.encode'>";
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
}
END_TEST

static void prepare_s(char *s)
{
	char xlat[] = "NOPQRSTUVWXYZABCDEFGHIJKLM[\\]^_`nopqrstuvwxyzabcdefghijklm";
	while(*s) {
		if(isalpha(*s)) {
			*s = xlat[*s - 'A'];
		}
		s++;
	}
}

static void prepare(void)
{
	prepare_s(jstest_buf4);
	prepare_s(jstest_expected4);
	prepare_s(jstest_buf5);
	prepare_s(jstest_buf9);
}

Suite *test_jsnorm_suite(void)
{
    Suite *s = suite_create("jsnorm");
    TCase *tc_jsnorm_gperf, *tc_jsnorm_token, *tc_jsnorm_api,
	  *tc_jsnorm_tokenizer, *tc_jsnorm_bugs;

    prepare();
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

    tc_jsnorm_bugs = tcase_create("bugs");
    suite_add_tcase (s, tc_jsnorm_bugs);
    tcase_add_checked_fixture(tc_jsnorm_bugs, dconf_setup, dconf_teardown);
    tcase_add_test(tc_jsnorm_bugs, js_begin_end);
    tcase_add_test(tc_jsnorm_bugs, multiple_scripts);
    tcase_add_test(tc_jsnorm_bugs, screnc_infloop);

    return s;
}

