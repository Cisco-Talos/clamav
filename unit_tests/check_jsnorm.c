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
	fail_unless(TOKEN_GET(&tok, dval) == -1, "token ival->dval");
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
	fail_unless(TOKEN_GET(&tok, dval) == val, "token dval->dval");
	fail_unless(TOKEN_GET(&tok, ival) == -1, "token dval->ival");
}
END_TEST

START_TEST (test_init_destroy)
{
	struct parser_state *state = cli_js_init();
	fail_unless(!!state, "cli_js_init()");
	cli_js_destroy(state);
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
	fail_unless(html_normalise_mem(buf, sizeof(buf), NULL, NULL, dconf) == 1, "normalise");
}
END_TEST

START_TEST (multiple_scripts)
{
	const char buf[] = "</script> stuff"\
			    "<script language='Javascript'> function foo() {} </script>"\
			    "<script language='Javascript'> function bar() {} </script>";
	m_area_t m_area;
	size_t p;
	struct cli_dconf *dconf = cli_dconf_init();

	fail_unless(!!dconf, "failed to init dconf");
	fail_unless(html_normalise_mem(buf, sizeof(buf), NULL, NULL, dconf) == 1, "normalise");
	/* TODO: test that both had been normalized */
}
END_TEST

Suite *test_jsnorm_suite(void)
{
    Suite *s = suite_create("jsnorm");
    TCase *tc_jsnorm_gperf, *tc_jsnorm_token, *tc_jsnorm_api, *tc_jsnorm_tokenizer, *tc_jsnorm_bugs;
    tc_jsnorm_gperf = tcase_create("jsnorm gperf");
    suite_add_tcase (s, tc_jsnorm_gperf);
    tcase_add_loop_test(tc_jsnorm_gperf, test_keywords, 0, sizeof(kw_test)/sizeof(kw_test[0]));
    tcase_add_loop_test(tc_jsnorm_gperf, test_operators, 0, sizeof(op_test)/sizeof(op_test[0]));

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

    tc_jsnorm_bugs = tcase_create("jsnorm bugs");
    suite_add_tcase (s, tc_jsnorm_bugs);
    tcase_add_test(tc_jsnorm_bugs, js_begin_end);
    tcase_add_test(tc_jsnorm_bugs, multiple_scripts);

    return s;
}

#endif
