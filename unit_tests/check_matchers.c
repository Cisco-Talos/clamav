/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
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

#include <check.h>
#include <stdio.h>
#include <string.h>

#include "../libclamav/clamav.h"
#include "../libclamav/readdb.h"
#include "../libclamav/matcher.h"
#include "../libclamav/matcher-ac.h"
#include "../libclamav/matcher-bm.h"
#include "../libclamav/matcher-pcre.h"
#include "../libclamav/others.h"
#include "../libclamav/default.h"
#include "checks.h"

static const struct ac_testdata_s {
    const char *data;
    const char *hexsig;
    const char *virname;
} ac_testdata[] = {
    /* IMPORTANT: ac_testdata[i].hexsig should only match ac_testdata[i].data */
    { "daaaaaaaaddbbbbbcce", "64[4-4]61616161{2}6262[3-6]65", "Test_1: anchored and ranged wildcard" },
    { "ebbbbbbbbeecccccddf", "6262(6162|6364|6265|6465){2}6363", "Test_2: multi-byte fixed alternate w/ ranged wild" },
    { "aaaabbbbcccccdddddeeee", "616161*63636363*6565", "Test_3: unbounded wildcards" },
    { "oprstuwxy","6f??727374????7879", "Test_4: nibble wildcards" },
    { "abdcabcddabccadbbdbacb", "6463{2-3}64646162(63|64|65)6361*6462????6261{-1}6362", "Test_5: various wildcard combinations w/ alternate" },
    { "abcdefghijkabcdefghijk", "62????65666768*696a6b6162{2-3}656667[1-3]6b", "Test_6: various wildcard combinations" },
    { "abcadbabcadbabcacb", "6?6164?26?62{3}?26162?361", "Test_7: nibble and ranged wildcards" },
    /* testcase for filter bug: it was checking only first 32 chars, and last
     * maxpatlen */
    { "\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1dddddddddddddddddddd5\1\1\1\1\1\1\1\1\1\1\1\1\1","6464646464646464646464646464646464646464(35|36)","Test_8: filter bug"},

    /* altbyte */
    { "aabaa", "6161(62|63|64)6161", "Ac_Altstr_Test_1" }, /* control */
    { "aacaa", "6161(62|63|64)6161", "Ac_Altstr_Test_1" }, /* control */
    { "aadaa", "6161(62|63|64)6161", "Ac_Altstr_Test_1" }, /* control */

    /* alt-fstr */
    { "aabbbaa", "6161(626262|636363|646464)6161", "Ac_Altstr_Test_2" }, /* control */
    { "aacccaa", "6161(626262|636363|646464)6161", "Ac_Altstr_Test_2" }, /* control */
    { "aadddaa", "6161(626262|636363|646464)6161", "Ac_Altstr_Test_2" }, /* control */

    /* alt-vstr */
    { "aabbaa", "6161(6262|63636363|6464646464)6161", "Ac_Altstr_Test_3" }, /* control */
    { "aaccccaa", "6161(6262|63636363|6464646464)6161", "Ac_Altstr_Test_3" }, /* control */
    { "aadddddaa", "6161(6262|63636363|6464646464)6161", "Ac_Altstr_Test_3" }, /* control */

    /* alt-embed */
    { "aajjaa", "6161(6a6a|66(6767|6868)66|6969)6161", "Ac_Altstr_Test_4" }, /* control */
    { "aafggfaa", "6161(6a6a|66(6767|6868)66|6969)6161", "Ac_Altstr_Test_4" }, /* control */
    { "aafhhfaa", "6161(6a6a|66(6767|6868)66|6969)6161", "Ac_Altstr_Test_4" }, /* control */
    { "aaiiaa", "6161(6a6a|66(6767|6868)66|6969)6161", "Ac_Altstr_Test_4" }, /* control */

    { NULL, NULL, NULL }
};

static const struct ac_sigopts_testdata_s {
    const char *data;
    uint32_t dlength;
    const char *hexsig;
    const char *offset;
    const uint16_t sigopts;
    const char *virname;
    const uint8_t expected_result;
} ac_sigopts_testdata[] = {
    /* nocase */
    { "aaaaa", 5, "6161616161", "*", ACPATT_OPTION_NOOPTS, "AC_Sigopts_Test_1", CL_VIRUS }, /* control */
    { "bBbBb", 5, "6262626262", "*", ACPATT_OPTION_NOOPTS, "AC_Sigopts_Test_2", CL_CLEAN }, /* nocase control */
    { "cCcCc", 5, "6363636363", "*", ACPATT_OPTION_NOCASE, "AC_Sigopts_Test_3", CL_VIRUS }, /* nocase test */

    /* fullword */
    { "ddddd&e", 7, "6464646464", "*", ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_4", CL_VIRUS }, /* fullword start */
    { "s&eeeee&e", 9, "6565656565", "*", ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_5", CL_VIRUS }, /* fullword middle */
    { "s&fffff", 7, "6666666666", "*", ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_6", CL_VIRUS }, /* fullword end */
    { "sggggg", 6, "6767676767", "*", ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_7", CL_CLEAN }, /* fullword fail start */
    { "hhhhhe", 6, "6868686868", "*", ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_8", CL_CLEAN }, /* fullword fail end */

    { "iiiii", 5, "(W)6969696969", "*", ACPATT_OPTION_NOOPTS, "AC_Sigopts_Test_9", CL_VIRUS }, /* fullword class start */
    { "jjj&jj", 6, "6a6a6a(W)6a6a", "*", ACPATT_OPTION_NOOPTS, "AC_Sigopts_Test_10", CL_VIRUS }, /* fullword class middle */
    { "kkkkk", 5, "6b6b6b6b6b(W)", "*", ACPATT_OPTION_NOOPTS, "AC_Sigopts_Test_11", CL_VIRUS }, /* fullword class end */
    { "slllll", 6, "(W)6c6c6c6c6c", "*", ACPATT_OPTION_NOOPTS, "AC_Sigopts_Test_12", CL_CLEAN }, /* fullword fail start */
    { "mmmmme", 6, "6d6d6d6d6d(W)", "*", ACPATT_OPTION_NOOPTS, "AC_Sigopts_Test_13", CL_CLEAN }, /* fullword class end */

    { "nNnNn", 5, "6e6e6e6e6e", "*", ACPATT_OPTION_NOCASE | ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_14", CL_VIRUS }, /* nocase fullword */
    { "soOoOo", 6, "6f6f6f6f6f", "*", ACPATT_OPTION_NOCASE | ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_15", CL_CLEAN }, /* nocase fullword start fail */
    { "pPpPpe", 6, "7070707070", "*", ACPATT_OPTION_NOCASE | ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_16", CL_CLEAN }, /* nocase fullword end fail */

    /* wide */
    { "q\0q\0q\0q\0q\0", 10, "7171717171", "*", ACPATT_OPTION_WIDE, "AC_Sigopts_Test_17", CL_VIRUS }, /* control */
    { "r\0R\0r\0R\0r\0", 10, "7272727272", "*", ACPATT_OPTION_WIDE | ACPATT_OPTION_NOCASE, "AC_Sigopts_Test_18", CL_VIRUS }, /* control */
    { "s\0s\0s\0s\0s\0", 10, "7373737373", "*", ACPATT_OPTION_WIDE | ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_19", CL_VIRUS }, /* control */

    { "t\0t\0t\0t\0t\0", 10, "7474747474", "*", ACPATT_OPTION_WIDE | ACPATT_OPTION_ASCII, "AC_Sigopts_Test_20", CL_VIRUS }, /* control */

    { "u\0u\0u\0u\0u\0", 10, "7575757575", "*", ACPATT_OPTION_WIDE | ACPATT_OPTION_NOCASE | ACPATT_OPTION_FULLWORD, "AC_Sigopts_Test_21", CL_VIRUS }, /* control */
    { "v\0v\0v\0v\0v\0", 10, "7676767676", "*", ACPATT_OPTION_WIDE | ACPATT_OPTION_NOCASE | ACPATT_OPTION_ASCII, "AC_Sigopts_Test_22", CL_VIRUS }, /* control */

    { "w\0w\0w\0w\0w\0", 10, "7777777777", "*", ACPATT_OPTION_WIDE | ACPATT_OPTION_FULLWORD | ACPATT_OPTION_ASCII, "AC_Sigopts_Test_23", CL_VIRUS }, /* control */
    { "x\0x\0x\0x\0x\0", 10, "7878787878", "*", ACPATT_OPTION_WIDE | ACPATT_OPTION_NOCASE | ACPATT_OPTION_FULLWORD | ACPATT_OPTION_ASCII, "AC_Sigopts_Test_24", CL_VIRUS }, /* control */

    { NULL, 0, NULL, NULL, ACPATT_OPTION_NOOPTS, NULL, CL_CLEAN }
};

#if HAVE_PCRE

static const struct pcre_testdata_s {
    const char *data;
    const char *hexsig;
    const char *offset;
    const uint16_t sigopts;
    const char *virname;
    const uint8_t expected_result;
} pcre_testdata[] = {
    { "clamav", "/clamav/", "*", ACPATT_OPTION_NOOPTS, "Test_1: simple string", CL_VIRUS },
    { "cla:mav", "/cla:mav/", "*", ACPATT_OPTION_NOOPTS, "Test_2: embedded colon", CL_VIRUS },

    { "notbasic", "/basic/r", "0", ACPATT_OPTION_NOOPTS, "Test_3: rolling option", CL_VIRUS },
    { "nottrue", "/true/", "0", ACPATT_OPTION_NOOPTS, "Test4: rolling(off) option", CL_SUCCESS },

    { "not12345678truly", "/12345678/e", "3,8", ACPATT_OPTION_NOOPTS, "Test_5: encompass option", CL_VIRUS },
    { "not23456789truly", "/23456789/e", "4,8", ACPATT_OPTION_NOOPTS, "Test6: encompass option (low end)", CL_SUCCESS },
    { "not34567890truly", "/34567890/e", "3,7", ACPATT_OPTION_NOOPTS, "Test7: encompass option (high end)", CL_SUCCESS },

    { "notapietruly", "/apie/re", "2,2", ACPATT_OPTION_NOOPTS, "Test8: rolling encompass", CL_SUCCESS },
    { "notafigtruly", "/afig/e", "2,2", ACPATT_OPTION_NOOPTS, "Test9: rolling(off) encompass", CL_SUCCESS },
    { "notatretruly", "/atre/re", "2,6", ACPATT_OPTION_NOOPTS, "Test10: rolling encompass", CL_VIRUS },
    { "notasadtruly", "/asad/e", "2,6", ACPATT_OPTION_NOOPTS, "Test11: rolling(off) encompass", CL_VIRUS },

    { NULL, NULL, NULL, ACPATT_OPTION_NOOPTS, NULL, CL_CLEAN }
};

#endif /* HAVE_PCRE */

static cli_ctx ctx;
static struct cl_scan_options options;

static fmap_t *thefmap = NULL;
static const char *virname = NULL;
static void setup(void)
{
	struct cli_matcher *root;
	virname = NULL;
	thefmap = NULL;

    memset(&ctx, 0, sizeof(ctx));
    memset(&options, 0, sizeof(struct cl_scan_options));
    ctx.options = &options;

	ctx.virname = &virname;
	ctx.fmap = &thefmap;
	ctx.engine = cl_engine_new();
	fail_unless(!!ctx.engine, "cl_engine_new() failed");
	root = (struct cli_matcher *) mpool_calloc(ctx.engine->mempool, 1, sizeof(struct cli_matcher));
	fail_unless(root != NULL, "root == NULL");
#ifdef USE_MPOOL
	root->mempool = ctx.engine->mempool;
#endif

	ctx.engine->root[0] = root;
}

static void teardown(void)
{
	cl_engine_free((struct cl_engine*)ctx.engine);
}

START_TEST (test_ac_scanbuff) {
	struct cli_ac_data mdata;
	struct cli_matcher *root;
	unsigned int i;
	int ret;

    root = ctx.engine->root[0];
    fail_unless(root != NULL, "root == NULL");
    root->ac_only = 1;

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ret = cli_ac_init(root, CLI_DEFAULT_AC_MINDEPTH, CLI_DEFAULT_AC_MAXDEPTH, 1);
    fail_unless(ret == CL_SUCCESS, "cli_ac_init() failed");


    for(i = 0; ac_testdata[i].data; i++) {
	ret = cli_parse_add(root, ac_testdata[i].virname, ac_testdata[i].hexsig, 0, 0, 0, "*", 0, NULL, 0);
	fail_unless(ret == CL_SUCCESS, "cli_parse_add() failed");
    }

    ret = cli_ac_buildtrie(root);
    fail_unless(ret == CL_SUCCESS, "cli_ac_buildtrie() failed");

    ret = cli_ac_initdata(&mdata, root->ac_partsigs, 0, 0, CLI_DEFAULT_AC_TRACKLEN);
    fail_unless(ret == CL_SUCCESS, "cli_ac_initdata() failed");

    ctx.options->general &= ~CL_SCAN_GENERAL_ALLMATCHES; /* make sure all-match is disabled */
    for(i = 0; ac_testdata[i].data; i++) {
	ret = cli_ac_scanbuff((const unsigned char*)ac_testdata[i].data, strlen(ac_testdata[i].data), &virname, NULL, NULL, root, &mdata, 0, 0, NULL, AC_SCAN_VIR, NULL);
	fail_unless_fmt(ret == CL_VIRUS, "cli_ac_scanbuff() failed for %s", ac_testdata[i].virname);
	fail_unless_fmt(!strncmp(virname, ac_testdata[i].virname, strlen(ac_testdata[i].virname)), "Dataset %u matched with %s", i, virname);

	ret = cli_scanbuff((const unsigned char*)ac_testdata[i].data, strlen(ac_testdata[i].data), 0, &ctx, 0, NULL);
	fail_unless_fmt(ret == CL_VIRUS, "cli_scanbuff() failed for %s", ac_testdata[i].virname);
	fail_unless_fmt(!strncmp(virname, ac_testdata[i].virname, strlen(ac_testdata[i].virname)), "Dataset %u matched with %s", i, virname);
    }

    cli_ac_freedata(&mdata);
}
END_TEST

START_TEST (test_ac_scanbuff_allscan) {
	struct cli_ac_data mdata;
	struct cli_matcher *root;
	unsigned int i;
	int ret;

    root = ctx.engine->root[0];
    fail_unless(root != NULL, "root == NULL");
    root->ac_only = 1;

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ret = cli_ac_init(root, CLI_DEFAULT_AC_MINDEPTH, CLI_DEFAULT_AC_MAXDEPTH, 1);
    fail_unless(ret == CL_SUCCESS, "cli_ac_init() failed");


    for(i = 0; ac_testdata[i].data; i++) {
	ret = cli_parse_add(root, ac_testdata[i].virname, ac_testdata[i].hexsig, 0, 0, 0, "*", 0, NULL, 0);
	fail_unless(ret == CL_SUCCESS, "cli_parse_add() failed");
    }

    ret = cli_ac_buildtrie(root);
    fail_unless(ret == CL_SUCCESS, "cli_ac_buildtrie() failed");

    ret = cli_ac_initdata(&mdata, root->ac_partsigs, 0, 0, CLI_DEFAULT_AC_TRACKLEN);
    fail_unless(ret == CL_SUCCESS, "cli_ac_initdata() failed");

    ctx.options->general |= CL_SCAN_GENERAL_ALLMATCHES; /* enable all-match */
    for(i = 0; ac_testdata[i].data; i++) {
	ret = cli_ac_scanbuff((const unsigned char*)ac_testdata[i].data, strlen(ac_testdata[i].data), &virname, NULL, NULL, root, &mdata, 0, 0, NULL, AC_SCAN_VIR, NULL);
	fail_unless_fmt(ret == CL_VIRUS, "cli_ac_scanbuff() failed for %s", ac_testdata[i].virname);
	fail_unless_fmt(!strncmp(virname, ac_testdata[i].virname, strlen(ac_testdata[i].virname)), "Dataset %u matched with %s", i, virname);

	ret = cli_scanbuff((const unsigned char*)ac_testdata[i].data, strlen(ac_testdata[i].data), 0, &ctx, 0, NULL);
	fail_unless_fmt(ret == CL_VIRUS, "cli_scanbuff() failed for %s", ac_testdata[i].virname);
	fail_unless_fmt(!strncmp(virname, ac_testdata[i].virname, strlen(ac_testdata[i].virname)), "Dataset %u matched with %s", i, virname);
	if (ctx.num_viruses)
	    ctx.num_viruses = 0;
     }

    cli_ac_freedata(&mdata);
}
END_TEST

START_TEST (test_ac_scanbuff_ex) {
	struct cli_ac_data mdata;
	struct cli_matcher *root;
	unsigned int i;
	int ret;

    root = ctx.engine->root[0];
    fail_unless(root != NULL, "root == NULL");
    root->ac_only = 1;

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ret = cli_ac_init(root, CLI_DEFAULT_AC_MINDEPTH, CLI_DEFAULT_AC_MAXDEPTH, 1);
    fail_unless(ret == CL_SUCCESS, "[ac_ex] cli_ac_init() failed");

    for(i = 0; ac_sigopts_testdata[i].data; i++) {
	ret = cli_sigopts_handler(root, ac_sigopts_testdata[i].virname, ac_sigopts_testdata[i].hexsig, ac_sigopts_testdata[i].sigopts, 0, 0, ac_sigopts_testdata[i].offset, 0, NULL, 0);
	fail_unless(ret == CL_SUCCESS, "[ac_ex] cli_sigopts_handler() failed");
    }

    ret = cli_ac_buildtrie(root);
    fail_unless(ret == CL_SUCCESS, "[ac_ex] cli_ac_buildtrie() failed");

    ret = cli_ac_initdata(&mdata, root->ac_partsigs, 0, 0, CLI_DEFAULT_AC_TRACKLEN);
    fail_unless(ret == CL_SUCCESS, "[ac_ex] cli_ac_initdata() failed");

    ctx.options->general &= ~CL_SCAN_GENERAL_ALLMATCHES; /* make sure all-match is disabled */
    for(i = 0; ac_sigopts_testdata[i].data; i++) {
	ret = cli_ac_scanbuff((const unsigned char*)ac_sigopts_testdata[i].data, ac_sigopts_testdata[i].dlength, &virname, NULL, NULL, root, &mdata, 0, 0, NULL, AC_SCAN_VIR, NULL);
	fail_unless_fmt(ret == ac_sigopts_testdata[i].expected_result, "[ac_ex] cli_ac_scanbuff() failed for %s (%d != %d)", ac_sigopts_testdata[i].virname, ret, ac_sigopts_testdata[i].expected_result);
	if (ac_sigopts_testdata[i].expected_result == CL_VIRUS)
	    fail_unless_fmt(!strncmp(virname, ac_sigopts_testdata[i].virname, strlen(ac_sigopts_testdata[i].virname)), "[ac_ex] Dataset %u matched with %s", i, virname);

	ret = cli_scanbuff((const unsigned char*)ac_sigopts_testdata[i].data, ac_sigopts_testdata[i].dlength, 0, &ctx, 0, NULL);
	fail_unless_fmt(ret == ac_sigopts_testdata[i].expected_result, "[ac_ex] cli_ac_scanbuff() failed for %s (%d != %d)", ac_sigopts_testdata[i].virname, ret, ac_sigopts_testdata[i].expected_result);
    }

    cli_ac_freedata(&mdata);
}
END_TEST

START_TEST (test_ac_scanbuff_allscan_ex) {
	struct cli_ac_data mdata;
	struct cli_matcher *root;
	unsigned int i;
	int ret;

    root = ctx.engine->root[0];
    fail_unless(root != NULL, "root == NULL");
    root->ac_only = 1;

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ret = cli_ac_init(root, CLI_DEFAULT_AC_MINDEPTH, CLI_DEFAULT_AC_MAXDEPTH, 1);
    fail_unless(ret == CL_SUCCESS, "[ac_ex] cli_ac_init() failed");

    for(i = 0; ac_sigopts_testdata[i].data; i++) {
	ret = cli_sigopts_handler(root, ac_sigopts_testdata[i].virname, ac_sigopts_testdata[i].hexsig, ac_sigopts_testdata[i].sigopts, 0, 0, ac_sigopts_testdata[i].offset, 0, NULL, 0);
	fail_unless(ret == CL_SUCCESS, "[ac_ex] cli_sigopts_handler() failed");
    }

    ret = cli_ac_buildtrie(root);
    fail_unless(ret == CL_SUCCESS, "[ac_ex] cli_ac_buildtrie() failed");

    ret = cli_ac_initdata(&mdata, root->ac_partsigs, 0, 0, CLI_DEFAULT_AC_TRACKLEN);
    fail_unless(ret == CL_SUCCESS, "[ac_ex] cli_ac_initdata() failed");

    ctx.options->general |= CL_SCAN_GENERAL_ALLMATCHES; /* enable all-match */
    for(i = 0; ac_sigopts_testdata[i].data; i++) {
	ret = cli_ac_scanbuff((const unsigned char*)ac_sigopts_testdata[i].data, ac_sigopts_testdata[i].dlength, &virname, NULL, NULL, root, &mdata, 0, 0, NULL, AC_SCAN_VIR, NULL);
	fail_unless_fmt(ret == ac_sigopts_testdata[i].expected_result, "[ac_ex] cli_ac_scanbuff() failed for %s (%d != %d)", ac_sigopts_testdata[i].virname, ret, ac_sigopts_testdata[i].expected_result);
	if (ac_sigopts_testdata[i].expected_result == CL_VIRUS)
	    fail_unless_fmt(!strncmp(virname, ac_sigopts_testdata[i].virname, strlen(ac_sigopts_testdata[i].virname)), "[ac_ex] Dataset %u matched with %s", i, virname);

	ret = cli_scanbuff((const unsigned char*)ac_sigopts_testdata[i].data, ac_sigopts_testdata[i].dlength, 0, &ctx, 0, NULL);
	fail_unless_fmt(ret == ac_sigopts_testdata[i].expected_result, "[ac_ex] cli_ac_scanbuff() failed for %s (%d != %d)", ac_sigopts_testdata[i].virname, ret, ac_sigopts_testdata[i].expected_result);
	if (ctx.num_viruses)
	    ctx.num_viruses = 0;
    }

    cli_ac_freedata(&mdata);
}
END_TEST

START_TEST (test_bm_scanbuff) {
	struct cli_matcher *root;
	const char *virname = NULL;
	int ret;


    root = ctx.engine->root[0];
    fail_unless(root != NULL, "root == NULL");

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ret = cli_bm_init(root);
    fail_unless(ret == CL_SUCCESS, "cli_bm_init() failed");

    ret = cli_parse_add(root, "Sig1", "deadbabe", 0, 0, 0, "*", 0, NULL, 0);
    fail_unless(ret == CL_SUCCESS, "cli_parse_add() failed");
    ret = cli_parse_add(root, "Sig2", "deadbeef", 0, 0, 0, "*", 0, NULL, 0);
    fail_unless(ret == CL_SUCCESS, "cli_parse_add() failed");
    ret = cli_parse_add(root, "Sig3", "babedead", 0, 0, 0, "*", 0, NULL, 0);
    fail_unless(ret == CL_SUCCESS, "cli_parse_add() failed");

    ctx.options->general &= ~CL_SCAN_GENERAL_ALLMATCHES; /* make sure all-match is disabled */
    ret = cli_bm_scanbuff((const unsigned char*)"blah\xde\xad\xbe\xef", 12, &virname, NULL, root, 0, NULL, NULL, NULL);
    fail_unless(ret == CL_VIRUS, "cli_bm_scanbuff() failed");
    fail_unless(!strncmp(virname, "Sig2", 4), "Incorrect signature matched in cli_bm_scanbuff()\n");
}
END_TEST

START_TEST (test_bm_scanbuff_allscan) {
	struct cli_matcher *root;
	const char *virname = NULL;
	int ret;


    root = ctx.engine->root[0];
    fail_unless(root != NULL, "root == NULL");

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ret = cli_bm_init(root);
    fail_unless(ret == CL_SUCCESS, "cli_bm_init() failed");

    ret = cli_parse_add(root, "Sig1", "deadbabe", 0, 0, 0, "*", 0, NULL, 0);
    fail_unless(ret == CL_SUCCESS, "cli_parse_add() failed");
    ret = cli_parse_add(root, "Sig2", "deadbeef", 0, 0, 0, "*", 0, NULL, 0);
    fail_unless(ret == CL_SUCCESS, "cli_parse_add() failed");
    ret = cli_parse_add(root, "Sig3", "babedead", 0, 0, 0, "*", 0, NULL, 0);
    fail_unless(ret == CL_SUCCESS, "cli_parse_add() failed");

    ctx.options->general |= CL_SCAN_GENERAL_ALLMATCHES; /* enable all-match */
    ret = cli_bm_scanbuff((const unsigned char*)"blah\xde\xad\xbe\xef", 12, &virname, NULL, root, 0, NULL, NULL, NULL);
    fail_unless(ret == CL_VIRUS, "cli_bm_scanbuff() failed");
    fail_unless(!strncmp(virname, "Sig2", 4), "Incorrect signature matched in cli_bm_scanbuff()\n");
}
END_TEST

#if HAVE_PCRE

START_TEST (test_pcre_scanbuff) {
	struct cli_ac_data mdata;
	struct cli_matcher *root;
	char *hexsig;
	unsigned int i, hexlen;
	int ret;

    root = ctx.engine->root[0];
    fail_unless(root != NULL, "root == NULL");

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ret = cli_pcre_init();
    fail_unless(ret == CL_SUCCESS, "[pcre] cli_pcre_init() failed");

    for(i = 0; pcre_testdata[i].data; i++) {
	hexlen = strlen(PCRE_BYPASS) + strlen(pcre_testdata[i].hexsig) + 1;

	hexsig = cli_calloc(hexlen, sizeof(char));
	fail_unless(hexsig != NULL, "[pcre] failed to prepend bypass (out-of-memory)");

	strncat(hexsig, PCRE_BYPASS, hexlen);
	strncat(hexsig, pcre_testdata[i].hexsig, hexlen);

	ret = cli_parse_add(root, pcre_testdata[i].virname, hexsig, pcre_testdata[i].sigopts, 0, 0, pcre_testdata[i].offset, 0, NULL, 0);
	fail_unless(ret == CL_SUCCESS, "[pcre] cli_parse_add() failed");
	free(hexsig);
    }

    ret = cli_pcre_build(root, CLI_DEFAULT_PCRE_MATCH_LIMIT, CLI_DEFAULT_PCRE_RECMATCH_LIMIT, NULL);
    fail_unless(ret == CL_SUCCESS, "[pcre] cli_pcre_build() failed");

    // recomputate offsets

    ret = cli_ac_initdata(&mdata, root->ac_partsigs, root->ac_lsigs, root->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN);
    fail_unless(ret == CL_SUCCESS, "[pcre] cli_ac_initdata() failed");

    ctx.options->general &= ~CL_SCAN_GENERAL_ALLMATCHES; /* make sure all-match is disabled */
    for(i = 0; pcre_testdata[i].data; i++) {
	ret = cli_pcre_scanbuf((const unsigned char*)pcre_testdata[i].data, strlen(pcre_testdata[i].data), &virname, NULL, root, NULL, NULL, NULL);
	fail_unless_fmt(ret == pcre_testdata[i].expected_result, "[pcre] cli_pcre_scanbuff() failed for %s (%d != %d)", pcre_testdata[i].virname, ret, pcre_testdata[i].expected_result);
	if (pcre_testdata[i].expected_result == CL_VIRUS)
	    fail_unless_fmt(!strncmp(virname, pcre_testdata[i].virname, strlen(pcre_testdata[i].virname)), "[pcre] Dataset %u matched with %s", i, virname);

	ret = cli_scanbuff((const unsigned char*)pcre_testdata[i].data, strlen(pcre_testdata[i].data), 0, &ctx, 0, NULL);
	fail_unless_fmt(ret == pcre_testdata[i].expected_result, "[pcre] cli_scanbuff() failed for %s", pcre_testdata[i].virname);
    }

    cli_ac_freedata(&mdata);
}
END_TEST

START_TEST (test_pcre_scanbuff_allscan) {
	struct cli_ac_data mdata;
	struct cli_matcher *root;
	char *hexsig;
	unsigned int i, hexlen;
	int ret;

    root = ctx.engine->root[0];
    fail_unless(root != NULL, "root == NULL");

#ifdef USE_MPOOL
    root->mempool = mpool_create();
#endif
    ret = cli_pcre_init();
    fail_unless(ret == CL_SUCCESS, "[pcre] cli_pcre_init() failed");

    for(i = 0; pcre_testdata[i].data; i++) {
	hexlen = strlen(PCRE_BYPASS) + strlen(pcre_testdata[i].hexsig) + 1;

	hexsig = cli_calloc(hexlen, sizeof(char));
	fail_unless(hexsig != NULL, "[pcre] failed to prepend bypass (out-of-memory)");

	strncat(hexsig, PCRE_BYPASS, hexlen);
	strncat(hexsig, pcre_testdata[i].hexsig, hexlen);

	ret = cli_parse_add(root, pcre_testdata[i].virname, hexsig, 0, 0, 0, pcre_testdata[i].offset, 0, NULL, 0);
	fail_unless(ret == CL_SUCCESS, "[pcre] cli_parse_add() failed");
	free(hexsig);
    }

    ret = cli_pcre_build(root, CLI_DEFAULT_PCRE_MATCH_LIMIT, CLI_DEFAULT_PCRE_RECMATCH_LIMIT, NULL);
    fail_unless(ret == CL_SUCCESS, "[pcre] cli_pcre_build() failed");

    // recomputate offsets

    ret = cli_ac_initdata(&mdata, root->ac_partsigs, root->ac_lsigs, root->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN);
    fail_unless(ret == CL_SUCCESS, "[pcre] cli_ac_initdata() failed");

    ctx.options->general |= CL_SCAN_GENERAL_ALLMATCHES; /* enable all-match */
    for(i = 0; pcre_testdata[i].data; i++) {
	ret = cli_pcre_scanbuf((const unsigned char*)pcre_testdata[i].data, strlen(pcre_testdata[i].data), &virname, NULL, root, NULL, NULL, NULL);
	fail_unless_fmt(ret == pcre_testdata[i].expected_result, "[pcre] cli_pcre_scanbuff() failed for %s (%d != %d)", pcre_testdata[i].virname, ret, pcre_testdata[i].expected_result);
	if (pcre_testdata[i].expected_result == CL_VIRUS)
	    fail_unless_fmt(!strncmp(virname, pcre_testdata[i].virname, strlen(pcre_testdata[i].virname)), "[pcre] Dataset %u matched with %s", i, virname);

	ret = cli_scanbuff((const unsigned char*)pcre_testdata[i].data, strlen(pcre_testdata[i].data), 0, &ctx, 0, NULL);
	fail_unless_fmt(ret == pcre_testdata[i].expected_result, "[pcre] cli_scanbuff() failed for %s", pcre_testdata[i].virname);
	/* num_virus field add to test case struct */
	if (ctx.num_viruses)
	    ctx.num_viruses = 0;
    }

    cli_ac_freedata(&mdata);
}
END_TEST

#endif /* HAVE_PCRE */

Suite *test_matchers_suite(void)
{
    Suite *s = suite_create("matchers");
    TCase *tc_matchers;
    tc_matchers = tcase_create("matchers");
    suite_add_tcase(s, tc_matchers);
    tcase_add_checked_fixture (tc_matchers, setup, teardown);
    tcase_add_test(tc_matchers, test_ac_scanbuff);
    tcase_add_test(tc_matchers, test_ac_scanbuff_ex);
    tcase_add_test(tc_matchers, test_bm_scanbuff);
#if HAVE_PCRE
    tcase_add_test(tc_matchers, test_pcre_scanbuff);
#endif
    tcase_add_test(tc_matchers, test_ac_scanbuff_allscan);
    tcase_add_test(tc_matchers, test_ac_scanbuff_allscan_ex);
    tcase_add_test(tc_matchers, test_bm_scanbuff_allscan);
#if HAVE_PCRE
    tcase_add_test(tc_matchers, test_pcre_scanbuff_allscan);
#endif
    return s;
}

