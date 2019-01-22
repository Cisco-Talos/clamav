/*
 *  Unit tests for JS normalizer.
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>
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
#include <stdlib.h>
#include <string.h>

#include "../libclamav/clamav.h"
#include "../libclamav/uniq.h"
#include "checks.h"

START_TEST (test_uniq_initfail) {
  struct uniq *U;
  U = uniq_init(0);
  fail_unless(U==NULL, "uniq_init(0)!=NULL");
}
END_TEST

START_TEST (test_uniq_known) {
  char *hash;
  uint32_t u;
  struct {
    const char *key;
    const uint32_t key_len;
    const char *expected;
  } tests[] = {
    { NULL, 0, "d41d8cd98f00b204e9800998ecf8427e" }, 
    { "_vba_project", 12, "ae4f6474bee50ccdf1a6b853ba8ad32a" },
    { "powerpoint document", 19, "87320d137f01f7b183eb533a1de6c62a" },
    { "worddocument", 12, "126ea3fd0ff7f18c9c5eec0c07398c49" },
    { "_1_ole10native", 14, "e74f5f7bbf0b77708bc591157d708d3d" },
    { NULL, 0, NULL }
  };
  int i;

  struct uniq *U = uniq_init(5);
  fail_unless(U!=0, "uniq_init");

  for(i=0; tests[i].expected; i++) {
        if (CL_SUCCESS != uniq_add(U, tests[i].key, tests[i].key_len, &hash, &u)) {
            fail("uniq_add(%s) failed.", tests[i].key);
        }
        fail_unless_fmt(u == 1 && strcmp(hash, tests[i].expected) == 0, "uniq_add(%s) = %u - expected %s, got %s", tests[i].key, u, tests[i].expected, hash);
  }

  for(i=0; tests[i].expected; i++) {
        if (CL_SUCCESS != uniq_get(U, tests[i].key, tests[i].key_len, &hash, &u)) {
            fail("uniq_get(%s) failed.", tests[i].key);
        }
    fail_unless_fmt(u==1 && strcmp(hash, tests[i].expected)==0, "uniq_get(%s) = %u - expected %s, got %s", tests[i].key, u, tests[i].expected, hash);
  }

  uniq_free(U);
}
END_TEST


START_TEST (test_uniq_colls) {
  uint32_t u;
  const char *tests[] = { "_vba_project", "powerpoint document", "worddocument", "_1_ole10native" };
  int i, j;

  struct uniq *U = uniq_init(10);
  fail_unless(U!=0, "uniq_init");

  for(j=4; j>0; j--)
        for (i = 0; i < j; i++) {
            if (CL_SUCCESS != uniq_add(U, tests[i], strlen(tests[i]), NULL, &u)) {
                fail("uniq_add(%s) failed.", tests[i]);
            }
        }
  
  for (i=0; i<4; i++) {
        if (CL_SUCCESS != uniq_get(U, tests[i], strlen(tests[i]), NULL, &u)) {
            fail("uniq_get(%s) failed.", tests[i]);
        }
    fail_unless_fmt(u+i==4, "uniq_get(%s) = %u - expected %u", tests[i], u, 4-i);
  }

  uniq_free(U);
}
END_TEST

Suite *test_uniq_suite(void)
{
    Suite *s = suite_create("unique");
    TCase *tc_uniq;
    tc_uniq = tcase_create("unique");
    suite_add_tcase (s, tc_uniq);
    tcase_add_test(tc_uniq, test_uniq_initfail);
    tcase_add_test(tc_uniq, test_uniq_known);
    tcase_add_test(tc_uniq, test_uniq_colls);
    return s;
}

