#ifndef CHECKS_H
#define CHECKS_H

#include "checks_common.h"
Suite *test_jsnorm_suite(void);
Suite *test_str_suite(void);
Suite *test_regex_suite(void);
Suite *test_disasm_suite(void);
Suite *test_uniq_suite(void);
Suite *test_matchers_suite(void);
Suite *test_htmlnorm_suite(void);
Suite *test_bytecode_suite(void);
void errmsg_expected(void);
int open_testfile(const char *name);
void diff_files(int fd, int reffd);
void diff_file_mem(int fd, const char *ref, size_t len);

extern struct cli_dconf *dconf;
void dconf_setup(void);
void dconf_teardown(void);

#endif
