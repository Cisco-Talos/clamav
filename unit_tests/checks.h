#ifndef CHECKS_H
#define CHECKS_H

#if CHECK_MAJOR_VERSION > 0 || ( CHECK_MINOR_VERSION > 9 || ( CHECK_MINOR_VERSION == 9 && CHECK_MICRO_VERSION > 3))
#define CHECK_HAVE_LOOPS
#endif
Suite *test_jsnorm_suite(void);
Suite *test_str_suite(void);
Suite *test_regex_suite(void);
Suite *test_disasm_suite(void);
Suite *test_uniq_suite(void);
Suite *test_matchers_suite(void);
void errmsg_expected(void);
int open_testfile(const char *name);
#endif
