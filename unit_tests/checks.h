#ifndef CHECKS_H
#define CHECKS_H
Suite *test_jsnorm_suite(void);
Suite *test_str_suite(void);
Suite *test_regex_suite(void);
void errmsg_expected(void);
int open_testfile(const char *name);
#endif
