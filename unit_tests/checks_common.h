#ifndef CHECKS_COMMON_H
#define CHECKS_COMMON_H

#if CHECK_MAJOR_VERSION > 0 || ( CHECK_MINOR_VERSION > 9 || ( CHECK_MINOR_VERSION == 9 && CHECK_MICRO_VERSION > 3))
#define CHECK_HAVE_LOOPS
#endif

#if CHECK_MAJOR_VERSION > 0 || ( CHECK_MINOR_VERSION > 9 || ( CHECK_MINOR_VERSION == 9 && CHECK_MICRO_VERSION > 0))
#define fail_unless_fmt fail_unless
#define fail_fmt fail
#else
#define fail_unless_fmt(cond, msg, ...) fail_unless(cond, msg)
#define fail_fmt(msg, ...) fail(msg)
#endif

#endif
