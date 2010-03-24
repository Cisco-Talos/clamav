#!/bin/sh -x
. $srcdir/check_common.sh
init_valgrind
CK_FORK=no WRAPPER="$VALGRIND $VALGRIND_FLAGS" test_run 0 $TOP/unit_tests/check_clamav
end_valgrind
