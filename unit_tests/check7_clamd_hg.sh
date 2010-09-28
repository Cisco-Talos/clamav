#!/bin/sh
exit 77
. $srcdir/check_common.sh
init_helgrind
WRAPPER="$VALGRIND $VALGRIND_FLAGS_RACE" test_clamd1 7
end_valgrind 7
