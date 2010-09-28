#!/bin/sh
. $srcdir/check_common.sh
init_helgrind
WRAPPER="$VALGRIND $VALGRIND_FLAGS_RACE" test_clamd2 8
end_valgrind 8
