#!/bin/sh
. $srcdir/check_common.sh
init_valgrind
WRAPPER="$VALGRIND $VALGRIND_FLAGS" test_clamscan 9
end_valgrind 9
