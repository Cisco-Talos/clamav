#!/bin/sh
. $srcdir/check_common.sh
init_valgrind
CK_FORK=no WRAPPER="$VALGRIND $VALGRIND_FLAGS" ./check_clamav
end_valgrind
