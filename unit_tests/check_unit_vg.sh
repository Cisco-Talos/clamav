#!/bin/sh
. $srcdir/check_common.sh
init_valgrind
export CK_FORK=no WRAPPER="$VALGRIND $VALGRIND_FLAGS" CK_DEFAULT_TIMEOUT=40
if test_run 0 $TOP/unit_tests/check_clamav; then
    echo "check_clamav failed to run" >&2
fi
end_valgrind
