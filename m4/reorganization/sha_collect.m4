AC_ARG_ENABLE([sha-collector-for-internal-use], [], [enable_sha_collector="yes"], [enable_sha_collector="no"])
if test "$enable_sha_collector" != "no"; then
    AC_DEFINE([HAVE__INTERNAL__SHA_COLLECT], 1, [For internal use only - DO NOT DEFINE])
fi
