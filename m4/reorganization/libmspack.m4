m4_include([libclamav/libmspack-0.5alpha/m4/libmspack-opts.m4])

if test "x$system_libmspack" = "xno"; then
    use_internal_mspack=yes
    AM_CONDITIONAL([USE_INTERNAL_MSPACK], test TRUE)
    CFLAGS="$CFLAGS -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64"
else
    PKG_CHECK_MODULES([LIBMSPACK], [libmspack],
                        use_internal_mspack=no, use_internal_mspack=yes)
    AM_CONDITIONAL([USE_INTERNAL_MSPACK], test "x$use_internal_mspack" = "xyes")
fi
