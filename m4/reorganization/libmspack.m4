m4_include([libclamav/libmspack-0.5alpha/m4/libmspack-opts.m4])

if test "x$system_libmspack" = "xno"; then
    use_internal_mspack=yes
    AM_CONDITIONAL([USE_INTERNAL_MSPACK], test TRUE)
else
    PKG_CHECK_MODULES([LIBMSPACK], [libmspack],
                        use_internal_mspack=no, use_internal_mspack=yes)
    AM_CONDITIONAL([USE_INTERNAL_MSPACK], test "x$use_internal_mspack" = "xyes")
fi
