AC_ARG_ENABLE([llvm],AC_HELP_STRING([--enable-llvm],
				    [Enable 'llvm' JIT/verifier support @<:@default=auto@:>@]),
				    [enable_llvm=$enableval], [enable_llvm="auto"])

if test "$enable_llvm" != "no"; then
    dnl Try to configure subdir, optionally
    AC_CONFIG_SUBDIRS_OPTIONAL([libclamav/c++])
fi
