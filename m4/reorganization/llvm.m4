m4_include([libclamav/c++/llvm-flags.m4])

if test "x$llvmconfig" = "x"; then
    llvmconfig="built-in"
fi

if test "$enable_llvm" != "no"; then
    dnl Try to configure subdir, optionally
    AC_CONFIG_SUBDIRS_OPTIONAL([libclamav/c++])
else
    llvmconfig="none"
    llvm_linking=""
fi

if test "$enable_llvm" = "yes" && test "$subdirfailed" != "no"; then
    AC_MSG_ERROR([Failed to configure LLVM, and LLVM was explicitly requested])
fi
if test "$enable_llvm" = "auto" && test "$subdirfailed" != "no"; then
    llvmconfig="not found"
    llvm_linking=""
fi
