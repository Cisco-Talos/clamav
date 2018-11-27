m4_include([libclamav/c++/m4/llvm-opts.m4])

if test "x$llvmoptserrmsg" != "x"; then
    if test "$enable_llvm" = "auto"; then
        enable_llvm="no"
    else
        AC_MSG_ERROR([Failed to configure LLVM, and LLVM was explicitly requested])
        dnl AC_MSG_ERROR([$llvmoptserrmsg])
    fi
fi

if test "$enable_llvm" != "no"; then
    dnl Try to configure subdir, optionally
    AC_CONFIG_SUBDIRS_OPTIONAL([libclamav/c++])
else
    system_llvm="none"
    llvm_linking=""
fi
