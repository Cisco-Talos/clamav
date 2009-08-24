AC_DEFUN([AC_CONFIG_LLVM],[
dnl automatically enable LLVM if host environment is supported, and automatically
dnl disable it if not, unless the user explicitly enables or disables LLVM.
AC_ARG_ENABLE([llvm],AC_HELP_STRING([--enable-llvm],
				    [Enable 'llvm' JIT/verifier support @<:@default=auto@:>@]),
				    [enable_llvm=$enableval], [enable_llvm="auto"])
if test "$enable_llvm" = "auto"; then
         AC_MSG_NOTICE([Checking whether we can build LLVM])
	 if test -z "$CXX"; then
	   AC_CHECK_TOOLS(GXX,[g++ c++ cxx])
	 else
	   GXX="$CXX";
	 fi
	 gxx_version=`${GXX} -dumpversion`
	 if test "$?" -ne 0; then
	    enable_llvm="no";
	    AC_MSG_NOTICE([GNU C++ compiler not found, not building LLVM])
	 else
	    case "${gxx_version}" in
	        [012].*|3.[0123].*)
	             enable_llvm="no"
		     AC_MSG_NOTICE([C++ compiler too old, not building LLVM])
                     ;;
                3.4.[012]*|4.0.1*|4.1.[12]*)
		    enable_llvm="no"
		    AC_MSG_NOTICE([C++ compiler is buggy, not building LLVM])
                    ;;
		*)
		    AC_CHECK_GNU_MAKE
		    if test -z "$llvm_cv_gnu_make_command"; then
		        enable_llvm="no"
		        AC_MSG_NOTICE([GNU make not found, not building LLVM])
                    else
		        case "$target_cpu" in
			    i?86|amd64|x86_64|powerpc*)
			       case "$target_os" in
			          darwin*|freebsd*|openbsd*|netbsd*|dragonfly*|linux*|solaris*|win32*|mingw*)
				       enable_llvm="yes"
				       AC_MSG_NOTICE([Building LLVM])
                                       ;;
				  *)
				       enable_llvm="no"
                                       AC_MSG_NOTICE([OS is not supported, not building LLVM])
                                       ;;
			       esac
			       ;;
			    alpha*|arm*)
			       enable_llvm="no"
			       AC_MSG_NOTICE([CPU support is untested, not building LLVM])
			       ;;
			    *)
			       enable_llvm="no"
			       AC_MSG_NOTICE([Unsupported CPU for JIT: $target_cpu, not building LLVM])
			esac
		    fi
	    esac
	 fi
	 if test "$enable_llvm" != "yes"; then
	    AC_MSG_WARN([LLVM is not supported on your platform, JIT not built])
	 fi
fi
AM_CONDITIONAL([ENABLE_LLVM],[test "$enable_llvm" = "yes"])
if test "$enable_llvm" = "yes"; then
    AC_CONFIG_SUBDIRS([./libclamav/llvm/llvm])
    GMAKE="$llvm_cv_gnu_make_command"
    AC_SUBST([GMAKE])
    ac_configure_args="$ac_configure_args --enable-targets=host-only --enable-bindings=none --enable-libffi=no --without-llvmgcc --without-llvmgxx --enable-optimized"
fi
])
