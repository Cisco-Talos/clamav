AC_ARG_ENABLE([distcheck-werror],
	      AC_HELP_STRING([--enable-distcheck-werror],
			     [enable warnings as error for distcheck
			      @<:@default=no@:>@]),
[enable_distcheckwerror=$enableval],[enable_distcheckwerror="no"])

# Enable distcheck warnings and Werror only for gcc versions that support them,
# and only after we've run the configure tests.
# Some configure tests fail (like checking for cos in -lm) if we enable these
# Werror flags for configure too (for example -Wstrict-prototypes makes
# configure think that -lm doesn't have cos, hence its in libc).
WERR_CFLAGS=
WERR_CFLAGS_MILTER=
if test "x$enable_distcheckwerror" = "xyes"; then
    if test "$distcheck_enable_flags" = "1"; then
	WERR_COMMON="-Wno-pointer-sign -Werror-implicit-function-declaration -Werror -Wextra -Wall -Wno-error=strict-aliasing -Wno-error=bad-function-cast -Wbad-function-cast -Wcast-align -Wendif-labels -Wfloat-equal -Wformat=2 -Wformat-security -Wmissing-declarations -Wmissing-prototypes -Wno-error=missing-prototypes -Wnested-externs -Wno-error=nested-externs -Wpointer-arith -Wstrict-prototypes -Wno-error=strict-prototypes -Wno-switch -Wno-switch-enum -Wundef -Wstrict-overflow=1 -Winit-self -Wmissing-include-dirs -Wdeclaration-after-statement -Waggregate-return -Wmissing-format-attribute -Wno-error=missing-format-attribute -Wno-error=type-limits -Wno-error=unused-but-set-variable -Wno-error=unused-function -Wno-error=unused-value -Wno-error=unused-variable -Wcast-qual -Wno-error=cast-qual -Wno-error=sign-compare -Wshadow -Wno-error=shadow -Wno-error=uninitialized -fdiagnostics-show-option -Wno-unused-parameter -Wno-error=unreachable-code -Winvalid-pch -Wno-error=invalid-pch -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-all -Wstack-protector -Wno-error=aggregate-return"
	WERR_CFLAGS="$WERR_COMMON -Wwrite-strings"
	WERR_CFLAGS_MILTER="$WERR_COMMON -Wno-error=format-nonliteral"
    fi
fi
AC_SUBST([WERR_CFLAGS])
AC_SUBST([WERR_CFLAGS_MILTER])
