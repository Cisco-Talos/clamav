AC_ARG_WITH([dbdir], 
[AS_HELP_STRING([--with-dbdir@<:@=path@:>@], [path to virus database directory])],
db_dir="$withval", db_dir="_default_")

dnl I had problems with $pkgdatadir thus these funny checks
if test "$db_dir" = "_default_"
then
    if test "$prefix" = "NONE"
    then
	db_dir="$ac_default_prefix/share/clamav"
    else
	db_dir="$prefix/share/clamav"
    fi
fi

AC_DEFINE_UNQUOTED([DATADIR],"$db_dir", [Path to virus database directory.])
DBDIR="$db_dir"
AC_SUBST([DBDIR])
