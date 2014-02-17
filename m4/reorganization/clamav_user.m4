dnl Check for clamav in /etc/passwd
if test "$test_clamav" = "yes"
then
    dnl parse /etc/passwd
    if test "$use_id" = "no"
    then
	AC_MSG_CHECKING([for $clamav_user in /etc/passwd])
	if test -r /etc/passwd; then
	    clamavuser=`cat /etc/passwd|grep "^$clamav_user:"`
	    clamavgroup=`cat /etc/group|grep "^$clamav_group:"`
	fi
    else
	AC_MSG_CHECKING([for $clamav_user using id])
	id $clamav_user > /dev/null 2>&1
	if test "$?" = 0 ; then
	    clamavuser=1
	    AC_PATH_PROG(GETENT, getent)
	    if test -n "$GETENT" ; then
		clamavgroup=`$GETENT group | grep "^${clamav_group}:"`
	    else
		clamavgroup=`cat /etc/group|grep $clamav_group`
	    fi
	fi
    fi

    if test "$use_netinfo" = "yes"
    then
	if test -x /usr/bin/dscl; then
	    AC_MSG_CHECKING([for $clamav_user using dscl])
	    clamavuser=`/usr/bin/dscl . -list /Users |grep ${clamav_user}`
	    clamavgroup=`/usr/bin/dscl . -list /Groups |grep ${clamav_group}`
	else
	    AC_MSG_CHECKING([for $clamav_user using netinfo])
	    clamavuser=`/usr/bin/nidump passwd . |grep ${clamav_user}`
	    clamavgroup=`/usr/bin/nidump group . |grep ${clamav_group}`
	fi
    fi

    if test "$use_yp" = "yes"
    then
	AC_MSG_CHECKING([for $clamav_user using ypmatch])
        clamavuser=`ypmatch ${clamav_user} passwd`
        clamavgroup=`ypmatch ${clamav_group} group`
    fi

    if test -z "$clamavuser" || test -z "$clamavgroup"
    then
	AC_MSG_RESULT(no)
	AC_MSG_ERROR([User $clamav_user (and/or group $clamav_group) doesn't exist. Please read the documentation !])
    else
	AC_MSG_RESULT([yes, user $clamav_user and group $clamav_group])
        CLAMAVUSER="$clamav_user"
        CLAMAVGROUP="$clamav_group"
        AC_SUBST([CLAMAVUSER])
        AC_SUBST([CLAMAVGROUP])
    fi
fi
