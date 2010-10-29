%define pref /usr
%define ver  2.9.1
%define ver2 2.9
%define rel  1

# Configurable settings (use --with(out) unicode on rpmbuild command line):
%define unicode 0
%{?_with_unicode: %{expand: %%define unicode 1}}
%{?_without_unicode: %{expand: %%define unicode 0}}

%if %{unicode}
    %define name         wx-base-unicode
    %define wxconfig     base-unicode-release-%{ver2}
    %define wxconfiglink wxbaseu-%{ver2}-config
%else
    %define name         wx-base
    %define wxconfig     base-ansi-release-%{ver2}
    %define wxconfiglink wxbase-%{ver2}-config
%endif

Summary: wxBase library - non-GUI support classes of wxWidgets toolkit
Name: %{name}
Version: %{ver}
Release: %{rel}
License: wxWindows Licence
Group: Development/Libraries
Source: wxBase-%{ver}.tar.bz2
URL: http://www.wxwidgets.org
Packager: Vadim Zeitlin <vadim@wxwindows.org>
Prefix: %{pref}
BuildRoot: %{_tmppath}/%{name}-root
Provides: wxBase

%description
wxBase is a collection of C++ classes providing basic data structures (strings,
lists, arrays), powerful wxDateTime class for date manipulations, portable
wrappers around many OS-specific functions allowing to build the same program
under all supported folders, wxThread class for writing multithreaded programs
using either Win32 or POSIX threads and much more. wxBase currently supports
the following platforms: Win32, generic Unix (Linux, FreeBSD, Solaris, HP-UX,
...) and BeOS.

%package devel
Summary: wxBase headers needed for developping with wxBase
Group: Development/Libraries
Requires: %{name} = %{ver}
Provides: wxBase-devel

%description devel
Header files for wxBase. You need them to develop programs using wxBase.

%package static
Summary: wxBase static libraries
Group: Development/Libraries
Requires: %{name}-devel = %{ver}

%description static
Static libraries for wxBase. You need them if you want to link statically against wxBase.

%prep
%setup -q -n wxBase-%{ver}

%build
if [ "$SMP" != "" ]; then
    export MAKE="make -j$SMP"
else
    export MAKE="make"
fi

mkdir obj-shared
cd obj-shared
../configure --prefix=%{pref} --disable-gui \
%if %{unicode}
                              --enable-unicode
%else
                              --disable-unicode \
%endif
$MAKE
cd ..

mkdir obj-static
cd obj-static
../configure --prefix=%{pref} --disable-gui --disable-shared \
%if %{unicode}
                              --enable-unicode
%else
                              --disable-unicode \
%endif
$MAKE
cd ..

%install
rm -rf $RPM_BUILD_ROOT
make -C locale allmo
make -C obj-static DESTDIR=$RPM_BUILD_ROOT prefix=%{pref} install
make -C obj-shared DESTDIR=$RPM_BUILD_ROOT prefix=%{pref} install

# we need to modify the absolute wx-config link to be relative or rpm complains
# (and our package wouldn't be relocatable)
ln -sf ../lib/wx/config/%{wxconfig} $RPM_BUILD_ROOT/%{pref}/bin/wx-config

%find_lang wxstd

%clean
rm -rf $RPM_BUILD_ROOT

%post
/sbin/ldconfig

%postun
/sbin/ldconfig

%post devel
# link wx-config when you install RPM.
ln -sf %{_libdir}/wx/config/%{wxconfig} %{_bindir}/wx-config
# link wx-config with explicit name.
ln -sf %{_libdir}/wx/config/%{wxconfig} %{_bindir}/%{wxconfiglink}
/sbin/ldconfig

%postun devel
/sbin/ldconfig

%preun devel
if test -f %{_bindir}/wx-config -a -f /usr/bin/md5sum ; then
    SUM1=`md5sum %{_libdir}/wx/config/%{wxconfig} | cut -c 0-32`
    SUM2=`md5sum %{_bindir}/wx-config | cut -c 0-32`  
    if test "x$SUM1" = "x$SUM2" ; then
        rm -f %{_bindir}/wx-config
    fi
fi
rm -f %{_bindir}/%{wxconfiglink}

%files -f wxstd.lang
%defattr (-,root,root)
%doc COPYING.LIB *.txt
%{_libdir}/libwx_base*-%{ver2}.so.*

%files devel
%defattr (-,root,root)
%{_bindir}/wx-config
%dir %{_includedir}/wx-%{ver2}
%{_includedir}/wx-%{ver2}/*
%{_libdir}/libwx_base*-%{ver2}.so
%dir %{_libdir}/wx
%{_libdir}/wx/*
%{_datadir}/aclocal/*.m4
%{_datadir}/bakefile/presets/*
%{_datadir}/locale/*/LC_MESSAGES/*.mo

%files static
%defattr (-,root,root)
%{_libdir}/lib*.a
