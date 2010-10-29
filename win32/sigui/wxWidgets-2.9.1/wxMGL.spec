%define pref /usr
%define ver 2.9.1
%define ver2 2.9
%define rel 1

Summary: The SciTech MGL port of the wxWindows library
Name: wxMGL
Version: %{ver}
Release: %{rel}
License: wxWindows Licence
Group: System/Libraries
Source: wxMGL-%{ver}.tar.bz2
URL: http://www.wxwindows.org
Packager: Vaclav Slavik <vaclav@wxwindows.org>
Prefix: %{pref}
BuildRoot: /var/tmp/%{name}-root

# all packages providing an implementation of wxWindows library (regardless of
# the toolkit used) should provide the (virtual) wxwin package, this makes it
# possible to require wxwin instead of requiring "wxgtk or wxmotif or wxuniv..."
Provides: wxwin

Provides: libwx_mgl.so
Provides: libwx_mgl-%{ver2}.so

Requires: mgl
BuildRequires: mgl-devel

%description
wxWindows is a free C++ library for cross-platform GUI development.
With wxWindows, you can create applications for different GUIs (GTK+,
Motif/LessTif, MS Windows, Mac) from the same source code.

%package devel
Summary: The SciTech MGL port of the wxWindows library
Group: Development/Libraries
Requires: wxMGL = %{ver}

%description devel
Header files for wxMGL, the SciTech MGL port of the wxWindows library.

%package static
Summary: wxMGL static libraries
Group: Development/Libraries

%description static
Static libraries for wxMGL. You need them if you want to link statically against wxMGL.

%prep
%setup -n wxMGL-%{ver}

%build
if [ "$SMP" != "" ]; then
  export MAKE="make -j$SMP"
else
  export MAKE="make"
fi

mkdir obj-shared
cd obj-shared
../configure --prefix=%{pref} --with-mgl --disable-fs_inet
$MAKE
cd ..

mkdir obj-static
cd obj-static
../configure --prefix=%{pref} --disable-shared --with-mgl --disable-fs_inet
$MAKE
cd ..

%install
rm -rf $RPM_BUILD_ROOT
(cd obj-static; make prefix=$RPM_BUILD_ROOT%{pref} install)
(cd obj-shared; make prefix=$RPM_BUILD_ROOT%{pref} install)

%find_lang wxstd

%clean
rm -rf $RPM_BUILD_ROOT

%post
/sbin/ldconfig

%postun
/sbin/ldconfig

%files -f wxstd.lang
%defattr(-,root,root)
%doc COPYING.LIB *.txt
%{_libdir}/libwx_mgl*-%{ver2}*.so.*

%files devel
%defattr(-,root,root)
%{_libdir}/libwx_mgl*-%{ver2}*.so
%dir %{_includedir}/wx-*
%{_includedir}/wx-*/*
%dir %{_libdir}/wx
%{_libdir}/wx/*
%{_bindir}/wxmgl*-config
%{_datadir}/aclocal/*.m4

%files static
%defattr (-,root,root)
%{_libdir}/lib*.a
