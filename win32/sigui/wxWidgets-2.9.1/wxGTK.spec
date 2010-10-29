%define _prefix /usr
%define ver  2.9.1
%define ver2 2.9
%define rel  1

# Configurable settings (use --with(out) {unicode,gtk2} on rpmbuild cmd line):
%define unicode 1
%{?_with_unicode: %{expand: %%define unicode 1}}
%{?_without_unicode: %{expand: %%define unicode 0}}

%define gtk2 1
%{?_with_gtk2: %{expand: %%define gtk2 1}}
%{?_without_gtk2: %{expand: %%define gtk2 0}}

# "buildname" needs to be e.g. gtk2ud for debug builds
%if %{gtk2}
    %define gtkver 2
    %define portname gtk2
%if %{unicode}
    %define buildname gtk2u
%else
    %define buildname gtk2
%endif
%else
    %define gtkver 1.2
    %define portname gtk
    %define buildname gtk
%endif

%if %{unicode}
    %define name		wx-%{portname}-unicode
    %define wxconfig		%{portname}-unicode-release-%{ver2}
    %define wxconfigstatic	%{portname}-unicode-release-static-%{ver2}
    %define wxconfiglink	wx%{portname}u-%{ver2}-config
%else
    %define name		wx-%{portname}-ansi
    %define wxconfig		%{portname}-ansi-release-%{ver2}
    %define wxconfigstatic	%{portname}-ansi-release-static-%{ver2}
    %define wxconfiglink	wx%{portname}-%{ver2}-config
%endif

%if %{unicode}
    %define wxbasename		wx-base-unicode
    %define wxbaseconfig	base-unicode-release-%{ver2}
    %define wxbaseconfiglink	wxbaseu-%{ver2}-config
%else
    %define wxbasename		wx-base-ansi
    %define wxbaseconfig	base-ansi-release-%{ver2}
    %define wxbaseconfiglink	wxbase-%{ver2}-config
%endif

Summary: The GTK+ %{gtkver} port of the wxWidgets library
Name: %{name}
Version: %{ver}
Release: %{rel}
License: wxWindows Licence
Group: X11/Libraries
Source: wxGTK-%{ver}.tar.bz2
URL: http://www.wxwidgets.org
Packager: Vadim Zeitlin <vadim@wxwindows.org>
Prefix: %{_prefix}
BuildRoot: %{_tmppath}/%{name}-root
Requires: %{wxbasename} = %{ver}
%if %{portname} == gtk2
BuildRequires: gtk+-2.0-devel
%else
BuildRequires: gtk+-devel >= 1.2.0
%endif

BuildRequires: zlib-devel, libjpeg-devel, libpng-devel, libtiff-devel

# all packages providing an implementation of wxWidgets library (regardless of
# the toolkit used) should provide the (virtual) wxwin package, this makes it
# possible to require wxwin instead of requiring "wxgtk or wxmotif or wxuniv..."
Provides: wxwin
Provides: wxGTK

%description
wxWidgets is a free C++ library for cross-platform GUI development.
With wxWidgets, you can create applications for different GUIs (GTK+,
Motif, MS Windows, MacOS X, Windows CE, GPE) from the same source code.

%package -n wx-i18n
Summary: The translations for the wxWidgets library.
Group: X11/Libraries

%description -n wx-i18n
The translations files for the wxWidgets library.

%package devel
Summary: The GTK+ %{gtkver} port of the wxWidgets library
Group: X11/Libraries
Requires: %{name} = %{ver}
Requires: %{wxbasename}-devel = %{ver}
Provides: wxGTK-devel

%description devel
The GTK+ %{gtkver} port of the wxWidgets library, header files.

%package gl
Summary: The GTK+ %{gtkver} port of the wxWidgets library, OpenGL add-on.
Group: X11/Libraries
Requires: %{name} = %{ver}
Provides: wxGTK-gl

%description gl
OpenGL add-on library for wxGTK, the GTK+ %{gtkver} port of the wxWidgets library.

%package -n %{wxbasename}
Summary: wxBase library - non-GUI support classes of the wxWidgets toolkit
Group: Development/Libraries
Provides: wxBase

%description -n %{wxbasename}
wxBase is a collection of C++ classes providing basic data structures (strings,
lists, arrays), portable wrappers around many OS-specific funstions (file
operations, time/date manipulations, threads, processes, sockets, shared
library loading) as well as other utility classes (streams, archive and
compression). wxBase currently supports Win32, most Unix variants (Linux, 
FreeBSD, Solaris, HP-UX) and MacOS X (Carbon and Mach-0).

%package -n %{wxbasename}-devel
Summary: wxBase library, header files.
Group: Development/Libraries
Provides: wxBase-devel

%description -n %{wxbasename}-devel
wxBase library - non-GUI support classes of the wxWidgets toolkit,
header files.

%package contrib
Summary: The GTK+ %{gtkver} port of the wxWidgets library, contributed libraries.
Group: X11/Libraries
Requires: %{name} = %{ver}

%description contrib
Contributed libraries for wxGTK, the GTK+ %{gtkver} port of the wxWidgets library.

%package contrib-devel
Summary: The GTK+ %{gtkver} port of the wxWidgets library
Group: X11/Libraries
Requires: %{name}-contrib = %{ver}
Requires: %{name}-devel = %{ver}

%description contrib-devel
Header files for contributed libraries for wxGTK, the GTK+ %{gtkver} port of the wxWidgets library.

%prep
%setup -q -n wxGTK-%{ver}

%build
if [ "$SMP" != "" ]; then
    export MAKE="make -j$SMP"
else
    export MAKE="make"
fi

mkdir obj-shared
cd obj-shared
../configure --prefix=%{_prefix} \
%if ! %{gtk2}
			      --with-gtk=1 \
%else
			      --with-gtk=2 \
%endif
%if %{unicode}
			      --enable-unicode \
%else
			      --disable-unicode \
%endif
			      --with-opengl
$MAKE

cd contrib/src
$MAKE
cd ../../..

mkdir obj-static
cd obj-static
../configure --prefix=%{_prefix} \
%if ! %{gtk2}
			      --with-gtk=1 \
%else
			      --with-gtk=2 \
%endif
			      --disable-shared \
%if %{unicode}
			      --enable-unicode \
%else
			      --disable-unicode \
%endif
			      --with-opengl
$MAKE

cd contrib/src
$MAKE
cd ../../..

make -C locale allmo

%install
rm -rf $RPM_BUILD_ROOT
(cd obj-static; make DESTDIR=$RPM_BUILD_ROOT prefix=%{_prefix} install)
(cd obj-shared; make DESTDIR=$RPM_BUILD_ROOT prefix=%{_prefix} install)

# --- wxBase headers list begins here ---
cat <<EOF >wxbase-headers.files
wx/afterstd.h
wx/any.h
wx/anystr.h
wx/app.h
wx/apptrait.h
wx/archive.h
wx/arrimpl.cpp
wx/arrstr.h
wx/atomic.h
wx/base64.h
wx/beforestd.h
wx/buffer.h
wx/build.h
wx/chartype.h
wx/checkeddelete.h
wx/chkconf.h
wx/clntdata.h
wx/cmdargs.h
wx/cmdline.h
wx/confbase.h
wx/config.h
wx/convauto.h
wx/containr.h
wx/cpp.h
wx/crt.h
wx/datetime.h
wx/datstrm.h
wx/dde.h
wx/debug.h
wx/defs.h
wx/dir.h
wx/dlimpexp.h
wx/dlist.h
wx/dynarray.h
wx/dynlib.h
wx/dynload.h
wx/encconv.h
wx/event.h
wx/evtloop.h
wx/except.h
wx/features.h
wx/flags.h
wx/ffile.h
wx/file.h
wx/fileconf.h
wx/filefn.h
wx/filename.h
wx/filesys.h
wx/fontenc.h
wx/fontmap.h
wx/fs_arc.h
wx/fs_filter.h
wx/fs_mem.h
wx/fs_zip.h
wx/hash.h
wx/hashmap.h
wx/hashset.h
wx/html/forcelnk.h
wx/iconloc.h
wx/init.h
wx/intl.h
wx/iosfwrap.h
wx/ioswrap.h
wx/ipc.h
wx/ipcbase.h
wx/kbdstate.h
wx/language.h
wx/link.h
wx/list.h
wx/listimpl.cpp
wx/log.h
wx/longlong.h
wx/math.h
wx/memconf.h
wx/memory.h
wx/memtext.h
wx/mimetype.h
wx/module.h
wx/mousestate.h
wx/msgout.h
wx/msgqueue.h
wx/mstream.h
wx/object.h
wx/platform.h
wx/platinfo.h
wx/power.h
wx/process.h
wx/ptr_scpd.h
wx/ptr_shrd.h
wx/recguard.h
wx/regex.h
wx/scopedarray.h
wx/scopedptr.h
wx/scopeguard.h
wx/sharedptr.h
wx/snglinst.h
wx/sstream.h
wx/stack.h
wx/stackwalk.h
wx/stdpaths.h
wx/stdstream.h
wx/stockitem.h
wx/stopwatch.h
wx/strconv.h
wx/stream.h
wx/string.h
wx/stringimpl.h
wx/stringops.h
wx/strvararg.h
wx/sysopt.h
wx/tarstrm.h
wx/textbuf.h
wx/textfile.h
wx/thread.h
wx/thrimpl.cpp
wx/timer.h
wx/tls.h
wx/tokenzr.h
wx/tracker.h
wx/translation.h
wx/txtstrm.h
wx/typeinfo.h
wx/types.h
wx/unichar.h
wx/uri.h
wx/ustring.h
wx/utils.h
wx/variant.h
wx/vector.h
wx/version.h
wx/volume.h
wx/weakref.h
wx/wfstream.h
wx/wx.h
wx/wxchar.h
wx/wxcrt.h
wx/wxcrtbase.h
wx/wxcrtvararg.h
wx/wxprec.h
wx/xlocale.h
wx/xti.h
wx/xtistrm.h
wx/zipstrm.h
wx/zstream.h
wx/meta/convertible.h
wx/meta/if.h
wx/meta/int2type.h
wx/meta/movable.h
wx/meta/pod.h
wx/fswatcher.h
wx/generic/fswatcher.h
wx/unix/app.h
wx/unix/apptbase.h
wx/unix/apptrait.h
wx/unix/chkconf.h
wx/unix/evtloop.h
wx/unix/evtloopsrc.h
wx/unix/pipe.h
wx/unix/stdpaths.h
wx/unix/stackwalk.h
wx/unix/tls.h
wx/unix/fswatcher_kqueue.h
wx/unix/execute.h
wx/unix/mimetype.h
wx/unix/fswatcher_inotify.h
wx/fs_inet.h
wx/protocol/file.h
wx/protocol/ftp.h
wx/protocol/http.h
wx/protocol/log.h
wx/protocol/protocol.h
wx/sckaddr.h
wx/sckipc.h
wx/sckstrm.h
wx/socket.h
wx/url.h
wx/xml/xml.h
wx/xtixml.h
EOF
# --- wxBase headers list ends here ---
cat <<EOF >wxbase-headers.paths
%{_includedir}/wx-%{ver2}/wx/afterstd.h
%{_includedir}/wx-%{ver2}/wx/app.h
%{_includedir}/wx-%{ver2}/wx/apptrait.h
%{_includedir}/wx-%{ver2}/wx/archive.h
%{_includedir}/wx-%{ver2}/wx/arrimpl.cpp
%{_includedir}/wx-%{ver2}/wx/arrstr.h
%{_includedir}/wx-%{ver2}/wx/beforestd.h
%{_includedir}/wx-%{ver2}/wx/buffer.h
%{_includedir}/wx-%{ver2}/wx/build.h
%{_includedir}/wx-%{ver2}/wx/chkconf.h
%{_includedir}/wx-%{ver2}/wx/clntdata.h
%{_includedir}/wx-%{ver2}/wx/cmdline.h
%{_includedir}/wx-%{ver2}/wx/confbase.h
%{_includedir}/wx-%{ver2}/wx/config.h
%{_includedir}/wx-%{ver2}/wx/containr.h
%{_includedir}/wx-%{ver2}/wx/convauto.h
%{_includedir}/wx-%{ver2}/wx/datetime.h
%{_includedir}/wx-%{ver2}/wx/datstrm.h
%{_includedir}/wx-%{ver2}/wx/dde.h
%{_includedir}/wx-%{ver2}/wx/debug.h
%{_includedir}/wx-%{ver2}/wx/defs.h
%{_includedir}/wx-%{ver2}/wx/dir.h
%{_includedir}/wx-%{ver2}/wx/dlimpexp.h
%{_includedir}/wx-%{ver2}/wx/dynarray.h
%{_includedir}/wx-%{ver2}/wx/dynlib.h
%{_includedir}/wx-%{ver2}/wx/dynload.h
%{_includedir}/wx-%{ver2}/wx/encconv.h
%{_includedir}/wx-%{ver2}/wx/event.h
%{_includedir}/wx-%{ver2}/wx/except.h
%{_includedir}/wx-%{ver2}/wx/features.h
%{_includedir}/wx-%{ver2}/wx/ffile.h
%{_includedir}/wx-%{ver2}/wx/file.h
%{_includedir}/wx-%{ver2}/wx/fileconf.h
%{_includedir}/wx-%{ver2}/wx/filefn.h
%{_includedir}/wx-%{ver2}/wx/filename.h
%{_includedir}/wx-%{ver2}/wx/filesys.h
%{_includedir}/wx-%{ver2}/wx/fontenc.h
%{_includedir}/wx-%{ver2}/wx/fontmap.h
%{_includedir}/wx-%{ver2}/wx/fs_mem.h
%{_includedir}/wx-%{ver2}/wx/fs_zip.h
%{_includedir}/wx-%{ver2}/wx/hash.h
%{_includedir}/wx-%{ver2}/wx/hashmap.h
%{_includedir}/wx-%{ver2}/wx/hashset.h
%{_includedir}/wx-%{ver2}/wx/html/forcelnk.h
%{_includedir}/wx-%{ver2}/wx/iconloc.h
%{_includedir}/wx-%{ver2}/wx/init.h
%{_includedir}/wx-%{ver2}/wx/intl.h
%{_includedir}/wx-%{ver2}/wx/iosfwrap.h
%{_includedir}/wx-%{ver2}/wx/ioswrap.h
%{_includedir}/wx-%{ver2}/wx/ipc.h
%{_includedir}/wx-%{ver2}/wx/ipcbase.h
%{_includedir}/wx-%{ver2}/wx/isql.h
%{_includedir}/wx-%{ver2}/wx/isqlext.h
%{_includedir}/wx-%{ver2}/wx/link.h
%{_includedir}/wx-%{ver2}/wx/list.h
%{_includedir}/wx-%{ver2}/wx/listimpl.cpp
%{_includedir}/wx-%{ver2}/wx/log.h
%{_includedir}/wx-%{ver2}/wx/longlong.h
%{_includedir}/wx-%{ver2}/wx/math.h
%{_includedir}/wx-%{ver2}/wx/memconf.h
%{_includedir}/wx-%{ver2}/wx/memory.h
%{_includedir}/wx-%{ver2}/wx/memtext.h
%{_includedir}/wx-%{ver2}/wx/mimetype.h
%{_includedir}/wx-%{ver2}/wx/module.h
%{_includedir}/wx-%{ver2}/wx/msgout.h
%{_includedir}/wx-%{ver2}/wx/mstream.h
%{_includedir}/wx-%{ver2}/wx/object.h
%{_includedir}/wx-%{ver2}/wx/platform.h
%{_includedir}/wx-%{ver2}/wx/power.h
%{_includedir}/wx-%{ver2}/wx/process.h
%{_includedir}/wx-%{ver2}/wx/ptr_scpd.h
%{_includedir}/wx-%{ver2}/wx/recguard.h
%{_includedir}/wx-%{ver2}/wx/regex.h
%{_includedir}/wx-%{ver2}/wx/scopeguard.h
%{_includedir}/wx-%{ver2}/wx/snglinst.h
%{_includedir}/wx-%{ver2}/wx/sstream.h
%{_includedir}/wx-%{ver2}/wx/stack.h
%{_includedir}/wx-%{ver2}/wx/stackwalk.h
%{_includedir}/wx-%{ver2}/wx/stdpaths.h
%{_includedir}/wx-%{ver2}/wx/stockitem.h
%{_includedir}/wx-%{ver2}/wx/stopwatch.h
%{_includedir}/wx-%{ver2}/wx/strconv.h
%{_includedir}/wx-%{ver2}/wx/stream.h
%{_includedir}/wx-%{ver2}/wx/string.h
%{_includedir}/wx-%{ver2}/wx/sysopt.h
%{_includedir}/wx-%{ver2}/wx/textbuf.h
%{_includedir}/wx-%{ver2}/wx/textfile.h
%{_includedir}/wx-%{ver2}/wx/thread.h
%{_includedir}/wx-%{ver2}/wx/thrimpl.cpp
%{_includedir}/wx-%{ver2}/wx/timer.h
%{_includedir}/wx-%{ver2}/wx/tokenzr.h
%{_includedir}/wx-%{ver2}/wx/txtstrm.h
%{_includedir}/wx-%{ver2}/wx/types.h
%{_includedir}/wx-%{ver2}/wx/uri.h
%{_includedir}/wx-%{ver2}/wx/utils.h
%{_includedir}/wx-%{ver2}/wx/variant.h
%{_includedir}/wx-%{ver2}/wx/vector.h
%{_includedir}/wx-%{ver2}/wx/version.h
%{_includedir}/wx-%{ver2}/wx/volume.h
%{_includedir}/wx-%{ver2}/wx/wfstream.h
%{_includedir}/wx-%{ver2}/wx/wx.h
%{_includedir}/wx-%{ver2}/wx/wxchar.h
%{_includedir}/wx-%{ver2}/wx/wxprec.h
%{_includedir}/wx-%{ver2}/wx/xti.h
%{_includedir}/wx-%{ver2}/wx/xtistrm.h
%{_includedir}/wx-%{ver2}/wx/zipstrm.h
%{_includedir}/wx-%{ver2}/wx/zstream.h
%{_includedir}/wx-%{ver2}/wx/fs_inet.h
%{_includedir}/wx-%{ver2}/wx/gsocket.h
%{_includedir}/wx-%{ver2}/wx/protocol/file.h
%{_includedir}/wx-%{ver2}/wx/protocol/ftp.h
%{_includedir}/wx-%{ver2}/wx/protocol/http.h
%{_includedir}/wx-%{ver2}/wx/protocol/protocol.h
%{_includedir}/wx-%{ver2}/wx/sckaddr.h
%{_includedir}/wx-%{ver2}/wx/sckipc.h
%{_includedir}/wx-%{ver2}/wx/sckstrm.h
%{_includedir}/wx-%{ver2}/wx/socket.h
%{_includedir}/wx-%{ver2}/wx/url.h
%{_includedir}/wx-%{ver2}/wx/xml/xml.h
%{_includedir}/wx-%{ver2}/wx/xtixml.h
%{_includedir}/wx-%{ver2}/wx/unix/apptbase.h
%{_includedir}/wx-%{ver2}/wx/unix/apptrait.h
%{_includedir}/wx-%{ver2}/wx/unix/execute.h
%{_includedir}/wx-%{ver2}/wx/unix/gsockunx.h
%{_includedir}/wx-%{ver2}/wx/unix/mimetype.h
%{_includedir}/wx-%{ver2}/wx/unix/pipe.h
%{_includedir}/wx-%{ver2}/wx/unix/private.h
%{_includedir}/wx-%{ver2}/wx/unix/stackwalk.h
%{_includedir}/wx-%{ver2}/wx/unix/stdpaths.h
EOF
# --- wxBase headers list ends here ---

# temporarily remove base headers
mkdir $RPM_BUILD_ROOT/_save_dir
cp -r $RPM_BUILD_ROOT%{_includedir}/wx-%{ver2} $RPM_BUILD_ROOT/_save_dir
for f in `cat wxbase-headers.files` ; do
    rm -f $RPM_BUILD_ROOT%{_includedir}/wx-%{ver2}/$f
done
# list of all core headers:
find $RPM_BUILD_ROOT%{_includedir}/wx-%{ver2} -type f | sed -e "s,$RPM_BUILD_ROOT,,g" >core-headers.files
# move base headers (actually all headers) back again
cp -f -r $RPM_BUILD_ROOT/_save_dir/* $RPM_BUILD_ROOT%{_includedir}
rm -rf $RPM_BUILD_ROOT/_save_dir

# contrib stuff:
(cd obj-static/contrib; make DESTDIR=$RPM_BUILD_ROOT prefix=%{_prefix} install)
(cd obj-shared/contrib; make DESTDIR=$RPM_BUILD_ROOT prefix=%{_prefix} install)

# utils:
(cd obj-shared/utils/wxrc; make DESTDIR=$RPM_BUILD_ROOT prefix=%{_prefix} install)

# wx-config link is created during package installation, remove it for now
rm -f $RPM_BUILD_ROOT%{_bindir}/wx-config

%clean
rm -rf $RPM_BUILD_ROOT

%post
/sbin/ldconfig

%postun
/sbin/ldconfig

%post devel
# link wx-config when you install RPM.
%if %{unicode}
    ln -sf %{_libdir}/wx/config/%{wxconfig} %{_bindir}/wx-config
%endif
# link wx-config with explicit name.
ln -sf %{_libdir}/wx/config/%{wxconfig} %{_bindir}/%{wxconfiglink}
/sbin/ldconfig

%postun devel
/sbin/ldconfig

%preun devel
%if %{unicode}
    rm -f %{_bindir}/wx-config
%endif
rm -f %{_bindir}/%{wxconfiglink}

%post -n %{wxbasename}
/sbin/ldconfig

%postun -n %{wxbasename}
/sbin/ldconfig

%post -n %{wxbasename}-devel
# link wx-config with explicit name.
ln -sf %{_libdir}/wx/config/%{wxbaseconfig} %{_bindir}/%{wxbaseconfiglink}
/sbin/ldconfig

%postun  -n %{wxbasename}-devel
/sbin/ldconfig

%preun  -n %{wxbasename}-devel
rm -f %{_bindir}/%{wxbaseconfiglink}

%post gl
/sbin/ldconfig

%postun gl
/sbin/ldconfig

%post contrib
/sbin/ldconfig

%postun contrib
/sbin/ldconfig

%post contrib-devel
/sbin/ldconfig

%postun contrib-devel
/sbin/ldconfig

%files
%defattr(-,root,root)
%doc COPYING.LIB *.txt
%{_libdir}/libwx_%{buildname}_adv-%{ver2}.so.*
%{_libdir}/libwx_%{buildname}_aui-%{ver2}.so.*
%{_libdir}/libwx_%{buildname}_core-%{ver2}.so.*
%{_libdir}/libwx_%{buildname}_html-%{ver2}.so.*
%{_libdir}/libwx_%{buildname}_mmedia-%{ver2}.so.*
%{_libdir}/libwx_%{buildname}_qa-%{ver2}.so.*
%{_libdir}/libwx_%{buildname}_richtext-%{ver2}.so.*
%{_libdir}/libwx_%{buildname}_xrc-%{ver2}.so.*

%files -n wx-i18n
%defattr(-,root,root)
%{_datadir}/locale/*/LC_MESSAGES/*.mo

%files devel -f core-headers.files
%defattr(-,root,root)
# shared libs
%{_libdir}/libwx_%{buildname}_adv-%{ver2}.so
%{_libdir}/libwx_%{buildname}_aui-%{ver2}.so
%{_libdir}/libwx_%{buildname}_core-%{ver2}.so
%{_libdir}/libwx_%{buildname}_gl-%{ver2}.so
%{_libdir}/libwx_%{buildname}_html-%{ver2}.so
%{_libdir}/libwx_%{buildname}_mmedia-%{ver2}.so
%{_libdir}/libwx_%{buildname}_qa-%{ver2}.so
%{_libdir}/libwx_%{buildname}_richtext-%{ver2}.so
%{_libdir}/libwx_%{buildname}_xrc-%{ver2}.so
# static libs
%{_libdir}/libwx_%{buildname}_adv-%{ver2}.a
%{_libdir}/libwx_%{buildname}_aui-%{ver2}.a
%{_libdir}/libwx_%{buildname}_core-%{ver2}.a
%{_libdir}/libwx_%{buildname}_gl-%{ver2}.a
%{_libdir}/libwx_%{buildname}_html-%{ver2}.a
%{_libdir}/libwx_%{buildname}_qa-%{ver2}.a
%{_libdir}/libwx_%{buildname}_richtext-%{ver2}.a
%{_libdir}/libwx_%{buildname}_xrc-%{ver2}.a
%dir %{_libdir}/wx
%{_libdir}/wx/config/%{wxconfig}
%{_libdir}/wx/include/%{wxconfig}/wx/setup.h
%{_libdir}/wx/config/%{wxconfigstatic}
%{_libdir}/wx/include/%{wxconfigstatic}/wx/setup.h
%{_bindir}/wxrc*

%files -n %{wxbasename}
%defattr(-,root,root)
%{_libdir}/libwx_base*-%{ver2}.so.*

%files -n %{wxbasename}-devel -f wxbase-headers.paths
%defattr (-,root,root)
%dir %{_includedir}/wx-%{ver2}
%{_libdir}/libwx_base*-%{ver2}.so
%{_libdir}/libwx_base*-%{ver2}.a
%if %{unicode}
    %{_libdir}/libwxregexu-%{ver2}.a
%endif
%dir %{_libdir}/wx
%{_datadir}/aclocal/*.m4
%{_datadir}/bakefile/presets/*

%files gl
%defattr(-,root,root)
%{_libdir}/libwx_%{buildname}_gl-%{ver2}.so.*

%files contrib
%defattr(-,root,root)
%{_libdir}/libwx_%{buildname}_animate-%{ver2}.so.*
%{_libdir}/libwx_%{buildname}_deprecated-%{ver2}.so.*
%{_libdir}/libwx_%{buildname}_fl-%{ver2}.so.*
%{_libdir}/libwx_%{buildname}_gizmos-%{ver2}.so.*
%{_libdir}/libwx_%{buildname}_gizmos_xrc-%{ver2}.so.*
%{_libdir}/libwx_%{buildname}_mmedia-%{ver2}.so.*
%{_libdir}/libwx_%{buildname}_ogl-%{ver2}.so.*
%{_libdir}/libwx_%{buildname}_plot-%{ver2}.so.*
%{_libdir}/libwx_%{buildname}_stc-%{ver2}.so.*
%{_libdir}/libwx_%{buildname}_svg-%{ver2}.so.*

# static libs
%{_libdir}/libwx_%{buildname}_animate-%{ver2}.a
%{_libdir}/libwx_%{buildname}_deprecated-%{ver2}.a
%{_libdir}/libwx_%{buildname}_fl-%{ver2}.a
%{_libdir}/libwx_%{buildname}_gizmos-%{ver2}.a
%{_libdir}/libwx_%{buildname}_gizmos_xrc-%{ver2}.a
%{_libdir}/libwx_%{buildname}_mmedia-%{ver2}.a
%{_libdir}/libwx_%{buildname}_ogl-%{ver2}.a
%{_libdir}/libwx_%{buildname}_plot-%{ver2}.a
%{_libdir}/libwx_%{buildname}_stc-%{ver2}.a
%{_libdir}/libwx_%{buildname}_svg-%{ver2}.a

%files contrib-devel
%defattr(-,root,root)
%dir %{_includedir}/wx-%{ver2}/wx/animate
%{_includedir}/wx-%{ver2}/wx/animate/*
%{_libdir}/libwx_%{buildname}_animate-%{ver2}.so

%dir %{_includedir}/wx-%{ver2}/wx/deprecated
%{_includedir}/wx-%{ver2}/wx/deprecated/*
%{_libdir}/libwx_%{buildname}_deprecated-%{ver2}.so

%dir %{_includedir}/wx-%{ver2}/wx/fl
%{_includedir}/wx-%{ver2}/wx/fl/*
%{_libdir}/libwx_%{buildname}_fl-%{ver2}.so

%dir %{_includedir}/wx-%{ver2}/wx/gizmos
%{_includedir}/wx-%{ver2}/wx/gizmos/*
%{_libdir}/libwx_%{buildname}_gizmos-%{ver2}.so
%{_libdir}/libwx_%{buildname}_gizmos_xrc-%{ver2}.so

%dir %{_includedir}/wx-%{ver2}/wx/mmedia
%{_includedir}/wx-%{ver2}/wx/mmedia/*
%{_libdir}/libwx_%{buildname}_mmedia-%{ver2}.so

%dir %{_includedir}/wx-%{ver2}/wx/ogl
%{_includedir}/wx-%{ver2}/wx/ogl/*
%{_libdir}/libwx_%{buildname}_ogl-%{ver2}.so

%dir %{_includedir}/wx-%{ver2}/wx/plot
%{_includedir}/wx-%{ver2}/wx/plot/*
%{_libdir}/libwx_%{buildname}_plot-%{ver2}.so

%dir %{_includedir}/wx-%{ver2}/wx/stc
%{_includedir}/wx-%{ver2}/wx/stc/*
%{_libdir}/libwx_%{buildname}_stc-%{ver2}.so

%dir %{_includedir}/wx-%{ver2}/wx/svg
%{_includedir}/wx-%{ver2}/wx/svg/*
%{_libdir}/libwx_%{buildname}_svg-%{ver2}.so
