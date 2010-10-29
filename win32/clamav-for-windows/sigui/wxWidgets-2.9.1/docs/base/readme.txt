                                wxBase README
                                =============

NB: this file applies to wxBase library only. If you are using a GUI version
    of wxWidgets, please refer to the documentation in the appropriate
    subdirectory (msw, gtk, motif &c).


 Welcome to wxBase!

0. Introduction
---------------

 wxBase is the library providing most of the non-GUI classes of the wxWidgets
cross-platform C++ framework. wxBase has some generic classes such as yet
another C++ string class, typesafe dynamic arrays, hashes and lists and, more
excitingly, wxDateTime -- a very flexible and powerful class for manipulating
the dates in the range of 580 million years with up to millisecond precision.
Another useful class not present in the standard C++ library is wxRegEx which
allows you to use regular expressions for string matching and replacing.

 There are also classes for writing portable programs in C++ painlessly which
encapsulate things like files (and their names), directories, processes,
threads, sockets and much more. Some of the other utility classes allow you to
parse the command line, limit the number of instances of your program
executing simultaneously (portably!) and so on.


1. Requirements and supported platforms
--------------------------------------

 wxBase can be compiled and used under Win32, mostly any modern Unix system
(including Mac OS X), VMS and BeOS (this release couldn't be tested under
these platforms so you might encounter some problems but they should be easy
to solve -- please contact us in this case!)

 It is written without using any modern C++ features (such as templates,
exceptions, namespaces) for maximal portability and so you shouldn't have
problems compiling it with any C++ compiler at all. However, we only provide
the project files for Microsoft Visual C++ 6.0 and make files for Borland C++
for Win32 (any contributions are welcome!) -- but our Unix makefiles should
work with any compiler.


2. Installing under Win32
-------------------------

Please note that wxBase can be compiled in different configurations under
Win32: as a static or shared library, in debug or release mode and in ANSI
or Unicode mode for a total of 8 possibilities.

a) Using Visual C++ 6.0

   Simply open the build/msw/wx_base.dsp file in MSDEV and build it. When it is
done you can also open samples/console/console.dsp project and build it as
well.

b) Cygwin

   Please refer to the Unix section below.

   Note that gcc's precompiled headers do not work on current versions of
   Cygwin. If your version of Cygwin is affected you will need to use the
   --disable-precomp-headers configure option.

c) Borland

   Please refer to the docs/msw/install.txt. The console sample compiles and
   runs but does not pass all tests.

d) Watcom

   The compilation has been tested only with OpenWatcom but should also work
   with Watcom 11.0 but probably not the earlier versions.

   To build wxBase itself (only static library build is supported), enter the
   directory src\msw and type "wmake -f makebase.wat". See also Watcom notes in
   docs/msw/install.txt.

   There is makefile.wat in samples\console which can be used to build the
   console sample with Watcom and also shows how can you write your own
   makefiles for wxBase and Watcom compiler.

e) Other compilers

   Unfortunately we don't have the makefiles for any other compilers yet.
Please contact us if you would like to help us with creating one for the
compiler you use.


3. Installing under Unix/BeOS
-----------------------------

Please note that GNU make may be required to build wxBase, please use it if
you get any errors from the native Unix make.

The recommended way to build wxBase is:

        % cd ..../wxWidgets
        % mkdir base-release # or any other directory of your liking
        % cd base-release
        % ../configure --disable-gui
        # ignore the error messages about missing samples
        % make
        % make install

You can also do:

        % mkdir base-debug
        % cd base-debug
        % ../configure --disable-gui --enable-debug
        % make

To build the sample then cd to samples/console and make there.


4. Documentation and support
----------------------------

 The console sample provided with this distribution tests most (but not all)
wxBase classes. It doesn't do anything useful per itself but you may want to
look at its code to see examples of usage of the class you are interested in.

 There is no separate documentation for wxBase, please refer to wxWidgets
documentation instead.

 Support for wxBase is available from the same places as for wxWidgets itself,
namely:

* Usenet newsgroup comp.soft-sys.wxwindows

* Mailing lists: see http://lists.wxwidgets.org/ for more information

* WWW page: http://www.wxwidgets.org/


 Hope you will find wxBase useful!

                                                                 Vadim Zeitlin
