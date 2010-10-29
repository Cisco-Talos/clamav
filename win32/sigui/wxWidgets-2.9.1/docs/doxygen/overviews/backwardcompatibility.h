/////////////////////////////////////////////////////////////////////////////
// Name:        backwardcompatibility.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_backwardcompat Backwards Compatibility

Many of the GUIs and platforms supported by wxWidgets are continuously
evolving, and some of the new platforms wxWidgets now supports were quite
unimaginable even a few years ago. In this environment wxWidgets must also
evolve in order to support these new features and platforms.

However the goal of wxWidgets is not only to provide a consistent programming
interface across many platforms, but also to provide an interface that is
reasonably stable over time, to help protect its users from some of the
uncertainty of the future.

@li @ref overview_backwardcompat_versionnumbering
@li @ref overview_backwardcompat_sourcecompat
@li @ref overview_backwardcompat_libbincompat
@li @ref overview_backwardcompat_appbincompat


<hr>


@section overview_backwardcompat_versionnumbering The Version Numbering Scheme

wxWidgets version numbers can have up to four components, with trailing zeros
sometimes omitted:

@verbatim
major.minor.release.sub-release
@endverbatim

A stable release of wxWidgets will have an even number for @e minor, e.g.
2.6.0. Stable, in this context, means that the API is not changing. In truth,
some changes are permitted, but only those that are backward compatible. For
example, you can expect later 2.6.x releases, such as 2.6.1 and 2.6.2 to be
backward compatible with their predecessor.

When it becomes necessary to make changes which are not wholly backward
compatible, the stable branch is forked, creating a new development branch of
wxWidgets. This development branch will have an odd number for @e minor, for
example 2.7.x. Releases from this branch are known as development snapshots.

The stable branch and the development branch will then be developed in parallel
for some time. When it is no longer useful to continue developing the stable
branch, the development branch is renamed and becomes a new stable branch, for
example: 2.8.0. And the process begins again. This is how the tension between
keeping the interface stable, and allowing the library to evolve is managed.

You can expect the versions with the same major and even minor version number
to be compatible, but between minor versions there will be incompatibilities.
Compatibility is not broken gratuitously however, so many applications will
require no changes or only small changes to work with the new version.


@section overview_backwardcompat_sourcecompat Source Level Compatibility

Later releases from a stable branch are backward compatible with earlier
releases from the same branch at the source level. This means that, for
example, if you develop your application using wxWidgets 2.8.0 then it should
also compile fine with all later 2.8.x versions.

The converse is also true providing you avoid any new features not present in
the earlier version. For example if you develop using 2.6.1 your program will
compile fine with wxWidgets 2.8.0 providing you don't use any 2.8.1 specific
features.

For some platforms binary compatibility is also supported, see
@ref overview_backwardcompat_libbincompat below.

Between minor versions, for example between 2.4.x, 2.6.x and 2.8.x, there will
be some incompatibilities. Wherever possible the old way of doing something is
kept alongside the new for a time wrapped inside:

@code
#if WXWIN_COMPATIBILITY_2_6
    // deprecated feature
    ...
#endif
@endcode

By default the @c WXWIN_COMPATIBILITY_X_X macro is set to 1 for the previous
stable branch, for example in 2.8.x, @c WXWIN_COMPATIBILITY_2_6 = 1. For the
next earlier stable branch the default is 0, so @c WXWIN_COMPATIBILITY_2_4 = 0
for 2.8.x. Earlier than that, obsolete features are removed.

These macros can be changed in @c setup.h. Or on UNIX-like systems you can set
them using the @c --disable-compat26 and @c --enable-compat24 options to
configure.

They can be useful in two ways:

@li Changing @c WXWIN_COMPATIBILITY_2_6 to 0 can be useful to find uses of
    deprecated features in your program that should eventually be removed.
@li Changing @c WXWIN_COMPATIBILITY_2_4 to 1 can be useful to compile a program
    developed using 2.4.x that no longer compiles with 2.8.x.

A program requiring one of these macros to be 1 will become incompatible with
some future version of wxWidgets, and you should consider updating it.


@section overview_backwardcompat_libbincompat Library Binary Compatibility

For some platforms, releases from a stable branch are not only source level
compatible but can also be binary compatible.

Binary compatibility makes it possible to get the maximum benefit from using
shared libraries, also known as dynamic link libraries (DLLs) on Windows or
dynamic shared libraries on OS X.

For example, suppose several applications are installed on a system requiring
wxWidgets 2.6.0, 2.6.1 and 2.6.2. Since 2.6.2 is backward compatible with the
earlier versions, it should be enough to install just wxWidgets 2.6.2 shared
libraries, and all the applications should be able to use them. If binary
compatibility is not supported, then all the required versions 2.6.0, 2.6.1 and
2.6.2 must be installed side by side.

Achieving this, without the user being required to have the source code and
recompile everything, places many extra constraints on the changes that can be
made within the stable branch. So it is not supported for all platforms, and
not for all versions of wxWidgets. To date it has mainly been supported by
wxGTK for UNIX-like platforms.

Another practical consideration is that for binary compatibility to work, all
the applications and libraries must have been compiled with compilers that are
capable of producing compatible code; that is, they must use the same ABI
(Application Binary Interface). Unfortunately most different C++ compilers do
not produce code compatible with each other, and often even different versions
of the same compiler are not compatible.


@section overview_backwardcompat_appbincompat Application Binary Compatibility

The most important aspect of binary compatibility is that applications compiled
with one version of wxWidgets, e.g. 2.6.1, continue to work with shared
libraries of a later binary compatible version, for example 2.6.2. The converse
can also be useful however. That is, it can be useful for a developer using a
later version, e.g. 2.6.2 to be able to create binary application packages that
will work with all binary compatible versions of the shared library starting
with, for example 2.6.0.

To do this the developer must, of course, avoid any features not available in
the earlier versions. However this is not necessarily enough; in some cases an
application compiled with a later version may depend on it even though the same
code would compile fine against an earlier version.

To help with this, a preprocessor symbol @c wxABI_VERSION can be defined during
the compilation of the application (this would usually be done in the
application's makefile or project settings). It should be set to the lowest
version that is being targeted, as a number with two decimal digits for each
component, for example @c wxABI_VERSION=20600 for 2.6.0.

Setting @c wxABI_VERSION should prevent the application from implicitly
depending on a later version of wxWidgets, and also disables any new features
in the API, giving a compile time check that the source is compatible with the
versions of wxWidgets being targeted.

Uses of @c wxABI_VERSION are stripped out of the wxWidgets sources when each
new development branch is created. Therefore it is only useful to help achieve
compatibility with earlier versions with the same major and even minor version
numbers. It won't, for example, help you write code compatible with 2.6.x using
wxWidgets 2.8.x.

*/

