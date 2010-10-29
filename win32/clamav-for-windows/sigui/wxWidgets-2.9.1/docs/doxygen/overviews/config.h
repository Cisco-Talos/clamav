/////////////////////////////////////////////////////////////////////////////
// Name:        config.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_config wxConfig Overview

Classes: wxConfigBase

This overview briefly describes what the config classes are and what they are
for. All the details about how to use them may be found in the description of
the wxConfigBase class and the documentation of the file, registry and INI file
based implementations mentions all the features/limitations specific to each
one of these versions.

The config classes provide a way to store some application configuration
information. They were especially designed for this usage and, although may
probably be used for many other things as well, should be limited to it. It
means that this information should be:

@li Typed, i.e. strings or numbers for the moment. You can not store binary
    data, for example.
@li Small. For instance, it is not recommended to use the Windows registry for
    amounts of data more than a couple of kilobytes.
@li Not performance critical, neither from speed nor from a memory consumption
    point of view.

On the other hand, the features provided make them very useful for storing all
kinds of small to medium volumes of hierarchically-organized, heterogeneous
data. In short, this is a place where you can conveniently stuff all your data
(numbers and strings) organizing it in a tree where you use the filesystem-like
paths to specify the location of a piece of data. In particular, these classes
were designed to be as easy to use as possible.

From another point of view, they provide an interface which hides the
differences between the Windows registry and the standard Unix text format
configuration files. Other (future) implementations of wxConfigBase might also
understand GTK resource files or their analogues on the KDE side.

In any case, each implementation of wxConfigBase does its best to make the data
look the same way everywhere. Due to limitations of the underlying physical
storage, it may not implement 100% of the base class functionality.

There are groups of entries and the entries themselves. Each entry contains
either a string or a number (or a boolean value; support for other types of
data such as dates or timestamps is planned) and is identified by the full path
to it: something like @c /MyApp/UserPreferences/Colors/Foreground.

The previous elements in the path are the group names, and each name may
contain an arbitrary number of entries and subgroups.

The path components are @e always separated with a slash, even though some
implementations use the backslash internally. Further details (including how to
read/write these entries) may be found in the documentation for wxConfigBase.

*/

