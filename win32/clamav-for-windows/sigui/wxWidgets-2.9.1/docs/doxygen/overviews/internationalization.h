/////////////////////////////////////////////////////////////////////////////
// Name:        internationalization.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_i18n Internationalization

@li @ref overview_i18n_intro
@li @ref overview_i18n_menuaccel

<hr>


@section overview_i18n_intro Introduction

Although internationalization of an application (i18n for short) involves far
more than just translating its text messages to another message - date, time
and currency formats need changing too, some languages are written left to
right and others right to left, character encoding may differ and many other
things may need changing too - it is a necessary first step. wxWidgets provides
facilities for message translation with it's wxLocale class and is itself fully
translated into several languages. Please consult wxWidgets home page for the
most up-to-date translations - and if you translate it into one of the
languages not done yet, your translations would be gratefully accepted for
inclusion into future versions of the library!

The wxWidgets approach to i18n closely follows the GNU gettext package.
wxWidgets uses the message catalogs which are binary compatible with gettext
catalogs and this allows to use all of the programs in this package to work
with them. But note that no additional libraries are needed during run-time,
however, so you have only the message catalogs to distribute and nothing else.

During program development you will need the gettext package for working with
message catalogs. @b Warning: gettext versions @< 0.10 are known to be buggy,
so you should find a later version of it!

There are two kinds of message catalogs: source catalogs which are text files
with extension .po and binary catalogs which are created from the source ones
with @e msgfmt program (part of gettext package) and have the extension .mo.
Only the binary files are needed during program execution.

Translating your application involves several steps:

@li Translating the strings in the program text using wxGetTranslation or
    equivalently the @c _() macro.
@li Extracting the strings to be translated from the program: this uses the
    work done in the previous step because @c xgettext program used for string
    extraction recognises the standard @c _() as well as (using its @c -k
    option) our wxGetTranslation and extracts all strings inside the calls to
    these functions. Alternatively, you may use @c -a option to extract all the
    strings, but it will usually result in many strings being found which don't
    have to be translated at all. This will create a text message catalog - a
    .po file.
@li Translating the strings extracted in the previous step to other
    language(s). It involves editing the .po file.
@li Compiling the .po file into .mo file to be used by the program.
@li Installing the .mo files with your application in the appropriate location
    for the target system which is the one returned by
    wxStandardPaths::GetLocalizedResourcesDir(
    wxStandardPaths::ResourceCat_Messages ). If the message catalogs are not
    installed in this default location you may explicitly use
    wxLocale::AddCatalogLookupPathPrefix() to still allow wxWidgets to find
    them but it is strongly recommended to use the default directory.
@li Setting the appropriate locale in your program to use the strings for the
    given language: see wxLocale.


@section overview_i18n_menuaccel Translating Menu Accelerators

If you translate the accelerator modifier names (Ctrl, Alt and Shift) in your
menu labels, you may find the accelerators no longer work. In your message
catalogs, you need to provide individual translations of these modifiers from
their lower case names (ctrl, alt, shift) so that the wxWidgets accelerator
code can recognise them even when translated. wxWidgets does not provide
translations for all of these currently. wxWidgets does not yet handle
translated special key names such as Backspace, End, Insert, etc.


@see
@li The gettext Manual: http://www.gnu.org/software/gettext/manual/gettext.html
@li @ref overview_nonenglish - It focuses on handling charsets related problems.
@li @ref page_samples_internat - Shows you how all this looks in practice.

*/

