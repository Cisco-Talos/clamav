/////////////////////////////////////////////////////////////////////////////
// Name:        nonenglish.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_nonenglish Writing Non-English Applications


@li @ref overview_nonenglish_locales
@li @ref overview_nonenglish_strings
@li @ref overview_nonenglish_fontmapping
@li @ref overview_nonenglish_converting
@li @ref overview_nonenglish_help


<hr>


This article describes how to write applications that communicate with the user
in a language other than English. Unfortunately many languages use different
charsets under Unix and Windows (and other platforms, to make the situation
even more complicated). These charsets usually differ in so many characters
that it is impossible to use the same texts under all platforms.

The wxWidgets library provides a mechanism that helps you avoid distributing
many identical, only differently encoded, packages with your application (e.g.
help files and menu items in iso8859-13 and windows-1257). Thanks to this
mechanism you can, for example, distribute only iso8859-13 data and it will be
handled transparently under all systems.

Please read the @ref overview_i18n which describes the locales concept.

In the following text, wherever @e iso8859-2 and @e windows-1250 are used, any
encodings are meant and any encodings may be substituted there.


@section overview_nonenglish_locales Locales

The best way to ensure correctly displayed texts in a GUI across platforms is
to use locales. Write your in-code messages in English or without diacritics
and put real messages into the message catalog (see @ref overview_i18n).

A standard .po file begins with a header like this:

@code
# SOME DESCRIPTIVE TITLE.
# Copyright (C) YEAR Free Software Foundation, Inc.
# FIRST AUTHOR <EMAIL@ADDRESS>, YEAR.
#
msgid ""
msgstr ""
"Project-Id-Version: PACKAGE VERSION\n"
"POT-Creation-Date: 1999-02-19 16:03+0100\n"
"PO-Revision-Date: YEAR-MO-DA HO:MI+ZONE\n"
"Last-Translator: FULL NAME <EMAIL@ADDRESS>\n"
"Language-Team: LANGUAGE <LL@li.org>\n"
"MIME-Version: 1.0\n"
"Content-Type: text/plain; charset=CHARSET\n"
"Content-Transfer-Encoding: ENCODING\n"
@endcode

Note this particular line:

@code
"Content-Type: text/plain; charset=CHARSET\n"
@endcode

It specifies the charset used by the catalog. All strings in the catalog are
encoded using this charset.

You have to fill in proper charset information. Your .po file may look like
this after doing so:

@code
# SOME DESCRIPTIVE TITLE.
# Copyright (C) YEAR Free Software Foundation, Inc.
# FIRST AUTHOR <EMAIL@ADDRESS>, YEAR.
#
msgid ""
msgstr ""
"Project-Id-Version: PACKAGE VERSION\n"
"POT-Creation-Date: 1999-02-19 16:03+0100\n"
"PO-Revision-Date: YEAR-MO-DA HO:MI+ZONE\n"
"Last-Translator: FULL NAME <EMAIL@ADDRESS>\n"
"Language-Team: LANGUAGE <LL@li.org>\n"
"MIME-Version: 1.0\n"
"Content-Type: text/plain; charset=iso8859-2\n"
"Content-Transfer-Encoding: 8bit\n"
@endcode

(Make sure that the header is @b not marked as @e fuzzy.)

wxWidgets is able to use this catalog under any supported platform
(although iso8859-2 is a Unix encoding and is normally not understood by
Windows).

How is this done? When you tell the wxLocale class to load a message catalog
that contains a correct header, it checks the charset. The catalog is then
converted to the charset used (see wxLocale::GetSystemEncoding and
wxLocale::GetSystemEncodingName) by the user's operating system.


@section overview_nonenglish_strings Non-English Strings or 8-bit Characters in Source

By convention, you should only use characters without diacritics (i.e. 7-bit
ASCII strings) for msgids in the source code and write them in English.

If you port software to wxWindows, you may be confronted with legacy source
code containing non-English string literals. Instead of translating the strings
in the source code to English and putting the original strings into message
catalog, you may configure wxWidgets to use non-English msgids and translate to
English using message catalogs:

@li If you use the program @c xgettext to extract the strings from the source
    code, specify the option <tt>--from-code=@<source code charset@></tt>.
@li Specify the source code language and charset as arguments to
    wxLocale::AddCatalog. For example:
    @code
    locale.AddCatalog(wxT("myapp"), wxLANGUAGE_GERMAN, wxT("iso-8859-1"));
    @endcode


@section overview_nonenglish_fontmapping Font Mapping

You can use @ref overview_mbconv and wxFontMapper to display text:

@code
if (!wxFontMapper::Get()->IsEncodingAvailable(enc, facename))
{
    wxFontEncoding alternative;
    if (wxFontMapper::Get()->GetAltForEncoding(enc, &alternative,
                                               facename, false))
    {
        wxCSConv convFrom(wxFontMapper::Get()->GetEncodingName(enc));
        wxCSConv convTo(wxFontMapper::Get()->GetEncodingName(alternative));
        text = wxString(text.mb_str(convFrom), convTo);
    }
    else
        ...failure (or we may try iso8859-1/7bit ASCII)...
}
...display text...
@endcode


@section overview_nonenglish_converting Converting Data

You may want to store all program data (created documents etc.) in the same
encoding, let's say @c utf-8. You can use wxCSConv to convert data to the
encoding used by the system your application is running on (see
wxLocale::GetSystemEncoding).


@section overview_nonenglish_help Help Files

If you're using wxHtmlHelpController there is no problem at all. You only need
to make sure that all the HTML files contain the META tag:

@code
<meta http-equiv="Content-Type" content="text/html; charset=iso8859-2">
@endcode

Also, the hhp project file needs one additional line in the @c OPTIONS section:

@code
Charset=iso8859-2
@endcode

This additional entry tells the HTML help controller what encoding is used in
contents and index tables.

*/

