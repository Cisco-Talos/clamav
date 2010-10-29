/////////////////////////////////////////////////////////////////////////////
// Name:        fontencoding.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_fontencoding Font Encodings

wxWidgets has support for multiple font encodings.

By encoding we mean here the mapping between the character codes and the
letters. Probably the most well-known encoding is (7 bit) ASCII one which is
used almost universally now to represent the letters of the English alphabet
and some other common characters. However, it is not enough to represent the
letters of foreign alphabets and here other encodings come into play. Please
note that we will only discuss 8-bit fonts here and not Unicode
(see @ref overview_unicode).

Font encoding support is ensured by several classes:
wxFont itself, but also wxFontEnumerator and wxFontMapper. wxFont encoding
support is reflected by a (new) constructor parameter @e encoding which takes
one of the following values (elements of enumeration type @c wxFontEncoding):

@beginDefList
@itemdef{wxFONTENCODING_SYSTEM,
        The default encoding of the underlying
        operating system (notice that this might be a "foreign" encoding for foreign
        versions of Windows 9x/NT).}
@itemdef{wxFONTENCODING_DEFAULT,
        The applications default encoding as returned by wxFont::GetDefaultEncoding.
        On program startup, the applications default encoding is the same as
        wxFONTENCODING_SYSTEM, but may be changed to make all the fonts created later
        to use it (by default).}
@itemdef{wxFONTENCODING_ISO8859_1..15,
        ISO8859 family encodings which are
        usually used by all non-Microsoft operating systems.}
@itemdef{wxFONTENCODING_KOI8,
        Standard Cyrillic encoding for the Internet
        (but see also wxFONTENCODING_ISO8859_5 and wxFONTENCODING_CP1251).}
@itemdef{wxFONTENCODING_CP1250, Microsoft analogue of ISO8859-2}
@itemdef{wxFONTENCODING_CP1251, Microsoft analogue of ISO8859-5}
@itemdef{wxFONTENCODING_CP1252, Microsoft analogue of ISO8859-1}
@endDefList

As you may see, Microsoft's encoding partly mirror the standard ISO8859 ones,
but there are (minor) differences even between ISO8859-1 (Latin1, ISO encoding
for Western Europe) and CP1251 (WinLatin1, standard code page for English
versions of Windows) and there are more of them for other encodings.

The situation is particularly complicated with Cyrillic encodings for which
(more than) three incompatible encodings exist: KOI8 (the old standard, widely
used on the Internet), ISO8859-5 (ISO standard for Cyrillic) and CP1251
(WinCyrillic).

This abundance of (incompatible) encodings should make it clear that using
encodings is less easy than it might seem. The problems arise both from the
fact that the standard encodings for the given language (say Russian, which is
written in Cyrillic) are different on different platforms and because the
fonts in the given encoding might just not be installed (this is especially a
problem with Unix, or, in general, non-Win32 systems).

To clarify, the wxFontEnumerator
class may be used to enumerate both all available encodings and to find the
facename(s) in which the given encoding exists. If you can find the font in
the correct encoding with wxFontEnumerator then your troubles are over, but,
unfortunately, sometimes this is not enough. For example, there is no standard
way (that I know of, please tell me if you do!) to find a font on a Windows system
for KOI8 encoding (only for WinCyrillic one which is quite different), so
wxFontEnumerator will never return one, even if the user has installed a KOI8
font on his system.

To solve this problem, a wxFontMapper class is provided.

This class stores the mapping between the encodings and the font face
names which support them in wxConfigBase object. 
Of course, it would be fairly useless if it tried to determine these mappings by
itself, so, instead, it (optionally) asks the user and remembers his answers
so that the next time the program will automatically choose the correct font.
All these topics are illustrated by the @ref page_samples_font;
please refer to it and the documentation of the classes mentioned here for
further explanations.

*/

