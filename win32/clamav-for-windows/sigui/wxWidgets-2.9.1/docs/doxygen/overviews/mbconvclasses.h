/////////////////////////////////////////////////////////////////////////////
// Name:        mbconvclasses.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_mbconv wxMBConv Overview

Classes: wxMBConv, wxMBConvLibc, wxMBConvUTF7, wxMBConvUTF8, wxCSConv,
         wxMBConvUTF16, wxMBConvUTF32

The wxMBConv classes in wxWidgets enable an Unicode-aware application to easily
convert between Unicode and the variety of 8-bit encoding systems still in use.

@li @ref overview_mbconv_need
@li @ref overview_mbconv_string
@li @ref overview_mbconv_classes
@li @ref overview_mbconv_objects
@li @ref overview_mbconv_csconv
@li @ref overview_mbconv_converting
@li @ref overview_mbconv_buffers


<hr>


@section overview_mbconv_need Background: The Need for Conversion

As programs are becoming more and more globalized, and users exchange documents
across country boundaries as never before, applications increasingly need to
take into account all the different character sets in use around the world. It
is no longer enough to just depend on the default byte-sized character set that
computers have traditionally used.

A few years ago, a solution was proposed: the Unicode standard. Able to contain
the complete set of characters in use in one unified global coding system, it
would resolve the character set problems once and for all.

But it hasn't happened yet, and the migration towards Unicode has created new
challenges, resulting in "compatibility encodings" such as UTF-8. A large
number of systems out there still depends on the old 8-bit encodings, hampered
by the huge amounts of legacy code still widely deployed. Even sending Unicode
data from one Unicode-aware system to another may need encoding to an 8-bit
multibyte encoding (UTF-7 or UTF-8 is typically used for this purpose), to pass
unhindered through any traditional transport channels.


@section overview_mbconv_string Background: The wxString Class

@todo rewrite this overview; it's not up2date with wxString changes

If you have compiled wxWidgets in Unicode mode, the wxChar type will become
identical to wchar_t rather than char, and a wxString stores wxChars. Hence,
all wxString manipulation in your application will then operate on Unicode
strings, and almost as easily as working with ordinary char strings (you just
need to remember to use the wxT() macro to encapsulate any string literals).

But often, your environment doesn't want Unicode strings. You could be sending
data over a network, or processing a text file for some other application. You
need a way to quickly convert your easily-handled Unicode data to and from a
traditional 8-bit encoding. And this is what the wxMBConv classes do.


@section overview_mbconv_classes wxMBConv Classes

The base class for all these conversions is the wxMBConv class (which itself
implements standard libc locale conversion). Derived classes include
wxMBConvLibc, several different wxMBConvUTFxxx classes, and wxCSConv, which
implement different kinds of conversions. You can also derive your own class
for your own custom encoding and use it, should you need it. All you need to do
is override the MB2WC and WC2MB methods.


@section overview_mbconv_objects wxMBConv Objects

Several of the wxWidgets-provided wxMBConv classes have predefined instances
(wxConvLibc, wxConvFileName, wxConvUTF7, wxConvUTF8, wxConvLocal). You can use
these predefined objects directly, or you can instantiate your own objects.

A variable, wxConvCurrent, points to the conversion object that the user
interface is supposed to use, in the case that the user interface is not
Unicode-based (like with GTK+ 1.2). By default, it points to wxConvLibc or
wxConvLocal, depending on which works best on the current platform.


@section overview_mbconv_csconv wxCSConv

The wxCSConv class is special because when it is instantiated, you can tell it
which character set it should use, which makes it meaningful to keep many
instances of them around, each with a different character set (or you can
create a wxCSConv instance on the fly).

The predefined wxCSConv instance, wxConvLocal, is preset to use the default
user character set, but you should rarely need to use it directly, it is better
to go through wxConvCurrent.


@section overview_mbconv_converting Converting Strings

Once you have chosen which object you want to use to convert your text, here is
how you would use them with wxString. These examples all assume that you are
using a Unicode build of wxWidgets, although they will still compile in a
non-Unicode build (they just won't convert anything).

Example 1: Constructing a wxString from input in current encoding.

@code
wxString str(input_data, *wxConvCurrent);
@endcode

Example 2: Input in UTF-8 encoding.

@code
wxString str(input_data, wxConvUTF8);
@endcode

Example 3: Input in KOI8-R. Construction of wxCSConv instance on the fly.

@code
wxString str(input_data, wxCSConv(wxT("koi8-r")));
@endcode

Example 4: Printing a wxString to stdout in UTF-8 encoding.

@code
puts(str.mb_str(wxConvUTF8));
@endcode

Example 5: Printing a wxString to stdout in custom encoding. Using
preconstructed wxCSConv instance.

@code
wxCSConv cust(user_encoding);
printf("Data: %s\n", (const char*) str.mb_str(cust));
@endcode

@note Since mb_str() returns a temporary wxCharBuffer to hold the result of the
conversion, you need to explicitly cast it to const char* if you use it in a
vararg context (like with printf).


@section overview_mbconv_buffers Converting Buffers

If you have specialized needs, or just don't want to use wxString, you can also
use the conversion methods of the conversion objects directly. This can even be
useful if you need to do conversion in a non-Unicode build of wxWidgets;
converting a string from UTF-8 to the current encoding should be possible by
doing this:

@code
wxString str(wxConvUTF8.cMB2WC(input_data), *wxConvCurrent);
@endcode

Here, cMB2WC of the UTF8 object returns a wxWCharBuffer containing a Unicode
string. The wxString constructor then converts it back to an 8-bit character
set using the passed conversion object, *wxConvCurrent. (In a Unicode build of
wxWidgets, the constructor ignores the passed conversion object and retains the
Unicode data.)

This could also be done by first making a wxString of the original data:

@code
wxString input_str(input_data);
wxString str(input_str.wc_str(wxConvUTF8), *wxConvCurrent);
@endcode

To print a wxChar buffer to a non-Unicode stdout:

@code
printf("Data: %s\n", (const char*) wxConvCurrent->cWX2MB(unicode_data));
@endcode

If you need to do more complex processing on the converted data, you may want
to store the temporary buffer in a local variable:

@code
const wxWX2MBbuf tmp_buf = wxConvCurrent->cWX2MB(unicode_data);
const char *tmp_str = (const char*) tmp_buf;
printf("Data: %s\n", tmp_str);
process_data(tmp_str);
@endcode

If a conversion had taken place in cWX2MB (i.e. in a Unicode build), the buffer
will be deallocated as soon as tmp_buf goes out of scope. The macro wxWX2MBbuf
reflects the correct return value of cWX2MB (either char* or wxCharBuffer),
except for the const.

*/

