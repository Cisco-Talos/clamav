/////////////////////////////////////////////////////////////////////////////
// Name:        string.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_string wxString Overview

Classes: wxString, wxArrayString, wxStringTokenizer

@li @ref overview_string_intro
@li @ref overview_string_internal
@li @ref overview_string_binary
@li @ref overview_string_comparison
@li @ref overview_string_advice
@li @ref overview_string_related
@li @ref overview_string_tuning
@li @ref overview_string_settings


<hr>


@section overview_string_intro Introduction

wxString is a class which represents a Unicode string of arbitrary length and
containing arbitrary Unicode characters.

This class has all the standard operations you can expect to find in a string
class: dynamic memory management (string extends to accommodate new
characters), construction from other strings, compatibility with C strings and
wide character C strings, assignment operators, access to individual characters, string
concatenation and comparison, substring extraction, case conversion, trimming and
padding (with spaces), searching and replacing and both C-like @c printf (wxString::Printf)
and stream-like insertion functions as well as much more - see wxString for a
list of all functions.

The wxString class has been completely rewritten for wxWidgets 3.0 but much work
has been done to make existing code using ANSI string literals work as it did
in previous versions.


@section overview_string_internal Internal wxString encoding

Since wxWidgets 3.0 wxString internally uses <b>UTF-16</b> (with Unicode
code units stored in @c wchar_t) under Windows and <b>UTF-8</b> (with Unicode
code units stored in @c char) under Unix, Linux and Mac OS X to store its content.

For definitions of <em>code units</em> and <em>code points</em> terms, please
see the @ref overview_unicode_encodings paragraph.

For simplicity of implementation, wxString when <tt>wxUSE_UNICODE_WCHAR==1</tt>
(e.g. on Windows) uses <em>per code unit indexing</em> instead of
<em>per code point indexing</em> and doesn't know anything about surrogate pairs;
in other words it always considers code points to be composed by 1 code unit,
while this is really true only for characters in the @e BMP (Basic Multilingual Plane).
Thus when iterating over a UTF-16 string stored in a wxString under Windows, the user
code has to take care of <em>surrogate pairs</em> himself.
(Note however that Windows itself has built-in support for surrogate pairs in UTF-16,
such as for drawing strings on screen.)

@remarks
Note that while the behaviour of wxString when <tt>wxUSE_UNICODE_WCHAR==1</tt>
resembles UCS-2 encoding, it's not completely correct to refer to wxString as
UCS-2 encoded since you can encode code points outside the @e BMP in a wxString
as two code units (i.e. as a surrogate pair; as already mentioned however wxString
will "see" them as two different code points)

When instead <tt>wxUSE_UNICODE_UTF8==1</tt> (e.g. on Linux and Mac OS X)
wxString handles UTF8 multi-bytes sequences just fine also for characters outside
the BMP (it implements <em>per code point indexing</em>), so that you can use
UTF8 in a completely transparent way:

Example:
@code
    // first test, using exotic characters outside of the Unicode BMP:

    wxString test = wxString::FromUTF8("\xF0\x90\x8C\x80");
        // U+10300 is "OLD ITALIC LETTER A" and is part of Unicode Plane 1
        // in UTF8 it's encoded as 0xF0 0x90 0x8C 0x80

    // it's a single Unicode code-point encoded as:
    // - a UTF16 surrogate pair under Windows
    // - a UTF8 multiple-bytes sequence under Linux
    // (without considering the final NULL)

    wxPrintf("wxString reports a length of %d character(s)", test.length());
        // prints "wxString reports a length of 1 character(s)" on Linux
        // prints "wxString reports a length of 2 character(s)" on Windows
        // since wxString on Windows doesn't have surrogate pairs support!


    // second test, this time using characters part of the Unicode BMP:

    wxString test2 = wxString::FromUTF8("\x41\xC3\xA0\xE2\x82\xAC");
        // this is the UTF8 encoding of capital letter A followed by
        // 'small case letter a with grave' followed by the 'euro sign'

    // they are 3 Unicode code-points encoded as:
    // - 3 UTF16 code units under Windows
    // - 6 UTF8 code units under Linux
    // (without considering the final NULL)

    wxPrintf("wxString reports a length of %d character(s)", test2.length());
        // prints "wxString reports a length of 3 character(s)" on Linux
        // prints "wxString reports a length of 3 character(s)" on Windows
@endcode

To better explain what stated above, consider the second string of the example
above; it's composed by 3 characters and the final @c NULL:

@image html overview_wxstring_encoding.png

As you can see, UTF16 encoding is straightforward (for characters in the @e BMP)
and in this example the UTF16-encoded wxString takes 8 bytes.
UTF8 encoding is more elaborated and in this example takes 7 bytes.

In general, for strings containing many latin characters UTF8 provides a big
advantage with regards to the memory footprint respect UTF16, but requires some
more processing for common operations like e.g. length calculation.

Finally, note that the type used by wxString to store Unicode code units
(@c wchar_t or @c char) is always @c typedef-ined to be ::wxStringCharType.


@section overview_string_binary Using wxString to store binary data

wxString can be used to store binary data (even if it contains @c NULs) using the
functions wxString::To8BitData and wxString::From8BitData.

Beware that even if @c NUL character is allowed, in the current string implementation
some methods might not work correctly with them.

Note however that other classes like wxMemoryBuffer are more suited to this task.
For handling binary data you may also want to look at the wxStreamBuffer,
wxMemoryOutputStream, wxMemoryInputStream classes.


@section overview_string_comparison Comparison to Other String Classes

The advantages of using a special string class instead of working directly with
C strings are so obvious that there is a huge number of such classes available.
The most important advantage is the need to always remember to allocate/free
memory for C strings; working with fixed size buffers almost inevitably leads
to buffer overflows. At last, C++ has a standard string class (@c std::string). So
why the need for wxString? There are several advantages:

@li <b>Efficiency:</b> Since wxWidgets 3.0 wxString uses @c std::string (in UTF8
    mode under Linux, Unix and OS X) or @c std::wstring (in UTF16 mode under Windows)
    internally by default to store its contents. wxString will therefore inherit the
    performance characteristics from @c std::string.
@li <b>Compatibility:</b> This class tries to combine almost full compatibility
    with the old wxWidgets 1.xx wxString class, some reminiscence of MFC's
    CString class and 90% of the functionality of @c std::string class.
@li <b>Rich set of functions:</b> Some of the functions present in wxString are
    very useful but don't exist in most of other string classes: for example,
    wxString::AfterFirst, wxString::BeforeLast, wxString::Printf.
    Of course, all the standard string operations are supported as well.
@li <b>wxString is Unicode friendly:</b> it allows to easily convert to
    and from ANSI and Unicode strings (see @ref overview_unicode
    for more details) and maps to @c std::wstring transparently.
@li <b>Used by wxWidgets:</b> And, of course, this class is used everywhere
    inside wxWidgets so there is no performance loss which would result from
    conversions of objects of any other string class (including @c std::string) to
    wxString internally by wxWidgets.

However, there are several problems as well. The most important one is probably
that there are often several functions to do exactly the same thing: for
example, to get the length of the string either one of wxString::length(),
wxString::Len() or wxString::Length() may be used. The first function, as
almost all the other functions in lowercase, is @c std::string compatible. The
second one is the "native" wxString version and the last one is the wxWidgets
1.xx way.

So which is better to use? The usage of the @c std::string compatible functions is
strongly advised! It will both make your code more familiar to other C++
programmers (who are supposed to have knowledge of @c std::string but not of
wxString), let you reuse the same code in both wxWidgets and other programs (by
just typedefing wxString as @c std::string when used outside wxWidgets) and by
staying compatible with future versions of wxWidgets which will probably start
using @c std::string sooner or later too.

In the situations where there is no corresponding @c std::string function, please
try to use the new wxString methods and not the old wxWidgets 1.xx variants
which are deprecated and may disappear in future versions.


@section overview_string_advice Advice About Using wxString

@subsection overview_string_implicitconv Implicit conversions

Probably the main trap with using this class is the implicit conversion
operator to <tt>const char*</tt>. It is advised that you use wxString::c_str()
instead to clearly indicate when the conversion is done. Specifically, the
danger of this implicit conversion may be seen in the following code fragment:

@code
// this function converts the input string to uppercase,
// output it to the screen and returns the result
const char *SayHELLO(const wxString& input)
{
    wxString output = input.Upper();
    printf("Hello, %s!\n", output);
    return output;
}
@endcode

There are two nasty bugs in these three lines. The first is in the call to the
@c printf() function. Although the implicit conversion to C strings is applied
automatically by the compiler in the case of

@code
puts(output);
@endcode

because the argument of @c puts() is known to be of the type
<tt>const char*</tt>, this is @b not done for @c printf() which is a function
with variable number of arguments (and whose arguments are of unknown types).
So this call may do any number of things (including displaying the correct
string on screen), although the most likely result is a program crash.
The solution is to use wxString::c_str(). Just replace this line with this:

@code
printf("Hello, %s!\n", output.c_str());
@endcode

The second bug is that returning @c output doesn't work. The implicit cast is
used again, so the code compiles, but as it returns a pointer to a buffer
belonging to a local variable which is deleted as soon as the function exits,
its contents are completely arbitrary. The solution to this problem is also
easy, just make the function return wxString instead of a C string.

This leads us to the following general advice: all functions taking string
arguments should take <tt>const wxString&</tt> (this makes assignment to the
strings inside the function faster) and all functions returning strings
should return wxString - this makes it safe to return local variables.

Finally note that wxString uses the current locale encoding to convert any C string
literal to Unicode. The same is done for converting to and from @c std::string
and for the return value of c_str().
For this conversion, the @a wxConvLibc class instance is used.
See wxCSConv and wxMBConv.


@subsection overview_string_iterating Iterating wxString's characters

As previously described, when <tt>wxUSE_UNICODE_UTF8==1</tt>, wxString internally
uses the variable-length UTF8 encoding.
Accessing a UTF-8 string by index can be very @b inefficient because
a single character is represented by a variable number of bytes so that
the entire string has to be parsed in order to find the character.
Since iterating over a string by index is a common programming technique and
was also possible and encouraged by wxString using the access operator[]()
wxString implements caching of the last used index so that iterating over
a string is a linear operation even in UTF-8 mode.

It is nonetheless recommended to use @b iterators (instead of index based
access) like this:

@code
wxString s = "hello";
wxString::const_iterator i;
for (i = s.begin(); i != s.end(); ++i)
{
    wxUniChar uni_ch = *i;
    // do something with it
}
@endcode



@section overview_string_related String Related Functions and Classes

As most programs use character strings, the standard C library provides quite
a few functions to work with them. Unfortunately, some of them have rather
counter-intuitive behaviour (like @c strncpy() which doesn't always terminate
the resulting string with a @NULL) and are in general not very safe (passing
@NULL to them will probably lead to program crash). Moreover, some very useful
functions are not standard at all. This is why in addition to all wxString
functions, there are also a few global string functions which try to correct
these problems: wxIsEmpty() verifies whether the string is empty (returning
@true for @NULL pointers), wxStrlen() also handles @NULL correctly and returns
0 for them and wxStricmp() is just a platform-independent version of
case-insensitive string comparison function known either as @c stricmp() or
@c strcasecmp() on different platforms.

The <tt>@<wx/string.h@></tt> header also defines ::wxSnprintf and ::wxVsnprintf
functions which should be used instead of the inherently dangerous standard
@c sprintf() and which use @c snprintf() instead which does buffer size checks
whenever possible. Of course, you may also use wxString::Printf which is also
safe.

There is another class which might be useful when working with wxString:
wxStringTokenizer. It is helpful when a string must be broken into tokens and
replaces the standard C library @c strtok() function.

And the very last string-related class is wxArrayString: it is just a version
of the "template" dynamic array class which is specialized to work with
strings. Please note that this class is specially optimized (using its
knowledge of the internal structure of wxString) for storing strings and so it
is vastly better from a performance point of view than a wxObjectArray of
wxStrings.


@section overview_string_tuning Tuning wxString for Your Application

@note This section is strictly about performance issues and is absolutely not
necessary to read for using wxString class. Please skip it unless you feel
familiar with profilers and relative tools.

For the performance reasons wxString doesn't allocate exactly the amount of
memory needed for each string. Instead, it adds a small amount of space to each
allocated block which allows it to not reallocate memory (a relatively
expensive operation) too often as when, for example, a string is constructed by
subsequently adding one character at a time to it, as for example in:

@code
// delete all vowels from the string
wxString DeleteAllVowels(const wxString& original)
{
    wxString vowels( "aeuioAEIOU" );
    wxString result;
    wxString::const_iterator i;
    for ( i = original.begin(); i != original.end(); ++i )
    {
        if (vowels.Find( *i ) == wxNOT_FOUND)
            result += *i;
    }

    return result;
}
@endcode

This is quite a common situation and not allocating extra memory at all would
lead to very bad performance in this case because there would be as many memory
(re)allocations as there are consonants in the original string. Allocating too
much extra memory would help to improve the speed in this situation, but due to
a great number of wxString objects typically used in a program would also
increase the memory consumption too much.

The very best solution in precisely this case would be to use wxString::Alloc()
function to preallocate, for example, len bytes from the beginning - this will
lead to exactly one memory allocation being performed (because the result is at
most as long as the original string).

However, using wxString::Alloc() is tedious and so wxString tries to do its
best. The default algorithm assumes that memory allocation is done in
granularity of at least 16 bytes (which is the case on almost all of
wide-spread platforms) and so nothing is lost if the amount of memory to
allocate is rounded up to the next multiple of 16. Like this, no memory is lost
and 15 iterations from 16 in the example above won't allocate memory but use
the already allocated pool.

The default approach is quite conservative. Allocating more memory may bring
important performance benefits for programs using (relatively) few very long
strings. The amount of memory allocated is configured by the setting of
@c EXTRA_ALLOC in the file string.cpp during compilation (be sure to understand
why its default value is what it is before modifying it!). You may try setting
it to greater amount (say twice nLen) or to 0 (to see performance degradation
which will follow) and analyse the impact of it on your program. If you do it,
you will probably find it helpful to also define @c WXSTRING_STATISTICS symbol
which tells the wxString class to collect performance statistics and to show
them on stderr on program termination. This will show you the average length of
strings your program manipulates, their average initial length and also the
percent of times when memory wasn't reallocated when string concatenation was
done but the already preallocated memory was used (this value should be about
98% for the default allocation policy, if it is less than 90% you should
really consider fine tuning wxString for your application).

It goes without saying that a profiler should be used to measure the precise
difference the change to @c EXTRA_ALLOC makes to your program.


@section overview_string_settings wxString Related Compilation Settings

Much work has been done to make existing code using ANSI string literals
work as before version 3.0.

If you nonetheless need to have a wxString that uses @c wchar_t
on Unix and Linux, too, you can specify this on the command line with the
@c configure @c --disable-utf8 switch or you can consider using wxUString
or @c std::wstring instead.

@c wxUSE_UNICODE is now defined as @c 1 by default to indicate Unicode support.
If UTF-8 is used for the internal storage in wxString, @c wxUSE_UNICODE_UTF8 is
also defined, otherwise @c wxUSE_UNICODE_WCHAR is.
See also @ref page_wxusedef_important.

*/

