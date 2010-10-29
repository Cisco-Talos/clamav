/////////////////////////////////////////////////////////////////////////////
// Name:        resyntax.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_resyntax Regular Expressions

A <em>regular expression</em> describes strings of characters. It's a  pattern
that matches certain strings and doesn't match others.

@li @ref overview_resyntax_differentflavors
@li @ref overview_resyntax_syntax
@li @ref overview_resyntax_bracket
@li @ref overview_resyntax_escapes
@li @ref overview_resyntax_metasyntax
@li @ref overview_resyntax_matching
@li @ref overview_resyntax_limits
@li @ref overview_resyntax_bre
@li @ref overview_resyntax_characters

@see

@li wxRegEx


<hr>


@section overview_resyntax_differentflavors Different Flavors of Regular Expressions

Regular expressions (RE), as defined by POSIX, come in two flavors:
<em>extended regular expressions</em> (ERE) and <em>basic regular
expressions</em> (BRE). EREs are roughly those of the traditional @e egrep,
while BREs are roughly those of the traditional @e ed. This implementation
adds a third flavor: <em>advanced regular expressions</em> (ARE), basically
EREs with some significant extensions.

This manual page primarily describes AREs. BREs mostly exist for backward
compatibility in some old programs. POSIX EREs are almost an exact subset of
AREs. Features of AREs that are not present in EREs will be indicated.


@section overview_resyntax_syntax Regular Expression Syntax

These regular expressions are implemented using the package written by Henry
Spencer, based on the 1003.2 spec and some (not quite all) of the Perl5
extensions (thanks, Henry!).  Much of the description of regular expressions
below is copied verbatim from his manual entry.

An ARE is one or more @e branches, separated by "|", matching anything that
matches any of the branches.

A branch is zero or more @e constraints or @e quantified atoms, concatenated.
It matches a match for the first, followed by a match for the second, etc; an
empty branch matches the empty string.

A quantified atom is an @e atom possibly followed by a single @e quantifier.
Without a quantifier, it matches a match for the atom. The quantifiers, and
what a so-quantified atom matches, are:

@beginTable
@row2col{ <tt>*</tt> ,
    A sequence of 0 or more matches of the atom. }
@row2col{ <tt>+</tt> ,
    A sequence of 1 or more matches of the atom. }
@row2col{ <tt>?</tt> ,
    A sequence of 0 or 1 matches of the atom. }
@row2col{ <tt>{m}</tt> ,
    A sequence of exactly @e m matches of the atom. }
@row2col{ <tt>{m\,}</tt> ,
    A sequence of @e m or more matches of the atom. }
@row2col{ <tt>{m\,n}</tt> ,
    A sequence of @e m through @e n (inclusive) matches of the atom; @e m may
    not exceed @e n. }
@row2col{ <tt>*? +? ?? {m}? {m\,}? {m\,n}?</tt> ,
    @e Non-greedy quantifiers, which match the same possibilities, but prefer
    the smallest number rather than the largest number of matches (see
    @ref overview_resyntax_matching). }
@endTable

The forms using @b { and @b } are known as @e bounds. The numbers @e m and
@e n are unsigned decimal integers with permissible values from 0 to 255
inclusive. An atom is one of:

@beginTable
@row2col{ <tt>(re)</tt> ,
    Where @e re is any regular expression, matches for @e re, with the match
    captured for possible reporting. }
@row2col{ <tt>(?:re)</tt> ,
    As previous, but does no reporting (a "non-capturing" set of
    parentheses). }
@row2col{ <tt>()</tt> ,
    Matches an empty string, captured for possible reporting. }
@row2col{ <tt>(?:)</tt> ,
    Matches an empty string, without reporting. }
@row2col{ <tt>[chars]</tt> ,
    A <em>bracket expression</em>, matching any one of the @e chars (see
    @ref overview_resyntax_bracket for more details). }
@row2col{ <tt>.</tt> ,
    Matches any single character. }
@row2col{ <tt>@\k</tt> ,
    Where @e k is a non-alphanumeric character, matches that character taken
    as an ordinary character, e.g. @\@\ matches a backslash character. }
@row2col{ <tt>@\c</tt> ,
    Where @e c is alphanumeric (possibly followed by other characters), an
    @e escape (AREs only), see @ref overview_resyntax_escapes below. }
@row2col{ <tt>@leftCurly</tt> ,
    When followed by a character other than a digit, matches the left-brace
    character "@leftCurly"; when followed by a digit, it is the beginning of a
    @e bound (see above). }
@row2col{ <tt>x</tt> ,
    Where @e x is a single character with no other significance, matches that
    character. }
@endTable

A @e constraint matches an empty string when specific conditions are met. A
constraint may not be followed by a quantifier. The simple constraints are as
follows; some more constraints are described later, under
@ref overview_resyntax_escapes.

@beginTable
@row2col{ <tt>^</tt> ,
    Matches at the beginning of a line. }
@row2col{ <tt>@$</tt> ,
    Matches at the end of a line. }
@row2col{ <tt>(?=re)</tt> ,
    @e Positive lookahead (AREs only), matches at any point where a substring
    matching @e re begins. }
@row2col{ <tt>(?!re)</tt> ,
    @e Negative lookahead (AREs only), matches at any point where no substring
    matching @e re begins. }
@endTable

The lookahead constraints may not contain back references (see later), and all
parentheses within them are considered non-capturing. A RE may not end with
"\".


@section overview_resyntax_bracket Bracket Expressions

A <em>bracket expression</em> is a list of characters enclosed in <tt>[]</tt>.
It normally matches any single character from the list (but see below). If the
list begins with @c ^, it matches any single character (but see below) @e not
from the rest of the list.

If two characters in the list are separated by <tt>-</tt>, this is shorthand
for the full @e range of characters between those two (inclusive) in the
collating sequence, e.g. <tt>[0-9]</tt> in ASCII matches any decimal digit.
Two ranges may not share an endpoint, so e.g. <tt>a-c-e</tt> is illegal.
Ranges are very collating-sequence-dependent, and portable programs should
avoid relying on them.

To include a literal <tt>]</tt> or <tt>-</tt> in the list, the simplest method
is to enclose it in <tt>[.</tt> and <tt>.]</tt> to make it a collating element
(see below). Alternatively, make it the first character (following a possible
<tt>^</tt>), or (AREs only) precede it with <tt>@\</tt>. Alternatively, for
<tt>-</tt>, make it the last character, or the second endpoint of a range. To
use a literal <tt>-</tt> as the first endpoint of a range, make it a collating
element or (AREs only) precede it with <tt>@\</tt>. With the exception of
these, some combinations using <tt>[</tt> (see next paragraphs), and escapes,
all other special characters lose their special significance within a bracket
expression.

Within a bracket expression, a collating element (a character, a
multi-character sequence that collates as if it were a single character, or a
collating-sequence name for either) enclosed in <tt>[.</tt> and <tt>.]</tt>
stands for the sequence of characters of that collating element.

@e wxWidgets: Currently no multi-character collating elements are defined. So
in <tt>[.X.]</tt>, @c X can either be a single character literal or the name
of a character. For example, the following are both identical:
<tt>[[.0.]-[.9.]]</tt> and <tt>[[.zero.]-[.nine.]]</tt> and mean the same as
<tt>[0-9]</tt>. See @ref overview_resyntax_characters.

Within a bracket expression, a collating element enclosed in <tt>[=</tt> and
<tt>=]</tt> is an equivalence class, standing for the sequences of characters
of all collating elements equivalent to that one, including itself. An
equivalence class may not be an endpoint of a range.

@e wxWidgets: Currently no equivalence classes are defined, so <tt>[=X=]</tt>
stands for just the single character @c X. @c X can either be a single
character literal or the name of a character, see
@ref overview_resyntax_characters.

Within a bracket expression, the name of a @e character class enclosed in
<tt>[:</tt> and <tt>:]</tt> stands for the list of all characters (not all
collating elements!) belonging to that class. Standard character classes are:

@beginTable
@row2col{ <tt>alpha</tt>  , A letter. }
@row2col{ <tt>upper</tt>  , An upper-case letter. }
@row2col{ <tt>lower</tt>  , A lower-case letter. }
@row2col{ <tt>digit</tt>  , A decimal digit. }
@row2col{ <tt>xdigit</tt> , A hexadecimal digit. }
@row2col{ <tt>alnum</tt>  , An alphanumeric (letter or digit). }
@row2col{ <tt>print</tt>  , An alphanumeric (same as alnum). }
@row2col{ <tt>blank</tt>  , A space or tab character. }
@row2col{ <tt>space</tt>  , A character producing white space in displayed text. }
@row2col{ <tt>punct</tt>  , A punctuation character. }
@row2col{ <tt>graph</tt>  , A character with a visible representation. }
@row2col{ <tt>cntrl</tt>  , A control character. }
@endTable

A character class may not be used as an endpoint of a range.

@e wxWidgets: In a non-Unicode build, these character classifications depend on
the current locale, and correspond to the values return by the ANSI C "is"
functions: <tt>isalpha</tt>, <tt>isupper</tt>, etc. In Unicode mode they are
based on Unicode classifications, and are not affected by the current locale.

There are two special cases of bracket expressions: the bracket expressions
<tt>[[:@<:]]</tt> and <tt>[[:@>:]]</tt> are constraints, matching empty strings at
the beginning and end of a word respectively.  A word is defined as a sequence
of word characters that is neither preceded nor followed by word characters. A
word character is an @e alnum character or an underscore (_). These special
bracket expressions are deprecated; users of AREs should use constraint escapes
instead (see escapes below).


@section overview_resyntax_escapes Escapes

Escapes (AREs only), which begin with a <tt>@\</tt> followed by an alphanumeric
character, come in several varieties: character entry, class shorthands,
constraint escapes, and back references. A <tt>@\</tt> followed by an
alphanumeric character but not constituting a valid escape is illegal in AREs.
In EREs, there are no escapes: outside a bracket expression, a <tt>@\</tt>
followed by an alphanumeric character merely stands for that character as an
ordinary character, and inside a bracket expression, <tt>@\</tt> is an ordinary
character. (The latter is the one actual incompatibility between EREs and
AREs.)

Character-entry escapes (AREs only) exist to make it easier to specify
non-printing and otherwise inconvenient characters in REs:

@beginTable
@row2col{ <tt>@\a</tt> , Alert (bell) character, as in C. }
@row2col{ <tt>@\b</tt> , Backspace, as in C. }
@row2col{ <tt>@\B</tt> ,
    Synonym for <tt>@\</tt> to help reduce backslash doubling in some
    applications where there are multiple levels of backslash processing. }
@row2col{ <tt>@\cX</tt> ,
    The character whose low-order 5 bits are the same as those of @e X, and
    whose other bits are all zero, where @e X is any character. }
@row2col{ <tt>@\e</tt> ,
    The character whose collating-sequence name is @c ESC, or failing that,
    the character with octal value 033. }
@row2col{ <tt>@\f</tt> , Formfeed, as in C. }
@row2col{ <tt>@\n</tt> , Newline, as in C. }
@row2col{ <tt>@\r</tt> , Carriage return, as in C. }
@row2col{ <tt>@\t</tt> , Horizontal tab, as in C. }
@row2col{ <tt>@\uwxyz</tt> ,
    The Unicode character <tt>U+wxyz</tt> in the local byte ordering, where
    @e wxyz is exactly four hexadecimal digits. }
@row2col{ <tt>@\Ustuvwxyz</tt> ,
    Reserved for a somewhat-hypothetical Unicode extension to 32 bits, where
    @e stuvwxyz is exactly eight hexadecimal digits. }
@row2col{ <tt>@\v</tt> , Vertical tab, as in C are all available. }
@row2col{ <tt>@\xhhh</tt> ,
    The single character whose hexadecimal value is @e 0xhhh, where @e hhh is
    any sequence of hexadecimal digits. }
@row2col{ <tt>@\0</tt> , The character whose value is 0. }
@row2col{ <tt>@\xy</tt> ,
    The character whose octal value is @e 0xy, where @e xy is exactly two octal
    digits, and is not a <em>back reference</em> (see below). }
@row2col{ <tt>@\xyz</tt> ,
    The character whose octal value is @e 0xyz, where @e xyz is exactly three
    octal digits, and is not a <em>back reference</em> (see below). }
@endTable

Hexadecimal digits are 0-9, a-f, and A-F. Octal digits are 0-7.

The character-entry escapes are always taken as ordinary characters. For
example, <tt>@\135</tt> is <tt>]</tt> in ASCII, but <tt>@\135</tt> does not
terminate a bracket expression. Beware, however, that some applications (e.g.,
C compilers) interpret  such sequences themselves before the regular-expression
package gets to see them, which may require doubling (quadrupling, etc.) the
'<tt>@\</tt>'.

Class-shorthand escapes (AREs only) provide shorthands for certain
commonly-used character classes:

@beginTable
@row2col{ <tt>@\d</tt> , <tt>[[:digit:]]</tt> }
@row2col{ <tt>@\s</tt> , <tt>[[:space:]]</tt> }
@row2col{ <tt>@\w</tt> , <tt>[[:alnum:]_]</tt> (note underscore) }
@row2col{ <tt>@\D</tt> , <tt>[^[:digit:]]</tt> }
@row2col{ <tt>@\S</tt> , <tt>[^[:space:]]</tt> }
@row2col{ <tt>@\W</tt> , <tt>[^[:alnum:]_]</tt> (note underscore) }
@endTable

Within bracket expressions, <tt>@\d</tt>, <tt>@\s</tt>, and <tt>@\w</tt> lose
their outer brackets, and <tt>@\D</tt>, <tt>@\S</tt>, <tt>@\W</tt> are illegal.
So, for example, <tt>[a-c@\d]</tt> is equivalent to <tt>[a-c[:digit:]]</tt>.
Also, <tt>[a-c@\D]</tt>, which is equivalent to <tt>[a-c^[:digit:]]</tt>, is
illegal.

A constraint escape (AREs only) is a constraint, matching the empty string if
specific conditions are met, written as an escape:

@beginTable
@row2col{ <tt>@\A</tt> , Matches only at the beginning of the string, see
                         @ref overview_resyntax_matching for how this differs
                         from <tt>^</tt>. }
@row2col{ <tt>@\m</tt> , Matches only at the beginning of a word. }
@row2col{ <tt>@\M</tt> , Matches only at the end of a word. }
@row2col{ <tt>@\y</tt> , Matches only at the beginning or end of a word. }
@row2col{ <tt>@\Y</tt> , Matches only at a point that is not the beginning or
                         end of a word. }
@row2col{ <tt>@\Z</tt> , Matches only at the end of the string, see
                         @ref overview_resyntax_matching for how this differs
                         from <tt>@$</tt>. }
@row2col{ <tt>@\m</tt> , A <em>back reference</em>, where @e m is a non-zero
                         digit. See below. }
@row2col{ <tt>@\mnn</tt> ,
    A <em>back reference</em>, where @e m is a nonzero digit, and @e nn is some
    more digits, and the decimal value @e mnn is not greater than the number of
    closing capturing parentheses seen so far. See below. }
@endTable

A word is defined as in the specification of <tt>[[:@<:]]</tt> and
<tt>[[:@>:]]</tt> above. Constraint escapes are illegal within bracket
expressions.

A back reference (AREs only) matches the same string matched by the
parenthesized subexpression specified by the number. For example, "([bc])\1"
matches "bb" or "cc" but not "bc". The subexpression must entirely precede the
back reference in the RE.Subexpressions are numbered in the order of their
leading parentheses. Non-capturing parentheses do not define subexpressions.

There is an inherent historical ambiguity between octal character-entry escapes
and back references, which is resolved by heuristics, as hinted at above. A
leading zero always indicates an octal escape. A single non-zero digit, not
followed by another digit, is always taken as a back reference. A multi-digit
sequence not starting with a zero is taken as a back  reference if it comes
after a suitable subexpression (i.e. the number is in the legal range for a
back reference), and otherwise is taken as octal.


@section overview_resyntax_metasyntax Metasyntax

In addition to the main syntax described above, there are some special forms
and miscellaneous syntactic facilities available.

Normally the flavor of RE being used is specified by application-dependent
means. However, this can be overridden by a @e director. If an RE of any flavor
begins with <tt>***:</tt>, the rest of the RE is an ARE. If an RE of any
flavor begins with <tt>***=</tt>, the rest of the RE is taken to be a literal
string, with all characters considered ordinary characters.

An ARE may begin with <em>embedded options</em>: a sequence <tt>(?xyz)</tt>
(where @e xyz is one or more alphabetic characters) specifies options affecting
the rest of the RE. These supplement, and can override, any options specified
by the application. The available option letters are:

@beginTable
@row2col{ <tt>b</tt> , Rest of RE is a BRE. }
@row2col{ <tt>c</tt> , Case-sensitive matching (usual default). }
@row2col{ <tt>e</tt> , Rest of RE is an ERE. }
@row2col{ <tt>i</tt> , Case-insensitive matching (see
                       @ref overview_resyntax_matching, below). }
@row2col{ <tt>m</tt> , Historical synonym for @e n. }
@row2col{ <tt>n</tt> , Newline-sensitive matching (see
                       @ref overview_resyntax_matching, below). }
@row2col{ <tt>p</tt> , Partial newline-sensitive matching (see
                       @ref overview_resyntax_matching, below). }
@row2col{ <tt>q</tt> , Rest of RE is a literal ("quoted") string, all ordinary
                       characters. }
@row2col{ <tt>s</tt> , Non-newline-sensitive matching (usual default). }
@row2col{ <tt>t</tt> , Tight syntax (usual default; see below). }
@row2col{ <tt>w</tt> , Inverse partial newline-sensitive ("weird") matching
                       (see @ref overview_resyntax_matching, below). }
@row2col{ <tt>x</tt> , Expanded syntax (see below). }
@endTable

Embedded options take effect at the <tt>)</tt> terminating the sequence. They
are available only at the start of an ARE, and may not be used later within it.

In addition to the usual (@e tight) RE syntax, in which all characters are
significant, there is an @e expanded syntax, available in AREs with the
embedded x option. In the expanded syntax, white-space characters are ignored
and all characters between a <tt>@#</tt> and the following newline (or the end
of the RE) are ignored, permitting paragraphing and commenting a complex RE.
There are three exceptions to that basic rule:

@li A white-space character or <tt>@#</tt> preceded by <tt>@\</tt> is retained.
@li White space or <tt>@#</tt> within a bracket expression is retained.
@li White space and comments are illegal within multi-character symbols like
    the ARE <tt>(?:</tt> or the BRE <tt>\(</tt>.

Expanded-syntax white-space characters are blank, tab, newline, and any
character that belongs to the @e space character class.

Finally, in an ARE, outside bracket expressions, the sequence <tt>(?@#ttt)</tt>
(where @e ttt is any text not containing a <tt>)</tt>) is a comment, completely
ignored. Again, this is not allowed between the characters of multi-character
symbols like <tt>(?:</tt>. Such comments are more a historical artifact than a
useful facility, and their use is deprecated; use the expanded syntax instead.

@e None of these metasyntax extensions is available if the application (or an
initial <tt>***=</tt> director) has specified that the user's input be treated
as a literal string rather than as an RE.


@section overview_resyntax_matching Matching

In the event that an RE could match more than one substring of a given string,
the RE matches the one starting earliest in the string. If the RE could match
more than one substring starting at that point, the choice is determined by
it's @e preference: either the longest substring, or the shortest.

Most atoms, and all constraints, have no preference. A parenthesized RE has the
same preference (possibly none) as the RE. A quantified atom with quantifier
<tt>{m}</tt> or <tt>{m}?</tt> has the same preference (possibly none) as the
atom itself. A quantified atom with other normal quantifiers (including
<tt>{m,n}</tt> with @e m equal to @e n) prefers longest match. A quantified
atom with other non-greedy quantifiers (including <tt>{m,n}?</tt> with @e m
equal to @e n) prefers shortest match. A branch has the same preference as the
first quantified atom in it which has a preference. An RE consisting of two or
more branches connected by the @c | operator prefers longest match.

Subject to the constraints imposed by the rules for matching the whole RE,
subexpressions also match the longest or shortest possible substrings, based on
their preferences, with subexpressions starting earlier in the RE taking
priority over ones starting later. Note that outer subexpressions thus take
priority over their component subexpressions.

Note that the quantifiers <tt>{1,1}</tt> and <tt>{1,1}?</tt> can be used to
force longest and shortest preference, respectively, on a subexpression or a
whole RE.

Match lengths are measured in characters, not collating elements. An empty
string is considered longer than no match at all. For example, <tt>bb*</tt>
matches the three middle characters of "abbbc",
<tt>(week|wee)(night|knights)</tt> matches all ten characters of "weeknights",
when <tt>(.*).*</tt> is matched against "abc" the parenthesized subexpression
matches all three characters, and when <tt>(a*)*</tt> is matched against "bc"
both the whole RE and the parenthesized subexpression match an empty string.

If case-independent matching is specified, the effect is much as if all case
distinctions had vanished from the alphabet. When an alphabetic that exists in
multiple cases appears as an ordinary character outside a bracket expression,
it is effectively transformed into a bracket expression containing both cases,
so that @c x becomes @c [xX]. When it appears inside a bracket expression, all
case counterparts of it are added to the bracket expression, so that @c [x]
becomes @c [xX] and @c [^x] becomes @c [^xX].

If newline-sensitive matching is specified, "." and bracket expressions using
"^" will never match the newline character (so that matches will never cross
newlines unless the RE explicitly arranges it) and "^" and "$" will match the
empty string after and before a newline respectively, in addition to matching
at beginning and end of string respectively. ARE <tt>@\A</tt> and <tt>@\Z</tt>
continue to match beginning or end of string @e only.

If partial newline-sensitive matching is specified, this affects "." and
bracket expressions as with newline-sensitive matching, but not "^" and "$".

If inverse partial newline-sensitive matching is specified, this affects "^"
and "$" as with newline-sensitive matching, but not "." and bracket
expressions. This isn't very useful but is provided for symmetry.


@section overview_resyntax_limits Limits and Compatibility

No particular limit is imposed on the length of REs. Programs intended to be
highly portable should not employ REs longer than 256 bytes, as a
POSIX-compliant implementation can refuse to accept such REs.

The only feature of AREs that is actually incompatible with POSIX EREs is that
<tt>@\</tt> does not lose its special significance inside bracket expressions.
All other ARE features use syntax which is illegal or has undefined or
unspecified effects in POSIX EREs; the <tt>***</tt> syntax of directors
likewise is outside the POSIX syntax for both BREs and EREs.

Many of the ARE extensions are borrowed from Perl, but some have been changed
to clean them up, and a few Perl extensions are not present. Incompatibilities
of note include <tt>@\b</tt>, <tt>@\B</tt>, the lack of special treatment for a
trailing newline, the addition of complemented bracket expressions to the
things affected by newline-sensitive matching, the restrictions on parentheses
and back references in lookahead constraints, and the longest/shortest-match
(rather than first-match) matching semantics.

The matching rules for REs containing both normal and non-greedy quantifiers
have changed since early beta-test versions of this package. The new rules are
much simpler and cleaner, but don't work as hard at guessing the user's real
intentions.

Henry Spencer's original 1986 @e regexp package, still in widespread use,
implemented an early version of today's EREs. There are four incompatibilities
between @e regexp's near-EREs (RREs for short) and AREs. In roughly increasing
order of significance:

@li In AREs, <tt>@\</tt> followed by an alphanumeric character is either an
    escape or an error, while in RREs, it was just another way of writing the
    alphanumeric. This should not be a problem because there was no reason to
    write such a sequence in RREs.
@li @c { followed by a digit in an ARE is the beginning of a bound, while in
    RREs, @c { was always an ordinary character. Such sequences should be rare,
    and will often result in an error because following characters will not
    look like a valid bound.
@li In AREs, @c @\ remains a special character within @c [], so a literal @c @\
    within @c [] must be written as <tt>@\@\</tt>. <tt>@\@\</tt> also gives a
    literal @c @\ within @c [] in RREs, but only truly paranoid programmers
    routinely doubled the backslash.
@li AREs report the longest/shortest match for the RE, rather than the first
    found in a specified search order. This may affect some RREs which were
    written in the expectation that the first match would be reported. The
    careful crafting of RREs to optimize the search order for fast matching is
    obsolete (AREs examine all possible matches in parallel, and their
    performance is largely insensitive to their complexity) but cases where the
    search order was exploited to deliberately find a match which was @e not
    the longest/shortest will need rewriting.


@section overview_resyntax_bre Basic Regular Expressions

BREs differ from EREs in several respects. @c |, @c +, and @c ? are ordinary
characters and there is no equivalent for their functionality. The delimiters
for bounds are @c @\{ and @c @\}, with @c { and @c } by themselves ordinary
characters. The parentheses for nested subexpressions are @c @\( and @c @\),
with @c ( and @c ) by themselves ordinary characters. @c ^ is an ordinary
character except at the beginning of the RE or the beginning of a parenthesized
subexpression, @c $ is an ordinary character except at the end of the RE or the
end of a parenthesized subexpression, and @c * is an ordinary character if it
appears at the beginning of the RE or the beginning of a parenthesized
subexpression (after a possible leading <tt>^</tt>). Finally, single-digit back
references are available, and @c @\@< and @c @\@> are synonyms for
<tt>[[:@<:]]</tt> and <tt>[[:@>:]]</tt> respectively; no other escapes are
available.


@section overview_resyntax_characters Regular Expression Character Names

Note that the character names are case sensitive.

<center><table class='doctable' border='0' cellspacing='5' cellpadding='4'><tr>

<td>
@beginTable
@row2col{ <tt>NUL</tt> , @\0 }
@row2col{ <tt>SOH</tt> , @\001 }
@row2col{ <tt>STX</tt> , @\002 }
@row2col{ <tt>ETX</tt> , @\003 }
@row2col{ <tt>EOT</tt> , @\004 }
@row2col{ <tt>ENQ</tt> , @\005 }
@row2col{ <tt>ACK</tt> , @\006 }
@row2col{ <tt>BEL</tt> , @\007 }
@row2col{ <tt>alert</tt> , @\007 }
@row2col{ <tt>BS</tt> , @\010 }
@row2col{ <tt>backspace</tt> , @\b }
@row2col{ <tt>HT</tt> , @\011 }
@row2col{ <tt>tab</tt> , @\t }
@row2col{ <tt>LF</tt> , @\012 }
@row2col{ <tt>newline</tt> , @\n }
@row2col{ <tt>VT</tt> , @\013 }
@row2col{ <tt>vertical-tab</tt> , @\v }
@row2col{ <tt>FF</tt> , @\014 }
@row2col{ <tt>form-feed</tt> , @\f }
@endTable
</td>

<td>
@beginTable
@row2col{ <tt>CR</tt> , @\015 }
@row2col{ <tt>carriage-return</tt> , @\r }
@row2col{ <tt>SO</tt> , @\016 }
@row2col{ <tt>SI</tt> , @\017 }
@row2col{ <tt>DLE</tt> , @\020 }
@row2col{ <tt>DC1</tt> , @\021 }
@row2col{ <tt>DC2</tt> , @\022 }
@row2col{ <tt>DC3</tt> , @\023 }
@row2col{ <tt>DC4</tt> , @\024 }
@row2col{ <tt>NAK</tt> , @\025 }
@row2col{ <tt>SYN</tt> , @\026 }
@row2col{ <tt>ETB</tt> , @\027 }
@row2col{ <tt>CAN</tt> , @\030 }
@row2col{ <tt>EM</tt> , @\031 }
@row2col{ <tt>SUB</tt> , @\032 }
@row2col{ <tt>ESC</tt> , @\033 }
@row2col{ <tt>IS4</tt> , @\034 }
@row2col{ <tt>FS</tt> , @\034 }
@row2col{ <tt>IS3</tt> , @\035 }
@endTable
</td>

<td>
@beginTable
@row2col{ <tt>GS</tt> , @\035 }
@row2col{ <tt>IS2</tt> , @\036 }
@row2col{ <tt>RS</tt> , @\036 }
@row2col{ <tt>IS1</tt> , @\037 }
@row2col{ <tt>US</tt> , @\037 }
@row2col{ <tt>space</tt> , " " (space) }
@row2col{ <tt>exclamation-mark</tt> , ! }
@row2col{ <tt>quotation-mark</tt> , " }
@row2col{ <tt>number-sign</tt> , @# }
@row2col{ <tt>dollar-sign</tt> , @$ }
@row2col{ <tt>percent-sign</tt> , @% }
@row2col{ <tt>ampersand</tt> , @& }
@row2col{ <tt>apostrophe</tt> , ' }
@row2col{ <tt>left-parenthesis</tt> , ( }
@row2col{ <tt>right-parenthesis</tt> , ) }
@row2col{ <tt>asterisk</tt> , * }
@row2col{ <tt>plus-sign</tt> , + }
@row2col{ <tt>comma</tt> , \, }
@row2col{ <tt>hyphen</tt> , - }
@endTable
</td>

<td>
@beginTable
@row2col{ <tt>hyphen-minus</tt> , - }
@row2col{ <tt>period</tt> , . }
@row2col{ <tt>full-stop</tt> , . }
@row2col{ <tt>slash</tt> , / }
@row2col{ <tt>solidus</tt> , / }
@row2col{ <tt>zero</tt> , 0 }
@row2col{ <tt>one</tt> , 1 }
@row2col{ <tt>two</tt> , 2 }
@row2col{ <tt>three</tt> , 3 }
@row2col{ <tt>four</tt> , 4 }
@row2col{ <tt>five</tt> , 5 }
@row2col{ <tt>six</tt> , 6 }
@row2col{ <tt>seven</tt> , 7 }
@row2col{ <tt>eight</tt> , 8 }
@row2col{ <tt>nine</tt> , 9 }
@row2col{ <tt>colon</tt> , : }
@row2col{ <tt>semicolon</tt> , ; }
@row2col{ <tt>less-than-sign</tt> , @< }
@row2col{ <tt>equals-sign</tt> , = }
@endTable
</td>

<td>
@beginTable
@row2col{ <tt>greater-than-sign</tt> , @> }
@row2col{ <tt>question-mark</tt> , ? }
@row2col{ <tt>commercial-at</tt> , @@ }
@row2col{ <tt>left-square-bracket</tt> , [ }
@row2col{ <tt>backslash</tt> , @\ }
@row2col{ <tt>reverse-solidus</tt> , @\ }
@row2col{ <tt>right-square-bracket</tt> , ] }
@row2col{ <tt>circumflex</tt> , ^ }
@row2col{ <tt>circumflex-accent</tt> , ^ }
@row2col{ <tt>underscore</tt> , _ }
@row2col{ <tt>low-line</tt> , _ }
@row2col{ <tt>grave-accent</tt> , ' }
@row2col{ <tt>left-brace</tt> , @leftCurly }
@row2col{ <tt>left-curly-bracket</tt> , @leftCurly }
@row2col{ <tt>vertical-line</tt> , | }
@row2col{ <tt>right-brace</tt> , @rightCurly }
@row2col{ <tt>right-curly-bracket</tt> , @rightCurly }
@row2col{ <tt>tilde</tt> , ~ }
@row2col{ <tt>DEL</tt> , @\177 }
@endTable
</td>

</tr></table></center>

*/

