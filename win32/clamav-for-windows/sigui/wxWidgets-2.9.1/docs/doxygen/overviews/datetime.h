/////////////////////////////////////////////////////////////////////////////
// Name:        datetime.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_datetime Date and Time

Classes: wxDateTime, wxDateSpan, wxTimeSpan, wxCalendarCtrl

@li @ref overview_datetime_introduction
@li @ref overview_datetime_classes
@li @ref overview_datetime_characteristics
@li @ref overview_datetime_timespandiff
@li @ref overview_datetime_arithmetics
@li @ref overview_datetime_timezones
@li @ref overview_datetime_dst
@li @ref overview_datetime_holidays
@li @ref overview_datetime_compat


<hr>


@section overview_datetime_introduction Introduction

wxWidgets provides a set of powerful classes to work with dates and times. Some
of the supported features of wxDateTime class are:

@li Wide range: the range of supported dates goes from about 4714 B.C. to
    some 480 million years in the future.

@li Precision: not using floating point calculations anywhere ensures that
    the date calculations don't suffer from rounding errors.

@li Many features: not only all usual calculations with dates are supported,
    but also more exotic week and year day calculations, work day testing, standard
    astronomical functions, conversion to and from strings in either strict or free
    format.

@li Efficiency: objects of wxDateTime are small (8 bytes) and working with
    them is fast



@section overview_datetime_classes All date/time classes at a glance

There are 3 main classes declared in @c wx/datetime.h: except wxDateTime itself
which represents an absolute moment in time, there are also two classes -
wxTimeSpan and wxDateSpan - which represent the intervals of time.

There are also helper classes which are used together with wxDateTime:
wxDateTimeHolidayAuthority which is used to determine whether a given date
is a holiday or not and wxDateTimeWorkDays which is a derivation of this
class for which (only) Saturdays and Sundays are the holidays. See more about
these classes in the discussion of the holidays (see @ref overview_datetime_holidays).

Finally, in other parts of this manual you may find mentions of wxDate and
wxTime classes. @ref overview_datetime_compat are obsolete and
superseded by wxDateTime.



@section overview_datetime_characteristics wxDateTime characteristics

wxDateTime stores the time as a signed number of
milliseconds since the Epoch which is fixed, by convention, to Jan 1, 1970 -
however this is not visible to the class users (in particular, dates prior to
the Epoch are handled just as well (or as bad) as the dates after it). But it
does mean that the best resolution which can be achieved with this class is 1
millisecond.

The size of wxDateTime object is 8 bytes because it is represented as a 64 bit
integer. The resulting range of supported dates is thus approximatively 580
million years, but due to the current limitations in the Gregorian calendar
support, only dates from Nov 24, 4714BC are supported (this is subject to
change if there is sufficient interest in doing it).

Finally, the internal representation is time zone independent (always in GMT)
and the time zones only come into play when a date is broken into
year/month/day components. See more about timezones below
(see @ref overview_datetime_timezones).

Currently, the only supported calendar is Gregorian one (which is used even
for the dates prior to the historic introduction of this calendar which was
first done on Oct 15, 1582 but is, generally speaking, country, and even
region, dependent). Future versions will probably have Julian calendar support
as well and support for other calendars (Maya, Hebrew, Chinese...) is not
ruled out.



@section overview_datetime_timespandiff Difference between wxDateSpan and wxTimeSpan

While there is only one logical way to represent an absolute moment in the
time (and hence only one wxDateTime class), there are at least two methods to
describe a time interval.

First, there is the direct and self-explaining way implemented by
wxTimeSpan: it is just a difference in milliseconds
between two moments in time. Adding or subtracting such an interval to
wxDateTime is always well-defined and is a fast operation.

But in the daily life other, calendar-dependent time interval specifications are
used. For example, 'one month later' is commonly used. However, it is clear
that this is not the same as wxTimeSpan of 60*60*24*31 seconds because 'one
month later' Feb 15 is Mar 15 and not Mar 17 or Mar 16 (depending on whether
the year is leap or not).

This is why there is another class for representing such intervals called
wxDateSpan. It handles these sort of operations in the
most natural way possible, but note that manipulating with intervals of
this kind is not always well-defined. Consider, for example, Jan 31 + '1
month': this will give Feb 28 (or 29), i.e. the last day of February and not
the non-existent Feb 31. Of course, this is what is usually wanted, but you
still might be surprised to notice that now subtracting back the same
interval from Feb 28 will result in Jan 28 and @b not Jan 31 we started
with!

So, unless you plan to implement some kind of natural language parsing in the
program, you should probably use wxTimeSpan instead of wxDateSpan (which is
also more efficient). However, wxDateSpan may be very useful in situations
when you do need to understand what 'in a month' means (of course, it is
just @c wxDateTime::Now() + wxDateSpan::Month()).



@section overview_datetime_arithmetics Date arithmetics

Many different operations may be performed with the dates, however not all of
them make sense. For example, multiplying a date by a number is an invalid
operation, even though multiplying either of the time span classes by a number
is perfectly valid.

Here is what can be done:

@li @b Addition: a wxTimeSpan or wxDateSpan can be added to wxDateTime
    resulting in a new wxDateTime object and also 2 objects of the same span class
    can be added together giving another object of the same class.

@li @b Subtraction: the same types of operations as above are
    allowed and, additionally, a difference between two wxDateTime objects can be
    taken and this will yield wxTimeSpan.

@li @b Multiplication: a wxTimeSpan or wxDateSpan object can be
    multiplied by an integer number resulting in an object of the same type.

@li <b>Unary minus</b>: a wxTimeSpan or wxDateSpan object may finally be
    negated giving an interval of the same magnitude but of opposite time
    direction.

For all these operations there are corresponding global (overloaded) operators
and also member functions which are synonyms for them: Add(), Subtract() and
Multiply(). Unary minus as well as composite assignment operations (like +=)
are only implemented as members and Neg() is the synonym for unary minus.



@section overview_datetime_timezones Time zone considerations

Although the time is always stored internally in GMT, you will usually work in
the local time zone. Because of this, all wxDateTime constructors and setters
which take the broken down date assume that these values are for the local
time zone. Thus, @c wxDateTime(1, wxDateTime::Jan, 1970) will not
correspond to the wxDateTime Epoch unless you happen to live in the UK.
All methods returning the date components (year, month, day, hour, minute,
second...) will also return the correct values for the local time zone by
default, so, generally, doing the natural things will lead to natural and
correct results.

If you only want to do this, you may safely skip the rest of this section.
However, if you want to work with different time zones, you should read it to
the end.

In this (rare) case, you are still limited to the local time zone when
constructing wxDateTime objects, i.e. there is no way to construct a
wxDateTime corresponding to the given date in, say, Pacific Standard Time.
To do it, you will need to call wxDateTime::ToTimezone or wxDateTime::MakeTimezone
methods to adjust the date for the target time zone. There are also special
versions of these functions wxDateTime::ToUTC and wxDateTime::MakeUTC for
the most common case - when the date should be constructed in UTC.

You also can just retrieve the value for some time zone without converting the
object to it first. For this you may pass TimeZone argument to any of the
methods which are affected by the time zone (all methods getting date
components and the date formatting ones, for example). In particular, the
Format() family of methods accepts a TimeZone parameter and this allows to
simply print time in any time zone.

To see how to do it, the last issue to address is how to construct a TimeZone
object which must be passed to all these methods. First of all, you may construct
it manually by specifying the time zone offset in seconds from GMT, but
usually you will just use one of the @ref overview_datetime and
let the conversion constructor do the job.

I.e. you would just write

@code
wxDateTime dt(...whatever...);
printf("The time is %s in local time zone", dt.FormatTime().c_str());
printf("The time is %s in GMT", dt.FormatTime(wxDateTime::GMT).c_str());
@endcode



@section overview_datetime_dst Daylight saving time (DST)

DST (a.k.a. 'summer time') handling is always a delicate task which is better
left to the operating system which is supposed to be configured by the
administrator to behave correctly. Unfortunately, when doing calculations with
date outside of the range supported by the standard library, we are forced to
deal with these issues ourselves.

Several functions are provided to calculate the beginning and end of DST in
the given year and to determine whether it is in effect at the given moment or
not, but they should not be considered as absolutely correct because, first of
all, they only work more or less correctly for only a handful of countries
(any information about other ones appreciated!) and even for them the rules
may perfectly well change in the future.

The time zone handling methods (see @ref overview_datetime_timezones) use
these functions too, so they are subject to the same limitations.



@section overview_datetime_holidays wxDateTime and Holidays

@todo WRITE THIS DOC PARAGRAPH.



@section overview_datetime_compat Compatibility

The old classes for date/time manipulations ported from wxWidgets version 1.xx
are still included but are reimplemented in terms of wxDateTime. However, using
them is strongly discouraged because they have a few quirks/bugs and were not
'Y2K' compatible.

*/

