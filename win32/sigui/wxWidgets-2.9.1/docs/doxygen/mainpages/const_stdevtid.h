/////////////////////////////////////////////////////////////////////////////
// Name:        const_stdevtid.h
// Purpose:     std event values enumerated
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////


/**

@page page_stdevtid Standard event identifiers

wxWidgets defines a special identifier value @c wxID_ANY which is used in
the following two situations:

@li when creating a new window you may specify @c wxID_ANY to let
    wxWidgets assign an unused identifier to it automatically
@li when installing an event handler using either the event table
    macros or wxEvtHandler::Connect,
    you may use it to indicate that you want to handle the events
    coming from any control, regardless of its identifier

Another standard special identifier value is @c wxID_NONE: this is a value
which is not matched by any other id.

wxWidgets also defines a few standard command identifiers which may be used by
the user code and also are sometimes used by wxWidgets itself. These reserved
identifiers are all in the range between @c wxID_LOWEST and
@c wxID_HIGHEST and, accordingly, the user code should avoid defining its
own constants in this range (e.g. by using wxNewId()).

Refer to ::wxStockID enumeration values for the reference of these IDs.

*/
