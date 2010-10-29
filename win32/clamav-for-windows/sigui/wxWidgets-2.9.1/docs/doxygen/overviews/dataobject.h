/////////////////////////////////////////////////////////////////////////////
// Name:        dataobject.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_dataobject wxDataObject Overview

Classes: wxDataObject, wxClipboard, wxDataFormat, wxDropSource, wxDropTarget

See also: @ref overview_dnd and @ref page_samples_dnd

This overview discusses data transfer through clipboard or drag and drop.
In wxWidgets, these two ways to transfer data (either between different
applications or inside one and the same) are very similar which allows to
implement both of them using almost the same code - or, in other
words, if you implement drag and drop support for your application, you get
clipboard support for free and vice versa.

At the heart of both clipboard and drag and drop operations lies the
wxDataObject class. The objects of this class (or, to
be precise, classes derived from it) represent the data which is being carried
by the mouse during drag and drop operation or copied to or pasted from the
clipboard. wxDataObject is a "smart" piece of data because it knows which
formats it supports (see GetFormatCount and GetAllFormats) and knows how to
render itself in any of them (see GetDataHere). It can also receive its value
from the outside in a format it supports if it implements the SetData method.
Please see the documentation of this class for more details.

Both clipboard and drag and drop operations have two sides: the source and
target, the data provider and the data receiver. These which may be in the same
application and even the same window when, for example, you drag some text from
one position to another in a word processor. Let us describe what each of them
should do.

@li @ref overview_dataobject_source
@li @ref overview_dataobject_target


<hr>


@section overview_dataobject_source The data provider (source) duties

The data provider is responsible for creating a wxDataObject containing the
data to be transferred. Then it should either pass it to the clipboard using
wxClipboard::SetData function or to wxDropSource and call wxDropSource::DoDragDrop
function.

The only (but important) difference is that the object for the clipboard
transfer must always be created on the heap (i.e. using @c new) and it will
be freed by the clipboard when it is no longer needed (indeed, it is not known
in advance when, if ever, the data will be pasted from the clipboard). On the
other hand, the object for drag and drop operation must only exist while
wxDropSource::DoDragDrop executes and may be safely deleted afterwards and so
can be created either on heap or on stack (i.e. as a local variable).

Another small difference is that in the case of clipboard operation, the
application usually knows in advance whether it copies or cuts (i.e. copies and
deletes) data - in fact, this usually depends on which menu item the user
chose. But for drag and drop it can only know it after
wxDropSource::DoDragDrop returns (from its return value).


@section overview_dataobject_target The data receiver (target) duties

To receive (paste in usual terminology) data from the clipboard, you should
create a wxDataObject derived class which supports the data formats you need
and pass it as argument to wxClipboard::GetData. If it returns @false,
no data in (any of) the supported format(s) is available. If it returns @true,
the data has been successfully transferred to wxDataObject.

For drag and drop case, the wxDropTarget::OnData virtual function will be called
when a data object is dropped, from which the data itself may be requested by calling
wxDropTarget::GetData method which fills the data object.

*/

