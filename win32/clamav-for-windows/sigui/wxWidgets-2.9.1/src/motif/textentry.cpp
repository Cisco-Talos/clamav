///////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/textentry.cpp
// Purpose:     implementation of wxTextEntry for wxMotif
// Author:      Vadim Zeitlin
// Created:     2007-11-05
// RCS-ID:      $Id$
// Copyright:   (c) 2007 Vadim Zeitlin <vadim@wxwindows.org>
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// for compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include "wx/string.h"
    #include "wx/window.h"
#endif //WX_PRECOMP

#include "wx/textentry.h"

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/Text.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

// return the text widget casted to the correct type
#define GetText() ((Widget)this->GetTextWidget())

// ============================================================================
// wxTextEntry implementation
// ============================================================================

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

long wxTextEntry::GetMotifPos(long pos) const
{
    // in wx API position -1 means "last one" but for Motif position must be
    // positive, i.e. it doesn't have this convention, so translate
    return pos == -1 ? GetLastPosition() : pos;
}

// ----------------------------------------------------------------------------
// operations on control text
// ----------------------------------------------------------------------------

wxString wxTextEntry::DoGetValue() const
{
    wxString str;

    char * const s = XmTextGetString(GetText());
    if ( s )
    {
        str = s;
        XtFree(s);
    }

    return str;
}

void wxTextEntry::WriteText(const wxString& text)
{
    long pos = GetInsertionPoint();

    XmTextInsert(GetText(), pos, text.char_str());

    pos += text.length();

    XtVaSetValues(GetText(), XmNcursorPosition, pos, NULL);
    SetInsertionPoint(pos);
    XmTextShowPosition(GetText(), pos);
}

void wxTextEntry::Replace(long from, long to, const wxString& value)
{
    XmTextReplace(GetText(), from, GetMotifPos(to), value.char_str());
}

void wxTextEntry::Remove(long from, long to)
{
    SetSelection(from, to);
    XmTextRemove(GetText());
}

// ----------------------------------------------------------------------------
// clipboard operations
// ----------------------------------------------------------------------------

void wxTextEntry::Copy()
{
    XmTextCopy(GetText(), CurrentTime);
}

void wxTextEntry::Cut()
{
    XmTextCut(GetText(), CurrentTime);
}

void wxTextEntry::Paste()
{
    XmTextPaste(GetText());
}

// ----------------------------------------------------------------------------
// undo/redo (not implemented)
// ----------------------------------------------------------------------------

void wxTextEntry::Undo()
{
}

void wxTextEntry::Redo()
{
}

bool wxTextEntry::CanUndo() const
{
    return false;
}

bool wxTextEntry::CanRedo() const
{
    return false;
}

// ----------------------------------------------------------------------------
// insertion point
// ----------------------------------------------------------------------------

void wxTextEntry::SetInsertionPoint(long pos)
{
    XmTextSetInsertionPosition(GetText(), GetMotifPos(pos));
}

long wxTextEntry::GetInsertionPoint() const
{
    return XmTextGetInsertionPosition(GetText());
}

wxTextPos wxTextEntry::GetLastPosition() const
{
    return XmTextGetLastPosition(GetText());
}

// ----------------------------------------------------------------------------
// selection
// ----------------------------------------------------------------------------

void wxTextEntry::GetSelection(long* from, long* to) const
{
    XmTextPosition left, right;
    if ( !XmTextGetSelectionPosition(GetText(), &left, &right) )
    {
        // no selection, for compatibility with wxMSW return empty range at
        // cursor position
        left =
        right = GetInsertionPoint();
    }

    if ( from )
        *from = left;
    if ( to )
        *to = right;
}

void wxTextEntry::SetSelection(long from, long to)
{
    XmTextSetSelection(GetText(), from, GetMotifPos(to), CurrentTime);
}


// ----------------------------------------------------------------------------
// editable state
// ----------------------------------------------------------------------------

bool wxTextEntry::IsEditable() const
{
    return XmTextGetEditable(GetText()) != 0;
}

void wxTextEntry::SetEditable(bool editable)
{
    XmTextSetEditable(GetText(), (Boolean) editable);
}

