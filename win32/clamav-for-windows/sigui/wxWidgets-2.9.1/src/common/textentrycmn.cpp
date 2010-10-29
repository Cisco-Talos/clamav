///////////////////////////////////////////////////////////////////////////////
// Name:        src/common/textentrycmn.cpp
// Purpose:     wxTextEntryBase implementation
// Author:      Vadim Zeitlin
// Created:     2007-09-26
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

#if wxUSE_TEXTCTRL || wxUSE_COMBOBOX

#ifndef WX_PRECOMP
    #include "wx/window.h"
    #include "wx/dataobj.h"
#endif //WX_PRECOMP

#include "wx/textentry.h"
#include "wx/clipbrd.h"

// ----------------------------------------------------------------------------
// wxTextEntryHintData
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxTextEntryHintData wxBIND_OR_CONNECT_HACK_ONLY_BASE_CLASS
{
public:
    wxTextEntryHintData(wxTextEntryBase *entry, wxWindow *win)
        : m_entry(entry),
          m_win(win)
    {
        wxBIND_OR_CONNECT_HACK(win, wxEVT_SET_FOCUS, wxFocusEventHandler,
                                wxTextEntryHintData::OnSetFocus, this);
        wxBIND_OR_CONNECT_HACK(win, wxEVT_KILL_FOCUS, wxFocusEventHandler,
                                wxTextEntryHintData::OnKillFocus, this);

        // we don't have any hint yet
        m_showsHint = false;
    }

    // default dtor is ok

    // are we showing the hint right now?
    bool ShowsHint() const { return m_showsHint; }

    void SetHintString(const wxString& hint)
    {
        m_hint = hint;

        if ( m_showsHint )
        {
            // update it immediately
            m_entry->ChangeValue(hint);
        }
        //else: the new hint will be shown later
    }

    const wxString& GetHintString() const { return m_hint; }

private:
    void OnSetFocus(wxFocusEvent& event)
    {
        // hide the hint if we were showing it
        if ( m_showsHint )
        {
            // Clear() would send an event which we don't want, so do it like
            // this
            m_entry->ChangeValue(wxString());
            m_win->SetForegroundColour(m_colFg);

            m_showsHint = false;
        }

        event.Skip();
    }

    void OnKillFocus(wxFocusEvent& event)
    {
        // restore the hint if the user didn't do anything in the control
        if ( m_entry->IsEmpty() )
        {
            m_entry->ChangeValue(m_hint);

            m_colFg = m_win->GetForegroundColour();
            m_win->SetForegroundColour(*wxLIGHT_GREY);

            m_showsHint = true;
        }

        event.Skip();
    }

    // the text control we're associated with (as its interface and its window)
    wxTextEntryBase * const m_entry;
    wxWindow * const m_win;

    // the original foreground colour of m_win before we changed it
    wxColour m_colFg;

    // the hint passed to wxTextEntry::SetHint()
    wxString m_hint;

    // true if we're currently showing it, for this we must be empty and not
    // have focus
    bool m_showsHint;

    wxDECLARE_NO_COPY_CLASS(wxTextEntryHintData);
};

// ============================================================================
// wxTextEntryBase implementation
// ============================================================================

wxTextEntryBase::~wxTextEntryBase()
{
    delete m_hintData;
}

// ----------------------------------------------------------------------------
// text accessors
// ----------------------------------------------------------------------------

wxString wxTextEntryBase::GetValue() const
{
    return m_hintData && m_hintData->ShowsHint() ? wxString() : DoGetValue();
}

wxString wxTextEntryBase::GetRange(long from, long to) const
{
    wxString sel;
    wxString value = GetValue();

    if ( from < to && (long)value.length() >= to )
    {
        sel = value.substr(from, to - from);
    }

    return sel;
}

// ----------------------------------------------------------------------------
// text operations
// ----------------------------------------------------------------------------

void wxTextEntryBase::AppendText(const wxString& text)
{
    SetInsertionPointEnd();
    WriteText(text);
}

void wxTextEntryBase::DoSetValue(const wxString& value, int flags)
{
    EventsSuppressor noeventsIf(this, !(flags & SetValue_SendEvent));

    SelectAll();
    WriteText(value);

    SetInsertionPoint(0);
}

void wxTextEntryBase::Replace(long from, long to, const wxString& value)
{
    {
        EventsSuppressor noevents(this);
        Remove(from, to);
    }

    SetInsertionPoint(from);
    WriteText(value);
}

// ----------------------------------------------------------------------------
// selection
// ----------------------------------------------------------------------------

bool wxTextEntryBase::HasSelection() const
{
    long from, to;
    GetSelection(&from, &to);

    return from < to;
}

void wxTextEntryBase::RemoveSelection()
{
    long from, to;
    GetSelection(& from, & to);
    if (from != -1 && to != -1)
        Remove(from, to);
}

wxString wxTextEntryBase::GetStringSelection() const
{
    long from, to;
    GetSelection(&from, &to);

    return GetRange(from, to);
}

// ----------------------------------------------------------------------------
// clipboard
// ----------------------------------------------------------------------------

bool wxTextEntryBase::CanCopy() const
{
    return HasSelection();
}

bool wxTextEntryBase::CanCut() const
{
    return CanCopy() && IsEditable();
}

bool wxTextEntryBase::CanPaste() const
{
    if ( IsEditable() )
    {
#if wxUSE_CLIPBOARD
        // check if there is any text on the clipboard
        if ( wxTheClipboard->IsSupported(wxDF_TEXT)
#if wxUSE_UNICODE
                || wxTheClipboard->IsSupported(wxDF_UNICODETEXT)
#endif // wxUSE_UNICODE
           )
        {
            return true;
        }
#endif // wxUSE_CLIPBOARD
    }

    return false;
}

// ----------------------------------------------------------------------------
// hints support
// ----------------------------------------------------------------------------

bool wxTextEntryBase::SetHint(const wxString& hint)
{
    if ( !m_hintData )
        m_hintData = new wxTextEntryHintData(this, GetEditableWindow());

    m_hintData->SetHintString(hint);

    return true;
}

wxString wxTextEntryBase::GetHint() const
{
    return m_hintData ? m_hintData->GetHintString() : wxString();
}

// ----------------------------------------------------------------------------
// margins support
// ----------------------------------------------------------------------------

bool wxTextEntryBase::DoSetMargins(const wxPoint& WXUNUSED(pt))
{
    return false;
}

wxPoint wxTextEntryBase::DoGetMargins() const
{
    return wxPoint(-1, -1);
}

// ----------------------------------------------------------------------------
// events
// ----------------------------------------------------------------------------

/* static */
bool wxTextEntryBase::SendTextUpdatedEvent(wxWindow *win)
{
    wxCHECK_MSG( win, false, "can't send an event without a window" );

    wxCommandEvent event(wxEVT_COMMAND_TEXT_UPDATED, win->GetId());

    // do not do this as it could be very inefficient if the text control
    // contains a lot of text and we're not using ref-counted wxString
    // implementation -- instead, event.GetString() will query the control for
    // its current text if needed
    //event.SetString(win->GetValue());

    event.SetEventObject(win);
    return win->HandleWindowEvent(event);
}

#endif // wxUSE_TEXTCTRL || wxUSE_COMBOBOX
