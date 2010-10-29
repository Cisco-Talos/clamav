///////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/textentry.cpp
// Purpose:     wxTextEntry implementation for wxOS2
// Author:      Stefan Neis
// Created:     2007-11-18
// RCS-ID:      $Id$
// Copyright:   (c) 2007 Stefan Neis
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
    #include "wx/arrstr.h"
    #include "wx/string.h"
#endif // WX_PRECOMP

#if wxUSE_TEXTCTRL || wxUSE_COMBOBOX

#include "wx/textentry.h"
#include "wx/dynlib.h"

#include "wx/os2/private.h"

#define GetEditHwnd() ((HWND)(GetEditHWND()))

// ============================================================================
// wxTextEntry implementation
// ============================================================================

// ----------------------------------------------------------------------------
// operations on text
// ----------------------------------------------------------------------------

void wxTextEntry::WriteText(const wxString& text)
{
    wxString newText = wxGetWindowText(GetEditHWND());
    long from, to;
    GetSelection(&from, &to);
    if (from > to){
      long swp = to;
      to = from;
      from = swp;
    }
    // Compose the new Text by replacing the selection of the old text
    newText.replace(from, to - from, text);
    // Set control to the new text
    ::WinSetWindowText(GetEditHwnd(), text.c_str());
}

wxString wxTextEntry::DoGetValue() const
{
    return wxGetWindowText(GetEditHWND());
}

void wxTextEntry::Remove(long from, long to)
{
    DoSetSelection(from, to, SetSel_NoScroll);
    WriteText(wxString());
}

// ----------------------------------------------------------------------------
// clipboard operations
// ----------------------------------------------------------------------------

void wxTextEntry::Copy()
{
    ::WinSendMsg(GetEditHwnd(), EM_COPY, 0, 0);
}

void wxTextEntry::Cut()
{
    ::WinSendMsg(GetEditHwnd(), EM_CUT, 0, 0);
}

void wxTextEntry::Paste()
{
    ::WinSendMsg(GetEditHwnd(), EM_PASTE, 0, 0);
}

// ----------------------------------------------------------------------------
// undo/redo
// ----------------------------------------------------------------------------

void wxTextEntry::Undo()
{
}

void wxTextEntry::Redo()
{
    // same as Undo, since Undo undoes the undo
    Undo();
    return;
}

bool wxTextEntry::CanUndo() const
{
    return false;
}

bool wxTextEntry::CanRedo() const
{
    // see comment in Redo()
    return CanUndo();
}

// ----------------------------------------------------------------------------
// insertion point and selection
// ----------------------------------------------------------------------------

void wxTextEntry::SetInsertionPoint(long pos)
{
    // be careful to call DoSetSelection() which is overridden in wxTextCtrl
    // and not just SetSelection() here
    DoSetSelection(pos, pos);
}

long wxTextEntry::GetInsertionPoint() const
{
    long from;
    GetSelection(&from, NULL);
    return from;
}

long wxTextEntry::GetLastPosition() const
{
    WNDPARAMS                   vParams;

    vParams.fsStatus = WPM_CCHTEXT;
    if (::WinSendMsg( GetEditHwnd()
                     ,WM_QUERYWINDOWPARAMS
                     ,&vParams
                     ,0
                    ))
    {
        return vParams.cchText;
    }
    return 0;
}

void wxTextEntry::DoSetSelection(long from, long to, int WXUNUSED(flags))
{
    // if from and to are both -1, it means (in wxWidgets) that all text should
    // be selected, translate this into Windows convention
    if ( (from == -1) && (to == -1) )
    {
        from = 0;
    }

    ::WinSendMsg(GetEditHwnd(), EM_SETSEL, MPFROM2SHORT((USHORT)from, (USHORT)to), 0);
}

void wxTextEntry::GetSelection(long *from, long *to) const
{
    long dwPos;
    dwPos = (long)::WinSendMsg(GetEditHwnd(), EM_QUERYSEL, 0, 0);

    if ( from )
        *from = SHORT1FROMMP((MPARAM)dwPos);
    if ( to )
        *to = SHORT2FROMMP((MPARAM)dwPos);
}

// ----------------------------------------------------------------------------
// editable state
// ----------------------------------------------------------------------------

bool wxTextEntry::IsEditable() const
{
    return (bool)LONGFROMMR(::WinSendMsg(GetEditHwnd(), EM_QUERYREADONLY, 0, 0));
}

void wxTextEntry::SetEditable(bool editable)
{
    ::WinSendMsg(GetEditHwnd(), EM_SETREADONLY, MPFROMLONG(!editable), 0);
}

// ----------------------------------------------------------------------------
// max length
// ----------------------------------------------------------------------------

void wxTextEntry::SetMaxLength(unsigned long len)
{
    if ( len >= 0x7fff )
    {
        // this will set it to a platform-specific maximum (32Kb under OS/2)
        len = 0x7fff;
    }

    ::WinSendMsg(GetEditHwnd(), EM_SETTEXTLIMIT, MPFROMSHORT(len), 0);
}

#endif // wxUSE_TEXTCTRL || wxUSE_COMBOBOX
