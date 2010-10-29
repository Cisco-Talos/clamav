/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/tglbtn.cpp
// Purpose:     Definition of the wxToggleButton class, which implements a
//              toggle button under wxMSW.
// Author: John Norris, minor changes by Axel Schlueter
// and William Gallafent.
// Modified by:
// Created:     08.02.01
// RCS-ID:      $Id$
// Copyright:   (c) 2000 Johnny C. Norris II
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declatations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_TOGGLEBTN

#include "wx/tglbtn.h"

#ifndef WX_PRECOMP
    #include "wx/button.h"
    #include "wx/brush.h"
    #include "wx/dcscreen.h"
    #include "wx/settings.h"

    #include "wx/log.h"
#endif // WX_PRECOMP

// ----------------------------------------------------------------------------
// macros
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxToggleButton, wxControl)
wxDEFINE_EVENT( wxEVT_COMMAND_TOGGLEBUTTON_CLICKED, wxCommandEvent );

#define BUTTON_HEIGHT_FROM_CHAR_HEIGHT(cy) (11*EDIT_HEIGHT_FROM_CHAR_HEIGHT(cy)/10)

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxToggleButton
// ----------------------------------------------------------------------------

bool wxToggleButton::OS2Command(WXUINT WXUNUSED(param), WXWORD WXUNUSED(id))
{
   wxCommandEvent event(wxEVT_COMMAND_TOGGLEBUTTON_CLICKED, m_windowId);
   event.SetInt(GetValue());
   event.SetEventObject(this);
   ProcessCommand(event);
   return true;
}

// Single check box item
bool wxToggleButton::Create(wxWindow *parent, wxWindowID id,
                            const wxString& label,
                            const wxPoint& pos,
                            const wxSize& size, long style,
                            const wxValidator& validator,
                            const wxString& name)
{
    if ( !CreateControl(parent, id, pos, size, style, validator, name) )
        return false;

    if ( !OS2CreateControl(wxT("BUTTON"), label, pos, size, 0) )
      return false;

    return true;
}

wxBorder wxToggleButton::GetDefaultBorder() const
{
    return wxBORDER_NONE;
}

WXDWORD wxToggleButton::OS2GetStyle(long style, WXDWORD *exstyle) const
{
    WXDWORD msStyle = wxControl::OS2GetStyle(style, exstyle);

#ifndef BS_PUSHLIKE
#define BS_PUSHLIKE 0x00001000L
#endif

    msStyle |= BS_AUTOCHECKBOX | BS_PUSHLIKE | WS_TABSTOP;

    return msStyle;
}

wxSize wxToggleButton::DoGetBestSize() const
{
   wxString                         label = wxGetWindowText(GetHWND());
   int                              wBtn;
   wxFont                           vFont =  GetFont();
   int                              wChar;
   int                              hChar;

   GetTextExtent(label, &wBtn, NULL);


   wxGetCharSize(GetHWND(), &wChar, &hChar, &vFont);

   // add a margin - the button is wider than just its label
   wBtn += 3*wChar;

   // the button height is proportional to the height of the font used
   int hBtn = BUTTON_HEIGHT_FROM_CHAR_HEIGHT(hChar);

#if wxUSE_BUTTON
   wxSize sz = wxButton::GetDefaultSize();
   if (wBtn > sz.x)
       sz.x = wBtn;
   if (hBtn > sz.y)
       sz.y = hBtn;
#else
   wxSize sz(wBtn, hBtn);
#endif

   return sz;
}

void wxToggleButton::SetValue(bool val)
{
   ::WinSendMsg(GetHwnd(), BM_SETCHECK, MPFROMSHORT(val), (MPARAM)0);
}

#ifndef BST_CHECKED
#define BST_CHECKED 0x0001
#endif

bool wxToggleButton::GetValue() const
{
   return (::WinSendMsg(GetHwnd(), BM_QUERYCHECK, 0, 0) == (MRESULT)BST_CHECKED);
}

void wxToggleButton::Command(wxCommandEvent & event)
{
   SetValue((event.GetInt() != 0));
   ProcessCommand(event);
}

#endif // wxUSE_TOGGLEBTN
