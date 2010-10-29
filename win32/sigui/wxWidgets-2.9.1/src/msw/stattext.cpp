/////////////////////////////////////////////////////////////////////////////
// Name:        src/msw/stattext.cpp
// Purpose:     wxStaticText
// Author:      Julian Smart
// Modified by:
// Created:     04/01/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
#pragma hdrstop
#endif

#if wxUSE_STATTEXT

#include "wx/stattext.h"

#ifndef WX_PRECOMP
    #include "wx/event.h"
    #include "wx/app.h"
    #include "wx/brush.h"
    #include "wx/dcclient.h"
    #include "wx/settings.h"
#endif

#include "wx/msw/private.h"

#if wxUSE_EXTENDED_RTTI
WX_DEFINE_FLAGS( wxStaticTextStyle )

wxBEGIN_FLAGS( wxStaticTextStyle )
    // new style border flags, we put them first to
    // use them for streaming out
    wxFLAGS_MEMBER(wxBORDER_SIMPLE)
    wxFLAGS_MEMBER(wxBORDER_SUNKEN)
    wxFLAGS_MEMBER(wxBORDER_DOUBLE)
    wxFLAGS_MEMBER(wxBORDER_RAISED)
    wxFLAGS_MEMBER(wxBORDER_STATIC)
    wxFLAGS_MEMBER(wxBORDER_NONE)

    // old style border flags
    wxFLAGS_MEMBER(wxSIMPLE_BORDER)
    wxFLAGS_MEMBER(wxSUNKEN_BORDER)
    wxFLAGS_MEMBER(wxDOUBLE_BORDER)
    wxFLAGS_MEMBER(wxRAISED_BORDER)
    wxFLAGS_MEMBER(wxSTATIC_BORDER)
    wxFLAGS_MEMBER(wxBORDER)

    // standard window styles
    wxFLAGS_MEMBER(wxTAB_TRAVERSAL)
    wxFLAGS_MEMBER(wxCLIP_CHILDREN)
    wxFLAGS_MEMBER(wxTRANSPARENT_WINDOW)
    wxFLAGS_MEMBER(wxWANTS_CHARS)
    wxFLAGS_MEMBER(wxFULL_REPAINT_ON_RESIZE)
    wxFLAGS_MEMBER(wxALWAYS_SHOW_SB )
    wxFLAGS_MEMBER(wxVSCROLL)
    wxFLAGS_MEMBER(wxHSCROLL)

    wxFLAGS_MEMBER(wxST_NO_AUTORESIZE)
    wxFLAGS_MEMBER(wxALIGN_LEFT)
    wxFLAGS_MEMBER(wxALIGN_RIGHT)
    wxFLAGS_MEMBER(wxALIGN_CENTRE)

wxEND_FLAGS( wxStaticTextStyle )

IMPLEMENT_DYNAMIC_CLASS_XTI(wxStaticText, wxControl,"wx/stattext.h")

wxBEGIN_PROPERTIES_TABLE(wxStaticText)
    wxPROPERTY( Label,wxString, SetLabel, GetLabel, wxString() , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY_FLAGS( WindowStyle , wxStaticTextStyle , long , SetWindowStyleFlag , GetWindowStyleFlag , EMPTY_MACROVALUE, 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // style
wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxStaticText)
wxEND_HANDLERS_TABLE()

wxCONSTRUCTOR_6( wxStaticText , wxWindow* , Parent , wxWindowID , Id , wxString , Label , wxPoint , Position , wxSize , Size , long , WindowStyle )
#else
IMPLEMENT_DYNAMIC_CLASS(wxStaticText, wxControl)
#endif

bool wxStaticText::Create(wxWindow *parent,
                          wxWindowID id,
                          const wxString& label,
                          const wxPoint& pos,
                          const wxSize& size,
                          long style,
                          const wxString& name)
{
    if ( !CreateControl(parent, id, pos, size, style, wxDefaultValidator, name) )
        return false;

    if ( !MSWCreateControl(wxT("STATIC"), wxEmptyString, pos, size) )
        return false;

    // we set the label here and not through MSWCreateControl() because we
    // need to do many operation on it for ellipsization&markup support
    SetLabel(label);

    // as we didn't pass the correct label to MSWCreateControl(), it didn't set
    // the initial size correctly -- do it now
    InvalidateBestSize();
    SetInitialSize(size);

    // NOTE: if the label contains ampersand characters which are interpreted as
    //       accelerators, they will be rendered (at least on WinXP) only if the
    //       static text is placed inside a window class which correctly handles
    //       focusing by TAB traversal (e.g. wxPanel).

    return true;
}

WXDWORD wxStaticText::MSWGetStyle(long style, WXDWORD *exstyle) const
{
    WXDWORD msStyle = wxControl::MSWGetStyle(style, exstyle);

    // translate the alignment flags to the Windows ones
    //
    // note that both wxALIGN_LEFT and SS_LEFT are equal to 0 so we shouldn't
    // test for them using & operator
    if ( style & wxALIGN_CENTRE )
        msStyle |= SS_CENTER;
    else if ( style & wxALIGN_RIGHT )
        msStyle |= SS_RIGHT;
    else
        msStyle |= SS_LEFT;

#ifdef SS_ENDELLIPSIS
    // this style is necessary to receive mouse events
    // Win NT and later have the SS_ENDELLIPSIS style which is useful to us:
    if (wxGetOsVersion() == wxOS_WINDOWS_NT)
    {
        // for now, add the SS_ENDELLIPSIS style if wxST_ELLIPSIZE_END is given;
        // we may need to remove it later in ::SetLabel() if the given label
        // has newlines
        if ( style & wxST_ELLIPSIZE_END )
            msStyle |= SS_ENDELLIPSIS;
    }
#endif // SS_ENDELLIPSIS

    msStyle |= SS_NOTIFY;

    return msStyle;
}

wxSize wxStaticText::DoGetBestClientSize() const
{
    wxClientDC dc(const_cast<wxStaticText *>(this));
    wxFont font(GetFont());
    if (!font.Ok())
        font = wxSystemSettings::GetFont(wxSYS_DEFAULT_GUI_FONT);

    dc.SetFont(font);

    wxCoord widthTextMax, heightTextTotal;
    dc.GetMultiLineTextExtent(GetLabelText(), &widthTextMax, &heightTextTotal);

#ifdef __WXWINCE__
    if ( widthTextMax )
        widthTextMax += 2;
#endif // __WXWINCE__

    return wxSize(widthTextMax, heightTextTotal);
}

void wxStaticText::DoSetSize(int x, int y, int w, int h, int sizeFlags)
{
    // note: we first need to set the size and _then_ call UpdateLabel
    wxStaticTextBase::DoSetSize(x, y, w, h, sizeFlags);

#ifdef SS_ENDELLIPSIS
    // do we need to ellipsize the contents?
    long styleReal = ::GetWindowLong(GetHwnd(), GWL_STYLE);
    if ( !(styleReal & SS_ENDELLIPSIS) )
    {
        // we don't have SS_ENDELLIPSIS style:
        // we need to (eventually) do ellipsization ourselves
        UpdateLabel();
    }
    //else: we don't or the OS will do it for us
#endif // SS_ENDELLIPSIS

    // we need to refresh the window after changing its size as the standard
    // control doesn't always update itself properly
    Refresh();
}

void wxStaticText::SetLabel(const wxString& label)
{
#ifdef SS_ENDELLIPSIS
    long styleReal = ::GetWindowLong(GetHwnd(), GWL_STYLE);
    if ( HasFlag(wxST_ELLIPSIZE_END) &&
          wxGetOsVersion() == wxOS_WINDOWS_NT )
    {
        // adding SS_ENDELLIPSIS or SS_ENDELLIPSIS "disables" the correct
        // newline handling in static texts: the newlines in the labels are
        // shown as square. Thus we don't use it even on newer OS when
        // the static label contains a newline.
        if ( label.Contains(wxT('\n')) )
            styleReal &= ~SS_ENDELLIPSIS;
        else
            styleReal |= SS_ENDELLIPSIS;

        ::SetWindowLong(GetHwnd(), GWL_STYLE, styleReal);
    }
    else // style not supported natively
    {
        styleReal &= ~SS_ENDELLIPSIS;
        ::SetWindowLong(GetHwnd(), GWL_STYLE, styleReal);
    }
#endif // SS_ENDELLIPSIS

    // save the label in m_labelOrig with both the markup (if any) and 
    // the mnemonics characters (if any)
    m_labelOrig = label;

#ifdef SS_ENDELLIPSIS
    if ( styleReal & SS_ENDELLIPSIS )
        DoSetLabel(GetLabelWithoutMarkup());
    else
#endif // SS_ENDELLIPSIS
        DoSetLabel(GetEllipsizedLabelWithoutMarkup());

    // adjust the size of the window to fit to the label unless autoresizing is
    // disabled
    if ( !HasFlag(wxST_NO_AUTORESIZE) &&
         !IsEllipsized() )  // if ellipsize is ON, then we don't want to get resized!
    {
        InvalidateBestSize();
        DoSetSize(wxDefaultCoord, wxDefaultCoord, wxDefaultCoord, wxDefaultCoord,
                  wxSIZE_AUTO_WIDTH | wxSIZE_AUTO_HEIGHT);
    }
}

bool wxStaticText::SetFont(const wxFont& font)
{
    bool ret = wxControl::SetFont(font);

    // adjust the size of the window to fit to the label unless autoresizing is
    // disabled
    if ( !HasFlag(wxST_NO_AUTORESIZE) )
    {
        InvalidateBestSize();
        DoSetSize(wxDefaultCoord, wxDefaultCoord, wxDefaultCoord, wxDefaultCoord,
                  wxSIZE_AUTO_WIDTH | wxSIZE_AUTO_HEIGHT);
    }

    return ret;
}

// for wxST_ELLIPSIZE_* support:

wxString wxStaticText::DoGetLabel() const
{
    return wxGetWindowText(GetHwnd());
}

void wxStaticText::DoSetLabel(const wxString& str)
{
    SetWindowText(GetHwnd(), str.c_str());
}


#endif // wxUSE_STATTEXT
