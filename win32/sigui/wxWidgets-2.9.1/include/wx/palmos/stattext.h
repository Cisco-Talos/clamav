/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/stattext.h
// Purpose:     wxStaticText class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by: Wlodzimierz ABX Skiba - native wxStaticText implementation
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne, Wlodzimierz Skiba
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_STATTEXT_H_
#define _WX_STATTEXT_H_

class WXDLLIMPEXP_CORE wxStaticText : public wxStaticTextBase
{
public:
    wxStaticText() { }

    wxStaticText(wxWindow *parent,
                 wxWindowID id,
                 const wxString& label,
                 const wxPoint& pos = wxDefaultPosition,
                 const wxSize& size = wxDefaultSize,
                 long style = 0,
                 const wxString& name = wxStaticTextNameStr)
    {
        Create(parent, id, label, pos, size, style, name);
    }

    bool Create(wxWindow *parent,
                wxWindowID id,
                const wxString& label,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = 0,
                const wxString& name = wxStaticTextNameStr);

    // override some methods to resize the window properly
    virtual bool SetFont( const wxFont &font );

protected:
    // implement/override some base class virtuals
    virtual wxBorder GetDefaultBorder() const;
    virtual wxSize DoGetBestSize() const;

    DECLARE_DYNAMIC_CLASS_NO_COPY(wxStaticText)
};

#endif
    // _WX_STATTEXT_H_
