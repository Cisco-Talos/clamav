/////////////////////////////////////////////////////////////////////////////
// Name:        wx/generic/stattextg.h
// Purpose:     wxGenericStaticText header
// Author:      Marcin Wojdyr
// Created:     2008-06-26
// Id:          $Id$
// Copyright:   Marcin Wojdyr
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_GENERIC_STATTEXTG_H_
#define _WX_GENERIC_STATTEXTG_H_

// prevent it from including the platform-specific wxStaticText declaration as
// this is not going to compile if it derives from wxGenericStaticText defined
// below (currently this is only the case in wxUniv but it could also happen
// with other ports)
#define wxNO_PORT_STATTEXT_INCLUDE
#include "wx/stattext.h"
#undef wxNO_PORT_STATTEXT_INCLUDE

class WXDLLIMPEXP_CORE wxGenericStaticText : public wxStaticTextBase
{
public:
    wxGenericStaticText() { }

    wxGenericStaticText(wxWindow *parent,
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


    // overridden base class virtual methods
    virtual void SetLabel(const wxString& label);
    virtual bool SetFont(const wxFont &font);

protected:
    virtual wxSize DoGetBestClientSize() const;

    virtual wxString DoGetLabel() const { return m_label; }
    virtual void DoSetLabel(const wxString& label);

    void DoSetSize(int x, int y, int width, int height, int sizeFlags);

private:
    void OnPaint(wxPaintEvent& event);

    wxString m_label;
    int m_mnemonic;

    DECLARE_DYNAMIC_CLASS_NO_COPY(wxGenericStaticText)
};

#endif // _WX_GENERIC_STATTEXTG_H_

