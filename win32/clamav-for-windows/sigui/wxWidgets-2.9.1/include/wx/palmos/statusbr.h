///////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/statusbr.h
// Purpose:     Palm OS implementation of wxStatusBar
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

#ifndef   _WX_STATUSBR_H_
#define   _WX_STATUSBR_H_

#if wxUSE_NATIVE_STATUSBAR

class WXDLLIMPEXP_CORE wxStatusBarPalm : public wxStatusBarBase
{
public:
    // ctors and such
    wxStatusBarPalm();
    wxStatusBarPalm(wxWindow *parent,
                    wxWindowID id = wxID_ANY,
                    long style = wxSTB_DEFAULT_STYLE,
                    const wxString& name = wxEmptyString)
    {
        (void)Create(parent, id, style, name);
    }

    bool Create(wxWindow *parent,
                wxWindowID id = wxID_ANY,
                long style = wxSTB_DEFAULT_STYLE,
                const wxString& name = wxEmptyString);

    virtual ~wxStatusBarPalm();

    // for native status bar use native check for visibility
    virtual bool IsShown() const;
    virtual bool Show( bool show = true );

    // a status line can have several (<256) fields numbered from 0
    virtual void SetFieldsCount(int number = 1, const int *widths = NULL);

    // implement base class methods
    virtual void SetStatusWidths(int n, const int widths_field[]);
    virtual void SetMinHeight(int height);
    virtual bool GetFieldRect(int i, wxRect& rect) const;

    virtual int GetBorderX() const;
    virtual int GetBorderY() const;

    void DrawStatusBar();

protected:
    virtual void DoUpdateStatusText(int nField);

    void CopyFieldsWidth(const int widths[]);
    void SetFieldsWidth();
/*
    // store the text in the status bar
    wxListString **StatusTextBuffer;
    void SetStatusBufferText(const wxString& text, int number);
    wxString GetStatusBufferText(int number);
    wxListString *GetOrCreateStatusBuffer(int i);
    wxListString *GetStatusBufferStack(int i) const;
    void DeleteStatusBuffer();

    TODO: reuse wxStatusBarBase's stack routines instead of reimplementing them here
*/

    // override base class virtual
    void DoMoveWindow(int x, int y, int width, int height);

private:
    DECLARE_DYNAMIC_CLASS_NO_COPY(wxStatusBarPalm)
};

#endif  // wxUSE_NATIVE_STATUSBAR

#endif
