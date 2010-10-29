/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/radiobox.h
// Purpose:     wxRadioBox class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by: Wlodzimierz ABX Skiba - native wxRadioBox implementation
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne, Wlodzimierz Skiba
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_RADIOBOX_H_
#define _WX_RADIOBOX_H_

class WXDLLIMPEXP_FWD_CORE wxBitmap;
class WXDLLIMPEXP_FWD_CORE wxRadioButton;

// ----------------------------------------------------------------------------
// wxRadioBox
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxRadioBox : public wxControl, public wxRadioBoxBase
{
public:
    wxRadioBox():m_radios(wxKEY_INTEGER,32)
    {
        Init();
    }

    wxRadioBox(wxWindow *parent,
               wxWindowID id,
               const wxString& title,
               const wxPoint& pos = wxDefaultPosition,
               const wxSize& size = wxDefaultSize,
               int n = 0, const wxString choices[] = NULL,
               int majorDim = 0,
               long style = wxRA_SPECIFY_COLS,
               const wxValidator& val = wxDefaultValidator,
               const wxString& name = wxRadioBoxNameStr)
              :m_radios(wxKEY_INTEGER,n+1)
    {
        Init();
        (void)Create(parent, id, title, pos, size, n, choices, majorDim,
                     style, val, name);
    }

    wxRadioBox(wxWindow *parent,
               wxWindowID id,
               const wxString& title,
               const wxPoint& pos,
               const wxSize& size,
               const wxArrayString& choices,
               int majorDim = 0,
               long style = wxRA_SPECIFY_COLS,
               const wxValidator& val = wxDefaultValidator,
               const wxString& name = wxRadioBoxNameStr)
              :m_radios(wxKEY_INTEGER,choices.GetCount()+1)
    {
        Init();
        (void)Create(parent, id, title, pos, size, choices, majorDim,
                     style, val, name);
    }

    virtual ~wxRadioBox();

    bool Create(wxWindow *parent,
                wxWindowID id,
                const wxString& title,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                int n = 0, const wxString choices[] = NULL,
                int majorDim = 0,
                long style = wxRA_SPECIFY_COLS,
                const wxValidator& val = wxDefaultValidator,
                const wxString& name = wxRadioBoxNameStr);

    bool Create(wxWindow *parent,
                wxWindowID id,
                const wxString& title,
                const wxPoint& pos,
                const wxSize& size,
                const wxArrayString& choices,
                int majorDim = 0,
                long style = wxRA_SPECIFY_COLS,
                const wxValidator& val = wxDefaultValidator,
                const wxString& name = wxRadioBoxNameStr);

    // Enabling
    virtual bool Enable(bool enable = true);
    virtual bool Enable(unsigned int n, bool enable = true);
    virtual bool IsItemEnabled(unsigned int WXUNUSED(n)) const
    {
        /* TODO */
        return true;
    }

    // Showing
    virtual bool Show(bool show = true);
    virtual bool Show(unsigned int n, bool show = true);
    virtual bool IsItemShown(unsigned int WXUNUSED(n)) const
    {
        /* TODO */
        return true;
    }

    // implement the radiobox interface
    virtual void SetSelection(int n);
    virtual int GetSelection() const;
    virtual unsigned int GetCount() const;
    virtual wxString GetString(unsigned int n) const;
    virtual void SetString(unsigned int n, const wxString& label);

    virtual void SetLabel(const wxString& label);
    virtual wxString GetLabel();

    virtual void DoGetPosition( int *x, int *y ) const;
    virtual void DoGetSize( int *width, int *height ) const;
    virtual void DoMoveWindow(int x, int y, int width, int height);

    virtual wxPoint GetClientAreaOrigin() const;

    void SetFocus();
    void SetLabelFont(const wxFont& WXUNUSED(font)) {};
    void SetButtonFont(const wxFont& font) { SetFont(font); }

    virtual void Refresh( bool eraseBackground = true,
                          const wxRect *rect = NULL );

    void Command(wxCommandEvent& event);

    int GetNumberOfRowsOrCols() const { return m_noRowsOrCols; }
    void SetNumberOfRowsOrCols(int n) { m_noRowsOrCols = n; }

    // implementation only from now on
    // -------------------------------

    virtual bool SetFont(const wxFont& font);

    void SendNotificationEvent();

protected:
    // get the max size of radio buttons
    wxSize GetMaxButtonSize() const;

    // get the total size occupied by the radio box buttons
    wxSize GetTotalButtonSize(const wxSize& sizeBtn) const;

    int *m_radioWidth;  // for bitmaps
    int *m_radioHeight;

    int  m_noRowsOrCols;
    int  m_selectedButton;

    virtual wxSize DoGetBestSize() const;

private:

    void Init();
    wxRadioButton *GetRadioButton(int i) const;

    wxPoint m_pos;
    wxSize m_size;
    wxHashTable m_radios;

    DECLARE_DYNAMIC_CLASS(wxRadioBox)
    wxDECLARE_NO_COPY_CLASS(wxRadioBox);
};

#endif
    // _WX_RADIOBOX_H_
