/////////////////////////////////////////////////////////////////////////////
// Name:        wx/msgdlgg.h
// Purpose:     common header and base class for wxMessageDialog
// Author:      Julian Smart
// Modified by:
// Created:
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_MSGDLG_H_BASE_
#define _WX_MSGDLG_H_BASE_

#include "wx/defs.h"

#if wxUSE_MSGDLG

#include "wx/dialog.h"
#include "wx/stockitem.h"

WXDLLIMPEXP_DATA_CORE(extern const char) wxMessageBoxCaptionStr[];

// ----------------------------------------------------------------------------
// wxMessageDialogBase: base class defining wxMessageDialog interface
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxMessageDialogBase : public wxDialog
{
public:
    // helper class for SetXXXLabels() methods: it makes it possible to pass
    // either a stock id (wxID_CLOSE) or a string ("&Close") to them
    class ButtonLabel
    {
    public:
        // ctors are not explicit, objects of this class can be implicitly
        // constructed from either stock ids or strings
        ButtonLabel(int stockId)
            : m_stockId(stockId)
        {
            wxASSERT_MSG( wxIsStockID(stockId), "invalid stock id" );
        }

        ButtonLabel(const wxString& label)
            : m_label(label), m_stockId(wxID_NONE)
        {
        }

        ButtonLabel(const char *label)
            : m_label(label), m_stockId(wxID_NONE)
        {
        }

        ButtonLabel(const wchar_t *label)
            : m_label(label), m_stockId(wxID_NONE)
        {
        }

        ButtonLabel(const wxCStrData& label)
            : m_label(label), m_stockId(wxID_NONE)
        {
        }

        // default copy ctor and dtor are ok

        // get the string label, whether it was originally specified directly
        // or as a stock id -- this is only useful for platforms without native
        // stock items id support
        wxString GetAsString() const
        {
            return m_stockId == wxID_NONE
                    ? m_label
                    : wxGetStockLabel(m_stockId, wxSTOCK_FOR_BUTTON);
        }

        // return the stock id or wxID_NONE if this is not a stock label
        int GetStockId() const { return m_stockId; }

    private:
        // the label if explicitly given or empty if this is a stock item
        const wxString m_label;

        // the stock item id or wxID_NONE if m_label should be used
        const int m_stockId;
    };


    // ctors
    wxMessageDialogBase() { m_dialogStyle = 0; }
    wxMessageDialogBase(wxWindow *parent,
                        const wxString& message,
                        const wxString& caption,
                        long style)
        : m_message(message),
          m_caption(caption)
    {
        m_parent = parent;
        SetMessageDialogStyle(style);
    }

    // virtual dtor for the base class
    virtual ~wxMessageDialogBase() { }


    // methods for setting up more custom message dialogs -- all functions
    // return false if they're not implemented
    virtual bool SetYesNoLabels(const ButtonLabel& WXUNUSED(yes),
                                const ButtonLabel& WXUNUSED(no))
    {
        return false;
    }

    virtual bool SetYesNoCancelLabels(const ButtonLabel& WXUNUSED(yes),
                                      const ButtonLabel& WXUNUSED(no),
                                      const ButtonLabel& WXUNUSED(cancel))
    {
        return false;
    }

    virtual bool SetOKLabel(const ButtonLabel& WXUNUSED(ok))
    {
        return false;
    }

    virtual bool SetOKCancelLabels(const ButtonLabel& WXUNUSED(ok),
                                   const ButtonLabel& WXUNUSED(cancel))
    {
        return false;
    }

    virtual void SetMessage(const wxString& message)
    {
        m_message = message;
    }

    virtual void SetExtendedMessage(const wxString& extendedMessage)
    {
        m_extendedMessage = extendedMessage;
    }

    // change the dialog style flag
    void SetMessageDialogStyle(long style)
    {
        wxASSERT_MSG( ((style & wxYES_NO) == wxYES_NO) || !(style & wxYES_NO),
                      "wxYES and wxNO may only be used together" );

        wxASSERT_MSG( !(style & wxYES) || !(style & wxOK),
                      "wxOK and wxYES/wxNO can't be used together" );

        wxASSERT_MSG( (style & wxYES) || (style & wxOK),
                      "one of wxOK and wxYES/wxNO must be used" );

        wxASSERT_MSG( (style & wxID_OK) != wxID_OK,
                      "wxMessageBox: Did you mean wxOK (and not wxID_OK)?" );

        wxASSERT_MSG( !(style & wxNO_DEFAULT) || (style & wxNO),
                      "wxNO_DEFAULT is invalid without wxNO" );

        wxASSERT_MSG( !(style & wxCANCEL_DEFAULT) || (style & wxCANCEL),
                      "wxCANCEL_DEFAULT is invalid without wxCANCEL" );

        wxASSERT_MSG( !(style & wxCANCEL_DEFAULT) || !(style & wxNO_DEFAULT),
                      "only one default button can be specified" );

        m_dialogStyle = style;
    }

protected:
    long GetMessageDialogStyle() const { return m_dialogStyle; }

    // based on message dialog style, returns exactly one of: wxICON_NONE,
    // wxICON_ERROR, wxICON_WARNING, wxICON_QUESTION, wxICON_INFORMATION
    long GetEffectiveIcon() const
    {
        if ( m_dialogStyle & wxICON_NONE )
            return wxICON_NONE;
        else if ( m_dialogStyle & wxICON_ERROR )
            return wxICON_ERROR;
        else if ( m_dialogStyle & wxICON_WARNING )
            return wxICON_WARNING;
        else if ( m_dialogStyle & wxICON_QUESTION )
            return wxICON_QUESTION;
        else if ( m_dialogStyle & wxICON_INFORMATION )
            return wxICON_INFORMATION;
        else if ( m_dialogStyle & wxYES )
            return wxICON_QUESTION;
        else
            return wxICON_INFORMATION;
    }


    // for the platforms not supporting separate main and extended messages
    // this function should be used to combine both of them in a single string
    wxString GetFullMessage() const
    {
        wxString msg = m_message;
        if ( !m_extendedMessage.empty() )
            msg << "\n\n" << m_extendedMessage;

        return msg;
    }

    wxString m_message,
             m_extendedMessage,
             m_caption;
    long m_dialogStyle;

    wxDECLARE_NO_COPY_CLASS(wxMessageDialogBase);
};

// this is a helper class for native wxMessageDialog implementations which need
// to store the custom button labels as member variables and then use them in
// ShowModal() (there could conceivably be a port which would have some native
// functions for setting these labels immediately and we also don't need to
// store them at all if custom labels are not supported, which is why we do
// this in a separate class and not wxMessageDialogBase itself)
#if defined(__WXCOCOA__) || \
    defined(__WXGTK20__) || \
    defined(__WXMAC__) || \
    defined(__WXMSW__)

class WXDLLIMPEXP_CORE wxMessageDialogWithCustomLabels
    : public wxMessageDialogBase
{
public:
    // ctors
    wxMessageDialogWithCustomLabels() { }
    wxMessageDialogWithCustomLabels(wxWindow *parent,
                                    const wxString& message,
                                    const wxString& caption,
                                    long style)
        : wxMessageDialogBase(parent, message, caption, style)
    {
    }

    // customization of the message box buttons
    virtual bool SetYesNoLabels(const ButtonLabel& yes,const ButtonLabel& no)
    {
        DoSetCustomLabel(m_yes, yes);
        DoSetCustomLabel(m_no, no);
        return true;
    }

    virtual bool SetYesNoCancelLabels(const ButtonLabel& yes,
                                      const ButtonLabel& no,
                                      const ButtonLabel& cancel)
    {
        DoSetCustomLabel(m_yes, yes);
        DoSetCustomLabel(m_no, no);
        DoSetCustomLabel(m_cancel, cancel);
        return true;
    }

    virtual bool SetOKLabel(const ButtonLabel& ok)
    {
        DoSetCustomLabel(m_ok, ok);
        return true;
    }

    virtual bool SetOKCancelLabels(const ButtonLabel& ok,
                                   const ButtonLabel& cancel)
    {
        DoSetCustomLabel(m_ok, ok);
        DoSetCustomLabel(m_cancel, cancel);
        return true;
    }

protected:
    // test if any custom labels were set
    bool HasCustomLabels() const
    {
        return !(m_ok.empty() && m_cancel.empty() &&
                 m_yes.empty() && m_no.empty());
    }

    // these functions return the label to be used for the button which is
    // either a custom label explicitly set by the user or the default label,
    // i.e. they always return a valid string
    wxString GetYesLabel() const
        { return m_yes.empty() ? GetDefaultYesLabel() : m_yes; }
    wxString GetNoLabel() const
        { return m_no.empty() ? GetDefaultNoLabel() : m_no; }
    wxString GetOKLabel() const
        { return m_ok.empty() ? GetDefaultOKLabel() : m_ok; }
    wxString GetCancelLabel() const
        { return m_cancel.empty() ? GetDefaultCancelLabel() : m_cancel; }

    // this function is called by our public SetXXXLabels() and should assign
    // the value to var with possibly some transformation (e.g. Cocoa version
    // currently uses this to remove any accelerators from the button strings
    // while GTK+ one handles stock items specifically here)
    virtual void DoSetCustomLabel(wxString& var, const ButtonLabel& label)
    {
        var = label.GetAsString();
    }

private:
    // these functions may be overridden to provide different defaults for the
    // default button labels (this is used by wxGTK)
    virtual wxString GetDefaultYesLabel() const { return wxGetTranslation("Yes"); }
    virtual wxString GetDefaultNoLabel() const { return wxGetTranslation("No"); }
    virtual wxString GetDefaultOKLabel() const { return wxGetTranslation("OK"); }
    virtual wxString GetDefaultCancelLabel() const { return wxGetTranslation("Cancel"); }

    // labels for the buttons, initially empty meaning that the defaults should
    // be used, use GetYes/No/OK/CancelLabel() to access them
    wxString m_yes,
             m_no,
             m_ok,
             m_cancel;

    wxDECLARE_NO_COPY_CLASS(wxMessageDialogWithCustomLabels);
};

#endif // ports needing wxMessageDialogWithCustomLabels

#if defined(__WX_COMPILING_MSGDLGG_CPP__) || \
    defined(__WXUNIVERSAL__) || defined(__WXGPE__) || \
    (defined(__WXGTK__) && !defined(__WXGTK20__))
    #include "wx/generic/msgdlgg.h"

    #define wxMessageDialog wxGenericMessageDialog
#elif defined(__WXCOCOA__)
    #include "wx/cocoa/msgdlg.h"
#elif defined(__WXPALMOS__)
    #include "wx/palmos/msgdlg.h"
#elif defined(__WXMSW__)
    #include "wx/msw/msgdlg.h"
#elif defined(__WXMOTIF__)
    #include "wx/motif/msgdlg.h"
#elif defined(__WXGTK20__)
    #include "wx/gtk/msgdlg.h"
#elif defined(__WXMAC__)
    #include "wx/osx/msgdlg.h"
#elif defined(__WXPM__)
    #include "wx/os2/msgdlg.h"
#endif

// ----------------------------------------------------------------------------
// wxMessageBox: the simplest way to use wxMessageDialog
// ----------------------------------------------------------------------------

int WXDLLIMPEXP_CORE wxMessageBox(const wxString& message,
                             const wxString& caption = wxMessageBoxCaptionStr,
                             long style = wxOK | wxCENTRE,
                             wxWindow *parent = NULL,
                             int x = wxDefaultCoord, int y = wxDefaultCoord);

#endif // wxUSE_MSGDLG

#endif // _WX_MSGDLG_H_BASE_
