/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/dialog.cpp
// Purpose:
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/dialog.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/frame.h"
    #include "wx/cursor.h"
#endif // WX_PRECOMP

#include "wx/evtloop.h"

#include <gdk/gdk.h>
#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>

#include "wx/gtk1/win_gtk.h"

//-----------------------------------------------------------------------------
// global data
//-----------------------------------------------------------------------------

extern int g_openDialogs;

//-----------------------------------------------------------------------------
// wxDialog
//-----------------------------------------------------------------------------

BEGIN_EVENT_TABLE(wxDialog,wxDialogBase)
    EVT_BUTTON  (wxID_OK,       wxDialog::OnOK)
    EVT_BUTTON  (wxID_CANCEL,   wxDialog::OnCancel)
    EVT_BUTTON  (wxID_APPLY,    wxDialog::OnApply)
    EVT_CLOSE   (wxDialog::OnCloseWindow)
END_EVENT_TABLE()

IMPLEMENT_DYNAMIC_CLASS(wxDialog,wxTopLevelWindow)

void wxDialog::Init()
{
    m_returnCode = 0;
    m_sizeSet = false;
    m_modalShowing = false;
    m_themeEnabled = true;
}

wxDialog::wxDialog( wxWindow *parent,
                    wxWindowID id, const wxString &title,
                    const wxPoint &pos, const wxSize &size,
                    long style, const wxString &name )
{
    Init();

    (void)Create( parent, id, title, pos, size, style, name );
}

bool wxDialog::Create( wxWindow *parent,
                       wxWindowID id, const wxString &title,
                       const wxPoint &pos, const wxSize &size,
                       long style, const wxString &name )
{
    SetExtraStyle(GetExtraStyle() | wxTOPLEVEL_EX_DIALOG);

    // all dialogs should have tab traversal enabled
    style |= wxTAB_TRAVERSAL;

    return wxTopLevelWindow::Create(parent, id, title, pos, size, style, name);
}

void wxDialog::OnApply( wxCommandEvent &WXUNUSED(event) )
{
    if (Validate())
        TransferDataFromWindow();
}

void wxDialog::OnCancel( wxCommandEvent &WXUNUSED(event) )
{
    if (IsModal())
    {
        EndModal(wxID_CANCEL);
    }
    else
    {
        SetReturnCode(wxID_CANCEL);
        Show(false);
    }
}

void wxDialog::OnOK( wxCommandEvent &WXUNUSED(event) )
{
    if (Validate() && TransferDataFromWindow())
    {
        if (IsModal())
        {
            EndModal(wxID_OK);
        }
        else
        {
            SetReturnCode(wxID_OK);
            Show(false);
        }
    }
}

void wxDialog::OnPaint( wxPaintEvent& WXUNUSED(event) )
{
    // yes
}

void wxDialog::OnCloseWindow(wxCloseEvent& WXUNUSED(event))
{
    // We'll send a Cancel message by default,
    // which may close the dialog.
    // Check for looping if the Cancel event handler calls Close().

    // Note that if a cancel button and handler aren't present in the dialog,
    // nothing will happen when you close the dialog via the window manager, or
    // via Close().
    // We wouldn't want to destroy the dialog by default, since the dialog may have been
    // created on the stack.
    // However, this does mean that calling dialog->Close() won't delete the dialog
    // unless the handler for wxID_CANCEL does so. So use Destroy() if you want to be
    // sure to destroy the dialog.
    // The default OnCancel (above) simply ends a modal dialog, and hides a modeless dialog.

    static wxList s_closing;

    if (s_closing.Member(this))
        return;   // no loops

    s_closing.Append(this);

    wxCommandEvent cancelEvent(wxEVT_COMMAND_BUTTON_CLICKED, wxID_CANCEL);
    cancelEvent.SetEventObject( this );
    HandleWindowEvent(cancelEvent);
    s_closing.DeleteObject(this);
}

bool wxDialog::Show( bool show )
{
    if (!show && IsModal())
    {
        EndModal( wxID_CANCEL );
    }

    if (show && !m_sizeSet)
    {
        /* by calling GtkOnSize here, we don't have to call
           either after showing the frame, which would entail
           much ugly flicker nor from within the size_allocate
           handler, because GTK 1.1.X forbids that. */

        GtkOnSize( m_x, m_y, m_width, m_height );
    }

    if (show && CanDoLayoutAdaptation())
        DoLayoutAdaptation();

    bool ret = wxWindow::Show( show );

    if (show) InitDialog();

    return ret;
}

bool wxDialog::IsModal() const
{
    return m_modalShowing;
}

void wxDialog::SetModal( bool WXUNUSED(flag) )
{
    wxFAIL_MSG( wxT("wxDialog:SetModal obsolete now") );
}

int wxDialog::ShowModal()
{
    if (IsModal())
    {
       wxFAIL_MSG( wxT("wxDialog:ShowModal called twice") );
       return GetReturnCode();
    }

    // use the apps top level window as parent if none given unless explicitly
    // forbidden
    wxWindow * const parent = GetParentForModalDialog();
    if ( parent )
    {
        m_parent = parent;
        gtk_window_set_transient_for( GTK_WINDOW(m_widget), GTK_WINDOW(parent->m_widget) );
    }

    wxBusyCursorSuspender cs; // temporarily suppress the busy cursor

    Show( true );

    m_modalShowing = true;

    g_openDialogs++;

    gtk_grab_add( m_widget );

    wxEventLoop().Run();

    gtk_grab_remove( m_widget );

    g_openDialogs--;

    return GetReturnCode();
}

void wxDialog::EndModal( int retCode )
{
    SetReturnCode( retCode );

    if (!IsModal())
    {
        wxFAIL_MSG( wxT("wxDialog:EndModal called twice") );
        return;
    }

    m_modalShowing = false;

    gtk_main_quit();

    Show( false );
}
