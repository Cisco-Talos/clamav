/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/dialog.cpp
// Purpose:     wxDialog class
// Author:      David Webster
// Modified by:
// Created:     10/14/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/dialog.h"

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/frame.h"
    #include "wx/app.h"
    #include "wx/settings.h"
    #include "wx/intl.h"
    #include "wx/log.h"
#endif

#include "wx/os2/private.h"
#include "wx/evtloop.h"
#include "wx/scopedptr.h"

#define wxDIALOG_DEFAULT_X 300
#define wxDIALOG_DEFAULT_Y 300

#define wxDIALOG_DEFAULT_WIDTH 500
#define wxDIALOG_DEFAULT_HEIGHT 500

IMPLEMENT_DYNAMIC_CLASS(wxDialog, wxTopLevelWindow)

// ----------------------------------------------------------------------------
// wxDialogModalData
// ----------------------------------------------------------------------------

// this is simply a container for any data we need to implement modality which
// allows us to avoid changing wxDialog each time the implementation changes
class wxDialogModalData
{
public:
    wxDialogModalData(wxDialog *dialog) : m_evtLoop(dialog) { }

    void RunLoop()
    {
        m_evtLoop.Run();
    }

    void ExitLoop()
    {
        m_evtLoop.Exit();
    }

private:
    wxModalEventLoop m_evtLoop;
};

wxDEFINE_TIED_SCOPED_PTR_TYPE(wxDialogModalData);

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxDialog construction
// ----------------------------------------------------------------------------

void wxDialog::Init()
{
    m_pOldFocus = NULL;
    m_isShown = false;
    m_pWindowDisabler = NULL;
    m_modalData = NULL;
    SetBackgroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_3DFACE));
} // end of wxDialog::Init

bool wxDialog::Create( wxWindow*       pParent,
                       wxWindowID      vId,
                       const wxString& rsTitle,
                       const wxPoint&  rPos,
                       const wxSize&   rSize,
                       long            lStyle,
                       const wxString& rsName )
{
    Init();
    SetExtraStyle(GetExtraStyle() | wxTOPLEVEL_EX_DIALOG);

    //
    // Save focus before doing anything which can potentially change it
    //
    m_pOldFocus = FindFocus();

    //
    // All dialogs should really have this style
    //
    lStyle |= wxTAB_TRAVERSAL;

    if (!wxTopLevelWindow::Create( pParent
                                  ,vId
                                  ,rsTitle
                                  ,rPos
                                  ,rSize
                                  ,lStyle
                                  ,rsName
                                 ))
        return false;

    SetFont(wxSystemSettings::GetFont(wxSYS_DEFAULT_GUI_FONT));

    //
    // Must defer setting the title until after dialog is created and sized
    //
    if (!rsTitle.IsNull())
        SetTitle(rsTitle);
    return true;
} // end of wxDialog::Create

#if WXWIN_COMPATIBILITY_2_6

// deprecated ctor
wxDialog::wxDialog(wxWindow *parent,
                   const wxString& title,
                   bool WXUNUSED(modal),
                   int x,
                   int y,
                   int w,
                   int h,
                   long style,
                   const wxString& name)
{
    Init();

    Create(parent, wxID_ANY, title, wxPoint(x, y), wxSize(w, h), style, name);
}

void wxDialog::SetModal(bool WXUNUSED(bFlag))
{
    // nothing to do, obsolete method
} // end of wxDialog::SetModal

#endif // WXWIN_COMPATIBILITY_2_6

wxDialog::~wxDialog()
{
    SendDestroyEvent();

    // this will also reenable all the other windows for a modal dialog
    Show(false);
} // end of wxDialog::~wxDialog

// ----------------------------------------------------------------------------
// showing the dialogs
// ----------------------------------------------------------------------------

#if WXWIN_COMPATIBILITY_2_6

bool wxDialog::IsModalShowing() const
{
    return IsModal();
} // end of wxDialog::IsModalShowing

#endif // WXWIN_COMPATIBILITY_2_6

bool wxDialog::Show( bool bShow )
{
    if ( bShow == IsShown() )
        return false;

    if (!bShow && m_modalData )
    {
        // we need to do this before calling wxDialogBase version because if we
        // had disabled other app windows, they must be reenabled right now as
        // if they stay disabled Windows will activate another window (one
        // which is enabled, anyhow) when we're hidden in the base class Show()
        // and we will lose activation
        m_modalData->ExitLoop();
#if 0
        wxDELETE(m_pWindowDisabler);
#endif
    }

    if (bShow)
    {
        if (CanDoLayoutAdaptation())
            DoLayoutAdaptation();

        // this usually will result in TransferDataToWindow() being called
        // which will change the controls values so do it before showing as
        // otherwise we could have some flicker
        InitDialog();
    }

    wxDialogBase::Show(bShow);

    wxString title = GetTitle();
    if (!title.empty())
        ::WinSetWindowText((HWND)GetHwnd(), title.c_str());

    if ( bShow )
    {
        // dialogs don't get WM_SIZE message after creation unlike most (all?)
        // other windows and so could start their life not laid out correctly
        // if we didn't call Layout() from here
        //
        // NB: normally we should call it just the first time but doing it
        //     every time is simpler than keeping a flag
        Layout();
    }

    return true;
} // end of wxDialog::Show

//
// Replacement for Show(true) for modal dialogs - returns return code
//
int wxDialog::ShowModal()
{
    wxASSERT_MSG( !IsModal(), wxT("wxDialog::ShowModal() reentered?") );

    m_endModalCalled = false;

    Show();

    // EndModal may have been called from InitDialog handler (called from
    // inside Show()), which would cause an infinite loop if we didn't take it
    // into account
    if ( !m_endModalCalled )
    {
        // modal dialog needs a parent window, so try to find one
        wxWindow * const parent = GetParentForModalDialog();

        // remember where the focus was
        wxWindow *oldFocus = m_pOldFocus;
        if ( !oldFocus )
        {
            // VZ: do we really want to do this?
            oldFocus = parent;
        }

        // We have to remember the HWND because we need to check
        // the HWND still exists (oldFocus can be garbage when the dialog
        // exits, if it has been destroyed)
        HWND hwndOldFocus = oldFocus ? GetHwndOf(oldFocus) : NULL;


        //
        // Before entering the modal loop, reset the "is in OnIdle()" flag (see
        // comment in app.cpp)
        //
        extern bool                     gbInOnIdle;
        bool                            bWasInOnIdle = gbInOnIdle;

        gbInOnIdle = false;

        // enter and run the modal loop
        {
            wxDialogModalDataTiedPtr modalData(&m_modalData,
                                               new wxDialogModalData(this));
            modalData->RunLoop();
        }
        gbInOnIdle = bWasInOnIdle;

        // and restore focus
        // Note that this code MUST NOT access the dialog object's data
        // in case the object has been deleted (which will be the case
        // for a modal dialog that has been destroyed before calling EndModal).
        if ( oldFocus && (oldFocus != this) && ::WinIsWindow(vHabmain, hwndOldFocus))
        {
            // This is likely to prove that the object still exists
            if (wxFindWinFromHandle((WXHWND) hwndOldFocus) == oldFocus)
                oldFocus->SetFocus();
        }
    }

    return GetReturnCode();
} // end of wxDialog::ShowModal

void wxDialog::EndModal(
  int                               nRetCode
)
{
    wxASSERT_MSG( IsModal(), wxT("EndModal() called for non modal dialog") );

    m_endModalCalled = true;
    SetReturnCode(nRetCode);

    Hide();
} // end of wxDialog::EndModal

MRESULT wxDialog::OS2WindowProc( WXUINT uMessage, WXWPARAM wParam, WXLPARAM lParam )
{
    MRESULT  rc = 0;
    bool     bProcessed = false;

    switch (uMessage)
    {
        case WM_CLOSE:
            //
            // If we can't close, tell the system that we processed the
            // message - otherwise it would close us
            //
            bProcessed = !Close();
            break;
    }

    if (!bProcessed)
        rc = wxWindow::OS2WindowProc( uMessage
                                     ,wParam
                                     ,lParam
                                    );
    return rc;
} // end of wxDialog::OS2WindowProc
