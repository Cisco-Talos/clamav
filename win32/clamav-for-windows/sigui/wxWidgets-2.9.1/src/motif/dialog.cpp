/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/dialog.cpp
// Purpose:     wxDialog class
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/dialog.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/utils.h"
    #include "wx/settings.h"
#endif

#include "wx/evtloop.h"

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/Xm.h>

#include <X11/Shell.h>
#if XmVersion >= 1002
#include <Xm/XmAll.h>
#endif
#include <Xm/MwmUtil.h>
#include <Xm/Label.h>
#include <Xm/BulletinB.h>
#include <Xm/Frame.h>
#include <Xm/Text.h>
#include <Xm/DialogS.h>
#include <Xm/FileSB.h>
#include <Xm/RowColumn.h>
#include <Xm/LabelG.h>
#include <Xm/AtomMgr.h>
#if   XmVersion > 1000
#include <Xm/Protocols.h>
#endif
#ifdef __VMS__
#pragma message enable nosimpint
#endif

#include "wx/motif/private.h"

// A stack of modal_showing flags, since we can't rely
// on accessing wxDialog::m_modalShowing within
// wxDialog::Show in case a callback has deleted the wxDialog.
// static wxList wxModalShowingStack;

// Lists to keep track of windows, so we can disable/enable them
// for modal dialogs
wxList wxModalDialogs;
extern wxList wxModelessWindows;  // Frames and modeless dialogs

#define wxUSE_INVISIBLE_RESIZE 1

IMPLEMENT_DYNAMIC_CLASS(wxDialog, wxTopLevelWindow)

wxDialog::wxDialog()
{
    m_modalShowing = false;
    m_eventLoop = NULL;
}

bool wxDialog::Create(wxWindow *parent, wxWindowID id,
                      const wxString& title,
                      const wxPoint& pos,
                      const wxSize& size,
                      long style,
                      const wxString& name)
{
    SetExtraStyle(GetExtraStyle() | wxTOPLEVEL_EX_DIALOG);

    if( !wxTopLevelWindow::Create( parent, id, title, pos, size, style,
                                   name ) )
        return false;

    m_modalShowing = false;
    m_eventLoop = NULL;

    Widget dialogShell = (Widget) m_mainWidget;

    SetTitle( title );

    // Can't remember what this was about... but I think it's necessary.
#if wxUSE_INVISIBLE_RESIZE
    if (pos.x > -1)
        XtVaSetValues(dialogShell, XmNx, pos.x,
        NULL);
    if (pos.y > -1)
        XtVaSetValues(dialogShell, XmNy, pos.y,
        NULL);

    if (size.x > -1)
        XtVaSetValues(dialogShell, XmNwidth, size.x, NULL);
    if (size.y > -1)
        XtVaSetValues(dialogShell, XmNheight, size.y, NULL);
#endif

    // Positioning of the dialog doesn't work properly unless the dialog
    // is managed, so we manage without mapping to the screen.
    // To show, we map the shell (actually it's parent).
#if !wxUSE_INVISIBLE_RESIZE
    Widget shell = XtParent(dialogShell) ;
    XtVaSetValues(shell, XmNmappedWhenManaged, False, NULL);
#endif

#if !wxUSE_INVISIBLE_RESIZE
    XtManageChild(dialogShell);
    SetSize(pos.x, pos.y, size.x, size.y);
#endif

    XtAddEventHandler(dialogShell,ExposureMask,False,
        wxUniversalRepaintProc, (XtPointer) this);

    PostCreation();

    return true;
}

bool wxDialog::XmDoCreateTLW(wxWindow* parent,
                             wxWindowID WXUNUSED(id),
                             const wxString& WXUNUSED(title),
                             const wxPoint& WXUNUSED(pos),
                             const wxSize& WXUNUSED(size),
                             long WXUNUSED(style),
                             const wxString& name)
{
    Widget parentWidget = (Widget) 0;
    if( parent )
        parentWidget = (Widget) parent->GetTopWidget();
    if( !parent )
        parentWidget = (Widget) wxTheApp->GetTopLevelWidget();

    wxASSERT_MSG( (parentWidget != (Widget) 0),
                  "Could not find a suitable parent shell for dialog." );

    Arg args[2];
    XtSetArg (args[0], XmNdefaultPosition, False);
    XtSetArg (args[1], XmNautoUnmanage, False);
    Widget dialogShell =
        XmCreateBulletinBoardDialog( parentWidget,
                                     name.char_str(),
                                     args, 2);
    m_mainWidget = (WXWidget) dialogShell;

    // We don't want margins, since there is enough elsewhere.
    XtVaSetValues( dialogShell,
                   XmNmarginHeight,   0,
                   XmNmarginWidth,    0,
                   XmNresizePolicy, XmRESIZE_NONE,
                   NULL ) ;

    XtTranslations ptr ;
    XtOverrideTranslations(dialogShell,
        ptr = XtParseTranslationTable("<Configure>: resize()"));
    XtFree((char *)ptr);

    XtRealizeWidget(dialogShell);

    wxAddWindowToTable( (Widget)m_mainWidget, this );

    return true;
}

void wxDialog::SetModal(bool flag)
{
   if ( flag )
       wxModelessWindows.DeleteObject(this);
   else
       wxModelessWindows.Append(this);
}

wxDialog::~wxDialog()
{
    SendDestroyEvent();

    // if the dialog is modal, this will end its event loop
    Show(false);

    delete m_eventLoop;

    if (m_mainWidget)
    {
        XtRemoveEventHandler((Widget) m_mainWidget, ExposureMask, False,
                             wxUniversalRepaintProc, (XtPointer) this);
    }

    m_modalShowing = false;

#if !wxUSE_INVISIBLE_RESIZE
    if (m_mainWidget)
    {
        XtUnmapWidget((Widget) m_mainWidget);
    }
#endif

    PreDestroy();

    if ( m_mainWidget )
    {
        wxDeleteWindowFromTable( (Widget)m_mainWidget );
        XtDestroyWidget( (Widget)m_mainWidget );
    }
}

void wxDialog::DoSetSize(int x, int y, int width, int height, int sizeFlags)
{
    XtVaSetValues((Widget) m_mainWidget, XmNresizePolicy, XmRESIZE_ANY, NULL);
    wxWindow::DoSetSize(x, y, width, height, sizeFlags);
    XtVaSetValues((Widget) m_mainWidget, XmNresizePolicy, XmRESIZE_NONE, NULL);
}

void wxDialog::DoSetClientSize(int width, int height)
{
    wxWindow::SetSize(-1, -1, width, height);
}

void wxDialog::SetTitle(const wxString& title)
{
    wxTopLevelWindow::SetTitle( title );

    if( !title.empty() )
    {
        wxXmString str( title );
        XtVaSetValues( (Widget)m_mainWidget,
                       XmNtitle, (const char*)title.mb_str(),
                       XmNdialogTitle, str(),
                       XmNiconName, (const char*)title.mb_str(),
                       NULL );
    }
}

bool wxDialog::Show( bool show )
{
    if( !wxWindowBase::Show( show ) )
        return false;

    if ( !show && IsModal() )
        EndModal(wxID_CANCEL);

    m_isShown = show;

    if (show)
    {
        if (CanDoLayoutAdaptation())
            DoLayoutAdaptation();

        // this usually will result in TransferDataToWindow() being called
        // which will change the controls values so do it before showing as
        // otherwise we could have some flicker
        InitDialog();
    }

    if (show)
    {
#if !wxUSE_INVISIBLE_RESIZE
        XtMapWidget(XtParent((Widget) m_mainWidget));
#else
        XtManageChild((Widget)m_mainWidget) ;
#endif

        XRaiseWindow( XtDisplay( (Widget)m_mainWidget ),
                      XtWindow( (Widget)m_mainWidget) );

    }
    else
    {
#if !wxUSE_INVISIBLE_RESIZE
        XtUnmapWidget(XtParent((Widget) m_mainWidget));
#else
        XtUnmanageChild((Widget)m_mainWidget) ;
#endif

        XFlush(XtDisplay((Widget)m_mainWidget));
        XSync(XtDisplay((Widget)m_mainWidget), False);
    }

    return true;
}

// Shows a dialog modally, returning a return code
int wxDialog::ShowModal()
{
    Show(true);

    // after the event loop ran, the widget might already have been destroyed
    WXDisplay* display = (WXDisplay*)XtDisplay( (Widget)m_mainWidget );

    if (m_modalShowing)
        return 0;
    m_eventLoop = new wxEventLoop;

    m_modalShowing = true;
    XtAddGrab((Widget) m_mainWidget, True, False);

    m_eventLoop->Run();

    // Now process all events in case they get sent to a destroyed dialog
    wxFlushEvents( display );

    wxDELETE(m_eventLoop);

    // TODO: is it safe to call this, if the dialog may have been deleted
    // by now? Probably only if we're using delayed deletion of dialogs.
    return GetReturnCode();
}

void wxDialog::EndModal(int retCode)
{
    if (!m_modalShowing)
        return;

    SetReturnCode(retCode);

    // Strangely, we don't seem to need this now.
    //    XtRemoveGrab((Widget) m_mainWidget);

    Show(false);

    m_modalShowing = false;
    m_eventLoop->Exit();

    SetModal(false);
}

// Destroy the window (delayed, if a managed window)
bool wxDialog::Destroy()
{
    if (!wxPendingDelete.Member(this))
        wxPendingDelete.Append(this);
    return true;
}

void wxDialog::ChangeFont(bool keepOriginalSize)
{
    wxWindow::ChangeFont(keepOriginalSize);
}

void wxDialog::ChangeBackgroundColour()
{
    if (GetMainWidget())
        wxDoChangeBackgroundColour(GetMainWidget(), m_backgroundColour);
}

void wxDialog::ChangeForegroundColour()
{
    if (GetMainWidget())
        wxDoChangeForegroundColour(GetMainWidget(), m_foregroundColour);
}
