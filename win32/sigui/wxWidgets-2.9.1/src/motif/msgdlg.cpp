/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/msgdlg.cpp
// Purpose:     wxMessageDialog
// Author:      Julian Smart
// Modified by:
// Created:     04/01/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __VMS
#pragma message disable nosimpint
#include "wx/vms_x_fix.h"
#endif
#include <X11/Xlib.h>

#include <Xm/Xm.h>
#include <Xm/MessageB.h>
#ifdef __VMS
#pragma message enable nosimpint
#endif

#include "wx/msgdlg.h"

#ifndef WX_PRECOMP
    #include "wx/intl.h"
    #include "wx/app.h"
    #include "wx/settings.h"
#endif

#include "wx/motif/private.h"

// ----------------------------------------------------------------------------
// macros
// ----------------------------------------------------------------------------

    IMPLEMENT_CLASS(wxMessageDialog, wxDialog)

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// the callbacks for message box buttons
// ----------------------------------------------------------------------------

// the common part
static void msgboxCallBack(Widget w, void* client_data, int id)
{
    // close the dialog
    XtUnmanageChild(w);

    wxMessageDialog *dlg = (wxMessageDialog *)client_data;
    dlg->SetResult(id);
}

static void msgboxCallBackOk(Widget w,
                             void* client_data,
                             XmAnyCallbackStruct *WXUNUSED(call_data))
{
    msgboxCallBack(w, client_data, wxID_OK);
}

static void msgboxCallBackCancel(Widget w,
                                 void* client_data,
                                 XmAnyCallbackStruct *WXUNUSED(call_data))
{
    msgboxCallBack(w, client_data, wxID_CANCEL);
}

static void msgboxCallBackHelp(Widget w,
                               void* client_data,
                               XmAnyCallbackStruct *WXUNUSED(call_data))
{
    msgboxCallBack(w, client_data, wxID_HELP);
}

static void msgboxCallBackClose(Widget w,
                                void* client_data,
                                XmAnyCallbackStruct *WXUNUSED(call_data))
{
    msgboxCallBack(w, client_data, wxID_CANCEL);
}

// ----------------------------------------------------------------------------
// wxMessageDialog
// ----------------------------------------------------------------------------

extern "C"
{
    typedef Widget (*DialogCreateFunction)(Widget, String, ArgList, Cardinal);
}

int wxMessageDialog::ShowModal()
{
    const long style = GetMessageDialogStyle();

    DialogCreateFunction dialogCreateFunction;
    if ( style & wxYES_NO )
    {
        // if we have [Yes], it must be a question
        dialogCreateFunction = XmCreateQuestionDialog;
    }
    else if ( style & wxICON_STOP )
    {
        // error dialog is the one with error icon...
        dialogCreateFunction = XmCreateErrorDialog;
    }
    else if ( style & wxICON_EXCLAMATION )
    {
        // ...and the warning dialog too
        dialogCreateFunction = XmCreateWarningDialog;
    }
    else
    {
        // finally, use the info dialog by default
        dialogCreateFunction = XmCreateInformationDialog;
    }

    Widget wParent = m_parent ? GetWidget(m_parent) : (Widget) 0;
    if ( !wParent )
    {
        wxWindow *window = wxTheApp->GetTopWindow();
        if ( !window )
        {
            wxFAIL_MSG("can't show message box without parent window");

            return wxID_CANCEL;
        }

        wParent = GetWidget(window);
    }

    // prepare the arg list
    Arg args[10];
    int ac = 0;

    wxXmString text(GetFullMessage());
    wxXmString title(m_caption);
    XtSetArg(args[ac], XmNmessageString, text()); ac++;
    XtSetArg(args[ac], XmNdialogTitle, title()); ac++;

    Display* dpy = XtDisplay(wParent);

    if (m_backgroundColour.Ok())
    {
        wxComputeColours (dpy, & m_backgroundColour, NULL);

        XtSetArg(args[ac], XmNbackground, g_itemColors[wxBACK_INDEX].pixel); ac++;
        XtSetArg(args[ac], XmNtopShadowColor, g_itemColors[wxTOPS_INDEX].pixel); ac++;
        XtSetArg(args[ac], XmNbottomShadowColor, g_itemColors[wxBOTS_INDEX].pixel); ac++;
        XtSetArg(args[ac], XmNforeground, g_itemColors[wxFORE_INDEX].pixel); ac++;
    }

    wxFont font = wxSystemSettings::GetFont(wxSYS_DEFAULT_GUI_FONT);

#if __WXMOTIF20__ && !__WXLESSTIF__
    XtSetArg(args[ac], XmNbuttonRenderTable, font.GetFontTypeC(dpy)); ac++;
    XtSetArg(args[ac], XmNlabelRenderTable, font.GetFontTypeC(dpy)); ac++;
    XtSetArg(args[ac], XmNtextRenderTable, font.GetFontTypeC(dpy)); ac++;
#else
    XtSetArg(args[ac], XmNbuttonFontList, font.GetFontTypeC(dpy)); ac++;
    XtSetArg(args[ac], XmNlabelFontList, font.GetFontTypeC(dpy)); ac++;
    XtSetArg(args[ac], XmNtextFontList, font.GetFontTypeC(dpy)); ac++;
#endif

    // do create message box

    Widget wMsgBox = (*dialogCreateFunction)(wParent, wxMOTIF_STR(""), args, ac);

    wxCHECK_MSG( wMsgBox, wxID_CANCEL, "msg box creation failed" );

    // get the buttons which we might either remove or rename
    // depending on the requested style
    //
    Widget wBtnOk = XmMessageBoxGetChild(wMsgBox, XmDIALOG_OK_BUTTON);
    Widget wBtnHelp = XmMessageBoxGetChild(wMsgBox, XmDIALOG_HELP_BUTTON);
    Widget wBtnCancel = XmMessageBoxGetChild(wMsgBox, XmDIALOG_CANCEL_BUTTON);

    if ( style & wxYES_NO )
    {
        wxXmString yes(_("Yes")), no(_("No")), cancel(_("Cancel"));

        if ( style & wxCANCEL )
        {
            // use the cancel button for No and the help button for
            // Cancel  Yuk :-)  MB
            //
            XtVaSetValues(wBtnOk, XmNlabelString, yes(), NULL);
            XtVaSetValues(wBtnCancel, XmNlabelString, no(), NULL);
            XtVaSetValues(wBtnHelp, XmNlabelString, cancel(), NULL);
        }
        else
        {
            // no cancel button requested...
            // remove the help button and use cancel for no
            //
            XtVaSetValues(wBtnCancel, XmNlabelString, no(), NULL);
            XtUnmanageChild(wBtnHelp);
        }
    }
    else
    {
        // remove the help button and the cancel button (unless it was
        // requested)
        //
        XtUnmanageChild(wBtnHelp);
        if ( !(style & wxCANCEL ) ) XtUnmanageChild(wBtnCancel);
    }

    // set the callbacks for the message box buttons
    XtAddCallback(wMsgBox, XmNokCallback,
                  (XtCallbackProc)msgboxCallBackOk, (XtPointer)this);
    XtAddCallback(wMsgBox, XmNcancelCallback,
                  (XtCallbackProc)msgboxCallBackCancel, (XtPointer)this);
    XtAddCallback(wMsgBox, XmNhelpCallback,
                  (XtCallbackProc)msgboxCallBackHelp, (XtPointer)this);
    XtAddCallback(wMsgBox, XmNunmapCallback,
                  (XtCallbackProc)msgboxCallBackClose, (XtPointer)this);

    // show it as a modal dialog
    XtManageChild(wMsgBox);
    XtAddGrab(wMsgBox, True, False);

    // the m_result will be changed when message box goes away
    m_result = -1;

    // local message loop
    XtAppContext context = XtWidgetToApplicationContext(wParent);
    XEvent event;
    while ( m_result == -1 )
    {
        XtAppNextEvent(context, &event);
        XtDispatchEvent(&event);
    }

    // translate the result if necessary
    if ( style & wxYES_NO )
    {
        if ( m_result == wxID_OK )
            m_result = wxID_YES;
        else if ( m_result == wxID_CANCEL )
            m_result = wxID_NO;
        else if ( m_result == wxID_HELP )
            m_result = wxID_CANCEL;
    }

    return m_result;
}
