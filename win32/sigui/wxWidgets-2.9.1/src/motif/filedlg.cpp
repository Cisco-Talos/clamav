/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/filedlg.cpp
// Purpose:     wxFileDialog
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/filedlg.h"

#ifndef WX_PRECOMP
    #include "wx/intl.h"
    #include "wx/app.h"
    #include "wx/utils.h"
    #include "wx/settings.h"
#endif

#include "wx/tokenzr.h"
#include "wx/stockitem.h"

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/Xm.h>
#include <Xm/MwmUtil.h>
#include <Xm/Label.h>
#include <Xm/BulletinB.h>
#include <Xm/Frame.h>
#include <Xm/Text.h>
#include <Xm/DialogS.h>
#include <Xm/FileSB.h>
#include <Xm/RowColumn.h>
#include <Xm/LabelG.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

#include "wx/motif/private.h"

IMPLEMENT_CLASS(wxFileDialog, wxFileDialogBase)

#define DEFAULT_FILE_SELECTOR_SIZE 0
// Let Motif defines the size of File
// Selector Box (if 1), or fix it to
// wxFSB_WIDTH x wxFSB_HEIGHT (if 0)
#define wxFSB_WIDTH                600
#define wxFSB_HEIGHT               500


wxString wxFileDialog::m_fileSelectorAnswer = wxEmptyString;
bool wxFileDialog::m_fileSelectorReturned = false;

static void wxFileSelClose(Widget WXUNUSED(w),
                           void* WXUNUSED(client_data),
                           XmAnyCallbackStruct *WXUNUSED(call_data))
{
    wxFileDialog::m_fileSelectorAnswer = wxEmptyString;
    wxFileDialog::m_fileSelectorReturned = true;
}

void wxFileSelCancel( Widget WXUNUSED(fs), XtPointer WXUNUSED(client_data),
                     XmFileSelectionBoxCallbackStruct *WXUNUSED(cbs) )
{
    wxFileDialog::m_fileSelectorAnswer = wxEmptyString;
    wxFileDialog::m_fileSelectorReturned = true;
}

void wxFileSelOk(Widget WXUNUSED(fs), XtPointer WXUNUSED(client_data), XmFileSelectionBoxCallbackStruct *cbs)
{
    char *filename = NULL;
    if (!XmStringGetLtoR(cbs->value, XmSTRING_DEFAULT_CHARSET, &filename)) {
        wxFileDialog::m_fileSelectorAnswer = wxEmptyString;
        wxFileDialog::m_fileSelectorReturned = true;
    } else {
        if (filename) {
            wxFileDialog::m_fileSelectorAnswer = filename;
            XtFree(filename);
        }
        wxFileDialog::m_fileSelectorReturned = true;
    }
}

static wxString ParseWildCard( const wxString& wild )
{
#if wxDEBUG_LEVEL
    static const char *msg =
        "Motif file dialog does not understand this wildcard syntax";
#endif

    wxArrayString wildDescriptions, wildFilters;
    const size_t count = wxParseCommonDialogsFilter(wild,
                                                    wildDescriptions,
                                                    wildFilters);
    wxCHECK_MSG( count, wxT("*.*"), wxT("wxFileDialog: bad wildcard string") );
    wxCHECK_MSG( count == 1, wxT("*.*"), msg );

    // check for *.txt;*.rtf
    wxStringTokenizer tok2( wildFilters[0], wxT(";") );
    wxString wildcard = tok2.GetNextToken();

    wxCHECK_MSG( tok2.CountTokens() <= 1, wildcard, msg );
    return wildcard;
}

wxFileDialog::wxFileDialog(wxWindow *parent, const wxString& message,
                           const wxString& defaultDir, const wxString& defaultFileName, const wxString& wildCard,
                           long style, const wxPoint& pos, const wxSize& sz, const wxString& name)
             :wxFileDialogBase(parent, message, defaultDir, defaultFileName, wildCard, style, pos, sz, name)
{
    m_filterIndex = 1;
}

static void wxChangeListBoxColours(wxWindow* WXUNUSED(win), Widget widget)
{
    wxDoChangeBackgroundColour((WXWidget) widget, *wxWHITE);

    // Change colour of the scrolled areas of the listboxes
    Widget listParent = XtParent (widget);
#if 0
    wxDoChangeBackgroundColour((WXWidget) listParent, *wxWHITE, true);
#endif

    Widget hsb = (Widget) 0;
    Widget vsb = (Widget) 0;
    XtVaGetValues (listParent,
        XmNhorizontalScrollBar, &hsb,
        XmNverticalScrollBar, &vsb,
        NULL);

   /* TODO: should scrollbars be affected? Should probably have separate
    * function to change them (by default, taken from wxSystemSettings)
    */
    wxColour backgroundColour = wxSystemSettings::GetColour(wxSYS_COLOUR_3DFACE);
    wxDoChangeBackgroundColour((WXWidget) hsb, backgroundColour, true);
    wxDoChangeBackgroundColour((WXWidget) vsb, backgroundColour, true);

    if (hsb)
      XtVaSetValues (hsb,
        XmNtroughColor, backgroundColour.AllocColour(XtDisplay(hsb)),
        NULL);
    if (vsb)
      XtVaSetValues (vsb,
        XmNtroughColor, backgroundColour.AllocColour(XtDisplay(vsb)),
        NULL);
}

int wxFileDialog::ShowModal()
{
    wxBeginBusyCursor();

    //  static char fileBuf[512];
    Widget parentWidget = (Widget) 0;
    if (m_parent)
        parentWidget = (Widget) m_parent->GetTopWidget();
    else
        parentWidget = (Widget) wxTheApp->GetTopLevelWidget();
    // prepare the arg list
    Display* dpy = XtDisplay(parentWidget);
    Arg args[10];
    int ac = 0;

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

    Widget fileSel = XmCreateFileSelectionDialog(parentWidget,
                                                 wxMOTIF_STR("file_selector"),
                                                 args, ac);
#define wxFSChild( name ) \
    XmFileSelectionBoxGetChild(fileSel, name)

    XtUnmanageChild(wxFSChild(XmDIALOG_HELP_BUTTON));

    Widget filterWidget = wxFSChild(XmDIALOG_FILTER_TEXT);
    Widget selectionWidget = wxFSChild(XmDIALOG_TEXT);
    Widget dirListWidget = wxFSChild(XmDIALOG_DIR_LIST);
    Widget fileListWidget = wxFSChild(XmDIALOG_LIST);

    // for changing labels
    Widget okWidget = wxFSChild(XmDIALOG_OK_BUTTON);
    Widget applyWidget = wxFSChild(XmDIALOG_APPLY_BUTTON);
    Widget cancelWidget = wxFSChild(XmDIALOG_CANCEL_BUTTON);
    Widget dirlistLabel = wxFSChild(XmDIALOG_DIR_LIST_LABEL);
    Widget filterLabel = wxFSChild(XmDIALOG_FILTER_LABEL);
    Widget listLabel = wxFSChild(XmDIALOG_LIST_LABEL);
    Widget selectionLabel = wxFSChild(XmDIALOG_SELECTION_LABEL);

#undef wxFSChild

    // change labels
    wxXmString btnOK( wxGetStockLabel( wxID_OK, false ) ),
               btnCancel( wxGetStockLabel( wxID_CANCEL, false ) ),
               btnFilter( _("Filter") ), lblFilter( _("Filter") ),
               lblDirectories( _("Directories") ),
               lblFiles( _("Files" ) ), lblSelection( _("Selection") );

    XtVaSetValues( okWidget, XmNlabelString, btnOK(), NULL );
    XtVaSetValues( applyWidget, XmNlabelString, btnFilter(), NULL );
    XtVaSetValues( cancelWidget, XmNlabelString, btnCancel(), NULL );
    XtVaSetValues( dirlistLabel, XmNlabelString, lblDirectories(), NULL );
    XtVaSetValues( filterLabel, XmNlabelString, lblFilter(), NULL );
    XtVaSetValues( listLabel, XmNlabelString, lblFiles(), NULL );
    XtVaSetValues( selectionLabel, XmNlabelString, lblSelection(), NULL );

    Widget shell = XtParent(fileSel);

    if (!m_message.IsNull())
        XtVaSetValues(shell,
                      XmNtitle, (const char*)m_message.mb_str(),
                      NULL);

    if (!m_wildCard.empty())
    {
        // return something understandable by Motif
        wxString wildCard = ParseWildCard( m_wildCard );
        wxString filter;
        if (!m_dir.empty())
            filter = m_dir + wxString("/") + wildCard;
        else
            filter = wildCard;

        XmTextSetString(filterWidget, filter.char_str());
        XmFileSelectionDoSearch(fileSel, NULL);
    }

    // Suggested by Terry Gitnick, 16/9/97, because of change in Motif
    // file selector on Solaris 1.5.1.
    if ( !m_dir.empty() )
    {
        wxXmString thePath( m_dir );

        XtVaSetValues (fileSel,
            XmNdirectory, thePath(),
            NULL);
    }

    wxString entirePath;

    if (!m_dir.empty())
    {
        entirePath = m_dir + wxString("/") + m_fileName;
    }
    else
    {
        entirePath = m_fileName;
    }

    if (!entirePath.empty())
    {
        XmTextSetString(selectionWidget, entirePath.char_str());
    }

    XtAddCallback(fileSel, XmNcancelCallback,
                  (XtCallbackProc)wxFileSelCancel, (XtPointer)NULL);
    XtAddCallback(fileSel, XmNokCallback,
                  (XtCallbackProc)wxFileSelOk, (XtPointer)NULL);
    XtAddCallback(fileSel, XmNunmapCallback,
                  (XtCallbackProc)wxFileSelClose, (XtPointer)this);

    //#if XmVersion > 1000
    // I'm not sure about what you mean with XmVersion.
    // If this is for Motif1.1/Motif1.2, then check XmVersion>=1200
    // (Motif1.1.4 ==> XmVersion 1100 )
    // Nevertheless, I put here a #define, so anyone can choose in (I)makefile.
    //
#if !DEFAULT_FILE_SELECTOR_SIZE
    int width = wxFSB_WIDTH;
    int height = wxFSB_HEIGHT;
    XtVaSetValues(fileSel,
        XmNwidth, width,
        XmNheight, height,
        XmNresizePolicy, XmRESIZE_NONE,
        NULL);
#endif
    wxDoChangeBackgroundColour((WXWidget) filterWidget, *wxWHITE);
    wxDoChangeBackgroundColour((WXWidget) selectionWidget, *wxWHITE);

    wxChangeListBoxColours(this, dirListWidget);
    wxChangeListBoxColours(this, fileListWidget);

    XtManageChild(fileSel);

    m_fileSelectorAnswer = wxEmptyString;
    m_fileSelectorReturned = false;

    wxEndBusyCursor();

    XtAddGrab(XtParent(fileSel), True, False);
    XtAppContext context = (XtAppContext) wxTheApp->GetAppContext();
    XEvent event;
    while (!m_fileSelectorReturned)
    {
        XtAppNextEvent(context, &event);
        XtDispatchEvent(&event);
    }
    XtRemoveGrab(XtParent(fileSel));

    XtUnmapWidget(XtParent(fileSel));
    XtDestroyWidget(XtParent(fileSel));

    // Now process all events, because otherwise
    // this might remain on the screen
    wxFlushEvents(XtDisplay(fileSel));

    m_path = m_fileSelectorAnswer;
    m_fileName = wxFileNameFromPath(m_fileSelectorAnswer);
    m_dir = wxPathOnly(m_path);

    if (m_fileName.empty())
        return wxID_CANCEL;
    else
        return wxID_OK;
}
