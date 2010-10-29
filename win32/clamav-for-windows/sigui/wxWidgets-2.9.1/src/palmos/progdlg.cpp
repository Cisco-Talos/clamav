///////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/progdlg.cpp
// Purpose:     wxProgressDialog implementation
// Author:      Wlodzimierz ABX Skiba
// Modified by:
// Created:     29.12.2004
// RCS-ID:      $Id$
// Copyright:   (c) Wlodzimierz Skiba
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_PROGRESSDLG

#include "wx/progdlg.h"

#ifndef WX_PRECOMP
    #include  "wx/string.h"
    #include "wx/msgdlg.h"
#endif //WX_PRECOMP

#include <Progress.h>
#include <SysEvtMgr.h>

IMPLEMENT_CLASS(wxProgressDialog, wxDialog)

static Boolean wxProgressCallback(PrgCallbackData *data)
{
    if(!data)
        return false;

    wxProgressDialog *dialog = (wxProgressDialog *)data->userDataP;

    if(!dialog)
        return false;

    return dialog->Callback(data);
}

wxProgressDialog::wxProgressDialog(const wxString &title,
                                   wxString const &message,
                                   int maximum,
                                   wxWindow *parent,
                                   int style)
                 :wxDialog(parent, wxID_ANY, title),
                  m_prgFrame(NULL),
                  m_msg(message),
                  m_cur(0),
                  m_max(maximum),
                  m_canSkip((style & wxPD_CAN_SKIP )==wxPD_CAN_SKIP)
{
    wxString prgTitle = title.Mid(0, progressMaxTitle);

    m_prgFrame = PrgStartDialog(prgTitle.ToAscii(), wxProgressCallback, this);
}

wxProgressDialog::~wxProgressDialog()
{
    if(m_prgFrame)
    {
        PrgStopDialog((ProgressType *)m_prgFrame, false);
        m_prgFrame = NULL;
    }
}

bool wxProgressDialog::Update(int value, const wxString& newmsg, bool *skip)
{
    if(!m_prgFrame)
        return false;
    if(!newmsg.empty())
        m_msg = newmsg;
    m_cur = value;

    EventType event;

    ProgressType *prg = (ProgressType *)m_prgFrame;
    do
    {
        EvtGetEvent(&event, 0);
        Boolean handled = PrgHandleEvent(prg, &event);
        if (!PrgHandleEvent(prg, &event))
            if( PrgUserCancel(prg) )
                return false;
    }
    while(event.eType != sysEventNilEvent);

    PrgUpdateDialog(prg, 0, 0, "", true);

    m_activeSkip = m_canSkip && true;

    return true;
}

void wxProgressDialog::Resume()
{
}

bool wxProgressDialog::Show(bool show)
{
    return false;
}

Boolean wxProgressDialog::Callback(void *data)
{
    PrgCallbackData *palmData = (PrgCallbackData *)data;
    strncpy( palmData->textP, m_msg.ToAscii() , palmData->textLen - 1 );
    palmData->textChanged = true;
#ifdef __WXPALMOS6__
    palmData->displaySkipBtn = m_canSkip;
#endif // __WXPALMOS6__
    palmData->barMaxValue = (uint32_t)m_max;
    palmData->barCurValue = (uint32_t)m_cur;
    palmData->delay = (m_max == m_cur);

    return true;
}

#endif // wxUSE_PROGRESSDLG
