/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/accel.cpp
// Purpose:     wxAcceleratorTable
// Author:      David Webster
// Modified by:
// Created:     10/13/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/accel.h"

#ifndef WX_PRECOMP
    #include <stdio.h>
    #include "wx/window.h"
    #include "wx/app.h"
    #include "wx/frame.h"
#endif

#include "wx/os2/private.h"


IMPLEMENT_DYNAMIC_CLASS(wxAcceleratorTable, wxObject)

class WXDLLEXPORT wxAcceleratorRefData: public wxObjectRefData
{
    friend class WXDLLEXPORT wxAcceleratorTable;
public:
    wxAcceleratorRefData();
    virtual ~wxAcceleratorRefData();

    inline HACCEL GetHACCEL() const { return m_hAccel; }
protected:
    HACCEL      m_hAccel;
    bool        m_ok;
};

#define M_ACCELDATA ((wxAcceleratorRefData *)m_refData)

wxAcceleratorRefData::wxAcceleratorRefData()
{
    m_ok = false;
    m_hAccel = 0;
} // end of wxAcceleratorRefData::wxAcceleratorRefData

wxAcceleratorRefData::~wxAcceleratorRefData()
{
    if (m_hAccel)
    {
        WinDestroyAccelTable((HACCEL) m_hAccel);
    }
    m_hAccel = 0 ;
} // end of wxAcceleratorRefData::~wxAcceleratorRefData

wxAcceleratorTable::wxAcceleratorTable()
{
    m_refData = NULL;
} // end of wxAcceleratorTable::wxAcceleratorTable

wxAcceleratorTable::~wxAcceleratorTable()
{
} // end of wxAcceleratorTable::~wxAcceleratorTable

// Load from .rc resource
wxAcceleratorTable::wxAcceleratorTable(
  const wxString&                  rResource
)
{
    HACCEL                          hAccel;
    ULONG                           ulId;

    m_refData = new wxAcceleratorRefData;

    ulId = atol(rResource.c_str());
    hAccel = ::WinLoadAccelTable( vHabmain
                                 ,NULL // resources always in .exe
                                 ,(ULONG)ulId
                                );
    if (wxTheApp->GetTopWindow() != NULL)
    {
        //
        // If we have accelerators the top window is the frame
        //
        wxFrame*                    pFrame = (wxFrame*)wxTheApp->GetTopWindow();

        ::WinSetAccelTable( vHabmain
                           ,hAccel
                           ,(HWND)pFrame->GetFrame()
                          );
    }
    M_ACCELDATA->m_hAccel = hAccel;
    M_ACCELDATA->m_ok = (hAccel != 0);
}

extern int wxCharCodeWXToOS2(
  int                               nId
, bool*                             pbIsVirtual
);

// Create from an array
wxAcceleratorTable::wxAcceleratorTable(
  int                               n
, const wxAcceleratorEntry          vaEntries[]
)
{
    int                             nAccelLength = ((sizeof(ACCEL) * n) + sizeof(ACCELTABLE));
    PACCELTABLE                     pArr;
    int                             i;

    m_refData = new wxAcceleratorRefData;
    pArr = (PACCELTABLE) new BYTE[nAccelLength];

    for (i = 0; i < n; i++)
    {
        USHORT                      uVirt = AF_CHAR;

        if (vaEntries[i].GetFlags() & wxACCEL_ALT)
        {
            uVirt |= AF_ALT;
            uVirt |= AF_VIRTUALKEY;
        }
        if (vaEntries[i].GetFlags() & wxACCEL_SHIFT)
        {
            uVirt |= AF_SHIFT;
            uVirt |= AF_VIRTUALKEY;
        }
        if (vaEntries[i].GetFlags() & wxACCEL_CTRL)
        {
            uVirt |= AF_CONTROL;
            uVirt |= AF_VIRTUALKEY;
        }

        bool bIsVirtual;
        USHORT uKey = (USHORT)wxCharCodeWXToOS2( vaEntries[i].GetKeyCode(),
                                                 &bIsVirtual);
        if (bIsVirtual)
            uVirt = AF_CHAR | AF_VIRTUALKEY;

        USHORT uCmd = (USHORT)vaEntries[i].GetCommand();

        pArr->aaccel[i].fs  = uVirt;
        pArr->aaccel[i].key = uKey;
        pArr->aaccel[i].cmd = uCmd;
    }
    pArr->codepage = (USHORT)::WinQueryCp(wxTheApp->m_hMq);
    pArr->cAccel = (USHORT)n;
    M_ACCELDATA->m_hAccel = ::WinCreateAccelTable( vHabmain
                                                  ,pArr
                                                 );
    if (wxTheApp->GetTopWindow() != NULL)
    {
        //
        // If we have accelerators the top window is the frame
        //
        wxFrame* pFrame = (wxFrame*)wxTheApp->GetTopWindow();

        ::WinSetAccelTable( vHabmain
                           ,M_ACCELDATA->m_hAccel
                           ,(HWND)pFrame->GetFrame()
                          );
    }

    delete[] pArr;
    M_ACCELDATA->m_ok = (M_ACCELDATA->m_hAccel != 0);
} // end of wxAcceleratorTable::wxAcceleratorTable

bool wxAcceleratorTable::IsOk() const
{
    return(M_ACCELDATA && (M_ACCELDATA->m_ok));
} // end of wxAcceleratorTable::IsOk

void wxAcceleratorTable::SetHACCEL(WXHACCEL hAccel)
{
    if (!M_ACCELDATA)
        m_refData = new wxAcceleratorRefData;

    M_ACCELDATA->m_hAccel = (HACCEL) hAccel;
}

WXHACCEL wxAcceleratorTable::GetHACCEL() const
{
    if (!M_ACCELDATA)
        return 0;
    return (WXHACCEL) M_ACCELDATA->m_hAccel;
}

bool wxAcceleratorTable::Translate( WXHWND  hWnd,
                                    WXMSG*  pWxmsg ) const
{
    PQMSG pMsg = (PQMSG)pWxmsg;
    BOOL  rc = FALSE;

    rc = ::WinTranslateAccel( vHabmain
                             ,(HWND)hWnd
                             ,GetHaccel()
                             ,pMsg
                            );
    return (Ok() && rc);
} // end of wxAcceleratorTable::Translate

// ---------------------------------------------------------------------------
// function for translating labels
// ---------------------------------------------------------------------------

wxString wxPMTextToLabel( const wxString& rsTitle )
{
    wxString      sTitle;
    const wxChar* zPc;

    if (rsTitle.empty())
        return(sTitle);

    for (zPc = rsTitle.c_str(); *zPc != wxT('\0'); zPc++)
    {
        if (*zPc == wxT('&'))
        {
            if (*(zPc + 1) == wxT('&'))
            {
                zPc++;
                sTitle << wxT('&');
            }
            else
                sTitle << wxT('~');
        }
        else
        {
            if ( *zPc == wxT('~'))
            {
                //
                // Tildes must be doubled to prevent them from being
                // interpreted as accelerator character prefix by PM ???
                //
                sTitle << *zPc;
            }
            sTitle << *zPc;
        }
    }
    return(sTitle);
} // end of wxPMTextToLabel
