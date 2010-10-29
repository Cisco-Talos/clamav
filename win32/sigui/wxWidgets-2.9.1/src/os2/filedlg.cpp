/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/filedlg.cpp
// Purpose:     wxFileDialog
// Author:      David Webster
// Modified by:
// Created:     10/05/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_FILEDLG

#include "wx/filedlg.h"

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/msgdlg.h"
    #include "wx/filename.h"
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/app.h"
    #include "wx/math.h"
#endif

#define INCL_PM
#include <os2.h>

#include "wx/os2/private.h"

#include <stdlib.h>
#include <string.h>

#include "wx/tokenzr.h"

#define wxMAXPATH                    1024
#define wxMAXFILE                    1024
#define wxMAXEXT                        5

#ifndef MAXPATH
# define MAXPATH                      400
#endif

#ifndef MAXDRIVE
# define MAXDRIVE                       3
#endif

#ifndef MAXFILE
# define MAXFILE                        9
#endif

#ifndef MAXEXT
# define MAXEXT                         5
#endif

IMPLEMENT_CLASS(wxFileDialog, wxFileDialogBase)

// ----------------------------------------------------------------------------
// CLASS wxFileDialog
// ----------------------------------------------------------------------------

wxFileDialog::wxFileDialog (
  wxWindow*                         pParent
, const wxString&                   rsMessage
, const wxString&                   rsDefaultDir
, const wxString&                   rsDefaultFileName
, const wxString&                   rsWildCard
, long                              lStyle
, const wxPoint&                    rPos,
  const wxSize& sz,
  const wxString& name
)
    :wxFileDialogBase(pParent, rsMessage, rsDefaultDir, rsDefaultFileName, rsWildCard, lStyle, rPos, sz, name)

{
    // NB: all style checks are done by wxFileDialogBase::Create

    m_filterIndex = 1;
} // end of wxFileDialog::wxFileDialog

void wxFileDialog::GetPaths (
  wxArrayString&                    rasPaths
) const
{
    wxString                        sDir(m_dir);
    size_t                          nCount = m_fileNames.GetCount();

    rasPaths.Empty();
    if (m_dir.Last() != wxT('\\'))
        sDir += wxT('\\');

    for ( size_t n = 0; n < nCount; n++ )
    {
        rasPaths.Add(sDir + m_fileNames[n]);
    }
} // end of wxFileDialog::GetPaths

int wxFileDialog::ShowModal()
{
    wxString                        sTheFilter;
    wxString                        sFilterBuffer;
    wxChar*                         pzFilterBuffer;
    static wxChar                   zFileNameBuffer[wxMAXPATH];           // the file-name
    HWND                            hWnd = 0;
    wxChar                          zTitleBuffer[wxMAXFILE + 1 + wxMAXEXT];  // the file-name, without path
    wxString                        sDir;
    size_t                          i;
    size_t                          nLen = m_dir.length();
    int                             nCount = 0;
    FILEDLG                         vFileDlg;
    ULONG                           lFlags = 0L;

    memset(&vFileDlg, '\0', sizeof(FILEDLG));
    if (m_parent)
        hWnd = (HWND) m_parent->GetHWND();
    if (!hWnd && wxTheApp->GetTopWindow())
        hWnd = (HWND) wxTheApp->GetTopWindow()->GetHWND();


    *zFileNameBuffer = wxT('\0');
    *zTitleBuffer    = wxT('\0');

    if (m_windowStyle & wxFD_SAVE)
        lFlags = FDS_SAVEAS_DIALOG;
    else
        lFlags = FDS_OPEN_DIALOG;

    if (m_windowStyle & wxFD_SAVE)
        lFlags |= FDS_SAVEAS_DIALOG;
    if (m_windowStyle & wxFD_MULTIPLE)
        lFlags |= FDS_OPEN_DIALOG | FDS_MULTIPLESEL;

    vFileDlg.cbSize = sizeof(FILEDLG);
    vFileDlg.fl = lFlags;
    vFileDlg.pszTitle = (PSZ)zTitleBuffer;

    //
    // Convert forward slashes to backslashes (file selector doesn't like
    // forward slashes) and also squeeze multiple consecutive slashes into one
    // as it doesn't like two backslashes in a row neither
    //
    sDir.reserve(nLen);
    for ( i = 0; i < nLen; i++ )
    {
        wxChar                      ch = m_dir[i];

        switch (ch)
        {
            case wxT('/'):
                //
                // Convert to backslash
                //
                ch = wxT('\\');

                //
                // Fall through
                //
            case wxT('\\'):
                while (i < nLen - 1)
                {
                    wxChar          chNext = m_dir[i + 1];

                    if (chNext != wxT('\\') && chNext != wxT('/'))
                        break;

                    //
                    // Ignore the next one, unless it is at the start of a UNC path
                    //
                    if (i > 0)
                        i++;
                    else
                        break;
                }

                //
                // Fall through
                //

            default:
                //
                // Normal char
                sDir += ch;
        }
    }
    if ( wxStrlen(m_wildCard) == 0 )
        sTheFilter = wxEmptyString;
    else
        sTheFilter = m_wildCard;

    wxStrtok(sTheFilter.wchar_str(), wxT("|"), &pzFilterBuffer);
    while(pzFilterBuffer != NULL)
    {
        if (nCount > 0 && !(nCount % 2))
            sDir += wxT(";");
        if (nCount % 2)
        {
            sDir += pzFilterBuffer;
        }
        wxStrtok(NULL, wxT("|"), &pzFilterBuffer);
        nCount++;
    }
    if (nCount == 0)
        sDir += m_fileName;
    if (sDir.empty())
        sDir = wxT("*.*");
    wxStrcpy((wxChar*)vFileDlg.szFullFile, sDir);
    sFilterBuffer = sDir;

    hWnd = ::WinFileDlg( HWND_DESKTOP
                        ,GetHwndOf(m_parent)
                        ,&vFileDlg
                       );
    if (hWnd && vFileDlg.lReturn == DID_OK)
    {
        m_fileNames.Empty();
        if ((m_windowStyle & wxFD_MULTIPLE ) && vFileDlg.ulFQFCount > 1)
        {
            for (int i = 0; i < (int)vFileDlg.ulFQFCount; i++)
            {
                if (i == 0)
                {
                    m_dir = wxPathOnly(wxString((const wxChar*)*vFileDlg.papszFQFilename[0]));
                    m_path = (const wxChar*)*vFileDlg.papszFQFilename[0];
                }
                m_fileName = wxFileNameFromPath(wxString((const wxChar*)*vFileDlg.papszFQFilename[i]));
                m_fileNames.Add(m_fileName);
            }
            ::WinFreeFileDlgList(vFileDlg.papszFQFilename);
        }
        else if (!(m_windowStyle & wxFD_SAVE))
        {
            m_path = (wxChar*)vFileDlg.szFullFile;
            m_fileName = wxFileNameFromPath(wxString((const wxChar*)vFileDlg.szFullFile));
            m_dir = wxPathOnly((const wxChar*)vFileDlg.szFullFile);
        }
        else // save file
        {
            const wxChar*           pzExtension = NULL;

            wxStrcpy(zFileNameBuffer, (const wxChar*)vFileDlg.szFullFile);

            int                     nIdx = wxStrlen(zFileNameBuffer) - 1;
            wxString                sExt;

            wxFileName::SplitPath( zFileNameBuffer
                                    ,&m_path
                                    ,&m_fileName
                                    ,&sExt
                                  );
            if (zFileNameBuffer[nIdx] == wxT('.') || sExt.empty())
            {
                zFileNameBuffer[nIdx] = wxT('\0');

                //
                // User has typed a filename without an extension:
                //
                // A filename can end in a "." here ("abc."), this means it
                // does not have an extension. Because later on a "." with
                // the default extension is appended we remove the "." if
                // filename ends with one (We don't want files called
                // "abc..ext")
                //
                pzExtension = sFilterBuffer.c_str();

                for( int i = 0; i < (int)sFilterBuffer.length(); i++ )
                {
                    //
                    // Get extension
                    //
                    pzExtension = wxStrrchr(pzExtension, wxT('.'));
                    if ( pzExtension                      &&
                        !wxStrrchr(pzExtension, wxT('*')) &&
                        !wxStrrchr(pzExtension, wxT('?')) &&
                        pzExtension[1]                    &&
                        pzExtension[1] != wxT(' ')
                       )              // != "blabla. "
                    {
                        //
                        // Now concat extension to the fileName:
                        //
                        m_path = wxString(zFileNameBuffer) + pzExtension;
                    }
                }
            }
            else
            {
                m_path = (wxChar*)vFileDlg.szFullFile;
            }
            m_fileName = wxFileNameFromPath((const wxChar*)vFileDlg.szFullFile);
            m_dir = wxPathOnly((const wxChar*)vFileDlg.szFullFile);

            //
            // === Simulating the wxFD_OVERWRITE_PROMPT >>============================
            //
            if ((m_windowStyle & wxFD_OVERWRITE_PROMPT) &&
                (m_windowStyle & wxFD_SAVE) &&
                (wxFileExists(m_path.c_str())))
            {
                wxString            sMessageText;

                sMessageText.Printf( _("File '%s' already exists.\nDo you want to replace it?")
                                    ,m_path.c_str()
                                   );
                if (wxMessageBox( sMessageText
                                 ,wxT("Save File As")
                                 ,wxYES_NO | wxICON_EXCLAMATION
                                ) != wxYES)
                {
                    return wxID_CANCEL;
                }
            }
        }
        return wxID_OK;
    }
    return wxID_CANCEL;
} // end of wxFileDialog::ShowModal

#endif // wxUSE_FILEDLG
