/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/choice.cpp
// Purpose:     wxChoice
// Author:      David Webster
// Modified by:
// Created:     10/13/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_CHOICE

#include "wx/choice.h"

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/log.h"
    #include "wx/settings.h"
#endif

#include "wx/os2/private.h"

IMPLEMENT_DYNAMIC_CLASS(wxChoice, wxControlWithItems)

bool wxChoice::Create(
  wxWindow*                         pParent
, wxWindowID                        vId
, const wxPoint&                    rPos
, const wxSize&                     rSize
, const wxArrayString&              asChoices
, long                              lStyle
, const wxValidator&                rValidator
, const wxString&                   rsName
)
{
    wxCArrayString chs(asChoices);

    return Create(pParent, vId, rPos, rSize, chs.GetCount(), chs.GetStrings(),
                  lStyle, rValidator, rsName);
}

bool wxChoice::Create(
  wxWindow*                         pParent
, wxWindowID                        vId
, const wxPoint&                    rPos
, const wxSize&                     rSize
, int                               n
, const wxString                    asChoices[]
, long                              lStyle
, const wxValidator&                rValidator
, const wxString&                   rsName
)
{
    long                            lSstyle;

    if (!CreateControl( pParent
                       ,vId
                       ,rPos
                       ,rSize
                       ,lStyle
                       ,rValidator
                       ,rsName
                      ))
        return false;
    lSstyle = CBS_DROPDOWNLIST |
              WS_TABSTOP       |
              WS_VISIBLE;

    // clipping siblings does not yet work
    // if (lStyle & wxCLIP_SIBLINGS )
    //     lSstyle |= WS_CLIPSIBLINGS;

    wxASSERT_MSG( !(lStyle & wxCB_DROPDOWN) &&
                  !(lStyle & wxCB_READONLY) &&
                  !(lStyle & wxCB_SIMPLE),
                  wxT("this style flag is ignored by wxChoice, you "
                     "probably want to use a wxComboBox") );

    if (!OS2CreateControl( wxT("COMBOBOX")
                          ,lSstyle
                         ))
        return false;

    //
    // A choice/combobox normally has a white background (or other, depending
    // on global settings) rather than inheriting the parent's background colour.
    //
    SetBackgroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_WINDOW));

    // initialize the controls contents
    for (int i = 0; i < n; i++)
    {
        Append(asChoices[i]);
    }
    SetSize( rPos.x
            ,rPos.y
            ,rSize.x
            ,rSize.y
           );

    // Set height to use with sizers i.e. without the dropdown listbox
    wxFont vFont = GetFont();
    int  nEditHeight;
    wxGetCharSize( GetHWND(), NULL, &nEditHeight, &vFont );
    nEditHeight = EDIT_HEIGHT_FROM_CHAR_HEIGHT(nEditHeight);
    SetInitialSize(wxSize(-1,nEditHeight+4));   // +2x2 for the border

    return true;
} // end of wxChoice::Create

wxChoice::~wxChoice()
{
    Clear();
}

// ----------------------------------------------------------------------------
// adding/deleting items to/from the list
// ----------------------------------------------------------------------------

int wxChoice::DoInsertItems(const wxArrayStringsAdapter& items
                           , unsigned int pos
                           , void **clientData
                           , wxClientDataType type
                           )
{
    int                             nIndex = wxNOT_FOUND;
    LONG                            nIndexType = 0;
    bool                            incrementPos = false;
    if ( IsSorted() )
        nIndexType = LIT_SORTASCENDING;
    else if (pos == GetCount())
        nIndexType = LIT_END;
    else
    {
        nIndexType = pos;
        incrementPos = true;
    }

    const unsigned int count = items.GetCount();
    for( unsigned int i = 0; i < count; ++i )
    {
        nIndex = (int)::WinSendMsg( GetHwnd()
                                   ,LM_INSERTITEM
                                   ,(MPARAM)nIndexType
                                   ,(MPARAM)items[i].wx_str()
                                  );
        if (nIndex < 0)
        {
            nIndex = wxNOT_FOUND;
            break;
        }
        AssignNewItemClientData(nIndex, clientData, i, type);

        if (incrementPos)
            ++nIndexType;
    }
    return nIndex;
} // end of wxChoice::DoInsertAppendItemsWithData

void wxChoice::DoDeleteOneItem(unsigned int n)
{
    wxCHECK_RET( IsValid(n), wxT("invalid item index in wxChoice::Delete") );

    ::WinSendMsg(GetHwnd(), LM_DELETEITEM, (MPARAM)n, (MPARAM)0);
} // end of wxChoice::Delete

void wxChoice::DoClear()
{
    ::WinSendMsg(GetHwnd(), LM_DELETEALL, (MPARAM)0, (MPARAM)0);
} // end of wxChoice::Clear

// ----------------------------------------------------------------------------
// selection
// ----------------------------------------------------------------------------

int wxChoice::GetSelection() const
{
    return((int)LONGFROMMR(::WinSendMsg(GetHwnd(), LM_QUERYSELECTION, (MPARAM)LIT_FIRST, (MPARAM)0)));
} // end of wxChoice::GetSelection

void wxChoice::SetSelection(
  int                               n
)
{
    ::WinSendMsg( GetHwnd()
                 ,LM_SELECTITEM
                 ,(MPARAM)n
                 ,(MPARAM)TRUE
                );
} // end of wxChoice::SetSelection

// ----------------------------------------------------------------------------
// string list functions
// ----------------------------------------------------------------------------

unsigned int wxChoice::GetCount() const
{
    return((unsigned int)LONGFROMMR(::WinSendMsg(GetHwnd(), LM_QUERYITEMCOUNT, (MPARAM)0, (MPARAM)0)));
} // end of wxChoice::GetCount

void wxChoice::SetString(unsigned int n, const wxString& rsStr)
{
    LONG  nIndexType = 0;
    void* pData;

    if ( HasClientData() )
    {
        pData = DoGetItemClientData(n);
    }
    else // no client data
    {
        pData = NULL;
    }

    ::WinSendMsg(GetHwnd(), LM_DELETEITEM, (MPARAM)n, 0);

    if (m_windowStyle & wxCB_SORT)
        nIndexType = LIT_SORTASCENDING;
    else
        nIndexType = LIT_END;
    ::WinSendMsg( GetHwnd()
                 ,LM_INSERTITEM
                 ,(MPARAM)nIndexType
                 ,(MPARAM)rsStr.wx_str()
                );

    if (pData)
    {
        DoSetItemClientData(n, pData);
    }
} // end of wxChoice::SetString

wxString wxChoice::GetString(unsigned int n) const
{
    int      nLen = 0;
    wxString sStr = wxEmptyString;
    wxChar*  zBuf;

    nLen = (size_t)LONGFROMMR(::WinSendMsg(GetHwnd(), LM_QUERYITEMTEXTLENGTH, (MPARAM)n, (MPARAM)0));
    if (nLen != LIT_ERROR && nLen > 0)
    {
        zBuf = new wxChar[++nLen];
        ::WinSendMsg( GetHwnd()
                     ,LM_QUERYITEMTEXT
                     ,MPFROM2SHORT((SHORT)n, (SHORT)nLen)
                     ,(MPARAM)zBuf
                    );
        sStr = zBuf;
        delete [] zBuf;
    }
    return sStr;
} // end of wxChoice::GetString

// ----------------------------------------------------------------------------
// client data
// ----------------------------------------------------------------------------

void wxChoice::DoSetItemClientData(unsigned int n, void* pClientData)
{
    ::WinSendMsg(GetHwnd(), LM_SETITEMHANDLE, (MPARAM)n, MPFROMP(pClientData));
} // end of wxChoice::DoSetItemClientData

void* wxChoice::DoGetItemClientData(unsigned int n) const
{
    MRESULT rc = ::WinSendMsg(GetHwnd(), LM_QUERYITEMHANDLE, (MPARAM)n, (MPARAM)0);
    return((void*)rc);
} // end of wxChoice::DoGetItemClientData

// ----------------------------------------------------------------------------
// wxOS2 specific helpers
// ----------------------------------------------------------------------------

void wxChoice::DoSetSize(int nX,
                         int nY,
                         int nWidth,
                         int WXUNUSED(nHeight),
                         int nSizeFlags)
{
    //
    // Ignore height parameter because height doesn't mean 'initially
    // displayed' height, it refers to the drop-down menu as well. The
    // wxWidgets interpretation is different; also, getting the size returns
    // the _displayed_ size (NOT the drop down menu size) so
    // setting-getting-setting size would not work.
    //
    wxControl::DoSetSize( nX
                         ,nY
                         ,nWidth
                         ,wxDefaultCoord
                         ,nSizeFlags
                        );
} // end of wxChoice::DoSetSize

wxSize wxChoice::DoGetBestSize() const
{
    //
    // Find the widest string
    //
    int    nLineWidth;
    int    nChoiceWidth = 0;
    int    nCx;
    int    nCy;
    wxFont vFont = (wxFont)GetFont();

    const unsigned int nItems = GetCount();

    for (unsigned int i = 0; i < nItems; i++)
    {
        wxString sStr(GetString(i));
        GetTextExtent( sStr, &nLineWidth, NULL );
        if (nLineWidth > nChoiceWidth)
            nChoiceWidth = nLineWidth;
    }

    //
    // Give it some reasonable default value if there are no strings in the
    // list
    //
    if (nChoiceWidth == 0L)
        nChoiceWidth = 100L;

    //
    // The combobox should be larger than the widest string
    //
    wxGetCharSize( GetHWND(), &nCx, &nCy, &vFont );
    nChoiceWidth += 5 * nCx;

    //
    // Choice drop-down list depends on number of items (limited to 10)
    //
    size_t nStrings = nItems == 0 ? 10 : wxMin(10, nItems) + 1;
    int    nChoiceHeight = EDIT_HEIGHT_FROM_CHAR_HEIGHT(nCy) * nStrings;

    return wxSize(nChoiceWidth, nChoiceHeight);
} // end of wxChoice::DoGetBestSize

MRESULT wxChoice::OS2WindowProc(
  WXUINT                            uMsg
, WXWPARAM                          wParam
, WXLPARAM                          lParam
)
{
    return wxWindow::OS2WindowProc( uMsg
                                   ,wParam
                                   ,lParam
                                  );
} // end of wxChoice::OS2WindowProc

bool wxChoice::OS2Command(
  WXUINT                            uParam
, WXWORD                            WXUNUSED(wId)
)
{
    if (uParam != LN_SELECT)
    {
        //
        // "selection changed" is the only event we're after
        //
        return false;
    }
    int                             n = GetSelection();

    if (n > -1)
    {
        wxCommandEvent              vEvent( wxEVT_COMMAND_CHOICE_SELECTED
                                           ,m_windowId
                                          );

        vEvent.SetInt(n);
        vEvent.SetEventObject(this);
        vEvent.SetString(GetStringSelection());
        if (HasClientObjectData())
            vEvent.SetClientObject(GetClientObject(n));
        else if (HasClientUntypedData())
            vEvent.SetClientData(GetClientData(n));
        ProcessCommand(vEvent);
    }
    return true;
} // end of wxChoice::OS2Command

#endif // wxUSE_CHOICE
