/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/toolbar.cpp
// Purpose:     wxToolBar
// Author:      David Webster
// Modified by:
// Created:     06/30/02
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_TOOLBAR && wxUSE_TOOLBAR_NATIVE

#include "wx/toolbar.h"

#ifndef WX_PRECOMP
    #include "wx/settings.h"
    #include "wx/window.h"
    #include "wx/frame.h"
    #include "wx/app.h"
    #include "wx/dcclient.h"
    #include "wx/dcmemory.h"
#endif

#include "wx/tooltip.h"
#include "wx/os2/dcclient.h"

bool wxToolBar::m_bInitialized = false;

// ----------------------------------------------------------------------------
// private classes
// ----------------------------------------------------------------------------

class wxToolBarTool : public wxToolBarToolBase
{
public:
    inline wxToolBarTool( wxToolBar*      pTbar
                         ,int             vId
                         ,const wxString& rsLabel
                         ,const wxBitmap& rBitmap1
                         ,const wxBitmap& rBitmap2
                         ,wxItemKind      vKind
                         ,wxObject*       pClientData
                         ,const wxString& rsShortHelpString
                         ,const wxString& rsLongHelpString
                        ) : wxToolBarToolBase( pTbar
                                              ,vId
                                              ,rsLabel
                                              ,rBitmap1
                                              ,rBitmap2
                                              ,vKind
                                              ,pClientData
                                              ,rsShortHelpString
                                              ,rsLongHelpString
                                             )
    {
    }

    inline wxToolBarTool( wxToolBar* pTbar
                         ,wxControl* pControl
                         ,const wxString& label
                        ) : wxToolBarToolBase( pTbar
                                              ,pControl
                                              ,label
                                             )
    {
    }

    void SetSize(const wxSize& rSize)
    {
        m_vWidth = rSize.x;
        m_vHeight = rSize.y;
    }

    wxCoord GetWidth(void) const { return m_vWidth; }
    wxCoord GetHeight(void) const { return m_vHeight; }

    wxCoord                         m_vX;
    wxCoord                         m_vY;
    wxCoord                         m_vWidth;
    wxCoord                         m_vHeight;
}; // end of CLASS wxToolBarTool

// ----------------------------------------------------------------------------
// wxWin macros
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxToolBar, wxControl)

BEGIN_EVENT_TABLE(wxToolBar, wxToolBarBase)
    EVT_SIZE(wxToolBar::OnSize)
    EVT_PAINT(wxToolBar::OnPaint)
    EVT_KILL_FOCUS(wxToolBar::OnKillFocus)
    EVT_MOUSE_EVENTS(wxToolBar::OnMouseEvent)
    EVT_TIMER(-1, wxToolBar::OnTimer)
END_EVENT_TABLE()

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// tool bar tools creation
// ----------------------------------------------------------------------------

wxToolBarToolBase* wxToolBar::CreateTool(
  int                               nId
, const wxString&                   rsLabel
, const wxBitmap&                   rBmpNormal
, const wxBitmap&                   rBmpDisabled
, wxItemKind                        eKind
, wxObject*                         pClientData
, const wxString&                   rsShortHelp
, const wxString&                   rsLongHelp
)
{
    return new wxToolBarTool( this
                             ,nId
                             ,rsLabel
                             ,rBmpNormal
                             ,rBmpDisabled
                             ,eKind
                             ,pClientData
                             ,rsShortHelp
                             ,rsLongHelp
                            );
} // end of wxToolBarSimple::CreateTool

wxToolBarToolBase *wxToolBar::CreateTool(
  wxControl*                        pControl
, const wxString&                   label
)
{
    return new wxToolBarTool( this
                             ,pControl
                             ,label
                            );
} // end of wxToolBarSimple::CreateTool

// ----------------------------------------------------------------------------
// wxToolBarSimple creation
// ----------------------------------------------------------------------------

void wxToolBar::Init()
{
    m_nCurrentRowsOrColumns = 0;

    m_vLastX = m_vLastY = 0;
    m_vMaxWidth = m_vMaxHeight = 0;
    m_nPressedTool = m_nCurrentTool = -1;
    m_vXPos = m_vYPos = -1;
    m_vTextX = m_vTextY = 0;

    m_toolPacking = 1;
    m_toolSeparation = 5;

    m_defaultWidth = 16;
    m_defaultHeight = 15;

    m_pToolTip = NULL;
} // end of wxToolBar::Init

wxToolBarToolBase* wxToolBar::DoAddTool(
  int                               vId
, const wxString&                   rsLabel
, const wxBitmap&                   rBitmap
, const wxBitmap&                   rBmpDisabled
, wxItemKind                        eKind
, const wxString&                   rsShortHelp
, const wxString&                   rsLongHelp
, wxObject*                         pClientData
, wxCoord                           vXPos
, wxCoord                           vYPos
)
{
    //
    // Rememeber the position for DoInsertTool()
    //
    m_vXPos = vXPos;
    m_vYPos = vYPos;

    return wxToolBarBase::DoAddTool( vId
                                    ,rsLabel
                                    ,rBitmap
                                    ,rBmpDisabled
                                    ,eKind
                                    ,rsShortHelp
                                    ,rsLongHelp
                                    ,pClientData
                                    ,vXPos
                                    ,vYPos
                                   );
} // end of wxToolBar::DoAddTool

bool wxToolBar::DeleteTool(
  int                               nId
)
{
    bool                            bOk = wxToolBarBase::DeleteTool(nId);

    if (bOk)
    {
        Realize();
    }
    return bOk;
} // end of wxToolBar::DeleteTool

bool wxToolBar::DeleteToolByPos(
  size_t                            nPos
)
{
    bool                            bOk = wxToolBarBase::DeleteToolByPos(nPos);

    if (bOk)
    {
        Realize();
    }
    return bOk;
} // end of wxToolBar::DeleteTool

wxToolBarToolBase* wxToolBar::InsertControl(
  size_t                            nPos
, wxControl*                        pControl
)
{
    wxToolBarToolBase*              pTool = wxToolBarBase::InsertControl( nPos
                                                                         ,pControl
                                                                        );
    if (m_bInitialized)
    {
        Realize();
        Refresh();
    }
    return pTool;
} // end of wxToolBar::InsertControl

wxToolBarToolBase* wxToolBar::InsertSeparator(
  size_t                            nPos
)
{
    wxToolBarToolBase*              pTool = wxToolBarBase::InsertSeparator(nPos);

    if (m_bInitialized)
    {
        Realize();
        Refresh();
    }
    return pTool;
} // end of wxToolBar::InsertSeparator

wxToolBarToolBase* wxToolBar::InsertTool(
  size_t                            nPos
, int                               nId
, const wxString&                   rsLabel
, const wxBitmap&                   rBitmap
, const wxBitmap&                   rBmpDisabled
, wxItemKind                        eKind
, const wxString&                   rsShortHelp
, const wxString&                   rsLongHelp
, wxObject*                         pClientData
)
{
    wxToolBarToolBase*              pTool = wxToolBarBase::InsertTool( nPos
                                                                      ,nId
                                                                      ,rsLabel
                                                                      ,rBitmap
                                                                      ,rBmpDisabled
                                                                      ,eKind
                                                                      ,rsShortHelp
                                                                      ,rsLongHelp
                                                                      ,pClientData
                                                                     );
    if (m_bInitialized)
    {
        Realize();
        Refresh();
    }
    return pTool;
} // end of wxToolBar::InsertTool

bool wxToolBar::DoInsertTool( size_t WXUNUSED(nPos),
                              wxToolBarToolBase* pToolBase )
{
    wxToolBarTool* pTool = (wxToolBarTool *)pToolBase;

    pTool->m_vX = m_vXPos;
    if (pTool->m_vX == -1)
        pTool->m_vX = m_xMargin;

    pTool->m_vY = m_vYPos;
    if (pTool->m_vY == -1)
        pTool->m_vX = m_yMargin;

    pTool->SetSize(GetToolSize());

    if (pTool->IsButton())
    {
        //
        // Calculate reasonable max size in case Layout() not called
        //
        if ((pTool->m_vX + pTool->GetNormalBitmap().GetWidth() + m_xMargin) > m_vMaxWidth)
            m_vMaxWidth = (wxCoord)((pTool->m_vX + pTool->GetWidth() + m_xMargin));

        if ((pTool->m_vY + pTool->GetNormalBitmap().GetHeight() + m_yMargin) > m_vMaxHeight)
            m_vMaxHeight = (wxCoord)((pTool->m_vY + pTool->GetHeight() + m_yMargin));
    }
    return true;
} // end of wxToolBar::DoInsertTool

bool wxToolBar::DoDeleteTool( size_t WXUNUSED(nPos),
                              wxToolBarToolBase* pTool )
{
    pTool->Detach();
    Refresh();
    return true;
} // end of wxToolBar::DoDeleteTool

bool wxToolBar::Create( wxWindow* pParent,
                        wxWindowID vId,
                        const wxPoint& rPos,
                        const wxSize& rSize,
                        long lStyle,
                        const wxString& rsName )
{
    if ( !wxWindow::Create( pParent
                           ,vId
                           ,rPos
                           ,rSize
                           ,lStyle
                           ,rsName
                          ))
        return false;

    // Set it to grey (or other 3D face colour)
    SetBackgroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_MENUBAR));
    SetFont(*wxSMALL_FONT);

    if (GetWindowStyleFlag() & (wxTB_LEFT | wxTB_RIGHT))
    {
        m_vLastX = 7;
        m_vLastY = 3;

        m_maxRows = 32000;      // a lot
        m_maxCols = 1;
    }
    else
    {
        m_vLastX = 3;
        m_vLastY = 7;

        m_maxRows = 1;
        m_maxCols = 32000;      // a lot
    }
    SetCursor(*wxSTANDARD_CURSOR);

    //
    // The toolbar's tools, if they have labels and the winTB_TEXT
    // style is set, then we need to take into account the size of
    // the text when drawing tool bitmaps and the text
    //
    if (HasFlag(wxTB_TEXT))
    {
        wxClientDC                  vDC(this);

        vDC.SetFont(GetFont());
        vDC.GetTextExtent( wxT("XXXX")
                          ,&m_vTextX
                          ,&m_vTextY
                         );
    }

    //
    // Position it
    //
    int                             nX      = rPos.x;
    int                             nY      = rPos.y;
    int                             nWidth  = rSize.x;
    int                             nHeight = rSize.y;

    if (lStyle & (wxTB_TOP | wxTB_BOTTOM))
    {
        if (nWidth <= 0)
        {
            nWidth = pParent->GetClientSize().x;
        }
        if (nHeight <= 0)
        {
            if (lStyle & wxTB_TEXT)
                nHeight = m_defaultHeight + m_vTextY;
            else
                nHeight = m_defaultHeight;
        }
    }
    else
    {
        if (nHeight <= 0)
        {
            nHeight = pParent->GetClientSize().y;
        }
        if (nWidth <= 0)
        {
            if (lStyle & wxTB_TEXT)
                nWidth = m_vTextX + (int)(m_vTextX/2); // a little margin
            else
                nWidth = m_defaultWidth + (int)(m_defaultWidth/2); // a little margin
        }
    }
    if (nX < 0)
        nX = 0;
    if (nY < 0)
        nY = 0;

    SetSize( nX
            ,nY
            ,nWidth
            ,nHeight
           );
    return true;
} // end of wxToolBar::Create

wxToolBar::~wxToolBar()
{
    wxDELETE(m_pToolTip);
} // end of wxToolBar::~wxToolBar

bool wxToolBar::Realize()
{
    int                             nMaxToolWidth  = 0;
    int                             nMaxToolHeight = 0;

    m_nCurrentRowsOrColumns = 0;
    m_vLastX               = m_xMargin;
    m_vLastY               = m_yMargin;
    m_vMaxWidth            = 0;
    m_vMaxHeight           = 0;


    //
    // Find the maximum tool width and height
    //
    wxToolBarToolsList::compatibility_iterator     node = m_tools.GetFirst();

    while (node )
    {
        wxToolBarTool*              pTool = (wxToolBarTool *)node->GetData();

        if (HasFlag(wxTB_TEXT) && !pTool->GetLabel().empty())
        {
            //
            // Set the height according to the font and the border size
            //
            if (pTool->GetWidth() > m_vTextX)
                nMaxToolWidth = pTool->GetWidth() + 4;
            else
                nMaxToolWidth = m_vTextX;
            if (pTool->GetHeight() + m_vTextY > nMaxToolHeight)
                nMaxToolHeight = pTool->GetHeight() + m_vTextY;
        }
        else
        {
            if (pTool->GetWidth() > nMaxToolWidth )
                nMaxToolWidth = pTool->GetWidth() + 4;
            if (pTool->GetHeight() > nMaxToolHeight)
                nMaxToolHeight = pTool->GetHeight();
        }
        node = node->GetNext();
    }

    wxCoord                         vTbWidth = 0L;
    wxCoord                         vTbHeight = 0L;

    GetSize( &vTbWidth
            ,&vTbHeight
           );
    if (vTbHeight < nMaxToolHeight)
    {
        SetSize( -1L
                ,-1L
                ,vTbWidth
                ,nMaxToolHeight + 4
               );
        if (GetParent()->IsKindOf(CLASSINFO(wxFrame)))
        {
            wxFrame*            pFrame = wxDynamicCast(GetParent(), wxFrame);

            if (pFrame)
                pFrame->PositionToolBar();
        }
    }

    int                             nSeparatorSize = m_toolSeparation;

    node = m_tools.GetFirst();
    while (node)
    {
        wxToolBarTool*              pTool = (wxToolBarTool *)node->GetData();

        if (pTool->IsSeparator())
        {
            if (GetWindowStyleFlag() & (wxTB_TOP | wxTB_BOTTOM))
            {
                pTool->m_vX = m_vLastX + nSeparatorSize;
                pTool->m_vHeight = m_defaultHeight + m_vTextY;
                if (m_nCurrentRowsOrColumns >= m_maxCols)
                    m_vLastY += nSeparatorSize;
                else
                    m_vLastX += nSeparatorSize * 4;
            }
            else
            {
                pTool->m_vY = m_vLastY + nSeparatorSize;
                pTool->m_vHeight = m_defaultHeight + m_vTextY;
                if (m_nCurrentRowsOrColumns >= m_maxRows)
                    m_vLastX += nSeparatorSize;
                else
                    m_vLastY += nSeparatorSize * 4;
            }
        }
        else if (pTool->IsButton())
        {
            if (GetWindowStyleFlag() & (wxTB_TOP | wxTB_BOTTOM))
            {
                if (m_nCurrentRowsOrColumns >= m_maxCols)
                {
                    m_nCurrentRowsOrColumns = 0;
                    m_vLastX                = m_xMargin;
                    m_vLastY               += nMaxToolHeight + m_toolPacking;
                }
                pTool->m_vX = m_vLastX + (nMaxToolWidth - ((int)(nMaxToolWidth/2) + (int)(pTool->GetWidth()/2)));
                if (HasFlag(wxTB_TEXT))
                    pTool->m_vY = m_vLastY + nSeparatorSize - 2; // just bit of adjustment
                else
                    pTool->m_vY = m_vLastY + (nMaxToolHeight - (int)(pTool->GetHeight()/2));
                m_vLastX += nMaxToolWidth + m_toolPacking + m_toolSeparation;
            }
            else
            {
                if (m_nCurrentRowsOrColumns >= m_maxRows)
                {
                    m_nCurrentRowsOrColumns = 0;
                    m_vLastX               += (nMaxToolWidth + m_toolPacking);
                    m_vLastY                = m_yMargin;
                }
                pTool->m_vX = m_vLastX + pTool->GetWidth();
                if (HasFlag(wxTB_TEXT) && !pTool->GetLabel().IsNull())
                    pTool->m_vY = m_vLastY + (nMaxToolHeight - m_vTextY) + m_toolPacking;
                else
                    pTool->m_vY = m_vLastY + (nMaxToolHeight - (int)(pTool->GetHeight()/2));
                m_vLastY += nMaxToolHeight + m_toolPacking + m_toolSeparation;
            }
            m_nCurrentRowsOrColumns++;
        }
        else
        {
            // TODO: support the controls
        }

        if (m_vLastX > m_maxWidth)
            m_maxWidth = m_vLastX;
        if (m_vLastY > m_maxHeight)
            m_maxHeight = m_vLastY;

        node = node->GetNext();
    }

    if (GetWindowStyleFlag() & (wxTB_TOP | wxTB_BOTTOM))
        m_maxWidth += nMaxToolWidth;
    else
        m_maxHeight += nMaxToolHeight;

    m_maxWidth += m_xMargin;
    m_maxHeight += m_yMargin;
    m_bInitialized = true;
    return true;
} // end of wxToolBar::Realize

// ----------------------------------------------------------------------------
// event handlers
// ----------------------------------------------------------------------------

void wxToolBar::OnPaint (
  wxPaintEvent&                     WXUNUSED(rEvent)
)
{
    wxPaintDC                       vDc(this);

    PrepareDC(vDc);

    static int                      nCount = 0;

    //
    // Prevent reentry of OnPaint which would cause wxMemoryDC errors.
    //
    if (nCount > 0)
        return;
    nCount++;

    wxPMDCImpl *impl = (wxPMDCImpl*) vDc.GetImpl();
    ::WinFillRect(impl->GetHPS(), &impl->m_vRclPaint, GetBackgroundColour().GetPixel());
    for ( wxToolBarToolsList::compatibility_iterator node = m_tools.GetFirst();
          node;
          node = node->GetNext() )
    {
        wxToolBarTool*              pTool = (wxToolBarTool*)node->GetData();

        if (pTool->IsButton() )
            DrawTool(vDc, pTool);
        if (pTool->IsSeparator())
        {
            wxColour gray85(85, 85, 85);
            wxPen vDarkGreyPen( gray85, 1, wxSOLID );
            int nX;
            int nY;
            int nHeight = 0;
            int nWidth = 0;

            vDc.SetPen(vDarkGreyPen);
            if (HasFlag(wxTB_TEXT))
            {
                if (HasFlag(wxTB_TOP) || HasFlag(wxTB_BOTTOM))
                {
                    nX = pTool->m_vX;
                    nY = pTool->m_vY - (m_vTextY - 6);
                    nHeight = (m_vTextY - 2) + pTool->GetHeight();
                }
                else
                {
                    nX = pTool->m_vX + m_xMargin + 10;
                    nY = pTool->m_vY + m_vTextY + m_toolSeparation;
                    nWidth = pTool->GetWidth() > m_vTextX ? pTool->GetWidth() : m_vTextX;
                }
            }
            else
            {
                nX = pTool->m_vX;
                nY = pTool->m_vY;
                if (HasFlag(wxTB_TOP) || HasFlag(wxTB_BOTTOM))
                    nHeight = pTool->GetHeight() - 2;
                else
                {
                    nX += m_xMargin + 10;
                    nY +=  m_yMargin + m_toolSeparation;
                    nWidth = pTool->GetWidth();
                }
            }
            vDc.DrawLine(nX, nY, nX + nWidth, nY + nHeight);
        }
    }
    nCount--;
} // end of wxToolBar::OnPaint

void wxToolBar::OnSize (
  wxSizeEvent&                      WXUNUSED(rEvent)
)
{
#if wxUSE_CONSTRAINTS
    if (GetAutoLayout())
        Layout();
#endif
} // end of wxToolBar::OnSize

void wxToolBar::OnKillFocus(
  wxFocusEvent&                     WXUNUSED(rEvent)
)
{
    OnMouseEnter(m_nPressedTool = m_nCurrentTool = -1);
} // end of wxToolBar::OnKillFocus

void wxToolBar::OnMouseEvent(
  wxMouseEvent&                     rEvent
)
{
    POINTL                          vPoint;
    HWND                            hWnd;
    wxCoord                         vX;
    wxCoord                         vY;
    HPOINTER                        hPtr = ::WinQuerySysPointer(HWND_DESKTOP, SPTR_ARROW, FALSE);

    ::WinSetPointer(HWND_DESKTOP, hPtr);
    ::WinQueryPointerPos(HWND_DESKTOP, &vPoint);
    hWnd = ::WinWindowFromPoint(HWND_DESKTOP, &vPoint, TRUE);
    if (hWnd != (HWND)GetHwnd())
    {
        m_vToolTimer.Stop();
        return;
    }

    rEvent.GetPosition(&vX, &vY);

    wxToolBarTool*            pTool = (wxToolBarTool *)FindToolForPosition( vX
                                                                           ,vY
                                                                          );

    if (rEvent.LeftDown())
    {
        CaptureMouse();
    }
    if (rEvent.LeftUp())
    {
        ReleaseMouse();
    }

    if (!pTool)
    {
        m_vToolTimer.Stop();
        if (m_nCurrentTool > -1)
        {
            if (rEvent.LeftIsDown())
                SpringUpButton(m_nCurrentTool);
            pTool = (wxToolBarTool *)FindById(m_nCurrentTool);
            if (pTool && !pTool->IsToggled())
            {
                RaiseTool( pTool, FALSE );
            }
            m_nCurrentTool = -1;
            OnMouseEnter(-1);
        }
        return;
    }
    if (!rEvent.IsButton())
    {
        if (pTool->GetId() != m_nCurrentTool)
        {
            //
            // If the left button is kept down and moved over buttons,
            // press those buttons.
            //
            if (rEvent.LeftIsDown() && pTool->IsEnabled())
            {
                SpringUpButton(m_nCurrentTool);
                if (pTool->CanBeToggled())
                {
                    pTool->Toggle();
                }
                DrawTool(pTool);
            }
            wxToolBarTool*          pOldTool = (wxToolBarTool*)FindById(m_nCurrentTool);

            if (pOldTool && !pTool->IsToggled())
                RaiseTool( pOldTool, FALSE );
            m_nCurrentTool = pTool->GetId();
            OnMouseEnter(m_nCurrentTool);
            if (!pTool->GetShortHelp().empty())
            {
                if (m_pToolTip)
                    delete m_pToolTip;
                m_pToolTip = new wxToolTip(pTool->GetShortHelp());
                m_vXMouse = (wxCoord)vPoint.x;
                m_vYMouse = (wxCoord)vPoint.y;
                m_vToolTimer.Start(1000L, TRUE);
            }
            if (!pTool->IsToggled())
                RaiseTool(pTool);
        }
        return;
    }

    // Left button pressed.
    if (rEvent.LeftDown() && pTool->IsEnabled())
    {
        if (pTool->CanBeToggled())
        {
            pTool->Toggle();
        }
        DrawTool(pTool);
    }
    else if (rEvent.RightDown())
    {
        OnRightClick( pTool->GetId()
                     ,vX
                     ,vY
                    );
    }

    //
    // Left Button Released.  Only this action confirms selection.
    // If the button is enabled and it is not a toggle tool and it is
    // in the pressed state, then raise the button and call OnLeftClick.
    //
    if (rEvent.LeftUp() && pTool->IsEnabled() )
    {
        //
        // Pass the OnLeftClick event to tool
        //
        if (!OnLeftClick( pTool->GetId()
                         ,pTool->IsToggled()) &&
                          pTool->CanBeToggled())
        {
            //
            // If it was a toggle, and OnLeftClick says No Toggle allowed,
            // then change it back
            //
            pTool->Toggle();
        }
        DrawTool(pTool);
    }
} // end of wxToolBar::OnMouseEvent

// ----------------------------------------------------------------------------
// drawing
// ----------------------------------------------------------------------------

void wxToolBar::DrawTool( wxToolBarToolBase* pTool )
{
    wxClientDC vDc(this);

    DrawTool( vDc, pTool );
} // end of wxToolBar::DrawTool

void wxToolBar::DrawTool( wxDC& rDc, wxToolBarToolBase* pToolBase )
{
    wxToolBarTool* pTool = (wxToolBarTool *)pToolBase;
    wxColour gray85( 85,85,85 );
    wxPen vDarkGreyPen( gray85, 1, wxSOLID );
    wxBitmap vBitmap = pTool->GetNormalBitmap();
    bool bUseMask = false;
    wxMask* pMask = NULL;

    PrepareDC(rDc);

    if (!vBitmap.Ok())
        return;
    if ((pMask = vBitmap.GetMask()) != NULL)
        if (pMask->GetMaskBitmap() != NULLHANDLE)
            bUseMask = true;

    if (!pTool->IsToggled())
    {
        LowerTool(pTool, FALSE);
        if (!pTool->IsEnabled())
        {
            wxColour vColor(wxT("GREY"));

            rDc.SetTextForeground(vColor);
            if (!pTool->GetDisabledBitmap().Ok())
                pTool->SetDisabledBitmap(wxDisableBitmap( vBitmap
                                                         ,(long)GetBackgroundColour().GetPixel()
                                                        ));
            rDc.DrawBitmap( pTool->GetDisabledBitmap()
                           ,pTool->m_vX
                           ,pTool->m_vY
                           ,bUseMask
                          );
        }
        else
        {
            rDc.SetTextForeground(*wxBLACK);
            rDc.DrawBitmap( vBitmap
                           ,pTool->m_vX
                           ,pTool->m_vY
                           ,bUseMask
                          );
        }
        if (m_windowStyle & wxTB_3DBUTTONS)
        {
            RaiseTool(pTool);
        }
        if (HasFlag(wxTB_TEXT) && !pTool->GetLabel().IsNull())
        {
            wxCoord                 vX;
            wxCoord                 vY;
            wxCoord                 vLeft = pTool->m_vX - (int)(pTool->GetWidth()/2);

            rDc.SetFont(GetFont());
            rDc.GetTextExtent( pTool->GetLabel()
                              ,&vX
                              ,&vY
                             );
            if (pTool->GetWidth() > vX) // large tools
            {
                vLeft = pTool->m_vX + (pTool->GetWidth() - vX);
                GetSize(&vX, &vY);
                rDc.DrawText( pTool->GetLabel()
                             ,vLeft
                             ,vY - m_vTextY - 1
                            );
            }
            else  // normal tools
            {
                vLeft += (wxCoord)((m_vTextX - vX)/2);
                rDc.DrawText( pTool->GetLabel()
                             ,vLeft
                             ,pTool->m_vY + m_vTextY - 1 // a bit of margin
                            );
            }
        }
    }
    else
    {
        wxColour vColor(wxT("GREY"));

        LowerTool(pTool);
        rDc.SetTextForeground(vColor);
        if (!pTool->GetDisabledBitmap().Ok())
            pTool->SetDisabledBitmap(wxDisableBitmap( vBitmap
                                                     ,(long)GetBackgroundColour().GetPixel()
                                                    ));
        rDc.DrawBitmap( pTool->GetDisabledBitmap()
                       ,pTool->m_vX
                       ,pTool->m_vY
                       ,bUseMask
                      );
        if (HasFlag(wxTB_TEXT) && !pTool->GetLabel().IsNull())
        {
            wxCoord                 vX;
            wxCoord                 vY;
            wxCoord                 vLeft = pTool->m_vX - (int)(pTool->GetWidth()/2);

            rDc.SetFont(GetFont());
            rDc.GetTextExtent( pTool->GetLabel()
                              ,&vX
                              ,&vY
                             );
            vLeft += (wxCoord)((m_vTextX - vX)/2);
            rDc.DrawText( pTool->GetLabel()
                         ,vLeft
                         ,pTool->m_vY + m_vTextY - 1 // a bit of margin
                        );
        }
    }
} // end of wxToolBar::DrawTool

// ----------------------------------------------------------------------------
// toolbar geometry
// ----------------------------------------------------------------------------

void wxToolBar::SetRows(
  int                               nRows
)
{
    wxCHECK_RET( nRows != 0, wxT("max number of rows must be > 0") );

    m_maxCols = (GetToolsCount() + nRows - 1) / nRows;
    Refresh();
} // end of wxToolBar::SetRows

wxToolBarToolBase* wxToolBar::FindToolForPosition(
  wxCoord                           vX
, wxCoord                           vY
) const
{
    wxCoord                         vTBarHeight = 0;

    GetSize( NULL
            ,&vTBarHeight
           );
    vY = vTBarHeight - vY;
    wxToolBarToolsList::compatibility_iterator node = m_tools.GetFirst();
    while (node)
    {
        wxToolBarTool*              pTool = (wxToolBarTool *)node->GetData();

        if (HasFlag(wxTB_TEXT) && !pTool->GetLabel().IsNull())
        {
            if ((vX >= (pTool->m_vX - ((wxCoord)(pTool->GetWidth()/2) - 2))) &&
                (vY >= (pTool->m_vY - 2)) &&
                (vX <= (pTool->m_vX + pTool->GetWidth())) &&
                (vY <= (pTool->m_vY + pTool->GetHeight() + m_vTextY + 2)))
            {
                return pTool;
            }
        }
        else
        {
            if ((vX >= pTool->m_vX) &&
                (vY >= pTool->m_vY) &&
                (vX <= (pTool->m_vX + pTool->GetWidth())) &&
                (vY <= (pTool->m_vY + pTool->GetHeight())))
            {
                return pTool;
            }
        }
        node = node->GetNext();
    }
    return NULL;
} // end of wxToolBar::FindToolForPosition

// ----------------------------------------------------------------------------
// tool state change handlers
// ----------------------------------------------------------------------------

void wxToolBar::DoEnableTool(
  wxToolBarToolBase*                pTool
, bool                              WXUNUSED(bEnable)
)
{
    DrawTool(pTool);
} // end of wxToolBar::DoEnableTool

void wxToolBar::DoToggleTool(
  wxToolBarToolBase*                pTool
, bool                              WXUNUSED(bToggle)
)
{
    DrawTool(pTool);
} // end of wxToolBar::DoToggleTool

void wxToolBar::DoSetToggle(
  wxToolBarToolBase*                WXUNUSED(pTool)
, bool                              WXUNUSED(bToggle)
)
{
    // nothing to do
} // end of wxToolBar::DoSetToggle

//
// Okay, so we've left the tool we're in ... we must check if the tool we're
// leaving was a 'sprung push button' and if so, spring it back to the up
// state.
//
void wxToolBar::SpringUpButton(
  int                               vId
)
{
    wxToolBarToolBase*              pTool = FindById(vId);

    if (pTool && pTool->CanBeToggled())
    {
        if (pTool->IsToggled())
            pTool->Toggle();

        DrawTool(pTool);
    }
} // end of wxToolBar::SpringUpButton

// ----------------------------------------------------------------------------
// private helpers
// ----------------------------------------------------------------------------

void wxToolBar::LowerTool ( wxToolBarToolBase* pToolBase,
                            bool               bLower )
{
    wxToolBarTool*                  pTool = (wxToolBarTool*)pToolBase;
    wxCoord vX;
    wxCoord vY;
    wxCoord vWidth;
    wxCoord vHeight;
    wxColour gray85( 85,85,85 );
    wxPen vDarkGreyPen( gray85, 1, wxSOLID );
    wxPen vClearPen( GetBackgroundColour(), 1, wxSOLID );
    wxClientDC vDC(this);

    if (!pTool)
        return;

    if (pTool->IsSeparator())
        return;

    //
    // We only do this for flat toolbars
    //
    if (!HasFlag(wxTB_FLAT))
        return;

    if (HasFlag(wxTB_TEXT) && !pTool->GetLabel().empty())
    {
        if (pTool->GetWidth() > m_vTextX)
        {
            vX = pTool->m_vX - 2;
            vWidth = pTool->GetWidth() + 4;
        }
        else
        {
            vX = pTool->m_vX - (wxCoord)(pTool->GetWidth()/2);
            vWidth = m_vTextX + 4;
        }
        vY = pTool->m_vY - 2;
        vHeight = pTool->GetHeight() + m_vTextY + 2;
    }
    else
    {
        vX = pTool->m_vX - 2;
        vY = pTool->m_vY - 2;
        vWidth = pTool->GetWidth() + 4;
        vHeight = pTool->GetHeight() + 4;
    }
    if (bLower)
    {
        vDC.SetPen(*wxWHITE_PEN);
        vDC.DrawLine(vX + vWidth, vY + vHeight, vX, vY + vHeight);
        vDC.DrawLine(vX + vWidth, vY, vX + vWidth, vY + vHeight);
        vDC.SetPen(vDarkGreyPen);
        vDC.DrawLine(vX, vY, vX + vWidth, vY);
        vDC.DrawLine(vX, vY + vHeight, vX, vY);
    }
    else
    {
        vDC.SetPen(vClearPen);
        vDC.DrawLine(vX + vWidth, vY + vHeight, vX, vY + vHeight);
        vDC.DrawLine(vX + vWidth, vY, vX + vWidth, vY + vHeight);
        vDC.DrawLine(vX, vY, vX + vWidth, vY);
        vDC.DrawLine(vX, vY + vHeight, vX, vY);
    }
} // end of WinGuiBase_CToolBarTool::LowerTool

void wxToolBar::RaiseTool ( wxToolBarToolBase* pToolBase,
                            bool bRaise )
{
    wxToolBarTool* pTool = (wxToolBarTool*)pToolBase;
    wxCoord vX;
    wxCoord vY;
    wxCoord vWidth;
    wxCoord vHeight;
    wxColour gray85( 85,85,85 );
    wxPen vDarkGreyPen( gray85, 1, wxSOLID );
    wxPen vClearPen( GetBackgroundColour(), 1, wxSOLID );
    wxClientDC vDC(this);

    if (!pTool)
        return;

    if (pTool->IsSeparator())
        return;

    if (!pTool->IsEnabled())
        return;

    //
    // We only do this for flat toolbars
    //
    if (!HasFlag(wxTB_FLAT))
        return;

    if (HasFlag(wxTB_TEXT) && !pTool->GetLabel().empty())
    {
        if (pTool->GetWidth() > m_vTextX)
        {
            vX = pTool->m_vX - 2;
            vWidth = pTool->GetWidth() + 4;
        }
        else
        {
            vX = pTool->m_vX - (wxCoord)(pTool->GetWidth()/2);
            vWidth = m_vTextX + 4;
        }
        vY = pTool->m_vY - 2;
        vHeight = pTool->GetHeight() + m_vTextY + 2;
    }
    else
    {
        vX = pTool->m_vX - 2;
        vY = pTool->m_vY - 2;
        vWidth = pTool->GetWidth() + 4;
        vHeight = pTool->GetHeight() + 4;
    }
    if (bRaise)
    {
        vDC.SetPen(vDarkGreyPen);
        vDC.DrawLine(vX + vWidth, vY + vHeight, vX, vY + vHeight);
        vDC.DrawLine(vX + vWidth, vY, vX + vWidth, vY + vHeight);
        vDC.SetPen(*wxWHITE_PEN);
        vDC.DrawLine(vX, vY, vX + vWidth, vY);
        vDC.DrawLine(vX, vY + vHeight, vX, vY);
    }
    else
    {
        vDC.SetPen(vClearPen);
        vDC.DrawLine(vX + vWidth, vY + vHeight, vX, vY + vHeight);
        vDC.DrawLine(vX + vWidth, vY, vX + vWidth, vY + vHeight);
        vDC.DrawLine(vX, vY, vX + vWidth, vY);
        vDC.DrawLine(vX, vY + vHeight, vX, vY);
    }
} // end of wxToolBar::RaiseTool

void wxToolBar::OnTimer ( wxTimerEvent& rEvent )
{
    if (rEvent.GetId() == m_vToolTimer.GetId())
    {
        wxPoint vPos( m_vXMouse, m_vYMouse );

        m_pToolTip->DisplayToolTipWindow(vPos);
        m_vToolTimer.Stop();
        m_vToolExpTimer.Start(4000L, TRUE);
    }
    else if (rEvent.GetId() == m_vToolExpTimer.GetId())
    {
        m_pToolTip->HideToolTipWindow();
        GetParent()->Refresh();
        m_vToolExpTimer.Stop();
    }
} // end of wxToolBar::OnTimer

#endif // ndef for wxUSE_TOOLBAR && wxUSE_TOOLBAR_NATIVE
