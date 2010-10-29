/////////////////////////////////////////////////////////////////////////////
// Name:        gtk/scrolwin.cpp
// Purpose:     wxScrolledWindow implementation
// Author:      Robert Roebling
// Modified by: Ron Lee
//              Vadim Zeitlin: removed 90% of duplicated common code
// Created:     01/02/97
// RCS-ID:      $Id$
// Copyright:   (c) Robert Roebling
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

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#include "wx/scrolwin.h"
#include "wx/gtk1/private.h"

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxScrollHelper implementation
// ----------------------------------------------------------------------------

void wxScrollHelper::SetScrollbars(int pixelsPerUnitX, int pixelsPerUnitY,
                                         int noUnitsX, int noUnitsY,
                                         int xPos, int yPos,
                                         bool noRefresh)
{
    int xs, ys;
    GetViewStart(& xs, & ys);

    int old_x = m_xScrollPixelsPerLine * xs;
    int old_y = m_yScrollPixelsPerLine * ys;

    m_xScrollPixelsPerLine = pixelsPerUnitX;
    m_yScrollPixelsPerLine = pixelsPerUnitY;

    m_win->m_hAdjust->value = m_xScrollPosition = xPos;
    m_win->m_vAdjust->value = m_yScrollPosition = yPos;

    // Setting hints here should arguably be deprecated, but without it
    // a sizer might override this manual scrollbar setting in old code.
    // m_targetWindow->SetVirtualSizeHints( noUnitsX * pixelsPerUnitX, noUnitsY * pixelsPerUnitY );

    int w = noUnitsX * pixelsPerUnitX;
    int h = noUnitsY * pixelsPerUnitY;
    m_targetWindow->SetVirtualSize( w ? w : wxDefaultCoord,
                                    h ? h : wxDefaultCoord);

    if (!noRefresh)
    {
        int new_x = m_xScrollPixelsPerLine * m_xScrollPosition;
        int new_y = m_yScrollPixelsPerLine * m_yScrollPosition;

        m_targetWindow->ScrollWindow( old_x - new_x, old_y - new_y );
    }

    m_targetWindow->m_hasScrolling = pixelsPerUnitX || pixelsPerUnitY;
}

void wxScrollHelper::DoAdjustScrollbar(GtkAdjustment *adj,
                                             int pixelsPerLine,
                                             int winSize,
                                             int virtSize,
                                             int *pos,
                                             int *lines,
                                             int *linesPerPage)
{
    if ( pixelsPerLine == 0 )
    {
        adj->upper = 1.0;
        adj->page_increment = 1.0;
        adj->page_size = 1.0;
    }
    else // we do have scrollbar
    {
        adj->upper = (virtSize + pixelsPerLine - 1) / pixelsPerLine;
        adj->page_size = winSize / pixelsPerLine;
        adj->page_increment = winSize / pixelsPerLine;

        // Special case. When client and virtual size are very close but
        // the client is big enough, kill scrollbar.

        if ((adj->page_size < adj->upper) && (winSize >= virtSize))
            adj->page_size += 1.0;

        // If the scrollbar hits the right side, move the window
        // right to keep it from over extending.

        if ( !wxIsNullDouble(adj->value) &&
                (adj->value + adj->page_size > adj->upper) )
        {
            adj->value = adj->upper - adj->page_size;
            if (adj->value < 0.0)
                adj->value = 0.0;

            if ( m_win->GetChildren().empty() )
            {
                // This is enough without child windows
                *pos = (int)adj->value;
            }
            else
            {
                // We need to actually scroll window
                gtk_signal_emit_by_name( GTK_OBJECT(adj), "value_changed" );
            }
        }
    }

    *lines = (int)(adj->upper + 0.5);
    *linesPerPage = (int)(adj->page_increment + 0.5);
    gtk_signal_emit_by_name( GTK_OBJECT(adj), "changed" );
}

void wxScrollHelper::AdjustScrollbars()
{
    int w, h;
    int vw, vh;

    m_targetWindow->GetClientSize( &w, &h );
    m_targetWindow->GetVirtualSize( &vw, &vh );

    DoAdjustScrollbar(m_win->m_hAdjust, m_xScrollPixelsPerLine, w, vw,
                      &m_xScrollPosition, &m_xScrollLines, &m_xScrollLinesPerPage);
    DoAdjustScrollbar(m_win->m_vAdjust, m_yScrollPixelsPerLine, h, vh,
                      &m_yScrollPosition, &m_yScrollLines, &m_yScrollLinesPerPage);
}

void wxScrollHelper::DoScrollOneDir(int orient,
                                    GtkAdjustment *adj,
                                    int pos,
                                    int pixelsPerLine,
                                    int *posOld)
{
    if ( pos != -1 && pos != *posOld && pixelsPerLine )
    {
        int max = (int)(adj->upper - adj->page_size + 0.5);
        if (max < 0)
            max = 0;
        if (pos > max)
            pos = max;
        if (pos < 0)
            pos = 0;

        adj->value = pos;

        int diff = (*posOld - pos)*pixelsPerLine;
        m_targetWindow->ScrollWindow(orient == wxHORIZONTAL ? diff : 0,
                                     orient == wxHORIZONTAL ? 0 : diff);

        *posOld = pos;

        m_win->GtkUpdateScrollbar(orient);
    }
}

void wxScrollHelper::DoScroll( int x_pos, int y_pos )
{
    wxCHECK_RET( m_targetWindow != 0, wxT("No target window") );

    DoScrollOneDir(wxHORIZONTAL, m_win->m_hAdjust, x_pos, m_xScrollPixelsPerLine,
                &m_xScrollPosition);
    DoScrollOneDir(wxVERTICAL, m_win->m_vAdjust, y_pos, m_yScrollPixelsPerLine,
                &m_yScrollPosition);
}

void wxScrollHelper::DoShowScrollbars(wxScrollbarVisibility WXUNUSED(horz),
                                      wxScrollbarVisibility WXUNUSED(vert))
{
    // TODO: not supported/implemented
}

