/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/tooltip.cpp
// Purpose:     wxToolTip implementation
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_TOOLTIPS

#include "wx/tooltip.h"

#ifndef WX_PRECOMP
    #include "wx/window.h"
#endif

#include "wx/gtk1/private.h"

//-----------------------------------------------------------------------------
// global data
//-----------------------------------------------------------------------------

static GtkTooltips *ss_tooltips = NULL;

//-----------------------------------------------------------------------------
// wxToolTip
//-----------------------------------------------------------------------------

IMPLEMENT_ABSTRACT_CLASS(wxToolTip, wxObject)

wxToolTip::wxToolTip( const wxString &tip )
{
    m_text = tip;
    m_window = NULL;
}

void wxToolTip::SetTip( const wxString &tip )
{
    m_text = tip;
    Apply( m_window );
}

void wxToolTip::Apply( wxWindow *win )
{
    if (!win) return;

    if (!ss_tooltips)
    {
        ss_tooltips = gtk_tooltips_new();
    }

    m_window = win;

    if (m_text.empty())
        m_window->ApplyToolTip( ss_tooltips, NULL );
    else
        m_window->ApplyToolTip( ss_tooltips, m_text );
}

void wxToolTip::Enable( bool flag )
{
    if (!ss_tooltips) return;

    if (flag)
        gtk_tooltips_enable( ss_tooltips );
    else
        gtk_tooltips_disable( ss_tooltips );
}

void wxToolTip::SetDelay( long msecs )
{
    if (!ss_tooltips)
        return;

    gtk_tooltips_set_delay( ss_tooltips, (int)msecs );
}

void wxToolTip::SetAutoPop( long WXUNUSED(msecs) )
{
}

void wxToolTip::SetReshow( long WXUNUSED(msecs) )
{
}

#endif
