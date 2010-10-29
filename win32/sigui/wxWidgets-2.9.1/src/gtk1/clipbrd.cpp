/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/clipbrd.cpp
// Purpose:
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_CLIPBOARD

#include "wx/clipbrd.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/utils.h"
    #include "wx/dataobj.h"
#endif

#include <glib.h>
#include <gdk/gdk.h>
#include <gtk/gtk.h>

//-----------------------------------------------------------------------------
// data
//-----------------------------------------------------------------------------

GdkAtom  g_clipboardAtom   = 0;
GdkAtom  g_targetsAtom     = 0;
GdkAtom  g_timestampAtom   = 0;

// the trace mask we use with wxLogTrace() - call
// wxLog::AddTraceMask(TRACE_CLIPBOARD) to enable the trace messages from here
// (there will be a *lot* of them!)
#define TRACE_CLIPBOARD "clipboard"

//-----------------------------------------------------------------------------
// reminder
//-----------------------------------------------------------------------------

/* The contents of a selection are returned in a GtkSelectionData
   structure. selection/target identify the request.
   type specifies the type of the return; if length < 0, and
   the data should be ignored. This structure has object semantics -
   no fields should be modified directly, they should not be created
   directly, and pointers to them should not be stored beyond the duration of
   a callback. (If the last is changed, we'll need to add reference
   counting)

struct _GtkSelectionData
{
  GdkAtom selection;
  GdkAtom target;
  GdkAtom type;
  gint    format;
  guchar *data;
  gint    length;
};

*/

//-----------------------------------------------------------------------------
// "selection_received" for targets
//-----------------------------------------------------------------------------

extern "C" {
static void
targets_selection_received( GtkWidget *WXUNUSED(widget),
                            GtkSelectionData *selection_data,
                            guint32 WXUNUSED(time),
                            wxClipboard *clipboard )
{
    if ( wxTheClipboard && selection_data->length > 0 )
    {
        // make sure we got the data in the correct form
        GdkAtom type = selection_data->type;
        if ( type != GDK_SELECTION_TYPE_ATOM )
        {
            gchar* atom_name = gdk_atom_name(type);
            if ( strcmp(atom_name, "TARGETS") )
            {
                wxLogTrace( TRACE_CLIPBOARD,
                            wxT("got unsupported clipboard target") );

                clipboard->m_waiting = false;
                g_free(atom_name);
                return;
            }
            g_free(atom_name);
        }

        wxDataFormat clip( selection_data->selection );
        wxLogTrace( TRACE_CLIPBOARD,
                    wxT("selection received for targets, clipboard %s"),
                    clip.GetId().c_str() );

        // the atoms we received, holding a list of targets (= formats)
        GdkAtom *atoms = (GdkAtom *)selection_data->data;

        for (unsigned int i=0; i<selection_data->length/sizeof(GdkAtom); i++)
        {
            wxDataFormat format( atoms[i] );

            wxLogTrace( TRACE_CLIPBOARD,
                        wxT("selection received for targets, format %s"),
                        format.GetId().c_str() );

//            printf( "format %s requested %s\n",
//                    gdk_atom_name( atoms[i] ),
//                    gdk_atom_name( clipboard->m_targetRequested ) );

            if (format == clipboard->m_targetRequested)
            {
                clipboard->m_waiting = false;
                clipboard->m_formatSupported = true;
                return;
            }
        }
    }

    clipboard->m_waiting = false;
}
}

//-----------------------------------------------------------------------------
// "selection_received" for the actual data
//-----------------------------------------------------------------------------

extern "C" {
static void
selection_received( GtkWidget *WXUNUSED(widget),
                    GtkSelectionData *selection_data,
                    guint32 WXUNUSED(time),
                    wxClipboard *clipboard )
{
    if (!wxTheClipboard)
    {
        clipboard->m_waiting = false;
        return;
    }

    wxDataObject *data_object = clipboard->m_receivedData;

    if (!data_object)
    {
        clipboard->m_waiting = false;
        return;
    }

    if (selection_data->length <= 0)
    {
        clipboard->m_waiting = false;
        return;
    }

    wxDataFormat format( selection_data->target );

    // make sure we got the data in the correct format
    if (!data_object->IsSupportedFormat( format ) )
    {
        clipboard->m_waiting = false;
        return;
    }

#if 0
    This seems to cause problems somehow
    // make sure we got the data in the correct form (selection type).
    // if so, copy data to target object
    if (selection_data->type != GDK_SELECTION_TYPE_STRING)
    {
        clipboard->m_waiting = false;
        return;
    }
#endif

    data_object->SetData( format, (size_t) selection_data->length, (const char*) selection_data->data );

    wxTheClipboard->m_formatSupported = true;
    clipboard->m_waiting = false;
}
}

//-----------------------------------------------------------------------------
// "selection_clear"
//-----------------------------------------------------------------------------

extern "C" {
static gint
selection_clear_clip( GtkWidget *WXUNUSED(widget), GdkEventSelection *event )
{
    if (!wxTheClipboard) return TRUE;

    if (event->selection == GDK_SELECTION_PRIMARY)
    {
        wxTheClipboard->m_ownsPrimarySelection = false;
    }
    else
    if (event->selection == g_clipboardAtom)
    {
        wxTheClipboard->m_ownsClipboard = false;
    }
    else
    {
        wxTheClipboard->m_waiting = false;
        return FALSE;
    }

    if ((!wxTheClipboard->m_ownsPrimarySelection) &&
        (!wxTheClipboard->m_ownsClipboard))
    {
        /* the clipboard is no longer in our hands. we can the delete clipboard data. */
        if (wxTheClipboard->m_data)
        {
            wxLogTrace(TRACE_CLIPBOARD, wxT("wxClipboard will get cleared" ));

            wxDELETE(wxTheClipboard->m_data);
        }
    }

    wxTheClipboard->m_waiting = false;
    return TRUE;
}
}

//-----------------------------------------------------------------------------
// selection handler for supplying data
//-----------------------------------------------------------------------------

extern "C" {
static void
selection_handler( GtkWidget *WXUNUSED(widget),
                   GtkSelectionData *selection_data,
                   guint WXUNUSED(info),
                   guint WXUNUSED(time),
                   gpointer signal_data )
{
    if (!wxTheClipboard) return;

    if (!wxTheClipboard->m_data) return;

    wxDataObject *data = wxTheClipboard->m_data;

    // ICCCM says that TIMESTAMP is a required atom.
    // In particular, it satisfies Klipper, which polls
    // TIMESTAMP to see if the clipboards content has changed.
    // It shall return the time which was used to set the data.
    if (selection_data->target == g_timestampAtom)
    {
        guint timestamp = GPOINTER_TO_UINT (signal_data);
        gtk_selection_data_set(selection_data,
                               GDK_SELECTION_TYPE_INTEGER,
                               32,
                               (guchar*)&(timestamp),
                               sizeof(timestamp));
        wxLogTrace(TRACE_CLIPBOARD,
                   wxT("Clipboard TIMESTAMP requested, returning timestamp=%u"),
                   timestamp);
        return;
    }

    wxDataFormat format( selection_data->target );

    wxLogTrace(TRACE_CLIPBOARD,
               wxT("clipboard data in format %s, GtkSelectionData is target=%s type=%s selection=%s timestamp=%u"),
               format.GetId().c_str(),
               wxString::FromAscii(gdk_atom_name(selection_data->target)).c_str(),
               wxString::FromAscii(gdk_atom_name(selection_data->type)).c_str(),
               wxString::FromAscii(gdk_atom_name(selection_data->selection)).c_str(),
               GPOINTER_TO_UINT( signal_data )
               );

    if (!data->IsSupportedFormat( format )) return;

    int size = data->GetDataSize( format );

    if (size == 0) return;

    void *d = malloc(size);

    // Text data will be in UTF8 in Unicode mode.
    data->GetDataHere( selection_data->target, d );

    gtk_selection_data_set(
            selection_data,
            GDK_SELECTION_TYPE_STRING,
            8 * sizeof(gchar),
            (unsigned char*) d,
            size );

    free(d);
}
}

//-----------------------------------------------------------------------------
// wxClipboard
//-----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxClipboard,wxObject)

wxClipboard::wxClipboard()
{
    m_open = false;
    m_waiting = false;

    m_ownsClipboard = false;
    m_ownsPrimarySelection = false;

    m_data = NULL;
    m_receivedData = NULL;

    /* we use m_targetsWidget to query what formats are available */

    m_targetsWidget = gtk_window_new( GTK_WINDOW_POPUP );
    gtk_widget_realize( m_targetsWidget );

    gtk_signal_connect( GTK_OBJECT(m_targetsWidget),
                        "selection_received",
                        GTK_SIGNAL_FUNC( targets_selection_received ),
                        (gpointer) this );

    /* we use m_clipboardWidget to get and to offer data */

    m_clipboardWidget = gtk_window_new( GTK_WINDOW_POPUP );
    gtk_widget_realize( m_clipboardWidget );

    gtk_signal_connect( GTK_OBJECT(m_clipboardWidget),
                        "selection_received",
                        GTK_SIGNAL_FUNC( selection_received ),
                        (gpointer) this );

    gtk_signal_connect( GTK_OBJECT(m_clipboardWidget),
                        "selection_clear_event",
                        GTK_SIGNAL_FUNC( selection_clear_clip ),
                        (gpointer) NULL );

    if (!g_clipboardAtom) g_clipboardAtom = gdk_atom_intern( "CLIPBOARD", FALSE );
    if (!g_targetsAtom) g_targetsAtom = gdk_atom_intern ("TARGETS", FALSE);
    if (!g_timestampAtom) g_timestampAtom = gdk_atom_intern ("TIMESTAMP", FALSE);

    m_formatSupported = false;
    m_targetRequested = 0;
}

wxClipboard::~wxClipboard()
{
    Clear();

    if (m_clipboardWidget) gtk_widget_destroy( m_clipboardWidget );
    if (m_targetsWidget) gtk_widget_destroy( m_targetsWidget );
}

void wxClipboard::Clear()
{
    if (m_data)
    {
#if wxUSE_THREADS
        /* disable GUI threads */
#endif

        //  As we have data we also own the clipboard. Once we no longer own
        //  it, clear_selection is called which will set m_data to zero
        if (gdk_selection_owner_get( g_clipboardAtom ) == m_clipboardWidget->window)
        {
            m_waiting = true;

            gtk_selection_owner_set( NULL, g_clipboardAtom,
                                     (guint32) GDK_CURRENT_TIME );

            while (m_waiting) gtk_main_iteration();
        }

        if (gdk_selection_owner_get( GDK_SELECTION_PRIMARY ) == m_clipboardWidget->window)
        {
            m_waiting = true;

            gtk_selection_owner_set( NULL, GDK_SELECTION_PRIMARY,
                                     (guint32) GDK_CURRENT_TIME );

            while (m_waiting) gtk_main_iteration();
        }

        wxDELETE(m_data);

#if wxUSE_THREADS
        /* re-enable GUI threads */
#endif
    }

    m_targetRequested = 0;
    m_formatSupported = false;
}

bool wxClipboard::Open()
{
    wxCHECK_MSG( !m_open, false, wxT("clipboard already open") );

    m_open = true;

    return true;
}

bool wxClipboard::SetData( wxDataObject *data )
{
    wxCHECK_MSG( m_open, false, wxT("clipboard not open") );

    wxCHECK_MSG( data, false, wxT("data is invalid") );

    Clear();

    return AddData( data );
}

bool wxClipboard::AddData( wxDataObject *data )
{
    wxCHECK_MSG( m_open, false, wxT("clipboard not open") );

    wxCHECK_MSG( data, false, wxT("data is invalid") );

    // we can only store one wxDataObject
    Clear();

    m_data = data;

    // get formats from wxDataObjects
    wxDataFormat *array = new wxDataFormat[ m_data->GetFormatCount() ];
    m_data->GetAllFormats( array );

    // primary selection or clipboard
    GdkAtom clipboard = m_usePrimary ? (GdkAtom)GDK_SELECTION_PRIMARY
                                     : g_clipboardAtom;

    // by default provide TIMESTAMP as a target
    gtk_selection_add_target( GTK_WIDGET(m_clipboardWidget),
                              clipboard,
                              g_timestampAtom,
                              0 );

    for (size_t i = 0; i < m_data->GetFormatCount(); i++)
    {
        wxLogTrace( TRACE_CLIPBOARD,
                    wxT("wxClipboard now supports atom %s"),
                    array[i].GetId().c_str() );

//        printf( "added %s\n",
//                    gdk_atom_name( array[i].GetFormatId() ) );

        gtk_selection_add_target( GTK_WIDGET(m_clipboardWidget),
                                  clipboard,
                                  array[i],
                                  0 );  /* what is info ? */
    }

    delete[] array;

    gtk_signal_connect( GTK_OBJECT(m_clipboardWidget),
                        "selection_get",
                        GTK_SIGNAL_FUNC(selection_handler),
                        GUINT_TO_POINTER( gdk_event_get_time(gtk_get_current_event()) ) );

#if wxUSE_THREADS
    /* disable GUI threads */
#endif

    /* Tell the world we offer clipboard data */
    bool res = (gtk_selection_owner_set( m_clipboardWidget,
                                         clipboard,
                                         (guint32) GDK_CURRENT_TIME ));

    if (m_usePrimary)
        m_ownsPrimarySelection = res;
    else
        m_ownsClipboard = res;

#if wxUSE_THREADS
    /* re-enable GUI threads */
#endif

    return res;
}

void wxClipboard::Close()
{
    wxCHECK_RET( m_open, wxT("clipboard not open") );

    m_open = false;
}

bool wxClipboard::IsOpened() const
{
    return m_open;
}

bool wxClipboard::IsSupported( const wxDataFormat& format )
{
    /* reentrance problems */
    if (m_waiting) return false;

    /* store requested format to be asked for by callbacks */
    m_targetRequested = format;

    wxLogTrace( TRACE_CLIPBOARD,
                wxT("wxClipboard:IsSupported: requested format: %s"),
                format.GetId().c_str() );

    wxCHECK_MSG( m_targetRequested, false, wxT("invalid clipboard format") );

    m_formatSupported = false;

    /* perform query. this will set m_formatSupported to
       true if m_targetRequested is supported.
       also, we have to wait for the "answer" from the
       clipboard owner which is an asynchronous process.
       therefore we set m_waiting = true here and wait
       until the callback "targets_selection_received"
       sets it to false */

    m_waiting = true;

    gtk_selection_convert( m_targetsWidget,
                           m_usePrimary ? (GdkAtom)GDK_SELECTION_PRIMARY
                                        : g_clipboardAtom,
                           g_targetsAtom,
                           (guint32) GDK_CURRENT_TIME );

    while (m_waiting) gtk_main_iteration();

    return m_formatSupported;
}

bool wxClipboard::GetData( wxDataObject& data )
{
    wxCHECK_MSG( m_open, false, wxT("clipboard not open") );

    /* get formats from wxDataObjects */
    wxDataFormat *array = new wxDataFormat[ data.GetFormatCount() ];
    data.GetAllFormats( array );

    for (size_t i = 0; i < data.GetFormatCount(); i++)
    {
        wxDataFormat format( array[i] );

        wxLogTrace( TRACE_CLIPBOARD,
                    wxT("wxClipboard::GetData: requested format: %s"),
                    format.GetId().c_str() );

        /* is data supported by clipboard ? */

        /* store requested format to be asked for by callbacks */
        m_targetRequested = format;

        wxCHECK_MSG( m_targetRequested, false, wxT("invalid clipboard format") );

        m_formatSupported = false;

       /* perform query. this will set m_formatSupported to
          true if m_targetRequested is supported.
          also, we have to wait for the "answer" from the
          clipboard owner which is an asynchronous process.
          therefore we set m_waiting = true here and wait
          until the callback "targets_selection_received"
          sets it to false */

        m_waiting = true;

        gtk_selection_convert( m_targetsWidget,
                           m_usePrimary ? (GdkAtom)GDK_SELECTION_PRIMARY
                                        : g_clipboardAtom,
                           g_targetsAtom,
                           (guint32) GDK_CURRENT_TIME );

        while (m_waiting) gtk_main_iteration();

        if (!m_formatSupported) continue;

        /* store pointer to data object to be filled up by callbacks */
        m_receivedData = &data;

        /* store requested format to be asked for by callbacks */
        m_targetRequested = format;

        wxCHECK_MSG( m_targetRequested, false, wxT("invalid clipboard format") );

        /* start query */
        m_formatSupported = false;

        /* ask for clipboard contents.  this will set
           m_formatSupported to true if m_targetRequested
           is supported.
           also, we have to wait for the "answer" from the
           clipboard owner which is an asynchronous process.
           therefore we set m_waiting = true here and wait
           until the callback "targets_selection_received"
           sets it to false */

        m_waiting = true;

        wxLogTrace( TRACE_CLIPBOARD,
                    wxT("wxClipboard::GetData: format found, start convert") );

        gtk_selection_convert( m_clipboardWidget,
                               m_usePrimary ? (GdkAtom)GDK_SELECTION_PRIMARY
                                            : g_clipboardAtom,
                               m_targetRequested,
                               (guint32) GDK_CURRENT_TIME );

        while (m_waiting) gtk_main_iteration();

        /*
           Normally this is a true error as we checked for the presence of such
           data before, but there are applications that may return an empty
           string (e.g. Gnumeric-1.6.1 on Linux if an empty cell is copied)
           which would produce a false error message here, so we check for the
           size of the string first. In ansi, GetDataSize returns an extra
           value (for the closing null?), with unicode, the exact number of
           tokens is given (that is more than 1 for special characters)
           (tested with Gnumeric-1.6.1 and OpenOffice.org-2.0.2)
         */
#if wxUSE_UNICODE
        if ( format != wxDF_UNICODETEXT || data.GetDataSize(format) > 0 )
#else // !UNICODE
        if ( format != wxDF_TEXT || data.GetDataSize(format) > 1 )
#endif // UNICODE / !UNICODE
        {
            wxCHECK_MSG( m_formatSupported, false,
                         wxT("error retrieving data from clipboard") );
        }

        /* return success */
        delete[] array;
        return true;
    }

    wxLogTrace( TRACE_CLIPBOARD,
                wxT("wxClipboard::GetData: format not found") );

    /* return failure */
    delete[] array;
    return false;
}

#endif
  // wxUSE_CLIPBOARD
