/////////////////////////////////////////////////////////////////////////////
// Name:        src/x11/clipbrd.cpp
// Purpose:     Clipboard functionality
// Author:      Robert Roebling
// Created:
// RCS-ID:      $Id$
// Copyright:   (c) Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// for compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_CLIPBOARD

#include "wx/clipbrd.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/utils.h"
    #include "wx/dataobj.h"
#endif

#include "wx/x11/private.h"

//-----------------------------------------------------------------------------
// data
//-----------------------------------------------------------------------------

#if !wxUSE_NANOX
Atom  g_clipboardAtom   = 0;
Atom  g_targetsAtom     = 0;
#endif

// avoid warnings about unused static variable (notice that we still use it
// even in release build if the compiler doesn't support variadic macros)
#if defined(__WXDEBUG__) || !defined(HAVE_VARIADIC_MACROS)

// the trace mask we use with wxLogTrace() - call
// wxLog::AddTraceMask(TRACE_CLIPBOARD) to enable the trace messages from here
// (there will be a *lot* of them!)
static const wxChar *TRACE_CLIPBOARD = wxT("clipboard");

#endif // __WXDEBUG__

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

#if 0

static void
targets_selection_received( GtkWidget *WXUNUSED(widget),
                            GtkSelectionData *selection_data,
#if (GTK_MINOR_VERSION > 0)
                            guint32 WXUNUSED(time),
#endif
                            wxClipboard *clipboard )
{
    if ( wxTheClipboard && selection_data->length > 0 )
    {
        /* make sure we got the data in the correct form */
        GdkAtom type = selection_data->type;
        if ( type != GDK_SELECTION_TYPE_ATOM )
        {
            if ( strcmp(gdk_atom_name(type), "TARGETS") )
            {
                wxLogTrace( TRACE_CLIPBOARD,
                            wxT("got unsupported clipboard target") );

                clipboard->m_waiting = false;
                return;
            }
        }

#ifdef __WXDEBUG__
        wxDataFormat clip( selection_data->selection );
        wxLogTrace( TRACE_CLIPBOARD,
                    wxT("selection received for targets, clipboard %s"),
                    clip.GetId().c_str() );
#endif // __WXDEBUG__

        // the atoms we received, holding a list of targets (= formats)
        GdkAtom *atoms = (GdkAtom *)selection_data->data;

        for (unsigned int i=0; i<selection_data->length/sizeof(GdkAtom); i++)
        {
            wxDataFormat format( atoms[i] );

            wxLogTrace( TRACE_CLIPBOARD,
                        wxT("selection received for targets, format %s"),
                        format.GetId().c_str() );

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

//-----------------------------------------------------------------------------
// "selection_received" for the actual data
//-----------------------------------------------------------------------------

static void
selection_received( GtkWidget *WXUNUSED(widget),
                    GtkSelectionData *selection_data,
#if (GTK_MINOR_VERSION > 0)
                    guint32 WXUNUSED(time),
#endif
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

    /* make sure we got the data in the correct format */
    if (!data_object->IsSupportedFormat( format ) )
    {
        clipboard->m_waiting = false;
        return;
    }

    /* make sure we got the data in the correct form (selection type).
       if so, copy data to target object */
    if (selection_data->type != GDK_SELECTION_TYPE_STRING)
    {
        clipboard->m_waiting = false;
        return;
    }

    data_object->SetData( format, (size_t) selection_data->length, (const char*) selection_data->data );

    wxTheClipboard->m_formatSupported = true;
    clipboard->m_waiting = false;
}

//-----------------------------------------------------------------------------
// "selection_clear"
//-----------------------------------------------------------------------------

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

//-----------------------------------------------------------------------------
// selection handler for supplying data
//-----------------------------------------------------------------------------

static void
selection_handler( GtkWidget *WXUNUSED(widget),
                   GtkSelectionData *selection_data,
                   guint WXUNUSED(info),
                   guint WXUNUSED(time),
                   gpointer WXUNUSED(data) )
{
    if (!wxTheClipboard) return;

    if (!wxTheClipboard->m_data) return;

    wxDataObject *data = wxTheClipboard->m_data;

    wxDataFormat format( selection_data->target );

    if (!data->IsSupportedFormat( format )) return;

    int size = data->GetDataSize( format );

    if (size == 0) return;

    void *d = malloc(size);

    data->GetDataHere( selection_data->target, d );

    // transform Unicode text into multibyte before putting it on clipboard
#if wxUSE_UNICODE
    if ( format.GetType() == wxDF_TEXT || format.GetType() == wxDF_UNICODETEXT)
    {
        const wchar_t *wstr = (const wchar_t *)d;
        size_t len = wxConvCurrent->WC2MB(NULL, wstr, 0);
        char *str = malloc(len + 1);
        wxConvCurrent->WC2MB(str, wstr, len);
        str[len] = '\0';

        free(d);
        d = str;
    }
#endif // wxUSE_UNICODE

    gtk_selection_data_set(
        selection_data,
        GDK_SELECTION_TYPE_STRING,
        8*sizeof(gchar),
        (unsigned char*) d,
        size );

    free(d);
}

#endif

//-----------------------------------------------------------------------------
// wxClipboard
//-----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxClipboard,wxObject)

wxClipboard::wxClipboard()
{
    m_open = false;

    m_ownsClipboard = false;
    m_ownsPrimarySelection = false;

    m_data = NULL;
    m_receivedData = NULL;

    /* we use m_targetsWidget to query what formats are available */

    /* we use m_clipboardWidget to get and to offer data */
#if !wxUSE_NANOX
    if (!g_clipboardAtom) g_clipboardAtom = XInternAtom( (Display*) wxGetDisplay(), "CLIPBOARD", False );
    if (!g_targetsAtom) g_targetsAtom = XInternAtom( (Display*) wxGetDisplay(), "TARGETS", False );
#endif

    m_formatSupported = false;
    m_targetRequested = 0;
}

wxClipboard::~wxClipboard()
{
    Clear();

//    if (m_clipboardWidget) gtk_widget_destroy( m_clipboardWidget );
//    if (m_targetsWidget) gtk_widget_destroy( m_targetsWidget );
}

void wxClipboard::Clear()
{
    if (m_data)
    {
#if wxUSE_THREADS
        /* disable GUI threads */
#endif

        /*  As we have data we also own the clipboard. Once we no longer own
            it, clear_selection is called which will set m_data to zero */
#if 0
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
#endif

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
#if wxUSE_NANOX
    return false;
#else
    wxCHECK_MSG( m_open, false, wxT("clipboard not open") );

    wxCHECK_MSG( data, false, wxT("data is invalid") );

    /* we can only store one wxDataObject */
    Clear();

    m_data = data;

    /* get formats from wxDataObjects */
    wxDataFormat *array = new wxDataFormat[ m_data->GetFormatCount() ];
    m_data->GetAllFormats( array );

#if 0
    /* primary selection or clipboard */
    Atom clipboard = m_usePrimary ? (Atom) 1  // 1 = primary selection
                                  : g_clipboardAtom;
#endif // 0


    for (size_t i = 0; i < m_data->GetFormatCount(); i++)
    {
        wxLogTrace( TRACE_CLIPBOARD,
                    wxT("wxClipboard now supports atom %s"),
                    array[i].GetId().c_str() );

#if 0
        gtk_selection_add_target( GTK_WIDGET(m_clipboardWidget),
                                  clipboard,
                                  array[i],
                                  0 );  /* what is info ? */
#endif
    }

    delete[] array;

#if 0
    gtk_signal_connect( GTK_OBJECT(m_clipboardWidget),
                        "selection_get",
                        GTK_SIGNAL_FUNC(selection_handler),
                        (gpointer) NULL );
#endif

#if wxUSE_THREADS
    /* disable GUI threads */
#endif

    bool res = false;
#if 0
    /* Tell the world we offer clipboard data */
    res = (gtk_selection_owner_set( m_clipboardWidget,
                                         clipboard,
                                         (guint32) GDK_CURRENT_TIME ));
#endif

    if (m_usePrimary)
        m_ownsPrimarySelection = res;
    else
        m_ownsClipboard = res;

#if wxUSE_THREADS
    /* re-enable GUI threads */
#endif

    return res;
#endif
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

#if 0
    wxLogTrace( TRACE_CLIPBOARD,
                wxT("wxClipboard:IsSupported: requested format: %s"),
                format.GetId().c_str() );
#endif

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

#if 0
    gtk_selection_convert( m_targetsWidget,
                           m_usePrimary ? (GdkAtom)GDK_SELECTION_PRIMARY
                                        : g_clipboardAtom,
                           g_targetsAtom,
                           (guint32) GDK_CURRENT_TIME );

    while (m_waiting) gtk_main_iteration();
#endif

    if (!m_formatSupported) return false;

    return true;
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

#if 0
        gtk_selection_convert( m_targetsWidget,
                           m_usePrimary ? (GdkAtom)GDK_SELECTION_PRIMARY
                                        : g_clipboardAtom,
                           g_targetsAtom,
                           (guint32) GDK_CURRENT_TIME );

        while (m_waiting) gtk_main_iteration();
#endif

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

#if 0
        gtk_selection_convert( m_clipboardWidget,
                               m_usePrimary ? (GdkAtom)GDK_SELECTION_PRIMARY
                                            : g_clipboardAtom,
                               m_targetRequested,
                               (guint32) GDK_CURRENT_TIME );

        while (m_waiting) gtk_main_iteration();
#endif

        /* this is a true error as we checked for the presence of such data before */
        wxCHECK_MSG( m_formatSupported, false, wxT("error retrieving data from clipboard") );

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
