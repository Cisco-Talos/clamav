/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/clipbrd.cpp
// Purpose:     Clipboard functionality
// Author:      Julian Smart
// Modified by: Mattia Barbon (added support for generic wxDataObjects)
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __VMS
#include "wx/vms_x_fix.h"
#define XtWindow XTWINDOW
#define XtScreen XTSCREEN
#define XtParent XTPARENT
#define XtIsRealized XTISREALIZED
#define XtDisplay XTDISPLAY
#endif

#if wxUSE_CLIPBOARD

#include "wx/clipbrd.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/utils.h"
    #include "wx/bitmap.h"
    #include "wx/dataobj.h"
#endif

#include "wx/scopedarray.h"

typedef wxScopedArray<wxDataFormat> wxDataFormatScopedArray;

#ifdef __VMS__
#pragma message disable nosimpint

#endif
#include <Xm/Xm.h>
#include <Xm/CutPaste.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

#include "wx/motif/private.h"

bool wxOpenClipboard()
{
    return wxTheClipboard->Open();
}

bool wxCloseClipboard()
{
    wxTheClipboard->Close();

    return true;
}

bool wxEmptyClipboard()
{
    wxTheClipboard->Clear();
    return true;
}

bool wxClipboardOpen()
{
    return wxTheClipboard->IsOpened();
}

bool wxIsClipboardFormatAvailable(const wxDataFormat& dataFormat)
{
    return wxTheClipboard->IsSupported( dataFormat );
}

bool wxSetClipboardData(wxDataFormat dataFormat, wxObject *obj,
                        int WXUNUSED(width), int WXUNUSED(height))
{
    wxDataObject* dobj = NULL;

    if( dataFormat == wxDF_TEXT )
    {
        wxChar* data = (wxChar*)obj;
        dobj = new wxTextDataObject( data );
    }
    else if( dataFormat = wxDF_BITMAP )
    {
        wxBitmap* data = (wxBitmap*)obj;
        dobj = new wxBitmapDataObject( *data );
    }

    if( !dobj )
        return false;

    return wxTheClipboard->SetData( dobj );
}

wxObject *wxGetClipboardData(wxDataFormat dataFormat, long *len)
{
    wxDataObject* dobj = NULL;
    wxTextDataObject* tobj = NULL;
    wxBitmapDataObject* bobj = NULL;

    if( dataFormat == wxDF_TEXT )
    {
        dobj = tobj = new wxTextDataObject;
    }
    else if( dataFormat = wxDF_BITMAP )
    {
        dobj = bobj = new wxBitmapDataObject;
    }

    if( !dobj || !wxTheClipboard->GetData( *dobj ) )
        return NULL;

    if( tobj )
    {
        wxString text = tobj->GetText();
        wxChar* buf = new wxChar[text.length() + 1];

        if( len ) *len = text.length();
        return (wxObject*)wxStrcpy( buf, text.c_str() );
    }
    else if( bobj )
    {
        if( len ) *len = 0;
        return new wxBitmap( bobj->GetBitmap() );
    }

    return NULL; // just in case...
}

wxDataFormat wxEnumClipboardFormats(const wxDataFormat& dataFormat)
{
    // Only wxDF_TEXT supported
    if (dataFormat == wxDF_TEXT)
       return wxDF_TEXT;
    else
       return wxDF_INVALID;
}

wxDataFormat wxRegisterClipboardFormat(char *WXUNUSED(formatName))
{
    // Not supported
    return wxDF_INVALID;
}

bool wxGetClipboardFormatName(const wxDataFormat& dataFormat, char *formatName,
                              int maxCount)
{
    wxStrlcpy( formatName, dataFormat.GetId().c_str(), maxCount );

    return true;
}

//-----------------------------------------------------------------------------
// wxClipboard
//-----------------------------------------------------------------------------

struct wxDataIdToDataObject
{
    wxDataIdToDataObject( wxDataObject* o, long d, size_t s )
        : object( o ), size( s ), dataId( d ) { }

    wxDataObject* object;
    size_t        size;
    long          dataId;
};

#include "wx/listimpl.cpp"

WX_DEFINE_LIST(wxDataObjectList)
WX_DEFINE_LIST(wxDataIdToDataObjectList)

extern "C"
{
#if wxCHECK_LESSTIF()
static void wxClipboardCallback( Widget widget, int* data_id,
                                 int* priv, int* reason );
#else // Motif
static void wxClipboardCallback( Widget widget, long* data_id,
                                 long* priv, int* reason );
#endif // Less/Motif
}

IMPLEMENT_DYNAMIC_CLASS(wxClipboard,wxObject)

wxClipboard::wxClipboard()
{
    m_open = false;
}

wxClipboard::~wxClipboard()
{
    Clear();
}

void wxClipboard::Clear()
{
    wxDataObjectList::compatibility_iterator node = m_data.GetFirst();
    while (node)
    {
        delete node->GetData();
        node = node->GetNext();
    }
    m_data.Clear();

    for( wxDataIdToDataObjectList::compatibility_iterator node2 = m_idToObject.GetFirst();
         node2; node2 = node2->GetNext() )
    {
        delete node2->GetData();
    }
    m_idToObject.Clear();
}

bool wxClipboard::Open()
{
    wxCHECK_MSG( !m_open, false, "clipboard already open" );

    m_open = true;

    return true;
}

bool wxClipboard::SetData( wxDataObject *data )
{
    wxCHECK_MSG( data, false, "data is invalid" );
    wxCHECK_MSG( m_open, false, "clipboard not open" );

    Clear();

    return AddData( data );
}

#if wxCHECK_LESSTIF()
void wxClipboardCallback( Widget xwidget, int* data_id,
                          int* priv, int* WXUNUSED(reason) )
#else
void wxClipboardCallback( Widget xwidget, long* data_id,
                          long* priv, int* WXUNUSED(reason) )
#endif
{
    Display* xdisplay = XtDisplay( xwidget );
    Window xwindow = XtWindow( xwidget );
    wxDataObject* dobj = NULL;
    size_t size = 0;

    for( wxDataIdToDataObjectList::compatibility_iterator node2 =
             wxTheClipboard->m_idToObject.GetFirst();
         node2; node2 = node2->GetNext() )
    {
        wxDataIdToDataObject* dido = node2->GetData();
        if( dido->dataId == *data_id )
        {
            dobj = dido->object;
            size = dido->size;
            break;
        }
    }

    if( !dobj ) return;

    wxCharBuffer buffer(size);
    size_t count = dobj->GetFormatCount( wxDataObject::Get );
    wxDataFormatScopedArray dfarr( new wxDataFormat[count] );
    dobj->GetAllFormats( dfarr.get(), wxDataObject::Get );

    if( !dobj->GetDataHere( dfarr[*priv], buffer.data() ) )
        return;

    while( XmClipboardCopyByName( xdisplay, xwindow, *data_id,
                                  buffer.data(), size, 0 )
           == XmClipboardLocked );
}

bool wxClipboard::AddData( wxDataObject *data )
{
    wxCHECK_MSG( data, false, "data is invalid" );
    wxCHECK_MSG( m_open, false, "clipboard not open" );

    m_data.Append( data );

    Display* xdisplay = wxGlobalDisplay();
    Widget xwidget = (Widget)wxTheApp->GetTopLevelRealizedWidget();
    Window xwindow = XtWindow( xwidget );
    wxXmString label( wxTheApp->GetAppDisplayName() );
    Time timestamp = XtLastTimestampProcessed( xdisplay );
    long itemId;

    int retval;

    while( ( retval = XmClipboardStartCopy( xdisplay, xwindow, label(),
                                            timestamp, xwidget,
                                            wxClipboardCallback,
                                            &itemId ) )
           == XmClipboardLocked );
    if( retval != XmClipboardSuccess )
        return false;

    size_t count = data->GetFormatCount( wxDataObject::Get );
    wxDataFormatScopedArray dfarr( new wxDataFormat[count] );
    data->GetAllFormats( dfarr.get(), wxDataObject::Get );

    for( size_t i = 0; i < count; ++i )
    {
        size_t size = data->GetDataSize( dfarr[i] );
        long data_id;
        wxString id = dfarr[i].GetId();

        while( ( retval = XmClipboardCopy( xdisplay, xwindow, itemId,
                                           id.char_str(),
                                           NULL, size, i, &data_id ) )
               == XmClipboardLocked );

        m_idToObject.Append( new wxDataIdToDataObject( data, data_id, size ) );
    }

    while( XmClipboardEndCopy( xdisplay, xwindow, itemId )
           == XmClipboardLocked );

    return true;
}

void wxClipboard::Close()
{
    wxCHECK_RET( m_open, "clipboard not open" );

    m_open = false;
}

bool wxClipboard::IsSupported(const wxDataFormat& format)
{
    Display* xdisplay = wxGlobalDisplay();
    Window xwindow = XtWindow( (Widget)wxTheApp->GetTopLevelRealizedWidget() );
    bool isSupported = false;
    int retval, count;
    unsigned long  max_name_length;
    wxString id = format.GetId();

    while( ( retval = XmClipboardLock( xdisplay, xwindow ) )
           == XmClipboardLocked );
    if( retval != XmClipboardSuccess )
        return false;

    if( XmClipboardInquireCount( xdisplay, xwindow, &count, &max_name_length )
        == XmClipboardSuccess )
    {
        wxCharBuffer buf( max_name_length + 1 );
        unsigned long copied;

        for( int i = 0; i < count; ++i )
        {
            if( XmClipboardInquireFormat( xdisplay, xwindow, i + 1,
                                          (XtPointer)buf.data(),
                                          max_name_length, &copied )
                != XmClipboardSuccess )
                continue;

            buf.data()[copied] = '\0';

            if( buf == id )
            {
                isSupported = true;
                break;
            }
        }
    }

    XmClipboardUnlock( xdisplay, xwindow, False );

    return isSupported;
}

class wxClipboardEndRetrieve
{
public:
    wxClipboardEndRetrieve( Display* display, Window window )
        : m_display( display ), m_window( window ) { }
    ~wxClipboardEndRetrieve()
    {
        while( XmClipboardEndRetrieve( m_display, m_window )
               == XmClipboardLocked );
    }
private:
    Display* m_display;
    Window m_window;
};

bool wxClipboard::GetData( wxDataObject& data )
{
    wxCHECK_MSG( m_open, false, "clipboard not open" );

    Display* xdisplay = wxGlobalDisplay();
    Window xwindow = XtWindow( (Widget)wxTheApp->GetTopLevelRealizedWidget() );
    Time timestamp = XtLastTimestampProcessed( xdisplay );

    wxDataFormat chosenFormat;
    int retval;

    ///////////////////////////////////////////////////////////////////////////
    // determine if the cliboard holds any format we like
    ///////////////////////////////////////////////////////////////////////////
    while( ( retval = XmClipboardStartRetrieve( xdisplay, xwindow,
                                                timestamp ) )
           == XmClipboardLocked );
    if( retval != XmClipboardSuccess )
        return false;

    wxClipboardEndRetrieve endRetrieve( xdisplay, xwindow );

    int count;
    unsigned long max_name_length;
    size_t dfcount = data.GetFormatCount( wxDataObject::Set );
    wxDataFormatScopedArray dfarr( new wxDataFormat[dfcount] );
    data.GetAllFormats( dfarr.get(), wxDataObject::Set );

    if( XmClipboardInquireCount( xdisplay, xwindow, &count, &max_name_length )
        == XmClipboardSuccess )
    {
        wxCharBuffer buf( max_name_length + 1 );
        unsigned long copied;

        for( int i = 0; i < count; ++i )
        {
            if( XmClipboardInquireFormat( xdisplay, xwindow, i + 1,
                                          (XtPointer)buf.data(),
                                          max_name_length, &copied )
                != XmClipboardSuccess )
                continue;

            buf.data()[copied] = '\0';

            // try preferred format
            if( buf == data.GetPreferredFormat( wxDataObject::Set ).GetId() )
            {
                chosenFormat = data.GetPreferredFormat( wxDataObject::Set );
                break;
            }

            // try all other formats
            for( size_t i = 0; i < dfcount; ++i )
            {
                if( buf == dfarr[i].GetId() )
                    chosenFormat = dfarr[i];
            }
        }
    }

    if( chosenFormat == wxDF_INVALID )
        return false;

    ///////////////////////////////////////////////////////////////////////////
    // now retrieve the data
    ///////////////////////////////////////////////////////////////////////////
    unsigned long length, dummy1;
    long dummy2;
    wxString id = chosenFormat.GetId();

    while( ( retval = XmClipboardInquireLength( xdisplay, xwindow,
                                                id.char_str(),
                                                &length ) )
           == XmClipboardLocked );
    if( retval != XmClipboardSuccess )
        return false;

    wxCharBuffer buf(length);

    while( ( retval = XmClipboardRetrieve( xdisplay, xwindow,
                                           id.char_str(),
                                           (XtPointer)buf.data(),
                                           length, &dummy1, &dummy2 ) )
           == XmClipboardLocked );
    if( retval != XmClipboardSuccess )
        return false;

    if( !data.SetData( chosenFormat, length, buf.data() ) )
        return false;

    return true;
}

#endif // wxUSE_CLIPBOARD
