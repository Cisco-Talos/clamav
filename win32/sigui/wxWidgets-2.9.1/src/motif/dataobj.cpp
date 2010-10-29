///////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/dataobj.cpp
// Purpose:     wxDataObject class
// Author:      Julian Smart
// Id:          $Id$
// Copyright:   (c) 1998 Julian Smart
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_CLIPBOARD

#include "wx/dataobj.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/utils.h"
#endif

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/Xm.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

#include "wx/motif/private.h"

//-------------------------------------------------------------------------
// global data
//-------------------------------------------------------------------------

Atom  g_textAtom        = 0;
Atom  g_bitmapAtom      = 0;
Atom  g_fileAtom        = 0;

//-------------------------------------------------------------------------
// wxDataFormat
//-------------------------------------------------------------------------

wxDataFormat::wxDataFormat()
{
    // do *not* call PrepareFormats() from here for 2 reasons:
    //
    // 1. we will have time to do it later because some other Set function
    //    must be called before we really need them
    //
    // 2. doing so prevents us from declaring global wxDataFormats because
    //    calling PrepareFormats (and thus gdk_atom_intern) before GDK is
    //    initialised will result in a crash
    m_type = wxDF_INVALID;
    m_format = (Atom) 0;
}

wxDataFormat::wxDataFormat( wxDataFormatId type )
{
    PrepareFormats();
    SetType( type );
}

wxDataFormat::wxDataFormat( const wxString &id )
{
    PrepareFormats();
    SetId( id );
}

wxDataFormat::wxDataFormat( NativeFormat format )
{
    PrepareFormats();
    SetId( format );
}

void wxDataFormat::SetType( wxDataFormatId type )
{
    PrepareFormats();
    m_type = type;

    if (m_type == wxDF_TEXT)
        m_format = g_textAtom;
    else
    if (m_type == wxDF_BITMAP)
        m_format = g_bitmapAtom;
    else
    if (m_type == wxDF_FILENAME)
        m_format = g_fileAtom;
    else
    {
       wxFAIL_MSG( wxT("invalid dataformat") );
    }
}

wxDataFormatId wxDataFormat::GetType() const
{
    return m_type;
}

wxString wxDataFormat::GetId() const
{
    char *t = XGetAtomName ((Display*) wxGetDisplay(), m_format);
    wxString ret( t );  // this will convert from ascii to Unicode
    if (t)
        XFree( t );
    return ret;
}

void wxDataFormat::SetId( NativeFormat format )
{
    PrepareFormats();
    m_format = format;

    if (m_format == g_textAtom)
        m_type = wxDF_TEXT;
    else
    if (m_format == g_bitmapAtom)
        m_type = wxDF_BITMAP;
    else
    if (m_format == g_fileAtom)
        m_type = wxDF_FILENAME;
    else
        m_type = wxDF_PRIVATE;
}

void wxDataFormat::SetId( const wxString& id )
{
    PrepareFormats();
    m_type = wxDF_PRIVATE;
    m_format = XInternAtom( wxGlobalDisplay(),
                            id.mbc_str(), False );
}

void wxDataFormat::PrepareFormats()
{
    if (!g_textAtom)
        g_textAtom = XInternAtom( wxGlobalDisplay(), "STRING", False );
    if (!g_bitmapAtom)
        g_bitmapAtom = XInternAtom( wxGlobalDisplay(), "PIXMAP", False );
    if (!g_fileAtom)
        g_fileAtom = XInternAtom( wxGlobalDisplay(), "file:ALL", False );
}

// ----------------------------------------------------------------------------
// wxDataObject
// ----------------------------------------------------------------------------

wxDataObject::~wxDataObject()
{
}

// ----------------------------------------------------------------------------
// wxBitmapDataObject
// ----------------------------------------------------------------------------

size_t wxBitmapDataObject::GetDataSize() const
{
    return sizeof(Pixmap);
}

bool wxBitmapDataObject::GetDataHere(void* buf) const
{
    if( !GetBitmap().Ok() )
        return false;

    (*(Pixmap*)buf) = (Pixmap)GetBitmap().GetDrawable();

    return true;
}

bool wxBitmapDataObject::SetData(size_t len, const void* buf)
{
    if( len != sizeof(Pixmap) )
        return false;

    WXPixmap pixmap = (WXPixmap)*(Pixmap*)buf;

    m_bitmap.Create( pixmap );

    return true;
}

#endif // wxUSE_CLIPBOARD
