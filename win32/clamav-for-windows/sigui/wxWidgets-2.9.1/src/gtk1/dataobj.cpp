///////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/dataobj.cpp
// Purpose:     wxDataObject class
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_DATAOBJ

#include "wx/dataobj.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/app.h"
    #include "wx/image.h"
#endif

#include "wx/mstream.h"
#include "wx/uri.h"

#include <gdk/gdk.h>

//-------------------------------------------------------------------------
// global data
//-------------------------------------------------------------------------

GdkAtom  g_textAtom        = 0;
GdkAtom  g_altTextAtom     = 0;
GdkAtom  g_pngAtom         = 0;
GdkAtom  g_fileAtom        = 0;

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
    m_format = (GdkAtom) 0;
}

wxDataFormat::wxDataFormat( wxDataFormatId type )
{
    PrepareFormats();
    SetType( type );
}

void wxDataFormat::InitFromString( const wxString &id )
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

#if wxUSE_UNICODE
    if (m_type == wxDF_UNICODETEXT)
        m_format = g_textAtom;
    else if (m_type == wxDF_TEXT)
        m_format = g_altTextAtom;
#else
    if (m_type == wxDF_TEXT || m_type == wxDF_UNICODETEXT)
        m_format = g_textAtom;
#endif
    else
    if (m_type == wxDF_BITMAP)
        m_format = g_pngAtom;
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
    gchar* atom_name = gdk_atom_name( m_format );
    wxString ret = wxString::FromAscii( atom_name );
    g_free(atom_name);
    return ret;
}

void wxDataFormat::SetId( NativeFormat format )
{
    PrepareFormats();
    m_format = format;

    if (m_format == g_textAtom)
#if wxUSE_UNICODE
        m_type = wxDF_UNICODETEXT;
#else
        m_type = wxDF_TEXT;
#endif
    else
    if (m_format == g_altTextAtom)
        m_type = wxDF_TEXT;
    else
    if (m_format == g_pngAtom)
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
    m_format = gdk_atom_intern( id.ToAscii(), FALSE );
}

void wxDataFormat::PrepareFormats()
{
    // VZ: GNOME included in RedHat 6.1 uses the MIME types below and not the
    //     atoms STRING and file:ALL as the old code was, but normal X apps
    //     use STRING for text selection when transfering the data via
    //     clipboard, for example, so do use STRING for now (GNOME apps will
    //     probably support STRING as well for compatibility anyhow), but use
    //     text/uri-list for file dnd because compatibility is not important
    //     here (with whom?)
    if (!g_textAtom)
#if wxUSE_UNICODE
        g_textAtom = gdk_atom_intern( "UTF8_STRING", FALSE );
        g_altTextAtom = gdk_atom_intern( "STRING", FALSE );
#else
        g_textAtom = gdk_atom_intern( "STRING" /* "text/plain" */, FALSE );
#endif
    if (!g_pngAtom)
        g_pngAtom = gdk_atom_intern( "image/png", FALSE );
    if (!g_fileAtom)
        g_fileAtom = gdk_atom_intern( "text/uri-list", FALSE );
}

//-------------------------------------------------------------------------
// wxDataObject
//-------------------------------------------------------------------------

wxDataObject::wxDataObject()
{
}

wxDataObject::~wxDataObject()
{
    // dtor is empty but needed for Darwin and AIX -- otherwise it doesn't link
}

bool wxDataObject::IsSupportedFormat(const wxDataFormat& format, Direction dir) const
{
    size_t nFormatCount = GetFormatCount(dir);
    if ( nFormatCount == 1 )
    {
        return format == GetPreferredFormat();
    }
    else
    {
        wxDataFormat *formats = new wxDataFormat[nFormatCount];
        GetAllFormats(formats,dir);

        size_t n;
        for ( n = 0; n < nFormatCount; n++ )
        {
            if ( formats[n] == format )
                break;
        }

        delete [] formats;

        // found?
        return n < nFormatCount;
    }
}

// ----------------------------------------------------------------------------
// wxFileDataObject
// ----------------------------------------------------------------------------

bool wxFileDataObject::GetDataHere(void *buf) const
{
    wxString filenames;

    for (size_t i = 0; i < m_filenames.GetCount(); i++)
    {
        filenames += wxT("file:");
        filenames += m_filenames[i];
        filenames += wxT("\r\n");
    }

    memcpy( buf, filenames.mbc_str(), filenames.length() + 1 );

    return true;
}

size_t wxFileDataObject::GetDataSize() const
{
    size_t res = 0;

    for (size_t i = 0; i < m_filenames.GetCount(); i++)
    {
        // This is junk in UTF-8
        res += m_filenames[i].length();
        res += 5 + 2; // "file:" (5) + "\r\n" (2)
    }

    return res + 1;
}

bool wxFileDataObject::SetData(size_t WXUNUSED(size), const void *buf)
{
    m_filenames.Empty();

    // we get data in the text/uri-list format, i.e. as a sequence of URIs
    // (filenames prefixed by "file:") delimited by "\r\n"
    wxString filename;
    for ( const char *p = (const char *)buf; ; p++ )
    {
        // some broken programs (testdnd GTK+ sample!) omit the trailing
        // "\r\n", so check for '\0' explicitly here instead of doing it in
        // the loop statement to account for it
        if ( (*p == '\r' && *(p+1) == '\n') || !*p )
        {
            size_t lenPrefix = 5; // strlen("file:")
            if ( filename.Left(lenPrefix).MakeLower() == wxT("file:") )
            {
                // sometimes the syntax is "file:filename", sometimes it's
                // URL-like: "file://filename" - deal with both
                if ( filename[lenPrefix] == wxT('/') &&
                     filename[lenPrefix + 1] == wxT('/') )
                {
                    // skip the slashes
                    lenPrefix += 2;
                }

                AddFile(wxURI::Unescape(filename.c_str() + lenPrefix));
                filename.Empty();
            }
            else
            {
                wxLogDebug(wxT("Unsupported URI '%s' in wxFileDataObject"),
                           filename.c_str());
            }

            if ( !*p )
                break;

            // skip '\r'
            p++;
        }
        else
        {
            filename += *p;
        }
    }

    return true;
}

void wxFileDataObject::AddFile( const wxString &filename )
{
   m_filenames.Add( filename );
}

// ----------------------------------------------------------------------------
// wxBitmapDataObject
// ----------------------------------------------------------------------------

wxBitmapDataObject::wxBitmapDataObject()
{
    Init();
}

wxBitmapDataObject::wxBitmapDataObject( const wxBitmap& bitmap )
                  : wxBitmapDataObjectBase(bitmap)
{
    Init();

    DoConvertToPng();
}

wxBitmapDataObject::~wxBitmapDataObject()
{
    Clear();
}

void wxBitmapDataObject::SetBitmap( const wxBitmap &bitmap )
{
    ClearAll();

    wxBitmapDataObjectBase::SetBitmap(bitmap);

    DoConvertToPng();
}

bool wxBitmapDataObject::GetDataHere(void *buf) const
{
    if ( !m_pngSize )
    {
        wxFAIL_MSG( wxT("attempt to copy empty bitmap failed") );

        return false;
    }

    memcpy(buf, m_pngData, m_pngSize);

    return true;
}

bool wxBitmapDataObject::SetData(size_t size, const void *buf)
{
    Clear();

    wxCHECK_MSG( wxImage::FindHandler(wxBITMAP_TYPE_PNG) != NULL,
                 false, wxT("You must call wxImage::AddHandler(new wxPNGHandler); to be able to use clipboard with bitmaps!") );

    m_pngSize = size;
    m_pngData = malloc(m_pngSize);

    memcpy(m_pngData, buf, m_pngSize);

    wxMemoryInputStream mstream((char*) m_pngData, m_pngSize);
    wxImage image;
    if ( !image.LoadFile( mstream, wxBITMAP_TYPE_PNG ) )
    {
        return false;
    }

    m_bitmap = wxBitmap(image);

    return m_bitmap.Ok();
}

void wxBitmapDataObject::DoConvertToPng()
{
    if ( !m_bitmap.Ok() )
        return;

    wxCHECK_RET( wxImage::FindHandler(wxBITMAP_TYPE_PNG) != NULL,
                 wxT("You must call wxImage::AddHandler(new wxPNGHandler); to be able to use clipboard with bitmaps!") );

    wxImage image = m_bitmap.ConvertToImage();

    wxCountingOutputStream count;
    image.SaveFile(count, wxBITMAP_TYPE_PNG);

    m_pngSize = count.GetSize() + 100; // sometimes the size seems to vary ???
    m_pngData = malloc(m_pngSize);

    wxMemoryOutputStream mstream((char*) m_pngData, m_pngSize);
    image.SaveFile(mstream, wxBITMAP_TYPE_PNG);
}

#endif // wxUSE_DATAOBJ
