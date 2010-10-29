///////////////////////////////////////////////////////////////////////////////
// Name:        src/x11/dataobj.cpp
// Purpose:     wxDataObject class
// Author:      Julian Smart
// Id:          $Id$
// Copyright:   (c) 1998 Julian Smart
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// for compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_DATAOBJ

#include "wx/dataobj.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/app.h"
    #include "wx/utils.h"
    #include "wx/image.h"
#endif

#include "wx/mstream.h"

#include "wx/x11/private.h"

//-------------------------------------------------------------------------
// global data
//-------------------------------------------------------------------------

Atom  g_textAtom        = 0;
Atom  g_pngAtom         = 0;
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

    if (m_type == wxDF_TEXT || m_type == wxDF_UNICODETEXT)
        m_format = g_textAtom;
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
#if wxUSE_NANOX
    return wxEmptyString;
#else
    char *t = XGetAtomName ((Display*) wxGetDisplay(), m_format);
    wxString ret = wxString::FromAscii( t );
    if (t)
        XFree( t );
    return ret;
#endif
}

void wxDataFormat::SetId( NativeFormat format )
{
    PrepareFormats();
    m_format = format;

    if (m_format == g_textAtom)
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
#if !wxUSE_NANOX
    PrepareFormats();
    m_type = wxDF_PRIVATE;
    m_format = XInternAtom( (Display*) wxGetDisplay(), id.ToAscii(), FALSE );
#endif
}

void wxDataFormat::PrepareFormats()
{
#if !wxUSE_NANOX
    if (!g_textAtom)
        g_textAtom = XInternAtom( (Display*) wxGetDisplay(), "STRING", FALSE );
    if (!g_pngAtom)
        g_pngAtom = XInternAtom( (Display*) wxGetDisplay(), "image/png", FALSE );
    if (!g_fileAtom)
        g_fileAtom = XInternAtom( (Display*) wxGetDisplay(), "text/uri-list", FALSE );
#endif
}

//-------------------------------------------------------------------------
// wxDataObject
//-------------------------------------------------------------------------

wxDataObject::wxDataObject()
{
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
        filenames += m_filenames[i];
        filenames += (wxChar) 0;
    }

    memcpy( buf, filenames.mbc_str(), filenames.length() + 1 );

    return true;
}

size_t wxFileDataObject::GetDataSize() const
{
    size_t res = 0;

    for (size_t i = 0; i < m_filenames.GetCount(); i++)
    {
        res += m_filenames[i].length();
        res += 1;
    }

    return res + 1;
}

bool wxFileDataObject::SetData(size_t WXUNUSED(size), const void *buf)
{
    // VZ: old format
#if 0
    // filenames are stores as a string with #0 as deliminators
    const char *filenames = (const char*) buf;
    size_t pos = 0;
    for(;;)
    {
        if (filenames[0] == 0)
            break;
        if (pos >= size)
            break;
        wxString file( filenames );  // this returns the first file
        AddFile( file );
        pos += file.length()+1;
        filenames += file.length()+1;
    }
#else // 1
    m_filenames.Empty();

    // the text/uri-list format is a sequence of URIs (filenames prefixed by
    // "file:" as far as I see) delimited by "\r\n" of total length size
    // (I wonder what happens if the file has '\n' in its filename??)
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

                AddFile(filename.c_str() + lenPrefix);
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
#endif // 0/1

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

#if wxUSE_LIBPNG
    m_pngSize = size;
    m_pngData = malloc(m_pngSize);

    memcpy( m_pngData, buf, m_pngSize );

    wxMemoryInputStream mstream( (char*) m_pngData, m_pngSize );
    wxImage image;
    wxPNGHandler handler;
    if ( !handler.LoadFile( &image, mstream ) )
    {
        return false;
    }

    m_bitmap = image;

    return m_bitmap.Ok();
#else
    return false;
#endif
}

void wxBitmapDataObject::DoConvertToPng()
{
#if wxUSE_LIBPNG
    if (!m_bitmap.Ok())
        return;

    wxImage image = m_bitmap.ConvertToImage();
    wxPNGHandler handler;

    wxCountingOutputStream count;
    handler.SaveFile( &image, count );

    m_pngSize = count.GetSize() + 100; // sometimes the size seems to vary ???
    m_pngData = malloc(m_pngSize);

    wxMemoryOutputStream mstream( (char*) m_pngData, m_pngSize );
    handler.SaveFile( &image, mstream );
#endif
}

#endif // wxUSE_DATAOBJ
