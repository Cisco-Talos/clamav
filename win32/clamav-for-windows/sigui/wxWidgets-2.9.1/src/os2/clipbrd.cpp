/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/clipbrd.cpp
// Purpose:     Clipboard functionality
// Author:      David Webster
// Modified by:
// Created:     10/13/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_CLIPBOARD

#include "wx/clipbrd.h"

#ifndef WX_PRECOMP
    #include "wx/object.h"
    #include "wx/event.h"
    #include "wx/app.h"
    #include "wx/frame.h"
    #include "wx/bitmap.h"
    #include "wx/utils.h"
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/dataobj.h"
#endif

#if wxUSE_METAFILE
    #include "wx/metafile.h"
#endif

#include <string.h>

#include "wx/os2/private.h"

// wxDataObject is tied to OLE/drag and drop implementation,
// therefore so is wxClipboard :-(

// ===========================================================================
// implementation
// ===========================================================================

// ---------------------------------------------------------------------------
// old-style clipboard functions using Windows API
// ---------------------------------------------------------------------------

static bool gs_wxClipboardIsOpen = false;

bool wxOpenClipboard()
{
    wxCHECK_MSG( !gs_wxClipboardIsOpen, true, wxT("clipboard already opened.") );
// TODO:
/*
    wxWindow *win = wxTheApp->GetTopWindow();
    if ( win )
    {
        gs_wxClipboardIsOpen = ::OpenClipboard((HWND)win->GetHWND()) != 0;

        if ( !gs_wxClipboardIsOpen )
        {
            wxLogSysError(_("Failed to open the clipboard."));
        }

        return gs_wxClipboardIsOpen;
    }
    else
    {
        wxLogDebug(wxT("Can not open clipboard without a main window."));

        return false;
    }
*/
    return false;
}

bool wxCloseClipboard()
{
    wxCHECK_MSG( gs_wxClipboardIsOpen, false, wxT("clipboard is not opened") );
// TODO:
/*
    gs_wxClipboardIsOpen = false;

    if ( ::CloseClipboard() == 0 )
    {
        wxLogSysError(_("Failed to close the clipboard."));

        return false;
    }
*/
    return true;
}

bool wxEmptyClipboard()
{
// TODO:
/*
    if ( ::EmptyClipboard() == 0 )
    {
        wxLogSysError(_("Failed to empty the clipboard."));

        return false;
    }
*/
    return true;
}

bool wxIsClipboardOpened()
{
  return gs_wxClipboardIsOpen;
}

bool wxIsClipboardFormatAvailable(wxDataFormat WXUNUSED(dataFormat))
{
    // TODO: return ::IsClipboardFormatAvailable(dataFormat) != 0;
    return false;
}

#if 0
#if wxUSE_DRAG_AND_DROP
static bool wxSetClipboardData(wxDataObject *data)
{
    // TODO:
/*
    size_t size = data->GetDataSize();
    HANDLE hGlobal = ::GlobalAlloc(GMEM_MOVEABLE | GMEM_DDESHARE, size);
    if ( !hGlobal )
    {
        wxLogSysError(_("Failed to allocate %dKb of memory for clipboard "
                        "transfer."), size / 1024);

        return false;
    }

    LPVOID lpGlobalMemory = ::GlobalLock(hGlobal);

    data->GetDataHere(lpGlobalMemory);

    GlobalUnlock(hGlobal);

    wxDataFormat format = data->GetPreferredFormat();
    if ( !::SetClipboardData(format, hGlobal) )
    {
        wxLogSysError(_("Failed to set clipboard data in format %s"),
                      wxDataObject::GetFormatName(format));

        return false;
    }
*/
    return true;
}
#endif // wxUSE_DRAG_AND_DROP
#endif

bool wxSetClipboardData(wxDataFormat WXUNUSED(dataFormat),
                        const void *WXUNUSED(data),
                        int WXUNUSED(width), int WXUNUSED(height))
{
// TODO:
/*
    HANDLE handle = 0; // return value of SetClipboardData
    switch (dataFormat)
    {
        case wxDF_BITMAP:
            {
                wxBitmap *bitmap = (wxBitmap *)data;

                HDC hdcMem = CreateCompatibleDC((HDC) NULL);
                HDC hdcSrc = CreateCompatibleDC((HDC) NULL);
                HBITMAP old = (HBITMAP)
                    ::SelectObject(hdcSrc, (HBITMAP)bitmap->GetHBITMAP());
                HBITMAP hBitmap = CreateCompatibleBitmap(hdcSrc,
                                                         bitmap->GetWidth(),
                                                         bitmap->GetHeight());
                if (!hBitmap)
                {
                    SelectObject(hdcSrc, old);
                    DeleteDC(hdcMem);
                    DeleteDC(hdcSrc);
                    return false;
                }

                HBITMAP old1 = (HBITMAP) SelectObject(hdcMem, hBitmap);
                BitBlt(hdcMem, 0, 0, bitmap->GetWidth(), bitmap->GetHeight(),
                       hdcSrc, 0, 0, SRCCOPY);

                // Select new bitmap out of memory DC
                SelectObject(hdcMem, old1);

                // Set the data
                handle = ::SetClipboardData(CF_BITMAP, hBitmap);

                // Clean up
                SelectObject(hdcSrc, old);
                DeleteDC(hdcSrc);
                DeleteDC(hdcMem);
                break;
            }

        case wxDF_DIB:
            {
#if wxUSE_IMAGE_LOADING_IN_MSW
                wxBitmap *bitmap = (wxBitmap *)data;
                HBITMAP hBitmap = (HBITMAP)bitmap->GetHBITMAP();
                // NULL palette means to use the system one
                HANDLE hDIB = wxBitmapToDIB(hBitmap, (HPALETTE)NULL);
                handle = SetClipboardData(CF_DIB, hDIB);
#endif
                break;
            }

#if wxUSE_METAFILE
        case wxDF_METAFILE:
            {
                wxMetafile *wxMF = (wxMetafile *)data;
                HANDLE data = GlobalAlloc(GHND, sizeof(METAFILEPICT) + 1);
                METAFILEPICT *mf = (METAFILEPICT *)GlobalLock(data);

                mf->mm = wxMF->GetWindowsMappingMode();
                mf->xExt = width;
                mf->yExt = height;
                mf->hMF = (HMETAFILE) wxMF->GetHMETAFILE();
                GlobalUnlock(data);
                wxMF->SetHMETAFILE((WXHANDLE) NULL);

                handle = SetClipboardData(CF_METAFILEPICT, data);
                break;
            }
#endif
        case CF_SYLK:
        case CF_DIF:
        case CF_TIFF:
        case CF_PALETTE:
        default:
            {
                wxLogError(_("Unsupported clipboard format."));
                return false;
            }

        case wxDF_OEMTEXT:
            dataFormat = wxDF_TEXT;
            // fall through

        case wxDF_TEXT:
            {
                char *s = (char *)data;

                width = strlen(s) + 1;
                height = 1;
                DWORD l = (width * height);
                HANDLE hGlobalMemory = GlobalAlloc(GHND, l);
                if ( hGlobalMemory )
                {
                    LPSTR lpGlobalMemory = (LPSTR)GlobalLock(hGlobalMemory);

                    memcpy(lpGlobalMemory, s, l);

                    GlobalUnlock(hGlobalMemory);
                }

                handle = SetClipboardData(dataFormat, hGlobalMemory);
                break;
            }
    }

    if ( handle == 0 )
    {
        wxLogSysError(_("Failed to set clipboard data."));

        return false;
    }
*/
    return true;
}

void *wxGetClipboardData(wxDataFormat WXUNUSED(dataFormat), long *WXUNUSED(len))
{
//  void *retval = NULL;
// TODO:
/*
    switch ( dataFormat )
    {
        case wxDF_BITMAP:
            {
                BITMAP bm;
                HBITMAP hBitmap = (HBITMAP) GetClipboardData(CF_BITMAP);
                if (!hBitmap)
                    break;

                HDC hdcMem = CreateCompatibleDC((HDC) NULL);
                HDC hdcSrc = CreateCompatibleDC((HDC) NULL);

                HBITMAP old = (HBITMAP) ::SelectObject(hdcSrc, hBitmap);
                GetObject(hBitmap, sizeof(BITMAP), (LPSTR)&bm);

                HBITMAP hNewBitmap = CreateBitmapIndirect(&bm);

                if (!hNewBitmap)
                {
                    SelectObject(hdcSrc, old);
                    DeleteDC(hdcMem);
                    DeleteDC(hdcSrc);
                    break;
                }

                HBITMAP old1 = (HBITMAP) SelectObject(hdcMem, hNewBitmap);
                BitBlt(hdcMem, 0, 0, bm.bmWidth, bm.bmHeight,
                       hdcSrc, 0, 0, SRCCOPY);

                // Select new bitmap out of memory DC
                SelectObject(hdcMem, old1);

                // Clean up
                SelectObject(hdcSrc, old);
                DeleteDC(hdcSrc);
                DeleteDC(hdcMem);

                // Create and return a new wxBitmap
                wxBitmap *wxBM = new wxBitmap;
                wxBM->SetHBITMAP((WXHBITMAP) hNewBitmap);
                wxBM->SetWidth(bm.bmWidth);
                wxBM->SetHeight(bm.bmHeight);
                wxBM->SetDepth(bm.bmPlanes);
                wxBM->SetOk(true);
                retval = wxBM;
                break;
            }

        case wxDF_METAFILE:
        case CF_SYLK:
        case CF_DIF:
        case CF_TIFF:
        case CF_PALETTE:
        case wxDF_DIB:
            {
                wxLogError(_("Unsupported clipboard format."));
                return NULL;
            }

        case wxDF_OEMTEXT:
            dataFormat = wxDF_TEXT;
            // fall through

        case wxDF_TEXT:
            {
                HANDLE hGlobalMemory = ::GetClipboardData(dataFormat);
                if (!hGlobalMemory)
                    break;

                DWORD hsize = ::GlobalSize(hGlobalMemory);
                if (len)
                    *len = hsize;

                char *s = new char[hsize];
                if (!s)
                    break;

                LPSTR lpGlobalMemory = (LPSTR)::GlobalLock(hGlobalMemory);

                memcpy(s, lpGlobalMemory, hsize);

                ::GlobalUnlock(hGlobalMemory);

                retval = s;
                break;
            }

        default:
            {
                HANDLE hGlobalMemory = ::GetClipboardData(dataFormat);
                if ( !hGlobalMemory )
                    break;

                DWORD size = ::GlobalSize(hGlobalMemory);
                if ( len )
                    *len = size;

                void *buf = malloc(size);
                if ( !buf )
                    break;

                LPSTR lpGlobalMemory = (LPSTR)::GlobalLock(hGlobalMemory);

                memcpy(buf, lpGlobalMemory, size);

                ::GlobalUnlock(hGlobalMemory);

                retval = buf;
                break;
            }
    }

    if ( !retval )
    {
        wxLogSysError(_("Failed to retrieve data from the clipboard."));
    }

    return retval;
*/
    return NULL;
}

wxDataFormat wxEnumClipboardFormats(wxDataFormat dataFormat)
{
  // TODO: return ::EnumClipboardFormats(dataFormat);
  return dataFormat;
}

int wxRegisterClipboardFormat(wxChar *WXUNUSED(formatName))
{
  // TODO: return ::RegisterClipboardFormat(formatName);
  return 0;
}

bool wxGetClipboardFormatName(wxDataFormat WXUNUSED(dataFormat),
                              wxChar *WXUNUSED(formatName),
                              int WXUNUSED(maxCount))
{
  // TODO: return ::GetClipboardFormatName((int)dataFormat, formatName, maxCount) > 0;
  return 0;
}

// ---------------------------------------------------------------------------
// wxClipboard
// ---------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxClipboard, wxObject)

wxClipboard::wxClipboard()
{
}

wxClipboard::~wxClipboard()
{
    Clear();
}

void wxClipboard::Clear()
{
}

bool wxClipboard::Flush()
{
    // TODO:
    return false;
}

bool wxClipboard::Open()
{
    return wxOpenClipboard();
}

bool wxClipboard::IsOpened() const
{
    return wxIsClipboardOpened();
}

bool wxClipboard::SetData( wxDataObject *WXUNUSED(data) )
{
    (void)wxEmptyClipboard();
    // TODO:
    /*
    if ( data )
        return AddData(data);
    else
        return true;
    */
    return true;
}

bool wxClipboard::AddData( wxDataObject *data )
{
    wxCHECK_MSG( data, false, wxT("data is invalid") );

#if wxUSE_DRAG_AND_DROP
    wxCHECK_MSG( wxIsClipboardOpened(), false, wxT("clipboard not open") );

//    wxDataFormat format = data->GetPreferredFormat();
// TODO:
/*
    switch ( format )
    {
        case wxDF_TEXT:
        case wxDF_OEMTEXT:
        {
            wxTextDataObject* textDataObject = (wxTextDataObject*) data;
            wxString str(textDataObject->GetText());
            return wxSetClipboardData(format, str.c_str());
        }

        case wxDF_BITMAP:
        case wxDF_DIB:
        {
            wxBitmapDataObject* bitmapDataObject = (wxBitmapDataObject*) data;
            wxBitmap bitmap(bitmapDataObject->GetBitmap());
            return wxSetClipboardData(data->GetPreferredFormat(), &bitmap);
        }

#if wxUSE_METAFILE
        case wxDF_METAFILE:
        {
            wxMetafileDataObject* metaFileDataObject =
                (wxMetafileDataObject*) data;
            wxMetafile metaFile = metaFileDataObject->GetMetafile();
            return wxSetClipboardData(wxDF_METAFILE, &metaFile,
                                      metaFileDataObject->GetWidth(),
                                      metaFileDataObject->GetHeight());
        }
#endif // wxUSE_METAFILE

        default:
            return wxSetClipboardData(data);
    }
#else // !wxUSE_DRAG_AND_DROP
*/
    return false;
#else
    return false;
#endif // wxUSE_DRAG_AND_DROP/!wxUSE_DRAG_AND_DROP
}

void wxClipboard::Close()
{
    wxCloseClipboard();
}

bool wxClipboard::IsSupported( const wxDataFormat& format )
{
    return wxIsClipboardFormatAvailable(format);
}

bool wxClipboard::GetData( wxDataObject& WXUNUSED(data) )
{
    wxCHECK_MSG( wxIsClipboardOpened(), false, wxT("clipboard not open") );

#if wxUSE_DRAG_AND_DROP
//    wxDataFormat format = data.GetPreferredFormat();
    // TODO:
/*
    switch ( format )
    {
        case wxDF_TEXT:
        case wxDF_OEMTEXT:
        {
            wxTextDataObject& textDataObject = (wxTextDataObject&) data;
            char* s = (char*) wxGetClipboardData(format);
            if ( s )
            {
                textDataObject.SetText(s);
                delete[] s;
                return true;
            }
            else
                return false;
        }

        case wxDF_BITMAP:
        case wxDF_DIB:
        {
            wxBitmapDataObject& bitmapDataObject = (wxBitmapDataObject &)data;
            wxBitmap* bitmap = (wxBitmap *)wxGetClipboardData(data->GetPreferredFormat());
            if (bitmap)
            {
                bitmapDataObject.SetBitmap(* bitmap);
                delete bitmap;
                return true;
            }
            else
                return false;
        }
#if wxUSE_METAFILE
        case wxDF_METAFILE:
        {
            wxMetafileDataObject& metaFileDataObject = (wxMetafileDataObject &)data;
            wxMetafile* metaFile = (wxMetafile *)wxGetClipboardData(wxDF_METAFILE);
            if (metaFile)
            {
                metaFileDataObject.SetMetafile(*metaFile);
                delete metaFile;
                return true;
            }
            else
                return false;
        }
#endif
        default:
            {
                long len;
                void *buf = wxGetClipboardData(format, &len);
                if ( buf )
                {
                    // FIXME this is for testing only!
                    ((wxPrivateDataObject &)data).SetData(buf, len);
                    free(buf);

                    return true;
                }
            }

            return false;
    }
#else
*/
    return false;
#else
    return false;
#endif
}

#endif // wxUSE_CLIPBOARD
