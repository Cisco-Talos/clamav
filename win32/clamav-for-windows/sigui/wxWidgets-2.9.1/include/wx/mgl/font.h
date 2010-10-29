/////////////////////////////////////////////////////////////////////////////
// Name:        font.h
// Author:      Vaclav Slavik
// Id:          $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef __WX_FONT_H__
#define __WX_FONT_H__

#include "wx/hash.h"

// ----------------------------------------------------------------------------
// classes
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_FWD_CORE wxDC;
class WXDLLIMPEXP_FWD_CORE wxPaintDC;
class WXDLLIMPEXP_FWD_CORE wxWindow;
class WXDLLIMPEXP_FWD_CORE wxFont;

struct font_t;

// ----------------------------------------------------------------------------
// wxFont
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxFont : public wxFontBase
{
public:
    // ctors and such
    wxFont() { }

    wxFont(const wxNativeFontInfo& info)
    {
        (void)Create(info);
    }

#if FUTURE_WXWIN_COMPATIBILITY_3_0
    wxFont(int size,
           int family,
           int style,
           int weight,
           bool underlined = false,
           const wxString& face = wxEmptyString,
           wxFontEncoding encoding = wxFONTENCODING_DEFAULT)
    {
        (void)Create(size, (wxFontFamily)family, (wxFontStyle)style, (wxFontWeight)weight, underlined, face, encoding);
    }
#endif

    wxFont(int size,
           wxFontFamily family,
           wxFontStyle style,
           wxFontWeight weight,
           bool underlined = false,
           const wxString& face = wxEmptyString,
           wxFontEncoding encoding = wxFONTENCODING_DEFAULT)
    {
        Create(size, family, style, weight, underlined, face, encoding);
    }

    wxFont(const wxSize& pixelSize,
           wxFontFamily family,
           wxFontStyle style,
           wxFontWeight weight,
           bool underlined = false,
           const wxString& face = wxEmptyString,
           wxFontEncoding encoding = wxFONTENCODING_DEFAULT)
    {
        Create(10, family, style, weight, underlined, face, encoding);
        SetPixelSize(pixelSize);
    }

    bool Create(int size,
                wxFontFamily family,
                wxFontStyle style,
                wxFontWeight weight,
                bool underlined = false,
                const wxString& face = wxEmptyString,
                wxFontEncoding encoding = wxFONTENCODING_DEFAULT);

    bool Create(const wxNativeFontInfo& fontinfo);

    virtual ~wxFont() {}

    // implement base class pure virtuals
    virtual int GetPointSize() const;
    virtual wxFontFamily GetFamily() const;
    virtual wxFontStyle GetStyle() const;
    virtual wxFontWeight GetWeight() const;
    virtual wxString GetFaceName() const;
    virtual bool GetUnderlined() const;
    virtual wxFontEncoding GetEncoding() const;
    virtual bool IsFixedWidth() const;
    virtual const wxNativeFontInfo *GetNativeFontInfo() const;

    virtual void SetPointSize(int pointSize);
    virtual void SetFamily(wxFontFamily family);
    virtual void SetStyle(wxFontStyle style);
    virtual void SetWeight(wxFontWeight weight);
    virtual bool SetFaceName(const wxString& faceName);
    virtual void SetUnderlined(bool underlined);
    virtual void SetEncoding(wxFontEncoding encoding);

    wxDECLARE_COMMON_FONT_METHODS();

    struct font_t *GetMGLfont_t(float scale, bool antialiased);

protected:
    // ref counting code
    virtual wxGDIRefData *CreateGDIRefData() const;
    virtual wxGDIRefData *CloneGDIRefData(const wxGDIRefData *data) const;

private:
    DECLARE_DYNAMIC_CLASS(wxFont)
};

#endif // __WX_FONT_H__
