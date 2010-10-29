/////////////////////////////////////////////////////////////////////////////
// Name:        wx/mgl/private/fontmgr.h
// Purpose:     font management for MGL
// Author:      Vaclav Slavik
// Created:     2006-11-18
// RCS-ID:      $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_MGL_PRIVATE_FONTMGR_H_
#define _WX_MGL_PRIVATE_FONTMGR_H_

struct font_info_t;
struct font_lib_t;
struct font_t;

class wxFontInstance : public wxFontInstanceBase
{
public:
    wxFontInstance(float ptSize, bool aa, font_lib_t *fontLib);
    virtual ~wxFontInstance();

    struct font_t *GetMGLfont_t() const { return m_font; }

private:
    font_t *m_font;
};

class wxFontFace : public wxFontFaceBase
{
public:
    wxFontFace(const wxString& filename)
        : m_fontLib(NULL), m_fileName(filename) {}

    virtual void Acquire();
    virtual void Release();

    virtual wxFontInstance *GetFontInstance(float ptSize, bool aa);

protected:
    wxFontInstance *CreateFontInstance(float ptSize, bool aa);

private:
    font_lib_t *m_fontLib;
    wxString m_fileName;
};

class wxFontBundle : public wxFontBundleBase
{
public:
    wxFontBundle(const font_info_t *fontInfo);

    virtual wxString GetName() const;
    virtual bool IsFixed() const;

    const font_info_t *GetInfo() const { return m_fontInfo; }

private:
    const font_info_t *m_fontInfo;
};

class wxFontsManager : public wxFontsManagerBase
{
public:
    wxFontsManager() { AddAllFonts(); }

    virtual wxString GetDefaultFacename(wxFontFamily family) const;

private:
    // adds all fonts using AddBundle()
    void AddAllFonts();
};

#endif // _WX_MGL_PRIVATE_FONTMGR_H_
