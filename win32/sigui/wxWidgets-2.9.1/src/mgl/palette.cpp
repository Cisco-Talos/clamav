/////////////////////////////////////////////////////////////////////////////
// Name:        src/mgl/palette.cpp
// Author:      Vaclav Slavik
// Created:     2001/03/11
// Id:          $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#include "wx/palette.h"
#include <mgraph.h>


//-----------------------------------------------------------------------------
// wxPalette
//-----------------------------------------------------------------------------

class wxPaletteRefData: public wxObjectRefData
{
    public:
        wxPaletteRefData(void);
        virtual ~wxPaletteRefData(void);

        int m_count;
        palette_t *m_entries;
};

wxPaletteRefData::wxPaletteRefData()
{
    m_count = 0;
    m_entries = NULL;
}

wxPaletteRefData::~wxPaletteRefData()
{
    delete[] m_entries;
}

//-----------------------------------------------------------------------------

#define M_PALETTEDATA ((wxPaletteRefData *)m_refData)

IMPLEMENT_DYNAMIC_CLASS(wxPalette,wxGDIObject)

wxPalette::wxPalette()
{
    m_refData = NULL;
}

wxPalette::wxPalette(int n, const unsigned char *red, const unsigned char *green, const unsigned char *blue)
{
    Create(n, red, green, blue);
}

wxPalette::~wxPalette()
{
}

bool wxPalette::Create(int n,
                       const unsigned char *red,
                       const unsigned char *green,
                       const unsigned char *blue)
{
    UnRef();
    m_refData = new wxPaletteRefData();

    M_PALETTEDATA->m_count = n;
    M_PALETTEDATA->m_entries = new palette_t[n];

    palette_t *e = M_PALETTEDATA->m_entries;
    for (int i = 0; i < n; i++, e++)
    {
        e->red = red[i];
        e->green = green[i];
        e->blue = blue[i];
        e->alpha = 0;
    }

    return true;
}

int wxPalette::GetPixel(unsigned char red,
                        unsigned char green,
                        unsigned char blue) const
{
    if (!m_refData) return wxNOT_FOUND;

    int closest = 0;
    double d, distance = 1000.0; // max. dist is 256

    palette_t *e = M_PALETTEDATA->m_entries;
    for (int i = 0; i < M_PALETTEDATA->m_count; i++, e++)
    {
        if ((d = 0.299 * abs(red - e->red) +
                 0.587 * abs(green - e->green) +
                 0.114 * abs(blue - e->blue)) < distance) {
            distance = d;
            closest = i;
        }
    }

    return closest;
}

bool wxPalette::GetRGB(int pixel,
                       unsigned char *red,
                       unsigned char *green,
                       unsigned char *blue) const
{
    if (!m_refData) return false;
    if (pixel >= M_PALETTEDATA->m_count) return false;

    palette_t& p = M_PALETTEDATA->m_entries[pixel];
    if (red) *red = p.red;
    if (green) *green = p.green;
    if (blue) *blue = p.blue;
    return true;
}

int wxPalette::GetColoursCount() const
{
    wxCHECK_MSG( Ok(), 0, wxT("invalid palette") );
    return M_PALETTEDATA->m_count;
}

palette_t *wxPalette::GetMGLpalette_t() const
{
    wxCHECK_MSG( Ok(), NULL, wxT("invalid palette") );
    return M_PALETTEDATA->m_entries;
}
