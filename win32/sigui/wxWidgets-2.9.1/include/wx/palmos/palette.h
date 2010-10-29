/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/palette.h
// Purpose:     wxPalette class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_PALETTE_H_
#define _WX_PALETTE_H_

#include "wx/gdiobj.h"

class WXDLLIMPEXP_FWD_CORE wxPalette;

class WXDLLIMPEXP_CORE wxPaletteRefData: public wxGDIRefData
{
    friend class WXDLLIMPEXP_FWD_CORE wxPalette;
public:
    wxPaletteRefData(void);
    virtual ~wxPaletteRefData(void);
protected:
 WXHPALETTE m_hPalette;
};

#define M_PALETTEDATA ((wxPaletteRefData *)m_refData)

class WXDLLIMPEXP_CORE wxPalette: public wxPaletteBase
{
  DECLARE_DYNAMIC_CLASS(wxPalette)

public:
  wxPalette(void);

  wxPalette(int n, const unsigned char *red, const unsigned char *green, const unsigned char *blue);
  virtual ~wxPalette(void);
  bool Create(int n, const unsigned char *red, const unsigned char *green, const unsigned char *blue);
  int GetPixel(unsigned char red, unsigned char green, unsigned char blue) const;
  bool GetRGB(int pixel, unsigned char *red, unsigned char *green, unsigned char *blue) const;

  virtual bool FreeResource(bool force = false);

  inline WXHPALETTE GetHPALETTE(void) const { return (M_PALETTEDATA ? M_PALETTEDATA->m_hPalette : 0); }
  void SetHPALETTE(WXHPALETTE pal);
};

#endif
    // _WX_PALETTE_H_
