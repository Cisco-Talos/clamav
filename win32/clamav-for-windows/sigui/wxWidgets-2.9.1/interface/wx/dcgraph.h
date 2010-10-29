/////////////////////////////////////////////////////////////////////////////
// Name:        dcgraph.h
// Purpose:     interface of wxGCDC
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxGCDC

    wxGCDC is a device context that draws on a wxGraphicsContext.

    @library{wxcore}
    @category{dc}

    @see wxDC, wxGraphicsContext
*/

class wxGCDC: public wxDC
{
public:
    /**
       Constructs a wxGCDC from a wxWindowDC.
    */
    wxGCDC( const wxWindowDC& dc );

    /**
       Constructs a wxGCDC from a wxMemoryDC.
    */
    wxGCDC( const wxMemoryDC& dc );

    /**
       Constructs a wxGCDC from a wxPrinterDC.
    */
    wxGCDC( const wxPrinterDC& dc );

    /**
       Retrieves associated wxGraphicsContext
    */
    wxGraphicsContext* GetGraphicsContext();
};

