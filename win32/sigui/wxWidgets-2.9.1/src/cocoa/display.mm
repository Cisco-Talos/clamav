/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/display.mm
// Purpose:     Cocoa implementation of wxDisplay class
// Author:      Ryan Norton
// Modified by:
// Created:     2004-10-03
// RCS-ID:      $Id$
// Copyright:   (c) Ryan Norton
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_DISPLAY

#include "wx/display.h"

#ifndef WX_PRECOMP
    #include "wx/dynarray.h"
    #include "wx/string.h"
    #include "wx/gdicmn.h"
#endif

#include "wx/display_impl.h"

#import <Foundation/Foundation.h>

// ----------------------------------------------------------------------------
// display classes implementation
// ----------------------------------------------------------------------------

class wxDisplayImplMacOSX : public wxDisplayImpl
{
public:
    wxDisplayImplMacOSX(unsigned n, CGDirectDisplayID id_)
        : wxDisplayImpl(n),
          m_id(id_)
    {
    }

    virtual wxRect GetGeometry() const;
    virtual wxString GetName() const { return wxString(); }

    virtual wxArrayVideoModes GetModes(const wxVideoMode& mode) const;
    virtual wxVideoMode GetCurrentMode() const;
    virtual bool ChangeMode(const wxVideoMode& mode);

private:
    CGDirectDisplayID m_id;

    wxDECLARE_NO_COPY_CLASS(wxDisplayImplMacOSX);
};

class wxDisplayFactoryMacOSX : public wxDisplayFactory
{
public:
    wxDisplayFactoryMacOSX() { }

    virtual wxDisplayImpl *CreateDisplay(unsigned n);
    virtual unsigned GetCount();
    virtual int GetFromPoint(const wxPoint& pt);

protected:
    wxDECLARE_NO_COPY_CLASS(wxDisplayFactoryMacOSX);
};

// ============================================================================
// wxDisplayFactoryMacOSX implementation
// ============================================================================

unsigned wxDisplayFactoryMacOSX::GetCount()
{
    CGDisplayCount count;
    CGDisplayErr err = CGGetActiveDisplayList(0, NULL, &count);
    wxCHECK_MSG( err != CGDisplayNoErr, 0, "CGGetActiveDisplayList() failed" );

    return count;
}

int wxDisplayFactoryMacOSX::GetFromPoint(const wxPoint& p)
{
    CGPoint thePoint = {(float)p.x, (float)p.y};
    CGDirectDisplayID theID;
    CGDisplayCount theCount;
    CGDisplayErr err = CGGetDisplaysWithPoint(thePoint, 1, &theID, &theCount);
    wxASSERT(err == CGDisplayNoErr);

    int nWhich = wxNOT_FOUND;

    if (theCount)
    {
        theCount = GetCount();
        CGDirectDisplayID* theIDs = new CGDirectDisplayID[theCount];
        err = CGGetActiveDisplayList(theCount, theIDs, &theCount);
        wxASSERT(err == CGDisplayNoErr);

        for (nWhich = 0; nWhich < (int) theCount; ++nWhich)
        {
            if (theIDs[nWhich] == theID)
                break;
        }

        delete [] theIDs;

        if (nWhich == (int) theCount)
        {
            wxFAIL_MSG(wxT("Failed to find display in display list"));
            nWhich = wxNOT_FOUND;
        }
    }

    return nWhich;
}

wxDisplayImpl *wxDisplayFactoryMacOSX::CreateDisplay(unsigned n)
{
    CGDisplayCount theCount = GetCount();
    CGDirectDisplayID* theIDs = new CGDirectDisplayID[theCount];

    CGDisplayErr err = CGGetActiveDisplayList(theCount, theIDs, &theCount);
    wxCHECK_MSG( err != CGDisplayNoErr, NULL, "CGGetActiveDisplayList() failed" );

    wxASSERT( n < theCount );

    wxDisplayImplMacOSX *display = new wxDisplayImplMacOSX(n, theIDs[n]);

    delete [] theIDs;

    return display;
}


wxRect wxDisplayImplMacOSX::GetGeometry() const
{
    CGRect theRect = CGDisplayBounds(m_id);
    return wxRect(  (int)theRect.origin.x,
                    (int)theRect.origin.y,
                    (int)theRect.size.width,
                    (int)theRect.size.height  ); //floats
}

static int wxCFDictKeyToInt( CFDictionaryRef desc, CFStringRef key )
{
    CFNumberRef value;
    int num = 0;

    if ( (value = (CFNumberRef) CFDictionaryGetValue(desc, key)) == NULL )
        return 0;
    CFNumberGetValue(value, kCFNumberIntType, &num);
    return num;
}

wxArrayVideoModes wxDisplayImplMacOSX::GetModes(const wxVideoMode& mode) const
{
    wxArrayVideoModes Modes;

    CFArrayRef theArray = CGDisplayAvailableModes(m_id);

    for(CFIndex i = 0; i < CFArrayGetCount(theArray); ++i)
    {
        CFDictionaryRef theValue = (CFDictionaryRef) CFArrayGetValueAtIndex(theArray, i);

        wxVideoMode theMode(wxCFDictKeyToInt(theValue, kCGDisplayWidth),
                            wxCFDictKeyToInt(theValue, kCGDisplayHeight),
                            wxCFDictKeyToInt(theValue, kCGDisplayBitsPerPixel),
                            wxCFDictKeyToInt(theValue, kCGDisplayRefreshRate));

        if (theMode.Matches(mode))
            Modes.Add(theMode);
    }

    return Modes;
}

wxVideoMode wxDisplayImplMacOSX::GetCurrentMode() const
{
    CFDictionaryRef theValue = CGDisplayCurrentMode (m_id);

    return wxVideoMode(wxCFDictKeyToInt(theValue, kCGDisplayWidth),
                            wxCFDictKeyToInt(theValue, kCGDisplayHeight),
                            wxCFDictKeyToInt(theValue, kCGDisplayBitsPerPixel),
                            wxCFDictKeyToInt(theValue, kCGDisplayRefreshRate));
}

bool wxDisplayImplMacOSX::ChangeMode(const wxVideoMode& mode)
{
    //Changing to default mode (wxDefualtVideoMode) doesn't
    //work because we don't have access to the system's 'scrn'
    //resource which holds the user's mode which the system
    //will return to after this app is done
    boolean_t bExactMatch;
    CFDictionaryRef theCGMode = CGDisplayBestModeForParametersAndRefreshRate (
                                        m_id,
                                        (size_t)mode.bpp,
                                        (size_t)mode.w,
                                        (size_t)mode.h,
                                        (double)mode.refresh,
                                        &bExactMatch);

    bool bOK = bExactMatch;

    if(bOK)
        bOK = CGDisplaySwitchToMode(m_id, theCGMode) == CGDisplayNoErr;

    return bOK;
}

// ============================================================================
// wxDisplay::CreateFactory()
// ============================================================================

/* static */ wxDisplayFactory *wxDisplay::CreateFactory()
{
    return new wxDisplayFactoryMacOSX;
}

#endif // wxUSE_DISPLAY
