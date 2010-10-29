///////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/apptbase.h
// Purpose:     declaration of wxAppTraits for Palm OS
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

#ifndef _WX_PALMOS_APPTBASE_H_
#define _WX_PALMOS_APPTBASE_H_

// ----------------------------------------------------------------------------
// wxAppTraits
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_BASE wxAppTraits : public wxAppTraitsBase
{
public:
    // wxExecute() support methods
    // ---------------------------

    // called before starting to wait for the child termination, may return
    // some opaque data which will be passed later to AfterChildWaitLoop()
    virtual void *BeforeChildWaitLoop() = 0;

    // called after starting to wait for the child termination, the parameter
    // is the return value of BeforeChildWaitLoop()
    virtual void AfterChildWaitLoop(void *data) = 0;


    // wxThread helpers
    // ----------------

    // process a message while waiting for a(nother) thread, should return
    // false if and only if we have to exit the application
    virtual bool DoMessageFromThreadWait() = 0;
};

#endif // _WX_PALMOS_APPTBASE_H_

