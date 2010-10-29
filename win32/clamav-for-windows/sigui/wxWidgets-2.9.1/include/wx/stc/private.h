////////////////////////////////////////////////////////////////////////////
// Name:        wx/stc/private.h
// Purpose:     Private declarations for wxSTC
// Author:      Robin Dunn
// Created:     2007-07-15
// RCS-ID:      $Id$
// Copyright:   (c) 2000 by Total Control Software
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_STC_PRIVATE_H_
#define _WX_STC_PRIVATE_H_

#include "wx/defs.h"
#include "wx/string.h"

//----------------------------------------------------------------------
// Utility functions used within wxSTC

#if wxUSE_UNICODE

extern wxString stc2wx(const char* str);
extern wxString stc2wx(const char* str, size_t len);
extern const wxWX2MBbuf wx2stc(const wxString& str);

#else // not UNICODE

inline wxString stc2wx(const char* str) {
    return wxString(str);
}
inline wxString stc2wx(const char* str, size_t len) {
    return wxString(str, len);
}
inline const wxWX2MBbuf wx2stc(const wxString& str) {
    return str.mbc_str();
}

#endif // UNICODE

#endif // _WX_STC_PRIVATE_H_
