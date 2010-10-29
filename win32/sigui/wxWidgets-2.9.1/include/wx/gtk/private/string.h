///////////////////////////////////////////////////////////////////////////////
// Name:        wx/gtk/private/string.h
// Purpose:     wxGtkString class declaration
// Author:      Vadim Zeitlin
// Created:     2006-10-19
// RCS-ID:      $Id$
// Copyright:   (c) 2006 Vadim Zeitlin <vadim@wxwindows.org>
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

#ifndef _WX_GTK_PRIVATE_STRING_H_
#define _WX_GTK_PRIVATE_STRING_H_

// ----------------------------------------------------------------------------
// Convenience class for g_freeing a gchar* on scope exit automatically
// ----------------------------------------------------------------------------

class wxGtkString
{
public:
    explicit wxGtkString(gchar *s) : m_str(s) { }
    ~wxGtkString() { g_free(m_str); }

    const gchar *c_str() const { return m_str; }

    operator gchar *() const { return m_str; }

private:
    gchar *m_str;

    wxDECLARE_NO_COPY_CLASS(wxGtkString);
};

#endif // _WX_GTK_PRIVATE_STRING_H_

