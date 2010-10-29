/*
 * Name:        wx/mgl/chkconf.h
 * Purpose:     Compiler-specific configuration checking
 * Author:      Julian Smart
 * Modified by:
 * Created:     01/02/97
 * RCS-ID:      $Id$
 * Copyright:   (c) Julian Smart
 * Licence:     wxWindows licence
 */

/* THIS IS A C FILE, DON'T USE C++ FEATURES (IN PARTICULAR COMMENTS) IN IT */

#ifndef _WX_MGL_CHKCONF_H_
#define _WX_MGL_CHKCONF_H_

#ifndef __WXUNIVERSAL__
#   error "wxMGL cannot be built without wxUniversal"
#endif

/* wxPalette is always needed */
#if !wxUSE_PALETTE
#   error "wxMGL requires wxUSE_PALETTE=1"
#endif

/*
   wxDisplay is not implemented for OS/2, use stub common version instead.
 */
#if wxUSE_DISPLAY
#   undef wxUSE_DISPLAY
#   define wxUSE_DISPLAY 0
#endif /* wxUSE_DISPLAY */

#ifdef __WATCOMC__

/* Watcom builds for MGL port are setup.h driven and setup.h is
   automatically generated from include/wx/setup_inc.h so we have
   to disable here features not supported currently or enable
   features required */

#if wxUSE_STACKWALKER
#   undef wxUSE_STACKWALKER
#   define wxUSE_STACKWALKER 0
#endif /* wxUSE_STACKWALKER */

#if wxUSE_ACCEL
#   undef wxUSE_ACCEL
#   define wxUSE_ACCEL 0
#endif /* wxUSE_ACCEL */

#if wxUSE_DYNLIB_CLASS
#   undef wxUSE_DYNLIB_CLASS
#   define wxUSE_DYNLIB_CLASS 0
#endif /* wxUSE_DYNLIB_CLASS */

#if wxUSE_DYNAMIC_LOADER
#   undef wxUSE_DYNAMIC_LOADER
#   define wxUSE_DYNAMIC_LOADER 0
#endif /* wxUSE_DYNAMIC_LOADER */

#if wxUSE_DATAOBJ
#   undef wxUSE_DATAOBJ
#   define wxUSE_DATAOBJ 0
#endif

#if wxUSE_CLIPBOARD
#   undef wxUSE_CLIPBOARD
#   define wxUSE_CLIPBOARD 0
#endif /* wxUSE_CLIPBOARD */

#if wxUSE_SOCKETS
#   undef wxUSE_SOCKETS
#   define wxUSE_SOCKETS 0
#endif /* wxUSE_SOCKETS */

#if wxUSE_THREADS
#   undef wxUSE_THREADS
#   define wxUSE_THREADS 0
#endif /* wxUSE_SOCKETS */

#if wxUSE_PROTOCOL
#   undef wxUSE_PROTOCOL
#   define wxUSE_PROTOCOL 0
#endif /* wxUSE_PROTOCOL */

#if wxUSE_URL
#   undef wxUSE_URL
#   define wxUSE_URL 0
#endif /* wxUSE_URL */

#if wxUSE_FS_INET
#   undef wxUSE_FS_INET
#   define wxUSE_FS_INET 0
#endif /* wxUSE_FS_INET */

#if wxUSE_MS_HTML_HELP
#   undef wxUSE_MS_HTML_HELP
#   define wxUSE_MS_HTML_HELP 0
#endif

#endif /* __WATCOM__ */

#endif /* _WX_MGL_CHKCONF_H_ */
