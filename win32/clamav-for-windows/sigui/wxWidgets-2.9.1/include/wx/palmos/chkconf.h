/*
 * Name:        wx/palmos/chkconf.h
 * Purpose:     Compiler-specific configuration checking
 * Author:      William Osborne - minimal working wxPalmOS port
 * Modified by: Yunhui Fu
 * Created:     10/13/04
 * RCS-ID:      $Id$
 * Copyright:   (c) William Osborne
 * Licence:     wxWindows licence
 */

/* THIS IS A C FILE, DON'T USE C++ FEATURES (IN PARTICULAR COMMENTS) IN IT */

#ifndef _WX_PALMOS_CHKCONF_H_
#define _WX_PALMOS_CHKCONF_H_

/*
 * disable the settings which are not implemented yet
 */

#undef wxUSE_ACCEL
#define wxUSE_ACCEL 0

#undef wxUSE_ARCHIVE_STREAMS
#define wxUSE_ARCHIVE_STREAMS 0

#undef wxUSE_BMPBUTTON
#define wxUSE_BMPBUTTON 0

#undef wxUSE_CALENDARCTRL
#define wxUSE_CALENDARCTRL 0

#undef wxUSE_CARET
#define wxUSE_CARET 0

#undef wxUSE_CHECKLISTBOX
#define wxUSE_CHECKLISTBOX 0

#undef wxUSE_CHOICE
#define wxUSE_CHOICE 0

#undef wxUSE_CHOICEBOOK
#define wxUSE_CHOICEBOOK 0

#undef wxUSE_CHOICEDLG
#define wxUSE_CHOICEDLG 0

#undef wxUSE_CLIPBOARD
#define wxUSE_CLIPBOARD 0

#undef wxUSE_COMBOBOX
#define wxUSE_COMBOBOX 0

#undef wxUSE_DATAOBJ
#define wxUSE_DATAOBJ 0

#undef wxUSE_DIRDLG
#define wxUSE_DIRDLG 1

#undef wxUSE_DISPLAY
#define wxUSE_DISPLAY 0

#undef wxUSE_DOC_VIEW_ARCHITECTURE
#define wxUSE_DOC_VIEW_ARCHITECTURE 0

#undef wxUSE_DRAG_AND_DROP
#define wxUSE_DRAG_AND_DROP 0

#undef wxUSE_DRAGIMAGE
#define wxUSE_DRAGIMAGE 0

#undef wxUSE_DYNAMIC_LOADER
#define wxUSE_DYNAMIC_LOADER 0

#undef wxUSE_DYNLIB_CLASS
#define wxUSE_DYNLIB_CLASS 0

#undef wxUSE_ENH_METAFILE
#define wxUSE_ENH_METAFILE 0

#undef wxUSE_FFILE
#define wxUSE_FFILE 0

#undef wxUSE_FILE
#define wxUSE_FILE 1

#undef wxUSE_FILECONFIG
#define wxUSE_FILECONFIG 0

#undef wxUSE_FILEDLG
#define wxUSE_FILEDLG 1

#undef wxUSE_FILESYSTEM
#define wxUSE_FILESYSTEM 0

#undef wxUSE_FINDREPLDLG
#define wxUSE_FINDREPLDLG 0

#undef wxUSE_FONTDLG
#define wxUSE_FONTDLG 0

#undef wxUSE_FONTMAP
#define wxUSE_FONTMAP 0

#undef wxUSE_FS_ARCHIVE
#define wxUSE_FS_ARCHIVE 0

#undef wxUSE_FS_INET
#define wxUSE_FS_INET 0

#undef wxUSE_FS_ZIP
#define wxUSE_FS_ZIP 0

#undef wxUSE_GAUGE
#define wxUSE_GAUGE 0

#undef wxUSE_GRID
#define wxUSE_GRID 0

#undef wxUSE_HELP
#define wxUSE_HELP 0

#undef wxUSE_HTML
#define wxUSE_HTML 0

#undef wxUSE_IMAGE
#define wxUSE_IMAGE 0

#undef wxUSE_LIBPNG
#define wxUSE_LIBPNG 0

#undef wxUSE_LIBJPEG
#define wxUSE_LIBJPEG 0

#undef wxUSE_LIBTIFF
#define wxUSE_LIBTIFF 0

#undef wxUSE_GIF
#define wxUSE_GIF 0

#undef wxUSE_PNM
#define wxUSE_PNM 0

#undef wxUSE_PCX
#define wxUSE_PCX 0

#undef wxUSE_XPM
#define wxUSE_XPM 0

#undef wxUSE_ICO_CUR
#define wxUSE_ICO_CUR 0

#undef wxUSE_SVG
#define wxUSE_SVG 0

#undef wxUSE_INTL
#define wxUSE_INTL 0

#undef wxUSE_IPC
#define wxUSE_IPC 0

#undef wxUSE_JOYSTICK
#define wxUSE_JOYSTICK 0

#undef wxUSE_LISTBOOK
#define wxUSE_LISTBOOK 0

#undef wxUSE_LISTBOX
#define wxUSE_LISTBOX 0

#undef wxUSE_LISTCTRL
#define wxUSE_LISTCTRL 0

#undef wxUSE_LOG_DIALOG
#define wxUSE_LOG_DIALOG 0

#undef wxUSE_LOGWINDOW
#define wxUSE_LOGWINDOW 0

#undef wxUSE_METAFILE
#define wxUSE_METAFILE 0

#undef wxUSE_MDI
#define wxUSE_MDI 0

#undef wxUSE_MDI_ARCHITECTURE
#define wxUSE_MDI_ARCHITECTURE 0

#undef wxUSE_MEDIACTRL
#define wxUSE_MEDIACTRL 0

#undef wxUSE_MIMETYPE
#define wxUSE_MIMETYPE 0

#undef wxUSE_MOUSEWHEEL
#define wxUSE_MOUSEWHEEL 0

#undef wxUSE_NOTEBOOK
#define wxUSE_NOTEBOOK 0

#undef wxUSE_NUMBERDLG
#define wxUSE_NUMBERDLG 0

#undef wxUSE_ON_FATAL_EXCEPTION
#define wxUSE_ON_FATAL_EXCEPTION 0

#undef wxUSE_PALETTE
#define wxUSE_PALETTE 0

#undef wxUSE_POPUPWIN
#define wxUSE_POPUPWIN 0

#undef wxUSE_PRINTING_ARCHITECTURE
#define wxUSE_PRINTING_ARCHITECTURE 0

#undef wxUSE_PROTOCOL
#define wxUSE_PROTOCOL 0

#undef wxUSE_PROTOCOL_FILE
#define wxUSE_PROTOCOL_FILE 0

#undef wxUSE_PROTOCOL_FTP
#define wxUSE_PROTOCOL_FTP 0

#undef wxUSE_PROTOCOL_HTTP
#define wxUSE_PROTOCOL_HTTP 0

#undef wxUSE_REGEX
#define wxUSE_REGEX 0

#undef wxUSE_SCROLLBAR
#define wxUSE_SCROLLBAR 0

#undef wxUSE_SNGLINST_CHECKER
#define wxUSE_SNGLINST_CHECKER 0

#undef wxUSE_SOCKETS
#define wxUSE_SOCKETS 0

#undef wxUSE_SOUND
#define wxUSE_SOUND 0

#undef wxUSE_SPINBTN
#define wxUSE_SPINBTN 0

#undef wxUSE_SPINCTRL
#define wxUSE_SPINCTRL 0

#undef wxUSE_SPLASH
#define wxUSE_SPLASH 0

#undef wxUSE_SPLINES
#define wxUSE_SPLINES 0

#undef wxUSE_STARTUP_TIPS
#define wxUSE_STARTUP_TIPS 0

#undef wxUSE_STATBMP
#define wxUSE_STATBMP 0

#undef wxUSE_STATBOX
#define wxUSE_STATBOX 0

#undef wxUSE_STATLINE
#define wxUSE_STATLINE 0

#undef wxUSE_TARSTREAM
#define wxUSE_TARSTREAM 0

#undef wxUSE_TEXTBUFFER
#define wxUSE_TEXTBUFFER 0

#undef wxUSE_TEXTCTRL
#define wxUSE_TEXTCTRL 0

#undef wxUSE_TEXTFILE
#define wxUSE_TEXTFILE 0

#undef wxUSE_TEXTDLG
#define wxUSE_TEXTDLG 0

#undef wxUSE_THREADS
#define wxUSE_THREADS 0

#undef wxUSE_TIPWINDOW
#define wxUSE_TIPWINDOW 0

#undef wxUSE_TREEBOOK
#define wxUSE_TREEBOOK 0

#undef wxUSE_TREECTRL
#define wxUSE_TREECTRL 0

#undef wxUSE_TIMER
#define wxUSE_TIMER 0

#undef wxUSE_TOOLBAR
#define wxUSE_TOOLBAR 0

#undef wxUSE_TOOLBAR_NATIVE
#define wxUSE_TOOLBAR_NATIVE 0

#undef wxUSE_TOOLTIPS
#define wxUSE_TOOLTIPS 0

#undef wxUSE_URL
#define wxUSE_URL 0

//#undef wxUSE_WCHAR_T
//#define wxUSE_WCHAR_T 1

#undef wxUSE_WIZARDDLG
#define wxUSE_WIZARDDLG 0

#undef wxUSE_WXHTML_HELP
#define wxUSE_WXHTML_HELP 0

#undef wxUSE_XML
#define wxUSE_XML 0

#undef wxUSE_XRC
#define wxUSE_XRC 0

#undef wxUSE_ZIPSTREAM
#define wxUSE_ZIPSTREAM 0

#undef wxUSE_ZLIB
#define wxUSE_ZLIB 0

#undef wxUSE_COLLPANE
#define wxUSE_COLLPANE 0

#undef wxUSE_TOOLBOOK
#define wxUSE_TOOLBOOK 0

#undef wxUSE_SELECT_DISPATCHER
#define wxUSE_SELECT_DISPATCHER 1

#endif
    /* _WX_PALMOS_CHKCONF_H_ */
