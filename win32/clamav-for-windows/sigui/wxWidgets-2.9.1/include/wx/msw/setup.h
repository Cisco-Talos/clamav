/////////////////////////////////////////////////////////////////////////////
// Name:        wx/msw/setup.h
// Purpose:     Configuration for the library
// Author:      Julian Smart
// Modified by:
// Created:     01/02/97
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_SETUP_H_
#define _WX_SETUP_H_

/* --- start common options --- */

#ifndef wxUSE_GUI
    #define wxUSE_GUI 1
#endif


#define WXWIN_COMPATIBILITY_2_6 0

#define WXWIN_COMPATIBILITY_2_8 0

#define wxDIALOG_UNIT_COMPATIBILITY   0



#define wxUSE_ON_FATAL_EXCEPTION 0

#define wxUSE_STACKWALKER 0

#define wxUSE_DEBUGREPORT 0



#define wxUSE_DEBUG_CONTEXT 0

#define wxUSE_MEMORY_TRACING 0

#define wxUSE_GLOBAL_MEMORY_OPERATORS 0

#define wxUSE_DEBUG_NEW_ALWAYS 0



#ifndef wxUSE_UNICODE
    #define wxUSE_UNICODE 1
#endif

#define wxUSE_WCHAR_T 1


#define wxUSE_EXCEPTIONS    0

#define wxUSE_EXTENDED_RTTI 0

#define wxUSE_STL 0

#define wxUSE_LOG 1

#define wxUSE_LOGWINDOW 0

#define wxUSE_LOGGUI 1

#define wxUSE_LOG_DIALOG 1

#define wxUSE_CMDLINE_PARSER 1

#define wxUSE_THREADS 0

#define wxUSE_STREAMS 1

#if defined(__DMC__) || defined(__WATCOMC__) \
        || (defined(_MSC_VER) && _MSC_VER < 1200)
    #define wxUSE_STD_DEFAULT  0
#else
    #define wxUSE_STD_DEFAULT  0
#endif

#define wxUSE_STD_IOSTREAM 0

#define wxUSE_STD_STRING 0

#define wxUSE_PRINTF_POS_PARAMS 0


#define wxUSE_LONGLONG 1

#define wxUSE_BASE64 1

#define wxUSE_CONSOLE_EVENTLOOP 1

#define wxUSE_FILE 1
#define wxUSE_FFILE 1

#define wxUSE_FSVOLUME      0

#define wxUSE_STDPATHS 1

#define wxUSE_TEXTBUFFER 1

#define wxUSE_TEXTFILE 1

/* TODO: enable if we need i18n */
#define wxUSE_INTL 0

#define wxUSE_XLOCALE 0

#define wxUSE_DATETIME 1

#define wxUSE_TIMER 1

#define wxUSE_STOPWATCH 0

#define wxUSE_FSWATCHER     0

#define wxUSE_CONFIG 1

#define wxUSE_CONFIG_NATIVE 1

#define wxUSE_DIALUP_MANAGER 0

#define wxUSE_DYNLIB_CLASS 1

#define wxUSE_DYNAMIC_LOADER 0

#define wxUSE_SOCKETS 0

#define wxUSE_IPV6          0

#define wxUSE_FILESYSTEM 0

#define wxUSE_FS_ZIP 0

#define wxUSE_FS_ARCHIVE 0

#define wxUSE_FS_INET 0

#define wxUSE_ARCHIVE_STREAMS 0

#define wxUSE_ZIPSTREAM     0

#define wxUSE_TARSTREAM 0

#define wxUSE_ZLIB          0

#define wxUSE_APPLE_IEEE 0

#define wxUSE_JOYSTICK 0

#define wxUSE_FONTENUM 0

#define wxUSE_FONTMAP 0

#define wxUSE_MIMETYPE 0

#define wxUSE_PROTOCOL 1

#define wxUSE_PROTOCOL_FILE 1
#define wxUSE_PROTOCOL_FTP 0
#define wxUSE_PROTOCOL_HTTP 0

#define wxUSE_URL 1

#define wxUSE_URL_NATIVE 1

#define wxUSE_VARIANT 0

#define wxUSE_ANY 1

#define wxUSE_REGEX       0

#define wxUSE_SYSTEM_OPTIONS 1

#define wxUSE_SOUND 0

#define wxUSE_MEDIACTRL 0

#define wxUSE_XRC       0

#define wxUSE_XML       wxUSE_XRC

#define wxUSE_AUI 0

#define wxUSE_RIBBON 0

#define wxUSE_PROPGRID 0

#define wxUSE_STC 0



#ifdef _MSC_VER
#   if _MSC_VER >= 1310


#define wxUSE_GRAPHICS_CONTEXT 0
#   else


#       define wxUSE_GRAPHICS_CONTEXT 0
#   endif
#else





#   define wxUSE_GRAPHICS_CONTEXT 0
#endif


#define wxUSE_CONTROLS 1

#define wxUSE_POPUPWIN 0

#define wxUSE_TIPWINDOW 0

#define wxUSE_ANIMATIONCTRL 0
#define wxUSE_BUTTON 1
#define wxUSE_BMPBUTTON 1
#define wxUSE_CALENDARCTRL 0
#define wxUSE_CHECKBOX 1
#define wxUSE_CHECKLISTBOX 0
#define wxUSE_CHOICE 1
#define wxUSE_COLLPANE 1
#define wxUSE_COLOURPICKERCTRL 0
#define wxUSE_COMBOBOX 1
#define wxUSE_DATAVIEWCTRL 0
#define wxUSE_DATEPICKCTRL 0
#define wxUSE_DIRPICKERCTRL 0
#define wxUSE_EDITABLELISTBOX 0
#define wxUSE_FILECTRL 0
#define wxUSE_FILEPICKERCTRL 0
#define wxUSE_FONTPICKERCTRL 0
#define wxUSE_GAUGE 1
#define wxUSE_HEADERCTRL 0
#define wxUSE_HYPERLINKCTRL 0
#define wxUSE_LISTBOX 1
#define wxUSE_LISTCTRL 1
#define wxUSE_RADIOBOX 1
#define wxUSE_RADIOBTN 1
#define wxUSE_SCROLLBAR 1
#define wxUSE_SEARCHCTRL 0
#define wxUSE_SLIDER 0
#define wxUSE_SPINBTN 1
#define wxUSE_SPINCTRL 1
#define wxUSE_STATBOX 1
#define wxUSE_STATLINE 1
#define wxUSE_STATTEXT 1
#define wxUSE_STATBMP 1
#define wxUSE_TEXTCTRL 1
#define wxUSE_TOGGLEBTN 0
#define wxUSE_TREECTRL 0

#define wxUSE_STATUSBAR 1

#define wxUSE_NATIVE_STATUSBAR 1

#define wxUSE_TOOLBAR 1
#define wxUSE_TOOLBAR_NATIVE 1

#define wxUSE_NOTEBOOK 1

#define wxUSE_LISTBOOK 0

#define wxUSE_CHOICEBOOK 0

#define wxUSE_TREEBOOK 0

#define wxUSE_TOOLBOOK 0

#define wxUSE_TASKBARICON 0

#define wxUSE_GRID 0

#define wxUSE_MINIFRAME 0

#define wxUSE_COMBOCTRL 1

#define wxUSE_ODCOMBOBOX 0

#define wxUSE_BITMAPCOMBOBOX 0

#define wxUSE_REARRANGECTRL 0


#define wxUSE_ACCEL 1

#define wxUSE_HOTKEY 1

#define wxUSE_CARET 0

#define wxUSE_DISPLAY 0

#define wxUSE_GEOMETRY 0

#define wxUSE_IMAGLIST 1

#define wxUSE_INFOBAR 1

#define wxUSE_MENUS 1

#define wxUSE_NOTIFICATION_MESSAGE 0

#define wxUSE_SASH 0

#define wxUSE_SPLITTER 0

#define wxUSE_TOOLTIPS 1

#define wxUSE_VALIDATORS 1

#ifdef __WXMSW__
#define wxUSE_AUTOID_MANAGEMENT 1
#else
#define wxUSE_AUTOID_MANAGEMENT 1
#endif


#define wxUSE_COMMON_DIALOGS 1

#define wxUSE_BUSYINFO 1

#define wxUSE_CHOICEDLG 1

#define wxUSE_COLOURDLG 0

#define wxUSE_DIRDLG 0


#define wxUSE_FILEDLG 1

#define wxUSE_FINDREPLDLG 0

#define wxUSE_FONTDLG 0

#define wxUSE_MSGDLG 1

#define wxUSE_PROGRESSDLG 1

#define wxUSE_STARTUP_TIPS 0

#define wxUSE_TEXTDLG 1

#define wxUSE_NUMBERDLG 0

#define wxUSE_SPLASH 0

#define wxUSE_WIZARDDLG 0

#define wxUSE_ABOUTDLG 0

#define wxUSE_FILE_HISTORY 0


#define wxUSE_METAFILE 0
#define wxUSE_ENH_METAFILE 0
#define wxUSE_WIN_METAFILES_ALWAYS  0


#define wxUSE_MDI 0

#define wxUSE_DOC_VIEW_ARCHITECTURE 0

#define wxUSE_MDI_ARCHITECTURE 0

#define wxUSE_PRINTING_ARCHITECTURE 0

#define wxUSE_HTML 0

#define wxUSE_GLCANVAS       0

#define wxUSE_RICHTEXT 0


#define wxUSE_CLIPBOARD 0

#define wxUSE_DATAOBJ 0

#define wxUSE_DRAG_AND_DROP 0

#define wxUSE_ACCESSIBILITY 0


#define wxUSE_SNGLINST_CHECKER 1

#define wxUSE_DRAGIMAGE 0

#define wxUSE_IPC 0

#define wxUSE_HELP 0


#define wxUSE_MS_HTML_HELP 0


#define wxUSE_WXHTML_HELP 0

#define wxUSE_CONSTRAINTS 1


#define wxUSE_SPLINES 0


#define wxUSE_MOUSEWHEEL 0


#define wxUSE_UIACTIONSIMULATOR 0


#define wxUSE_POSTSCRIPT 0

#define wxUSE_AFM_FOR_POSTSCRIPT 0

#define wxUSE_SVG 0


#define REMOVE_UNUSED_ARG   1

#define wxUSE_IOSTREAMH     0



#define wxUSE_IMAGE 1

#define wxUSE_LIBPNG        0

#define wxUSE_LIBJPEG       0

#define wxUSE_LIBTIFF       0

#define wxUSE_TGA 0

#define wxUSE_GIF 0

#define wxUSE_PNM 0

#define wxUSE_PCX 0

#define wxUSE_IFF 0

#define wxUSE_XPM 1

#define wxUSE_ICO_CUR 1

#define wxUSE_PALETTE 1


#define wxUSE_ALL_THEMES    0

#define wxUSE_THEME_GTK     0
#define wxUSE_THEME_METAL   0
#define wxUSE_THEME_MONO    0
#define wxUSE_THEME_WIN32   0


/* --- end common options --- */

/*
 * Unix-specific options
 */
#define wxUSE_SELECT_DISPATCHER 0
#define wxUSE_EPOLL_DISPATCHER 0

#define wxUSE_UNICODE_UTF8 0
#define wxUSE_UTF8_LOCALE_ONLY 0

/*
   Use GStreamer for Unix.

   Default is 0 as this requires a lot of dependencies which might not be
   available.

   Recommended setting: 1 (wxMediaCtrl won't work by default without it).
 */
#define wxUSE_GSTREAMER 0

/* --- start MSW options --- */

#ifndef wxUSE_UNICODE_MSLU
    #define wxUSE_UNICODE_MSLU 0
#endif

#define wxUSE_MFC           0

#define wxUSE_OLE 0

#define wxUSE_OLE_AUTOMATION 0

#define wxUSE_ACTIVEX 0

#define wxUSE_DC_CACHEING 1

#define wxUSE_WXDIB 1

#define wxUSE_POSTSCRIPT_ARCHITECTURE_IN_MSW 0

#define wxUSE_REGKEY 1

#define wxUSE_RICHEDIT 0

#define wxUSE_RICHEDIT2 0

#define wxUSE_OWNER_DRAWN 1

#define wxUSE_TASKBARICON_BALLOONS 0

#define wxUSE_UXTHEME 1

#define wxUSE_INKEDIT  0

#define wxUSE_INICONF 0


#define wxUSE_DATEPICKCTRL_GENERIC 0


#define wxUSE_CRASHREPORT 0
/* --- end MSW options --- */

#endif // _WX_SETUP_H_

