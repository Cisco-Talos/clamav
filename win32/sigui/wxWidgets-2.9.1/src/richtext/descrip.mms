#*****************************************************************************
#                                                                            *
# Make file for VMS                                                          *
# Author : J.Jansen (joukj@hrem.nano.tudelft.nl)                             *
# Date : 3 October 2009                                                      *
#                                                                            *
#*****************************************************************************
.first
	define wx [--.include.wx]

.ifdef __WXMOTIF__
CXX_DEFINE = /define=(__WXMOTIF__=1)/name=(as_is,short)\
	   /assume=(nostdnew,noglobal_array_new)
CC_DEFINE = /define=(__WXMOTIF__=1)/name=(as_is,short)
.else
.ifdef __WXGTK__
CXX_DEFINE = /define=(__WXGTK__=1)/float=ieee/name=(as_is,short)/ieee=denorm\
	   /assume=(nostdnew,noglobal_array_new)
CC_DEFINE = /define=(__WXGTK__=1)/float=ieee/name=(as_is,short)/ieee=denorm
.else
.ifdef __WXGTK2__
CXX_DEFINE = /define=(__WXGTK__=1,VMS_GTK2=1)/float=ieee/name=(as_is,short)/ieee=denorm\
	   /assume=(nostdnew,noglobal_array_new)
CC_DEFINE = /define=(__WXGTK__=1,VMS_GTK2=1)/float=ieee/name=(as_is,short)/ieee=denorm
.else
.ifdef __WXX11__
CXX_DEFINE = /define=(__WXX11__=1,__WXUNIVERSAL__==1)/float=ieee\
	/name=(as_is,short)/assume=(nostdnew,noglobal_array_new)
CC_DEFINE = /define=(__WXX11__=1,__WXUNIVERSAL__==1)/float=ieee\
	/name=(as_is,short)
.else
CXX_DEFINE =
CC_DEFINE =
.endif
.endif
.endif
.endif

.suffixes : .cpp

.cpp.obj :
	cxx $(CXXFLAGS)$(CXX_DEFINE) $(MMS$TARGET_NAME).cpp
.c.obj :
	cc $(CFLAGS)$(CC_DEFINE) $(MMS$TARGET_NAME).c

OBJECTS=richtextbuffer.obj,richtextctrl.obj,\
	richtextformatdlg.obj,richtexthtml.obj,\
	richtextindentspage.obj,richtextprint.obj,\
	richtextstyledlg.obj,richtextstylepage.obj,richtextstyles.obj,\
	richtextsymboldlg.obj,richtexttabspage.obj,richtextxml.obj

SOURCES=richtextbuffer.cpp,richtextbulletspage.cpp,richtextctrl.cpp,\
	richtextfontpage.cpp,richtextformatdlg.cpp,richtexthtml.cpp,\
	richtextindentspage.cpp,richtextliststylepage.cpp,richtextprint.cpp,\
	richtextstyledlg.cpp,richtextstylepage.cpp,richtextstyles.cpp,\
	richtextsymboldlg.cpp,richtexttabspage.cpp,richtextxml.cpp


all : $(SOURCES)
	$(MMS)$(MMSQUALIFIERS) $(OBJECTS)
.ifdef __WXMOTIF__
	library [--.lib]libwx_motif.olb $(OBJECTS)
.else
.ifdef __WXGTK__
	library [--.lib]libwx_gtk.olb $(OBJECTS)
.else
.ifdef __WXGTK2__
	library [--.lib]libwx_gtk2.olb $(OBJECTS)
.else
.ifdef __WXX11__
	library [--.lib]libwx_x11_univ.olb $(OBJECTS)
.endif
.endif
.endif
.endif

richtextbuffer.obj : richtextbuffer.cpp
richtextctrl.obj : richtextctrl.cpp
richtextformatdlg.obj : richtextformatdlg.cpp
richtexthtml.obj : richtexthtml.cpp
richtextindentspage.obj : richtextindentspage.cpp
richtextprint.obj : richtextprint.cpp
richtextstyledlg.obj : richtextstyledlg.cpp
richtextstylepage.obj : richtextstylepage.cpp
richtextstyles.obj : richtextstyles.cpp
richtextsymboldlg.obj : richtextsymboldlg.cpp
richtexttabspage.obj : richtexttabspage.cpp
richtextxml.obj : richtextxml.cpp
