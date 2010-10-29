#*****************************************************************************
#                                                                            *
# Make file for VMS                                                          *
# Author : J.Jansen (joukj@hrem.nano.tudelft.nl)                             *
# Date : 2 December 2008                                                     *
#                                                                            *
#*****************************************************************************
.first
	define wx [--.include.wx]

.ifdef __WXMOTIF__
CXX_DEFINE = /define=(__WXMOTIF__=1)/name=(as_is,short)\
	   /assume=(nostdnew,noglobal_array_new)
CC_DEFINE = /define=(__WXMOTIF__=1)/name=(as_is,short)
.else
CXX_DEFINE =
.endif

.suffixes : .cpp

.cpp.obj :
	cxx $(CXXFLAGS)$(CXX_DEFINE) $(MMS$TARGET_NAME).cpp
.c.obj :
	cc $(CFLAGS)$(CC_DEFINE) $(MMS$TARGET_NAME).c

OBJECTS = \
		xmcombo.obj,\
		accel.obj,\
		app.obj,\
		bmpbuttn.obj,\
		bmpmotif.obj,\
		button.obj,\
		checkbox.obj,\
		checklst.obj,\
		choice.obj,\
		clipbrd.obj,\
		colour.obj,\
		combobox.obj,\
		control.obj,\
		cursor.obj,\
		data.obj,\
		dataobj.obj,\
		dc.obj,\
		dcclient.obj,\
		dcmemory.obj,\
		dcscreen.obj,\
		dialog.obj,\
		evtloop.obj,\
		filedlg.obj,\
		font.obj,\
		frame.obj,\
		gauge.obj,\
		sockmot.obj,\
		icon.obj,\
		listbox.obj,\
		main.obj,\
		menu.obj,\
		menuitem.obj,\
		minifram.obj,\
		msgdlg.obj,\
		radiobox.obj,\
		radiobut.obj,\
		scrolbar.obj,\
		settings.obj,\
		slider.obj,\
		spinbutt.obj,\
		statbmp.obj,\
		statbox.obj,\
		stattext.obj,\
		textctrl.obj,\
		textentry.obj,\
		toplevel.obj,\
		timer.obj,\
		toolbar.obj,\
		utils.obj,\
		window.obj

SOURCES = \
		accel.cpp,\
		app.cpp,\
		bmpbuttn.cpp,\
		bmpmotif.cpp,\
		button.cpp,\
		checkbox.cpp,\
		checklst.cpp,\
		choice.cpp,\
		clipbrd.cpp,\
		colour.cpp,\
		combobox.cpp,\
		control.cpp,\
		cursor.cpp,\
		data.cpp,\
		dataobj.cpp,\
		dc.cpp,\
		dcclient.cpp,\
		dcmemory.cpp,\
		dcscreen.cpp,\
		dialog.cpp,\
		evtloop.cpp,\
		filedlg.cpp,\
		font.cpp,\
		frame.cpp,\
		gauge.cpp,\
		sockmot.cpp,\
		icon.cpp,\
		listbox.cpp,\
		main.cpp,\
		menu.cpp,\
		menuitem.cpp,\
		minifram.cpp,\
		msgdlg.cpp,\
		radiobox.cpp,\
		radiobut.cpp,\
		scrolbar.cpp,\
		settings.cpp,\
		slider.cpp,\
		spinbutt.cpp,\
		statbmp.cpp,\
		statbox.cpp,\
		stattext.cpp,\
		textctrl.cpp,\
		textentry.cpp,\
		toplevel.cpp,\
		timer.cpp,\
		toolbar.cpp,\
		utils.cpp,\
		window.cpp,\
		[.xmcombo]xmcombo.c\

all : $(SOURCES)
	$(MMS)$(MMSQUALIFIERS) $(OBJECTS)
.ifdef __WXMOTIF__
	library [--.lib]libwx_motif.olb $(OBJECTS)
.endif

$(OBJECTS) : [--.include.wx]setup.h

xmcombo.obj : [.xmcombo]xmcombo.c
	cc $(CFLAGS)$(CC_DEFINE) [.xmcombo]xmcombo.c

accel.obj : accel.cpp
app.obj : app.cpp
bmpbuttn.obj : bmpbuttn.cpp
bmpmotif.obj : bmpmotif.cpp
button.obj : button.cpp
checkbox.obj : checkbox.cpp
checklst.obj : checklst.cpp
choice.obj : choice.cpp
clipbrd.obj : clipbrd.cpp
colour.obj : colour.cpp
combobox.obj : combobox.cpp
control.obj : control.cpp
cursor.obj : cursor.cpp
data.obj : data.cpp
dataobj.obj : dataobj.cpp
dc.obj : dc.cpp
dcclient.obj : dcclient.cpp
dcmemory.obj : dcmemory.cpp
dcscreen.obj : dcscreen.cpp
dialog.obj : dialog.cpp
evtloop.obj : evtloop.cpp
filedlg.obj : filedlg.cpp
font.obj : font.cpp
frame.obj : frame.cpp
gauge.obj : gauge.cpp
sockmot.obj : sockmot.cpp
icon.obj : icon.cpp
listbox.obj : listbox.cpp
main.obj : main.cpp
menu.obj : menu.cpp
menuitem.obj : menuitem.cpp
minifram.obj : minifram.cpp
msgdlg.obj : msgdlg.cpp
radiobox.obj : radiobox.cpp
radiobut.obj : radiobut.cpp
scrolbar.obj : scrolbar.cpp
settings.obj : settings.cpp
slider.obj : slider.cpp
spinbutt.obj : spinbutt.cpp
statbmp.obj : statbmp.cpp
statbox.obj : statbox.cpp
stattext.obj : stattext.cpp
textctrl.obj : textctrl.cpp
textentry.obj : textentry.cpp
toplevel.obj : toplevel.cpp
timer.obj : timer.cpp
toolbar.obj : toolbar.cpp
utils.obj : utils.cpp
window.obj : window.cpp
