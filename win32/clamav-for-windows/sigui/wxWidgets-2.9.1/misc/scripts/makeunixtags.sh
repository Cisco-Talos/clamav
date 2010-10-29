##############################################################################
# Name:       misc/scripts/makeunixtags.sh
# Purpose:    create tags file for a wxWidgets port under a Unix system
# Created:    2007-05-05
# RCS-ID:     $Id$
# Copyright:  (c) 2007 Vadim Zeitlin <vadim@wxwindows.org>
# Licence:    wxWindows licence
##############################################################################

# this function should be called with a single parameter containing addition
# port-specific directories to scan
create_tags()
{
ctags --totals --c++-kinds=+px --language-force=c++ \
	--exclude=include/wx/vms_x_fix.h \
	-I @misc/scripts/ctags.ignore \
	include/wx/*.h \
	include/wx/private/*.h \
	include/wx/aui/*.h \
	include/wx/generic/*.h \
	include/wx/generic/private/*.h \
	include/wx/$1/*.h \
	include/wx/$1/private/*.h \
	include/wx/html/*.h \
	include/wx/propgrid/*.h \
	include/wx/protocol/*.h \
	include/wx/richtext/*.h \
	include/wx/xml/*.h \
	include/wx/xrc/*.h \
	include/wx/unix/*.h \
	include/wx/unix/private/*.h \
	src/aui/*.cpp \
	src/common/*.cpp \
	src/generic/*.cpp \
	src/$1/*.cpp \
	src/html/*.cpp \
	src/propgrid/*.cpp \
	src/richtext/*.cpp \
	src/unix/*.cpp \
	src/xml/*.cpp \
	src/xrc/*.cpp
}
