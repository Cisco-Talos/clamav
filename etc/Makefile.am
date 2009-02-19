#
#  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.

EXTRA_DIST = clamd.conf freshclam.conf clamav-milter.conf
CFGINST = @CFGDIR@
 
install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(CFGINST)
	@test -f $(DESTDIR)$(CFGINST)/clamd.conf || \
	$(INSTALL_DATA) $(srcdir)/clamd.conf $(DESTDIR)$(CFGINST)
	@test -f $(DESTDIR)$(CFGINST)/freshclam.conf || \
	$(INSTALL_DATA) $(srcdir)/freshclam.conf $(DESTDIR)$(CFGINST)
if BUILD_CLAMD
if HAVE_MILTER
	@test -f $(DESTDIR)$(CFGINST)/clamav-milter.conf || \
	$(INSTALL_DATA) $(srcdir)/clamav-milter.conf $(DESTDIR)$(CFGINST)
endif
endif
