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
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

EXTRA_DIST = clamd.conf freshclam.conf
CFGINST = @CFGDIR@
 
install:
	$(mkinstalldirs) $(DESTDIR)$(CFGINST)
	@test -f $(DESTDIR)$(CFGINST)/clamd.conf || \
	$(INSTALL_DATA) $(srcdir)/clamd.conf $(DESTDIR)$(CFGINST)
	@test -f $(DESTDIR)$(CFGINST)/freshclam.conf || \
	$(INSTALL_DATA) $(srcdir)/freshclam.conf $(DESTDIR)$(CFGINST)
