#
#  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
#  Fixes by Arkadiusz Miskiewicz <misiek@pld.org.pl>
#	    Masaki Ogawa <proc@mac.com>
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

EXTRA_DIST = main.cvd daily.cvd
DBINST = @DBDIR@
CLAMAVUSER = @CLAMAVUSER@
CLAMAVGROUP = @CLAMAVGROUP@
 
install:
	$(mkinstalldirs) $(DESTDIR)$(DBINST)
	@test -f $(DESTDIR)$(DBINST)/main.cvd || $(INSTALL_DATA) $(srcdir)/main.cvd $(DESTDIR)$(DBINST)
	@test -f $(DESTDIR)$(DBINST)/daily.cvd || $(INSTALL_DATA) $(srcdir)/daily.cvd $(DESTDIR)$(DBINST)
	@test -f $(DESTDIR)$(DBINST)/mirrors.txt && rm -f $(DESTDIR)$(DBINST)/mirrors.txt || true
	@test -f $(DESTDIR)$(DBINST)/viruses.db && rm -f $(DESTDIR)$(DBINST)/viruses.db || true
	@test -f $(DESTDIR)$(DBINST)/viruses.db2 && rm -f $(DESTDIR)$(DBINST)/viruses.db2 || true
	@if test `id|sed -e 's/^.[^(]*(\([^)]*\)).*/\1/'` = "root" && test -n "${CLAMAVUSER}" && test -n "${CLAMAVGROUP}"; then \
	    chmod 775 $(DESTDIR)$(DBINST); \
	    chown ${CLAMAVUSER} $(DESTDIR)$(DBINST); \
	    chgrp ${CLAMAVGROUP} $(DESTDIR)$(DBINST); \
	    chmod 664 $(DESTDIR)$(DBINST)/main.cvd; \
	    chown ${CLAMAVUSER} $(DESTDIR)$(DBINST)/main.cvd; \
	    chgrp ${CLAMAVGROUP} $(DESTDIR)$(DBINST)/main.cvd; \
	    chmod 664 $(DESTDIR)$(DBINST)/daily.cvd; \
	    chown ${CLAMAVUSER} $(DESTDIR)$(DBINST)/daily.cvd; \
	    chgrp ${CLAMAVGROUP} $(DESTDIR)$(DBINST)/daily.cvd; \
	fi
