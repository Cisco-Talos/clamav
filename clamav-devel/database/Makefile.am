#
#  Copyright (C) 2002 Tomasz Kojm <zolw@konarski.edu.pl>
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

EXTRA_DIST = viruses.db viruses.db2 mirrors.txt
DBINST = @DBDIR@
CLAMAVUSER = @CLAMAVUSER@
CLAMAVGROUP = @CLAMAVGROUP@
 
install:
	$(mkinstalldirs) $(DESTDIR)$(DBINST)
#	@$(INSTALL_DATA) viruses.db $(DESTDIR)$(DBINST)
#	@$(INSTALL_DATA) viruses.db2 $(DESTDIR)$(DBINST)
	@$(INSTALL_DATA) mirrors.txt $(DESTDIR)$(DBINST)
	@if test -n "${CLAMAVUSER}" && test -n "${CLAMAVGROUP}"; then \
	    chmod 775 $(DESTDIR)$(DBINST); \
	    chown ${CLAMAVUSER} $(DESTDIR)$(DBINST); \
	    chgrp ${CLAMAVGROUP} $(DESTDIR)$(DBINST); \
	    chmod 664 $(DESTDIR)$(DBINST)/viruses.db; \
	    chown ${CLAMAVUSER} $(DESTDIR)$(DBINST)/viruses.db; \
	    chgrp ${CLAMAVGROUP} $(DESTDIR)$(DBINST)/viruses.db; \
	    chmod 664 $(DESTDIR)$(DBINST)/viruses.db2; \
	    chown ${CLAMAVUSER} $(DESTDIR)$(DBINST)/viruses.db2; \
	    chgrp ${CLAMAVGROUP} $(DESTDIR)$(DBINST)/viruses.db2; \
	    chmod 664 $(DESTDIR)$(DBINST)/mirrors.txt; \
	    chown ${CLAMAVUSER} $(DESTDIR)$(DBINST)/mirrors.txt; \
	    chgrp ${CLAMAVGROUP} $(DESTDIR)$(DBINST)/mirrors.txt; \
	fi
