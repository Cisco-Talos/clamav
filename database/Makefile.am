#
#  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
#  Copyright (C) 2007-2013 Sourcefire, Inc.
#  Copyright (C) 2002-2007 Tomasz Kojm <tkojm@clamav.net>
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
 
install-data-local:
	@test -s $(srcdir)/main.cvd -a -s $(srcdir)/daily.cvd || exit 0;\
	$(mkinstalldirs) $(DESTDIR)$(DBINST);\
	test -f $(DESTDIR)$(DBINST)/main.cvd || test -f $(DESTDIR)$(DBINST)/main.cld || $(INSTALL_DATA) $(srcdir)/main.cvd $(DESTDIR)$(DBINST);\
	test -f $(DESTDIR)$(DBINST)/daily.cvd || test -f $(DESTDIR)$(DBINST)/daily.cld || $(INSTALL_DATA) $(srcdir)/daily.cvd $(DESTDIR)$(DBINST);\
	if test `id|sed -e 's/^.[^(]*(\([^)]*\)).*/\1/'` = "root" && test -n "${CLAMAVUSER}" && test -n "${CLAMAVGROUP}"; then \
	    chmod 775 $(DESTDIR)$(DBINST); \
	    chown ${CLAMAVUSER} $(DESTDIR)$(DBINST); \
	    chgrp ${CLAMAVGROUP} $(DESTDIR)$(DBINST); \
	    if test -f $(DESTDIR)$(DBINST)/main.cvd; then chmod 664 $(DESTDIR)$(DBINST)/main.cvd; fi;\
	    if test -f $(DESTDIR)$(DBINST)/main.cvd; then chown ${CLAMAVUSER} $(DESTDIR)$(DBINST)/main.cvd; fi;\
	    if test -f $(DESTDIR)$(DBINST)/main.cvd; then chgrp ${CLAMAVGROUP} $(DESTDIR)$(DBINST)/main.cvd; fi;\
	    if test -f $(DESTDIR)$(DBINST)/daily.cvd; then chmod 664 $(DESTDIR)$(DBINST)/daily.cvd; fi;\
	    if test -f $(DESTDIR)$(DBINST)/daily.cvd; then chown ${CLAMAVUSER} $(DESTDIR)$(DBINST)/daily.cvd; fi;\
	    if test -f $(DESTDIR)$(DBINST)/daily.cvd; then chgrp ${CLAMAVGROUP} $(DESTDIR)$(DBINST)/daily.cvd; fi;\
	fi

