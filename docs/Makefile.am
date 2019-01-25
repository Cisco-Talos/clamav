#
#  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
#  Copyright (C) 2007-2013 Sourcefire, Inc.
#  Copyright (C) 2002-2007 Tomasz Kojm <tkojm@clamav.net>
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

EXTRA_DIST = html UserManual UserManual.md $(top_srcdir)/docs/man/*.in  
man_MANS = man/clamscan.1 man/freshclam.1 man/sigtool.1 man/clamd.8 man/clamd.conf.5 man/clamdscan.1 man/clamav-milter.8 man/clamav-milter.conf.5 man/freshclam.conf.5 man/clamconf.1 man/clamdtop.1 man/clambc.1

if ENABLE_CLAMSUBMIT
man_MANS += man/clamsubmit.1
endif
