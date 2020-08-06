#
#  Copyright (C) 2013-2020 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

EXTRA_DIST = clamd.conf.sample.in.in \
             freshclam.conf.sample.in.in \
             clamav-milter.conf.sample.in.in
CFGINST = @CFGDIR@

sysconf_DATA = clamd.conf.sample freshclam.conf.sample

# Custom variable to simplify the "edit" rule below.
sysconf_DATA_intermediate = clamd.conf.sample.in freshclam.conf.sample.in

if HAVE_MILTER
sysconf_DATA += clamav-milter.conf.sample
sysconf_DATA_intermediate += clamav-milter.conf.sample.in
endif

# Otherwise these don't get cleaned up by "make distclean",
# even though they are auto-generated.
DISTCLEANFILES = $(sysconf_DATA) $(sysconf_DATA_intermediate)

# This rule includes EVERY source/intermediate file as a dependency of
# EVERY output file, which is clearly wrong, but it may be the best we
# can do without duplication. At least it's the right kind of wrong,
# and rebuilds too often rather than not often enough.
$(sysconf_DATA): $(sysconf_DATA_intermediate) $(EXTRA_DIST) Makefile
	rm -f $@ $@.tmp
	$(editgnudirs) $@.in > $@.tmp
	mv $@.tmp $@
>>>>>>> ea2f2442b... etc: convert conf files to templates and make @VARIABLE@ substitutions.
