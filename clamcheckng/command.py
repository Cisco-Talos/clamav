# Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
#
# Author: Shawn Webb
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.
#
# In addition, as a special exception, the copyright holders give
# permission to link the code of portions of this program with the
# OpenSSL library under certain conditions as described in each
# individual source file, and distribute linked combinations
# including the two.
# 
# You must obey the GNU General Public License in all respects
# for all of the code used other than OpenSSL.  If you modify
# file(s) with this exception, you may extend this exception to your
# version of the file(s), but you are not obligated to do so.  If you
# do not wish to do so, delete this exception statement from your
# version.  If you delete this exception statement from all source
# files in the program, then also delete it here.

import os, subprocess
import tempfile

def LogVerbose(config, out, message=""):
    if "logging" not in config:
        return
    if "verbose" not in config["logging"]:
        return

    if config["logging"]["verbose"] == 1:
        # Log to file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(out)
            print "[*] " + message + " LogVerbose(1): " + f.name
    elif config["logging"]["verbose"] == 2:
        # Write to stdout
        print out
    elif config["logging"]["verbose"] == 3:
        # Log to file and write to stdout
        print out
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(out)
            print "[*] " + message + " LogVerbose(3): " + f.name
        print out

def RunCommand(config, args, message=""):
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (out, err) = p.communicate()
    LogVerbose(config, out, message)
    return p.returncode
