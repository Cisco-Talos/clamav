#!/usr/bin/env python2.7
#
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
import shlex, json
import tempfile
import clamscan, clamutil, command

apps = ["clamscan", "clamd"]
codepath = ""

def readConfig(path):
    f = open(path, 'r')
    config = json.load(f)
    f.close()
    for feature in config["features"]:
        config["features"][feature]["status"] = False
    return config

def main():
    config = readConfig(clamutil.GetCodePath() + "/clamcheckng/config.json")

    for featurename in config["features"]:
        print "[*] Feature: " + featurename

        objdir = clamutil.GetObjectDir(config, featurename)
        os.chdir(objdir)
        feature = config["features"][featurename]
        if "forceclean" in feature and feature["forceclean"] == True:
            if os.access(objdir + "/config.log", os.F_OK) == True:
                clamutil.CleanMe(config)

        #########################
        #### Configure stage ####
        #########################

        if os.access(objdir + "/config.log", os.F_OK) == False:
            args = []
            args.append(clamutil.Resolve(config, "%CLAMBASE%/configure"))
            if "configure" in config:
                for a in config["configure"]:
                    args.append(a)
            if "configure" in feature:
                for a in feature["configure"]:
                    args.append(a)
            if command.RunCommand(config, args) != 0:
                print "   [-] Configure stage failed."
                return

        ###########################
        #### Compilation Stage ####
        ###########################

        args = []
        if "compile" in config:
            if "make" in config["compile"]:
                args.append(config["compile"]["make"])
            else:
                args.append("make")
            if "jobs" in config["compile"]:
                args.append("-j" + str(config["compile"]["jobs"]))

        if command.RunCommand(config, args) != 0:
            print "    [-] Compilation stage failed."
            return

        #############################
        #### Library Check Stage ####
        #############################

        if "libs" in feature:
            env = os.environ
            env["LD_LIBRARY_PATH"] = objdir + "/libclamav/.libs"
            p = subprocess.Popen(["ldd", objdir + "/libclamav/.libs/libclamav.so"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
            (out, err) = p.communicate()
            command.LogVerbose(config, out)
            for lib in feature["libs"]:
                if lib not in out:
                    print "    [-] Could not find library " + lib + "." + filename
                    return

        ########################
        #### Clamscan Stage ####
        ########################
        if "clamscan" in feature:
            runner = clamscan.Clamscan(config, featurename, feature, feature["clamscan"]["arguments"])
            if runner.Run() == False:
                feature["status"] = False
            else:
                feature["status"] = True

    print "SUMMARY:"
    for feature in config["features"]:
        status = "[*] " + feature + ": "
        if config["features"][feature]["status"] == True:
            status += "SUCCESS"
        else:
            status += "FAIL"
        print status

if __name__ == "__main__":
    os.chdir(clamutil.GetCodePath())
    main()
