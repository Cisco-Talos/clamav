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

import os, sys
import shutil
import subprocess

codepath=""

def GetTempDir(config):
    tmp = "/tmp/clamcheckng"
    if "temp" in config:
        tmp = config["temp"]

    if os.path.exists(tmp) == False:
        os.mkdir(tmp)
    elif os.path.isdir(tmp) == False:
        raise Exception("Temporary directory is not a directory")

    return tmp

def GetCodePath():
    global codepath
    if len(codepath) > 0:
        return codepath

    codepath = os.path.realpath(os.path.dirname(__file__) + "/..")
    return codepath

def CleanMe(config):
    if os.access("config.log", os.F_OK) == True:
        make="make"
        if "compile" in config:
            if "make" in config["compile"]:
                make=config["compile"]["make"]

        p = subprocess.Popen([make, "clean", "distclean"], stdout=subprocess.PIPE)
        p.communicate()

def CleanTempDir(config):
    tempdir = GetTempDir(config)
    if len(os.listdir(tempdir)) > 0:
        shutil.rmtree(tempdir, True)

def Resolve(config, rawpath, feature=""):
    path = rawpath.replace("%CLAMBASE%", GetCodePath())
    if feature != "":
        path = path.replace("%OBJDIR%", GetObjectDir(config, feature))
    return path

def ValidateArgument(argument):
    if "argument" not in argument:
        return False

    validType = False
    if argument["type"] == "flag":
        validType = True

    if validType == False:
        return False

    if "behavior" not in argument:
        return False

    if "enabled" in argument["behavior"]:
        if argument["type"] != "flag":
            return False

        if "detections" in argument["behavior"]["enabled"]:
            for d in argument["behavior"]["enabled"]["detections"]:
                if "file" not in d:
                    return False
                if "detect" not in d:
                    return False
        if "grep" in argument["behavior"]["enabled"]:
            if "result" not in argument["behavior"]["enabled"] or type(argument["behavior"]["enabled"]["grep"]["result"]) is not bool:
                return False
            if "location" not in argument["behavior"]["enabled"]["grep"]:
                return False
            if "temps" not in argument["behavior"]["enabled"]["grep"]["location"]:
                return False

    if "disabled" in argument["behavior"]:
        if argument["type"] != "flag":
            return False

        if "detections" in argument["behavior"]["disabled"]:
            for d in argument["behavior"]["disabled"]["detections"]:
                if "file" not in d:
                    return False
                if "detect" not in d:
                    return False
        if "grep" in argument["behavior"]["disabled"]:
            if "result" not in argument["behavior"]["disabled"] or type(argument["behavior"]["disabled"]["grep"]["result"]) is not bool:
                return False
            if "location" not in argument["behavior"]["disabled"]["grep"]:
                return False
            if "temps" not in argument["behavior"]["disabled"]["grep"]["location"]:
                return False

    return True

def GetObjectDir(config, feature):
    objdir = "%CLAMBASE%/obj/" + feature
    if "objdir" in config:
        objdir = config["objdir"]
    objdir = Resolve(config, objdir + "/" + feature)
    if os.path.isdir(objdir) == False:
        os.makedirs(objdir)
    return objdir
