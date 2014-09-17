# Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.

# Author: Shawn Webb

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.

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

import os, sys, subprocess
import clamutil

class Clamscan:
    def __init__(self, config, feature, arguments):
        self.config = config.copy()
        self.arguments = arguments[:]
        self.feature = feature.copy()
        self.database = "%CLAMBASE%/unit_tests/input/clamav.hdb"
        if "database" in self.feature:
            self.database = self.feature["database"]
        self.status = "init"
        self._arguments = None
        self._arg_modifications = False

    def IsDetected(self, output, fname, detection):
        lines = output.split('\n')
        for line in lines:
            if line.find(fname) != -1:
                if line.find(detection) != -1:
                    return True
        return False

    def GrepResult(self, argument, value):
        p = subprocess.Popen(["grep", "-rqc", value, clamutil.GetTempDir(self.config)])
        (out, err) = p.communicate()
        if p.returncode == 0:
            return True
        else:
            return False

    def CheckBehavior(self, argument, enabled, setting, output):
        argument["status"] = "CHECK:Initialized:"

        if "behavior" not in argument:
            argument["status"] = "SUCCESS::"
            return True

        if argument["type"] == "flag":
            if enabled == True and "enabled" not in argument["behavior"]:
                argument["status"] = "SUCCESS::"
                return True
            elif enabled == False and "disabled" not in argument["behavior"]:
                argument["status"] = "SUCCESS::"
                return True

            if enabled == True:
                if "detections" in argument["behavior"]["enabled"]:
                    for f in argument["behavior"]["enabled"]["detections"]:
                        if self.IsDetected(output, clamutil.Resolve(self.config, f["file"]), f["detect"]) == False:
                            argument["status"] = "FAIL:DETECT:enabled"
                            return False
                if "grep" in argument["behavior"]["enabled"]:
                    if argument["behavior"]["enabled"]["grep"]["location"] == "temps":
                        if self.GrepResult(argument, argument["behavior"]["enabled"]["grep"]["value"]) != argument["behavior"]["enabled"]["grep"]["result"]:
                            argument["status"] = "FAIL:GREP:enabled"
                            return False
            else:
                if "detections" in argument["behavior"]["disabled"]:
                    for f in argument["behavior"]["disabled"]["detections"]:
                        if self.IsDetected(output, clamutil.Resolve(self.config, f["file"]), f["detect"]) == False:
                            argument["status"] = "FAIL:DETECT:disabled"
                            return False
                if "grep" in argument["behavior"]["disabled"]:
                    if argument["behavior"]["disabled"]["grep"]["location"] == "temps":
                        if self.GrepResult(argument, argument["behavior"]["disabled"]["grep"]["value"]) != argument["behavior"]["disabled"]["grep"]["result"]:
                            argument["status"] = "FAIL:GREP:disabled"
                            return False
        return True

    def Run(self):
        self.status = "RUN"
        for arg in self.arguments:
            moreIterations = True
            arg["setting"] = None
            while moreIterations == True:
                clamutil.CleanTempDir(self.config)
                args = [
                    clamutil.Resolve(self.config, "%CLAMBASE%/clamscan/clamscan"),
                    "-d",
                    clamutil.Resolve(self.config, self.database)
                ]

                if "temps" in arg and "keep" in arg["temps"] and arg["temps"]["keep"] == True:
                    args.append("--leave-temps")
                    args.append("--tempdir=" + clamutil.GetTempDir(self.config))
                elif "behavior" in arg and "enabled" in arg["behavior"] and "grep" in arg["behavior"]["enabled"]:
                    args.append("--leave-temps")
                    args.append("--tempdir=" + clamutil.GetTempDir(self.config))
                elif "behavior" in arg and "disabled" in arg["behavior"] and "grep" in arg["behavior"]["disabled"]:
                    args.append("--leave-temps")
                    args.append("--tempdir=" + clamutil.GetTempDir(self.config))

                if arg["type"] == "flag":
                    if arg["setting"] == None:
                        args.append(clamutil.Resolve(self.config, arg["argument"]))
                        arg["setting"] = True
                    else:
                        moreIterations = False
                        arg["setting"] = False

                if "extra_args" in arg:
                    for extra in arg["extra_args"]:
                        args.append(clamutil.Resolve(self.config, extra))

                for f in arg["files"]:
                    args.append(clamutil.Resolve(self.config, f))

                p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                (out, err) = p.communicate()
                setting=None
                if arg["type"] != "flag":
                    setting = arg["setting"]

                if self.CheckBehavior(arg, arg["setting"], setting, out) == False:
                    print "Behavior check failed: " + arg["status"]
                    self.status = "FAIL"
                    return False

        return True
