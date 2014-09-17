#!/usr/bin/env python2.7

import os, subprocess
import shlex, json
import tempfile
import clamscan, clamutil

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

    ###########################
    #### Clean Environment ####
    ###########################
    if os.access("config.log", os.F_OK) == True:
        print "[*] Existing build detected. Cleaning."
        clamutil.CleanMe(config)

    for feature in config["features"]:
        print "[*] Feature: " + feature
        clamutil.CleanMe(config)
        feature = config["features"][feature]

        #########################
        #### Configure stage ####
        #########################

        args = []
        args.append("./configure")
        if "configure" in config:
            for a in config["configure"]:
                args.append(a)
        if "configure" in feature:
            for a in feature["configure"]:
                args.append(a)
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (out, err) = p.communicate()
        if p.returncode != 0:
            filename=""
            if config["debug"] == True:
                f = tempfile.NamedTemporaryFile(delete=False)
                f.write(out)
                filename = " Log written to " + f.name
                f.close()
            print "   [-] Configure stage failed." + filename
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

        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (out, err) = p.communicate()
        if p.returncode != 0:
            filename=""
            if config["debug"] == True:
                f = tempfile.NamedTemporaryFile(delete=False)
                f.write(out)
                filename = " Log written to " + f.name
                f.close()
            print "    [-] Compilation stage failed." + filename
            return

        #############################
        #### Library Check Stage ####
        #############################

        if "libs" in feature:
            env = os.environ
            env["LD_LIBRARY_PATH"] = clamutil.GetCodePath() + "/libclamav/.libs"
            p = subprocess.Popen(["ldd", clamutil.GetCodePath() + "/libclamav/.libs/libclamav.so"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
            (out, err) = p.communicate()
            for lib in feature["libs"]:
                if out.find(lib) == -1:
                    filename=""
                    if config["debug"] == True:
                        f = tempfile.NamedTemporaryFile(delete=False)
                        f.write(out)
                        filename = " Log written to " + f.name
                        f.close()
                    print "    [-] Could not find library " + lib + "." + filename
                    return

        ########################
        #### Clamscan Stage ####
        ########################
        if "clamscan" in feature:
            runner = clamscan.Clamscan(config, feature, feature["clamscan"]["arguments"])
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
