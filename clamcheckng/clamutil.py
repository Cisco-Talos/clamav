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

def Resolve(config, rawpath):
    return rawpath.replace("%CLAMBASE%", GetCodePath())
