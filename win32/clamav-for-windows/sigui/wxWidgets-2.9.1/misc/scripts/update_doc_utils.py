##############################################################################
# Name:       misc/scripts/update_doc_utils.py
# Purpose:    base utilities for others update_doc_*.py scripts
# Created:    2007-08-1
# RCS-ID:     $Id: makeunixtags.sh 46320 2007-06-04 11:02:29Z VZ $
# Copyright:  (c) 2007 Francesco Montorsi
# Licence:    wxWindows licence
##############################################################################

import sys, os, glob, distutils.file_util

DOCS_PATH="../../docs/latex/wx"

# Calls the given callback with the name of a documented class, its .tex related file,
# the content of that .tex file and the number of the line of the relative \class tag,
# for all documented class in DOCS_PATH. If the callback returns false the processing is stopped.
# Returns the number of .tex files processed.
def scanTexFiles(callback):
    count = 0
    for f in glob.glob(DOCS_PATH + '/*.tex'):
        file = open(f, "r")
        if not file:
            print "could not open %s" % f
            continue
        print "opened file %s" % f
        count = count + 1

        # search \class tags
        content = file.readlines()
        classdecl = 0
        for i in range(len(content)):
            line = content[i]
            if "\class{" in line:
                classdecl = classdecl + 1

                # polish the class name
                classname = line
                classname = classname[classname.find("\class{"):]
                classname = classname[classname.find("{")+1:classname.find("}")]
                print " the class declared is named '%s'" % classname

                # process this \class
                if not callback(classname, f, content, i):
                    return count

        print " file %s contains %d class declarations" % (f, classdecl)

    return count

