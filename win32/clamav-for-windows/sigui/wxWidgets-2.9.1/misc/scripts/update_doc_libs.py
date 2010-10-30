##############################################################################
# Name:       misc/scripts/update_doc_libs.py
# Purpose:    Automatically insert \Library{} headers in the doc files
# Created:    2007-07-28
# RCS-ID:     $Id: makeunixtags.sh 46320 2007-06-04 11:02:29Z VZ $
# Copyright:  (c) 2007 Francesco Montorsi
# Licence:    wxWindows licence
##############################################################################

from update_doc_utils import scanTexFiles

INCLUDE_PATH="../../include"

def myCallback(classname, texFileName, content, i):
    tofix.add(texFileName)     # consider this .tex broken

    # now search the include file for this class
    include = ""
    for j in range(i,len(content)):
        line = content[j]
        if "wx/" in line and ".h" in line:
            include = line[line.find("wx/"):line.find(".h")+2]
            break
    if include == "":
        print " no include file declared for class %s" % classname
        return True # go on with next \class

    include = include.replace("\\_", "_")
    print " the include file for %s is %s" % (classname, include)

    # does this .tex already contains the \wxheading{Library} section nearby the include file?
    for k in range(j,min(len(content), j+3)):
        line = content[k]
        if "\wxheading{Library}" in line:
            print " this \class section already has its \wxheading{Library} section... skipping"
            tofix.remove(texFileName) # was a valid .tex (at least for current class)
            return True   # go on with next \class

    # now try to understand which lib contains this class
    include = INCLUDE_PATH + "/" + include
    header = open(include, "r")
    if not header:
        print " could not open %s" % include
        return True # go on with next \class

    decl = ""
    content2 = header.readlines()

    # if they exist append port-specific headers contents
    for c in ["wx/gtk/", "wx/msw/", "wx/mac/", "wx/generic/"]:
        try:
            temp = include.replace("wx/", c)
            print " trying to open %s..." % temp
            header = open(temp, "r")
            headercontents = header.readlines()
            content2 = content2 + headercontents
            print " added %d lines from %s" % (len(headercontents), temp)
        except:
            pass

    # now search for the export-declaration associated with this class
    for line in content2:
        if "class " in line and classname in line:
            if line.find("class") < line.find(classname):  # could be a comment
                if "_" in line:
                    decl = line[line.find("_")+1:]
                    decl = decl[:decl.find(" ")]
                    decl = decl.replace("FWD_", "")
                    decl = decl[0:1].upper() + decl[1:].lower()
                    break
                elif " WXDLLEXPORT " in line:
                    decl = "Core"
                    break

    if decl == "":
        print " no declaration associated with %s" % classname
        return True # go on with next \class

    print " the declaration associated with %s is %s" % (classname, decl)
    tofix.remove(texFileName) # was a valid .tex (at least for current class)

    # now modify the .tex file
    content.insert(j+2, "\wxheading{Library}\n\n\helpref{wx%s}{librarieslist}\n\n" % decl)

    # write it
    file = open(texFileName, "w")
    file.write(''.join(content))
    file.flush()

    print " updated %s" % texFileName
    fixed = fixed+1

    return True

fixed = 0
tofix = set()
count = scanTexFiles(myCallback)

print "\nProcessed %d files, automatically fixed %d files." % (count, fixed)
print "There are %d files to fix manually:\n%s" % (len(tofix), '\n'.join(tofix))
