##############################################################################
# Name:       misc/scripts/update_doc_baseclasses.py
# Purpose:    Warns about missing classes in the "Derived from" 
#             sections in the doc files
# Created:    2007-07-28
# RCS-ID:     $Id: makeunixtags.sh 46320 2007-06-04 11:02:29Z VZ $
# Copyright:  (c) 2007 Francesco Montorsi
# Licence:    wxWindows licence
##############################################################################

from update_doc_utils import scanTexFiles

# classes whose docs cannot be fixed automatically
# because of:
#   1) multiple inheritance
#   2) other strange things specific of these classes
EXCEPTIONS=['wxNotebook','wxChoicebook','wxListbook','wxToolbook','wxTreebook','wxURLDataObject','wxHScrolledWindow','wxVScrolledWindow','wxVarHVScrollHelper','wxHVScrolledWindow','wxFileStream']

def myCallback(classname, texFileName, content, i):
    # now search the base classes for this class
    baseclasses = []
    for j in range(i,len(content)):
        line = content[j]
        if line.startswith("\wxheading{Derived from}"):
            # take all lines contained between this \wxheading and the next one
            # as base classes
            for k in range(j+1,len(content)):
                line = content[k]
                if "\wxheading" in line:
                    break
                elif "\helpref" in line:
                    baseclasses.append(line)
            break   # we've already processed the 'derived from' section for this class

    if baseclasses == []:
        print " no base classes declared for class %s" % classname
        return True     # keep going on with next \class tags

    # polish baseclasses list
    for i in range(len(baseclasses)):
        s = baseclasses[i]
        baseclasses[i] = s[s.find("{")+1:s.find("}")]

    # store the baseclasses
    tree[classname] = baseclasses
    treetex[classname] = texFileName
    treepos[classname] = j+1
    print " class '%s' has %d base class(es): %s" % (classname, len(baseclasses), ','.join(baseclasses))

    return True


tree = dict()
treetex = dict()
treepos = dict()
count = scanTexFiles(myCallback)

print "\nProcessed %d files." % count
print "\nNow starting to compare the base class lists.\n"

def getFullListOfBaseClasses(classname):
    if classname not in tree or classname=='':
        return []

    # only use the first base class of info taken from .tex files
    # i.e. we assume that at least the first class declared as base class is always correct
    baseclass = tree[classname][0]
    return [baseclass] + getFullListOfBaseClasses(baseclass)

# now compare the theorical list of base classes with the list of base
# classes taken from the .tex files
fixed=0
tofix=set()
for classname in tree:
    theorical=getFullListOfBaseClasses(classname)
    real=tree[classname]

    # compare them
    if real!=theorical:
        print "* for class '%s' documented in '%s'" % (classname,treetex[classname])
        print "  theorical list: %s" % theorical
        print "  declared list:  %s" % real

        if classname in EXCEPTIONS:
            tofix.add(treetex[classname])
            print "  cannot fix automatically (blacklisted class!)\n"
            continue

        # fix it!
        file = open(treetex[classname], "r")
        content = file.readlines()

        #print "old content is:"
        #print ''.join(content)

        # remove old \helpref lines
        startidx = treepos[classname]
        count = 0
        while count < len(tree[classname]):
            # we want to remove n \helpref lines, where 'n' is the
            # number of base classes declared
            if content[startidx].startswith('\helpref'):
                del content[startidx]
                count = count+1
            else:
                startidx = startidx+1 # probably an empty line

        # insert new ones
        if len(theorical)>1:
            for j in range(len(theorical)-1):
                c = theorical[j]
                content.insert(startidx+j, "\helpref{%s}{%s}\\\\\n" % (c, c.lower()))
        else:
            j=-1
        c = theorical[j+1]
        content.insert(startidx+j+1, "\helpref{%s}{%s}\n" % (c, c.lower()))

        #print "new content is:"
        #print ''.join(content)

        # save the file
        file = open(treetex[classname], "w")
        file.write(''.join(content))
        file.flush()

        print "  fixed the .tex file\n"
        fixed=fixed+1

print "Total number of errors reported: %d" % fixed
print "There are %d files to fix manually:\n%s" % (len(tofix), '\n'.join(tofix))
