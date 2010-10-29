
 Ifacecheck utility
 ==================

 1) INTRODUCTION

 This utility compares the wxWidgets real interface contained in the "include"
 hierarchy with the wxWidgets interface used for documentation purposes and
 kept in the "interface" hierarchy.

 Ifacecheck warns about incoherences (mainly wrong prototype signatures) and
 can even correct them automatically. It uses the XML outputs of the gccxml utility
 (see http://www.gccxml.org) and of the Doxygen utility (see http://www.doxygen.org)
 to do the comparison.

 It's explicitely designed for wxWidgets documentation needs and is probably of little
 use for anything else than wxWidgets docs reviewing.


 2) PREREQUISITES FOR USING IT

 To use this utility you'll need at least:
  - wxWidgets "include" and "interface" headers tree
  - Doxygen installed
  - Gccxml installed


 3) HOW TO USE IT (on Linux)

    First, create the doxygen XML:

     > cd docs/doxygen
     > ./regen.sh xml
     > cd ../..

    Next, create the gcc XML:

     > ./configure                # configure wxWidgets as you would do when building it
     > cd utils/ifacecheck
     > ./rungccxml.sh
     > cd ../..

    Last, build and run ifacecheck:

     > cd utils/ifacecheck/src
     > make
     > make install
     > cd ..
     > ifacecheck -u wxapi-preproc.txt wxapi.xml ../../docs/doxygen/out/xml/index.xml >ifacecheck.log

    Now you should have the log of the utility saved in 'ifacecheck.log'.
    Its contents should be easy to interpret.

    For more info about ifacecheck options just type:
     > ifacecheck --help
