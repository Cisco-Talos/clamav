lib\watcom subdirectory
-----------------------

If odbc32.lib isn't supplied with your Watcom C++ compiler,
you can use this one. If you find that the ODBC API changes
and you get some unresolved SQL... references, add items to
odbc.txt, put odbc32.dll in this directory, and then call
makeit.bat in order to regenerate odbc32.lib.

If you already have a suitable odbc32.dll, change the reference
in src\makewat.env to the one you wish to use.

Julian Smart, October 1999
