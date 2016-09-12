echo off
set arg1=%1
set arg2=%2
call "%~1\vcvarsall.bat" %2
cl /O2 -I. /c *.c
link *.obj /DLL /DEF:mspack.def /IMPLIB:mspack.lib
