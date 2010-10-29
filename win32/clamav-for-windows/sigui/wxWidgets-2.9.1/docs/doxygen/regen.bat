@echo off
REM $Id$

REM This bash script regenerates the HTML doxygen version of the
REM wxWidgets manual and adjusts the doxygen log to make it more
REM readable.

mkdir out 2>&1 >NUL
mkdir out\html 2>&1 >NUL
mkdir out\html\wxgtk 2>&1 >NUL
mkdir out\html\wxmsw 2>&1 >NUL
mkdir out\html\wxmac 2>&1 >NUL

REM These not automatically copied by Doxygen because it's not
REM used in doxygen documentation, only in our html footer.
copy images\powered-by-wxwidgets.png out\html 2>&1 >NUL
copy images\logo_*.png out\html 2>&1 >NUL
copy images\wxgtk\*.png out\html\wxgtk 2>&1 >NUL
copy images\wxmsw\*.png out\html\wxmsw 2>&1 >NUL
copy images\wxmac\*.png out\html\wxmac 2>&1 >NUL
copy wxwidgets.js out\html 2>&1 >NUL

REM this CSS is automatically copied by Doxygen because it's
REM included by our custom html header...
copy wxwidgets.css out\html 2>&1 >NUL

REM set cfgfile variable to the right doxyfile to use,
REM using MS broken batch scripting
setlocal enableextensions
set arg=%1
if "%arg%" EQU "" set cfgfile=Doxyfile_all
if "%arg%" NEQ "" set cfgfile=Doxyfile_%1

pushd ..\..
set WXWIDGETS=%CD%
popd

REM
REM NOW RUN DOXYGEN
REM
REM NB: we do this _after_ copying the required files to the output folders
REM     otherwise when generating the CHM file with Doxygen, those files are
REM     not included!
REM
set PATH=%PATH%;%HHC_PATH%
doxygen %cfgfile%
