rem This file was contributed by Ralf Junker.
rem
rem MS Windows batch file to run pcretest on testfiles with the correct options.
rem
rem Assumes that this file as well as pcretest.exe is located in the PCRE root folder.
rem
rem Output written to a newly generated subfolder named "testdata".

if not exist .\testout\ md .\testout\

pcretest -q      testdata\testinput1 > testout\testoutput1
pcretest -q      testdata\testinput2 > testout\testoutput2
pcretest -q      testdata\testinput3 > testout\testoutput3
pcretest -q      testdata\testinput4 > testout\testoutput4
pcretest -q      testdata\testinput5 > testout\testoutput5
pcretest -q      testdata\testinput6 > testout\testoutput6
pcretest -q -dfa testdata\testinput7 > testout\testoutput7
pcretest -q -dfa testdata\testinput8 > testout\testoutput8
pcretest -q -dfa testdata\testinput9 > testout\testoutput9

