# Microsoft Developer Studio Project File - Name="screenshotgen" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Application" 0x0101

CFG=screenshotgen - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "screenshotgen.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "screenshotgen.mak" CFG="screenshotgen - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "screenshotgen - Win32 DLL Universal Release" (based on "Win32 (x86) Application")
!MESSAGE "screenshotgen - Win32 DLL Universal Debug" (based on "Win32 (x86) Application")
!MESSAGE "screenshotgen - Win32 DLL Release" (based on "Win32 (x86) Application")
!MESSAGE "screenshotgen - Win32 DLL Debug" (based on "Win32 (x86) Application")
!MESSAGE "screenshotgen - Win32 Universal Release" (based on "Win32 (x86) Application")
!MESSAGE "screenshotgen - Win32 Universal Debug" (based on "Win32 (x86) Application")
!MESSAGE "screenshotgen - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "screenshotgen - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "screenshotgen - Win32 DLL Universal Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "vc_mswunivudll"
# PROP BASE Intermediate_Dir "vc_mswunivudll\screenshotgen"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "vc_mswunivudll"
# PROP Intermediate_Dir "vc_mswunivudll\screenshotgen"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /FD /MD /Zi /Fdvc_mswunivudll\screenshotgen.pdb /opt:ref /opt:icf /O2 /GR /EHsc /I ".\..\..\..\lib\vc_dll\mswunivu" /I ".\..\..\..\include" /W4 /I "." /I ".\..\..\..\samples" /D "WIN32" /D "__WXMSW__" /D "__WXUNIVERSAL__" /D "NDEBUG" /D "_UNICODE" /D "WXUSINGDLL" /D "_WINDOWS" /D "NOPCH" /c
# ADD CPP /nologo /FD /MD /Zi /Fdvc_mswunivudll\screenshotgen.pdb /opt:ref /opt:icf /O2 /GR /EHsc /I ".\..\..\..\lib\vc_dll\mswunivu" /I ".\..\..\..\include" /W4 /I "." /I ".\..\..\..\samples" /D "WIN32" /D "__WXMSW__" /D "__WXUNIVERSAL__" /D "NDEBUG" /D "_UNICODE" /D "WXUSINGDLL" /D "_WINDOWS" /D "NOPCH" /c
# ADD BASE MTL /nologo /D "WIN32" /D "__WXMSW__" /D "__WXUNIVERSAL__" /D "NDEBUG" /D "_UNICODE" /D "WXUSINGDLL" /D "_WINDOWS" /D "NOPCH" /mktyplib203 /win32
# ADD MTL /nologo /D "WIN32" /D "__WXMSW__" /D "__WXUNIVERSAL__" /D "NDEBUG" /D "_UNICODE" /D "WXUSINGDLL" /D "_WINDOWS" /D "NOPCH" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "__WXMSW__" /d "__WXUNIVERSAL__" /d "NDEBUG" /d "_UNICODE" /i ".\..\..\..\lib\vc_dll\mswunivu" /i ".\..\..\..\include" /i "." /d "WXUSINGDLL" /d "_WINDOWS" /i ".\..\..\..\samples" /d NOPCH
# ADD RSC /l 0x409 /d "__WXMSW__" /d "__WXUNIVERSAL__" /d "NDEBUG" /d "_UNICODE" /i ".\..\..\..\lib\vc_dll\mswunivu" /i ".\..\..\..\include" /i "." /d "WXUSINGDLL" /d "_WINDOWS" /i ".\..\..\..\samples" /d NOPCH
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 wxmswuniv29u_aui.lib wxmswuniv29u_adv.lib wxmswuniv29u_richtext.lib wxmswuniv29u_html.lib wxbase29u_xml.lib wxmswuniv29u_core.lib wxbase29u.lib wxtiff.lib wxjpeg.lib wxpng.lib wxzlib.lib wxregexu.lib wxexpat.lib kernel32.lib user32.lib gdi32.lib comdlg32.lib winspool.lib winmm.lib shell32.lib comctl32.lib ole32.lib oleaut32.lib uuid.lib rpcrt4.lib advapi32.lib wsock32.lib wininet.lib /nologo /machine:i386 /out:"vc_mswunivudll\screenshotgen.exe" /debug /pdb:"vc_mswunivudll\screenshotgen.pdb" /libpath:".\..\..\..\lib\vc_dll" /subsystem:windows
# ADD LINK32 wxmswuniv29u_aui.lib wxmswuniv29u_adv.lib wxmswuniv29u_richtext.lib wxmswuniv29u_html.lib wxbase29u_xml.lib wxmswuniv29u_core.lib wxbase29u.lib wxtiff.lib wxjpeg.lib wxpng.lib wxzlib.lib wxregexu.lib wxexpat.lib kernel32.lib user32.lib gdi32.lib comdlg32.lib winspool.lib winmm.lib shell32.lib comctl32.lib ole32.lib oleaut32.lib uuid.lib rpcrt4.lib advapi32.lib wsock32.lib wininet.lib /nologo /machine:i386 /out:"vc_mswunivudll\screenshotgen.exe" /debug /pdb:"vc_mswunivudll\screenshotgen.pdb" /libpath:".\..\..\..\lib\vc_dll" /subsystem:windows

!ELSEIF  "$(CFG)" == "screenshotgen - Win32 DLL Universal Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "vc_mswunivuddll"
# PROP BASE Intermediate_Dir "vc_mswunivuddll\screenshotgen"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "vc_mswunivuddll"
# PROP Intermediate_Dir "vc_mswunivuddll\screenshotgen"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /FD /MDd /Zi /Fdvc_mswunivuddll\screenshotgen.pdb /Od /Gm /GR /EHsc /I ".\..\..\..\lib\vc_dll\mswunivud" /I ".\..\..\..\include" /W4 /I "." /I ".\..\..\..\samples" /D "WIN32" /D "_DEBUG" /D "__WXMSW__" /D "__WXUNIVERSAL__" /D "_UNICODE" /D "WXUSINGDLL" /D "_WINDOWS" /D "NOPCH" /c
# ADD CPP /nologo /FD /MDd /Zi /Fdvc_mswunivuddll\screenshotgen.pdb /Od /Gm /GR /EHsc /I ".\..\..\..\lib\vc_dll\mswunivud" /I ".\..\..\..\include" /W4 /I "." /I ".\..\..\..\samples" /D "WIN32" /D "_DEBUG" /D "__WXMSW__" /D "__WXUNIVERSAL__" /D "_UNICODE" /D "WXUSINGDLL" /D "_WINDOWS" /D "NOPCH" /c
# ADD BASE MTL /nologo /D "WIN32" /D "_DEBUG" /D "__WXMSW__" /D "__WXUNIVERSAL__" /D "_UNICODE" /D "WXUSINGDLL" /D "_WINDOWS" /D "NOPCH" /mktyplib203 /win32
# ADD MTL /nologo /D "WIN32" /D "_DEBUG" /D "__WXMSW__" /D "__WXUNIVERSAL__" /D "_UNICODE" /D "WXUSINGDLL" /D "_WINDOWS" /D "NOPCH" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG" /d "__WXMSW__" /d "__WXUNIVERSAL__" /d "_UNICODE" /i ".\..\..\..\lib\vc_dll\mswunivud" /i ".\..\..\..\include" /i "." /d "WXUSINGDLL" /d "_WINDOWS" /i ".\..\..\..\samples" /d NOPCH
# ADD RSC /l 0x409 /d "_DEBUG" /d "__WXMSW__" /d "__WXUNIVERSAL__" /d "_UNICODE" /i ".\..\..\..\lib\vc_dll\mswunivud" /i ".\..\..\..\include" /i "." /d "WXUSINGDLL" /d "_WINDOWS" /i ".\..\..\..\samples" /d NOPCH
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 wxmswuniv29ud_aui.lib wxmswuniv29ud_adv.lib wxmswuniv29ud_richtext.lib wxmswuniv29ud_html.lib wxbase29ud_xml.lib wxmswuniv29ud_core.lib wxbase29ud.lib wxtiffd.lib wxjpegd.lib wxpngd.lib wxzlibd.lib wxregexud.lib wxexpatd.lib kernel32.lib user32.lib gdi32.lib comdlg32.lib winspool.lib winmm.lib shell32.lib comctl32.lib ole32.lib oleaut32.lib uuid.lib rpcrt4.lib advapi32.lib wsock32.lib wininet.lib /nologo /machine:i386 /out:"vc_mswunivuddll\screenshotgen.exe" /debug /pdb:"vc_mswunivuddll\screenshotgen.pdb" /libpath:".\..\..\..\lib\vc_dll" /subsystem:windows
# ADD LINK32 wxmswuniv29ud_aui.lib wxmswuniv29ud_adv.lib wxmswuniv29ud_richtext.lib wxmswuniv29ud_html.lib wxbase29ud_xml.lib wxmswuniv29ud_core.lib wxbase29ud.lib wxtiffd.lib wxjpegd.lib wxpngd.lib wxzlibd.lib wxregexud.lib wxexpatd.lib kernel32.lib user32.lib gdi32.lib comdlg32.lib winspool.lib winmm.lib shell32.lib comctl32.lib ole32.lib oleaut32.lib uuid.lib rpcrt4.lib advapi32.lib wsock32.lib wininet.lib /nologo /machine:i386 /out:"vc_mswunivuddll\screenshotgen.exe" /debug /pdb:"vc_mswunivuddll\screenshotgen.pdb" /libpath:".\..\..\..\lib\vc_dll" /subsystem:windows

!ELSEIF  "$(CFG)" == "screenshotgen - Win32 DLL Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "vc_mswudll"
# PROP BASE Intermediate_Dir "vc_mswudll\screenshotgen"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "vc_mswudll"
# PROP Intermediate_Dir "vc_mswudll\screenshotgen"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /FD /MD /Zi /Fdvc_mswudll\screenshotgen.pdb /opt:ref /opt:icf /O2 /GR /EHsc /I ".\..\..\..\lib\vc_dll\mswu" /I ".\..\..\..\include" /W4 /I "." /I ".\..\..\..\samples" /D "WIN32" /D "__WXMSW__" /D "NDEBUG" /D "_UNICODE" /D "WXUSINGDLL" /D "_WINDOWS" /D "NOPCH" /c
# ADD CPP /nologo /FD /MD /Zi /Fdvc_mswudll\screenshotgen.pdb /opt:ref /opt:icf /O2 /GR /EHsc /I ".\..\..\..\lib\vc_dll\mswu" /I ".\..\..\..\include" /W4 /I "." /I ".\..\..\..\samples" /D "WIN32" /D "__WXMSW__" /D "NDEBUG" /D "_UNICODE" /D "WXUSINGDLL" /D "_WINDOWS" /D "NOPCH" /c
# ADD BASE MTL /nologo /D "WIN32" /D "__WXMSW__" /D "NDEBUG" /D "_UNICODE" /D "WXUSINGDLL" /D "_WINDOWS" /D "NOPCH" /mktyplib203 /win32
# ADD MTL /nologo /D "WIN32" /D "__WXMSW__" /D "NDEBUG" /D "_UNICODE" /D "WXUSINGDLL" /D "_WINDOWS" /D "NOPCH" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "__WXMSW__" /d "NDEBUG" /d "_UNICODE" /i ".\..\..\..\lib\vc_dll\mswu" /i ".\..\..\..\include" /i "." /d "WXUSINGDLL" /d "_WINDOWS" /i ".\..\..\..\samples" /d NOPCH
# ADD RSC /l 0x409 /d "__WXMSW__" /d "NDEBUG" /d "_UNICODE" /i ".\..\..\..\lib\vc_dll\mswu" /i ".\..\..\..\include" /i "." /d "WXUSINGDLL" /d "_WINDOWS" /i ".\..\..\..\samples" /d NOPCH
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 wxmsw29u_aui.lib wxmsw29u_adv.lib wxmsw29u_richtext.lib wxmsw29u_html.lib wxbase29u_xml.lib wxmsw29u_core.lib wxbase29u.lib wxtiff.lib wxjpeg.lib wxpng.lib wxzlib.lib wxregexu.lib wxexpat.lib kernel32.lib user32.lib gdi32.lib comdlg32.lib winspool.lib winmm.lib shell32.lib comctl32.lib ole32.lib oleaut32.lib uuid.lib rpcrt4.lib advapi32.lib wsock32.lib wininet.lib /nologo /machine:i386 /out:"vc_mswudll\screenshotgen.exe" /debug /pdb:"vc_mswudll\screenshotgen.pdb" /libpath:".\..\..\..\lib\vc_dll" /subsystem:windows
# ADD LINK32 wxmsw29u_aui.lib wxmsw29u_adv.lib wxmsw29u_richtext.lib wxmsw29u_html.lib wxbase29u_xml.lib wxmsw29u_core.lib wxbase29u.lib wxtiff.lib wxjpeg.lib wxpng.lib wxzlib.lib wxregexu.lib wxexpat.lib kernel32.lib user32.lib gdi32.lib comdlg32.lib winspool.lib winmm.lib shell32.lib comctl32.lib ole32.lib oleaut32.lib uuid.lib rpcrt4.lib advapi32.lib wsock32.lib wininet.lib /nologo /machine:i386 /out:"vc_mswudll\screenshotgen.exe" /debug /pdb:"vc_mswudll\screenshotgen.pdb" /libpath:".\..\..\..\lib\vc_dll" /subsystem:windows

!ELSEIF  "$(CFG)" == "screenshotgen - Win32 DLL Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "vc_mswuddll"
# PROP BASE Intermediate_Dir "vc_mswuddll\screenshotgen"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "vc_mswuddll"
# PROP Intermediate_Dir "vc_mswuddll\screenshotgen"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /FD /MDd /Zi /Fdvc_mswuddll\screenshotgen.pdb /Od /Gm /GR /EHsc /I ".\..\..\..\lib\vc_dll\mswud" /I ".\..\..\..\include" /W4 /I "." /I ".\..\..\..\samples" /D "WIN32" /D "_DEBUG" /D "__WXMSW__" /D "_UNICODE" /D "WXUSINGDLL" /D "_WINDOWS" /D "NOPCH" /c
# ADD CPP /nologo /FD /MDd /Zi /Fdvc_mswuddll\screenshotgen.pdb /Od /Gm /GR /EHsc /I ".\..\..\..\lib\vc_dll\mswud" /I ".\..\..\..\include" /W4 /I "." /I ".\..\..\..\samples" /D "WIN32" /D "_DEBUG" /D "__WXMSW__" /D "_UNICODE" /D "WXUSINGDLL" /D "_WINDOWS" /D "NOPCH" /c
# ADD BASE MTL /nologo /D "WIN32" /D "_DEBUG" /D "__WXMSW__" /D "_UNICODE" /D "WXUSINGDLL" /D "_WINDOWS" /D "NOPCH" /mktyplib203 /win32
# ADD MTL /nologo /D "WIN32" /D "_DEBUG" /D "__WXMSW__" /D "_UNICODE" /D "WXUSINGDLL" /D "_WINDOWS" /D "NOPCH" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG" /d "__WXMSW__" /d "_UNICODE" /i ".\..\..\..\lib\vc_dll\mswud" /i ".\..\..\..\include" /i "." /d "WXUSINGDLL" /d "_WINDOWS" /i ".\..\..\..\samples" /d NOPCH
# ADD RSC /l 0x409 /d "_DEBUG" /d "__WXMSW__" /d "_UNICODE" /i ".\..\..\..\lib\vc_dll\mswud" /i ".\..\..\..\include" /i "." /d "WXUSINGDLL" /d "_WINDOWS" /i ".\..\..\..\samples" /d NOPCH
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 wxmsw29ud_aui.lib wxmsw29ud_adv.lib wxmsw29ud_richtext.lib wxmsw29ud_html.lib wxbase29ud_xml.lib wxmsw29ud_core.lib wxbase29ud.lib wxtiffd.lib wxjpegd.lib wxpngd.lib wxzlibd.lib wxregexud.lib wxexpatd.lib kernel32.lib user32.lib gdi32.lib comdlg32.lib winspool.lib winmm.lib shell32.lib comctl32.lib ole32.lib oleaut32.lib uuid.lib rpcrt4.lib advapi32.lib wsock32.lib wininet.lib /nologo /machine:i386 /out:"vc_mswuddll\screenshotgen.exe" /debug /pdb:"vc_mswuddll\screenshotgen.pdb" /libpath:".\..\..\..\lib\vc_dll" /subsystem:windows
# ADD LINK32 wxmsw29ud_aui.lib wxmsw29ud_adv.lib wxmsw29ud_richtext.lib wxmsw29ud_html.lib wxbase29ud_xml.lib wxmsw29ud_core.lib wxbase29ud.lib wxtiffd.lib wxjpegd.lib wxpngd.lib wxzlibd.lib wxregexud.lib wxexpatd.lib kernel32.lib user32.lib gdi32.lib comdlg32.lib winspool.lib winmm.lib shell32.lib comctl32.lib ole32.lib oleaut32.lib uuid.lib rpcrt4.lib advapi32.lib wsock32.lib wininet.lib /nologo /machine:i386 /out:"vc_mswuddll\screenshotgen.exe" /debug /pdb:"vc_mswuddll\screenshotgen.pdb" /libpath:".\..\..\..\lib\vc_dll" /subsystem:windows

!ELSEIF  "$(CFG)" == "screenshotgen - Win32 Universal Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "vc_mswunivu"
# PROP BASE Intermediate_Dir "vc_mswunivu\screenshotgen"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "vc_mswunivu"
# PROP Intermediate_Dir "vc_mswunivu\screenshotgen"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /FD /MD /Zi /Fdvc_mswunivu\screenshotgen.pdb /opt:ref /opt:icf /O2 /GR /EHsc /I ".\..\..\..\lib\vc_lib\mswunivu" /I ".\..\..\..\include" /W4 /I "." /I ".\..\..\..\samples" /D "WIN32" /D "__WXMSW__" /D "__WXUNIVERSAL__" /D "NDEBUG" /D "_UNICODE" /D "_WINDOWS" /D "NOPCH" /c
# ADD CPP /nologo /FD /MD /Zi /Fdvc_mswunivu\screenshotgen.pdb /opt:ref /opt:icf /O2 /GR /EHsc /I ".\..\..\..\lib\vc_lib\mswunivu" /I ".\..\..\..\include" /W4 /I "." /I ".\..\..\..\samples" /D "WIN32" /D "__WXMSW__" /D "__WXUNIVERSAL__" /D "NDEBUG" /D "_UNICODE" /D "_WINDOWS" /D "NOPCH" /c
# ADD BASE MTL /nologo /D "WIN32" /D "__WXMSW__" /D "__WXUNIVERSAL__" /D "NDEBUG" /D "_UNICODE" /D "_WINDOWS" /D "NOPCH" /mktyplib203 /win32
# ADD MTL /nologo /D "WIN32" /D "__WXMSW__" /D "__WXUNIVERSAL__" /D "NDEBUG" /D "_UNICODE" /D "_WINDOWS" /D "NOPCH" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "__WXMSW__" /d "__WXUNIVERSAL__" /d "NDEBUG" /d "_UNICODE" /i ".\..\..\..\lib\vc_lib\mswunivu" /i ".\..\..\..\include" /i "." /d "_WINDOWS" /i ".\..\..\..\samples" /d NOPCH
# ADD RSC /l 0x409 /d "__WXMSW__" /d "__WXUNIVERSAL__" /d "NDEBUG" /d "_UNICODE" /i ".\..\..\..\lib\vc_lib\mswunivu" /i ".\..\..\..\include" /i "." /d "_WINDOWS" /i ".\..\..\..\samples" /d NOPCH
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 wxmswuniv29u_aui.lib wxmswuniv29u_adv.lib wxmswuniv29u_richtext.lib wxmswuniv29u_html.lib wxbase29u_xml.lib wxmswuniv29u_core.lib wxbase29u.lib wxtiff.lib wxjpeg.lib wxpng.lib wxzlib.lib wxregexu.lib wxexpat.lib kernel32.lib user32.lib gdi32.lib comdlg32.lib winspool.lib winmm.lib shell32.lib comctl32.lib ole32.lib oleaut32.lib uuid.lib rpcrt4.lib advapi32.lib wsock32.lib wininet.lib /nologo /machine:i386 /out:"vc_mswunivu\screenshotgen.exe" /debug /pdb:"vc_mswunivu\screenshotgen.pdb" /libpath:".\..\..\..\lib\vc_lib" /subsystem:windows
# ADD LINK32 wxmswuniv29u_aui.lib wxmswuniv29u_adv.lib wxmswuniv29u_richtext.lib wxmswuniv29u_html.lib wxbase29u_xml.lib wxmswuniv29u_core.lib wxbase29u.lib wxtiff.lib wxjpeg.lib wxpng.lib wxzlib.lib wxregexu.lib wxexpat.lib kernel32.lib user32.lib gdi32.lib comdlg32.lib winspool.lib winmm.lib shell32.lib comctl32.lib ole32.lib oleaut32.lib uuid.lib rpcrt4.lib advapi32.lib wsock32.lib wininet.lib /nologo /machine:i386 /out:"vc_mswunivu\screenshotgen.exe" /debug /pdb:"vc_mswunivu\screenshotgen.pdb" /libpath:".\..\..\..\lib\vc_lib" /subsystem:windows

!ELSEIF  "$(CFG)" == "screenshotgen - Win32 Universal Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "vc_mswunivud"
# PROP BASE Intermediate_Dir "vc_mswunivud\screenshotgen"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "vc_mswunivud"
# PROP Intermediate_Dir "vc_mswunivud\screenshotgen"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /FD /MDd /Zi /Fdvc_mswunivud\screenshotgen.pdb /Od /Gm /GR /EHsc /I ".\..\..\..\lib\vc_lib\mswunivud" /I ".\..\..\..\include" /W4 /I "." /I ".\..\..\..\samples" /D "WIN32" /D "_DEBUG" /D "__WXMSW__" /D "__WXUNIVERSAL__" /D "_UNICODE" /D "_WINDOWS" /D "NOPCH" /c
# ADD CPP /nologo /FD /MDd /Zi /Fdvc_mswunivud\screenshotgen.pdb /Od /Gm /GR /EHsc /I ".\..\..\..\lib\vc_lib\mswunivud" /I ".\..\..\..\include" /W4 /I "." /I ".\..\..\..\samples" /D "WIN32" /D "_DEBUG" /D "__WXMSW__" /D "__WXUNIVERSAL__" /D "_UNICODE" /D "_WINDOWS" /D "NOPCH" /c
# ADD BASE MTL /nologo /D "WIN32" /D "_DEBUG" /D "__WXMSW__" /D "__WXUNIVERSAL__" /D "_UNICODE" /D "_WINDOWS" /D "NOPCH" /mktyplib203 /win32
# ADD MTL /nologo /D "WIN32" /D "_DEBUG" /D "__WXMSW__" /D "__WXUNIVERSAL__" /D "_UNICODE" /D "_WINDOWS" /D "NOPCH" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG" /d "__WXMSW__" /d "__WXUNIVERSAL__" /d "_UNICODE" /i ".\..\..\..\lib\vc_lib\mswunivud" /i ".\..\..\..\include" /i "." /d "_WINDOWS" /i ".\..\..\..\samples" /d NOPCH
# ADD RSC /l 0x409 /d "_DEBUG" /d "__WXMSW__" /d "__WXUNIVERSAL__" /d "_UNICODE" /i ".\..\..\..\lib\vc_lib\mswunivud" /i ".\..\..\..\include" /i "." /d "_WINDOWS" /i ".\..\..\..\samples" /d NOPCH
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 wxmswuniv29ud_aui.lib wxmswuniv29ud_adv.lib wxmswuniv29ud_richtext.lib wxmswuniv29ud_html.lib wxbase29ud_xml.lib wxmswuniv29ud_core.lib wxbase29ud.lib wxtiffd.lib wxjpegd.lib wxpngd.lib wxzlibd.lib wxregexud.lib wxexpatd.lib kernel32.lib user32.lib gdi32.lib comdlg32.lib winspool.lib winmm.lib shell32.lib comctl32.lib ole32.lib oleaut32.lib uuid.lib rpcrt4.lib advapi32.lib wsock32.lib wininet.lib /nologo /machine:i386 /out:"vc_mswunivud\screenshotgen.exe" /debug /pdb:"vc_mswunivud\screenshotgen.pdb" /libpath:".\..\..\..\lib\vc_lib" /subsystem:windows
# ADD LINK32 wxmswuniv29ud_aui.lib wxmswuniv29ud_adv.lib wxmswuniv29ud_richtext.lib wxmswuniv29ud_html.lib wxbase29ud_xml.lib wxmswuniv29ud_core.lib wxbase29ud.lib wxtiffd.lib wxjpegd.lib wxpngd.lib wxzlibd.lib wxregexud.lib wxexpatd.lib kernel32.lib user32.lib gdi32.lib comdlg32.lib winspool.lib winmm.lib shell32.lib comctl32.lib ole32.lib oleaut32.lib uuid.lib rpcrt4.lib advapi32.lib wsock32.lib wininet.lib /nologo /machine:i386 /out:"vc_mswunivud\screenshotgen.exe" /debug /pdb:"vc_mswunivud\screenshotgen.pdb" /libpath:".\..\..\..\lib\vc_lib" /subsystem:windows

!ELSEIF  "$(CFG)" == "screenshotgen - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "vc_mswu"
# PROP BASE Intermediate_Dir "vc_mswu\screenshotgen"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "vc_mswu"
# PROP Intermediate_Dir "vc_mswu\screenshotgen"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /FD /MD /Zi /Fdvc_mswu\screenshotgen.pdb /opt:ref /opt:icf /O2 /GR /EHsc /I ".\..\..\..\lib\vc_lib\mswu" /I ".\..\..\..\include" /W4 /I "." /I ".\..\..\..\samples" /D "WIN32" /D "__WXMSW__" /D "NDEBUG" /D "_UNICODE" /D "_WINDOWS" /D "NOPCH" /c
# ADD CPP /nologo /FD /MD /Zi /Fdvc_mswu\screenshotgen.pdb /opt:ref /opt:icf /O2 /GR /EHsc /I ".\..\..\..\lib\vc_lib\mswu" /I ".\..\..\..\include" /W4 /I "." /I ".\..\..\..\samples" /D "WIN32" /D "__WXMSW__" /D "NDEBUG" /D "_UNICODE" /D "_WINDOWS" /D "NOPCH" /c
# ADD BASE MTL /nologo /D "WIN32" /D "__WXMSW__" /D "NDEBUG" /D "_UNICODE" /D "_WINDOWS" /D "NOPCH" /mktyplib203 /win32
# ADD MTL /nologo /D "WIN32" /D "__WXMSW__" /D "NDEBUG" /D "_UNICODE" /D "_WINDOWS" /D "NOPCH" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "__WXMSW__" /d "NDEBUG" /d "_UNICODE" /i ".\..\..\..\lib\vc_lib\mswu" /i ".\..\..\..\include" /i "." /d "_WINDOWS" /i ".\..\..\..\samples" /d NOPCH
# ADD RSC /l 0x409 /d "__WXMSW__" /d "NDEBUG" /d "_UNICODE" /i ".\..\..\..\lib\vc_lib\mswu" /i ".\..\..\..\include" /i "." /d "_WINDOWS" /i ".\..\..\..\samples" /d NOPCH
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 wxmsw29u_aui.lib wxmsw29u_adv.lib wxmsw29u_richtext.lib wxmsw29u_html.lib wxbase29u_xml.lib wxmsw29u_core.lib wxbase29u.lib wxtiff.lib wxjpeg.lib wxpng.lib wxzlib.lib wxregexu.lib wxexpat.lib kernel32.lib user32.lib gdi32.lib comdlg32.lib winspool.lib winmm.lib shell32.lib comctl32.lib ole32.lib oleaut32.lib uuid.lib rpcrt4.lib advapi32.lib wsock32.lib wininet.lib /nologo /machine:i386 /out:"vc_mswu\screenshotgen.exe" /debug /pdb:"vc_mswu\screenshotgen.pdb" /libpath:".\..\..\..\lib\vc_lib" /subsystem:windows
# ADD LINK32 wxmsw29u_aui.lib wxmsw29u_adv.lib wxmsw29u_richtext.lib wxmsw29u_html.lib wxbase29u_xml.lib wxmsw29u_core.lib wxbase29u.lib wxtiff.lib wxjpeg.lib wxpng.lib wxzlib.lib wxregexu.lib wxexpat.lib kernel32.lib user32.lib gdi32.lib comdlg32.lib winspool.lib winmm.lib shell32.lib comctl32.lib ole32.lib oleaut32.lib uuid.lib rpcrt4.lib advapi32.lib wsock32.lib wininet.lib /nologo /machine:i386 /out:"vc_mswu\screenshotgen.exe" /debug /pdb:"vc_mswu\screenshotgen.pdb" /libpath:".\..\..\..\lib\vc_lib" /subsystem:windows

!ELSEIF  "$(CFG)" == "screenshotgen - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "vc_mswud"
# PROP BASE Intermediate_Dir "vc_mswud\screenshotgen"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "vc_mswud"
# PROP Intermediate_Dir "vc_mswud\screenshotgen"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /FD /MDd /Zi /Fdvc_mswud\screenshotgen.pdb /Od /Gm /GR /EHsc /I ".\..\..\..\lib\vc_lib\mswud" /I ".\..\..\..\include" /W4 /I "." /I ".\..\..\..\samples" /D "WIN32" /D "_DEBUG" /D "__WXMSW__" /D "_UNICODE" /D "_WINDOWS" /D "NOPCH" /c
# ADD CPP /nologo /FD /MDd /Zi /Fdvc_mswud\screenshotgen.pdb /Od /Gm /GR /EHsc /I ".\..\..\..\lib\vc_lib\mswud" /I ".\..\..\..\include" /W4 /I "." /I ".\..\..\..\samples" /D "WIN32" /D "_DEBUG" /D "__WXMSW__" /D "_UNICODE" /D "_WINDOWS" /D "NOPCH" /c
# ADD BASE MTL /nologo /D "WIN32" /D "_DEBUG" /D "__WXMSW__" /D "_UNICODE" /D "_WINDOWS" /D "NOPCH" /mktyplib203 /win32
# ADD MTL /nologo /D "WIN32" /D "_DEBUG" /D "__WXMSW__" /D "_UNICODE" /D "_WINDOWS" /D "NOPCH" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG" /d "__WXMSW__" /d "_UNICODE" /i ".\..\..\..\lib\vc_lib\mswud" /i ".\..\..\..\include" /i "." /d "_WINDOWS" /i ".\..\..\..\samples" /d NOPCH
# ADD RSC /l 0x409 /d "_DEBUG" /d "__WXMSW__" /d "_UNICODE" /i ".\..\..\..\lib\vc_lib\mswud" /i ".\..\..\..\include" /i "." /d "_WINDOWS" /i ".\..\..\..\samples" /d NOPCH
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 wxmsw29ud_aui.lib wxmsw29ud_adv.lib wxmsw29ud_richtext.lib wxmsw29ud_html.lib wxbase29ud_xml.lib wxmsw29ud_core.lib wxbase29ud.lib wxtiffd.lib wxjpegd.lib wxpngd.lib wxzlibd.lib wxregexud.lib wxexpatd.lib kernel32.lib user32.lib gdi32.lib comdlg32.lib winspool.lib winmm.lib shell32.lib comctl32.lib ole32.lib oleaut32.lib uuid.lib rpcrt4.lib advapi32.lib wsock32.lib wininet.lib /nologo /machine:i386 /out:"vc_mswud\screenshotgen.exe" /debug /pdb:"vc_mswud\screenshotgen.pdb" /libpath:".\..\..\..\lib\vc_lib" /subsystem:windows
# ADD LINK32 wxmsw29ud_aui.lib wxmsw29ud_adv.lib wxmsw29ud_richtext.lib wxmsw29ud_html.lib wxbase29ud_xml.lib wxmsw29ud_core.lib wxbase29ud.lib wxtiffd.lib wxjpegd.lib wxpngd.lib wxzlibd.lib wxregexud.lib wxexpatd.lib kernel32.lib user32.lib gdi32.lib comdlg32.lib winspool.lib winmm.lib shell32.lib comctl32.lib ole32.lib oleaut32.lib uuid.lib rpcrt4.lib advapi32.lib wsock32.lib wininet.lib /nologo /machine:i386 /out:"vc_mswud\screenshotgen.exe" /debug /pdb:"vc_mswud\screenshotgen.pdb" /libpath:".\..\..\..\lib\vc_lib" /subsystem:windows

!ENDIF

# Begin Target

# Name "screenshotgen - Win32 DLL Universal Release"
# Name "screenshotgen - Win32 DLL Universal Debug"
# Name "screenshotgen - Win32 DLL Release"
# Name "screenshotgen - Win32 DLL Debug"
# Name "screenshotgen - Win32 Universal Release"
# Name "screenshotgen - Win32 Universal Debug"
# Name "screenshotgen - Win32 Release"
# Name "screenshotgen - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\autocapture.cpp
# End Source File
# Begin Source File

SOURCE=.\customcombo.cpp
# End Source File
# Begin Source File

SOURCE=.\guiframe.cpp
# End Source File
# Begin Source File

SOURCE=.\screenshot_app.cpp
# End Source File
# Begin Source File

SOURCE=.\screenshot_main.cpp
# End Source File
# Begin Source File

SOURCE=.\screenshotgen.rc
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\autocapture.h
# End Source File
# Begin Source File

SOURCE=.\customcombo.h
# End Source File
# Begin Source File

SOURCE=.\guiframe.h
# End Source File
# Begin Source File

SOURCE=.\screenshot_app.h
# End Source File
# Begin Source File

SOURCE=.\screenshot_main.h
# End Source File
# End Group
# End Target
# End Project

