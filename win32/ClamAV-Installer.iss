; -- ClamAV-Installer.iss --
; Install ClamAV.
; Will install the correct files and DLLs built for two different
; for the system architecture (x86 or x64) using a single installer:
; on a "x86" edition of Windows the x86 version of the program will be
; installed but on a "x64" edition of Windows the x64 version will
; be installed.

[Setup]
AppName=ClamAV
AppVersion=0.101.4
DefaultDirName={pf}\ClamAV
DefaultGroupName=ClamAV
AppCopyright=2019 Cisco Systems, Inc.
AppPublisher=Cisco Systems, Inc.
AppPublisherURL=https://www.clamav.net/
LicenseFile=..\COPYING
UninstallDisplayIcon={app}\clam.ico
UninstallDisplayName=ClamAV
Compression=lzma2
SolidCompression=yes
OutputDir=.
OutputBaseFilename=ClamAV-0.101.4
WizardImageFile=demon.bmp
WizardSmallImageFile=talos.bmp

; "ArchitecturesInstallIn64BitMode=x64" requests that the install be
; done in "64-bit mode" on x64, meaning it should use the native
; 64-bit Program Files directory and the 64-bit view of the registry.
; On all other architectures it will install in "32-bit mode".
ArchitecturesInstallIn64BitMode=x64
; Note: We don't set ProcessorsAllowed because we want this
; installation to run on all architectures (including Itanium,
; since it's capable of running 32-bit code too).

[Files]
; x64 files here
Source: "x64\Release\clambc.exe"; DestDir: "{app}"; DestName: "clambc.exe"; Check: Is64BitInstallMode
Source: "x64\Release\clamconf.exe"; DestDir: "{app}"; DestName: "clamconf.exe"; Check: Is64BitInstallMode
Source: "x64\Release\clamd.exe"; DestDir: "{app}"; DestName: "clamd.exe"; Check: Is64BitInstallMode
Source: "x64\Release\clamdscan.exe"; DestDir: "{app}"; DestName: "clamdscan.exe"; Check: Is64BitInstallMode
Source: "x64\Release\clamscan.exe"; DestDir: "{app}"; DestName: "clamscan.exe"; Check: Is64BitInstallMode
Source: "x64\Release\freshclam.exe"; DestDir: "{app}"; DestName: "freshclam.exe"; Check: Is64BitInstallMode
Source: "x64\Release\libclamav.dll"; DestDir: "{app}"; DestName: "libclamav.dll"; Check: Is64BitInstallMode
Source: "x64\Release\libclamunrar_iface.dll"; DestDir: "{app}"; DestName: "libclamunrar_iface.dll"; Check: Is64BitInstallMode
Source: "x64\Release\libclamunrar.dll"; DestDir: "{app}"; DestName: "libclamunrar.dll"; Check: Is64BitInstallMode
Source: "x64\Release\mspack.dll"; DestDir: "{app}"; DestName: "mspack.dll"; Check: Is64BitInstallMode
Source: "x64\Release\pthreads.dll"; DestDir: "{app}"; DestName: "pthreads.dll"; Check: Is64BitInstallMode
Source: "x64\Release\sigtool.exe"; DestDir: "{app}"; DestName: "sigtool.exe"; Check: Is64BitInstallMode
Source: "libcrypto-1_1-x64.dll"; DestDir: "{app}"; DestName: "libcrypto-1_1-x64.dll"; Check: Is64BitInstallMode
Source: "libssl-1_1-x64.dll"; DestDir: "{app}"; DestName: "libssl-1_1-x64.dll"; Check: Is64BitInstallMode
Source: "C:\clam_dependencies\vcredist\vc_redist.x64.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall; Check: Is64BitInstallMode

; x86 files here, first one should be marked 'solidbreak'
Source: "Win32\Release\clambc.exe"; DestDir: "{app}"; DestName: "clambc.exe"; Check: not Is64BitInstallMode; Flags: solidbreak
Source: "Win32\Release\clamconf.exe"; DestDir: "{app}"; DestName: "clamconf.exe"; Check: not Is64BitInstallMode
Source: "Win32\Release\clamd.exe"; DestDir: "{app}"; DestName: "clamd.exe"; Check: not Is64BitInstallMode
Source: "Win32\Release\clamdscan.exe"; DestDir: "{app}"; DestName: "clamdscan.exe"; Check: not Is64BitInstallMode
Source: "Win32\Release\clamscan.exe"; DestDir: "{app}"; DestName: "clamscan.exe"; Check: not Is64BitInstallMode
Source: "Win32\Release\freshclam.exe"; DestDir: "{app}"; DestName: "freshclam.exe"; Check: not Is64BitInstallMode
Source: "Win32\Release\libclamav.dll"; DestDir: "{app}"; DestName: "libclamav.dll"; Check: not Is64BitInstallMode
Source: "Win32\Release\libclamunrar_iface.dll"; DestDir: "{app}"; DestName: "libclamunrar_iface.dll"; Check: not Is64BitInstallMode
Source: "Win32\Release\libclamunrar.dll"; DestDir: "{app}"; DestName: "libclamunrar.dll"; Check: not Is64BitInstallMode
Source: "Win32\Release\mspack.dll"; DestDir: "{app}"; DestName: "mspack.dll"; Check: not Is64BitInstallMode
Source: "Win32\Release\pthreads.dll"; DestDir: "{app}"; DestName: "pthreads.dll"; Check: not Is64BitInstallMode
Source: "Win32\Release\sigtool.exe"; DestDir: "{app}"; DestName: "sigtool.exe"; Check: not Is64BitInstallMode
Source: "libcrypto-1_1.dll"; DestDir: "{app}"; DestName: "libcrypto-1_1.dll"; Check: not Is64BitInstallMode
Source: "libssl-1_1.dll"; DestDir: "{app}"; DestName: "libssl-1_1.dll"; Check: not Is64BitInstallMode
Source: "C:\clam_dependencies\vcredist\vc_redist.x86.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall; Check: not Is64BitInstallMode

; Place all common files here, first one should be marked 'solidbreak'
Source: "res\clam.ico"; DestDir: "{app}"; DestName: "clam.ico"; Flags: solidbreak
Source: "conf_examples\clamd.conf.sample"; DestDir: "{app}\conf_examples"; DestName: "clamd.conf.sample"
Source: "conf_examples\freshclam.conf.sample"; DestDir: "{app}\conf_examples"; DestName: "freshclam.conf.sample"
Source: "..\COPYING"; DestDir: "{app}\COPYING"; DestName: "COPYING"
Source: "..\COPYING.bzip2"; DestDir: "{app}\COPYING"; DestName: "COPYING.bzip2"
Source: "..\COPYING.file"; DestDir: "{app}\COPYING"; DestName: "COPYING.file"
Source: "..\COPYING.getopt"; DestDir: "{app}\COPYING"; DestName: "COPYING.getopt"
Source: "..\COPYING.LGPL"; DestDir: "{app}\COPYING"; DestName: "COPYING.LGPL"
Source: "..\COPYING.llvm"; DestDir: "{app}\COPYING"; DestName: "COPYING.llvm"
Source: "..\COPYING.lzma"; DestDir: "{app}\COPYING"; DestName: "COPYING.lzma"
Source: "..\COPYING.pcre"; DestDir: "{app}\COPYING"; DestName: "COPYING.pcre"
Source: "..\COPYING.regex"; DestDir: "{app}\COPYING"; DestName: "COPYING.regex"
Source: "..\COPYING.unrar"; DestDir: "{app}\COPYING"; DestName: "COPYING.unrar"
Source: "..\COPYING.YARA"; DestDir: "{app}\COPYING"; DestName: "COPYING.YARA"
Source: "..\COPYING.zlib"; DestDir: "{app}\COPYING"; DestName: "COPYING.zlib"
Source: "..\ChangeLog.md"; DestDir: "{app}\docs"; DestName: "ChangeLog.md"
Source: "..\NEWS.md"; DestDir: "{app}\docs"; DestName: "NEWS.md"
Source: "..\README.md"; DestDir: "{app}"; DestName: "README.md"
Source: "..\docs\html\*"; DestDir: "{app}\docs"; Flags: recursesubdirs

[Dirs]
Name: "{app}\database"

; The VCRedistNeedsInstall function checks if a given version of VC++ is already installed
; Modify the function with one (or more) of the VC_* constants to suit your version

[Run]
Filename: "{tmp}\vc_redist.x86.exe"; Parameters: "/q /norestart"; Check: not Is64BitInstallMode and VCRedistNeedsInstall; WorkingDir: {app}\redist; StatusMsg: Installing VC++ 2015 Redistributables...; Flags: shellexec
Filename: "{tmp}\vc_redist.x64.exe"; Parameters: "/q /norestart"; Check: Is64BitInstallMode and VCRedistNeedsInstall; WorkingDir: {app}\redist; StatusMsg: Installing VC++ 2015 Redistributables...; Flags: shellexec
Filename: file://{app}/docs/UserManual.html; Description: "Open the User Manual in the default browser"; Flags: postinstall shellexec

[Code]
#IFDEF UNICODE
  #DEFINE AW "W"
#ELSE
  #DEFINE AW "A"
#ENDIF
type
  INSTALLSTATE = Longint;
const
  INSTALLSTATE_INVALIDARG = -2;  // An invalid parameter was passed to the function.
  INSTALLSTATE_UNKNOWN = -1;     // The product is neither advertised or installed.
  INSTALLSTATE_ADVERTISED = 1;   // The product is advertised but not installed.
  INSTALLSTATE_ABSENT = 2;       // The product is installed for a different user.
  INSTALLSTATE_DEFAULT = 5;      // The product is installed for the current user.

  VC_2005_REDIST_X86 = '{A49F249F-0C91-497F-86DF-B2585E8E76B7}';
  VC_2005_REDIST_X64 = '{6E8E85E8-CE4B-4FF5-91F7-04999C9FAE6A}';
  VC_2005_REDIST_IA64 = '{03ED71EA-F531-4927-AABD-1C31BCE8E187}';
  VC_2005_SP1_REDIST_X86 = '{7299052B-02A4-4627-81F2-1818DA5D550D}';
  VC_2005_SP1_REDIST_X64 = '{071C9B48-7C32-4621-A0AC-3F809523288F}';
  VC_2005_SP1_REDIST_IA64 = '{0F8FB34E-675E-42ED-850B-29D98C2ECE08}';
  VC_2005_SP1_ATL_SEC_UPD_REDIST_X86 = '{837B34E3-7C30-493C-8F6A-2B0F04E2912C}';
  VC_2005_SP1_ATL_SEC_UPD_REDIST_X64 = '{6CE5BAE9-D3CA-4B99-891A-1DC6C118A5FC}';
  VC_2005_SP1_ATL_SEC_UPD_REDIST_IA64 = '{85025851-A784-46D8-950D-05CB3CA43A13}';

  VC_2008_REDIST_X86 = '{FF66E9F6-83E7-3A3E-AF14-8DE9A809A6A4}';
  VC_2008_REDIST_X64 = '{350AA351-21FA-3270-8B7A-835434E766AD}';
  VC_2008_REDIST_IA64 = '{2B547B43-DB50-3139-9EBE-37D419E0F5FA}';
  VC_2008_SP1_REDIST_X86 = '{9A25302D-30C0-39D9-BD6F-21E6EC160475}';
  VC_2008_SP1_REDIST_X64 = '{8220EEFE-38CD-377E-8595-13398D740ACE}';
  VC_2008_SP1_REDIST_IA64 = '{5827ECE1-AEB0-328E-B813-6FC68622C1F9}';
  VC_2008_SP1_ATL_SEC_UPD_REDIST_X86 = '{1F1C2DFC-2D24-3E06-BCB8-725134ADF989}';
  VC_2008_SP1_ATL_SEC_UPD_REDIST_X64 = '{4B6C7001-C7D6-3710-913E-5BC23FCE91E6}';
  VC_2008_SP1_ATL_SEC_UPD_REDIST_IA64 = '{977AD349-C2A8-39DD-9273-285C08987C7B}';
  VC_2008_SP1_MFC_SEC_UPD_REDIST_X86 = '{9BE518E6-ECC6-35A9-88E4-87755C07200F}';
  VC_2008_SP1_MFC_SEC_UPD_REDIST_X64 = '{5FCE6D76-F5DC-37AB-B2B8-22AB8CEDB1D4}';
  VC_2008_SP1_MFC_SEC_UPD_REDIST_IA64 = '{515643D1-4E9E-342F-A75A-D1F16448DC04}';

  VC_2010_REDIST_X86 = '{196BB40D-1578-3D01-B289-BEFC77A11A1E}';
  VC_2010_REDIST_X64 = '{DA5E371C-6333-3D8A-93A4-6FD5B20BCC6E}';
  VC_2010_REDIST_IA64 = '{C1A35166-4301-38E9-BA67-02823AD72A1B}';
  VC_2010_SP1_REDIST_X86 = '{F0C3E5D1-1ADE-321E-8167-68EF0DE699A5}';
  VC_2010_SP1_REDIST_X64 = '{1D8E6291-B0D5-35EC-8441-6616F567A0F7}';
  VC_2010_SP1_REDIST_IA64 = '{88C73C1C-2DE5-3B01-AFB8-B46EF4AB41CD}';

  // Microsoft Visual C++ 2012 x86 Minimum Runtime - 11.0.61030.0 (Update 4)
  VC_2012_REDIST_MIN_UPD4_X86 = '{BD95A8CD-1D9F-35AD-981A-3E7925026EBB}';
  VC_2012_REDIST_MIN_UPD4_X64 = '{CF2BEA3C-26EA-32F8-AA9B-331F7E34BA97}';
  // Microsoft Visual C++ 2012 x86 Additional Runtime - 11.0.61030.0 (Update 4)
  VC_2012_REDIST_ADD_UPD4_X86 = '{B175520C-86A2-35A7-8619-86DC379688B9}';
  VC_2012_REDIST_ADD_UPD4_X64 = '{37B8F9C7-03FB-3253-8781-2517C99D7C00}';

  // Visual C++ 2013 Redistributable 12.0.21005
  VC_2013_REDIST_X86_MIN = '{13A4EE12-23EA-3371-91EE-EFB36DDFFF3E}';
  VC_2013_REDIST_X64_MIN = '{A749D8E6-B613-3BE3-8F5F-045C84EBA29B}';

  VC_2013_REDIST_X86_ADD = '{F8CFEB22-A2E7-3971-9EDA-4B11EDEFC185}';
  VC_2013_REDIST_X64_ADD = '{929FBD26-9020-399B-9A7A-751D61F0B942}';

  // Visual C++ 2015 Redistributable 14.0.23026
  VC_2015_REDIST_X86_MIN = '{A2563E55-3BEC-3828-8D67-E5E8B9E8B675}';
  VC_2015_REDIST_X64_MIN = '{0D3E9E15-DE7A-300B-96F1-B4AF12B96488}';

  VC_2015_REDIST_X86_ADD = '{BE960C1C-7BAD-3DE6-8B1A-2616FE532845}';
  VC_2015_REDIST_X64_ADD = '{BC958BD2-5DAC-3862-BB1A-C1BE0790438D}';

function MsiQueryProductState(szProduct: string): INSTALLSTATE;
  external 'MsiQueryProductState{#AW}@msi.dll stdcall';

function VCVersionInstalled(const ProductID: string): Boolean;
begin
  Result := MsiQueryProductState(ProductID) = INSTALLSTATE_DEFAULT;
end;

function VCRedistNeedsInstall: Boolean;
begin
  Result := not (VCVersionInstalled(VC_2015_REDIST_X86_MIN) or VCVersionInstalled(VC_2015_REDIST_X86_ADD) or VCVersionInstalled(VC_2015_REDIST_X64_MIN) or VCVersionInstalled(VC_2015_REDIST_X64_ADD));
end;