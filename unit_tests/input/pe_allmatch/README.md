## Overview

This aims to provide many different types of ClamAV rules for the given `test.exe` x86 Windows executable binary in order to test ClamAV's ability to report multiple signature matches (`-z` or `--allmatch` in `clamscan`).

- `src` - contains the code necessary to rebuild the `test.exe` program.
- `alert-sigs` are a combination of signatures generated by this tool, and those that were manually created.
  - As the name implies, these signatures are expected to alert on the `text.exe` program.
  - Some of these signatures depend on signatures in `weak-sigs`.
- `weak-sigs` are a combination of signatures generated by this tool, and those that were manually created.
  - As the name implies, these signatures support the `alert-sigs`, but do not alert on their own.

The tools necessary to (re)generate those sigs that were generated are not included here.

## Requirements

These are the requirements to build the `test.exe` program.
The requirements, features needed to generate those of the sig test set that weren't hand-written are not provided here.

- `python3`
- `mingw-w64`
  - Just `sudo apt install mingw-w64` on ubuntu 20.04
- `osslsigncode`
  - The ubuntu package is dated, but it's pretty easy to install from https://github.com/mtrojnar/osslsigncode
    - Follow the directions for those prereqs.
    - Note: you can use these `cmake` commands:
      ```bash
      mkdir build && cd build
      cmake .. && cmake --build .
      sudo cmake --install . --prefix /usr/local/bin
      ```

## Steps to regenerate the `test.exe` program

1. Build the binary with: `./build.py`

2. Generate the signatures. First run:
   ```sh
   mkdir gen
   ```
   Then run:
   ```sh
   python generate.py build/test.exe
   ```

## Testing:
 - Example invocation:
```
$ clamscan -z -d gen/ -d manual/ build/test.exe --bytecode-unsigned --no-summary | sort -n
test.exe: Test.GenSig.HSB_01of06_MD5_FIXED.UNOFFICIAL FOUND
test.exe: Test.GenSig.MSB_01of90_MD5_FIXED_dottext.UNOFFICIAL FOUND
test.exe: Test.GenSig.MSB_02of90_SHA1_FIXED_dottext.UNOFFICIAL FOUND
test.exe: Test.GenSig.MSB_03of90_SHA256_FIXED_dottext.UNOFFICIAL FOUND
test.exe: Test.GenSig.MSB_04of90_MD5_STAR_dottext.UNOFFICIAL FOUND
test.exe: Test.GenSig.MSB_05of90_SHA1_STAR_dottext.UNOFFICIAL FOUND
test.exe: Test.GenSig.MSB_06of90_SHA256_STAR_dottext.UNOFFICIAL FOUND
test.exe: Test.GenSig.NDB_01of08_legalcopyright.UNOFFICIAL FOUND
test.exe: Test.GenSig.NDB_02of08_internalname.UNOFFICIAL FOUND
test.exe: Test.GenSig.NDB_03of08_fileversion.UNOFFICIAL FOUND
test.exe: Test.GenSig.NDB_04of08_companyname.UNOFFICIAL FOUND
test.exe: Test.GenSig.NDB_05of08_productname.UNOFFICIAL FOUND
test.exe: Test.GenSig.NDB_06of08_productversion.UNOFFICIAL FOUND
test.exe: Test.GenSig.NDB_07of08_filedescription.UNOFFICIAL FOUND
test.exe: Test.GenSig.NDB_08of08_originalfilename.UNOFFICIAL FOUND
test.exe: Test.Sig.LDB_01of16_PE_1.UNOFFICIAL FOUND
test.exe: Test.Sig.LDB_02of16_PE_2.UNOFFICIAL FOUND
test.exe: Test.Sig.LDB_03of16_ANY_1.UNOFFICIAL FOUND
test.exe: Test.Sig.LDB_04of16_ANY_2.UNOFFICIAL FOUND
test.exe: Test.Sig.LDB_05of16_PE_EP_1.UNOFFICIAL FOUND
test.exe: Test.Sig.LDB_06of16_PE_EP_2.UNOFFICIAL FOUND
test.exe: Test.Sig.LDB_07of16_PE_SE1_1.UNOFFICIAL FOUND
test.exe: Test.Sig.LDB_09of16_PE_S1_1.UNOFFICIAL FOUND
test.exe: Test.Sig.LDB_10of16_PE_S1_2.UNOFFICIAL FOUND
test.exe: Test.Sig.LDB_11of16_PE_PCRE_1.UNOFFICIAL FOUND
test.exe: Test.Sig.LDB_12of16_PE_PCRE_2.UNOFFICIAL FOUND
test.exe: Test.Sig.LDB_13of16_ANY_PCRE_1.UNOFFICIAL FOUND
test.exe: Test.Sig.LDB_14of16_ANY_PCRE_2.UNOFFICIAL FOUND
test.exe: Test.Sig.LDB_15of16_PE_ICON_1.UNOFFICIAL FOUND
test.exe: Test.Sig.LDB_16of16_PE_ICON_2.UNOFFICIAL FOUND
test.exe: Test.Sig.NDB_01of10_PE_1.UNOFFICIAL FOUND
test.exe: Test.Sig.NDB_02of10_PE_2.UNOFFICIAL FOUND
test.exe: Test.Sig.NDB_03of10_ANY_1.UNOFFICIAL FOUND
test.exe: Test.Sig.NDB_04of10_ANY_2.UNOFFICIAL FOUND
test.exe: Test.Sig.NDB_05of10_PE_EP_1.UNOFFICIAL FOUND
test.exe: Test.Sig.NDB_06of10_PE_EP_2.UNOFFICIAL FOUND
test.exe: Test.Sig.NDB_07of10_PE_SE2_1.UNOFFICIAL FOUND
test.exe: Test.Sig.NDB_09of10_PE_S1_1.UNOFFICIAL FOUND
test.exe: Test.Sig.NDB_10of10_PE_S1_2.UNOFFICIAL FOUND
test.exe: YARA.Test_Sig_YARA_1of1_strings.UNOFFICIAL FOUND
```

## Steps to generate the .ico file:
```
head -c 245760 /dev/urandom | convert -depth 8 -size 320x256 RGB:- test.png
convert -background transparent test.png -define icon:auto-resize=16,32,48,64,256 test.ico
```