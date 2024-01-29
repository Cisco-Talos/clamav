/*
 *  Static filetype data for use when daily.ftm is not available.
 *
 *  Copyright (C) 2013-2024 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#ifndef __FILETYPES_INT_H
#define __FILETYPES_INT_H

/* ftypes_int is used when daily.ftm (usually within daily.cvd) isn't loaded.
 * The contents here should directly mirror daily.ftm to ensure that ClamAV
 * operates the same whether the official signature sets are loaded or not,
 * and also to make it easier to maintain both sets of FTM signatures. New
 * FTM sigs should get added to the bottom of this list and added into
 * daily.ftm.
 *
 * ftypes_int was last updated on Jun 11 2021 and mirrors daily.ftm in
 * daily.cvd version 26198.
 */
static const char *ftypes_int[] = {
    "0:0:1f8b:GZip:CL_TYPE_ANY:CL_TYPE_GZ",
    "0:0:23407e5e:SCRENC:CL_TYPE_ANY:CL_TYPE_SCRENC",
    "0:0:28546869732066696c65206d75737420626520636f6e76657274656420776974682042696e48657820342e3029:BinHex:CL_TYPE_ANY:CL_TYPE_BINHEX",
    "0:0:2e524d46:Real Media File:CL_TYPE_ANY:CL_TYPE_IGNORED",
    "0:0:3e46726f6d20:Mail:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:424d:BMP:CL_TYPE_ANY:CL_TYPE_GRAPHICS",
    "0:0:425a68:BZip:CL_TYPE_ANY:CL_TYPE_BZ",
    "0:0:446174653a20:Mail:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:44656c6976657265642d546f3a20:Mail:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:44656c69766572792d646174653a20:Mail:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:456e76656c6f70652d746f3a20:Mail:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:466f723a20:Eserv mail:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:46726f6d20:MBox:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:46726f6d3a20:Exim mail:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:48692e20546869732069732074686520716d61696c2d73656e64:Qmail bounce:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:494433:MP3:CL_TYPE_ANY:CL_TYPE_IGNORED",
    "0:0:49545346:MS CHM:CL_TYPE_ANY:CL_TYPE_MSCHM",
    "0:0:4d5a:MS-EXE/DLL:CL_TYPE_ANY:CL_TYPE_MSEXE",
    "0:0:4d6573736167652d49443a20:Mail:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:4d6573736167652d49643a20:Mail:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:4f676753:Ogg Stream:CL_TYPE_ANY:CL_TYPE_IGNORED",
    "0:0:504b0304:ZIP:CL_TYPE_ANY:CL_TYPE_ZIP",
    "0:0:504b3030504b0304:ZIP:CL_TYPE_ANY:CL_TYPE_ZIP",
    "0:0:52494646:RIFF:CL_TYPE_ANY:CL_TYPE_RIFF",
    "0:0:52494658:RIFX:CL_TYPE_ANY:CL_TYPE_RIFF",
    "0:0:52617221:RAR:CL_TYPE_ANY:CL_TYPE_RAR",
    "0:0:52656365697665643a20:Raw mail:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:52657475726e2d506174683a20:Maildir:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:52657475726e2d706174683a20:Maildir:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:535a4444:compress.exed:CL_TYPE_ANY:CL_TYPE_MSSZDD",
    "0:0:5375626a6563743a20:Mail:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:546f3a20:Mail:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:582d4170706172656e746c792d546f3a20:Mail:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:582d455653:EVS mail:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:582d456e76656c6f70652d46726f6d3a20:Mail:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:582d4f726967696e616c2d546f3a20:Mail:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:582d5265616c2d546f3a20:Mail:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:582d53696576653a20:Mail:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:582d53796d616e7465632d:Symantec:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:582d5549444c3a20:Mail:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:60ea:ARJ:CL_TYPE_ANY:CL_TYPE_ARJ",
    "0:0:626567696e20:UUencoded:CL_TYPE_ANY:CL_TYPE_UUENCODED",
    "0:0:763a0a52656365697665643a20:VPOP3 Mail (UNIX):CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:763a0d0a52656365697665643a20:VPOP3 Mail (DOS):CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:789f3e22:TNEF:CL_TYPE_ANY:CL_TYPE_TNEF",
    "0:0:7f454c46:ELF:CL_TYPE_ANY:CL_TYPE_ELF",
    "0:0:b6b9acaefeffffff:CryptFF:CL_TYPE_ANY:CL_TYPE_CRYPTFF",
    "0:0:d0cf11e0a1b11ae1:OLE2 container:CL_TYPE_ANY:CL_TYPE_MSOLE2",
    "0:0:fffb90:MP3:CL_TYPE_ANY:CL_TYPE_IGNORED",
    "1:*:3c4120*(68|48)(72|52)4546:HTML data:CL_TYPE_ANY:CL_TYPE_HTML",
    "1:*:3c4120*(68|48)(72|52)6566:HTML data:CL_TYPE_ANY:CL_TYPE_HTML",
    "1:*:3c484541443e:HTML data:CL_TYPE_ANY:CL_TYPE_HTML",
    "1:*:3c48544d4c3e:HTML data:CL_TYPE_ANY:CL_TYPE_HTML",
    "1:*:3c486561643e:HTML data:CL_TYPE_ANY:CL_TYPE_HTML",
    "1:*:3c48746d6c3e:HTML data:CL_TYPE_ANY:CL_TYPE_HTML",
    "1:*:3c494652414d45:HTML data:CL_TYPE_ANY:CL_TYPE_HTML",
    "1:*:3c494d47:HTML data:CL_TYPE_ANY:CL_TYPE_HTML",
    "1:*:3c496d67:HTML data:CL_TYPE_ANY:CL_TYPE_HTML",
    "1:*:3c4f424a454354:HTML data:CL_TYPE_ANY:CL_TYPE_HTML",
    "1:*:3c4f626a656374:HTML data:CL_TYPE_ANY:CL_TYPE_HTML",
    "1:*:3c534352495054:HTML data:CL_TYPE_ANY:CL_TYPE_HTML",
    "1:*:3c536372697074:HTML data:CL_TYPE_ANY:CL_TYPE_HTML",
    "1:*:3c5441424c45:HTML data:CL_TYPE_ANY:CL_TYPE_HTML",
    "1:*:3c6120*(68|48)(72|52)4546:HTML data:CL_TYPE_ANY:CL_TYPE_HTML",
    "1:*:3c6120*(68|48)(72|52)6566:HTML data:CL_TYPE_ANY:CL_TYPE_HTML",
    "1:*:3c686561643e:HTML data:CL_TYPE_ANY:CL_TYPE_HTML",
    "1:*:3c68746d6c3e:HTML data:CL_TYPE_ANY:CL_TYPE_HTML",
    "1:*:3c696672616d65:HTML data:CL_TYPE_ANY:CL_TYPE_HTML",
    "1:*:3c696d67:HTML data:CL_TYPE_ANY:CL_TYPE_HTML",
    "1:*:3c6f626a656374:HTML data:CL_TYPE_ANY:CL_TYPE_HTML",
    "1:*:3c736372697074:HTML data:CL_TYPE_ANY:CL_TYPE_HTML",
    "1:*:3c7461626c65:HTML data:CL_TYPE_ANY:CL_TYPE_HTML",
    "1:*:4d5a{60-300}50450000:PE:CL_TYPE_ANY:CL_TYPE_MSEXE",
    "1:*:504b0304:ZIP-SFX:CL_TYPE_ANY:CL_TYPE_ZIPSFX",
    "1:*:526172211a0700:RAR-SFX:CL_TYPE_ANY:CL_TYPE_RARSFX",
    "1:*:60ea{7}0002:ARJ-SFX:CL_TYPE_ANY:CL_TYPE_ARJSFX",
    "1:*:60ea{7}0102:ARJ-SFX:CL_TYPE_ANY:CL_TYPE_ARJSFX",
    "1:*:60ea{7}0202:ARJ-SFX:CL_TYPE_ANY:CL_TYPE_ARJSFX",
    "1:*:a3484bbe986c4aa9994c530a86d6487d41553321454130(35|36):AUTOIT:CL_TYPE_ANY:CL_TYPE_AUTOIT",
    "1:*:efbeadde4e756c6c736f6674496e7374:NSIS:CL_TYPE_ANY:CL_TYPE_NULSFT",
    "0:0:5349502d48495420285349502f48:SIP log:CL_TYPE_ANY:CL_TYPE_IGNORED",
    "1:0:3c2540204c414e4755414745203d:HTML data:CL_TYPE_ANY:CL_TYPE_HTML",
    "0:257:7573746172:TAR-POSIX:CL_TYPE_ANY:CL_TYPE_POSIX_TAR",
    "0:0:5b616c69617365735d:mirc ini:CL_TYPE_ANY:CL_TYPE_SCRIPT",
    "1:0,1024:0a(46|66)726f6d3a20{-1024}0a(4d|6d)(49|69)(4d|6d)(45|65)2d(56|76)657273696f6e3a20:Mail file:CL_TYPE_ANY:CL_TYPE_MAIL",
    "1:0,1024:0a(46|66)726f6d3a20{-2048}0a(43|63)6f6e74656e742d(54|74)7970653a20:Mail file:CL_TYPE_ANY:CL_TYPE_MAIL",
    "1:0,1024:0a(4d|6d)(49|69)(4d|6d)(45|65)2d(56|76)657273696f6e3a20{-2048}0a(43|63)6f6e74656e742d(54|74)7970653a20:Mail file:CL_TYPE_ANY:CL_TYPE_MAIL",
    "1:0,1024:0a(4d|6d)6573736167652d(49|69)643a20{-1024}0a(43|63)6f6e74656e742d(54|74)7970653a20:Mail file:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:cefaedfe:Mach-O LE:CL_TYPE_ANY:CL_TYPE_MACHO:45",
    "0:0:cffaedfe:Mach-O LE 64-bit:CL_TYPE_ANY:CL_TYPE_MACHO:45",
    "0:0:feedface:Mach-O BE:CL_TYPE_ANY:CL_TYPE_MACHO:45",
    "0:0:feedfacf:Mach-O BE 64-bit:CL_TYPE_ANY:CL_TYPE_MACHO:45",
    "0:0:377abcaf271c:7zip:CL_TYPE_ANY:CL_TYPE_7Z:47",
    "0:0:52656365697665642d5350463a20:Mail file:CL_TYPE_ANY:CL_TYPE_MAIL",
    "1:0,2048:0a(52|72)656365697665643a20{-2048}0a(43|63)6f6e74656e742d(54|74)7970653a20:Mail file:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:303730373031:CPIO NEWC:CL_TYPE_ANY:CL_TYPE_CPIO_NEWC:45",
    "0:0:303730373032:CPIO CRC:CL_TYPE_ANY:CL_TYPE_CPIO_CRC:45",
    "0:0:303730373037:CPIO ODC:CL_TYPE_ANY:CL_TYPE_CPIO_ODC:45",
    "0:0:71c7:CPIO OLD BINARY BE:CL_TYPE_ANY:CL_TYPE_CPIO_OLD:45",
    "0:0:c771:CPIO OLD BINARY LE:CL_TYPE_ANY:CL_TYPE_CPIO_OLD:45",
    "1:*:496e7374616c6c536869656c6400{292}0600000000000000????????????????0000000001:ISHIELD-MSI:CL_TYPE_ANY:CL_TYPE_ISHIELD_MSI:45",
    "0:0:255044462d:PDF document:CL_TYPE_ANY:CL_TYPE_PDF:55",
    "1:*:255044462d??2e:PDF:CL_TYPE_ANY:CL_TYPE_PDF:55",
    "1:*:257064662d??2e:PDF:CL_TYPE_ANY:CL_TYPE_PDF:55",
    "0:0:53594d430100:SYM DATFILE:CL_TYPE_ANY:CL_TYPE_IGNORED",
    "1:0,128:2f5247420a49440affffffffffffffffffffffffffffffffffffffffffffffff:PDF image:CL_TYPE_ANY:CL_TYPE_IGNORED",
    "0:0:377f0682002de218:SQLite WAL:CL_TYPE_ANY:CL_TYPE_IGNORED",
    "0:0:377f0683002de218:SQLite WAL:CL_TYPE_ANY:CL_TYPE_IGNORED",
    "0:0:53514c69746520666f726d6174203300:SQLite database:CL_TYPE_ANY:CL_TYPE_IGNORED",
    "0:0:d9d505f920a163d7:SQLite journal:CL_TYPE_ANY:CL_TYPE_IGNORED",
    "0:0:465753:SWF (uncompressed):CL_TYPE_ANY:CL_TYPE_SWF:71",
    "0:0:4d53434600000000:MS CAB:CL_TYPE_ANY:CL_TYPE_MSCAB",
    "1:*:4d53434600000000:CAB-SFX:CL_TYPE_ANY:CL_TYPE_CABSFX",
    "1:*:014344303031{2043-2443}4344303031:ISO9660:CL_TYPE_ANY:CL_TYPE_ISO9660:71",
    "1:0,32768:004245413031:UDF:CL_TYPE_ANY:CL_TYPE_UDF:180",
    "0:0:5b616c69617365735d:TAR-POSIX-CVE-2012-1419:CL_TYPE_ANY:CL_TYPE_POSIX_TAR",
    "1:8,12:19040010:SIS:CL_TYPE_ANY:CL_TYPE_SIS",
    "1:0,1024:44656c6976657265642d546f3a{-256}52656365697665643a:Mail file:CL_TYPE_ANY:CL_TYPE_MAIL",
    "0:0:0000000c6a5020200d0a870a:JPEG2000:CL_TYPE_ANY:CL_TYPE_GRAPHICS",
    "0:0:000001b3:MPEG video stream:CL_TYPE_ANY:CL_TYPE_BINARY_DATA",
    "0:0:000001ba:MPEG sys stream:CL_TYPE_ANY:CL_TYPE_BINARY_DATA",
    "1:0:cafebabe0000000?:Universal Binary:CL_TYPE_ANY:CL_TYPE_MACHO_UNIBIN:75",
    "1:0:cafebabe0000001?:Universal Binary:CL_TYPE_ANY:CL_TYPE_MACHO_UNIBIN:75",
    "1:0:cafebabe0000002?:Java class file:CL_TYPE_ANY:CL_TYPE_JAVA:75",
    "1:0:cafebabe0000003?:Java class file:CL_TYPE_ANY:CL_TYPE_JAVA:75",
    "0:0:78617221:XAR container file:CL_TYPE_ANY:CL_TYPE_XAR:75",
    "1:EOF-512:6b6f6c79:DMG container file:CL_TYPE_ANY:CL_TYPE_DMG:75",
    "0:0:fd377a585a00:XZ container file:CL_TYPE_ANY:CL_TYPE_XZ:76",
    "4:1024:482B0004:HFS+ partition:CL_TYPE_PART_ANY:CL_TYPE_PART_HFSPLUS:75",
    "4:1024:48580005:HFSX partition:CL_TYPE_PART_ANY:CL_TYPE_PART_HFSPLUS:75",
    "1:0:3c3f786d6c2076657273696f6e3d22312e3022{0-1024}3c576f726b626f6f6b:Microsoft Excel 2003 XML Document:CL_TYPE_ANY:CL_TYPE_XML_XL:80",
    "1:0:3c3f786d6c2076657273696f6e3d22312e3022{0-1024}3c776f7264446f63756d656e74:Microsoft Word 2003 XML Document:CL_TYPE_ANY:CL_TYPE_XML_WORD:80",
    "1:0:3c3f786d6c2076657273696f6e3d22312e3022{0-1024}3c??3a576f726b626f6f6b:Microsoft Excel 2003 XML Document:CL_TYPE_ANY:CL_TYPE_XML_XL:80",
    "1:0:3c3f786d6c2076657273696f6e3d22312e3022{0-1024}3c??3a776f7264446f63756d656e74:Microsoft Word 2003 XML Document:CL_TYPE_ANY:CL_TYPE_XML_WORD:80",
    "0:512:4546492050415254:Disk Image - GUID Partition Table:CL_TYPE_ANY:CL_TYPE_GPT:77",
    "1:*:3c7864703a786470:Adobe XDP - Embedded PDF:CL_TYPE_ANY:CL_TYPE_XDP:79",
    "1:0:4552{510}504d0000:Disk Image - Apple Partition Map:CL_TYPE_ANY:CL_TYPE_APM:77",
    "1:510:55aa:Disk Image - Master Boot Record:CL_TYPE_ANY:CL_TYPE_MBR:77",
    "0:4:d0cf11e0a1b11ae1:HWP embedded OLE2:CL_TYPE_ANY:CL_TYPE_HWPOLE2:82",
    "1:0:efbbbf3c3f786d6c2076657273696f6e3d22312e3022*3c4857504d4c:HWPML Document:CL_TYPE_ANY:CL_TYPE_XML_HWP:82",
    "0:0:48575020446f63756d656e742046696c652056332e3030201a0102030405:HWP3 Document:CL_TYPE_ANY:CL_TYPE_HWP3:82",
    "0:0:7b5c7274:RTF:CL_TYPE_ANY:CL_TYPE_RTF:30",
    "0:0:cafebabe:Universal Binary/Java Bytecode:CL_TYPE_ANY:CL_TYPE_MACHO_UNIBIN:46:74",
    "0:0:252150532d41646f62652d:PostScript:CL_TYPE_ANY:CL_TYPE_ANY:51:82",
    "0:0:252150532d41646f62652d:PostScript:CL_TYPE_ANY:CL_TYPE_PS:83:83",
    "0:0:252150532d41646f62652d:PostScript:CL_TYPE_ANY:CL_TYPE_PS:90",
    "1:0:(4d|6d)(49|69)(4d|6d)(45|65)2d(56|76)657273696f6e3a20{-1024}0a(43|63)6f6e74656e742d(54|74)7970653a20:MHTML file:CL_TYPE_ANY:CL_TYPE_MHTML:83:83",
    "1:*:0a(4d|6d)(49|69)(4d|6d)(45|65)2d(56|76)657273696f6e3a20{-1024}0a(43|63)6f6e74656e742d(54|74)7970653a20:MHTML file:CL_TYPE_ANY:CL_TYPE_MHTML:83:83",
    "1:0:(4d|6d)(49|69)(4d|6d)(45|65)2d(56|76)657273696f6e3a20{-1024}0a(43|63)6f6e74656e742d(54|74)7970653a20:MHTML file:CL_TYPE_ANY:CL_TYPE_MHTML:90",
    "1:*:0a(4d|6d)(49|69)(4d|6d)(45|65)2d(56|76)657273696f6e3a20{-1024}0a(43|63)6f6e74656e742d(54|74)7970653a20:MHTML file:CL_TYPE_ANY:CL_TYPE_MHTML:90",
    "0:0:252150532d41646f62652d:PostScript:CL_TYPE_ANY:CL_TYPE_ANY:84:85",
    "0:0:4C0000000114020000000000C000000000000046:Microsoft Windows Shortcut File:CL_TYPE_ANY:CL_TYPE_LNK:100",
    "0:0:435753:SWF (zlib compressed):CL_TYPE_ANY:CL_TYPE_SWF:71",
    "0:0:45474741:Egg Archive:CL_TYPE_ANY:CL_TYPE_EGG:115",
    "0:0:89504e47:PNG:CL_TYPE_ANY:CL_TYPE_GRAPHICS::121",
    "0:0:89504e47:PNG:CL_TYPE_ANY:CL_TYPE_PNG:122",
    "0:0:474946:GIF:CL_TYPE_ANY:CL_TYPE_GRAPHICS::121",
    "0:0:474946:GIF:CL_TYPE_ANY:CL_TYPE_GIF:122",
    "0:0:ffd8ff:JPEG:CL_TYPE_ANY:CL_TYPE_GRAPHICS::121",
    "0:0:ffd8ff:JPEG:CL_TYPE_ANY:CL_TYPE_JPEG:122",
    "0:0:49492a00:TIFF Little Endian:CL_TYPE_ANY:CL_TYPE_TIFF:122",
    "0:0:4d4d:TIFF Big Endian:CL_TYPE_ANY:CL_TYPE_TIFF:122",
    "0:0:7b20224d61676963223a2022434c414d4a534f4e763022:Internal properties:CL_TYPE_ANY:CL_TYPE_INTERNAL:78:119",
    "0:0:7b0a2020224d61676963223a22434c414d4a534f4e763022:Internal properties:CL_TYPE_ANY:CL_TYPE_INTERNAL:120",
    "0:0:5a5753:SWF (LZMA compressed):CL_TYPE_ANY:CL_TYPE_SWF:81",
    "0:0:49492a00:TIFF Little Endian:CL_TYPE_ANY:CL_TYPE_GRAPHICS:81:121",
    "0:0:4d4d:TIFF Big Endian:CL_TYPE_ANY:CL_TYPE_GRAPHICS:81:121",
    "1:*:377abcaf271c:7zip-SFX:CL_TYPE_ANY:CL_TYPE_7ZSFX:74",
    "1:0:3c3f786d6c2076657273696f6e3d22312e3022{0-1024}70726f6769643d22576f72642e446f63756d656e74223f3e:Microsoft Word 2003 XML Document:CL_TYPE_ANY:CL_TYPE_XML_WORD:80",
    "0:0:e4525c7b8cd8a74daeb15378d02996d3:Microsoft OneNote Document:CL_TYPE_ANY:CL_TYPE_ONENOTE:200",
    "0:0:02099900:Python 1.0 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:03099900:Python 1.1/1.2 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:892e0d0a:Python 1.3 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:04170d0a:Python 1.4 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:994e0d0a:Python 1.5 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:fcc40d0a:Python 1.6 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:fdc40d0a:Python 1.6 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:87c60d0a:Python 2.0 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:88c60d0a:Python 2.0 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:2aeb0d0a:Python 2.1 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:2beb0d0a:Python 2.1 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:2ded0d0a:Python 2.2 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:2eed0d0a:Python 2.2 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:3bf20d0a:Python 2.3 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:3cf20d0a:Python 2.3 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:45f20d0a:Python 2.3 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:59f20d0a:Python 2.4 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:63f20d0a:Python 2.4 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:6df20d0a:Python 2.4 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:6ef20d0a:Python 2.4 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:77f20d0a:Python 2.5 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:81f20d0a:Python 2.5 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:8bf20d0a:Python 2.5 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:8cf20d0a:Python 2.5 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:95f20d0a:Python 2.5 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:9ff20d0a:Python 2.5 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:a9f20d0a:Python 2.5 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:b3f20d0a:Python 2.5 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:b4f20d0a:Python 2.5 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:c7f20d0a:Python 2.6 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:d1f20d0a:Python 2.6 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:d2f20d0a:Python 2.6 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:dbf20d0a:Python 2.7 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:e5f20d0a:Python 2.7 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:eff20d0a:Python 2.7 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:f9f20d0a:Python 2.7 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:03f30d0a:Python 2.7 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:04f30d0a:Python 2.7 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:0af30d0a:PyPy 2.7 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:b80b0d0a:Python 3.0 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:c20b0d0a:Python 3.0 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:cc0b0d0a:Python 3.0 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:d60b0d0a:Python 3.0 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:e00b0d0a:Python 3.0 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:ea0b0d0a:Python 3.0 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:f40b0d0a:Python 3.0 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:f50b0d0a:Python 3.0 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:ff0b0d0a:Python 3.0 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:090c0d0a:Python 3.0 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:130c0d0a:Python 3.0 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:1d0c0d0a:Python 3.0 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:1f0c0d0a:Python 3.0 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:270c0d0a:Python 3.0 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:3b0c0d0a:Python 3.0 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:450c0d0a:Python 3.1 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:4f0c0d0a:Python 3.1 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:580c0d0a:Python 3.2 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:620c0d0a:Python 3.2 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:6c0c0d0a:Python 3.2 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:760c0d0a:Python 3.3 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:800c0d0a:Python 3.3 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:8a0c0d0a:Python 3.3 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:940c0d0a:Python 3.3 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:9e0c0d0a:Python 3.3 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:b20c0d0a:Python 3.4 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:bc0c0d0a:Python 3.4 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:c60c0d0a:Python 3.4 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:d00c0d0a:Python 3.4 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:da0c0d0a:Python 3.4 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:e40c0d0a:Python 3.4 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:ee0c0d0a:Python 3.4 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:f80c0d0a:Python 3.5.1- byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:020d0d0a:Python 3.5.1- byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:0c0d0d0a:Python 3.5.1- byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:160d0d0a:Python 3.5.1- byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:170d0d0a:Python 3.5.2+ byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:200d0d0a:Python 3.6 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:210d0d0a:Python 3.6 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:2a0d0d0a:Python 3.6 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:2b0d0d0a:Python 3.6 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:2c0d0d0a:Python 3.6 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:2d0d0d0a:Python 3.6 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:2f0d0d0a:Python 3.6 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:300d0d0a:Python 3.6 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:310d0d0a:Python 3.6 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:320d0d0a:Python 3.6 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:330d0d0a:Python 3.6 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:3e0d0d0a:Python 3.7 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:3f0d0d0a:Python 3.7 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:f00d0d0a:PyPy 3.7 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:00010d0a:PyPy 3.8 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "0:0:50010d0a:PyPy 3.9 byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    "1:0:??0d0d0a:Python 3.7 or newer byte-compiled (.pyc):CL_TYPE_ANY:CL_TYPE_PYTHON_COMPILED:200",
    NULL};
#endif
