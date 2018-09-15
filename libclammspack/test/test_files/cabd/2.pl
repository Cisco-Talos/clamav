#!perl -w
use strict;

sub  byte($)  {pack 'c',$_[0]};
sub ubyte($)  {pack 'C',$_[0]};
sub uword($)  {pack 'v',$_[0]};
sub ulong($)  {pack 'V',$_[0]};

my $header
  = 'MSCF'     # 00 SIGNATURE
  . ulong(0)   # 04
  . ulong(0)   # 08 CABINET SIZE
  . ulong(0)   # 0C
  . ulong(0)   # 10 FILES OFFSET
  . ulong(0)   # 14
  . ubyte(3)   # 18 MINOR VERSION
  . ubyte(1)   # 19 MAJOR VERSION
  . uword(1)   # 1A number of folders
  . uword(3)   # 1C number of files
  . uword(1)   # 1E flags
  . uword(12345) # 20 set id
  . uword(4)   # 22 cab index
  . "cabd_multi_basic_pt4.cab\0"
  . "basic multipart test part 4\0"

;

my $folder
  = ulong(0)  # data offset
  . uword(1)  # number of blocks
  . uword(0)  # compression method
;

my $files
  = ulong(76) # uncompressed size
  . ulong(0) # folder offset
  . uword(0xFFFD) # folder index
  . uword(0x226C) # time
  . uword(0x59BA) # date
  . uword(0x20)   # attribs
  . "test1.txt\0"

  . ulong(38) # uncompressed size
  . ulong(76) # folder offset
  . uword(0xFFFD) # folder index
  . uword(0x226C) # time
  . uword(0x59BA) # date
  . uword(0x20)   # attribs
  . "test2.txt\0"

  . ulong(76) # uncompressed size
  . ulong(76+38) # folder offset
  . uword(0xFFFD) # folder index
  . uword(0x226C) # time
  . uword(0x59BA) # date
  . uword(0x20)   # attribs
  . "test3.txt\0"
;

my $datablocks
  = ulong(0) # checksum
  . uword(38) # compressed size
  . uword(190) # uncompressed size
  . "This is the data from cabinet part 5.\n" # actual data
;

my $pre_files = $header . $folder;
my $pre_data  = $pre_files . $files;
my $cab       = $pre_data . $datablocks;

substr($header, 0x08, 4, ulong(length($cab)));
substr($header, 0x10, 4, ulong(length($pre_files)));
substr($folder, 0x00, 4, ulong(length($pre_data)));

print $header . $folder . $files . $datablocks;
