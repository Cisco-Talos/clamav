#!perl -w
use strict;

sub  byte($)  {pack 'c',$_[0]};
sub ubyte($)  {pack 'C',$_[0]};
sub uword($)  {pack 'v',$_[0]};
sub ulong($)  {pack 'V',$_[0]};

my $RESV_HEADER = 'reserved header test 12345';
#my $RESV_HEADER = '';
#my $RESV_FOLDER = 'reserved folder test 12345';
my $RESV_FOLDER = '';
my $RESV_DATA   = 'reserved data test 12345';
#my $RESV_DATA   = '';

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
  . uword(2)   # 1C number of files
  . uword(4)   # 1E flags
  . uword(1)   # 20 set id
  . uword(0)   # 22 cab index

  . uword(length($RESV_HEADER))   # 00 header reserved
  . ubyte(length($RESV_FOLDER))   # 02 folder resv
  . ubyte(length($RESV_DATA))     # 03 data resv
  . $RESV_HEADER
;

my $folder
  = ulong(0)  # data offset
  . uword(2)  # number of blocks
  . uword(0)  # compression method
  . $RESV_FOLDER
;

my $files
  = ulong(5) # uncompressed size
  . ulong(0) # folder offset
  . uword(0) # folder index
  . uword(0x226C) # time
  . uword(0x59BA) # date
  . uword(0x20)   # attribs
  . "test1.txt\0"

  . ulong(5) # uncompressed size
  . ulong(5) # folder offset
  . uword(0) # folder index
  . uword(0x226C) # time
  . uword(0x59BA) # date
  . uword(0x20)   # attribs
  . "test2.txt\0"
;

my $datablocks
  = ulong(0) # checksum
  . uword(5) # compressed size
  . uword(5) # uncompressed size
  . $RESV_DATA
  . "TEST\n" # actual data

  . ulong(0) # checksum
  . uword(5) # compressed size
  . uword(5) # uncompressed size
  . $RESV_DATA
  . "test\n" # actual data
;

my $pre_files = $header . $folder;
my $pre_data  = $pre_files . $files;
my $cab       = $pre_data . $datablocks;

substr($header, 0x08, 4, ulong(length($cab)));
substr($header, 0x10, 4, ulong(length($pre_files)));
substr($folder, 0x00, 4, ulong(length($pre_data)));

print $header . $folder . $files . $datablocks;
