#!/usr/bin/perl -w
use strict;
use Encode qw(encode);
use bigint;

my $clen  = 4096; # standard chunk length
my $max_entries = $clen - 22; # max free space for entries in one chunk

sub u1($) { pack 'C', $_[0] }
sub u2($) { pack 'v', $_[0] }
sub u4($) { pack 'V', $_[0] }
sub u8($) { pack 'Q<', $_[0] }

sub guid($) {
    my @x = split /-/, $_[0];
    return pack 'VvvnH12', (map hex, @x[0..3]), $x[4];
}

sub encint($) {
  my ($in, $out) = ($_[0] >> 7, u1($_[0] & 0x7F));
  while ($in) {
     $out = u1(0x80 | ($in & 0x7F)) . $out;
     $in >>= 7;
  }
  return $out;
}

sub entry {
    my ($name, $section, $offset, $length) = @_;
    return encint(length $name)
        . $name
        . encint($section)
        . encint($offset)
        . encint($length);
}

sub chunk {
    my @entries = @_;

    my $chdr = 'PMGL' # PMGL id
        . u4(0)        # 0x04 free space (FIXUP)
        . u4(0)        # 0x08 unknown
        . u4(-1)       # 0x0C previous chunk (FIXUP)
        . u4(-1)       # 0x10 next chunk (FIXUP)
        ;              # 0x14 SIZEOF
    my $cdata = join '', @entries;

    my $cfree = $clen - length($cdata) - length($chdr);
    die if length($cdata) > $max_entries;

    # append empty "free space" area and number of entries
    my $chunk = $chdr
        . $cdata
        . (u1(0) x ($cfree - 2))
        . u2(scalar @entries);

    # fixup free space in header
    substr($chunk, 0x04, 4, u4($cfree));
    return $chunk;
}

sub hdr {
    my $guid1 = guid('7C01FD10-7BAA-11D0-9E0C-00A0C922E6EC');
    my $guid2 = guid('7C01FD11-7BAA-11D0-9E0C-00A0C922E6EC');
    return 'ITSF'    # 0x00 id
        . u4(2)      # 0x04 version
        . u4(0x58)   # 0x08 total header length
        . u4(1)      # 0x0C unknown
        . u4(0)      # 0x10 timestamp
        . u4(0x409)  # 0x14 language (english)
        . $guid1     # 0x18 GUID
        . $guid2     # 0x28 GUID
        . u8(0)      # 0x38 hdr0 offset (FIXUP)
        . u8(0)      # 0x40 hdr0 length (FIXUP)
        . u8(0)      # 0x48 hdr1 offset (FIXUP)
        . u8(0)      # 0x50 hdr1 length (FIXUP)
        ;            # SIZEOF: 0x54
}

sub hs0 {
    return u4(0x1FE) # 0x00 unknown
        . u4(0)      # 0x04 unknown
        . u8(0)      # 0x08 file size (FIXUP)
        . u4(0)      # 0x10 unknown
        . u4(0)      # 0x14 unknown
        ;            # SIZEOF: 0x18
}

sub hs1 {
    my $cmax = shift;
    my $guid3 = guid('5D02926A-212E-11D0-9DF9-00A0C922E6EC');
    return 'ITSP'       # 0x00 id
        . u4(1)         # 0x04 unknown
        . u4(0x54)      # 0x08 dir header length
        . u4(0x0A)      # 0x0C unknown
        . u4($clen)     # 0x10 dir chunk size
        . u4(2)         # 0x14 quickref density
        . u4(1)         # 0x18 index depth
        . u4(-1)        # 0x1C root PMGI chunk
        . u4(0)         # 0x20 first PMGL chunk
        . u4($cmax)     # 0x24 last PMGL chunk
        . u4(-1)        # 0x28 unknown
        . u4(1)         # 0x2C number of chunks
        . u4(0x904)     # 0x30 language
        . $guid3        # 0x34 GUID
        . u4(0x54)      # 0x44 header length
        . u4(-1)        # 0x48 unknown
        . u4(-1)        # 0x4C unknown
        . u4(-1)        # 0x50 unknown
        ;                 # SIZEOF: 0x54
}

sub chm {
    my @chunks = @_;
    my ($hdr, $hs0, $hs1) = (hdr(), hs0(), hs1($#chunks));
    substr($hdr, 0x38, 8, u8(length($hdr))); # hs0 offset
    substr($hdr, 0x40, 8, u8(length($hs0))); # hs0 length
    substr($hdr, 0x48, 8, u8(length($hdr) + length($hs0))); # hs1 offset
    substr($hdr, 0x50, 8, u8(length($hs1))); # hs1 length
    substr($hs0, 0x08, 8, u8(length($hdr) + length($hs0) + length($hs1) + ($clen * @chunks))); # chm length
    for (my $i = 1; $i <= $#chunks; $i++) {
        substr($chunks[$i],     0x0C, 4, u4($i - 1)); # previous chunk
        substr($chunks[$i - 1], 0x10, 4, u4($i));     # next chunk
    }
    return join '', $hdr, $hs0, $hs1, @chunks;
}

# Create a CHM with the filename "::" right at the end of a PMGL chunk
#
# libmspack < 0.9.1alpha calls memcmp() on any entry beginning "::" to see if
# it begins "::DataSpace/Storage/MSCompressed/" (33 bytes), even when the name
# is shorter. If the entry is right at the end of a chunk, we can get libmspack
# to overread past the end of the chunk by up to 28 bytes
sub chm_sysname_overread {
    if (open my $fh, '>', 'cve-2019-1010305-name-overread.chm') {
        my $sysname = entry('::', 0, 0, 0);
        my $padding = entry('x' x $clen, 0, 0, 0);
        my $padding_overhead = length($padding) - $clen;
        my $maxlen = $max_entries - length($sysname) - $padding_overhead;
        $padding = entry('x' x $maxlen, 0, 0, 0);
        print $fh chm(chunk($padding, $sysname));
        close $fh;
    }
}

# Create a CHM with entries containing unicode character U+100
sub chm_unicode_u100 {
    if (open my $fh, '>', 'cve-2018-14682-unicode-u100.chm') {
        my $u100 = encode('UTF-8', chr(256));
        my $entry1 = entry("1", 0, 1, 1);
        my $entry2 = entry($u100, 0, 2, 2);
        print $fh chm(chunk($entry1, $entry2));
        close $fh;
    }
}

# Create a CHM with ENCINTs that go beyond what 32-bit architectures can handle
sub chm_encints_32bit {
    chm_encints('encints-32bit-offsets.chm', 2147483647, 1, 0);
    chm_encints('encints-32bit-lengths.chm', 2147483647, 0, 1);
    chm_encints('encints-32bit-both.chm',    2147483647, 1, 1);
}

# Create a CHM with ENCINTs that go beyond what 64-bit architectures can handle
sub chm_encints_64bit {
    chm_encints('encints-64bit-offsets.chm', 9223372036854775807, 1, 0);
    chm_encints('encints-64bit-lengths.chm', 9223372036854775807, 0, 1);
    chm_encints('encints-64bit-both.chm',    9223372036854775807, 1, 1);
}

sub chm_encints {
    my ($fname, $max_good, $off_val, $len_val) = @_;
    my @vals = (
        127, 128, # 1->2 byte encoding
        16383, 16384, # 2->3 byte encoding
        2097151, 2097152, # 3->4 byte encoding
        268435455, 268435456, # 4->5 byte encoding
        2147483647, 2147483648, # 2^31-1, 2^31 (doesn't fit in 32-bit off_t)
        34359738367, 34359738368, # 5->6 byte encoding
        4398046511103, 4398046511104, # 6->7 byte encoding
        562949953421311, 562949953421312, # 7->8 byte encoding
        72057594037927935, 72057594037927936, # 8->9 byte encoding
        9223372036854775807, 9223372036854775808, # 2^63-1, 2^63 (doesn't fit in 64-bit off_t)
        147573952589676412927, 147573952589676412928, # 9->10 byte encoding
        1180591620717411303423, 1180591620717411303424, # 10->11 byte encoding
        151115727451828646838271, 151115727451828646838272, # 11->12 byte encoding
        19342813113834066795298815, 19342813113834066795298816); # 12->13 byte encoding
    my @entries;
    my $i = 0;
    for my $val (@vals) {
        my $name = sprintf '%s%02i', $val <= $max_good ? 'good' : 'bad', $i++;
        my $offset = $off_val ? $val : 1;
        my $length = $len_val ? $val : 1;
        push @entries, entry($name, 0, $offset, $length);
    }
    if (open my $fh, '>', $fname) {
        print $fh chm(chunk(@entries));
        close $fh;
    }
}

chm_sysname_overread();
chm_unicode_u100();
chm_encints_32bit();
chm_encints_64bit();
