#!/usr/bin/perl -w
use strict;
my $name = '123456789';
for my $file (0 .. 9) {
    for my $ext (0 .. 4) {
        open my $fh, '>', "f$file$ext.kwj";
        my $offset = 14  + $file + $ext;
        my $flags  = ($file > 0 ? 8 : 0) | ($ext > 0 ? 16 : 0);
        print $fh pack 'A4Vvvv', 'KWAJ', 0xD127F088, 0, $offset, $flags;
        print $fh substr $name, 0, $file if $file > 0;
        print $fh "\0" if $file > 0 && $file < 9;
        print $fh substr $name, 0, $ext if $ext > 0;
        print $fh "\0" if $ext > 0 && $ext < 4;
        print $fh "\xFF";
        close $fh;
    }
}
