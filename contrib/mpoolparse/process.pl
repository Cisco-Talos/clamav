#!/usr/bin/perl
use strict;
use warnings;

my %reallocs;
my %mallocs;
while (<>) {
    if (/realloc @ 0x([0-9a-f]+)/) {
	$reallocs{$1}="";
    }
    if (/malloc 0x([0-9a-f]+) size ([0-9]+)/) {
	$mallocs{$1}=$2;
    }
}
my %sizes;
while (my ($address, $size) = each(%mallocs)) {
    if (not defined $reallocs{$address}) {
	$sizes{$size}++;
    }
}
while (my ($size, $count) = each(%sizes)) {
    print "$size, /* $count */\n";
}
