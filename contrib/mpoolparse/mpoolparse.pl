#!/usr/bin/perl

use strict;
use warnings;

my %frags = ();

while (<>) {
	chomp;
	next unless /^LibClamAV Warning: [mc]alloc .* size (\d+) .*$/;
	$frags{$1}++;
}

foreach (sort {$a<=>$b} (keys(%frags))) {
	print "$_, /* ($frags{$_}) */\n";
}

