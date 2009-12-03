#!/usr/bin/perl

use strict;
use warnings;

my ($event, $trace);
my %locks;
my $t;

while(<>) {
	chomp;
	next if /^#/;
	if (/^\s+(.*)-\d+\s+\[\d+\]\s+[0-9.]+: (.*) \(([0-9.]+) us\)$/) {
		$locks{$trace} += $t if defined $t;
		$t = $3;
		$trace="$1: $2\n";
		next;
	}
	next unless s/^ => ([^\s])/$1/;
	$trace.="$_\n";
}
$locks{$trace} += $t+0 if defined $t;

foreach (sort { $locks{$b} <=> $locks{$a} } keys %locks) {
	last unless $locks{$_} >= 100000;
	my @bt = split "\n";
	print "--- $locks{$_} us --- $bt[0]\n";
	my $i;
	for ($i = 1; $i <= $#bt; $i++) {
		my $l = $bt[$i];
		if ($l =~ /^(\/.*)\[\+(0x.*)\]$/) {
			my $path = $1;
			my $addr = $2;
			my $code = `addr2line -fe "$path" $addr`;
			my @spam = split("\n", $code);
			if ($? != 0) {
				$code = "$addr";
			} else {
				$code = "$spam[0] - $spam[1]";
			}
			$l = "$path [$code]";
		} elsif ($l =~ /^ /) {
			$l.=" (unknown)";
		} else {
			$l.=" (kernel)";
		}

		print "$l\n";
	}
	print "\n";
}
