#!/usr/bin/perl

use strict;
use warnings;

my %h = ();
my $added = 0;
my $found = 0;
my $notfound = 0;

while(1) {
	my $hash = '';
	last if(read(STDIN, $hash, 17) != 17);
	my $op = substr($hash, 0, 1);
	$hash = substr($hash, 1);
	if($op eq "A") {
		$h{$hash} = 1;
		$added++;
	} elsif ($op eq "C") {
		if(exists($h{$hash})) {
			$found++;
		} else {
			$notfound++;
		}
	} else {
		die "bad command $op\n";
	}
}

my $lookups = $found + $notfound;
print "added: $added\nlooked up: $lookups (found $found, not found $notfound)\n";
printf "items in the hash: ".(scalar keys %h)."\n";

