#!/usr/bin/perl
# (C) 2008  Török Edwin <edwin@clamav.net>
# parse <!ENTITY declarations and output them in the format
# used by generate_entitylist.c
# Format is EntityName,EntityValue.
# Only accepts entity values 0 < V < 0xffff, and doesn't accept entities that have multiple values assigned.
while(<>) {
	chomp;
	if(/<!ENTITY +([^ \t]+)[ \t]+\" *([^ \"]+) *\" *>/) {
		$name = $1;
		$v = $2;
		if($v =~ /^&(#38;)?#([^;]+);$/) {
			$valx = $2;
			my $value;
			if($valx =~ /^x([0-9a-fA-F]+)$/) {
				$value = hex($valx);
				if($value > 0xffff) {
					printf STDERR "TOOBIG $_\n"
				} else {
					printf "$name,%d\n", $value
				}
			} elsif($valx =~ /^[0-9]+$/) {
				if($valx > 0xffff) {
					print STDERR "TOOBIG $_\n";
				} else {
					printf "$name,%d\n", $valx
				}
			} else {
				print "unknown1: $_\n";
			}
		} elsif($v =~ /^(&#x[0-9a-fA-F]+;)+$/) {
			print STDERR "MULTIPLECHARS $name $1\n";
		} else {
			print "unknown2: $_\n";
		}
	} elsif(/.*<!ENTITY.*/) {
		if($_ !~ /.*(PUBLIC|SYSTEM).*/) {
			print "unknown3: $_\n";
		}
	}
}
