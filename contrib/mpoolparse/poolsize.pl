#!/usr/bin/perl

use strict;
use warnings;

# usage poolsize.pl < mpool_spamfile

my $sizeof_void_ptr;
my $overhead = 0;

my %ptrs;
my %sizes;

my $maxsz = 0;

while(<>) {
    if(/malloc @(0x[0-9a-z]+) size (\d+) \((.*)\)/) {
	die "ptr $1 re-malloc" if defined $ptrs{$1};
	$ptrs{$1} = $2;
	$sizes{$ptrs{$1}} = [0, 0, ''] unless defined $sizes{$ptrs{$1}};
	$maxsz = $2 unless $maxsz >= $2;
	$overhead++ if $3 eq 'new map';
	next;
    }
    if(/free @(0x[0-9a-z]+)/) {
	die "ptr $1 invalid free" unless defined $ptrs{$1};
	$sizes{$ptrs{$1}}[0]++;
	delete $ptrs{$1};
	next;
    }
    if(/Map created @.*voidptr=(\d+)/) {
	$sizeof_void_ptr = $1;
	next;
    }
    chomp;
    print STDERR "warning bogus line:\n$_\n";
}

$overhead *= $sizeof_void_ptr;

foreach (keys %ptrs) {
    $sizes{$ptrs{$_}}[1]++;
}

$maxsz |= $maxsz>>16;
$maxsz |= $maxsz>>8;
$maxsz |= $maxsz>>4;
$maxsz |= $maxsz>>2;
$maxsz |= $maxsz>>1;
$maxsz++;

while($maxsz) {
    if(defined $sizes{$maxsz}) {
	$sizes{$maxsz}[2] = 'POW2';
    } else {
	$sizes{$maxsz} = [0, 0, 'POW2'];
    }
    $maxsz>>=1;
}

my $grp_size = 0;
foreach (sort { $b <=> $a } keys %sizes) {
    my $count = $sizes{$_}[1];
    my $score = ($grp_size - $_) * $count - $overhead;
    $score = 0 unless $grp_size != 0;

    if($score >= 0 || $sizes{$_}[2] eq 'POW2') {
	$grp_size = $_;
	if($score >=0) {
	    $sizes{$_}[2] = $sizes{$_}[2] eq 'POW2' ? 'USE/POW2' : 'USE';
	}
    } else {
	$sizes{$_}[2] = 'GROUP';
    }
}

print "/* SIZE        PERM    TEMP    ACT! */\n";
foreach (sort { $a <=> $b } keys %sizes) {
    printf "%7u, /* %7u %7u %8s */\n", $_, $sizes{$_}[1], $sizes{$_}[0], $sizes{$_}[2];
}
