#!/usr/bin/perl

use strict;
use warnings;

use constant PERM => 0;
use constant TEMP => 1;
use constant MAXA => 2;
use constant REAS => 3;

use constant TAKE => PERM;

# usage poolsize.pl < mpool_allocfile

my $sizeof_void_ptr;
my $overhead = 0;

my %ptrs;
my %sizes;
my %maxes;

my $maxsz = 0;

print STDERR "Parsing allocations...\n";
while(<>) {
    if(/malloc @(0x[0-9a-z]+) size (\d+) \((.*)\)/) {
	die "ptr $1 re-malloc" if defined $ptrs{$1};
	$ptrs{$1} = $2;
	$sizes{$ptrs{$1}} = [0, 0, 0, 'UNUSED'] unless defined $sizes{$ptrs{$1}};
	$maxes{$ptrs{$1}} = [0, 0] unless defined $maxes{$ptrs{$1}};
	$maxes{$ptrs{$1}}[0]++;
	$maxes{$ptrs{$1}}[1] = $maxes{$ptrs{$1}}[0] unless $maxes{$ptrs{$1}}[1] >= $maxes{$ptrs{$1}}[0];
	$maxsz = $2 unless $maxsz >= $2;
	$overhead++ if $3 eq 'new map';
	next;
    }
    if(/free @(0x[0-9a-z]+)/) {
	die "ptr $1 invalid free" unless defined $ptrs{$1};
	$sizes{$ptrs{$1}}[TEMP]++;
	$maxes{$ptrs{$1}}[0]--;
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
print STDERR "Parsing complete (size overhead = $overhead)\n";

$sizes{$ptrs{$_}}[PERM]++ foreach (keys %ptrs);
undef %ptrs;

$sizes{$_}[MAXA] = $maxes{$_}[1] foreach (keys %maxes);
undef %maxes;

$maxsz |= $maxsz>>16;
$maxsz |= $maxsz>>8;
$maxsz |= $maxsz>>4;
$maxsz |= $maxsz>>2;
$maxsz |= $maxsz>>1;
$maxsz++;

while($maxsz) {
    my $nextsz = $maxsz>>1;
    if(defined $sizes{$maxsz}) {
	$sizes{$maxsz}[REAS] = 'POW2';
    } else {
	$sizes{$maxsz} = [0, 0, 0, 'POW2'];
    }
    my $nextpow2 = $nextsz;
    while(1) {
	my $refsz = $maxsz;
	my @group;
	foreach (sort { $b <=> $a } keys %sizes) {
	    next unless $_ > $nextpow2;
	    next unless $_ <= $maxsz;
	    next unless ($sizes{$_}[TAKE] > 0 || $_ == $maxsz);
	    $nextsz = $_;
	    last unless ($refsz - $_) * $sizes{$_}[TAKE] <= $overhead;
	    $refsz = $_;
	    push @group, $_;
	}
	while($#group >= 23) {
	    my $items = $#group / 2;
	    $nextsz = $group[$items + 1];
	    @group = @group[0..$items];
	}
	print STDERR "Processing group $maxsz -> $nextsz (count ".($#group + 1).")\n";
	my @topscore; # 0 => score | 1 => used bits | origbits
	for(my $origbits = 0; $origbits < 1<<$#group ; $origbits++) {
	    my $bits = $origbits;
	    my $bitcnt = 0;
	    my $score = $overhead;
	    my $grp_size = $maxsz;

	    printf STDERR "%3i%%\r", $origbits * 100 / (1<<$#group) unless ($origbits & 1);
	    for (my $i = 1; $i<= $#group; $i++) {
		if($bits & 1) {
		    $score +=  $overhead + $sizes{$group[$i]}[TAKE] * $group[$i];
		    $bitcnt++;
		    $grp_size = $group[$i];
		} else {
		    $score += $sizes{$group[$i]}[TAKE] * $grp_size;
		}
		$bits>>=1;
	    }
	    if(!defined $topscore[0] || $score < $topscore[0] || ($score == $topscore[0] && $bitcnt > $topscore[1])) {
		@topscore = ($score, $bitcnt, $origbits);
	    }
	}
	my $bits = ($topscore[2]<<1) | 1;
	for (my $i = 0; $i<=$#group; $i++) {
	    if ($bits & 1) {
		$sizes{$group[$i]}[REAS] = "USE";
	    } else {
		$sizes{$group[$i]}[REAS] = "GROUP";
	    }
	    $bits>>=1;
	}
	last unless $nextsz < $maxsz;
	$maxsz = $nextsz;
    }
    $maxsz = $nextpow2;
}

print "/* SIZE        PERM    TEMP     MAX    ACT! */\n";
foreach (sort { $a <=> $b } keys %sizes) {
    printf "%7u, /* %7u %7u %7u %8s */\n", $_, $sizes{$_}[PERM], $sizes{$_}[TEMP], $sizes{$_}[MAXA], $sizes{$_}[REAS];
}
