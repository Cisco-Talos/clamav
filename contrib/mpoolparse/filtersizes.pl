#!/usr/bin/perl
# Usage:
# perl poolsize.pl <log >log_sizes
# perl filtersizes.pl <voidptrsize> <sizeoverhead> <log_sizes >log_final
# (for example: perl filtersizes.pl 4 1252 <log_sizes >log_final)
use strict;
use warnings;
my %size_counts;
my @sizes;
die "Usage: filtersizes.pl <voidptrsize> <sizeoverhead>\n" if $#ARGV != 1;
my $size_overhead = $ARGV[1];
my $voidptrsize = $ARGV[0];
while (<STDIN>) {
    if (/(\d+).+(\d+)\s+(\d+)\s+(\d+).+ USE/) {
	$size_counts{$1} = $4;
	push @sizes, $1;
    }
}
my $pow2 = $voidptrsize;
my $max_overhead = 2*$size_overhead;
for (my $i = 0; $i < $#sizes-1; $i++) {
    my $size = $sizes[$i];
    my $count = $size_counts{$size};
    my $waste = $count*($sizes[$i+1]-$size);
    # keep power of 2 sizes
    if ($size == $pow2) {
	$pow2 <<= 1;
	next;
    }
    # if removing this size adds less overhead then max, remove it
    next unless $waste <= $max_overhead || $size < $voidptrsize;
    $size_counts{$sizes[$i+1]} += $count;
    delete $size_counts{$size};
}
foreach (sort { $a <=> $b } keys %size_counts)
{
    printf "%7u, /* %7u */\n", $_, $size_counts{$_};
}
