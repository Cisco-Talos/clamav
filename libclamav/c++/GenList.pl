#!/usr/bin/perl
use strict;
use warnings;

my $path = $ARGV[0];
`(cd $path/tools/llvm-config; make ENABLE_OPTIMIZED=0 llvm-config-perobjincl)`;

my %compdeps;
my @codegencomponents = ('x86codegen','powerpccodegen','armcodegen');
my @allnonsys = ('support','jit','fullcodegen',@codegencomponents);
my @allcomponents= ('system',@allnonsys);
my $allJIT="jit core lib/Support/SourceMgr.o lib/Analysis/PointerTracking.o lib/Transforms/Scalar/DCE.o lib/Analysis/IPA/CallGraph.o";
for my $component (@allcomponents) {
    $/ = " ";
    $component =~ s/^fullcodegen/codegen interpreter jit target/;
    if ($component =~ "^jit") {
	open DEPS, "$path/tools/llvm-config/llvm-config-perobjincl --libnames $allJIT|";
    } else {
	open DEPS, "$path/tools/llvm-config/llvm-config-perobjincl --libnames $component|";
    }
    $component =~ s/^codegen.+/fullcodegen/;
    while (<DEPS>) {
	chomp;
	s/[\n\r]//;
	next if (!/\.o$/);
        s/Support\/reg(.*).o/Support\/reg$1.c/;
	s/\.o$/.cpp/;
	$compdeps{$component}{$_}=1;
    }
    close DEPS or die "llvm-config failed";
}

# System is always linked in, so remove it from all else
foreach my $systemcomp (keys %{$compdeps{'system'}}) {
    foreach my $component (@allnonsys) {
	delete $compdeps{$component}{$systemcomp} if defined $compdeps{$component}{$systemcomp};
    }
}

# Eliminate components from codegen that are in JIT already.
# and compute common codegen components.
my %intersection = ();
my %count = ();

foreach my $codegen (@codegencomponents) {
    my %newdeps;
    for my $depobj (keys %{$compdeps{$codegen}}) {
	next if $compdeps{'jit'}{$depobj};
	$newdeps{$depobj}=1;
	$count{$depobj}++;
    }
    $compdeps{$codegen} = \%newdeps;
}
foreach my $element (keys %count) {
    $intersection{$element}=1 if $count{$element} > 1;
}

foreach my $codegen (@codegencomponents) {
    foreach my $element (keys %intersection) {
       delete $compdeps{$codegen}{$element};
    }
    # Move the system and support objs required (even if not common) to codegen,
    # since these were already built for tblgen.
    foreach my $element (keys %{$compdeps{'system'}}) {
       next unless defined $compdeps{$codegen}{$element};
       delete $compdeps{$codegen}{$element};
       $intersection{$element}=1;
    }
    foreach my $element (keys %{$compdeps{'support'}}) {
       next unless defined $compdeps{$codegen}{$element};
       delete $compdeps{$codegen}{$element};
       $intersection{$element}=1;
    }
}

@allcomponents=(@allcomponents,'codegen');
$compdeps{'codegen'}=\%intersection;
foreach my $comp (keys %{$compdeps{'codegen'}}) {
    delete $compdeps{'fullcodegen'}{$comp};
}
foreach my $comp (keys %{$compdeps{'jit'}}) {
    delete $compdeps{'fullcodegen'}{$comp};
}
foreach my $comp (keys %{$compdeps{'support'}}) {
    $compdeps{'support_nodups'}{$comp}=1;
}

foreach my $comp (keys %{$compdeps{'jit'}}) {
    next unless defined $compdeps{'support_nodups'}{$comp};
    delete $compdeps{'support_nodups'}{$comp};
}
@allcomponents=(@allcomponents,'codegen','support_nodups');

foreach my $comp (@allcomponents) {
    print "libllvm$comp"."_la_SOURCES=";
    foreach my $dep (sort keys %{$compdeps{$comp}}) {
	print "\\\n\tllvm/$dep";
    }
    print "\n\n";
}

