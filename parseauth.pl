#!/usr/bin/env perl
################################################################################
# Standard defs **ALWAYS** use strict and warnings
################################################################################
use strict;
use warnings;

my $argnum = 0;
my $line;
my $timestamp;
my $date;
my $time;
my $facsev;
my $facility;
my $severity;
my $hostname;
my $tag;
my $pid;
my $msg;
my @logrecords;

################################################################################
# Parse lines from logfile, discarding service checks, stunnel messages, 
# selinux setcon errors, publickey and sftp notices.
# Store lines in an array so references can be removed/overwritten
# for /etc/passwd user failures when they succeed with sssd (ipa). Array 
# indices are skipped if defined as 'undef'.
################################################################################
foreach $argnum (0...$#ARGV) {
	open(my $fh, "<", $ARGV[$argnum]) or die "cannot open < $ARGV[$argnum]: $!";
	my $i = 0;
	while(<$fh>) {
		chomp;
		next if /ssh_selinux_change_context: setcon failed with Invalid argument/;
		next if /Received disconnect from .+ disconnected by user/;
		next if /Postponed publickey for /;
		next if /subsystem request for sftp/;
		next if /stunnel/;
		$line = $_;
		($timestamp,$facsev,$hostname,$tag,$msg) = split(' ',$line,5); 
		($date,$time) = split('T',$timestamp,2);
		$facsev =~ s/<|>//g;
		($facility,$severity) = split(',',$facsev,2);
		if ($tag =~ m/(\d+)/) {
			$pid = $1;
			$tag =~ s/(\w+).\d+../$1/;
		}
		if ($msg =~ m/authentication success/) {
			if ($pid) {
				for my $index (reverse 0..$#logrecords) {
					if (($logrecords[$index]) && $logrecords[$index] =~ m/$pid/ && $logrecords[$index] =~ m/failure/) {
						splice(@logrecords, $index, 1, ());
					}
				}
			}
		}
		if ($msg =~ m/session closed/) {
			if ($pid) {
				for my $index (reverse 0..$#logrecords) {
					if (($logrecords[$index]) && $logrecords[$index] =~ m/$pid/ && $logrecords[$index] =~ m/Accepted \S+ for /) {
						splice(@logrecords, $index, 1, ());
					} elsif (($logrecords[$index]) && $logrecords[$index] =~ m/$pid/ && $logrecords[$index] =~ m/session opened/) {
						splice(@logrecords, $index, 1, ());
					}
				}
				$line = undef;
			}
		}
	push @logrecords, $line;	
	}
	for my $index (0..$#logrecords) {
		if ($logrecords[$index]) {
		print("$logrecords[$index]\n");
		}
	}
}
