#!/usr/bin/perl
################################################################################
# Script for converting local user accounts to ldif for import into RedHat
# Identity Manager or freeipa (CentOS/Fedora)
################################################################################

use warnings;
use strict;

# Using builtin perl module for retrieving host name
use Sys::Hostname;

# Die if UID is not root
if ($> != 0) {
	die "Must run with root privileges: $!";
}

# Split hostname on '.' and then reformat to LDIF dn suffix format

my @fqdn = split(/\./,hostname);
if (($#fqdn == 0) || ($fqdn[1] eq 'localdomain')) {
	print "FQDN could not be determined automatically. Please enter FQDN: ";
	my $userinput = <STDIN>;
	chomp $userinput;
	if ($userinput eq "") {
		print "Null string not accepted. Please try again.\n";
		exit 0;
	}else{
		@fqdn = split(/\./,$userinput);
	}
}
my $domain=$fqdn[1];
my $dc="dc=".join(",dc=",@fqdn[1..$#fqdn]);
my $host=$fqdn[0];
print "Using $host as Hostname. Output will be in $host.ldif\n";
print "Using $dc as LDAP suffix.\n";

my %shadow;
my %passwd;
my %group;

open SHADOW, "< /etc/shadow" or die "Could not open /etc/shadow: $!";
while (<SHADOW>) {
	chomp;
	next if /^\s*#/;
	my @f = split /:/;
	if (($f[1] ne '!!') && ($f[1] ne '*')) {
		@{$shadow{$f[0]}} = @f;
	}
}
open PASSWD, "< /etc/passwd" or die "Could not open /etc/passwd: $!";
while (<PASSWD>) {
	chomp;
	next if /^\s*#/;
	my @g = split /:/;
	if ((exists $shadow{$g[0]}) && ($g[2] >= 100)) {
		@{$passwd{$g[0]}} = @g;
		$passwd{$g[0]}[1] = $shadow{$g[0]}[1];
	}
}
open GROUP, "< /etc/group" or die "Could not open /etc/group: $!";
while (<GROUP>) {
	chomp;
	next if /^\s*#/;
	my @h = split /:/;
	if ((defined $h[3]) && ($h[2] >= 100)) {
		@{$group{$h[0]}} = @h;
	}
}
open OUTPUT, "> $host.ldif" or die "Could not open ./$host.ldif: $!";

print OUTPUT "dn: $dc\n";
print OUTPUT "objectClass: dcObject\n";
print OUTPUT "objectClass: organization\n";
print OUTPUT "dc: $domain\n";
print OUTPUT "o: $domain\n";
print OUTPUT "\n\n";

print OUTPUT "dn: ou=Users,$dc\n";
print OUTPUT "ou: Users\n";
print OUTPUT "objectClass: top\n";
print OUTPUT "objectClass: organizationalUnit\n";
print OUTPUT "\n\n";

print OUTPUT "dn: ou=Groups,$dc\n";
print OUTPUT "ou: Groups\n";
print OUTPUT "objectClass: top\n";
print OUTPUT "objectClass: organizationalUnit\n";
print OUTPUT "\n\n";

for my $key (keys %passwd) {
	if (length($passwd{$key}[4]) == 0) {
		$passwd{$key}[4] = $key;
	}
	my @name = split(/ /,$passwd{$key}[4]);
	print OUTPUT "dn: cn=$key,ou=Users,$dc\n";
	print OUTPUT "cn: $passwd{$key}[4]\n";
	print OUTPUT "givenName: $name[0]\n";
	print OUTPUT "sn: $name[-1]\n";
	print OUTPUT "uid: $key\n";
	print OUTPUT "uidNumber: $passwd{$key}[2]\n";
	print OUTPUT "homeDirectory: $passwd{$key}[5]\n";
	print OUTPUT "loginShell: $passwd{$key}[6]\n";
	print OUTPUT "ObjectClass: top\n";
	print OUTPUT "ObjectClass: shadowAccount\n";
	print OUTPUT "ObjectClass: posixAccount\n";
	print OUTPUT "userPassword: {crypt}$passwd{$key}[1]\n";
	print OUTPUT "shadowLastChange: $shadow{$key}[2]\n";
	print OUTPUT "shadowMin: $shadow{$key}[3]\n";
	print OUTPUT "shadowMax: $shadow{$key}[4]\n";
	print OUTPUT "shadowWarning: $shadow{$key}[5]\n";
	print OUTPUT "\n\n";
}

for my $key (keys %group) {
	print OUTPUT "dn: cn=$key,ou=Groups,$dc\n";
	print OUTPUT "cn: $key\n";
	print OUTPUT "objectClass: top\n";
	print OUTPUT "objectClass: groupOfNames\n";
	my @members = split(/,/,$group{$key}[3]);
	for my $member (@members) {
		print OUTPUT "member: cn=$member,ou=Users,$dc\n";
	}
	print OUTPUT "\n\n";
}
