#!/usr/bin/perl
#	$Id: basic.pl,v 1.2 1998/06/08 15:31:17 cvs Exp $
#
## Copyright (c) 1998 Nigel Metheringham. All rights reserved.
## This program is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
#
use strict;
use Authcard::SDI qw( /^ACM_/ );
use Term::ReadLine;
use Carp;

my $ver = ' $Id: basic.pl,v 1.2 1998/06/08 15:31:17 cvs Exp $ ';

#
# Basically a small, pretty nasty, example of how to put the functions
# together...
#

sub prompt {
    my($term,
       $prompt,
       $default) = @_;
    
    my $fullprompt = $prompt;
    $fullprompt .= " [$default]" if ($default);
    my $response = $term->readline("$fullprompt: ");
    chomp($response);
    if (length($response) == 0) {
	return $default if ($default);
	print "[no response - giving up]\n";
	exit;
    }
    return $response;
}



sub print_data {
    my($res, $sdi) = @_;
    
    print "[Return status code = $res, (", $sdi->constant_name($res), ")]\n";
    print "\tusername = ", $sdi->username, "\n";
    print "\tapplication_id = ", $sdi->application_id, "\n";
    print "\tprotectdir = ", $sdi->protectdir, "\n";
    print "\trelease_code = ", $sdi->release_code, "\n";
    print "\tshell = ", $sdi->shell, "\n";
    print "\tvalidated_passcode = ", $sdi->validated_passcode, "\n";
    if ($res == ACM_NEW_PIN_REQUIRED) {
	print "fixed_pin_size\t = ", $sdi->fixed_pin_size, "\n";
	print "\tmin_pin_len = ", $sdi->min_pin_len, "\n";
	print "\tmax_pin_len = ", $sdi->max_pin_len, "\n";
	print "\tsystem_pin = ", $sdi->system_pin, "\n";
	print "\tuser_selectable = ", $sdi->user_selectable, "\n";
    }
    if ($res == ACM_NEXT_CODE_REQUIRED) {
	print "\ttimeout = ", $sdi->timeout, "\n";
    }
    return;    
}

my $term = Term::ReadLine->new("Authcard::SDI Test Harness");

print "Authcard::SDI Test Harness - starting up\n\t$ver\n";
my $sdi = new Authcard::SDI;

if (defined($sdi)) {
    print "Initialised Authcard::SDI OK\n";
} else {
    print "Initialisation of  Authcard::SDI failed\n";
    print "Check the permissions of the sdconf.rec file\n";
    croak();
}

my $user = prompt($term, "User to authenticate", $ENV{'USER'}||getpwuid($<));
my $code = prompt($term, "Passcode (PIN + Tokencode)");
print "[Calling check() with user=$user, code=$code]\n";
my $res = $sdi->check($code, $user);

print_data($res, $sdi);
exit if (($res == ACM_OK) || ($res == ACM_ACCESS_DENIED));

if ($res == ACM_NEXT_CODE_REQUIRED) {
    my $nextcode = prompt($term, "NEXT Passcode");
    print "[Calling next() with code=$nextcode]\n";
    $res = $sdi->next($nextcode);
    print_data($res, $sdi);
    exit if (($res == ACM_OK) || ($res == ACM_ACCESS_DENIED));
}

if ($res == ACM_NEW_PIN_REQUIRED) {
    my $pin = prompt($term, "Enter PIN");
    print "[Calling pin() with pin=$pin, cancelled=0]\n";
    $res = $sdi->pin($pin, 0);
    print_data($res, $sdi);
    exit if (($res == ACM_NEW_PIN_ACCEPTED) || ($res == ACM_NEW_PIN_REJECTED));
}

print "Unexpected return code...\n";
exit;
