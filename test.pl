# $Id: test.pl,v 1.18 1998/06/08 15:36:12 cvs Exp $
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

my $DEBUG = 1;

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..65\n"; }
END {print "not ok 1\n" unless $loaded;}
use Authcard::SDI qw[ /^ACM_/ ];
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

# remember this needs access to sdconf.rec
my $sdi = new Authcard::SDI;
print (($sdi ? "" : "not "), "ok 2\n");

# test all the constants - should all be non-zero other than ACM_OK
my $test = 3;
my $name;
foreach $name (qw[ACM_ACCESS_DENIED
		  ACM_ENTRY_ERR
		  ACM_LOG_ACK
		  ACM_NEW_PIN_ACCEPTED
		  ACM_NEW_PIN_REJECTED
		  ACM_NEW_PIN_REQUIRED
		  ACM_NEXT_CODE_BAD
		  ACM_NEXT_CODE_OK
		  ACM_NEXT_CODE_REQUIRED
		  ACM_OK
		  ACM_PC_BAD
		  ACM_PC_OK
		  ACM_SHELL_BAD
		  ACM_SHELL_OK
		  ACM_SUSPECT_ACK
		  ACM_TIME_OK ] ) {
    my $val = eval($name);
    print ((defined($val) 
	    ? "ok " 
	    : "not ok "), $test++, "\n");
    # check value maps to name OK
    print (((Authcard::SDI::constant_name($val) eq $name) 
	    ? "ok " 
	    : "not ok "), $test++, "\n");
    # and again as a method
    print ((($sdi->constant_name($val) eq $name) 
	    ? "ok " 
	    : "not ok "), $test++, "\n");
}
undef $name;

# these tests are to check that the code is linked in OK -
# the results are going to be a bit useless without getting
# authentication input....
print ((defined($sdi->application_id) ? "ok " : "not ok "), "51\n");
print ((defined($sdi->username) ? "ok " : "not ok "), "52\n");
print ((defined($sdi->passcode_time) ? "ok " : "not ok "), "53\n");
print ((defined($sdi->validated_passcode) ? "ok " : "not ok "), "54\n");
print ((defined($sdi->shell) ? "ok " : "not ok "), "55\n");
print ((defined($sdi->release_code) ? "ok " : "not ok "), "56\n");
print ((defined($sdi->protectdir) ? "ok " : "not ok "), "57\n");
print ((defined($sdi->time_delta) ? "ok " : "not ok "), "58\n");
print ((defined($sdi->timeout) ? "ok " : "not ok "), "59\n");
print ((defined($sdi->fixed_pin_size) ? "ok " : "not ok "), "60\n");
print ((defined($sdi->system_pin) ? "ok " : "not ok "), "61\n");
print ((defined($sdi->min_pin_len) ? "ok " : "not ok "), "62\n");
print ((defined($sdi->max_pin_len) ? "ok " : "not ok "), "63\n");
print ((defined($sdi->user_selectable) ? "ok " : "not ok "), "64\n");
print ((defined($sdi->alphanumeric) ? "ok " : "not ok "), "65\n");

# you cannot test anything else without requiring interventio...

undef $sdi;
