package Authcard::SDI;
#	$Id: SDI.pm,v 1.13 1998/06/08 15:31:17 cvs Exp $

## Copyright (c) 1998 Nigel Metheringham. All rights reserved.
## This program is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.

use strict;
use Carp;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK $AUTOLOAD);

require Exporter;
require DynaLoader;
require AutoLoader;

@ISA = qw(Exporter DynaLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
);
@EXPORT_OK = qw(
        ACM_ACCESS_DENIED
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
        ACM_TIME_OK
);

# Version number
$VERSION = '1.00';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.  If a constant is not found then control is passed
    # to the AUTOLOAD in AutoLoader.

    my $constname;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    my $val = constant($constname, @_ ? $_[0] : 0);
    if ($! != 0) {
        if ($! =~ /Invalid/) {
            $AutoLoader::AUTOLOAD = $AUTOLOAD;
            goto &AutoLoader::AUTOLOAD;
        }
        else {
                croak "Your vendor has not defined Authcard::SDI macro $constname";
        }
    }
    eval "sub $AUTOLOAD { $val }";
    goto &$AUTOLOAD;
}


bootstrap Authcard::SDI $VERSION;

# Preloaded methods go here.
sub constant_name {
    my $val = shift;		# could be ref or int depending how called
    $val = shift if (ref($val)); # dump self reference if passed
    return(Authcard::SDI::_constant_name($val));
}

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Authcard::SDI - Perl extension for user authentications with SecurID token

=head1 SYNOPSIS

  use Authcard::SDI;

  $sdi = new Authcard::SDI;
  $res = $sdi->auth();          # check authorisation using tty i/f
  $res = $sdi->check($tokencode, $user);
                                # check a tokencode for a user
  $res = $sdi->next($nextcode); # check a next token code
  $res = $sdi->pin($pin,$cancelled)
                                # register a pin

=head1 DESCRIPTION

A perl encapsulation of the B<ACE/SecurID> API in a slightly OO fashion.

The main API functions are all implemented as methods of the
B<Authcard::SDI> object, the names are the same as the B<ACE/SecurID>
API without the C<sd_> prefix.  The version of the API implemented is
for the B<ACE/SecurID> version 1.3 server.

The B<ACE/SecurID> API is not at all thread-safe, and having more than
one B<Authcard::SDI> is likely to break things.  The API is closed and
has lumps of global static data around making this problem difficult
to work around cleanly.

=head2 new()

The B<new> invocation creates a new B<ACE/SecurID> object.  It will
fail if there is insufficient memory of if the underlying calls cannot
complete (C<creadcfg()> and C<sd_init()>).  Specifically the local
system must be configured to be able to see a B<SecurId> server and
the user running the code must be able to read the config file
(normally in F</var/ace/sdconf.rec>).  If the initialisation fails an
undefined value is returned.

=head2 auth($user)

B<auth> provides the all-in-one authentication function including all
authentication prompts and responses (e.g., "Enter PASSCODE";
"PASSCODE accepted"; "Access denied") on the current tty.

If the optional C<user> parameter is passed then authentication is
performed for the selected user, otherwise the user is grubbed out
from the environment.

Return values are:-

=over 4

=item ACM_OK

User successfully authenticated.  The shell method will give you their
shell as registered in the SecurID server.

=item ACM_ACCESS_DENIED

User failed authentication. 

=back

=head2 check($tokencode, $username)

B<check> performs authentication by checking the validity of the
TOKENCODE entered by a user.  The integrating application must do all
I/O - check does not display the authentication prompts and
messages.

Input arguments:-

=over 4

=item tokencode

The tokencode string.  The tokencode must contain 4-16 characters.

=item username

The username string.  The username must contain fewer than 32
characters.

=back

Return values are:-

=over 4

=item ACM_OK

User successfully authenticated.  The shell method will give you their
shell as registered in the SecurID server.

=item ACM_ACCESS_DENIED

User failed authentication. 

=item ACM_NEXT_CODE_REQUIRED

Next tokencode required.  The number of seconds the server will wait
for a user response to the next-code prompt can be obtained from the
B<timeout()> method.  Use B<next()> to complete the transaction.

=item ACM_NEW_PIN_REQUIRED

New PIN required.  The following items can be obtained by calling the
apppropriate methods:-

=over 4

=item system_pin

Random PIN generated by system

=item min_pin_len

Minimum PIN length

=item max_pin_len

Maximum PIN length

=item user_selectable

=over 4

=item CANNOT_CHOOSE_PIN

The user must either accept a system-generated PIN or cancel the
operation and leave the token in New PIN mode.

=item MUST_CHOOSE_PIN

The user must create his or her own PIN.  Do not give the user the
option of receiving a system-generated PIN.

=item USER_SELECTABLE

The user can create his or her own PIN or can request a
system-generated one.

=back

=back

=back

=head2 next($nextcode)

B<next> is used in response to an ACM_NEXT_CODE_REQUIRED return from
C<check()>.  B<next> performs the Next Code operation which takes a
second successive tokencode from a user and checks its validity.  The
integrating application must do all I/O because B<next> does not
display the Next Code prompt.

Input arguments:-

=over 4

=item nextcode

The tokencode string.  The tokencode must contain 4-16 characters.

=back

Return values are:-

=over 4

=item ACM_OK

User successfully authenticated.  The shell method will give you their
shell as registered in the SecurID server.

=item ACM_ACCESS_DENIED

User failed authentication. 

=back

=head2 pin($pin, $cancelled)

pin performs the New PIN operation in which a new PIN is stored in a
token record.  The integrating application must do all I/O because
B<pin()> does not display the New PIN prompts and messages.  B<pin()>
should be called only in response to an ACM_NEW_PIN_REQUIRED returned
from B<check()>.

Input arguments:-

=over 4

=item pin

The tokencode string.  The tokencode must contain 4-16 characters.

=item cancelled

This value should be false if a PIN is to be selected.  If a token is
in New PIN mode but you do not want to select the PIN at that time,
sd_pin should be called with the value set to a true value.

=back

Return values are:-

=over 4

=item ACM_NEW_PIN_ACCEPTED

The new PIN has been accepted by the ACE/Server.  The user should now
be required to authenticate with it.

=item ACM_NEW_PIN_REJECTED

The new PIN was rejected by the ACE/Server.  The PIN may not have
matched the parameters set in the return from B<check()>.

=back

=head2 Client object access methods

The following fields from the SD_CLIENT object defined by the
B<ACE/SecurID> API can be accessed using the methods of the same name.
They cannot be modified at this time other than username which may be
set by passing a suitable length string as a parameter.

The value returned is either an integer or a string depending on the
type declared in the B<ACE/SecurID> API.

=over 4

=item alphanumeric()

=item application_id()

=item fixed_pin_size()

=item max_pin_len()

=item min_pin_len()

=item passcode_time()

=item protectdir()

=item release_code()

=item shell()

=item system_pin()

=item time_delta()

=item timeout()

=item user_selectable()

=item username()

=item validated_passcode()

=back

=head2 Costants defined by the ACE/SecurID API

The following constants are defined and may be exported from the
module:- 

=over 4

=item ACM_ACCESS_DENIED

=item ACM_ENTRY_ERR

=item ACM_LOG_ACK

=item ACM_NEW_PIN_ACCEPTED

=item ACM_NEW_PIN_REJECTED

=item ACM_NEW_PIN_REQUIRED

=item ACM_NEXT_CODE_BAD

=item ACM_NEXT_CODE_OK

=item ACM_NEXT_CODE_REQUIRED

=item ACM_OK

=item ACM_PC_BAD

=item ACM_PC_OK

=item ACM_SHELL_BAD

=item ACM_SHELL_OK

=item ACM_SUSPECT_ACK

=item ACM_TIME_OK

=back

=head1 AUTHOR

Nigel Metheringham <nigel@pobox.com>

=head1 SEE ALSO

perl(1) clientapi(3) creadcfg(3) sd_auth(3) sd_check(3) sd_close(3)
sd_init(3) sd_next(3) sd_pin(3).

=cut
