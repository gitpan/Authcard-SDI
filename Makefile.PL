# $Id: Makefile.PL,v 1.6 1998/06/08 15:31:16 cvs Exp $
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
#
## Copyright (c) 1998 Nigel Metheringham. All rights reserved.
## This program is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
#
# Tweak these as reqiured
my $AceBaseDirectory = '/usr/ace'; # where the base of the ace tree is
my $Architecture = 'sun';
my $AceLibrary = join('/', $AceBaseDirectory, $Architecture);
WriteMakefile(
	      'NAME'		=> 'Authcard::SDI',
	      'VERSION_FROM' 	=> 'SDI.pm',
				# finds $VERSION
	      'LIBS'		=> ["-L$AceLibrary -lsdiclient"],
				# e.g., '-lm' 
	      'DEFINE'		=> '',
				# e.g., '-DHAVE_SOMETHING' 
	      'INC'		=> "-I$AceLibrary",
				# e.g., '-I/usr/include/other' 
	      'TYPEMAPS'	=> ['perlobject.map' ],
	     );
