# $Id: Makefile.PL,v 1.1.1.1 1998/12/16 23:05:29 daniel Exp $

use ExtUtils::MakeMaker;

sub MY::libscan {
	my($self,$path) = @_;
	return '' if $path =~ /RCS/;
	$path;
}

WriteMakefile(
	'NAME'		=> 'Apache::AuthenRadius',
	'VERSION_FROM'	=> 'AuthenRadius.pm', 
	'PREREQ_PM'	=> { Authen::Radius => 0.05 },
	'dist'		=> { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
);
