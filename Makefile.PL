# $Id: Makefile.PL,v 1.2 1998/06/08 22:15:10 dsully Exp dsully $

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
