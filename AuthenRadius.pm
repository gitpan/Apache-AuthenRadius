package Apache::AuthenRadius;

# $Id: AuthenRadius.pm,v 1.2 1999/07/31 22:14:23 daniel Exp $

use strict;
use Apache ();
use Apache::Constants qw(OK AUTH_REQUIRED DECLINED SERVER_ERROR);
use Authen::Radius;
use vars qw($VERSION);

$VERSION = '0.3';

sub handler {
	my $r = shift;
	
	# Continue only if the first request.
	return OK unless $r->is_initial_req;

	my $reqs_arr = $r->requires;
	return OK unless $reqs_arr;

	# Grab the password, or return if HTTP_UNAUTHORIZED
	my($res,$pass) = $r->get_basic_auth_pw;
	return $res if $res;

	# Get the user name.
	my $user = $r->connection->user;

	# Radius Server and port.
	my $host    = $r->dir_config("Auth_Radius_host") or return DECLINED;
	my $port    = $r->dir_config("Auth_Radius_port") || 1647;

	# Shared secret for the host we are running on.
	my $secret  = $r->dir_config("Auth_Radius_secret") or return DECLINED;

	# Timeout to wait for a response from the radius server.
	my $timeout = $r->dir_config("Auth_Radius_timeout") || 5;

	# Sanity for usernames and passwords.
	if (length $user > 64 or $user =~ /[^A-Za-z0-9]/) {
		$r->log_reason("Apache::AuthenRadius username too long or"
			."contains illegal characters", $r->uri);
		$r->note_basic_auth_failure;
		return AUTH_REQUIRED;
	}

	if (length $pass > 256) {
		$r->log_reason("Apache::AuthenRadius password too long",$r->uri);
		$r->note_basic_auth_failure;
		return AUTH_REQUIRED;
	}

	# Create the radius connection.
	my $radius = Authen::Radius->new(
		Host => "$host:$port",
		Secret => $secret,
		TimeOut => $timeout
	);

	# Error if we can't connect.
	if (!defined $radius) {
		$r->log_reason("Apache::AuthenRadius failed to"
			."connect to $host: $port",$r->uri);
		return SERVER_ERROR;
	}
	
	# Do the actual check.
	if ($radius->check_pwd($user,$pass)) {
		return OK;
	} else {
		$r->log_reason("Apache::AuthenRadius failed for user $user",
			$r->uri);
		$r->note_basic_auth_failure;
		return AUTH_REQUIRED;
	}
}

1;

__END__

=head1 NAME

Apache::AuthenRadius - Authentication via a Radius server

=head1 SYNOPSIS

 # Configuration in httpd.conf

 PerlModule Apache::AuthenRadius

 # Authentication in .htaccess

 AuthName Radius
 AuthType Basic

 # authenticate via Radius
 PerlAuthenHandler Apache::AuthenRadius

 PerlSetVar Auth_Radius_host radius.foo.com
 PerlSetVar Auth_Radius_port 1647
 PerlSetVar Auth_Radius_secret MySharedSecret
 PerlSetVar Auth_Radius_timeout 5

 require valid-user

=head1 DESCRIPTION

This module allows authentication against a Radius server.

=head1 LIST OF TOKENS

=item *
Auth_Radius_host

The Radius server host: either its name or its dotted quad IP number.
The parameter is passed as the PeerHost option to IO::Socket::INET->new.

=item *
Auth_Radius_port

The port on which the Radius server is listening: either its service
name or its actual port number. This parameter defaults to "1647"
which is the official service name for Radius servers. The parameter
is passed as the PeerPort option to IO::Socket::INET->new.

=item *
Auth_Radius_secret

The shared secret for connection to the Radius server.

=item *
Auth_Radius_timeout

The timeout in seconds to wait for a response from the Radius server.

=head1 CONFIGURATION

The module should be loaded upon startup of the Apache daemon.
Add the following line to your httpd.conf:

 PerlModule Apache::AuthenRadius

=head1 PREREQUISITES

For AuthenRadius you need to enable the appropriate call-back hook 
when making mod_perl: 

  perl Makefile.PL PERL_AUTHEN=1

=head1 SEE ALSO

L<Apache>, L<mod_perl>, L<Authen::Radius>

=head1 AUTHORS

=item *
mod_perl by Doug MacEachern <dougm@osf.org>

=item *
Authen::Radius by Carl Declerck <carl@miskatonic.inbe.net>

=item *
Apache::AuthenRadius by Daniel Sully <daniel-cpan-authenradius@electricrain.com>

=head1 COPYRIGHT

The Apache::AuthenRadius module is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

=cut
