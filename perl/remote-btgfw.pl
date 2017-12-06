#!/usr/bin/perl -w

use IO::KQueue;
use IO::Socket;
use Socket;
use Crypt::Mode::CBC;

use constant {
	SOCKS5_VERSION => 5,
	REQ_HEADER_LEN => 4,
	CLIENT         => 1,
	REMOTE         => 2,
	BUFFER_LEN     => 8096,
	RESERVED       => 0,
};

# Method
use constant {
	NO_AUTH_REQUIRED => 0x0,
	GSSAPI           => 0x1,
	USERNAME_PASSWD  => 0x2,
	NO_ACCEPTABLE_METHODS => 0xFF,
};

use constant {
	SUCCEEDED      => 0,
	SERVER_FAILURE => 1,
	NOT_ALLOWED    => 2,
	NETWORK_UNREACHABLE => 3,
	HOST_UNREADCHABLE   => 4,
	CONNECTION_REFUSED  => 5,
	TTL_EXPIRED         => 6,
	COMMAND_NOT_SUPPORTED => 7,
	ADDRESS_TYPE_NOT_SUPPORTED => 8,
};

use constant {
	EXMETHOD    => 0,
	AUTH        => 1,
	EXHOST      => 2,
	STREAMING   => 3,
};

# CMD
use constant {
	CONNECT  => 1,
	BIND     => 2,
	UDP      => 3,
};

# Type
use constant {
	IPV4     => 1,
	DONAME   => 3,
	IPV6     => 4,
};

if (scalar(@ARGV) != 3) {
	print "Usage:\n";
	print "  ./remote-btgfw <local port> <username> <password>\n";
	exit 1;
}

my $local_port = shift;
my $user = shift;
my $pass = shift;
my $plen = length($pass);

if ($plen != 16) {
	print "the length of password is not 16\n";
	exit 1;
}

my $server;
my $serverfd;
my $kq;
my %socket_map;

my $iv = "abcdefg987654321";
my $cbc = Crypt::Mode::CBC->new('AES');

sub local_server_init {
	$server = IO::Socket::INET->new(
		LocalAddr => "127.0.0.1:$local_port",
		Listen => 128,
		Blocking => 0,
		Reuse => 1,
	);
	IO::Handle::blocking($server, 0);
	$kq = IO::KQueue->new();
	$serverfd = fileno $server;
	$kq->EV_SET($serverfd, EVFILT_READ, EV_ADD, 0, 5);
}

sub signal_registation {
	$SIG{PIPE}  = 'IGNORE';
	$SIG{HUP}   = sub { die "caught SIGHUP"; };
	$SIG{TERM}  = sub { die "caught SIGTERM"; };
}

sub do_accept {
	my $client = $server->accept();
	IO::Handle::blocking($client, 0);
	if (! $client) {
		print "accept() failed: $!";
		return;
	}

	my $fd = fileno $client;
	$kq->EV_SET($fd, EVFILT_READ, EV_ADD);

	my %sock = (
		type => CLIENT,
		sock => $client,
		state => EXMETHOD,
		recvbuf => '',
		remotefd => 0,
	);
	$socket_map{$fd} = \%sock;
	printf "accept incoming from %s:%d. open socket: %d\n",
		$client->peerhost, $client->peerport, $fd;
}

sub client_event {
	my $clientfd = shift;
	my $sock = shift;

	my $client_state = \$socket_map{$clientfd}{state};
	my $recvbuf = \$socket_map{$clientfd}{recvbuf};
	my $remotefd = \$socket_map{$clientfd}{remotefd};

	my $buffer;
	my $blen = $$sock->read($buffer, BUFFER_LEN);

	if (!$blen) {
		# eof
		print "close socket: $clientfd\n";
		delete $socket_map{$clientfd};
		$kq->EV_SET($clientfd, EVFILT_READ, EV_DELETE);
		$$sock->close;
		return;
	}

	if ($blen == -1) {
		# error
		print "close socket: $clientfd\n";
		delete $socket_map{$clientfd};
		$kq->EV_SET($clientfd, EVFILT_READ, EV_DELETE);
		$$sock->close;
		return;
	}

	$$recvbuf .= $buffer;
	my $recvlen = length($$recvbuf);

	if ($$client_state == EXMETHOD) {
		return unless $recvlen >= 3;
		my ($ver, $nmethod, $method) = unpack("C C C", $$recvbuf);
		if ($ver != SOCKS5_VERSION) {
			print "not socks5. close socket: $clientfd\n";
			delete $socket_map{$clientfd};
			$kq->EV_SET($clientfd, EVFILT_READ, EV_DELETE);
			$$sock->close;
		} else {
			my $bin = pack("C C", $ver, $method);
			$$sock->write($bin);
			$$client_state = $method == USERNAME_PASSWD ? AUTH : EXHOST;
			$$recvbuf = substr($$recvbuf, 3);
		}
	} elsif ($$client_state == AUTH) {
		return unless $recvlen >= 2;
		my ($ver, $ulen) = unpack("C C", $$recvbuf);
		if ($ver != SOCKS5_VERSION) {
			print "not socks5. close socket: $clientfd\n";
			delete $socket_map{$clientfd};
			$kq->EV_SET($clientfd, EVFILT_READ, EV_DELETE);
			$$sock->close;
			return;
		}

		return unless $recvlen >= 2 + $ulen + 1;
		my ($username, $plen) = unpack("a$ulen C", substr($$recvbuf, 2));
		return unless $recvlen >= 2 + $ulen + 1 + $plen;
		my $passwd = unpack("a$plen", substr($$recvbuf, 2 + $ulen + 1));
		my $plainuser = $cbc->decrypt($username, $pass, $iv);
		my $plainpass = $cbc->decrypt($passwd, $pass, $iv);
		if (($plainuser eq $user) && ($plainpass eq $pass)) {
			my $bin = pack("C C", $ver, 0);
			$$sock->write($bin);
			$$client_state = EXHOST;
		} else {
			print "incorrect username or password. close socket: $clientfd\n";
			my $bin = pack("C C", $ver, 0);
			$$sock->write($bin);
			delete $socket_map{$clientfd};
			$kq->EV_SET($clientfd, EVFILT_READ, EV_DELETE);
			$$sock->close;
			return;
		}
		$$recvbuf = substr($$recvbuf, 2 + $ulen + 1 + $plen);
	} elsif ($$client_state == EXHOST) {
		return unless $recvlen >= 4;
		my $cipherdata_len = unpack("i", $$recvbuf);
		return unless $recvlen >= $cipherdata_len + 4;
		my $plaindata =
			$cbc->decrypt(substr($$recvbuf, 4, $cipherdata_len), $pass, $iv);
		my $plaindata_len = length($plaindata);
		return unless $plaindata_len >= REQ_HEADER_LEN;
		my ($ver, $cmd, $rsv, $atyp) = unpack("C C C C", $plaindata);
		if ($ver != SOCKS5_VERSION) {
			print "not socks5. close socket: $clientfd\n";
			delete $socket_map{$clientfd};
			$kq->EV_SET($clientfd, EVFILT_READ, EV_DELETE);
			$$sock->close;
			return;
		}

		if (($cmd != CONNECT) && ($cmd != BIND) && ($cmd != UDP)) {
			print "unsupport cmd: $cmd. close socket: $clientfd\n";
			delete $socket_map{$clientfd};
			$kq->EV_SET($clientfd, EVFILT_READ, EV_DELETE);
			$$sock->close;
			return;
		}

		if ($atyp == IPV4) {
			return unless $plaindata_len >= REQ_HEADER_LEN + 4 + 2;
			my ($ip0, $ip1, $ip2, $ip3, $port) =
				unpack("C C C C n", substr($plaindata, REQ_HEADER_LEN));
			my $ip = sprintf("%d.%d.%d.%d", $ip0, $ip1, $ip2, $ip3);
			my $remote = IO::Socket::INET->new(
					PeerAddr => $ip,
					PeerPort => "$port",
					Proto => 'tcp',
					Timeout => 0.5);
			if (! $remote) {
				print "connect to $ip:$port timeout.",
					" close socket: $clientfd\n";
				my $bin = pack("C C C C I S",
						SOCKS5_VERSION, SUCCEEDED, RESERVED, IPV4,
						unpack("N", inet_aton($ip)), $port);
				$$sock->write($bin);
				delete $socket_map{$clientfd};
				$kq->EV_SET($clientfd, EVFILT_READ, EV_DELETE);
				$$sock->close;
				return;
			}

			$$remotefd = fileno $remote;
			IO::Handle::blocking($remote, 0);
			my $bin = pack("C C C C I S", SOCKS5_VERSION, SUCCEEDED, RESERVED,
					IPV4, unpack("N", inet_aton($ip)), $port);
			$$sock->write($bin);
			my %sock = (
				type => REMOTE,
				sock => $remote,
				clientfd => $clientfd,
			);
			$socket_map{$$remotefd} = \%sock;
			$kq->EV_SET($$remotefd, EVFILT_READ, EV_ADD);
			$$recvbuf = substr($plaindata, REQ_HEADER_LEN + 4 + 2);
			print "connected to $ip:$port.",
				" open tunnel: $clientfd <--> $$remotefd\n";
		} elsif ($atyp == DONAME) {
			my $doname_len = unpack("C", substr($plaindata, REQ_HEADER_LEN));
			return unless $plaindata_len >= REQ_HEADER_LEN + 1 + $doname_len + 2;
			my ($doname, $port) =
				unpack("a$doname_len n", substr($plaindata, REQ_HEADER_LEN + 1));
			my $remote = IO::Socket::INET->new(PeerAddr => $doname,
							   PeerPort => "$port",
							   Proto => 'tcp',
							   Timeout => 0.5);
			if (! $remote) {
				print "connect to $doname:$port timeout.",
					" close socket: $clientfd\n";
				my $bin = pack("C C C C C a$doname_len n",
						SOCKS5_VERSION, SUCCEEDED, RESERVED, DONAME,
						1 + $doname_len + 2, $doname, $port);
				$$sock->write($bin);
				delete $socket_map{$clientfd};
				$kq->EV_SET($clientfd, EVFILT_READ, EV_DELETE);
				$$sock->close;
				return;
			}

			$$remotefd = fileno $remote;
			IO::Handle::blocking($remote, 0);
			my $ip = unpack("N", inet_aton($remote->sockhost()));
			my $bin = pack("C C C C I n", SOCKS5_VERSION, SUCCEEDED,
					RESERVED, IPV4, $ip, $port);
			$$sock->write($bin);
			my %sock = (
				type => REMOTE,
				sock => $remote,
				clientfd => $clientfd,
			);
			$socket_map{$$remotefd} = \%sock;
			$kq->EV_SET($$remotefd, EVFILT_READ, EV_ADD);
			$$recvbuf = substr($plaindata, REQ_HEADER_LEN + 1 + $doname_len + 2);
			print "connected to $doname:$port.",
				" open tunnel: $clientfd <--> $$remotefd\n";
		} elsif ($atyp == IPV6) {
			# TODO
		} else {
			print "unsupport type: $atyp. close socket: $clientfd\n";
			delete $socket_map{$clientfd};
			$kq->EV_SET($clientfd, EVFILT_READ, EV_DELETE);
			$$sock->close;
			return;
		}

		$$client_state = STREAMING;
	} elsif ($$client_state == STREAMING) {
		return unless $recvlen >= 4;
		my $len = unpack("I", $$recvbuf);
		return unless $recvlen >= $len + 4;
		my $cipherdata = unpack("a$len", substr($$recvbuf, 4));
		my $rawdata = $cbc->decrypt($cipherdata, $pass, $iv);
		my $remote = \$socket_map{$$remotefd}{sock};
		if (defined $$remote) {
			$$remote->write($rawdata);
		}
		$$recvbuf = substr($$recvbuf, $len + 4);
	}
}

sub remote_event {
	my $remotefd = shift;
	my $sock = shift;

	my $clientfd = \$socket_map{$remotefd}{clientfd};

	my $buffer;
	my $blen = $$sock->read($buffer, BUFFER_LEN);

	if (! $blen) {
		# eof
		print "close socket: $remotefd\n";
		delete $socket_map{$remotefd};
		$kq->EV_SET($remotefd, EVFILT_READ, EV_DELETE);
		$$sock->close;
	} elsif ($blen < 0) {
		print "close socket: $remotefd\n";
		delete $socket_map{$remotefd};
		$kq->EV_SET($remotefd, EVFILT_READ, EV_DELETE);
		$$sock->close;
	} else {
		my $client = \$socket_map{$$clientfd}{sock};
		if (defined $$client) {
			print "found tunnel: $remotefd <--> $$clientfd\n";
			$$client->write($buffer);
		}
	}
}

sub main {
	local_server_init();
	signal_registation();

	while (1) {
		my @ret = $kq->kevent();
		if (!@ret) {
			die "No kevents: $!";
		}

		foreach my $kevent (@ret) {
			my $fd = $kevent->[KQ_IDENT];

			if ($fd == $serverfd) {
				do_accept();
				next;
			}

			my $sock = \$socket_map{$fd}{sock};
			my $type = \$socket_map{$fd}{type};

			if (! $$sock) {
				print "unknown fd: $fd\n";
				next;
			}

			if ($$type == CLIENT) {
				client_event($fd, \$$sock);
			} else {
				remote_event($fd, \$$sock);
			}
		}
	}
}

main();

