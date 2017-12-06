#!/usr/bin/perl -w

use IO::KQueue;
use IO::Socket;
use Socket;

use constant {
	SOCKS5_VERSION => 5,
	REQ_HEADER_LEN => 4,
	PORT_LEN       => 2,
	CLIENT         => 1,
	REMOTE         => 2,
	BUFFER_LEN     => 8096,
	RESERVED       => 0,
};

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
	EXHOST      => 1,
	STREAMING   => 2,
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

#
use constant {
	USERNAME => 'test',
	PASSWD   => 'test',
};

my $local_port = shift || 1086;

`networksetup -setsocksfirewallproxystate Wi-Fi off`;
`networksetup -setsocksfirewallproxy Wi-Fi localhost $local_port`;

my $server = IO::Socket::INET->new(
	LocalAddr => "127.0.0.1:$local_port",
	Listen => 128,
	Blocking => 0,
	Reuse => 1,
);

# Must ignore SIGPIPE, or it will exit.
$SIG{PIPE}  = 'IGNORE';
$SIG{HUP}   = sub { die "caught SIGHUP"; };
$SIG{TERM}  = sub { die "caught SIGTERM"; };

IO::Handle::blocking($server, 0);

my $kq = IO::KQueue->new();
my $serverfd = fileno $server;

$kq->EV_SET($serverfd, EVFILT_READ, EV_ADD, 0, 5);

my %socket_map;

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
		stage => EXMETHOD,
		ci => '',
		remotefd => 0,
	);
	$socket_map{$fd} = \%sock;
	print "accept incoming. open socket: $fd\n";
}

sub client_event {
	my $fd = shift;
	my $sock = shift;

	my $stage = \$socket_map{$fd}{stage};
	my $ci = \$socket_map{$fd}{ci};
	my $remotefd = \$socket_map{$fd}{remotefd};

	my $buffer;
	my $blen = $$sock->read($buffer, BUFFER_LEN);

	if (!$blen) {
		# eof
		print "close socket: $fd\n";
		delete $socket_map{$fd};
		$kq->EV_SET($fd, EVFILT_READ, EV_DELETE);
		$$sock->close;
	} elsif ($blen == -1) {
		# error
		die "read error on $fd: $!";
	} else {
		if ($$stage == EXMETHOD) {
			$$ci .= $buffer;
			if ((length $$ci) != 3) {
				return;
			}

			my ($ver, $nmethod, $method) = unpack("C C C", $$ci);
			if ($ver != SOCKS5_VERSION) {
				print "not socks5. close socket: $fd\n";
				delete $socket_map{$fd};
				$kq->EV_SET($fd, EVFILT_READ, EV_DELETE);
				$$sock->close;
			} else {
				my $bin = pack("C C", $ver, $method);
				$$sock->write($bin);
				$$stage = EXHOST;
				$$ci = '';
			}
		} elsif ($$stage == EXHOST) {
			$$ci .= $buffer;

			if (length($$ci) < REQ_HEADER_LEN) {
				return;
			}

			my ($ver, $cmd, $rsv, $type) = unpack("C C C C", $$ci);

			if ($ver != SOCKS5_VERSION) {
				print "not socks5. close socket: $fd\n";
				delete $socket_map{$fd};
				$kq->EV_SET($fd, EVFILT_READ, EV_DELETE);
				$$sock->close;
				return;
			}

			if (($cmd != CONNECT) && ($cmd != BIND) && ($cmd != UDP)) {
				print "unsupport cmd: $cmd. close socket: $fd\n";
				delete $socket_map{$fd};
				$kq->EV_SET($fd, EVFILT_READ, EV_DELETE);
				$$sock->close;
				return;
			}

			if ($type == IPV4) {
       				# TODO
			} elsif ($type == DONAME) {
				my $doname_len = unpack("C", substr($$ci, REQ_HEADER_LEN));
				if (length($$ci) < REQ_HEADER_LEN + 1 + $doname_len + PORT_LEN) {
					print "wait for more data\n";
					return;
				}

				my ($doname, $port) = unpack("a$doname_len n", substr($$ci, REQ_HEADER_LEN + 1));
				my $remote = IO::Socket::INET->new(PeerAddr => $doname,
								   PeerPort => "$port",
								   Proto => 'tcp',
								   Timeout => 0.5);
				if (! $remote) {
					print "connect to $doname:$port timeout. close socket: $fd\n";
					my $bin = pack("C C C C C a$doname_len S",
							SOCKS5_VERSION, SUCCEEDED, RESERVED, DONAME, 1 + $doname_len + PORT_LEN, $doname, $port);
					$$sock->write($bin);
					delete $socket_map{$fd};
					$kq->EV_SET($fd, EVFILT_READ, EV_DELETE);
					$$sock->close;
					return;
				}

				IO::Handle::blocking $remote, 0;
				my $bin;
				my $pack_addr = inet_aton($remote->peeraddr());
				if (defined $pack_addr) {
					$bin = pack("C C C C I S", SOCKS5_VERSION, SUCCEEDED, RESERVED, IPV4, $pack_addr, $port);
				} else {
					$bin = pack("C C C C I S", SOCKS5_VERSION, SUCCEEDED, RESERVED, IPV4, 0, $port);
				}
				$$sock->write($bin);
				my %sock = (
					type => REMOTE,
					sock => $remote,
					clientfd => $fd,
				);
				$$remotefd = fileno $remote;
				$socket_map{$$remotefd} = \%sock;
				print "open tunnel: $fd <--> $$remotefd\n";
				$kq->EV_SET($$remotefd, EVFILT_READ, EV_ADD);
			} elsif ($type == IPV6) {
				# TODO
			} else {
				print "unsupport type: $type. close socket: $fd\n";
				delete $socket_map{$fd};
				$kq->EV_SET($fd, EVFILT_READ, EV_DELETE);
				$$sock->close;
				return;
			}

			$$stage = STREAMING;
			$$ci = '';
		} elsif ($$stage == STREAMING) {
			my $remote = \$socket_map{$$remotefd}{sock};
			if (defined $$remote) {
				$$remote->write($buffer);
			}
		}
	}
}

sub remote_event {
	my $fd = shift;
	my $sock = shift;

	my $clientfd = \$socket_map{$fd}{clientfd};
	print "found tunnel: $fd <--> $$clientfd\n";

	my $buffer;
	my $blen = $$sock->read($buffer, BUFFER_LEN);

	if (! $blen) {
		# eof
		print "close socket: $fd\n";
		delete $socket_map{$fd};
		$kq->EV_SET($fd, EVFILT_READ, EV_DELETE);
		$$sock->close;
	} elsif ($blen < 0) {
		# TODO
	} else {
		my $client = \$socket_map{$$clientfd}{sock};
		if (defined $$client) {
			$$client->write($buffer);
		}
	}
}

while (1) {
	my @ret = $kq->kevent();
	if (!@ret) {
		die "No kevents: $!";
	}

	foreach my $kevent (@ret) {
		my $fd = $kevent->[KQ_IDENT];

		if ($fd == $serverfd) {
			do_accept();
		} else {
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

