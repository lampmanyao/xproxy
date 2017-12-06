#!/usr/bin/perl -w

use Socket;
use IO::Socket;
use IO::KQueue;
use Crypt::Mode::CBC;

use constant {
	SOCKS5_VERSION => 5,
	REQ_HEADER_LEN => 4,
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
	EXMETHOD  => 0,
	AUTH0     => 1,
	AUTH1     => 2,
	EXHOST    => 3,
	STREAMING => 4,
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

if (scalar (@ARGV) != 5) {
	print "Usage:\n";
	print "  ./local-btgfw <local port> <remote proxy ip> <remote proxy port> <username> <password>\n";
	print "Arguments:\n";
	print "  local port:        the local proxy port of SOCKS5\n";
	print "  remote proxy ip:   remote proxy ip\n";
	print "  remote proxy port: remote proxy port\n";
	print "  username:          username of remote proxy\n";
	print "  password:          password of remote proxy. should be 16 characters\n";
	exit 1;
}

my $local_port  = shift;
my $remote_host = shift;
my $remote_port = shift;
my $user = shift;
my $pass = shift;
my $ulen = length($user);
my $plen = length($pass);

if ($plen != 16) {
	print "the length of password is not 16\n";
	exit 1;
}

my $iv = "abcdefg987654321";
my $cbc = Crypt::Mode::CBC->new('AES');
my $cipheruser = $cbc->encrypt($user, $pass, $iv);
my $cipheruser_len = length($cipheruser);
my $cipherpass = $cbc->encrypt($pass, $pass, $iv);
my $cipherpass_len = length($cipherpass);

my $server;
my $serverfd;
my $kq;
my %socket_map;

sub local_proxy_setup {
	`networksetup -setsocksfirewallproxystate Wi-Fi off`;
	`networksetup -setsocksfirewallproxy Wi-Fi localhost $local_port`;
}

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
	$SIG{QUIT}  = sub { die "caught SIGQUIT"; };
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
		target => '',
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
	my $target = \$socket_map{$clientfd}{target};

	my $buffer;
	my $blen = $$sock->read($buffer, BUFFER_LEN);

	if (! $blen) {
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
			return;
		}

		my $remote = IO::Socket::INET->new(PeerAddr => $remote_host,
						   PeerPort => "$remote_port",
						   Proto => 'tcp',
						   Timeout => 1);
		if (! $remote) {
			print "connect to $remote_host:$remote_port timeout.",
				" close socket: $clientfd\n";
			delete $socket_map{$clientfd};
			$kq->EV_SET($clientfd, EVFILT_READ, EV_DELETE);
			$$sock->close;
			return;
		}

		$$remotefd = fileno $remote;
		IO::Handle::blocking($remote, 0);
		my $bin = pack("C C C", SOCKS5_VERSION, 1, USERNAME_PASSWD);
		$remote->write($bin);
		my %sock = (
			type => REMOTE,
			sock => $remote,
			clientfd => $clientfd,
			state => AUTH0);

		$socket_map{$$remotefd} = \%sock;
		$kq->EV_SET($$remotefd, EVFILT_READ, EV_ADD);

		$$recvbuf = substr($$recvbuf, 3);

		print "connected to $remote_host:$remote_port.",
			" open tunnel: $clientfd <--> $$remotefd\n";
	} elsif ($$client_state == EXHOST) {
		return unless $recvlen >= REQ_HEADER_LEN;
		my ($ver, $cmd, $rsv, $atyp) = unpack("C C C C", $$recvbuf);
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

		my $bin;

		if ($atyp == IPV4) {
			return unless $recvlen >= REQ_HEADER_LEN + 4 + 2;
			my ($ip0, $ip1, $ip2, $ip3, $port) =
				unpack("C C C C n", substr($$recvbuf, REQ_HEADER_LEN));
			$$target = sprintf("%d.%d.%d.%d", $ip0, $ip1, $ip2, $ip3);
			$bin = substr($$recvbuf, 0, REQ_HEADER_LEN + 4 + 2);
			$$recvbuf = substr($$recvbuf, REQ_HEADER_LEN + 4 + 2);
		} elsif ($atyp == DONAME) {
			my $doname_len = unpack("C", substr($$recvbuf, REQ_HEADER_LEN));
			return unless $recvlen >= REQ_HEADER_LEN + 1 + $doname_len + 2;
			$$target = unpack("a$doname_len", substr($$recvbuf, REQ_HEADER_LEN + 1));
			$bin = substr($$recvbuf, 0, REQ_HEADER_LEN + 1 + $doname_len + 2);
			$$recvbuf = substr($$recvbuf, REQ_HEADER_LEN + 1 + $doname_len + 2);
		} elsif ($atyp == IPV6) {
			die "not support IPv6 yet!\n";
		}

		my $cipherdata = $cbc->encrypt($bin, $pass, $iv);
		my $cipherdata_len = length($cipherdata);
		my $sendbuf = pack("i a$cipherdata_len", $cipherdata_len, $cipherdata);

		my $remote = \$socket_map{$$remotefd}{sock};
		my $remote_state = \$socket_map{$$remotefd}{state};
		if (defined $$remote) {
			$$remote->write($sendbuf);
			$$client_state = STREAMING;
			$$remote_state = EXHOST;
		} else {
			print "could not find remote socket: $$remotefd\n"
		}
	} elsif ($$client_state == STREAMING) {
		my $chipherdata = $cbc->encrypt($buffer, $pass, $iv);
		my $len = length($chipherdata);
		my $data = pack("I a$len", $len, $chipherdata);
		my $remote = \$socket_map{$$remotefd}{sock};
		if (defined $$remote) {
			print "forwarding to $$target\n";
			$$remote->write($data);
		}
	}
}

sub remote_event {
	my $remotefd = shift;
	my $sock = shift;

	my $clientfd = \$socket_map{$remotefd}{clientfd};
	my $remote_state = \$socket_map{$remotefd}{state};
	my $recvbuf = \$socket_map{$remotefd}{recvbuf};

	my $buffer;
	my $blen = $$sock->read($buffer, BUFFER_LEN);

	if (! $blen) {
		# eof
		print "close socket: $remotefd\n";
		delete $socket_map{$remotefd};
		$kq->EV_SET($remotefd, EVFILT_READ, EV_DELETE);
		$$sock->close;
		return;
	}

	if ($blen < 0) {
		print "close socket: $remotefd\n";
		delete $socket_map{$remotefd};
		$kq->EV_SET($remotefd, EVFILT_READ, EV_DELETE);
		$$sock->close;
		return;
	}

	$$recvbuf .= $buffer;
	my $recvlen = length($$recvbuf);

	if ($$remote_state == AUTH0) {
		my $bin = pack("C C a$cipheruser_len C a$cipherpass_len",
				SOCKS5_VERSION,
				$cipheruser_len, $cipheruser,
				$cipherpass_len, $cipherpass);
		$$sock->write($bin);
		$$remote_state = AUTH1;
		$$recvbuf = '';
	} elsif ($$remote_state == AUTH1) {
		my $client       = \$socket_map{$$clientfd}{sock};
		my $client_state = \$socket_map{$$clientfd}{state};
		my $client_recvbuf    = \$socket_map{$$clientfd}{recvbuf};
		if (defined $$client) {
			my $bin = pack("C C", SOCKS5_VERSION, 0);
			$$client->write($bin);
			$$client_state = EXHOST;
		}
		$$recvbuf = '';
	} elsif ($$remote_state == EXHOST) {
		return unless $recvlen >= 4;
		my $bin;
		my ($ver, $rsp, $rsv, $atyp) = unpack("C C C C", $$recvbuf);
		if ($atyp == IPV4) {
			return unless $recvlen >= 4 + 4 + 2;
			$bin = substr($$recvbuf, 0, 10);
			$$recvbuf = substr($$recvbuf, 10);
		} elsif ($atyp == DONAME) {
			my $doname_len = unpack("C", substr($$recvbuf, 4));
			return unless $recvlen >= 4 + 1 + $doname_len + 2;
			$bin = substr($$recvbuf, 0, 4 + 1 + $doname_len + 2);
			$$recvbuf = substr($$recvbuf, 4 + 1 + $doname_len + 2);
		} elsif ($atyp == IPV6) {
			die "not support IPv6 yet!\n"
		}

		my $client = \$socket_map{$$clientfd}{sock};
		if (defined $$client) {
			$$client->write($bin);
		}

		$$remote_state = STREAMING;
	} elsif ($$remote_state == STREAMING) {
		my $client = \$socket_map{$$clientfd}{sock};
		my $target = \$socket_map{$$clientfd}{target};
		if (defined $$client) {
			print "reply from $$target\n";
			$$client->write($$recvbuf);
			$$recvbuf = '';
		}
	}
}

sub main {
	local_proxy_setup();
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

