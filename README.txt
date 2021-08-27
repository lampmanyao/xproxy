xproxy
======
Xproxy is a socks5 proxy, it consists of local-proxy and remote-proxy.
Local-proxy runs on the local computer, remote-proxy runs on the remote computer.

Dependency
==========
- libssl-dev

Dependency installation
=======================
Ubuntu:
$ sudo apt install libssl-dev

macOS:
$ brew install openssl

Build from source
=================
$ git clone https://github.com/lampmanyao/xproxy.git
$ cd xproxy
$ ./autogen.sh
$ ./configure
$ make

How to run
==========
local-proxy:
$ ./local-proxy -c local.conf

remote-proxy:
$ ./remote-proxy -c remote.conf

System socks5 proxy setup
=========================
macOS:
  a) enable:
  $ networksetup -setsocksfirewallproxy Wi-Fi localhost 1080

  b) disable:
  $ networksetup -setsocksfirewallproxystate Wi-Fi off

  c) status:
  $ networksetup -getsocksfirewallproxy Wi-Fi


TODOs
=====
- support proxy auto-config
- support more cipher-suites
- support DNS cache
- support IPv6
- support UDP

