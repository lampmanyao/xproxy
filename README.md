# btgfw
Break through gfw.

## Dependency
- libssl-dev

## Dependency installation
Ubuntu
`sudo apt install libssl-dev`

## Build from source
1. git clone https://github.com/lampmanyao/btgfw.git
2. cd src
3. make

## System socks5 proxy setup
### Mac
- start: networksetup -setsocksfirewallproxy Wi-Fi localhost 1080
- stop: networksetup -setsocksfirewallproxystate Wi-Fi off

## TODOs
- support more cipher-suites
- support DNS cache
- support IPv6
- support UDP
