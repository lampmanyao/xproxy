# btgfw
Break through gfw

## Dependency
- libssl

## Build
1. git clone https://github.com/lampmanyao/btgfw.git
2. cd btgfw/c
3. make

## How to setup
### remote-btgfw
```
cd btgfw/c/modules/remote-btgfw-module
make install
cd btgfw/c/remote-btgfw
./run.sh
```

### local-btgfw
```
cd btgfw/c/modules/local-btgfw-module
make install
cd btgfw/c/local-btgfw
./run.sh
```

### System socks5 proxy setup
#### Mac
- start: networksetup -setsocksfirewallproxy Wi-Fi localhost 10086
- stop: networksetup -setsocksfirewallproxystate Wi-Fi off

## TODOs
- support DNS cache
- support IPv6
- support UDP
