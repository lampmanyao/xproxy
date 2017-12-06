ulimit -c unlimited
nohup ./remote-btgfw ./server.conf &
echo $! > my.pid
