ulimit -c unlimited
nohup ./local-btgfw ./server.conf &
echo $! > my.pid
