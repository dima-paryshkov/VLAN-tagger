#!/bin/bash

echo "Create first virtual if eth0" 
ip link add eth0 type dummy
ifconfig eth0 hw ether C8:D7:4A:4E:47:50
sudo ip link set dev eth0 up

echo "Create second virtual if eth1" 
ip link add eth1 type dummy
ifconfig eth1 hw ether C8:D7:4A:4E:47:51
sudo ip link set dev eth1 up

./autotest "eth0" "eth1"

ip link delete eth0 type dummy

ip link delete eth1 type dummy
