#!/bin/sh

if [ $# -lt 1 ]; then
	set eth0
fi

IFACE=$1
VLAN=992

ip link add link $IFACE ${IFACE}.$VLAN type vlan id $VLAN
ip link set ${IFACE}.$VLAN promisc on up
ip addr add 192.168.168.56/24 dev ${IFACE}.$VLAN
