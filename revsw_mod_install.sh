#!/bin/sh -e

kern=$(uname -r)

echo $kern

# Ensure the extra directory exists for the
# currently running kernel
if [ ! -d "/lib/modules/$kern/extra" ]; then
	mkdir /lib/modules/$kern/extra
fi

cp revsw/*.ko /lib/modules/$kern/extra

depmod -a
modprobe revsw

cp 10-enable-revsw-tcp-module.conf /etc/sysctl.d/.

sysctl -p /etc/sysctl.d/10-enable-revsw-tcp-module.conf

