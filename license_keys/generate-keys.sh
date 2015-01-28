#!/bin/sh -e

x509File="./x509.genkey"

if [ ! -e $x509File ]; then
	echo "x509 Gen File does not exist"
	exit
fi

if [ "$1" != "" ]; then
	linuxversion=$1
else
	echo "No linux version specified"
	exit
fi

privKeyFile=Revsw-$linuxversion.priv
x509KeyFile=Revsw-$linuxversion.x509

if [ -e $privKeyFile ] && [ -e $x509KeyFile ]; then
	exit
fi

openssl req -new -nodes -utf8 -sha512 -days 36500 -batch -x509 -config $x509File -outform DER -out $x509KeyFile -keyout $privKeyFile
