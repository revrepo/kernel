#!/bin/sh -e

modVersionFile="tcp_revsw_version.h"

if [ ! -e $modVersionFile ]; then
	echo "File $modVersionFile does not exist"
	exit
fi

if [ "$1" != "" ]; then
	linuxVersion=$1
else
	echo "No linux version specified"
	exit
fi

if [ "$2" != "" ]; then
	signFileDir=$2
else
	echo "No signature file location specified"
	exit
fi

privKey=../license_keys/Revsw-$linuxVersion.priv
x509Key=../license_keys/Revsw-$linuxVersion.x509

if [ ! -e $privKeyFile ] || [ ! -e $x509KeyFile ]; then
	echo "Signing Key files are missing"
        exit
fi

major=$(awk '/TCP_REVSW_MAJOR/ {print $3} ' $modVersionFile)
minor=$(awk '/TCP_REVSW_MINOR/ {print $3} ' $modVersionFile)
sublevel=$(awk '/TCP_REVSW_SUBLEVEL/ {print $3} ' $modVersionFile)

modVersion=$major.$minor.$sublevel

modFiles=$(ls *.ko)

echo $signFileDir

for file in $modFiles; do
	$signFileDir/sign-file sha512 $privKey $x509Key $file
done

tar cvf Revsw-modules-$modVersion-linux-$linuxVersion.tar $modFiles revsw-mod-install.sh 10-enable-revsw-tcp-module.conf
