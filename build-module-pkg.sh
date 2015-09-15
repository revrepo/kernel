#!/bin/sh 

linuxVersionFile="./linux/Makefile"

# Get Linux version information
version=$(awk '/^VERSION/ {print $3} ' $linuxVersionFile)
patchlevel=$(awk '/^PATCHLEVEL/ {print $3} ' $linuxVersionFile)
lsublevel=$(awk '/^SUBLEVEL/ {print $3} ' $linuxVersionFile)
extraversion=$(awk '/^EXTRAVERSION/ {print $3} ' $linuxVersionFile)

# CI version is for module
# for kernel dependency we also need to know dependent job's version aka $1
ci=""
if [ "x$BUILD_NUMBER" != "x" ]; then
	ci="-$BUILD_NUMBER"
else
	ci=""
fi

if [ "x$1" != "x" ]; then
	extraversion="$extraversion$ci"
fi

if [ "$extraversion" != "" ]; then
	linuxVersion=$version.$patchlevel.$lsublevel$extraversion
else
	linuxVersion=$version.$patchlevel.$lsublevel
fi

revVersionFile="./revsw/tcp_revsw_version.h"

# Get the RevSw Module version information
major=$(awk '/TCP_REVSW_MAJOR/ {print $3} ' $revVersionFile)
minor=$(awk '/TCP_REVSW_MINOR/ {print $3} ' $revVersionFile)
rsublevel=$(awk '/TCP_REVSW_SUBLEVEL/ {print $3} ' $revVersionFile)

revVersion=$major.$minor.$rsublevel$ci

# Build keys.
# There should be always some gpg key with name matching entry in debian changelog

cd ./license_keys/ && ./generate-gpgs.sh
cd ..

echo "Done keys"
# Build id
cd ./revsw
echo "$linuxVersion ../linux $revVersion, ci=$ci"
./build-revsw-pkg.sh $linuxVersion ../linux $revVersion $ci
cd ..
