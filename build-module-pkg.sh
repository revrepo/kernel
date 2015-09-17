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
	ci="$BUILD_NUMBER"
else
	ci="0"
fi

# Get kernel version from other source
kver=$1
if [ "x$kver" == "x" ]; then
	kver=$(cat kernel-build-ver.txt)
fi

if [ "x$kver" != "x" ]; then
	extraversion="$extraversion-$kver"
fi

if [ "$extraversion" != "" ]; then
	linuxVersion=$version.$patchlevel.$lsublevel$extraversion
else
	linuxVersion=$version.$patchlevel.$lsublevel
fi

revVersionFile="./revsw/tcp_revsw_version.h"

# Get the RevSw Module version information
major=2 # $(awk '/TCP_REVSW_MAJOR/ {print $3} ' $revVersionFile)
minor=0 # $(awk '/TCP_REVSW_MINOR/ {print $3} ' $revVersionFile)
rsublevel=$ci #  $(awk '/TCP_REVSW_SUBLEVEL/ {print $3} ' $revVersionFile)

revVersion=$major.$minor.$rsublevel

# Build keys.
# There should be always some gpg key with name matching entry in debian changelog

cd ./license_keys/ && ./generate-gpgs.sh
cd ..

echo "Done keys"
# Build id
cd ./revsw
echo "$linuxVersion ../linux $revVersion, kernel ver=$kver"
./build-revsw-pkg.sh $linuxVersion ../linux $revVersion $kver
cd ..
