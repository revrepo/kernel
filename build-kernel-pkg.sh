#!/bin/sh -e

NJOBS=`getconf _NPROCESSORS_ONLN`

linuxVersionFile="./linux/Makefile"

# Cleanup spare debs
rm -f packages/*.deb

# Get Linux version information
version=$(awk '/^VERSION/ {print $3} ' $linuxVersionFile)
patchlevel=$(awk '/^PATCHLEVEL/ {print $3} ' $linuxVersionFile)
lsublevel=$(awk '/^SUBLEVEL/ {print $3} ' $linuxVersionFile)
extraversion=$(awk '/^EXTRAVERSION/ {print $3} ' $linuxVersionFile)

ci=""
if [ "x$BUILD_NUMBER" != "x" ]; then
	ci="-$BUILD_NUMBER"
	extraversion="$extraversion$ci"
	linuxVersion=$version.$patchlevel.$lsublevel$extraversion
else
	ci=""
	if [ "$extraversion" != "" ]; then
		linuxVersion=$version.$patchlevel.$lsublevel.$extraversion
	else
		linuxVersion=$version.$patchlevel.$lsublevel
	fi

fi



revVersionFile="./revsw/tcp_revsw_version.h"

# Get the RevSw Module version information
major=$(awk '/TCP_REVSW_MAJOR/ {print $3} ' $revVersionFile)
minor=$(awk '/TCP_REVSW_MINOR/ {print $3} ' $revVersionFile)
rsublevel=$(awk '/TCP_REVSW_SUBLEVEL/ {print $3} ' $revVersionFile)

revVersion=$major.$minor.$rsublevel$ci

# Generate the signing key files if necessary and copy them over to the
# the linux build directory
cd license_keys
./generate-keys.sh $linuxVersion
cp Revsw-$linuxVersion.priv ../linux/signing_key.priv
cp Revsw-$linuxVersion.x509 ../linux/signing_key.x509
cp x509.genkey ../linux/.

echo "copied over signature files"

echo "linux ver : $linuxVersion extra $extraversion ci $ci"
cd ../linux

if [ ! -f .config ]; then
        if [ -f default_config ]; then
                cp default_config .config
        else
                make xconfig || make menuconfig
        fi
fi

make -j$NJOBS INSTALL_MOD_STRIP=1 EXTRAVERSION=$extraversion deb-pkg

cd ..
mv linux-image-$linuxVersion*.deb packages/
rm *.deb