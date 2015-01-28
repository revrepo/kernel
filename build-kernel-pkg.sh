#!/bin/sh -e

NJOBS=`getconf _NPROCESSORS_ONLN`

linuxVersionFile="./linux/Makefile"

# Get Linux version information
version=$(awk '/^VERSION/ {print $3} ' $linuxVersionFile)
patchlevel=$(awk '/^PATCHLEVEL/ {print $3} ' $linuxVersionFile)
lsublevel=$(awk '/^SUBLEVEL/ {print $3} ' $linuxVersionFile)
extraversion=$(awk '/^EXTRAVERSION/ {print $3} ' $linuxVersionFile)

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

revVersion=$major.$minor.$rsublevel

# Generate the signing key files if necessary and copy them over to the
# the linux build directory
cd license_keys
./generate-keys.sh $linuxVersion
cp Revsw-$linuxVersion.priv ../linux/signing_key.priv
cp Revsw-$linuxVersion.x509 ../linux/signing_key.x509
cp x509.genkey ../linux/.

echo "copied over signature files"

cd ../linux

if [ ! -f .config ]; then
        if [ -f default_config ]; then
                cp default_config .config
        else
                make xconfig || make menuconfig
        fi
fi

make -j$NJOBS INSTALL_MOD_STRIP=1 deb-pkg

# Build and package the RevSw Module
cd ../revsw
./build-revsw-pkg.sh $linuxVersion ../linux
cd ..

# Remove Linux DBG image if necessary
linuxDbgImage=linux-image-$linuxVersion-dbg*.deb
if [ -e $linuxDbgImage ]; then
        rm $linuxDbgImage
fi

# Now package everything together in a tar file
linuxImage=linux-image-$linuxVersion*.deb
modImage=revsw/Revsw-modules-$revVersion-linux-$linuxVersion.tar

echo $linuxImage

tar cvf Revsw-linux-$linuxVersion-rev-$revVersion-amd64.tar $linuxImage $modImage revsw-install.sh

rm *.deb
