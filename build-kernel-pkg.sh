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
	linuxVersion=$version.$patchlevel.$lsublevel
#$extraversion
	echo $BUILD_NUMBER > kernel-build-ver.txt
else
	ci=""
#	if [ "$extraversion" != "" ]; then
		linuxVersion=$version.$patchlevel.$lsublevel
#.$extraversion
#	else
#		linuxVersion=$version.$patchlevel.$lsublevel
#	fi

fi

# Generate the signing key files if necessary and copy them over to the
# the linux build directory
cd license_keys
./generate-keys.sh $linuxVersion$extraversion
cp Revsw-$linuxVersion$extraversion.priv ../linux/signing_key.priv
cp Revsw-$linuxVersion$extraversion.x509 ../linux/signing_key.x509
cp x509.genkey ../linux/.

echo "keys generated for $linuxVersion$extraversion, copied; linux ver : $linuxVersion extra $extraversion ci $ci"
cd ../linux

if [ ! -f .config ]; then
        if [ -f default_config ]; then
                cp default_config .config
        else
                make xconfig || make menuconfig
        fi
fi

rm -f packages/linux-image*.deb || true

echo "extra ver $extraversion"
make -j$NJOBS INSTALL_MOD_STRIP=1 EXTRAVERSION=$extraversion deb-pkg

cd ..
mv linux-image-$linuxVersion*.deb packages/
rm *.deb