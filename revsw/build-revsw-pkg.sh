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
	linuxDir=$2
else
	echo "No Linux directory specified"
	exit
fi

if [ "x$BUILD_NUMBER" != "x" ]; then
	ci=$BUILD_NUMBER
else
	echo "No build-specific version specified"
	ci="0"
fi

privKey=../license_keys/Revsw-$linuxVersion.priv
x509Key=../license_keys/Revsw-$linuxVersion.x509

if [ ! -e $privKeyFile ] || [ ! -e $x509KeyFile ]; then
	echo "Signing Key files are missing"
        exit
fi

major=2
minor=0
sublevel=$ci

modVersion=$major.$minor.$sublevel

make ARCH=x86_64 -C $linuxDir M=$PWD TCP_REVSW_MAJOR=2 TCP_REVSW_MINOR=0 TCP_REVSW_SUBLEVEL=$ci

modFiles=$(ls *.ko)

for file in $modFiles; do
	$linuxDir/scripts/sign-file sha512 $privKey $x509Key $file
done

# Build debian package

pak=revsw-mod
kernver=$linuxVersion
ver=$modVersion
templatedir=template-build-$kernver-$ver
dat=$(date "+%a, %d %b %Y %H:%M:%S %z")

echo "Building module $modVersion for linux $linuxVersion, final ver $ver"

# revsw_name is first ()-marked part of linux-image-(revsw-3.11.10-034)-(3.11.10-034-2).deb
# revsw_ver is second
rname=$kernver
rnver=$kernver

rm -vrf ../packages/$templatedir
cp -vr module-deb-template ../packages/$templatedir

sed "s/DEBIAN_VERSION/$ver/g" -i ../packages/$templatedir/debian/changelog || exit -1
sed "s/DEBIAN_PACKAGE/$pak/g" -i ../packages/$templatedir/debian/changelog || exit -1
sed "s/DEBIAN_PACKAGE/$pak/g" -i ../packages/$templatedir/debian/control || exit -1
sed "s/REVSW_VER/$rnver/g"  -i ../packages/$templatedir/debian/control || exit -1
sed "s/REVSW_NAME/$rname/g" -i ../packages/$templatedir/debian/control || exit -1
sed "s/REVSW_NAME/$rname/g" -i ../packages/$templatedir/debian/install || exit -1
sed "s/DATE_STAMP/$dat/g"   -i ../packages/$templatedir/debian/changelog || exit -1


mkdir -p ../packages/$templatedir/lib/modules/$kernver/extra/
modFiles=$(ls *.ko)

for file in $modFiles; do
	cp $file ../packages/$templatedir/lib/modules/$kernver/extra/
done

cd ../packages/$templatedir && dpkg-buildpackage -d -uc || exit -1
rm -rf ../packages/$templatedir
