#!/bin/sh -e

NJOBS=`getconf _NPROCESSORS_ONLN`

cd linux

if [ ! -e .config ]; then
	cp default_config .config
	make xconfig || make menuconfig
fi

make -j$NJOBS INSTALL_MOD_STRIP=1 deb-pkg

cd ../revsw

make ARCH=x86_64 -C ../linux M=$PWD

cd ..

# Now package everything together in a tar file

imageFile=(linux-image-*.deb)
modFiles=$(ls revsw/*.ko)

if [ ! -f "$imageFile" ]; then
        echo "Linux image file does NOT exist"
        return
fi

version=${imageFile:12:17}

# Ensure the install script is executable
chmod +x revsw_mod_install.sh

tar cvf Revsw-linux-$version-amd64.tar $imageFile $modFiles revsw_mod_install.sh 10-enable-revsw-tcp-module.conf

rm *.deb
