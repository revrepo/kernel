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

