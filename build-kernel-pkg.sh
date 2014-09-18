#!/bin/sh -e

NJOBS=`getconf _NPROCESSORS_ONLN`

cd linux

if [ ! -e .config ]; then
	if [ -e default_config ]; then
		cp default_config .config
	else
		make xconfig || make menuconfig
	fi
fi

make -j$NJOBS INSTALL_MOD_STRIP=1 deb-pkg

cd ../revsw

make

../linux/scripts/sign-file sha512 ../linux/signing_key.priv ../linux/signing_key.x509 tcp_revsw_sysctl.ko
../linux/scripts/sign-file sha512 ../linux/signing_key.priv ../linux/signing_key.x509 tcp_revsw_session_db.ko
../linux/scripts/sign-file sha512 ../linux/signing_key.priv ../linux/signing_key.x509 tcp_revsw.ko
../linux/scripts/sign-file sha512 ../linux/signing_key.priv ../linux/signing_key.x509 tcp_rre.ko

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
