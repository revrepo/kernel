#!/bin/sh -e

cd ./revsw

modImage=Revsw-modules-*.tar

tar xvf $modImage

./revsw-mod-install.sh

cd ..
