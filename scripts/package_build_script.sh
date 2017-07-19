#!/bin/bash

#
# This script builds Rev API Debian package
#

if [ -z "$WORKSPACE" ]; then
	echo "ERROR: WORKSPACE env. variable is not set"
	exit 1
fi

if [ -z "$BUILD_NUMBER" ]; then
	echo "ERROR: BUILD_NUMBER env. variable is not set"
	exit 1
fi

if [ -z "$VERSION" ]; then
	VERSION=1.0.$BUILD_NUMBER
	echo "INFO: VERSION env variable is not set - setting it to $VERSION"
fi

PACKAGENAME=revsw-nxtool

PACKAGEDIR=packages

if [ ! -d $PACKAGEDIR ]; then
	echo "INFO: Directory $PACKAGEDIR does not exist - creating it..."
	mkdir $PACKAGEDIR
	if [ $? -ne 0 ]; then
		echo "ERROR: Failed to create directory $PACKAGEDIR - aborting"
		exit 1
	fi
fi

WORKDIR="package_build_dir"

sudo rm -rf $WORKDIR
mkdir $WORKDIR
cd $WORKDIR

if [ $? -ne 0 ]; then
  echo "FATAL: Failed to CD to directory $WORKDIR"
  exit 1
fi


foldername=$PACKAGENAME'_'$VERSION

mkdir -p $foldername/DEBIAN
touch $foldername/DEBIAN/control

PackageName=$PACKAGENAME
PackageVersion=$VERSION
MaintainerName="Victor Gartvich"
MaintainerEmail=victor@revsw.com

echo "Package: $PackageName
Version: $PackageVersion
Architecture: amd64
Maintainer: $MaintainerName <$MaintainerEmail>
Installed-Size: 26
Section: unknown
Priority: extra
Homepage: www.nuubit.com
Description: Rev NAXSI nxtool code" >> $foldername/DEBIAN/control

# cp -rp $WORKSPACE/scripts/logrotate_revsw-api $foldername/etc/logrotate.d/revsw-api

mkdir -p $foldername/opt/$PackageName/
#mkdir -p $foldername/opt/$PackageName/docs
#mkdir -p $foldername/opt/$PackageName/utils

cp -rf  $WORKSPACE/tpl  $foldername/opt/$PackageName/
cp -rf  $WORKSPACE/nx_datas  $foldername/opt/$PackageName/
cp -rf  $WORKSPACE/*.py  $foldername/opt/$PackageName/
cp -rf  $WORKSPACE/nxapi  $foldername/opt/$PackageName/
cp -rf  $WORKSPACE/nxapi.json  $foldername/opt/$PackageName/
cp -rf  $WORKSPACE/requirements.txt  $foldername/opt/$PackageName/

# sudo chown -R root:root $foldername

dpkg -b $foldername $WORKSPACE/$PACKAGEDIR/$foldername.deb
 
