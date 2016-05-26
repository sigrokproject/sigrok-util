#!/bin/bash

# (c) 2016 Simon Peter
# This file is licensed under the terms of the MIT license.
#
# Bundle PulseView and its dependencies as an AppImage for x86_64 Linux
# TODO: Change it to use build products and libraries from a more mature
# distribution such as Debian oldstable, CentOS 6 or Ubuntu Trusty or older.

APP=PulseView
LOWERAPP=${APP,,} 

ARCH=x86_64

mkdir -p ./$APP/$APP.AppDir/usr/bin ./$APP/$APP.AppDir/usr/lib
cd ./$APP

wget -q https://github.com/probonopd/AppImages/raw/master/functions.sh -O ./functions.sh
. ./functions.sh

########################################################################
# Get runtime dependencies
########################################################################

sudo apt-get update

# The following are installed into the host system so that we can bundle them into the AppImage as dependencies
sudo apt-get -y --force-yes install libqt5svg5 libqt5gui5 libboost-thread1.58.0 libboost-test1.58.0 libboost-chrono1.58.0 libboost-atomic1.58.0 libftdi1-2 libzip4

########################################################################
# Get build products from Jenkins
# FIXME: Do the actual building here instead
########################################################################

wget http://sigrok.org/jenkins/job/pulseview/buildtype=shared,compiler=gcc,platform=native-amd64/ws/_inst/bin/*zip*/bin.zip
unzip bin.zip

FW=$(wget -q "http://sigrok.org/download/binary/sigrok-firmware-fx2lafw/?C=M;O=D" -O - | grep .tar.gz | head -n 1 | cut -d '"' -f 13 | cut -d ">" -f 2 | cut -d "<" -f 1)
wget -c "http://sigrok.org/download/binary/sigrok-firmware-fx2lafw/$FW"
tar xf sigrok-firmware-fx2lafw-bin-*.tar.gz
rm sigrok-firmware-fx2lafw-bin-*.tar.gz

cd $APP.AppDir/

mv ../bin/pulseview usr/bin/
chmod a+x usr/bin/*

cd usr/lib/
wget http://sigrok.org/jenkins/job/libsigrok/buildtype=shared,compiler=gcc,platform=native-amd64/ws/_inst/lib/libsigrok.so.3
wget http://sigrok.org/jenkins/job/libsigrok/buildtype=shared,compiler=gcc,platform=native-amd64/ws/_inst/lib/libsigrokcxx.so.3
wget http://sigrok.org/jenkins/job/libserialport/buildtype=shared,compiler=gcc,platform=native-amd64/lastSuccessfulBuild/artifact/_inst/lib/libserialport.so.0
cd ../../

wget "http://sigrok.org/jenkins/job/libsigrokdecode/buildtype=shared,compiler=gcc,platform=native-amd64/lastSuccessfulBuild/artifact/*zip*/archive.zip"
unzip archive.zip
mv archive/_inst/share/libsigrokdecode usr/share/libsigrokdecode
mv archive/_inst/lib/libsigrokdecode.so.3 usr/lib/
rm -rf archive*

# Reduce binary size
strip usr/bin/*
strip usr/lib/*

########################################################################
# AppRun is the main launcher that gets executed when AppImage is run
########################################################################

get_apprun

########################################################################
# Copy desktop and icon file to AppDir for AppRun to pick them up
########################################################################

wget http://sigrok.org/jenkins/job/pulseview/buildtype=shared,compiler=gcc,platform=native-amd64/ws/contrib/pulseview.desktop
wget -q "http://sigrok.org/gitweb/?p=pulseview.git;a=blob_plain;f=icons/sigrok-logo-notext.png" -O sigrok-logo-notext.png

########################################################################
# Patch away absolute paths; it would be nice if they were relative
########################################################################

sed -i -e 's|/home/jenkins_slave/fsroot/workspace/libsigrokdecode/buildtype/shared/compiler/gcc/platform/native-amd64/_inst/share/|.//////////////////////////////////////////////////////////////////////////////////////////////////////////////share/|g' usr/lib/libsigrokdecode.so.3

########################################################################
# Copy in the dependencies that cannot be assumed to be available
# on all target systems
########################################################################

mkdir -p usr/share/
mv ../sigrok-firmware-* usr/share/sigrok-firmware

copy_deps

########################################################################
# Delete stuff that should not go into the AppImage
########################################################################

delete_blacklisted
move_lib
mv ./usr/lib/x86_64-linux-gnu/* usr/lib/
rm -r ./usr/lib/x86_64-linux-gnu/

########################################################################
# Determine the version of the app; also include needed glibc version
########################################################################

VER1=$(./AppRun --version | cut -d " "  -f 2)
GLIBC_NEEDED=$(glibc_needed)
VERSION=$VER1.glibc$GLIBC_NEEDED
echo $VERSION

########################################################################
# Patch away absolute paths; it would be nice if they were relative
########################################################################

patch_usr

########################################################################
# AppDir complete
# Now packaging it as an AppImage
########################################################################

cd ..

generate_appimage
