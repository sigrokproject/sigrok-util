#!/bin/sh
##
## This file is part of the sigrok-util project.
##
## Copyright (C) 2016 Uwe Hermann <uwe@hermann-uwe.de>
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 3 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, see <http://www.gnu.org/licenses/>.
##

umask 022

WGET="wget -c -q"
if [ -z $PREFIX ]; then
	PREFIX="/usr/local"
fi
FWDIR="$PREFIX/share/sigrok-firmware"

# Use the upstream 0.97 firmware/bitstream set. This is the only supported
# set of files in libsigrok >= 20170621.
FWURL="https://github.com/DreamSourceLab/DSView/raw/886b847c21c606df3138ce7ad8f8e8c363ee758b/DSView/res"

echo "Installing into: $FWDIR"

mkdir -p $FWDIR

$WGET $FWURL/DSLogic50.bin -O $FWDIR/dreamsourcelab-dslogic-fpga-5v.fw
$WGET $FWURL/DSLogic33.bin -O $FWDIR/dreamsourcelab-dslogic-fpga-3v3.fw
$WGET $FWURL/DSLogic.fw -O $FWDIR/dreamsourcelab-dslogic-fx2.fw

$WGET $FWURL/DSCope.bin -O $FWDIR/dreamsourcelab-dscope-fpga.fw
$WGET $FWURL/DSCope.fw -O $FWDIR/dreamsourcelab-dscope-fx2.fw

$WGET $FWURL/DSLogicPro.bin -O $FWDIR/dreamsourcelab-dslogic-pro-fpga.fw
$WGET $FWURL/DSLogicPro.fw -O $FWDIR/dreamsourcelab-dslogic-pro-fx2.fw

$WGET $FWURL/DSLogicPlus.bin -O $FWDIR/dreamsourcelab-dslogic-plus-fpga.fw
$WGET $FWURL/DSLogicPlus.fw -O $FWDIR/dreamsourcelab-dslogic-plus-fx2.fw

$WGET $FWURL/DSLogicBasic.bin -O $FWDIR/dreamsourcelab-dslogic-basic-fpga.fw
$WGET $FWURL/DSLogicBasic.fw -O $FWDIR/dreamsourcelab-dslogic-basic-fx2.fw
