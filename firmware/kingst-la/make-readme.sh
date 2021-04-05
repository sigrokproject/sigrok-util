#!/bin/bash
groff -Tascii -man sigrok-fwextract-kingst-la2016.1 | col -bx > README
cat README

