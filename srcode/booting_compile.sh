#!/bin/bash

sudo make -j16 && sudo rm -rf /boot/*5.11.0+*/ && rm -rf /lib/modules/*5.11.0+* && sudo make modules_install -j16 && sudo find /lib/modules/5.11.0+/ -name *.ko -exec strip --strip-unneeded {} + && sudo make install -j16
