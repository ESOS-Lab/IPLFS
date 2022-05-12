#!/bin/bash

sudo make -j16 && sudo make modules_install && sudo make install -j16
