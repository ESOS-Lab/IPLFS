#!/bin/bash
FIRST=$NORM
SECOND=$IFLBA
BENCHMARK_DIR=/mnt
DEV_partition=/dev/nvme0n1p1
RES_FILE=_parti20G_file4G_4Grndwrt
RES_DIR=./test_$WORKLOAD/$FIRST$RES_FILE
FTRACE_PATH=/sys/kernel/debug/tracing/

sudo rm $BENCHMARK_DIR/* -rf
sudo umount $DEV_partition\

sudo rmmod f2fs
sudo insmod ./mod/f2fs_$1.ko;

sudo mkfs.f2fs -f $DEV_partition;\
sudo mount -t f2fs -o mode=lfs -o discard $DEV_partition $BENCHMARK_DIR;\
