#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

set $dir=/mnt
#set $nfiles=49152 #f
#set $nfiles=58880 #50%
#set $nfiles=70656 #60%
#set $nfiles=82432 #70%
#set $nfiles=94208 #80%
set $nfiles=105984 #90%
#set $nfiles=111872 #95%
set $meandirwidth=20

set $filesize=cvar(type=cvar-gamma,parameters=mean:2097152;gamma:1.5) #for real 80% of 230GB partition.

# set $filesize=cvar(type=cvar-gamma,parameters=mean:131072;gamma:1.5)
#set $filesize=cvar(type=cvar-gamma,parameters=mean:11875000;gamma:1.#5) #93GB
#set $filesize=cvar(type=cvar-gamma,parameters=mean:28014951;gamma:1.5) #for 90% of 230GB partition
#set $filesize=cvar(type=cvar-gamma,parameters=mean:25014951;gamma:1.5) #for 80% of 230GB partition
#set $filesize=cvar(type=cvar-gamma,parameters=mean:22014951;gamma:1.5) #for 70% of 230GB partition
#set $filesize=cvar(type=cvar-gamma,parameters=mean:19014951;gamma:1.5) #for 60% of 230GB partition
#set $filesize=cvar(type=cvar-gamma,parameters=mean:16014951;gamma:1.5) #for 50% of 230GB partition
#set $filesize=cvar(type=cvar-gamma,parameters=mean:2968750;gamma:1.5) #for 88% of 30GB partition
#set $filesize=cvar(type=cvar-gamma,parameters=mean:3204900;gamma:1.5) #for 95% of 30GB partition
#set $filesize=cvar(type=cvar-gamma,parameters=mean:337357;gamma:1.5) #for 10% for 30GB partition
set $nthreads=50
set $iosize=1m
set $meanappendsize=16k
#set $runtime=350
#set $runtime=200
#set $runtime=10
#set $runtime=600
#set $runtime=1200
#set $runtime=900
set $runtime=300 

define fileset name=bigfileset,path=$dir,size=$filesize,entries=$nfiles,dirwidth=$meandirwidth,prealloc=80

define process name=filereader,instances=1
{
  thread name=filereaderthread,memsize=10m,instances=$nthreads
  {
    flowop createfile name=createfile1,filesetname=bigfileset,fd=1
    flowop writewholefile name=wrtfile1,srcfd=1,fd=1,iosize=$iosize
    flowop closefile name=closefile1,fd=1
    flowop openfile name=openfile1,filesetname=bigfileset,fd=1
    flowop appendfilerand name=appendfilerand1,iosize=$meanappendsize,fd=1
    flowop closefile name=closefile2,fd=1
    flowop openfile name=openfile2,filesetname=bigfileset,fd=1
    flowop readwholefile name=readfile1,fd=1,iosize=$iosize
    flowop closefile name=closefile3,fd=1
    flowop deletefile name=deletefile1,filesetname=bigfileset
    flowop statfile name=statfile1,filesetname=bigfileset
  }
}

echo  "File-server Version 3.0 personality successfully loaded"

run $runtime
