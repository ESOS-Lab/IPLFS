#!/bin/bash

WORKLOAD=fileserver_fig14
# WORKLOAD=filemicro_rwrite
# WORKLOAD=varmail
FILEBENCH_PATH=./$WORKLOAD.f
MNT=/mnt

DEV=(/dev/nvme0n1p1)
DEV_whole=/dev/nvme0n1
RES_FILE=blk
FTRACE_PATH=/sys/kernel/debug/tracing/
OUTPUTDIR="filebench_"$WORKLOAD"_`date "+%Y%m%d"`_`date "+%H%M"`"
MKBIN="./"
FILE_SIZE_COLD=25165824 #24GB, 80% of 30GB partition
#FILESYSTEM=(IPLFS)
FILESYSTEM=(vanilla)
IO_TYPE=(randwrite)
#	write)   #read randread write randwrite trimwrite)	

NUM_JOBS=(4)

# 4 8)    #1 4 8)

RANDOM_BLOCK_SIZE=(4k) # 4k 8k 16k 32k)
SEQ_BLOCK_SIZE=(4k)   # 64k 256k)

main()
{
	# Create result root directory
	mkdir ${OUTPUTDIR}

	# Disable ASLR
	echo 0 > /proc/sys/kernel/randomize_va_space

	for dev in ${DEV[@]}
	do
		# Identify device name and set a device result name
		case $dev in
			"/dev/sda1") #870QVO
				OUTPUTDIR_DEV=${OUTPUTDIR}/850pro
				;;
			"/dev/sdc") #860EVO
				OUTPUTDIR_DEV=${OUTPUTDIR}/860evo
				;;
			"/dev/nvme0n1p1") #OpenSSD
				OUTPUTDIR_DEV=${OUTPUTDIR}/OpenSSD
				;;
			"/dev/nvme1n1") #970evo
				OUTPUTDIR_DEV=${OUTPUTDIR}/970evo
				;;
			"/dev/nvme2n1") #750P
			    OUTPUTDIR_DEV=${OUTPUTDIR}/905P
				;;
		esac

		# Create directory for device
		mkdir ${OUTPUTDIR_DEV}

		for fs in ${IO_TYPE[@]}
		do
			# Set a filesystem result name
			OUTPUTDIR_DEV_FS=${OUTPUTDIR_DEV}/${fs}

			# Craete directory for filesystem
			mkdir ${OUTPUTDIR_DEV_FS}

 		    case $fs in
			    "write")
					BLOCK_SIZE=${SEQ_BLOCK_SIZE[@]}
				    ;;
				"randwrite")
					BLOCK_SIZE=${RANDOM_BLOCK_SIZE[@]}
					;;
				"trimwrite")
				    BLOCK_SIZE=${SEQ_BLOCK_SIZE[@]}
					;;
				"read")
				    BLOCK_SIZE=${SEQ_BLOCK_SIZE[@]}
					;;
				"randread")
				    BLOCK_SIZE=${RANDOM_BLOCK_SIZE[@]}
					;;
		    esac
		    for filesys in ${FILESYSTEM[@]}
		    	do
		    for numjob in ${NUM_JOBS[@]}
			do
			   # Set a number of jobs result name
			   OUTPUTDIR_DEV_FS_JOB=${OUTPUTDIR_DEV_FS}/${filesys}/${numjob}

			   # Create dirctory for numjob
			   mkdir -p ${OUTPUTDIR_DEV_FS_JOB}

			   for block_size in ${BLOCK_SIZE}
			   do
			 	   echo $'\n'
				   echo "==== Start experiment of ${block_size} fio ===="

				   # Format and Mount
				   echo "==== Format $dev on $MNT ===="

				   echo "==== Fotmat complete ===="

				   ${MKBIN}f2fs.sh ${filesys}

				   # Run
				   echo "==== Run workload ===="

				   sudo cp $FILEBENCH_PATH ${OUTPUTDIR_DEV_FS_JOB}/
				   sync
			   	   dmesg -C
				   echo 3 > /proc/sys/vm/drop_caches 
				   sudo sysctl kernel.randomize_va_space=0;
				   sudo filebench -f $FILEBENCH_PATH 1> ${OUTPUTDIR_DEV_FS_JOB}/result.txt;
				   
				   echo 0 > ${FTRACE_PATH}tracing_on
				   dmesg > ${OUTPUTDIR_DEV_FS_JOB}/dmesg
   		  		   echo "fb end";

				   echo "blkparsing start!";

				   echo "==== Workload complete ===="

				   echo "==== End the experiment ===="
				   dmesg > ${OUTPUTDIR_DEV_FS_JOB}/dmesg_aft_umount
				   echo $'\n'
			   done
		   	done
			done
		done
	done
}

main               





