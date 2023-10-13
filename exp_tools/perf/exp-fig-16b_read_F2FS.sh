#!/bin/bash

# Device
# - /dev/sdb: SAMSUNG 860EVO 500GB
# - /dev/nvme0n1: SAMSUNG 970PRO 512GB
# - /dev/nvme1n1: SAMSUNG 970EVO 500GB
# - /dev/nvme2n1: INTEL 750 
DEV=(/dev/nvme0n1p1)
DEV_whole=/dev/nvme0n1
RES_FILE=blk

FTRACE_PATH=/sys/kernel/debug/tracing/

OUTPUTDIR="fio_result_`date "+%Y%m%d"`_`date "+%H%M"`"

MKBIN="./"

MNT=/mnt
#FILESYSTEM=(IPLFS)
FILESYSTEM=(vanilla)
IO_TYPE=(randread)

NUM_JOBS=(4)


RANDOM_BLOCK_SIZE=(4k) # 4k 8k 16k 32k)
SEQ_BLOCK_SIZE=(128k)   # 64k 256k)

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
			"/dev/nvme0n1p1") #970pro
				OUTPUTDIR_DEV=${OUTPUTDIR}/970pro
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

				   # Format Page Cache
				   sync
			   	   dmesg -C
				   echo 3 > /proc/sys/vm/drop_caches 
				   ${MKBIN}f2fs.sh ${filesys}



				   # Run
				   echo "==== Run workload ===="
				   fio \
					   	    --filename=/mnt/test  \
					   	    --name test \
							--rw=${fs}  \
						    --bs=${block_size} \
						    --filesize=28GB \
						    --numjobs=${numjob} \
							--norandommap \
							--direct=1 \
							--allow_mounted_write=1	\
							--random_generator=lfsr \
						    --time_based --runtime=600s \
						    --group_reporting=1 \
						    --log_avg_msec=2000\
						    --write_iops_log=${block_size}\
						    --write_lat_log=${block_size} \
						    --fadvise_hint=0 \
						    | tee ${OUTPUTDIR_DEV_FS_JOB}/result_${block_size}.txt;
						    #--filesize=200GB \
						    #--filesize=18GB \
						    #--time_based --runtime=300s \
							# > ${OUTPUTDIR_DEV_FS_JOB}/result_${block_size}.txt;
				   echo 0 > ${FTRACE_PATH}tracing_on
				   awk -F ',' '{print $2}' ${block_size}_lat.1.log | sort -n -k 1 > tmp_lat.txt
				   mv tmp_lat.txt ${OUTPUTDIR_DEV_FS_JOB}/latency_${block_size}.log;
				   awk -F ',' '{print $2}' ${block_size}_iops.1.log | sort -n -k 1 > tmp_iops.txt
				   mv tmp_iops.txt ${OUTPUTDIR_DEV_FS_JOB}/iops_${block_size}.log;
				   mv *.log ${OUTPUTDIR_DEV_FS_JOB}/;
				   python sum.py ${OUTPUTDIR_DEV_FS_JOB}/${block_size}_iops. > ${OUTPUTDIR_DEV_FS_JOB}/kiops_sum
				   dmesg > ${OUTPUTDIR_DEV_FS_JOB}/dmesg
				   echo "==== Workload complete ===="

				   echo "==== End the experiment ===="
				   echo $'\n'
			   done
		   	done
			done
		done
	done
}

main               
