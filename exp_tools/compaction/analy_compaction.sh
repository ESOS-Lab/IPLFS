#!/bin/bash
#target=$1
#HOT_DATA_START=536870912
#WARM_DATA_START=1073741824
#COLD_DATA_START=1610612736
#HOT_NODE_START=2147483648
#WARM_NODE_START=2684354560
#COLD_NODE_START=3221225472
#
#
#cat $1 | awk '{if ($1 >= 536870912 && $1 < 1073741824 ) print}' > $1_HOT_DATA
#cat $1 | awk '{if ($1 >= 1073741824 && $1 < 1610612736 ) print}' > $1_WARM_DATA
#cat $1 | awk '{if ($1 >= 1610612736 && $1 < 2147483648 ) print}' > $1_COLD_DATA
#cat $1 | awk '{if ($1 >= 2147483648 && $1 < 2684354560 ) print}' > $1_HOT_NODE
#cat $1 | awk '{if ($1 >= 2684354560 && $1 < 3221225472 ) print}' > $1_WARM_NODE
#cat $1 | awk '{if ($1 >= 3221225472) print}' > $1_COLD_NODE

#python contig_check.py $DRANGE > res_discard_range

#awk '{cnt=($2-$1)} {print cnt}' $DRANGE | sort -V > $DCNT

#python dcnt_distribution.py $DCNT > $DCNTRES
fname=$1
#type_=(_HOT_DATA _COLD_NODE _COLD_DATA _HOT_NODE _WARM_NODE)
type_=(_WARM_DATA)
#type_=(_WARM_DATA _WARM_NODE)
#type_=('')
#type_=(_COLD_NODE)
#type_=(_WARM_DATA _WARM_NODE _HOT_DATA _HOT_NODE)
#type_=( _WARM_NODE _HOT_DATA _HOT_NODE)
#type_=('')
#type_=(_WARM_DATA)
#mssz=(4 8 16 32 64 128 256 512)
#mssz=(16 64 256) #MB
mssz=(16) #MB
#mssz=(256) #MB
#urange_sz=(512 1024 4096) #KB
#urange_sz=(64 256 512 1024 4096 8192 16384) #KB
urange_sz=(0) #KB
#urange_sz=(0) #KB
#urange_sz=(64 256) #KB
#urange_sz=(8192 16384) # 32768 65536) #KB
#urange_sz=(0) #KB
#urange_sz=(1024) #KB



for t in "${type_[@]}"
do
	echo "${fname}${t}"
	#echo "${1}${t}"
	#echo -e "$cols" > res_${fname}${t}
	for msz in "${mssz[@]}"
	do
	for usz in "${urange_sz[@]}"
	do
		#python compaction.py $1$t $msz $usz> ${fname}${t}_${msz}_usz${usz}_result
		python compaction.py $1$t $msz $usz> ${fname}${t}_${msz}_usz${usz}_result_compaction_only
		if [ $usz -eq 0 ]
		then
			#cat ${fname}${t}_${msz}_usz${usz}_result_compaction_only | grep drange > ${fname}${t}_${msz}_usz_mindiscard_range_unit_compaction_only
			#cat ${fname}${t}_${msz}_usz${usz}_result | grep drange > ${fname}${t}_${msz}_usz${usz}_range_unit_compaction_only
			cat ${fname}${t}_${msz}_usz${usz}_result_compaction_only | grep -v drange > ${fname}${t}_timestamp_compact-on_compact-off
			#cat ${fname}${t}_${msz}_usz${usz}_result | grep -v drange > ${fname}${t}_${msz}_usz_mindiscard_result_compaction_only
			rm ${fname}${t}_${msz}_usz${usz}_result_compaction_only
			#rm ${fname}${t}_${msz}_usz${usz}_result
		fi
	done
	done
	
done


