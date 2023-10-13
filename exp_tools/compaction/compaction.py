import sys
from math import *

mask = ~0x1fffffff
fname = sys.argv[1]
timeidx = 0
sLBAidx = 1
nblkidx = 2

#mapping segment (map node) size in MB
szMS = int(sys.argv[2])
DRANGE_SZ = int(sys.argv[3])/4 #unit of 4K blk
parent_map_sz = 16*1024 #MB
parent_sz = parent_map_sz / szMS * 4 #byte

#map seg size in 4K blk
MSblks = szMS * 1024 / 4 

pastsLBA = 0
pasteLBA = 0

# 4K block validity bitmap. For simplicity, bitmap is replaced by array. 
bitarray = [1 for i in range(MSblks)] 
bit_MSidx = 0
last_MSidx = 0
first = True

MS_info = {}
dirty_MSidx = {}

# semi-minimum discard range in KB
URthr = 256
#URthr = 64
URthrblks = URthr / 4
map_granularity = 16 # FTL mapping granularity in KB
mg = map_granularity / 4
metasz = 10 # size of metadata in map segment (byte)
default_urd_sz = 2
default_mrb_sz = 4 + MSblks / mg * 4
default_bitmapsz = MSblks / 8
default_MS_sz = metasz + default_bitmapsz + default_urd_sz + default_mrb_sz
default_PT_sz = default_bitmapsz + MSblks / mg * 4
default_trunc_PT_sz = 4 + 4 + default_bitmapsz + MSblks / mg * 4 # start LBA + len + bitmap + mapping

shival = 0

# if mapping granularity is 4K, no need to have bitmap
if (mg == 1):
	default_MS_sz -= default_bitmapsz 
	default_PT_sz -= default_bitmapsz
	default_trunc_PT_sz -= default_bitmapsz

compacted_memory = 0
truncated_memory = 0
compaction_target_memory = 0
discarded_LBA = 0
dealloc_ms = 0

#MSinfo
bmapidx = 0
szidx = 1
trunc_szidx = 2
vcnt_idx = 3 #valid 4K block count
compact_sz = 0


t = 0
total_range = 0
start_MSidx = -1
end_MSidx = -1
#compact_period = 30000 #ms
compact_period = 10000 #ms

#comp effi
#compac_effi_thres = 0.7
#compac_effi_thres = 0.3
compac_effi_thres = 0.3


def edge_truncation(m_len):
	# m_len is number of 4K block in mapping range	
	truc_bitmapsz = ceil(m_len / 8)
	truc_mrb_sz = 4 * (ceil(m_len/mg) + 1)
	truncated_MS_sz = metasz + truc_bitmapsz + default_urd_sz + truc_mrb_sz
	if (mg == 1):
		truncated_MS_sz -= truc_bitmapsz
	return truncated_MS_sz 


def compaction(idx):
	global MS_info
	global compact_sz
	global truncated_memory
	global compaction_target_memory
	global dealloc_ms
	global shival
	global compac_effi_thres
	try:
		ms_info = MS_info[idx]
	except:
		print("compaction error")
		exit()
	
	bitarray = ms_info[bmapidx]
	mssz = ms_info[szidx]

	vrangecnt = 0 # valid range count
	vmapcnt = 0 # valid map count
	new_sofs = 0 # start offset of new mapping range
	setsofs = False
	new_eofs = 0 # end offset of new mapping range
	drangesz = MSblks #unit of 4K blks
	past_is_valid = False
	curdrange_sz = 0
	# bitmap scanning
	assert(len(bitarray)%mg == 0) # 16K aligned check
	first_valid = True

	valid_cnt = 0
	# vacancy check. This should not be implemented in FTL
	for ii in range(len(bitarray)):
		if (bitarray[ii] == 1):
			valid_cnt += 1
	assert(valid_cnt > 0)
		


	for i in range(len(bitarray)/mg):
		v = False

		# mapping granularity handling
		for ii in range(mg):
			b = bitarray[i*mg + ii]
			if (b == 1):
				# valid block case
				# define first valid mapping
				#if (shival%100 == 0):
				#	print("shival")
				shival += 1
				if not setsofs:
					setsofs = True
					new_sofs = i*mg + ii
				v = True
				new_eofs = i*mg + ii
			elif (b != 0):
				# weird case
				assert(0)

		# valid map count update
		if (v):	
			# valid mapping case
			vmapcnt += 1
			if (not past_is_valid):
				# valid range fist encountered
				vrangecnt += 1
				# obtain minimum dicsard range
				# skip the edge discard case
				if (not first_valid):
					if (curdrange_sz >= URthrblks):
						drangesz = min(drangesz, curdrange_sz)
					#drangesz = min(drangesz, curdrange_sz)
					
					
				curdrange_sz = 0
			past_is_valid = True
			first_valid = False
		else:
			# invalid mapping case
			if (past_is_valid):
				assert(curdrange_sz == 0)	
			curdrange_sz += mg
			past_is_valid = False

	#By commenting this code, skip edge discard case	
	#if (not v):
	#	if (curdrange_sz >= URthrblks):
	#		drangesz = min(drangesz, curdrange_sz)
	#print("msidx: {} compaction:".format(idx))
	# get new mapping range size (# of 4K block)
	new_mlen = new_eofs - new_sofs + 1
	
	# get new bitmap size (byte)
	newbitmap_sz = ceil(new_mlen / 8)
	
	# set unit range size (# of 4K block)
	if (DRANGE_SZ == 0):
		usz = drangesz #(# of 4K block)
		print("drange: {} KB".format(drangesz*4))
	elif (DRANGE_SZ > 0):
		usz = DRANGE_SZ #(# of 4K block)
	else:
		assert(0)
	# unit range directory size (byte)
	urdsz = ceil(new_mlen / usz) * 2
	
	# mapping range buffer size (byte)
	ideal_mrbsz = 4 * (vmapcnt + vrangecnt)

	invcnt = 0 # mapping count: 4Kblknum/ mg
	head_saving = 0
	for i in range(int(ceil(float(new_eofs - new_sofs + 1) / usz ))):
		range_existed = False
		past_was_valid = False
		for ii in range(usz/mg): # unit range size is aligned to mapping granularity
			off = i*usz + ii*mg + new_sofs
			# mapping granularity handling
			v = False
			for iii in range(mg):
				if (off+iii > new_eofs):
					if (v and range_existed):
						invcnt += (off/mg - last_valid - 1)
						head_saving += 1
						range_existed = False
					break			
				b = bitarray[off + iii]
				if (b == 1):
					# valid block case
					v = True
				elif (b != 0):
					# weird case
					assert(0)
			
			if (v):
				if (range_existed):
					invcnt += (off/mg - last_valid - 1)
					head_saving += 1
					range_existed = False
				last_valid = off/mg
				past_was_valid = True
					
			else:
				if (past_was_valid):
					range_existed = True

	mrbsz = ideal_mrbsz + 4*invcnt - 4*head_saving
			
	# compacted mapsegment size (byte)
	newMS_sz = metasz + newbitmap_sz + urdsz + mrbsz
	# if mapping is 4K, no need to have bitmap
	if (mg == 1):
		newMS_sz -= newbitmap_sz
	
	# compaction ratio
	c_rate = float(newMS_sz) / float(default_MS_sz)

	#if new compacted map seg is bigger than previous one
	if (ms_info[szidx] < newMS_sz):
		return	0
	if (1 - float(newMS_sz)/ms_info[szidx] < compac_effi_thres ):
		return 0
	compact_sz += (ms_info[szidx] - newMS_sz)
	ms_info[szidx] = newMS_sz
	# truncation ratio
	#print("msidx: {} MSblks: {}, new_mlen: {} newbitmapsz: {} usz: {} urdsz: {} mrbsz{} vmapcnt: {} vrangecnt: {} newMSsz: {}".format(idx, MSblks, new_mlen, newbitmap_sz, usz, urdsz, mrbsz, vmapcnt, vrangecnt,  newMS_sz))
	truncatedMS_sz = edge_truncation(new_mlen)
	t_rate = float(truncatedMS_sz) / float(default_MS_sz)
	#print("msidx: {} compaction rate: {:.2f} % truncation rate: {:.2f} %".format(idx, c_rate*100, t_rate*100))
	#compacted_memory += (default_MS_sz - newMS_sz)
	truncated_memory += (ms_info[trunc_szidx] - truncatedMS_sz )
	ms_info[trunc_szidx] = truncatedMS_sz
	compaction_target_memory += default_MS_sz

	return 0

def print_size(compaction):
	global dealloc_ms
	global start_MSidx
        global end_MSidx
	global t
	global compact_sz
	global parent_map_sz
	global parent_sz
	total_MScnt = end_MSidx - start_MSidx + 1
	
	parentcnt = ceil(float(total_MScnt * szMS) / parent_map_sz)
	parent_total_sz = parentcnt * parent_sz
	#conpaction on
	sz = float(parent_total_sz + (total_MScnt - dealloc_ms) * default_MS_sz - compact_sz) / 1024/1024
	#compaction off
	pt_sz = float(parent_total_sz + (total_MScnt - dealloc_ms) * default_MS_sz) / 1024/1024
	
	#truncate
	trunc_sz = float(parent_total_sz + (total_MScnt - dealloc_ms) * default_MS_sz - truncated_memory) / 1024/1024
	dealloc_sz = float(dealloc_ms * default_MS_sz) / 1024 / 1024
	#print("start MSidx: {} end MSidx: {} total MScnt; {} dealloc_ms: {}".format(start_MSidx, end_MSidx, total_MScnt, dealloc_ms))
	if not compaction:
		#x = 1
		#print("{} {} {} {} {} {} MB".format(t, sz, compact_sz/1024/1024, pt_sz, trunc_sz, dealloc_sz))
		print("{} {} {} MB".format(t, sz, pt_sz))
	else:
		print("{} {} {} MB compaction !!".format(t, sz, pt_sz))
	


def vacancy_check(MSidx):
	global MS_info
	global compact_sz
	global truncated_memory
	try: 
		msinfo = MS_info[MSidx]
	except:
		print("vacancy_check wrong!!")
		exit()
	
	bitarray = msinfo[bmapidx]

	global dealloc_ms
	valid_cnt = msinfo[vcnt_idx]
	assert(valid_cnt >= 0)
	
	#for ii in range(len(bitarray)):
	#	if (bitarray[ii] == 1):
	#		valid_cnt += 1
	if (valid_cnt == 0):
		#print("msidx: {} all discarded".format(idx))\
		dealloc_ms += 1
		ms_compacted_sz = default_MS_sz - msinfo[szidx]
		compact_sz -= ms_compacted_sz
		ms_truncated_sz = default_MS_sz - msinfo[trunc_szidx]
		truncated_memory -= ms_truncated_sz
		del(MS_info[MSidx])
		try:
			tmp = dirty_MSidx[MSidx]
		except:
			print_size(False)
			return
		del(dirty_MSidx[MSidx])
	
	print_size(False)
		

def punch_bitmap(MSidx, sofs, eofs):
	global MS_info
	try: 
		msinfo = MS_info[MSidx]
	except:
		bitarray = [1 for i in range(MSblks)] 
		MS_info[MSidx] = [bitarray, default_MS_sz , default_MS_sz, MSblks]
		msinfo = MS_info[MSidx]
	assert(sofs <= eofs)
	assert(sofs >= 0 and eofs >= 0)
	for ii in range(sofs, eofs+1):
		assert(msinfo[bmapidx][ii] == 1)
		msinfo[bmapidx][ii] = 0
	msinfo[vcnt_idx] -= (eofs-sofs+1)
	vacancy_check(MSidx)
	

global_sLBA = -1
global_eLBA = -1
f = open(fname, 'r')
for l in f:
	tmpl = l.strip().split()
	t = float(tmpl[timeidx])
	sLBA = tmpl[sLBAidx]
	sLBA = int(float(sLBA))
	nblk = int(float(tmpl[nblkidx]))
	#discarded_LBA += nblk
	SZLBA = sLBA & mask #super zone start LBA
	
	#first mapseg idx
	MSidx = (sLBA - SZLBA) / MSblks

	if (start_MSidx == -1):
		start_MSidx = MSidx
		global_sLBA = sLBA
	
	start_MSidx = min(MSidx, start_MSidx)
	global_sLBA = min(sLBA, global_sLBA)

f.close()


f = open(fname, 'r')
veryfirst = True
for l in f:
	tmpl = l.strip().split()
	t = float(tmpl[timeidx])
	sLBA = tmpl[sLBAidx]
	sLBA = int(float(sLBA))
	if (veryfirst):
		veryfirst = False
		firstLBA = sLBA
	nblk = int(float(tmpl[nblkidx]))
	discarded_LBA += nblk
	SZLBA = sLBA & mask #super zone start LBA
	
	#first mapseg idx
	MSidx = (sLBA - SZLBA) / MSblks
	try:
		tmp = dirty_MSidx[MSidx]
	except:
		dirty_MSidx[MSidx] = 0

	#if (start_MSidx == -1):
		#start_MSidx = MSidx
	if (end_MSidx == -1):	
		end_MSidx = MSidx
		global_eLBA = sLBA + nblk-1
	
	#start_MSidx = min(MSidx, start_MSidx)

	#last mapseg idx
	last_MSidx = (sLBA + nblk - 1 - SZLBA) / MSblks
	end_MSidx = max(last_MSidx, end_MSidx)
	global_eLBA = max(global_eLBA, sLBA+nblk-1)

	ofs = (sLBA - SZLBA) % MSblks
	MSnum = last_MSidx - MSidx + 1
	for i in range(MSnum):
		cur_MSidx = MSidx+i
		bit_MSidx = cur_MSidx
		#get last ofs
		if (i < MSnum - 1):
			last_ofs = len(bitarray)-1
		else:
			last_ofs = (sLBA + nblk -1 - SZLBA) % MSblks
		if (last_ofs - ofs+1 < MSblks):
			trash = 0
			#print("msidx: {} punch: {}~{}".format(cur_MSidx, ofs, last_ofs ))
		punch_bitmap(cur_MSidx, ofs, last_ofs)
		#if (i < MSnum - 1):
		#	compaction(cur_MSidx)	
		ofs = 0
	
	# compaction	
	if ((int(t) * 1000) % compact_period == 0):
		for msidx in dirty_MSidx.keys():
			compaction(msidx)
			del(dirty_MSidx[msidx])
		print_size(True)
		#print_size(False)


for msidx in dirty_MSidx.keys():
	compaction(msidx)
	del(dirty_MSidx[msidx])
print_size(True)
#print_size(False)

ideal_erased_mem = (float(discarded_LBA) /4 * 4 + ceil(float(discarded_LBA)/8)) / 1024 / 1024

print("sLBA: {} {} eLBA: {} {} LBAspace_size: {} MB ideal_saved_mem: {} MB".format(global_sLBA, hex(global_sLBA), global_eLBA, hex(global_eLBA), (global_eLBA-global_sLBA)*4/1024, ideal_erased_mem))

'''if (compaction_target_memory > 0):

	compacted_mem = float(compacted_memory)/1024/1024
	truncated_mem = float(truncated_memory)/1024/1024
	dealloc_mapseg_sz = float(dealloc_ms * default_MS_sz)/1024/1024
	dealloc_PT_sz = float(dealloc_ms * default_PT_sz)/1024/1024
	dealloc_trunc_PT_sz = float(dealloc_ms * default_trunc_PT_sz)/1024/1024
	ideal_erased_mem = (float(discarded_LBA) /4 * 4 + ceil(float(discarded_LBA)/8)) / 1024 / 1024
	
	total_dealloc_mem = compacted_mem + dealloc_mapseg_sz 
	#print("compacted memory: {} truncated memory: {} total target memory: {}".format(compacted_memory, truncated_memory, compaction_target_memory))
		
	

	lastLBA = pasteLBA
	#print(hex(firstLBA))
	#wholelen = lastLBA - 0x2002C508
	wholelen = lastLBA - firstLBA
	#print(wholelen)
	wholemapsegcnt = ceil(float(wholelen) / MSblks)
	totalmapsegsz = float(wholemapsegcnt * default_MS_sz) / 1024 / 1024
	totalPTsz = float(wholemapsegcnt * default_PT_sz) / 1024 / 1024
	totaltruncPTsz = float(wholemapsegcnt * default_trunc_PT_sz) / 1024 / 1024

	wholedatanode = wholelen/ parent_map_sz
	#data node's array size
	total_parentsz = wholedatanode * (parent_map_sz /szMS * 4) / 1024 / 1024
	remainder_mapseg_mem = total_parentsz + totalmapsegsz - total_dealloc_mem
	remainder_mapseg_mem_no_compact = total_parentsz + totalmapsegsz - dealloc_mapseg_sz
	remainder_PT_mem = total_parentsz + totalPTsz - dealloc_PT_sz
	remainder_trunc_PT_mem = total_parentsz + totaltruncPTsz - dealloc_trunc_PT_sz - truncated_mem

	#print("{}\t\t{:.2f}\t\t{:.2f}\t\t\t{:.2f}\t\t{:.2f}\t\t{:.2f}\t\t\t{}\t\t{:.2f}\t\t{}\t\t\t{:.2f}\t\t\t\t{}".format(
	print("{}\t\t{:.2f}\t\t{:.2f}\t\t{:.2f}\t\t{:.2f}\t\t\t{:.2f}\t\t\t\t{:.2f}\t\t{:.2f}\t\t\t\t{}".format(
	szMS, # mapsegment sz MB
	float(compacted_memory)/ compaction_target_memory,  # compaction ratio
	#compacted_mem,  # compacted memory
	float(truncated_memory)/compaction_target_memory,  # truncation ratio
	#float(compaction_target_memory)/1024/1024,  # compaction target memory
	float(remainder_mapseg_mem)/(total_parentsz + totalmapsegsz), #tree compaction ratio
	#dealloc_mapseg_sz, # deallocated mapseg size
	#compaction_target_memory / szMS, # target mapseg number
	#total_dealloc_mem, # total deallocated mem
	remainder_mapseg_mem, #remaining mapseg tree memory
	remainder_mapseg_mem_no_compact, #remaining mapseg tree memory without compaction
	remainder_PT_mem, #remaining page table memory
	#remainder_trunc_PT_mem, # remaining page table truncate enable
	ideal_erased_mem, # ideal deallocated memory (MB)
	discarded_LBA * 4 / 1024 )) # discard range (MB)
'''
