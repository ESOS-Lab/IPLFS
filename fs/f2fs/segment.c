// SPDX-License-Identifier: GPL-2.0
/*
 * fs/f2fs/segment.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 */
#include <linux/fs.h>
#include <linux/f2fs_fs.h>
#include <linux/bio.h>
#include <linux/prefetch.h>
#include <linux/kthread.h>
#include <linux/swap.h>
#include <linux/timer.h>
#include <linux/freezer.h>
#include <linux/sched/signal.h>

#include "f2fs.h"
#include "segment.h"
#include "node.h"
#include "gc.h"
#include "trace.h"
#include <trace/events/f2fs.h>

#define __reverse_ffz(x) __reverse_ffs(~(x))

static struct kmem_cache *discard_entry_slab;
static struct kmem_cache *discard_cmd_slab;
static struct kmem_cache *sit_entry_set_slab;
static struct kmem_cache *inmem_entry_slab;
static struct kmem_cache *discard_map_slab;
static struct kmem_cache *discard_range_slab;
DEFINE_HASHTABLE(ht, 7);

static unsigned long __reverse_ulong(unsigned char *str)
{
	unsigned long tmp = 0;
	int shift = 24, idx = 0;

#if BITS_PER_LONG == 64
	shift = 56;
#endif
	while (shift >= 0) {
		tmp |= (unsigned long)str[idx++] << shift;
		shift -= BITS_PER_BYTE;
	}
	return tmp;
}

/*
 * __reverse_ffs is copied from include/asm-generic/bitops/__ffs.h since
 * MSB and LSB are reversed in a byte by f2fs_set_bit.
 */
static inline unsigned long __reverse_ffs(unsigned long word)
{
	int num = 0;

#if BITS_PER_LONG == 64
	if ((word & 0xffffffff00000000UL) == 0)
		num += 32;
	else
		word >>= 32;
#endif
	if ((word & 0xffff0000) == 0)
		num += 16;
	else
		word >>= 16;

	if ((word & 0xff00) == 0)
		num += 8;
	else
		word >>= 8;

	if ((word & 0xf0) == 0)
		num += 4;
	else
		word >>= 4;

	if ((word & 0xc) == 0)
		num += 2;
	else
		word >>= 2;

	if ((word & 0x2) == 0)
		num += 1;
	return num;
}

/*
 * __find_rev_next(_zero)_bit is copied from lib/find_next_bit.c because
 * f2fs_set_bit makes MSB and LSB reversed in a byte.
 * @size must be integral times of unsigned long.
 * Example:
 *                             MSB <--> LSB
 *   f2fs_set_bit(0, bitmap) => 1000 0000
 *   f2fs_set_bit(7, bitmap) => 0000 0001
 */
static unsigned long __find_rev_next_bit(const unsigned long *addr,
			unsigned long size, unsigned long offset)
{
	const unsigned long *p = addr + BIT_WORD(offset);
	unsigned long result = size;
	unsigned long tmp;

	if (offset >= size)
		return size;

	size -= (offset & ~(BITS_PER_LONG - 1));
	offset %= BITS_PER_LONG;

	while (1) {
		if (*p == 0)
			goto pass;

		tmp = __reverse_ulong((unsigned char *)p);

		tmp &= ~0UL >> offset;
		if (size < BITS_PER_LONG)
			tmp &= (~0UL << (BITS_PER_LONG - size));
		if (tmp)
			goto found;
pass:
		if (size <= BITS_PER_LONG)
			break;
		size -= BITS_PER_LONG;
		offset = 0;
		p++;
	}
	return result;
found:
	return result - size + __reverse_ffs(tmp);
}

static unsigned long __find_rev_next_zero_bit(const unsigned long *addr,
			unsigned long size, unsigned long offset)
{
	const unsigned long *p = addr + BIT_WORD(offset);
	unsigned long result = size;
	unsigned long tmp;

	if (offset >= size)
		return size;

	size -= (offset & ~(BITS_PER_LONG - 1));
	offset %= BITS_PER_LONG;

	while (1) {
		if (*p == ~0UL)
			goto pass;

		tmp = __reverse_ulong((unsigned char *)p);

		if (offset)
			tmp |= ~0UL << (BITS_PER_LONG - offset);
		if (size < BITS_PER_LONG)
			tmp |= ~0UL >> size;
		if (tmp != ~0UL)
			goto found;
pass:
		if (size <= BITS_PER_LONG)
			break;
		size -= BITS_PER_LONG;
		offset = 0;
		p++;
	}
	return result;
found:
	return result - size + __reverse_ffz(tmp);
}

bool f2fs_need_SSR(struct f2fs_sb_info *sbi)
{
	int node_secs = get_blocktype_secs(sbi, F2FS_DIRTY_NODES);
	int dent_secs = get_blocktype_secs(sbi, F2FS_DIRTY_DENTS);
	int imeta_secs = get_blocktype_secs(sbi, F2FS_DIRTY_IMETA);

	if (f2fs_lfs_mode(sbi))
		return false;
	panic("f2fs_need_SSR(): not expected!! must be lfs mode!!");
	if (sbi->gc_mode == GC_URGENT_HIGH)
		return true;
	if (unlikely(is_sbi_flag_set(sbi, SBI_CP_DISABLED)))
		return true;

	return free_sections(sbi) <= (node_secs + 2 * dent_secs + imeta_secs +
			SM_I(sbi)->min_ssr_sections + reserved_sections(sbi));
}

void f2fs_register_inmem_page(struct inode *inode, struct page *page)
{
	struct inmem_pages *new;

	f2fs_trace_pid(page);

	f2fs_set_page_private(page, ATOMIC_WRITTEN_PAGE);

	new = f2fs_kmem_cache_alloc(inmem_entry_slab, GFP_NOFS);

	/* add atomic page indices to the list */
	new->page = page;
	INIT_LIST_HEAD(&new->list);

	/* increase reference count with clean state */
	get_page(page);
	mutex_lock(&F2FS_I(inode)->inmem_lock);
	list_add_tail(&new->list, &F2FS_I(inode)->inmem_pages);
	inc_page_count(F2FS_I_SB(inode), F2FS_INMEM_PAGES);
	mutex_unlock(&F2FS_I(inode)->inmem_lock);

	trace_f2fs_register_inmem_page(page, INMEM);
}

static int __revoke_inmem_pages(struct inode *inode,
				struct list_head *head, bool drop, bool recover,
				bool trylock)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct inmem_pages *cur, *tmp;
	int err = 0;

	list_for_each_entry_safe(cur, tmp, head, list) {
		struct page *page = cur->page;

		if (drop)
			trace_f2fs_commit_inmem_page(page, INMEM_DROP);

		if (trylock) {
			/*
			 * to avoid deadlock in between page lock and
			 * inmem_lock.
			 */
			if (!trylock_page(page))
				continue;
		} else {
			lock_page(page);
		}

		f2fs_wait_on_page_writeback(page, DATA, true, true);

		if (recover) {
			struct dnode_of_data dn;
			struct node_info ni;

			trace_f2fs_commit_inmem_page(page, INMEM_REVOKE);
retry:
			set_new_dnode(&dn, inode, NULL, NULL, 0);
			err = f2fs_get_dnode_of_data(&dn, page->index,
								LOOKUP_NODE);
			if (err) {
				if (err == -ENOMEM) {
					congestion_wait(BLK_RW_ASYNC,
							DEFAULT_IO_TIMEOUT);
					cond_resched();
					goto retry;
				}
				err = -EAGAIN;
				goto next;
			}

			err = f2fs_get_node_info(sbi, dn.nid, &ni);
			if (err) {
				f2fs_put_dnode(&dn);
				return err;
			}

			if (cur->old_addr == NEW_ADDR) {
				f2fs_invalidate_blocks(sbi, dn.data_blkaddr);
				f2fs_update_data_blkaddr(&dn, NEW_ADDR);
			} else
				f2fs_replace_block(sbi, &dn, dn.data_blkaddr,
					cur->old_addr, ni.version, true, true);
			f2fs_put_dnode(&dn);
		}
next:
		/* we don't need to invalidate this in the sccessful status */
		if (drop || recover) {
			ClearPageUptodate(page);
			clear_cold_data(page);
		}
		f2fs_clear_page_private(page);
		f2fs_put_page(page, 1);

		list_del(&cur->list);
		kmem_cache_free(inmem_entry_slab, cur);
		dec_page_count(F2FS_I_SB(inode), F2FS_INMEM_PAGES);
	}
	return err;
}

void f2fs_drop_inmem_pages_all(struct f2fs_sb_info *sbi, bool gc_failure)
{
	struct list_head *head = &sbi->inode_list[ATOMIC_FILE];
	struct inode *inode;
	struct f2fs_inode_info *fi;
	unsigned int count = sbi->atomic_files;
	unsigned int looped = 0;
next:
	spin_lock(&sbi->inode_lock[ATOMIC_FILE]);
	if (list_empty(head)) {
		spin_unlock(&sbi->inode_lock[ATOMIC_FILE]);
		return;
	}
	fi = list_first_entry(head, struct f2fs_inode_info, inmem_ilist);
	inode = igrab(&fi->vfs_inode);
	if (inode)
		list_move_tail(&fi->inmem_ilist, head);
	spin_unlock(&sbi->inode_lock[ATOMIC_FILE]);

	if (inode) {
		if (gc_failure) {
			if (!fi->i_gc_failures[GC_FAILURE_ATOMIC])
				goto skip;
		}
		set_inode_flag(inode, FI_ATOMIC_REVOKE_REQUEST);
		f2fs_drop_inmem_pages(inode);
skip:
		iput(inode);
	}
	congestion_wait(BLK_RW_ASYNC, DEFAULT_IO_TIMEOUT);
	cond_resched();
	if (gc_failure) {
		if (++looped >= count)
			return;
	}
	goto next;
}

void f2fs_drop_inmem_pages(struct inode *inode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct f2fs_inode_info *fi = F2FS_I(inode);

	while (!list_empty(&fi->inmem_pages)) {
		mutex_lock(&fi->inmem_lock);
		__revoke_inmem_pages(inode, &fi->inmem_pages,
						true, false, true);
		mutex_unlock(&fi->inmem_lock);
	}

	fi->i_gc_failures[GC_FAILURE_ATOMIC] = 0;

	spin_lock(&sbi->inode_lock[ATOMIC_FILE]);
	if (!list_empty(&fi->inmem_ilist))
		list_del_init(&fi->inmem_ilist);
	if (f2fs_is_atomic_file(inode)) {
		clear_inode_flag(inode, FI_ATOMIC_FILE);
		sbi->atomic_files--;
	}
	spin_unlock(&sbi->inode_lock[ATOMIC_FILE]);
}

void f2fs_drop_inmem_page(struct inode *inode, struct page *page)
{
	struct f2fs_inode_info *fi = F2FS_I(inode);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct list_head *head = &fi->inmem_pages;
	struct inmem_pages *cur = NULL;

	f2fs_bug_on(sbi, !IS_ATOMIC_WRITTEN_PAGE(page));

	mutex_lock(&fi->inmem_lock);
	list_for_each_entry(cur, head, list) {
		if (cur->page == page)
			break;
	}

	f2fs_bug_on(sbi, list_empty(head) || cur->page != page);
	list_del(&cur->list);
	mutex_unlock(&fi->inmem_lock);

	dec_page_count(sbi, F2FS_INMEM_PAGES);
	kmem_cache_free(inmem_entry_slab, cur);

	ClearPageUptodate(page);
	f2fs_clear_page_private(page);
	f2fs_put_page(page, 0);

	trace_f2fs_commit_inmem_page(page, INMEM_INVALIDATE);
}

static int __f2fs_commit_inmem_pages(struct inode *inode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct f2fs_inode_info *fi = F2FS_I(inode);
	struct inmem_pages *cur, *tmp;
	struct f2fs_io_info fio = {
		.sbi = sbi,
		.ino = inode->i_ino,
		.type = DATA,
		.op = REQ_OP_WRITE,
		.op_flags = REQ_SYNC | REQ_PRIO,
		.io_type = FS_DATA_IO,
	};
	struct list_head revoke_list;
	bool submit_bio = false;
	int err = 0;

	INIT_LIST_HEAD(&revoke_list);

	list_for_each_entry_safe(cur, tmp, &fi->inmem_pages, list) {
		struct page *page = cur->page;

		lock_page(page);
		if (page->mapping == inode->i_mapping) {
			trace_f2fs_commit_inmem_page(page, INMEM);

			f2fs_wait_on_page_writeback(page, DATA, true, true);

			set_page_dirty(page);
			if (clear_page_dirty_for_io(page)) {
				inode_dec_dirty_pages(inode);
				f2fs_remove_dirty_inode(inode);
			}
retry:
			fio.page = page;
			fio.old_blkaddr = NULL_ADDR;
			fio.encrypted_page = NULL;
			fio.need_lock = LOCK_DONE;
			err = f2fs_do_write_data_page(&fio);
			if (err) {
				if (err == -ENOMEM) {
					congestion_wait(BLK_RW_ASYNC,
							DEFAULT_IO_TIMEOUT);
					cond_resched();
					goto retry;
				}
				unlock_page(page);
				break;
			}
			/* record old blkaddr for revoking */
			cur->old_addr = fio.old_blkaddr;
			submit_bio = true;
		}
		unlock_page(page);
		list_move_tail(&cur->list, &revoke_list);
	}

	if (submit_bio)
		f2fs_submit_merged_write_cond(sbi, inode, NULL, 0, DATA);

	if (err) {
		/*
		 * try to revoke all committed pages, but still we could fail
		 * due to no memory or other reason, if that happened, EAGAIN
		 * will be returned, which means in such case, transaction is
		 * already not integrity, caller should use journal to do the
		 * recovery or rewrite & commit last transaction. For other
		 * error number, revoking was done by filesystem itself.
		 */
		err = __revoke_inmem_pages(inode, &revoke_list,
						false, true, false);

		/* drop all uncommitted pages */
		__revoke_inmem_pages(inode, &fi->inmem_pages,
						true, false, false);
	} else {
		__revoke_inmem_pages(inode, &revoke_list,
						false, false, false);
	}

	return err;
}

int f2fs_commit_inmem_pages(struct inode *inode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct f2fs_inode_info *fi = F2FS_I(inode);
	int err;

	f2fs_balance_fs(sbi, true);

	down_write(&fi->i_gc_rwsem[WRITE]);

	f2fs_lock_op(sbi);
	set_inode_flag(inode, FI_ATOMIC_COMMIT);

	mutex_lock(&fi->inmem_lock);
	err = __f2fs_commit_inmem_pages(inode);
	mutex_unlock(&fi->inmem_lock);

	clear_inode_flag(inode, FI_ATOMIC_COMMIT);

	f2fs_unlock_op(sbi);
	up_write(&fi->i_gc_rwsem[WRITE]);

	return err;
}

/*
 * This function balances dirty node and dentry pages.
 * In addition, it controls garbage collection.
 */
void f2fs_balance_fs(struct f2fs_sb_info *sbi, bool need)
{
	if (time_to_inject(sbi, FAULT_CHECKPOINT)) {
		f2fs_show_injection_info(sbi, FAULT_CHECKPOINT);
		f2fs_stop_checkpoint(sbi, false);
	}

	/* balance_fs_bg is able to be pending */
	if (need && excess_cached_nats(sbi))
		f2fs_balance_fs_bg(sbi, false);

	if (!f2fs_is_checkpoint_ready(sbi))
		return;

	/*
	 * We should do GC or end up with checkpoint, if there are so many dirty
	 * dir/node pages without enough free segments.
	 */
	//if (has_not_enough_free_secs(sbi, 0, 0)) {
	if (has_not_enough_free_physical_secs(sbi, 0, 0)) {
		panic("f2fs_balance_fs: gc not expected!");
		down_write(&sbi->gc_lock);
		f2fs_gc(sbi, false, false, NULL_SEGNO);
	}
}

void f2fs_balance_fs_bg(struct f2fs_sb_info *sbi, bool from_bg)
{
	if (unlikely(is_sbi_flag_set(sbi, SBI_POR_DOING)))
		return;

	/* try to shrink extent cache when there is no enough memory */
	if (!f2fs_available_free_memory(sbi, EXTENT_CACHE))
		f2fs_shrink_extent_tree(sbi, EXTENT_CACHE_SHRINK_NUMBER);

	/* check the # of cached NAT entries */
	if (!f2fs_available_free_memory(sbi, NAT_ENTRIES))
		f2fs_try_to_free_nats(sbi, NAT_ENTRY_PER_BLOCK);

	if (!f2fs_available_free_memory(sbi, FREE_NIDS))
		f2fs_try_to_free_nids(sbi, MAX_FREE_NIDS);
	else
		f2fs_build_free_nids(sbi, false, false);

	if (excess_dirty_nats(sbi) || excess_dirty_nodes(sbi) ||
		excess_prefree_segs(sbi))
		goto do_sync;

	/* there is background inflight IO or foreground operation recently */
	if (is_inflight_io(sbi, REQ_TIME) ||
		(!f2fs_time_over(sbi, REQ_TIME) && rwsem_is_locked(&sbi->cp_rwsem)))
		return;

	/* exceed periodical checkpoint timeout threshold */
	if (f2fs_time_over(sbi, CP_TIME))
		goto do_sync;

	/* checkpoint is the only way to shrink partial cached entries */
	if (f2fs_available_free_memory(sbi, NAT_ENTRIES) ||
		f2fs_available_free_memory(sbi, INO_ENTRIES))
		return;

do_sync:
	if (test_opt(sbi, DATA_FLUSH) && from_bg) {
		struct blk_plug plug;

		mutex_lock(&sbi->flush_lock);

		blk_start_plug(&plug);
		f2fs_sync_dirty_inodes(sbi, FILE_INODE);
		blk_finish_plug(&plug);

		mutex_unlock(&sbi->flush_lock);
	}
	f2fs_sync_fs(sbi->sb, true);
	stat_inc_bg_cp_count(sbi->stat_info);
}

static int __submit_flush_wait(struct f2fs_sb_info *sbi,
				struct block_device *bdev)
{
	struct bio *bio;
	int ret;

	bio = f2fs_bio_alloc(sbi, 0, false);
	if (!bio)
		return -ENOMEM;

	bio->bi_opf = REQ_OP_WRITE | REQ_SYNC | REQ_PREFLUSH;
	bio_set_dev(bio, bdev);
	ret = submit_bio_wait(bio);
	bio_put(bio);

	trace_f2fs_issue_flush(bdev, test_opt(sbi, NOBARRIER),
				test_opt(sbi, FLUSH_MERGE), ret);
	return ret;
}

static int submit_flush_wait(struct f2fs_sb_info *sbi, nid_t ino)
{
	int ret = 0;
	int i;

	if (!f2fs_is_multi_device(sbi))
		return __submit_flush_wait(sbi, sbi->sb->s_bdev);

	for (i = 0; i < sbi->s_ndevs; i++) {
		if (!f2fs_is_dirty_device(sbi, ino, i, FLUSH_INO))
			continue;
		ret = __submit_flush_wait(sbi, FDEV(i).bdev);
		if (ret)
			break;
	}
	return ret;
}

static int issue_flush_thread(void *data)
{
	struct f2fs_sb_info *sbi = data;
	struct flush_cmd_control *fcc = SM_I(sbi)->fcc_info;
	wait_queue_head_t *q = &fcc->flush_wait_queue;
repeat:
	if (kthread_should_stop())
		return 0;

	sb_start_intwrite(sbi->sb);

	if (!llist_empty(&fcc->issue_list)) {
		struct flush_cmd *cmd, *next;
		int ret;

		fcc->dispatch_list = llist_del_all(&fcc->issue_list);
		fcc->dispatch_list = llist_reverse_order(fcc->dispatch_list);

		cmd = llist_entry(fcc->dispatch_list, struct flush_cmd, llnode);

		ret = submit_flush_wait(sbi, cmd->ino);
		atomic_inc(&fcc->issued_flush);

		llist_for_each_entry_safe(cmd, next,
					  fcc->dispatch_list, llnode) {
			cmd->ret = ret;
			complete(&cmd->wait);
		}
		fcc->dispatch_list = NULL;
	}

	sb_end_intwrite(sbi->sb);

	wait_event_interruptible(*q,
		kthread_should_stop() || !llist_empty(&fcc->issue_list));
	goto repeat;
}

int f2fs_issue_flush(struct f2fs_sb_info *sbi, nid_t ino)
{
	struct flush_cmd_control *fcc = SM_I(sbi)->fcc_info;
	struct flush_cmd cmd;
	int ret;

	if (test_opt(sbi, NOBARRIER))
		return 0;

	if (!test_opt(sbi, FLUSH_MERGE)) {
		atomic_inc(&fcc->queued_flush);
		ret = submit_flush_wait(sbi, ino);
		atomic_dec(&fcc->queued_flush);
		atomic_inc(&fcc->issued_flush);
		return ret;
	}

	if (atomic_inc_return(&fcc->queued_flush) == 1 ||
	    f2fs_is_multi_device(sbi)) {
		ret = submit_flush_wait(sbi, ino);
		atomic_dec(&fcc->queued_flush);

		atomic_inc(&fcc->issued_flush);
		return ret;
	}

	cmd.ino = ino;
	init_completion(&cmd.wait);

	llist_add(&cmd.llnode, &fcc->issue_list);

	/* update issue_list before we wake up issue_flush thread */
	smp_mb();

	if (waitqueue_active(&fcc->flush_wait_queue))
		wake_up(&fcc->flush_wait_queue);

	if (fcc->f2fs_issue_flush) {
		wait_for_completion(&cmd.wait);
		atomic_dec(&fcc->queued_flush);
	} else {
		struct llist_node *list;

		list = llist_del_all(&fcc->issue_list);
		if (!list) {
			wait_for_completion(&cmd.wait);
			atomic_dec(&fcc->queued_flush);
		} else {
			struct flush_cmd *tmp, *next;

			ret = submit_flush_wait(sbi, ino);

			llist_for_each_entry_safe(tmp, next, list, llnode) {
				if (tmp == &cmd) {
					cmd.ret = ret;
					atomic_dec(&fcc->queued_flush);
					continue;
				}
				tmp->ret = ret;
				complete(&tmp->wait);
			}
		}
	}

	return cmd.ret;
}

int f2fs_create_flush_cmd_control(struct f2fs_sb_info *sbi)
{
	dev_t dev = sbi->sb->s_bdev->bd_dev;
	struct flush_cmd_control *fcc;
	int err = 0;

	if (SM_I(sbi)->fcc_info) {
		fcc = SM_I(sbi)->fcc_info;
		if (fcc->f2fs_issue_flush)
			return err;
		goto init_thread;
	}

	fcc = f2fs_kzalloc(sbi, sizeof(struct flush_cmd_control), GFP_KERNEL);
	if (!fcc)
		return -ENOMEM;
	atomic_set(&fcc->issued_flush, 0);
	atomic_set(&fcc->queued_flush, 0);
	init_waitqueue_head(&fcc->flush_wait_queue);
	init_llist_head(&fcc->issue_list);
	SM_I(sbi)->fcc_info = fcc;
	if (!test_opt(sbi, FLUSH_MERGE))
		return err;

init_thread:
	fcc->f2fs_issue_flush = kthread_run(issue_flush_thread, sbi,
				"f2fs_flush-%u:%u", MAJOR(dev), MINOR(dev));
	if (IS_ERR(fcc->f2fs_issue_flush)) {
		err = PTR_ERR(fcc->f2fs_issue_flush);
		kfree(fcc);
		SM_I(sbi)->fcc_info = NULL;
		return err;
	}

	return err;
}

void f2fs_destroy_flush_cmd_control(struct f2fs_sb_info *sbi, bool free)
{
	struct flush_cmd_control *fcc = SM_I(sbi)->fcc_info;

	if (fcc && fcc->f2fs_issue_flush) {
		struct task_struct *flush_thread = fcc->f2fs_issue_flush;

		fcc->f2fs_issue_flush = NULL;
		kthread_stop(flush_thread);
	}
	if (free) {
		kfree(fcc);
		SM_I(sbi)->fcc_info = NULL;
	}
}

int f2fs_flush_device_cache(struct f2fs_sb_info *sbi)
{
	int ret = 0, i;

	if (!f2fs_is_multi_device(sbi))
		return 0;

	if (test_opt(sbi, NOBARRIER))
		return 0;

	for (i = 1; i < sbi->s_ndevs; i++) {
		if (!f2fs_test_bit(i, (char *)&sbi->dirty_device))
			continue;
		ret = __submit_flush_wait(sbi, FDEV(i).bdev);
		if (ret)
			break;

		spin_lock(&sbi->dev_lock);
		f2fs_clear_bit(i, (char *)&sbi->dirty_device);
		spin_unlock(&sbi->dev_lock);
	}

	return ret;
}

static void __locate_dirty_segment(struct f2fs_sb_info *sbi, unsigned int segno,
		enum dirty_type dirty_type)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);

	/* need not be added */
	if (IS_CURSEG(sbi, segno))
		return;

	if (!test_and_set_bit(segno, dirty_i->dirty_segmap[dirty_type]))
		dirty_i->nr_dirty[dirty_type]++;

	/*if (dirty_type == DIRTY) {
		struct seg_entry *sentry = get_seg_entry(sbi, segno);
		enum dirty_type t = sentry->type;

		if (unlikely(t >= DIRTY)) {
			f2fs_bug_on(sbi, 1);
			return;
		}
		if (!test_and_set_bit(segno, dirty_i->dirty_segmap[t]))
			dirty_i->nr_dirty[t]++;

		if (__is_large_section(sbi)) {
			unsigned int secno = GET_SEC_FROM_SEG(sbi, segno);
			block_t valid_blocks =
				get_valid_blocks(sbi, segno, true);

			f2fs_bug_on(sbi, unlikely(!valid_blocks ||
					valid_blocks == BLKS_PER_SEC(sbi)));

			if (!IS_CURSEC(sbi, secno))
				set_bit(secno, dirty_i->dirty_secmap);
		}
	}*/
}

static void __remove_dirty_segment(struct f2fs_sb_info *sbi, unsigned int segno,
		enum dirty_type dirty_type)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	block_t valid_blocks;

	if (test_and_clear_bit(segno, dirty_i->dirty_segmap[dirty_type]))
		dirty_i->nr_dirty[dirty_type]--;

	if (dirty_type == DIRTY) {
		struct seg_entry *sentry = get_seg_entry(sbi, segno);
		enum dirty_type t = sentry->type;

		if (test_and_clear_bit(segno, dirty_i->dirty_segmap[t]))
			dirty_i->nr_dirty[t]--;

		valid_blocks = get_valid_blocks(sbi, segno, true);
		if (valid_blocks == 0) {
			clear_bit(GET_SEC_FROM_SEG(sbi, segno),
						dirty_i->victim_secmap);
#ifdef CONFIG_F2FS_CHECK_FS
			clear_bit(segno, SIT_I(sbi)->invalid_segmap);
#endif
		}
		if (__is_large_section(sbi)) {
			unsigned int secno = GET_SEC_FROM_SEG(sbi, segno);

			if (!valid_blocks ||
					valid_blocks == BLKS_PER_SEC(sbi)) {
				clear_bit(secno, dirty_i->dirty_secmap);
				return;
			}

			if (!IS_CURSEC(sbi, secno))
				set_bit(secno, dirty_i->dirty_secmap);
		}
	}
}

/*
 * Should not occur error such as -ENOMEM.
 * Adding dirty entry into seglist is not critical operation.
 * If a given segment is one of current working segments, it won't be added.
 */
static void locate_dirty_segment(struct f2fs_sb_info *sbi, unsigned int segno)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	unsigned short valid_blocks, ckpt_valid_blocks;
	unsigned int usable_blocks;

	if (segno == NULL_SEGNO || IS_CURSEG(sbi, segno))
		return;
	/*
	usable_blocks = f2fs_usable_blks_in_seg(sbi, segno);
	mutex_lock(&dirty_i->seglist_lock);

	valid_blocks = get_valid_blocks(sbi, segno, false);
	//ckpt_valid_blocks = get_ckpt_valid_blocks(sbi, segno);

	if (valid_blocks == 0 && (!is_sbi_flag_set(sbi, SBI_CP_DISABLED) ||
		ckpt_valid_blocks == usable_blocks)) {
		//__locate_dirty_segment(sbi, segno, PRE);
		//__remove_dirty_segment(sbi, segno, DIRTY);
	} else if (valid_blocks < usable_blocks) {
		//__locate_dirty_segment(sbi, segno, DIRTY);
	} else {
		// Recovery routine with SSR needs this 
		//__remove_dirty_segment(sbi, segno, DIRTY);
	}
	mutex_unlock(&dirty_i->seglist_lock);
	*/
}

/* This moves currently empty dirty blocks to prefree. Must hold seglist_lock */
void f2fs_dirty_to_prefree(struct f2fs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	unsigned int segno;

	mutex_lock(&dirty_i->seglist_lock);
	for_each_set_bit(segno, dirty_i->dirty_segmap[DIRTY], MAIN_SEGS(sbi)) {
		if (get_valid_blocks(sbi, segno, false))
			continue;
		if (IS_CURSEG(sbi, segno))
			continue;
		//__locate_dirty_segment(sbi, segno, PRE);
		//__remove_dirty_segment(sbi, segno, DIRTY);
	}
	mutex_unlock(&dirty_i->seglist_lock);
}

block_t f2fs_get_unusable_blocks(struct f2fs_sb_info *sbi)
{
	panic("f2fs_get_unusable_blocks: did not expect");
	/*
	int ovp_hole_segs =
		(overprovision_segments(sbi) - reserved_segments(sbi));
	block_t ovp_holes = ovp_hole_segs << sbi->log_blocks_per_seg;
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	block_t holes[2] = {0, 0};	// DATA and NODE 
	block_t unusable;
	struct seg_entry *se;
	unsigned int segno;
	mutex_lock(&dirty_i->seglist_lock);
	for_each_set_bit(segno, dirty_i->dirty_segmap[DIRTY], MAIN_SEGS(sbi)) {
		se = get_seg_entry(sbi, segno);
		if (IS_NODESEG(se->type))
			holes[NODE] += f2fs_usable_blks_in_seg(sbi, segno) -
							se->valid_blocks;
		else
			holes[DATA] += f2fs_usable_blks_in_seg(sbi, segno) -
							se->valid_blocks;
	}
	mutex_unlock(&dirty_i->seglist_lock);
	unusable = holes[DATA] > holes[NODE] ? holes[DATA] : holes[NODE];
	if (unusable > ovp_holes)
		return unusable - ovp_holes;
	return 0;
	*/
}

int f2fs_disable_cp_again(struct f2fs_sb_info *sbi, block_t unusable)
{
	int ovp_hole_segs =
		(overprovision_segments(sbi) - reserved_segments(sbi));
	if (unusable > F2FS_OPTION(sbi).unusable_cap)
		return -EAGAIN;
	if (is_sbi_flag_set(sbi, SBI_CP_DISABLED_QUICK))
		panic("f2fs_disable_cp_again(): SBI_CP_DISABLED_QUICK not expected!!");
	/*if (is_sbi_flag_set(sbi, SBI_CP_DISABLED_QUICK) &&
		dirty_segments(sbi) > ovp_hole_segs)
		return -EAGAIN;
	*/
	return 0;
}

/* This is only used by SBI_CP_DISABLED */
static unsigned int get_free_segment(struct f2fs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	unsigned int segno = 0;

	mutex_lock(&dirty_i->seglist_lock);
	for_each_set_bit(segno, dirty_i->dirty_segmap[DIRTY], MAIN_SEGS(sbi)) {
		if (get_valid_blocks(sbi, segno, false))
			continue;
		if (get_ckpt_valid_blocks(sbi, segno))
			continue;
		mutex_unlock(&dirty_i->seglist_lock);
		return segno;
	}
	mutex_unlock(&dirty_i->seglist_lock);
	return NULL_SEGNO;
}

static struct discard_cmd *__create_discard_cmd(struct f2fs_sb_info *sbi,
		struct block_device *bdev, block_t lstart,
		block_t start, block_t len)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct list_head *pend_list;
	struct discard_cmd *dc;

	f2fs_bug_on(sbi, !len);

	pend_list = &dcc->pend_list[plist_idx(len)];

	dc = f2fs_kmem_cache_alloc(discard_cmd_slab, GFP_NOFS);
	INIT_LIST_HEAD(&dc->list);
	dc->bdev = bdev;
	dc->lstart = lstart;
	dc->start = start;
	dc->len = len;
	dc->ref = 0;
	dc->state = D_PREP;
	dc->queued = 0;
	dc->error = 0;
	init_completion(&dc->wait);
	list_add_tail(&dc->list, pend_list);
	spin_lock_init(&dc->lock);
	dc->bio_ref = 0;
	atomic_inc(&dcc->discard_cmd_cnt);
	dcc->undiscard_blks += len;

	return dc;
}

static struct discard_cmd *__attach_discard_cmd(struct f2fs_sb_info *sbi,
				struct block_device *bdev, block_t lstart,
				block_t start, block_t len,
				struct rb_node *parent, struct rb_node **p,
				bool leftmost)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct discard_cmd *dc;

	dc = __create_discard_cmd(sbi, bdev, lstart, start, len);

	rb_link_node(&dc->rb_node, parent, p);
	rb_insert_color_cached(&dc->rb_node, &dcc->root, leftmost);

	return dc;
}

static void __detach_discard_cmd(struct discard_cmd_control *dcc,
							struct discard_cmd *dc)
{
	if (dc->state == D_DONE)
		atomic_sub(dc->queued, &dcc->queued_discard);

	list_del(&dc->list);
	rb_erase_cached(&dc->rb_node, &dcc->root);
	dcc->undiscard_blks -= dc->len;

	kmem_cache_free(discard_cmd_slab, dc);

	atomic_dec(&dcc->discard_cmd_cnt);
}

static void __remove_discard_cmd(struct f2fs_sb_info *sbi,
							struct discard_cmd *dc)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	unsigned long flags;

	trace_f2fs_remove_discard(dc->bdev, dc->start, dc->len);

	spin_lock_irqsave(&dc->lock, flags);
	if (dc->bio_ref) {
		spin_unlock_irqrestore(&dc->lock, flags);
		return;
	}
	spin_unlock_irqrestore(&dc->lock, flags);

	f2fs_bug_on(sbi, dc->ref);

	if (dc->error == -EOPNOTSUPP)
		dc->error = 0;

	if (dc->error)
		printk_ratelimited(
			"%sF2FS-fs (%s): Issue discard(%u, %u, %u) failed, ret: %d",
			KERN_INFO, sbi->sb->s_id,
			dc->lstart, dc->start, dc->len, dc->error);
	__detach_discard_cmd(dcc, dc);
}

static void f2fs_submit_discard_endio(struct bio *bio)
{
	struct discard_cmd *dc = (struct discard_cmd *)bio->bi_private;
	unsigned long flags;

	spin_lock_irqsave(&dc->lock, flags);
	if (!dc->error)
		dc->error = blk_status_to_errno(bio->bi_status);
	dc->bio_ref--;
	if (!dc->bio_ref && dc->state == D_SUBMIT) {
		dc->state = D_DONE;
		complete_all(&dc->wait);
	}
	spin_unlock_irqrestore(&dc->lock, flags);
	bio_put(bio);
}

static void __check_sit_bitmap(struct f2fs_sb_info *sbi,
				block_t start, block_t end)
{
#ifdef CONFIG_F2FS_CHECK_FS
	struct seg_entry *sentry;
	unsigned int segno;
	block_t blk = start;
	unsigned long offset, size, max_blocks = sbi->blocks_per_seg;
	unsigned long *map;

	while (blk < end) {
		segno = GET_SEGNO(sbi, blk);
		sentry = get_seg_entry(sbi, segno);
		offset = GET_BLKOFF_FROM_SEG0(sbi, blk);

		if (end < START_BLOCK(sbi, segno + 1))
			size = GET_BLKOFF_FROM_SEG0(sbi, end);
		else
			size = max_blocks;
		map = (unsigned long *)(sentry->cur_valid_map);
		offset = __find_rev_next_bit(map, size, offset);
		f2fs_bug_on(sbi, offset != size);
		blk = START_BLOCK(sbi, segno + 1);
	}
#endif
}

static void __init_discard_policy(struct f2fs_sb_info *sbi,
				struct discard_policy *dpolicy,
				int discard_type, unsigned int granularity)
{
	/* common policy */
	dpolicy->type = discard_type;
	dpolicy->sync = true;
	dpolicy->ordered = false;
	dpolicy->granularity = granularity;

	dpolicy->max_requests = DEF_MAX_DISCARD_REQUEST;
	//dpolicy->max_requests = 5000000;//DEF_MAX_DISCARD_REQUEST;
	dpolicy->io_aware_gran = MAX_PLIST_NUM;
	dpolicy->timeout = false;

	if (discard_type == DPOLICY_BG) {
		dpolicy->min_interval = DEF_MIN_DISCARD_ISSUE_TIME;
		dpolicy->mid_interval = DEF_MID_DISCARD_ISSUE_TIME;
		dpolicy->max_interval = DEF_MAX_DISCARD_ISSUE_TIME;
		dpolicy->io_aware = true;
		dpolicy->sync = false;
		dpolicy->ordered = true;
		if (utilization(sbi) > DEF_DISCARD_URGENT_UTIL) {
			dpolicy->granularity = 1;
			dpolicy->max_interval = DEF_MIN_DISCARD_ISSUE_TIME;
		}
	} else if (discard_type == DPOLICY_FORCE) {
		dpolicy->min_interval = DEF_MIN_DISCARD_ISSUE_TIME;
		dpolicy->mid_interval = DEF_MID_DISCARD_ISSUE_TIME;
		dpolicy->max_interval = DEF_MAX_DISCARD_ISSUE_TIME;
		dpolicy->io_aware = false;
	} else if (discard_type == DPOLICY_FSTRIM) {
		dpolicy->io_aware = false;
	} else if (discard_type == DPOLICY_UMOUNT) {
		dpolicy->io_aware = false;
		/* we need to issue all to keep CP_TRIMMED_FLAG */
		dpolicy->granularity = 1;
		dpolicy->ordered = true;
		dpolicy->max_requests = 500000000;//DEF_MAX_DISCARD_REQUEST;
		//dpolicy->timeout = true;
	}
}

static void __update_discard_tree_range(struct f2fs_sb_info *sbi,
				struct block_device *bdev, block_t lstart,
				block_t start, block_t len);
/* this function is copied from blkdev_issue_discard from block/blk-lib.c */
static int __submit_discard_cmd(struct f2fs_sb_info *sbi,
						struct discard_policy *dpolicy,
						struct discard_cmd *dc,
						unsigned int *issued)
{
	struct block_device *bdev = dc->bdev;
	struct request_queue *q = bdev_get_queue(bdev);
	unsigned int max_discard_blocks =
			SECTOR_TO_BLOCK(q->limits.max_discard_sectors);
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct list_head *wait_list = (dpolicy->type == DPOLICY_FSTRIM) ?
					&(dcc->fstrim_list) : &(dcc->wait_list);
	int flag = dpolicy->sync ? REQ_SYNC : 0;
	block_t lstart, start, len, total_len;
	int err = 0;


	if (dc->state != D_PREP)
		return 0;

	if (is_sbi_flag_set(sbi, SBI_NEED_FSCK))
		return 0;

	trace_f2fs_issue_discard(bdev, dc->start, dc->len);

	lstart = dc->lstart;
	start = dc->start;
	len = dc->len;
	total_len = len;

	dc->len = 0;

	while (total_len && *issued < dpolicy->max_requests && !err) {
		struct bio *bio = NULL;
		unsigned long flags;
		bool last = true;

		if (len > max_discard_blocks) {
			len = max_discard_blocks;
			last = false;
		}

		(*issued)++;
		if (*issued == dpolicy->max_requests)
			last = true;

		dc->len += len;

		if (time_to_inject(sbi, FAULT_DISCARD)) {
			f2fs_show_injection_info(sbi, FAULT_DISCARD);
			err = -EIO;
			goto submit;
		}
		err = __blkdev_issue_discard(bdev,
					SECTOR_FROM_BLOCK(start),
					SECTOR_FROM_BLOCK(len),
					GFP_NOFS, 0, &bio);
submit:
		if (err) {
			spin_lock_irqsave(&dc->lock, flags);
			if (dc->state == D_PARTIAL)
				dc->state = D_SUBMIT;
			spin_unlock_irqrestore(&dc->lock, flags);

			break;
		}

		f2fs_bug_on(sbi, !bio);

		/*
		 * should keep before submission to avoid D_DONE
		 * right away
		 */
		spin_lock_irqsave(&dc->lock, flags);
		if (last)
			dc->state = D_SUBMIT;
		else
			dc->state = D_PARTIAL;
		dc->bio_ref++;
		spin_unlock_irqrestore(&dc->lock, flags);

		atomic_inc(&dcc->queued_discard);
		dc->queued++;
		list_move_tail(&dc->list, wait_list);

		/* sanity check on discard range */
		//__check_sit_bitmap(sbi, lstart, lstart + len);

		bio->bi_private = dc;
		bio->bi_end_io = f2fs_submit_discard_endio;
		bio->bi_opf |= flag;
		submit_bio(bio);

		atomic_inc(&dcc->issued_discard);

		f2fs_update_iostat(sbi, FS_DISCARD, 1);

		lstart += len;
		start += len;
		total_len -= len;
		len = total_len;
	}

	if (!err && len) {
		dcc->undiscard_blks -= len;
		__update_discard_tree_range(sbi, bdev, lstart, start, len);
	}
	return err;
}

static void __insert_discard_tree(struct f2fs_sb_info *sbi,
				struct block_device *bdev, block_t lstart,
				block_t start, block_t len,
				struct rb_node **insert_p,
				struct rb_node *insert_parent)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct rb_node **p;
	struct rb_node *parent = NULL;
	bool leftmost = true;

	if (insert_p && insert_parent) {
		parent = insert_parent;
		p = insert_p;
		goto do_insert;
	}

	p = f2fs_lookup_rb_tree_for_insert(sbi, &dcc->root, &parent,
							lstart, &leftmost);
do_insert:
	__attach_discard_cmd(sbi, bdev, lstart, start, len, parent,
								p, leftmost);
}

static void __relocate_discard_cmd(struct discard_cmd_control *dcc,
						struct discard_cmd *dc)
{
	list_move_tail(&dc->list, &dcc->pend_list[plist_idx(dc->len)]);
}

static void __punch_discard_cmd(struct f2fs_sb_info *sbi,
				struct discard_cmd *dc, block_t blkaddr)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct discard_info di = dc->di;
	bool modified = false;

	if (dc->state == D_DONE || dc->len == 1) {
		__remove_discard_cmd(sbi, dc);
		return;
	}

	dcc->undiscard_blks -= di.len;

	if (blkaddr > di.lstart) {
		dc->len = blkaddr - dc->lstart;
		dcc->undiscard_blks += dc->len;
		__relocate_discard_cmd(dcc, dc);
		modified = true;
	}

	if (blkaddr < di.lstart + di.len - 1) {
		if (modified) {
			__insert_discard_tree(sbi, dc->bdev, blkaddr + 1,
					di.start + blkaddr + 1 - di.lstart,
					di.lstart + di.len - 1 - blkaddr,
					NULL, NULL);
		} else {
			dc->lstart++;
			dc->len--;
			dc->start++;
			dcc->undiscard_blks += dc->len;
			__relocate_discard_cmd(dcc, dc);
		}
	}
}

static void __update_discard_tree_range(struct f2fs_sb_info *sbi,
				struct block_device *bdev, block_t lstart,
				block_t start, block_t len)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct discard_cmd *prev_dc = NULL, *next_dc = NULL;
	struct discard_cmd *dc;
	struct discard_info di = {0};
	struct rb_node **insert_p = NULL, *insert_parent = NULL;
	struct request_queue *q = bdev_get_queue(bdev);
	unsigned int max_discard_blocks =
			SECTOR_TO_BLOCK(q->limits.max_discard_sectors);
	block_t end = lstart + len;

	dc = (struct discard_cmd *)f2fs_lookup_rb_tree_ret(&dcc->root,
					NULL, lstart,
					(struct rb_entry **)&prev_dc,
					(struct rb_entry **)&next_dc,
					&insert_p, &insert_parent, true, NULL);
	if (dc)
		prev_dc = dc;

	if (!prev_dc) {
		di.lstart = lstart;
		di.len = next_dc ? next_dc->lstart - lstart : len;
		di.len = min(di.len, len);
		di.start = start;
	}

	while (1) {
		struct rb_node *node;
		bool merged = false;
		struct discard_cmd *tdc = NULL;

		if (prev_dc) {
			di.lstart = prev_dc->lstart + prev_dc->len;
			if (di.lstart < lstart)
				di.lstart = lstart;
			if (di.lstart >= end)
				break;

			if (!next_dc || next_dc->lstart > end)
				di.len = end - di.lstart;
			else
				di.len = next_dc->lstart - di.lstart;
			di.start = start + di.lstart - lstart;
		}

		if (!di.len)
			goto next;

		if (prev_dc && prev_dc->state == D_PREP &&
			prev_dc->bdev == bdev &&
			__is_discard_back_mergeable(&di, &prev_dc->di,
							max_discard_blocks)) {
			prev_dc->di.len += di.len;
			dcc->undiscard_blks += di.len;
			__relocate_discard_cmd(dcc, prev_dc);
			di = prev_dc->di;
			tdc = prev_dc;
			merged = true;
		}

		if (next_dc && next_dc->state == D_PREP &&
			next_dc->bdev == bdev &&
			__is_discard_front_mergeable(&di, &next_dc->di,
							max_discard_blocks)) {
			next_dc->di.lstart = di.lstart;
			next_dc->di.len += di.len;
			next_dc->di.start = di.start;
			dcc->undiscard_blks += di.len;
			__relocate_discard_cmd(dcc, next_dc);
			if (tdc)
				__remove_discard_cmd(sbi, tdc);
			merged = true;
		}

		if (!merged) {
			__insert_discard_tree(sbi, bdev, di.lstart, di.start,
							di.len, NULL, NULL);
		}
 next:
		prev_dc = next_dc;
		if (!prev_dc)
			break;

		node = rb_next(&prev_dc->rb_node);
		next_dc = rb_entry_safe(node, struct discard_cmd, rb_node);
	}
}

static int __queue_discard_cmd(struct f2fs_sb_info *sbi,
		struct block_device *bdev, block_t blkstart, block_t blklen)
{
	block_t lblkstart = blkstart;

	if (!f2fs_bdev_support_discard(bdev))
		return 0;

	trace_f2fs_queue_discard(bdev, blkstart, blklen);

	if (f2fs_is_multi_device(sbi)) {
		int devi = f2fs_target_device_index(sbi, blkstart);

		blkstart -= FDEV(devi).start_blk;
	}
	mutex_lock(&SM_I(sbi)->dcc_info->cmd_lock);
	__update_discard_tree_range(sbi, bdev, lblkstart, blkstart, blklen);
	mutex_unlock(&SM_I(sbi)->dcc_info->cmd_lock);
	return 0;
}

static unsigned int __issue_discard_cmd_orderly(struct f2fs_sb_info *sbi,
					struct discard_policy *dpolicy)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct discard_cmd *prev_dc = NULL, *next_dc = NULL;
	struct rb_node **insert_p = NULL, *insert_parent = NULL;
	struct discard_cmd *dc;
	struct blk_plug plug;
	unsigned int pos = dcc->next_pos;
	unsigned int issued = 0;
	bool io_interrupted = false;

	mutex_lock(&dcc->cmd_lock);
	dc = (struct discard_cmd *)f2fs_lookup_rb_tree_ret(&dcc->root,
					NULL, pos,
					(struct rb_entry **)&prev_dc,
					(struct rb_entry **)&next_dc,
					&insert_p, &insert_parent, true, NULL);
	if (!dc)
		dc = next_dc;

	blk_start_plug(&plug);

	while (dc) {
		struct rb_node *node;
		int err = 0;

		if (dc->state != D_PREP)
			goto next;

		/*if (dpolicy->io_aware && !is_idle(sbi, DISCARD_TIME)) {
			io_interrupted = true;
			break;
		}*/

		dcc->next_pos = dc->lstart + dc->len;
		err = __submit_discard_cmd(sbi, dpolicy, dc, &issued);

		if (issued >= dpolicy->max_requests)
			break;
next:
		node = rb_next(&dc->rb_node);
		if (err)
			__remove_discard_cmd(sbi, dc);
		dc = rb_entry_safe(node, struct discard_cmd, rb_node);
	}

	blk_finish_plug(&plug);

	if (!dc)
		dcc->next_pos = 0;

	mutex_unlock(&dcc->cmd_lock);

	if (!issued && io_interrupted)
		issued = -1;

	return issued;
}
static unsigned int __wait_all_discard_cmd(struct f2fs_sb_info *sbi,
					struct discard_policy *dpolicy);

static int __issue_discard_cmd(struct f2fs_sb_info *sbi,
					struct discard_policy *dpolicy)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct list_head *pend_list;
	struct discard_cmd *dc, *tmp;
	struct blk_plug plug;
	int i, issued;
	bool io_interrupted = false;
	//static unsigned int issue_cnt = 0;
	//static unsigned int order_cnt = 0;
	//static unsigned int pend_cnt = 0;
	//int rtr = 0;
	//issue_cnt += 1;
	//printk("[JW DBG] %s: discard issue cnt: %u \n", __func__, issue_cnt);


	if (dpolicy->timeout)
		f2fs_update_time(sbi, UMOUNT_DISCARD_TIMEOUT);

retry:
	issued = 0;
	for (i = MAX_PLIST_NUM - 1; i >= 0; i--) {
	//	if (dpolicy->timeout &&
	//			f2fs_time_over(sbi, UMOUNT_DISCARD_TIMEOUT))
	//		break;

	//	if (i + 1 < dpolicy->granularity)
	//		break;

		if (i < DEFAULT_DISCARD_GRANULARITY && dpolicy->ordered)
			return  __issue_discard_cmd_orderly(sbi, dpolicy);
			//pend_cnt += issued;
			//printk("[JW DBG] %s: discard pend cnt: %u \n", __func__, pend_cnt);
			//order_cnt += rtr;
			//printk("[JW DBG] %s: discard order cnt: %u \n", __func__, order_cnt);
			//return rtr;
		pend_list = &dcc->pend_list[i];

		mutex_lock(&dcc->cmd_lock);
		if (list_empty(pend_list))
			goto next;
		if (unlikely(dcc->rbtree_check))
			f2fs_bug_on(sbi, !f2fs_check_rb_tree_consistence(sbi,
							&dcc->root, false));
		blk_start_plug(&plug);
		list_for_each_entry_safe(dc, tmp, pend_list, list) {
			f2fs_bug_on(sbi, dc->state != D_PREP);

			if (dpolicy->timeout &&
				f2fs_time_over(sbi, UMOUNT_DISCARD_TIMEOUT))
				break;

			/*if (dpolicy->io_aware && i < dpolicy->io_aware_gran &&
						!is_idle(sbi, DISCARD_TIME)) {
				io_interrupted = true;
				break;
			}*/

			//printk("[JW DBG] %s: submit discard", __func__);
			__submit_discard_cmd(sbi, dpolicy, dc, &issued);

			if (issued >= dpolicy->max_requests && dpolicy->type != DPOLICY_UMOUNT)
				break;
		}
		blk_finish_plug(&plug);
next:
		mutex_unlock(&dcc->cmd_lock);

		if (issued >= dpolicy->max_requests && dpolicy->type != DPOLICY_UMOUNT)// || io_interrupted)
			break;
	}

	if (dpolicy->type == DPOLICY_UMOUNT && issued) {
		__wait_all_discard_cmd(sbi, dpolicy);
		goto retry;
	}

	if (!issued && io_interrupted)
		issued = -1;

	//pend_cnt += issued;
	//printk("[JW DBG] %s: discard pend cnt: %u \n", __func__, pend_cnt);
	//printk("[JW DBG] %s: discard order cnt: %u \n", __func__, order_cnt);
	return issued;
}

static bool __drop_discard_cmd(struct f2fs_sb_info *sbi)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct list_head *pend_list;
	struct discard_cmd *dc, *tmp;
	int i;
	bool dropped = false;

	mutex_lock(&dcc->cmd_lock);
	for (i = MAX_PLIST_NUM - 1; i >= 0; i--) {
		pend_list = &dcc->pend_list[i];
		list_for_each_entry_safe(dc, tmp, pend_list, list) {
			f2fs_bug_on(sbi, dc->state != D_PREP);
			__remove_discard_cmd(sbi, dc);
			dropped = true;
		}
	}
	mutex_unlock(&dcc->cmd_lock);

	return dropped;
}

void f2fs_drop_discard_cmd(struct f2fs_sb_info *sbi)
{
	__drop_discard_cmd(sbi);
}

static unsigned int __wait_one_discard_bio(struct f2fs_sb_info *sbi,
							struct discard_cmd *dc)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	unsigned int len = 0;

	wait_for_completion_io(&dc->wait);
	mutex_lock(&dcc->cmd_lock);
	f2fs_bug_on(sbi, dc->state != D_DONE);
	dc->ref--;
	if (!dc->ref) {
		if (!dc->error)
			len = dc->len;
		__remove_discard_cmd(sbi, dc);
	}
	mutex_unlock(&dcc->cmd_lock);

	return len;
}

static unsigned int __wait_discard_cmd_range(struct f2fs_sb_info *sbi,
						struct discard_policy *dpolicy,
						block_t start, block_t end)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct list_head *wait_list = (dpolicy->type == DPOLICY_FSTRIM) ?
					&(dcc->fstrim_list) : &(dcc->wait_list);
	struct discard_cmd *dc, *tmp;
	bool need_wait;
	unsigned int trimmed = 0;

next:
	need_wait = false;

	mutex_lock(&dcc->cmd_lock);
	list_for_each_entry_safe(dc, tmp, wait_list, list) {
		if (dc->lstart + dc->len <= start || end <= dc->lstart)
			continue;
		if (dc->len < dpolicy->granularity)
			continue;
		if (dc->state == D_DONE && !dc->ref) {
			wait_for_completion_io(&dc->wait);
			if (!dc->error)
				trimmed += dc->len;
			__remove_discard_cmd(sbi, dc);
		} else {
			dc->ref++;
			need_wait = true;
			break;
		}
	}
	mutex_unlock(&dcc->cmd_lock);

	if (need_wait) {
		trimmed += __wait_one_discard_bio(sbi, dc);
		goto next;
	}

	return trimmed;
}

static unsigned int __wait_all_discard_cmd(struct f2fs_sb_info *sbi,
						struct discard_policy *dpolicy)
{
	struct discard_policy dp;
	unsigned int discard_blks;

	if (dpolicy)
		return __wait_discard_cmd_range(sbi, dpolicy, 0, UINT_MAX);

	/* wait all */
	__init_discard_policy(sbi, &dp, DPOLICY_FSTRIM, 1);
	discard_blks = __wait_discard_cmd_range(sbi, &dp, 0, UINT_MAX);
	__init_discard_policy(sbi, &dp, DPOLICY_UMOUNT, 1);
	discard_blks += __wait_discard_cmd_range(sbi, &dp, 0, UINT_MAX);

	return discard_blks;
}

/* This should be covered by global mutex, &sit_i->sentry_lock */
static void f2fs_wait_discard_bio(struct f2fs_sb_info *sbi, block_t blkaddr)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct discard_cmd *dc;
	bool need_wait = false;

	mutex_lock(&dcc->cmd_lock);
	dc = (struct discard_cmd *)f2fs_lookup_rb_tree(&dcc->root,
							NULL, blkaddr);
	if (dc) {
		if (dc->state == D_PREP) {
			__punch_discard_cmd(sbi, dc, blkaddr);
		} else {
			dc->ref++;
			need_wait = true;
		}
	}
	mutex_unlock(&dcc->cmd_lock);

	if (need_wait)
		__wait_one_discard_bio(sbi, dc);
}

void f2fs_stop_discard_thread(struct f2fs_sb_info *sbi)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;

	if (dcc && dcc->f2fs_issue_discard) {
		struct task_struct *discard_thread = dcc->f2fs_issue_discard;

		dcc->f2fs_issue_discard = NULL;
		kthread_stop(discard_thread);
	}
}

/* This comes from f2fs_put_super */
bool f2fs_issue_discard_timeout(struct f2fs_sb_info *sbi)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct discard_policy dpolicy;
	bool dropped;

	__init_discard_policy(sbi, &dpolicy, DPOLICY_UMOUNT,
					dcc->discard_granularity);
	__issue_discard_cmd(sbi, &dpolicy);
	dropped = __drop_discard_cmd(sbi);

	/* just to make sure there is no pending discard commands */
	__wait_all_discard_cmd(sbi, NULL);

	f2fs_bug_on(sbi, atomic_read(&dcc->discard_cmd_cnt));
	return dropped;
}

static int issue_discard_thread(void *data)
{
	struct f2fs_sb_info *sbi = data;
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	wait_queue_head_t *q = &dcc->discard_wait_queue;
	struct discard_policy dpolicy;
	unsigned int wait_ms = DEF_MIN_DISCARD_ISSUE_TIME;
	int issued;

	set_freezable();

	do {
		__init_discard_policy(sbi, &dpolicy, DPOLICY_BG,
					dcc->discard_granularity);

		wait_event_interruptible_timeout(*q,
				kthread_should_stop() || freezing(current) ||
				dcc->discard_wake,
				msecs_to_jiffies(wait_ms));

		if (dcc->discard_wake)
			dcc->discard_wake = 0;

		/* clean up pending candidates before going to sleep */
		if (atomic_read(&dcc->queued_discard))
			__wait_all_discard_cmd(sbi, NULL);

		if (try_to_freeze())
			continue;
		if (f2fs_readonly(sbi->sb))
			continue;
		if (kthread_should_stop())
			return 0;
		if (is_sbi_flag_set(sbi, SBI_NEED_FSCK)) {
			wait_ms = dpolicy.max_interval;
			continue;
		}

		if (sbi->gc_mode == GC_URGENT_HIGH)
			__init_discard_policy(sbi, &dpolicy, DPOLICY_FORCE, 1);

		sb_start_intwrite(sbi->sb);

		issued = __issue_discard_cmd(sbi, &dpolicy);
		if (issued > 0) {
			__wait_all_discard_cmd(sbi, &dpolicy);
			wait_ms = dpolicy.min_interval;
			//wait_ms = dpolicy.max_interval;
		} else if (issued == -1){
			wait_ms = f2fs_time_to_wait(sbi, DISCARD_TIME);
			if (!wait_ms)
				wait_ms = dpolicy.mid_interval;
		} else {
			wait_ms = dpolicy.max_interval;
		}

		sb_end_intwrite(sbi->sb);

	} while (!kthread_should_stop());
	return 0;
}

#ifdef CONFIG_BLK_DEV_ZONED
static int __f2fs_issue_discard_zone(struct f2fs_sb_info *sbi,
		struct block_device *bdev, block_t blkstart, block_t blklen)
{
	sector_t sector, nr_sects;
	block_t lblkstart = blkstart;
	int devi = 0;

	if (f2fs_is_multi_device(sbi)) {
		devi = f2fs_target_device_index(sbi, blkstart);
		if (blkstart < FDEV(devi).start_blk ||
		    blkstart > FDEV(devi).end_blk) {
			f2fs_err(sbi, "Invalid block %x", blkstart);
			return -EIO;
		}
		blkstart -= FDEV(devi).start_blk;
	}

	/* For sequential zones, reset the zone write pointer */
	if (f2fs_blkz_is_seq(sbi, devi, blkstart)) {
		sector = SECTOR_FROM_BLOCK(blkstart);
		nr_sects = SECTOR_FROM_BLOCK(blklen);

		if (sector & (bdev_zone_sectors(bdev) - 1) ||
				nr_sects != bdev_zone_sectors(bdev)) {
			f2fs_err(sbi, "(%d) %s: Unaligned zone reset attempted (block %x + %x)",
				 devi, sbi->s_ndevs ? FDEV(devi).path : "",
				 blkstart, blklen);
			return -EIO;
		}
		trace_f2fs_issue_reset_zone(bdev, blkstart);
		return blkdev_zone_mgmt(bdev, REQ_OP_ZONE_RESET,
					sector, nr_sects, GFP_NOFS);
	}

	/* For conventional zones, use regular discard if supported */
	return __queue_discard_cmd(sbi, bdev, lblkstart, blklen);
}
#endif

static int __issue_discard_async(struct f2fs_sb_info *sbi,
		struct block_device *bdev, block_t blkstart, block_t blklen)
{
#ifdef CONFIG_BLK_DEV_ZONED
	if (f2fs_sb_has_blkzoned(sbi) && bdev_is_zoned(bdev))
		return __f2fs_issue_discard_zone(sbi, bdev, blkstart, blklen);
#endif
	return __queue_discard_cmd(sbi, bdev, blkstart, blklen);
}

static int f2fs_issue_discard(struct f2fs_sb_info *sbi,
				block_t blkstart, block_t blklen)
{
	sector_t start = blkstart, len = 0;
	struct block_device *bdev;
	//struct seg_entry *se;
	//unsigned int offset;
	block_t i;
	int err = 0;

	bdev = f2fs_target_device(sbi, blkstart, NULL);

	for (i = blkstart; i < blkstart + blklen; i++, len++) {
		if (i != start) {
			struct block_device *bdev2 =
				f2fs_target_device(sbi, i, NULL);

			if (bdev2 != bdev) {
				err = __issue_discard_async(sbi, bdev,
						start, len);
				if (err)
					return err;
				bdev = bdev2;
				start = i;
				len = 0;
			}
		}

		//se = get_seg_entry(sbi, GET_SEGNO(sbi, i));
		//offset = GET_BLKOFF_FROM_SEG0(sbi, i);

		//if (!f2fs_test_and_set_bit(offset, se->discard_map))
		//	sbi->discard_blks--;
	}

	if (len)
		err = __issue_discard_async(sbi, bdev, start, len);
	return err;
}

/*
static struct dynamic_discard_map* get_dynamic_discard_map(struct f2fs_sb_info *sbi,
	       						unsigned long long segno, int* height)
{
	struct dynamic_discard_map_control *ddmc = SM_I(sbi)->ddmc_info;
	struct rb_node **p, *parent = NULL;
	struct rb_entry *re;
	bool left_most;
	struct dynamic_discard_map* ddm;

	p = f2fs_lookup_pos_rb_tree_ext(sbi, &ddmc->root, &parent, segno, &left_most, height);
	
	re = rb_entry_safe(*p, struct rb_entry, rb_node);
	ddm = dynamic_discard_map(re, struct dynamic_discard_map, rbe);
	return ddm;
}
*/



static void __remove_dynamic_discard_map(struct f2fs_sb_info *sbi, struct dynamic_discard_map *ddm)
{
	struct dynamic_discard_map_control *ddmc = SM_I(sbi)->ddmc_info;
	atomic_dec(&ddmc->node_cnt);
	//printk("[JW DBG] %s: 1", __func__);
	//list_del(&ddm->list);
	//printk("[JW DBG] %s: 2", __func__);
	list_del(&ddm->history_list);
	list_del(&ddm->drange_journal_list);
	list_del(&ddm->dmap_journal_list);
	//printk("[JW DBG] %s: 3", __func__);
	//rb_erase_cached(&ddm->rbe.rb_node, &ddmc->root);
	hash_del(&ddm->hnode);
	kvfree(ddm->dc_map);
	kmem_cache_free(discard_map_slab, ddm);
}

static void remove_issued_discard_cmds(struct f2fs_sb_info *sbi);
static void issue_all_discard_journals(struct f2fs_sb_info *sbi);

void issue_and_clean_all_ddm(struct f2fs_sb_info *sbi)
{
	struct dynamic_discard_map_control *ddmc = SM_I(sbi)->ddmc_info;
	struct dynamic_discard_map *ddm, *tmpddm;
	struct list_head *history_head_ddm = &ddmc->history_head;

	issue_all_discard_journals(sbi);
	list_for_each_entry_safe(ddm, tmpddm, history_head_ddm, history_list) {
        	__remove_dynamic_discard_map(sbi, ddm);
	}
	remove_issued_discard_cmds(sbi);
}

static bool add_discard_addrs(struct f2fs_sb_info *sbi, struct cp_control *cpc,
							bool check_only)
{
	int entries = SIT_VBLOCK_MAP_SIZE / sizeof(unsigned long);
	int max_blocks = sbi->blocks_per_seg;
	struct seg_entry *se = get_seg_entry(sbi, cpc->trim_start);
	unsigned long *cur_map = (unsigned long *)se->cur_valid_map;
	unsigned long *ckpt_map = (unsigned long *)se->ckpt_valid_map;
	unsigned long *discard_map = (unsigned long *)se->discard_map;
	unsigned long *dmap = SIT_I(sbi)->tmp_map;
	//unsigned long *ddmap;
	unsigned int start = 0, end = -1;
	bool force = (cpc->reason & CP_DISCARD);
	struct discard_entry *de = NULL;
	struct list_head *head = &SM_I(sbi)->dcc_info->entry_list;
	int i;
	//struct dynamic_discard_map *ddm;
	//bool ddm_blk_exst = true;
	//bool ori_blk_exst = true;
	//unsigned int start_ddm = 0, end_ddm = -1;
	//int height = 0;

	if (force)
		panic("add_discard_addrs: cpc_discard, FITRIM occurs!!!\n");

	//ddm = get_dynamic_discard_map(sbi, (unsigned long long) cpc->trim_start, &height);
	/*if (!ddm)
		ddm_blk_exst = false;
	else{
		printk("add_discard_addrs: DDM Height is %d for segno %d\n", height, cpc->trim_start);
		ddmap = (unsigned long *)ddm->dc_map;
		start = __find_rev_next_bit(ddmap, max_blocks, end + 1);
		if (start >= max_blocks){
			ddm_blk_exst = false;
			__remove_dynamic_discard_map(sbi, ddm);
		}
	}*/

	if (se->valid_blocks == max_blocks || !f2fs_hw_support_discard(sbi)){
		/*if (ddm_blk_exst){
			__remove_dynamic_discard_map(sbi, ddm);
			
		}*/
		
		return false;
	} 
	if (!force) {
		if (!f2fs_realtime_discard_enable(sbi) || !se->valid_blocks ||
			SM_I(sbi)->dcc_info->nr_discards >=
				SM_I(sbi)->dcc_info->max_discards){
			//The condition !se->valid_blocks must be commented later. 
			//My code should handle case empty segments. 
			//Cuz I'll erase prefree segments issuing in clear_prefree_segments function. 
			/*if (ddm_blk_exst){
				__remove_dynamic_discard_map(sbi, ddm);
			}*/
			
			return false;
		}
	}

	
	/* SIT_VBLOCK_MAP_SIZE should be multiple of sizeof(unsigned long) */
	for (i = 0; i < entries; i++)
		dmap[i] = force ? ~ckpt_map[i] & ~discard_map[i] :
				(cur_map[i] ^ ckpt_map[i]) & ckpt_map[i];
	
	/* check existence of discarded block in original version dmap*/
	//start = __find_rev_next_bit(dmap, max_blocks, end + 1);
	
	//if (start >= max_blocks)
	//	ori_blk_exst = false;
	//ori_blk_exst = !(start >= max_blocks);
	//if (ddm_blk_exst != ori_blk_exst)
	//	panic("add discard addrs: exst not match\n");
		//printk("add discard addrs: exst not match\n");
	//f2fs_bug_on(sbi, ddm_blk_exst != ori_blk_exst);

	//if (!(ddm_blk_exst | ori_blk_exst))
	/*if (!ddm_blk_exst)
		return false;
	*/
	while (force || SM_I(sbi)->dcc_info->nr_discards <=
				SM_I(sbi)->dcc_info->max_discards) {
		start = __find_rev_next_bit(dmap, max_blocks, end + 1);
		if (start >= max_blocks)
			break;
		//start = __find_rev_next_bit(ddmap, max_blocks, end_ddm + 1);

		end = __find_rev_next_zero_bit(dmap, max_blocks, start + 1);
		//end = __find_rev_next_zero_bit(ddmap, max_blocks, start_ddm +1);

		/*if (!force){
			if (start != start_ddm || end != end_ddm)
				panic("start end not match in add_discard_addrs");
				//printk("start end not match in add_discard_addrs");
			//f2fs_bug_on(sbi, start != start_ddm || end != end_ddm);
		}*/
		if (force && start && end != max_blocks
					&& (end - start) < cpc->trim_minlen)
			continue;

		if (check_only){
			//__remove_dynamic_discard_map(sbi, ddm);
			return true;
		}
		if (!de) {
			de = f2fs_kmem_cache_alloc(discard_entry_slab,
								GFP_F2FS_ZERO);
			de->start_blkaddr = START_BLOCK(sbi, cpc->trim_start);
			list_add_tail(&de->list, head);
		}

		for (i = start; i < end; i++)
			__set_bit_le(i, (void *)de->discard_map);

		SM_I(sbi)->dcc_info->nr_discards += end - start;
	}
	//__remove_dynamic_discard_map(sbi, ddm);
	return false;
}

static void release_discard_addr(struct discard_entry *entry)
{
	list_del(&entry->list);
	list_del(&entry->ddm_list);
	kmem_cache_free(discard_entry_slab, entry);
}


void f2fs_release_discard_addrs(struct f2fs_sb_info *sbi)
{
	struct list_head *head = &(SM_I(sbi)->dcc_info->entry_list);
	struct discard_entry *entry, *this;

	/* drop caches */
	list_for_each_entry_safe(entry, this, head, list)
		release_discard_addr(entry);
}

/*
 * Should call f2fs_clear_prefree_segments after checkpoint is done.
 */
static void set_prefree_as_free_segments(struct f2fs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	unsigned int segno;

	mutex_lock(&dirty_i->seglist_lock);
	for_each_set_bit(segno, dirty_i->dirty_segmap[PRE], MAIN_SEGS(sbi))
		__set_test_and_free(sbi, segno, false);
	mutex_unlock(&dirty_i->seglist_lock);
}

void f2fs_clear_prefree_segments(struct f2fs_sb_info *sbi,
						struct cp_control *cpc)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct list_head *head = &dcc->entry_list;
	struct discard_entry *entry, *this;
	//struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	//unsigned long *prefree_map = dirty_i->dirty_segmap[PRE];
	//unsigned int start = 0, end = -1;
	//unsigned int secno, start_segno;
	bool force = (cpc->reason & CP_DISCARD);

	int tmp;
	tmp = (int) atomic_read(&dcc->discard_cmd_cnt );
	//printk("[JW DBG] %s: aft discard cmd count: %d \n", __func__, tmp);
	//printk("[JW DBG] %s: prev discard cmd count: %d \n", __func__, tmp);

	//bool need_align = f2fs_lfs_mode(sbi) && __is_large_section(sbi);

	/*
	mutex_lock(&dirty_i->seglist_lock);

	while (1) {
		int i;

		if (need_align && end != -1)
			end--;
		start = find_next_bit(prefree_map, MAIN_SEGS(sbi), end + 1);
		if (start >= MAIN_SEGS(sbi))
			break;
		end = find_next_zero_bit(prefree_map, MAIN_SEGS(sbi),
								start + 1);

		if (need_align) {
			start = rounddown(start, sbi->segs_per_sec);
			end = roundup(end, sbi->segs_per_sec);
		}

		for (i = start; i < end; i++) {
			if (test_and_clear_bit(i, prefree_map))
				dirty_i->nr_dirty[PRE]--;
		}

		if (!f2fs_realtime_discard_enable(sbi))
			continue;

		if (force && start >= cpc->trim_start &&
					(end - 1) <= cpc->trim_end)
				continue;

		if (!f2fs_lfs_mode(sbi) || !__is_large_section(sbi)) {
			f2fs_issue_discard(sbi, START_BLOCK(sbi, start),
				(end - start) << sbi->log_blocks_per_seg);
			continue;
		}
next:
		secno = GET_SEC_FROM_SEG(sbi, start);
		start_segno = GET_SEG_FROM_SEC(sbi, secno);
		if (!IS_CURSEC(sbi, secno) &&
			!get_valid_blocks(sbi, start, true))
			f2fs_issue_discard(sbi, START_BLOCK(sbi, start_segno),
				sbi->segs_per_sec << sbi->log_blocks_per_seg);

		start = start_segno + sbi->segs_per_sec;
		if (start < end)
			goto next;
		else
			end = start - 1;
	}
	mutex_unlock(&dirty_i->seglist_lock);
	*/
	/* send small discards */
	/*list_for_each_entry_safe(entry, this, head, list) {
		unsigned int cur_pos = 0, next_pos, len, total_len = 0;
		bool is_valid = test_bit_le(0, entry->discard_map);

find_next:
		if (is_valid) {
			next_pos = find_next_zero_bit_le(entry->discard_map,
					sbi->blocks_per_seg, cur_pos);
			len = next_pos - cur_pos;

			if (f2fs_sb_has_blkzoned(sbi) ||
			    (force && len < cpc->trim_minlen))
				goto skip;

			f2fs_issue_discard(sbi, entry->start_blkaddr + cur_pos,
									len);
			total_len += len;
		} else {
			next_pos = find_next_bit_le(entry->discard_map,
					sbi->blocks_per_seg, cur_pos);
		}
skip:
		cur_pos = next_pos;
		is_valid = !is_valid;

		if (cur_pos < sbi->blocks_per_seg)
			goto find_next;

		release_discard_addr(entry);
		dcc->nr_discards -= total_len;
	}*/
	//tmp = (int) atomic_read(&dcc->discard_cmd_cnt );
	//printk("[JW DBG] %s: aft discard cmd count: %d \n", __func__, tmp);

	//wake_up_discard_thread(sbi, false);
	wake_up_discard_thread(sbi, true);
}



static bool add_discard_journal(struct f2fs_sb_info *sbi, struct discard_journal_bitmap *dj_map)
{
        
        struct discard_entry *de = NULL;
        struct list_head *head = &SM_I(sbi)->dcc_info->entry_list;

        if (!f2fs_hw_support_discard(sbi)){
		panic("Why HW not support discard!!");
                return false;
        }
        if (!f2fs_realtime_discard_enable(sbi)){// || 
                //SM_I(sbi)->dcc_info->nr_discards >=
                //        SM_I(sbi)->dcc_info->max_discards){
                panic("Why discard not accepted?");
                return false;
        }


        de = f2fs_kmem_cache_alloc(discard_entry_slab,
        	                               GFP_F2FS_ZERO);

        
	de->start_blkaddr = le32_to_cpu(dj_map->start_blkaddr);
        list_add_tail(&de->list, head);
	memcpy(de->discard_map, dj_map->discard_map, DISCARD_BLOCK_MAP_SIZE);

	return true;		

}

int f2fs_recover_discard_journals(struct f2fs_sb_info *sbi)
{

	block_t start_blk, discard_journal_blocks, i, j;
	start_blk = __start_cp_addr(sbi) +
		le32_to_cpu(F2FS_CKPT(sbi)->cp_pack_total_block_count);
	int err = 0;

	discard_journal_blocks = le32_to_cpu(F2FS_CKPT(sbi)->discard_journal_block_count);
	//printk("[JW DBG] %s: dj blocks %u when filling super \n", __func__, discard_journal_blocks);
	if (discard_journal_blocks == 0)
		return 1;

	f2fs_ra_meta_pages(sbi, start_blk, discard_journal_blocks, META_CP, true);

	for (i = 0; i < discard_journal_blocks; i++) {
		struct page *page;
		struct discard_journal_block *dj_blk;
		struct discard_journal_block_info *dj_blk_info;

		page = f2fs_get_meta_page(sbi, start_blk + i);
		if (IS_ERR(page)) {
			err = PTR_ERR(page);
			goto fail;
		}

		dj_blk = (struct discard_journal_block *)page_address(page);
		dj_blk_info = (struct discard_journal_block_info *)&dj_blk->dj_block_info;
		f2fs_bug_on(sbi, dj_blk_info->type != DJ_BLOCK_BITMAP);
	
		for (j = 0; j < le32_to_cpu(dj_blk_info->entry_cnt); j++) {
			struct discard_journal_bitmap *dj_map;

			dj_map = &dj_blk->bitmap_entries[j];
			if (!add_discard_journal(sbi, dj_map)){
				f2fs_put_page(page, 1);
				goto fail;
			}
		}
		f2fs_put_page(page, 1);
	}


	/*This part is modification of f2fs_clear_prefree_segments*/
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct list_head *head = &dcc->entry_list;
	struct discard_entry *entry, *this;
	
	list_for_each_entry_safe(entry, this, head, list) {
		unsigned int cur_pos = 0, next_pos, len, total_len = 0;
		bool is_valid = test_bit_le(0, entry->discard_map);

find_next:
		if (is_valid) {
			next_pos = find_next_zero_bit_le(entry->discard_map,
					sbi->blocks_per_seg, cur_pos);
			len = next_pos - cur_pos;

			f2fs_issue_discard(sbi, entry->start_blkaddr + cur_pos,
									len);
			total_len += len;
		} else {
			next_pos = find_next_bit_le(entry->discard_map,
					sbi->blocks_per_seg, cur_pos);
		}

		cur_pos = next_pos;
		is_valid = !is_valid;

		if (cur_pos < sbi->blocks_per_seg)
			goto find_next;

		release_discard_addr(entry);
	}

	wake_up_discard_thread(sbi, true);

	return 1;
fail:
	panic("[JW DBG] %s: discard journal flushing error! \n", __func__);
}


static int create_dynamic_discard_map_control(struct f2fs_sb_info *sbi)
{
	struct dynamic_discard_map_control *ddmc;

	if (SM_I(sbi)->ddmc_info) {
		ddmc = SM_I(sbi)->ddmc_info;
		return 0;
	}

	ddmc = f2fs_kzalloc(sbi, sizeof(struct dynamic_discard_map_control), GFP_KERNEL);
        if (!ddmc)
                return -ENOMEM;

        mutex_init(&ddmc->ddm_lock);
        ddmc->root = RB_ROOT_CACHED;

	/*variable*/
	hash_init(ht);
	ddmc->ht = ht;
	ddmc->hbits = 7;
	//ddmc->ht_lkc_list = f2fs_kzalloc(sbi, sizeof(struct mutex)*pow(2, 7));
	ddmc->segs_per_node = 300;  
	
	
	atomic_set(&ddmc->node_cnt, 0);
	atomic_set(&ddmc->blk_cnt, 0);
	atomic_set(&ddmc->dj_seg_cnt, 0);
	atomic_set(&ddmc->dj_range_cnt, 0);
	atomic_set(&ddmc->history_seg_cnt, 0);
	INIT_LIST_HEAD(&ddmc->dirty_head);
	INIT_LIST_HEAD(&ddmc->history_head);

	atomic_set(&ddmc->drange_entry_cnt, 0);
	INIT_LIST_HEAD(&ddmc->discard_range_head);
	INIT_LIST_HEAD(&ddmc->discard_map_head);
	INIT_LIST_HEAD(&ddmc->issued_discard_head);
	

	SM_I(sbi)->ddmc_info = ddmc;
	return 0;

}



static int create_discard_cmd_control(struct f2fs_sb_info *sbi)
{
	dev_t dev = sbi->sb->s_bdev->bd_dev;
	struct discard_cmd_control *dcc;
	int err = 0, i;

	if (SM_I(sbi)->dcc_info) {
		dcc = SM_I(sbi)->dcc_info;
		goto init_thread;
	}

	dcc = f2fs_kzalloc(sbi, sizeof(struct discard_cmd_control), GFP_KERNEL);
	if (!dcc)
		return -ENOMEM;

	dcc->discard_granularity = DEFAULT_DISCARD_GRANULARITY;
	INIT_LIST_HEAD(&dcc->entry_list);
	for (i = 0; i < MAX_PLIST_NUM; i++)
		INIT_LIST_HEAD(&dcc->pend_list[i]);
	INIT_LIST_HEAD(&dcc->wait_list);
	INIT_LIST_HEAD(&dcc->fstrim_list);
	mutex_init(&dcc->cmd_lock);
	atomic_set(&dcc->issued_discard, 0);
	atomic_set(&dcc->queued_discard, 0);
	atomic_set(&dcc->discard_cmd_cnt, 0);
	dcc->nr_discards = 0;
	dcc->max_discards = MAIN_SEGS(sbi) << sbi->log_blocks_per_seg;
	dcc->undiscard_blks = 0;
	dcc->next_pos = 0;
	dcc->root = RB_ROOT_CACHED;
	dcc->rbtree_check = false;

	init_waitqueue_head(&dcc->discard_wait_queue);
	SM_I(sbi)->dcc_info = dcc;
init_thread:
	dcc->f2fs_issue_discard = kthread_run(issue_discard_thread, sbi,
				"f2fs_discard-%u:%u", MAJOR(dev), MINOR(dev));
	if (IS_ERR(dcc->f2fs_issue_discard)) {
		err = PTR_ERR(dcc->f2fs_issue_discard);
		kfree(dcc);
		SM_I(sbi)->dcc_info = NULL;
		return err;
	}

	return err;
}


static void destroy_dynamic_discard_map_control(struct f2fs_sb_info *sbi)
{
	struct dynamic_discard_map_control *ddmc = SM_I(sbi)->ddmc_info;

	if (!ddmc)
		return;

	//f2fs_stop_discard_thread(sbi);

	/*
	 * Recovery can cache discard commands, so in error path of
	 * fill_super(), it needs to give a chance to handle them.
	 */
	/*if (unlikely(atomic_read(&ddmcc->discard_cmd_cnt)))
		f2fs_issue_discard_timeout(sbi);
	*/
	kfree(ddmc);
	SM_I(sbi)->ddmc_info = NULL;
}



static void destroy_discard_cmd_control(struct f2fs_sb_info *sbi)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;

	if (!dcc)
		return;

	f2fs_stop_discard_thread(sbi);

	/*
	 * Recovery can cache discard commands, so in error path of
	 * fill_super(), it needs to give a chance to handle them.
	 */
	if (unlikely(atomic_read(&dcc->discard_cmd_cnt)))
		f2fs_issue_discard_timeout(sbi);

	kfree(dcc);
	SM_I(sbi)->dcc_info = NULL;
}

static bool __mark_sit_entry_dirty(struct f2fs_sb_info *sbi, unsigned int segno)
{
	struct sit_info *sit_i = SIT_I(sbi);

	if (!__test_and_set_bit(segno, sit_i->dirty_sentries_bitmap)) {
		sit_i->dirty_sentries++;
		return false;
	}

	return true;
}

static void __set_sit_entry_type(struct f2fs_sb_info *sbi, int type,
					unsigned int segno, int modified)
{
	struct seg_entry *se = get_seg_entry(sbi, segno);
	se->type = type;
	if (modified)
		__mark_sit_entry_dirty(sbi, segno);
}

static inline unsigned long long get_segment_mtime(struct f2fs_sb_info *sbi,
								block_t blkaddr)
{
	unsigned int segno = GET_SEGNO(sbi, blkaddr);

	if (segno == NULL_SEGNO)
		return 0;
	return get_seg_entry(sbi, segno)->mtime;
}

static void update_segment_mtime(struct f2fs_sb_info *sbi, block_t blkaddr,
						unsigned long long old_mtime)
{
	struct seg_entry *se;
	unsigned int segno = GET_SEGNO(sbi, blkaddr);
	unsigned long long ctime = get_mtime(sbi, false);
	unsigned long long mtime = old_mtime ? old_mtime : ctime;
	panic("update_segment_mtime(): this must not be executed");

	if (segno == NULL_SEGNO)
		return;

	se = get_seg_entry(sbi, segno);

	if (!se->mtime)
		se->mtime = mtime;
	else
		se->mtime = div_u64(se->mtime * se->valid_blocks + mtime,
						se->valid_blocks + 1);

	if (ctime > SIT_I(sbi)->max_mtime)
		SIT_I(sbi)->max_mtime = ctime;
}


static struct dynamic_discard_map *__create_discard_map(struct f2fs_sb_info *sbi)
{
	struct dynamic_discard_map *ddm;
	//unsigned int count_down = SM_I(sbi)->ddmc_info->removal_count;
	unsigned int segs_per_ddm = SM_I(sbi)->ddmc_info->segs_per_node;

	ddm = f2fs_kmem_cache_alloc(discard_map_slab, GFP_NOFS);
	ddm->dc_map = f2fs_kvzalloc(sbi, SIT_VBLOCK_MAP_SIZE * segs_per_ddm, GFP_KERNEL);
	INIT_LIST_HEAD(&ddm->dirty_list);
	INIT_LIST_HEAD(&ddm->history_list);

	INIT_LIST_HEAD(&ddm->drange_journal_list);
	INIT_LIST_HEAD(&ddm->dmap_journal_list);
	
	atomic_set(&ddm->is_dirty, 0);
	//atomic_set(&ddm->remove_cnt_down, count_down);	
	//hash
	INIT_HLIST_NODE(&ddm->hnode);
	return ddm;
	
}

static void get_ddm_info(struct f2fs_sb_info *sbi, unsigned int segno, unsigned int offset, 
			unsigned long long *p_ddmkey, unsigned int *p_offset)
{
	unsigned int segs_per_ddm = SM_I(sbi)->ddmc_info->segs_per_node;
	unsigned int blocks_per_seg = sbi->blocks_per_seg;
	unsigned int start_segno;
	unsigned int delta_segno;	
	*p_ddmkey = (unsigned long long) segno/segs_per_ddm;
	start_segno = (*p_ddmkey) * segs_per_ddm;
	delta_segno = segno - start_segno;
	*p_offset = offset + (delta_segno) * blocks_per_seg;
	if (segno/segs_per_ddm - (int)(segno/segs_per_ddm))
		panic("update_dynamic_discard_map: float in key!!");
}

static struct dynamic_discard_map *f2fs_lookup_hash(struct f2fs_sb_info *sbi,  
					unsigned long long key, unsigned int *height)
{
	struct hlist_head *head = &ht[hash_min(key, HASH_BITS(ht))];
	struct dynamic_discard_map *ddm;
	*height = 0;

	hlist_for_each_entry(ddm, head, hnode){
		*height += 1;
		if (ddm->key == key)
			return ddm;

	}
	return NULL;

}


static void update_dynamic_discard_map(struct f2fs_sb_info *sbi, unsigned int segno,
	       					unsigned int offset, int del)
{
	struct dynamic_discard_map_control *ddmc = SM_I(sbi)->ddmc_info;
	//struct hlist_head *ht = ddmc->ht;
	struct dynamic_discard_map *ddm;
	unsigned long long ddmkey;
	unsigned int offset_in_ddm;
	unsigned int height;
	struct list_head *dirty_head = &ddmc->dirty_head;
	struct list_head *history_head = &ddmc->history_head;

	get_ddm_info(sbi, segno, offset, &ddmkey, &offset_in_ddm);
	
	ddm = f2fs_lookup_hash(sbi, ddmkey, &height);


	//printk("update_ddm_hash: height is %d\n", height);
	if (del < 0) {
		//if (segno == GET_SEGNO(sbi, 37120) && offset == (GET_BLKOFF_FROM_SEG0(sbi, 37120)))
		//	printk("[JW DBG] %s: 37120 is added to ddm!!\n", __func__);
		if (!ddm){
			/*not exist, so create it*/
			ddm = __create_discard_map(sbi);
			if (ddm == 0)
				panic("__create_discard_map failed");
			ddm->key = ddmkey;
			//if (ddmkey == 0){
				//printk("[JW DBG] %s: ddm node with ddmkey 0 created by segno: %u, offset: %u!!\n", __func__, segno, offset);
			//}
			//hash_add(ddmc->ht, &ddm->hnode, ddmkey);
			hash_add(ht, &ddm->hnode, ddmkey);
			//list_add_tail(&ddm->list, head);
			list_add_tail(&ddm->history_list, history_head);
			atomic_inc(&ddmc->node_cnt);
			//printk("[JW DBG] %s: ddm created with ddmkey %u!!\n", __func__, ddmkey);

			
		}
		if (atomic_read(&ddm->is_dirty) == 0){
			atomic_set(&ddm->is_dirty, 1);
			list_add_tail(&ddm->dirty_list, dirty_head);
			//printk("[JW DBG] %s: ddm added to dirty list %u!!\n", __func__, ddmkey);
		}
		f2fs_test_and_set_bit(offset_in_ddm, ddm->dc_map);
		atomic_inc(&ddmc->blk_cnt);
			
		return;
	}
	if (del > 0) {
		//if (segno == GET_SEGNO(sbi, 37120) && offset == (GET_BLKOFF_FROM_SEG0(sbi, 37120)))
		//	printk("[JW DBG] %s: 37120 is deleted in ddm!!\n", __func__);
		if (!ddm){
			return;	
		}
		if (f2fs_test_and_clear_bit(offset_in_ddm, ddm->dc_map))
			atomic_dec(&ddmc->blk_cnt);
	}

}

static void update_sit_entry(struct f2fs_sb_info *sbi, block_t blkaddr, int del)
{
	struct seg_entry *se;
	unsigned int segno, offset;
	long int new_vblocks;
	bool exist;
	//bool ddmhash = false;
#ifdef CONFIG_F2FS_CHECK_FS
	bool mir_exist;
#endif

	segno = GET_SEGNO(sbi, blkaddr);

	//se = get_seg_entry(sbi, segno);
	//new_vblocks = se->valid_blocks + del;
	offset = GET_BLKOFF_FROM_SEG0(sbi, blkaddr);

	/*f2fs_bug_on(sbi, (new_vblocks < 0 ||
			(new_vblocks > f2fs_usable_blks_in_seg(sbi, segno))));
	*/
	//se->valid_blocks = new_vblocks;

	
	mutex_lock(&SM_I(sbi)->ddmc_info->ddm_lock);
	update_dynamic_discard_map(sbi, segno, offset, del);
	//update_dynamic_discard_map(sbi, segno, offset, del);
	mutex_unlock(&SM_I(sbi)->ddmc_info->ddm_lock);
	

	/* Update valid block bitmap */
	/*if (del > 0) {
		exist = f2fs_test_and_set_bit(offset, se->cur_valid_map);
#ifdef CONFIG_F2FS_CHECK_FS
		mir_exist = f2fs_test_and_set_bit(offset,
						se->cur_valid_map_mir);
		if (unlikely(exist != mir_exist)) {
			f2fs_err(sbi, "Inconsistent error when setting bitmap, blk:%u, old bit:%d",
				 blkaddr, exist);
			f2fs_bug_on(sbi, 1);
		}
#endif
		if (unlikely(exist)) {
			f2fs_err(sbi, "Bitmap was wrongly set, blk:%u",
				 blkaddr);
			f2fs_bug_on(sbi, 1);
			se->valid_blocks--;
			del = 0;
		}

		if (!f2fs_test_and_set_bit(offset, se->discard_map))
			sbi->discard_blks--;

		//
		// SSR should never reuse block which is checkpointed
		// or newly invalidated.
		//
		if (!is_sbi_flag_set(sbi, SBI_CP_DISABLED)) {
			if (!f2fs_test_and_set_bit(offset, se->ckpt_valid_map))
				se->ckpt_valid_blocks++;
		}
	} else {
		exist = f2fs_test_and_clear_bit(offset, se->cur_valid_map);
#ifdef CONFIG_F2FS_CHECK_FS
		mir_exist = f2fs_test_and_clear_bit(offset,
						se->cur_valid_map_mir);
		if (unlikely(exist != mir_exist)) {
			f2fs_err(sbi, "Inconsistent error when clearing bitmap, blk:%u, old bit:%d",
				 blkaddr, exist);
			f2fs_bug_on(sbi, 1);
		}
#endif
		if (unlikely(!exist)) {
			f2fs_err(sbi, "Bitmap was wrongly cleared, blk:%u",
				 blkaddr);
			f2fs_bug_on(sbi, 1);
			se->valid_blocks++;
			del = 0;
		} else if (unlikely(is_sbi_flag_set(sbi, SBI_CP_DISABLED))) {
			//
			// If checkpoints are off, we must not reuse data that
			// was used in the previous checkpoint. If it was used
			// before, we must track that to know how much space we
			// really have.
			//
			if (f2fs_test_bit(offset, se->ckpt_valid_map)) {
				spin_lock(&sbi->stat_lock);
				sbi->unusable_block_count++;
				spin_unlock(&sbi->stat_lock);
			}
		}

		if (f2fs_test_and_clear_bit(offset, se->discard_map))
			sbi->discard_blks++;
	}
	if (!f2fs_test_bit(offset, se->ckpt_valid_map))
		se->ckpt_valid_blocks += del;

	__mark_sit_entry_dirty(sbi, segno);
	*/
	/* update total number of valid blocks to be written in ckpt area */
	SIT_I(sbi)->written_valid_blocks += del;

	/*if (__is_large_section(sbi))
		get_sec_entry(sbi, segno)->valid_blocks += del;
	*/
}

void f2fs_invalidate_blocks(struct f2fs_sb_info *sbi, block_t addr)
{
	unsigned int segno = GET_SEGNO(sbi, addr);
	struct sit_info *sit_i = SIT_I(sbi);

	f2fs_bug_on(sbi, addr == NULL_ADDR);
	if (addr == NEW_ADDR || addr == COMPRESS_ADDR)
		return;

	invalidate_mapping_pages(META_MAPPING(sbi), addr, addr);

	/* add it into sit main buffer */
	down_write(&sit_i->sentry_lock);

	//update_segment_mtime(sbi, addr, 0);
	update_sit_entry(sbi, addr, -1);

	/* add it into dirty seglist */
	//locate_dirty_segment(sbi, segno);

	up_write(&sit_i->sentry_lock);
}

bool f2fs_is_checkpointed_data(struct f2fs_sb_info *sbi, block_t blkaddr)
{
	struct sit_info *sit_i = SIT_I(sbi);
	unsigned int segno, offset;
	struct seg_entry *se;
	bool is_cp = false;

	if (!__is_valid_data_blkaddr(blkaddr))
		return true;

	down_read(&sit_i->sentry_lock);

	segno = GET_SEGNO(sbi, blkaddr);
	se = get_seg_entry(sbi, segno);
	offset = GET_BLKOFF_FROM_SEG0(sbi, blkaddr);

	if (f2fs_test_bit(offset, se->ckpt_valid_map))
		is_cp = true;

	up_read(&sit_i->sentry_lock);

	return is_cp;
}

/*
 * This function should be resided under the curseg_mutex lock
 */
static void __add_sum_entry(struct f2fs_sb_info *sbi, int type,
					struct f2fs_summary *sum)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	void *addr = curseg->sum_blk;
	addr += curseg->next_blkoff * sizeof(struct f2fs_summary);
	memcpy(addr, sum, sizeof(struct f2fs_summary));
}

/*
 * Calculate the number of current summary pages for writing
 */
int f2fs_npages_for_summary_flush(struct f2fs_sb_info *sbi, bool for_ra)
{
	int valid_sum_count = 0;
	int i, sum_in_page;

	for (i = CURSEG_HOT_DATA; i <= CURSEG_COLD_DATA; i++) {
		if (sbi->ckpt->alloc_type[i] == SSR)
			valid_sum_count += sbi->blocks_per_seg;
		else {
			if (for_ra)
				valid_sum_count += le16_to_cpu(
					F2FS_CKPT(sbi)->cur_data_blkoff[i]);
			else
				valid_sum_count += curseg_blkoff(sbi, i);
		}
	}

	sum_in_page = (PAGE_SIZE - 2 * SUM_JOURNAL_SIZE -
			SUM_FOOTER_SIZE) / SUMMARY_SIZE;
	if (valid_sum_count <= sum_in_page)
		return 1;
	else if ((valid_sum_count - sum_in_page) <=
		(PAGE_SIZE - SUM_FOOTER_SIZE) / SUMMARY_SIZE)
		return 2;
	return 3;
}

/*
 * Caller should put this summary page
 */
struct page *f2fs_get_sum_page(struct f2fs_sb_info *sbi, unsigned int segno)
{
	if (unlikely(f2fs_cp_error(sbi)))
		return ERR_PTR(-EIO);
	return f2fs_get_meta_page_retry(sbi, GET_SUM_BLOCK(sbi, segno));
}

void f2fs_update_meta_page(struct f2fs_sb_info *sbi,
					void *src, block_t blk_addr)
{
	struct page *page = f2fs_grab_meta_page(sbi, blk_addr);

	memcpy(page_address(page), src, PAGE_SIZE);
	set_page_dirty(page);
	f2fs_put_page(page, 1);
}

static void write_sum_page(struct f2fs_sb_info *sbi,
			struct f2fs_summary_block *sum_blk, block_t blk_addr)
{
	f2fs_update_meta_page(sbi, (void *)sum_blk, blk_addr);
}

static void write_current_sum_page(struct f2fs_sb_info *sbi,
						int type, block_t blk_addr)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	struct page *page = f2fs_grab_meta_page(sbi, blk_addr);
	struct f2fs_summary_block *src = curseg->sum_blk;
	struct f2fs_summary_block *dst;

	dst = (struct f2fs_summary_block *)page_address(page);
	memset(dst, 0, PAGE_SIZE);

	mutex_lock(&curseg->curseg_mutex);

	down_read(&curseg->journal_rwsem);
	memcpy(&dst->journal, curseg->journal, SUM_JOURNAL_SIZE);
	up_read(&curseg->journal_rwsem);

	memcpy(dst->entries, src->entries, SUM_ENTRY_SIZE);
	memcpy(&dst->footer, &src->footer, SUM_FOOTER_SIZE);

	mutex_unlock(&curseg->curseg_mutex);

	set_page_dirty(page);
	f2fs_put_page(page, 1);
}

static int is_next_segment_free(struct f2fs_sb_info *sbi,
				struct curseg_info *curseg, int type)
{
	unsigned int segno = curseg->segno + 1;
	struct free_segmap_info *free_i = FREE_I(sbi);

	if (segno < MAIN_SEGS(sbi) && segno % sbi->segs_per_sec)
		return !test_bit(segno, free_i->free_segmap);
	return 0;
}

//for IF LBA. calculate rightmost zoneno and return zoneno + 1
static unsigned int get_free_zone(struct f2fs_sb_info *sbi)
{
	int i;
	unsigned int zone = 0;
	unsigned int total_zones = MAIN_SECS(sbi) / sbi->secs_per_zone;

	down_read(&SM_I(sbi)->curseg_zone_lock);
	for (i = 0; i < NR_CURSEG_TYPE; i++)
		zone = max(zone, CURSEG_I(sbi, i)->zone);
	up_read(&SM_I(sbi)->curseg_zone_lock);
	//if (zone + 1 > total_zones)
	//	printk("get_free_zone: new zone %d is out of total zone %d",zone + 1, total_zones );
	return zone + 1;
}

static void get_new_segment_IFLBA(struct f2fs_sb_info *sbi,
			unsigned int *newseg, bool new_sec, int type)
{
	unsigned int segno, secno, zoneno;
	unsigned int old_secno = GET_SEC_FROM_SEG(sbi, *newseg);

	//find next free segment in section
	if (!new_sec && ((*newseg + 1) % sbi->segs_per_sec)) {
		segno = *newseg + 1;
		if (segno < GET_SEG_FROM_SEC(sbi, old_secno + 1))
			panic("get_new_segment_IFLBA: must not be here\n");
		goto got_it;
	}
	//find to next section in zone. 
	if((old_secno + 1) % sbi->secs_per_zone ) {
		secno = old_secno + 1;
		segno = GET_SEG_FROM_SEC(sbi, secno);
		goto got_it;
	}
	//find next free zone
	zoneno = get_free_zone(sbi);
	secno = zoneno * sbi->secs_per_zone;
	segno = secno * sbi->segs_per_sec;

got_it:
	/* set it as dirty segment in free segmap */
	*newseg = segno;

}

/*
 * Find a new segment from the free segments bitmap to right order
 * This function should be returned with success, otherwise BUG
 */
static void get_new_segment(struct f2fs_sb_info *sbi,
			unsigned int *newseg, bool new_sec, int dir)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	unsigned int segno, secno, zoneno;
	unsigned int total_zones = MAIN_SECS(sbi) / sbi->secs_per_zone;
	unsigned int hint = GET_SEC_FROM_SEG(sbi, *newseg);
	unsigned int old_zoneno = GET_ZONE_FROM_SEG(sbi, *newseg);
	unsigned int left_start = hint;
	bool init = true;
	int go_left = 0;
	int i;

	spin_lock(&free_i->segmap_lock);

	if (!new_sec && ((*newseg + 1) % sbi->segs_per_sec)) {
		segno = find_next_zero_bit(free_i->free_segmap,
			GET_SEG_FROM_SEC(sbi, hint + 1), *newseg + 1);
		if (segno < GET_SEG_FROM_SEC(sbi, hint + 1))
			goto got_it;
	}
find_other_zone:
	secno = find_next_zero_bit(free_i->free_secmap, MAIN_SECS(sbi), hint);
	if (secno >= MAIN_SECS(sbi)) {
		if (dir == ALLOC_RIGHT) {
			secno = find_next_zero_bit(free_i->free_secmap,
							MAIN_SECS(sbi), 0);
			f2fs_bug_on(sbi, secno >= MAIN_SECS(sbi));
		} else {
			go_left = 1;
			left_start = hint - 1;
		}
	}
	if (go_left == 0)
		goto skip_left;

	while (test_bit(left_start, free_i->free_secmap)) {
		if (left_start > 0) {
			left_start--;
			continue;
		}
		left_start = find_next_zero_bit(free_i->free_secmap,
							MAIN_SECS(sbi), 0);
		f2fs_bug_on(sbi, left_start >= MAIN_SECS(sbi));
		break;
	}
	secno = left_start;
skip_left:
	segno = GET_SEG_FROM_SEC(sbi, secno);
	zoneno = GET_ZONE_FROM_SEC(sbi, secno);

	/* give up on finding another zone */
	if (!init)
		goto got_it;
	if (sbi->secs_per_zone == 1)
		goto got_it;
	if (zoneno == old_zoneno)
		goto got_it;
	if (dir == ALLOC_LEFT) {
		if (!go_left && zoneno + 1 >= total_zones)
			goto got_it;
		if (go_left && zoneno == 0)
			goto got_it;
	}
	for (i = 0; i < NR_CURSEG_TYPE; i++)
		if (CURSEG_I(sbi, i)->zone == zoneno)
			break;

	if (i < NR_CURSEG_TYPE) {
		/* zone is in user, try another */
		if (go_left)
			hint = zoneno * sbi->secs_per_zone - 1;
		else if (zoneno + 1 >= total_zones)
			hint = 0;
		else
			hint = (zoneno + 1) * sbi->secs_per_zone;
		init = false;
		goto find_other_zone;
	}
got_it:
	/* set it as dirty segment in free segmap */
	f2fs_bug_on(sbi, test_bit(segno, free_i->free_segmap));
	__set_inuse(sbi, segno);
	*newseg = segno;
	spin_unlock(&free_i->segmap_lock);
}

static void reset_curseg(struct f2fs_sb_info *sbi, int type, int modified)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	struct summary_footer *sum_footer;
	unsigned short seg_type = curseg->seg_type;

	curseg->inited = true;
	curseg->segno = curseg->next_segno;

	down_write(&SM_I(sbi)->curseg_zone_lock);
	curseg->zone = GET_ZONE_FROM_SEG(sbi, curseg->segno);
	up_write(&SM_I(sbi)->curseg_zone_lock);

	curseg->next_blkoff = 0;
	curseg->next_segno = NULL_SEGNO;

	sum_footer = &(curseg->sum_blk->footer);
	memset(sum_footer, 0, sizeof(struct summary_footer));

	sanity_check_seg_type(sbi, seg_type);

	if (IS_DATASEG(seg_type))
		SET_SUM_TYPE(sum_footer, SUM_TYPE_DATA);
	if (IS_NODESEG(seg_type))
		SET_SUM_TYPE(sum_footer, SUM_TYPE_NODE);
	//__set_sit_entry_type(sbi, seg_type, curseg->segno, modified);
}

static unsigned int __get_next_segno(struct f2fs_sb_info *sbi, int type)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	unsigned short seg_type = curseg->seg_type;

	sanity_check_seg_type(sbi, seg_type);

	/* if segs_per_sec is large than 1, we need to keep original policy. */
	if (__is_large_section(sbi))
		return curseg->segno;

	/* inmem log may not locate on any segment after mount */
	if (!curseg->inited)
		return 0;

	if (unlikely(is_sbi_flag_set(sbi, SBI_CP_DISABLED)))
		return 0;

	if (test_opt(sbi, NOHEAP) &&
		(seg_type == CURSEG_HOT_DATA || IS_NODESEG(seg_type)))
		return 0;

	if (SIT_I(sbi)->last_victim[ALLOC_NEXT])
		return SIT_I(sbi)->last_victim[ALLOC_NEXT];

	/* find segments from 0 to reuse freed segments */
	if (F2FS_OPTION(sbi).alloc_mode == ALLOC_MODE_REUSE)
		return 0;

	return curseg->segno;
}

/*
 * Allocate a current working segment.
 * This function always allocates a free segment in LFS manner.
 */
static void new_curseg(struct f2fs_sb_info *sbi, int type, bool new_sec)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	unsigned short seg_type = curseg->seg_type;
	unsigned int segno = curseg->segno;
	int dir = ALLOC_LEFT;

	/*if (curseg->inited)
		write_sum_page(sbi, curseg->sum_blk,
				GET_SUM_BLOCK(sbi, segno));
	*/
	if (seg_type == CURSEG_WARM_DATA || seg_type == CURSEG_COLD_DATA)
		dir = ALLOC_RIGHT;

	if (test_opt(sbi, NOHEAP))
		dir = ALLOC_RIGHT;

	segno = __get_next_segno(sbi, type);
	get_new_segment(sbi, &segno, new_sec, dir);
	curseg->next_segno = segno;
	reset_curseg(sbi, type, 1);
	curseg->alloc_type = LFS;
}
static void new_curseg_IFLBA(struct f2fs_sb_info *sbi, int type, bool new_sec)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	//unsigned short seg_type = curseg->seg_type;
	unsigned int segno = curseg->segno;

	//segno = __get_next_segno(sbi, type);
	get_new_segment_IFLBA(sbi, &segno, new_sec, type);
	curseg->next_segno = segno;
	reset_curseg(sbi, type, 1);
	curseg->alloc_type = LFS;
}

static void __next_free_blkoff(struct f2fs_sb_info *sbi,
			struct curseg_info *seg, block_t start)
{
	struct seg_entry *se = get_seg_entry(sbi, seg->segno);
	int entries = SIT_VBLOCK_MAP_SIZE / sizeof(unsigned long);
	unsigned long *target_map = SIT_I(sbi)->tmp_map;
	unsigned long *ckpt_map = (unsigned long *)se->ckpt_valid_map;
	unsigned long *cur_map = (unsigned long *)se->cur_valid_map;
	int i, pos;

	for (i = 0; i < entries; i++)
		target_map[i] = ckpt_map[i] | cur_map[i];

	pos = __find_rev_next_zero_bit(target_map, sbi->blocks_per_seg, start);

	seg->next_blkoff = pos;
}

/*
 * If a segment is written by LFS manner, next block offset is just obtained
 * by increasing the current block offset. However, if a segment is written by
 * SSR manner, next block offset obtained by calling __next_free_blkoff
 */
static void __refresh_next_blkoff(struct f2fs_sb_info *sbi,
				struct curseg_info *seg)
{
	if (seg->alloc_type == SSR){
		panic("__refresh_next_blkoff(): why SSR? not expected\n");
		__next_free_blkoff(sbi, seg, seg->next_blkoff + 1);
	}
	else
		seg->next_blkoff++;
}

/*
 * This function always allocates a used segment(from dirty seglist) by SSR
 * manner, so it should recover the existing segment information of valid blocks
 */
static void change_curseg(struct f2fs_sb_info *sbi, int type, bool flush)
{
	//struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	unsigned int new_segno = curseg->next_segno;
	//struct f2fs_summary_block *sum_node;
	//struct page *sum_page;

	/*if (flush)
		write_sum_page(sbi, curseg->sum_blk,
						GET_SUM_BLOCK(sbi, curseg->segno));*/
	panic("change_curseg(): this should not be called!");
	//__set_test_and_inuse(sbi, new_segno);

	//mutex_lock(&dirty_i->seglist_lock);
	//__remove_dirty_segment(sbi, new_segno, PRE);
	//__remove_dirty_segment(sbi, new_segno, DIRTY);
	//mutex_unlock(&dirty_i->seglist_lock);

	reset_curseg(sbi, type, 1);
	curseg->alloc_type = SSR;
	__next_free_blkoff(sbi, curseg, 0);

	//sum_page = f2fs_get_sum_page(sbi, new_segno);
	//if (IS_ERR(sum_page)) {
		/* GC won't be able to use stale summary pages by cp_error */
	//	memset(curseg->sum_blk, 0, SUM_ENTRY_SIZE);
	//	return;
	//}
	/*sum_node = (struct f2fs_summary_block *)page_address(sum_page);
	memcpy(curseg->sum_blk, sum_node, SUM_ENTRY_SIZE);
	f2fs_put_page(sum_page, 1);
	*/
}

static int get_ssr_segment(struct f2fs_sb_info *sbi, int type,
				int alloc_mode, unsigned long long age);

static void get_atssr_segment(struct f2fs_sb_info *sbi, int type,
					int target_type, int alloc_mode,
					unsigned long long age)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	panic("get_atssr_segment(): not expected!!");
	curseg->seg_type = target_type;

	if (get_ssr_segment(sbi, type, alloc_mode, age)) {
		struct seg_entry *se = get_seg_entry(sbi, curseg->next_segno);

		curseg->seg_type = se->type;
		change_curseg(sbi, type, true);
	} else {
		/* allocate cold segment by default */
		curseg->seg_type = CURSEG_COLD_DATA;
		new_curseg(sbi, type, true);
	}
	stat_inc_seg_type(sbi, curseg);
}

static void __f2fs_init_atgc_curseg(struct f2fs_sb_info *sbi)
{
	struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_ALL_DATA_ATGC);

	if (!sbi->am.atgc_enabled)
		return;

	down_read(&SM_I(sbi)->curseg_lock);

	mutex_lock(&curseg->curseg_mutex);
	down_write(&SIT_I(sbi)->sentry_lock);

	get_atssr_segment(sbi, CURSEG_ALL_DATA_ATGC, CURSEG_COLD_DATA, SSR, 0);

	up_write(&SIT_I(sbi)->sentry_lock);
	mutex_unlock(&curseg->curseg_mutex);

	up_read(&SM_I(sbi)->curseg_lock);

}
void f2fs_init_inmem_curseg(struct f2fs_sb_info *sbi)
{
	__f2fs_init_atgc_curseg(sbi);
}

static void __f2fs_save_inmem_curseg(struct f2fs_sb_info *sbi, int type)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);

	mutex_lock(&curseg->curseg_mutex);
	if (!curseg->inited)
		goto out;

	//if (get_valid_blocks(sbi, curseg->segno, false)) {
		/*write_sum_page(sbi, curseg->sum_blk,
				GET_SUM_BLOCK(sbi, curseg->segno));*/
	//} else {
	/*
	if (!get_valid_blocks(sbi, curseg->segno, false)) {
		mutex_lock(&DIRTY_I(sbi)->seglist_lock);
		__set_test_and_free(sbi, curseg->segno, true);
		mutex_unlock(&DIRTY_I(sbi)->seglist_lock);
	}*/
out:
	mutex_unlock(&curseg->curseg_mutex);
}

void f2fs_save_inmem_curseg(struct f2fs_sb_info *sbi)
{
	__f2fs_save_inmem_curseg(sbi, CURSEG_COLD_DATA_PINNED);

	if (sbi->am.atgc_enabled)
		__f2fs_save_inmem_curseg(sbi, CURSEG_ALL_DATA_ATGC);
}

static void __f2fs_restore_inmem_curseg(struct f2fs_sb_info *sbi, int type)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);

	mutex_lock(&curseg->curseg_mutex);
	if (!curseg->inited)
		goto out;
	if (get_valid_blocks(sbi, curseg->segno, false))
		goto out;

	/*mutex_lock(&DIRTY_I(sbi)->seglist_lock);
	__set_test_and_inuse(sbi, curseg->segno);
	mutex_unlock(&DIRTY_I(sbi)->seglist_lock);
	*/
out:
	mutex_unlock(&curseg->curseg_mutex);
}

void f2fs_restore_inmem_curseg(struct f2fs_sb_info *sbi)
{
	__f2fs_restore_inmem_curseg(sbi, CURSEG_COLD_DATA_PINNED);

	if (sbi->am.atgc_enabled)
		__f2fs_restore_inmem_curseg(sbi, CURSEG_ALL_DATA_ATGC);
}

static int get_ssr_segment(struct f2fs_sb_info *sbi, int type,
				int alloc_mode, unsigned long long age)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	const struct victim_selection *v_ops = DIRTY_I(sbi)->v_ops;
	unsigned segno = NULL_SEGNO;
	unsigned short seg_type = curseg->seg_type;
	int i, cnt;
	bool reversed = false;
	panic("get_ssr_segment(): this should not be called except resize fs case.");
	sanity_check_seg_type(sbi, seg_type);

	/* f2fs_need_SSR() already forces to do this */
	if (!v_ops->get_victim(sbi, &segno, BG_GC, seg_type, alloc_mode, age)) {
		curseg->next_segno = segno;
		return 1;
	}

	/* For node segments, let's do SSR more intensively */
	if (IS_NODESEG(seg_type)) {
		if (seg_type >= CURSEG_WARM_NODE) {
			reversed = true;
			i = CURSEG_COLD_NODE;
		} else {
			i = CURSEG_HOT_NODE;
		}
		cnt = NR_CURSEG_NODE_TYPE;
	} else {
		if (seg_type >= CURSEG_WARM_DATA) {
			reversed = true;
			i = CURSEG_COLD_DATA;
		} else {
			i = CURSEG_HOT_DATA;
		}
		cnt = NR_CURSEG_DATA_TYPE;
	}

	for (; cnt-- > 0; reversed ? i-- : i++) {
		if (i == seg_type)
			continue;
		if (!v_ops->get_victim(sbi, &segno, BG_GC, i, alloc_mode, age)) {
			curseg->next_segno = segno;
			return 1;
		}
	}

	/* find valid_blocks=0 in dirty list */
	if (unlikely(is_sbi_flag_set(sbi, SBI_CP_DISABLED))) {
		segno = get_free_segment(sbi);
		if (segno != NULL_SEGNO) {
			curseg->next_segno = segno;
			return 1;
		}
	}
	return 0;
}

/*
 * flush out current segment and replace it with new segment
 * This function should be returned with success, otherwise BUG
 */
static void allocate_segment_by_default(struct f2fs_sb_info *sbi,
						int type, bool force)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);

	if (force)
		new_curseg(sbi, type, true);
	else if (!is_set_ckpt_flags(sbi, CP_CRC_RECOVERY_FLAG) &&
					curseg->seg_type == CURSEG_WARM_NODE)
		new_curseg(sbi, type, false);
	else if (curseg->alloc_type == LFS &&
			is_next_segment_free(sbi, curseg, type) &&
			likely(!is_sbi_flag_set(sbi, SBI_CP_DISABLED)))
		new_curseg(sbi, type, false);
	else if (f2fs_need_SSR(sbi) &&
			get_ssr_segment(sbi, type, SSR, 0))
		change_curseg(sbi, type, true);
	else
		new_curseg(sbi, type, false);

	stat_inc_seg_type(sbi, curseg);
}


static void append_only_allocate_segment(struct f2fs_sb_info *sbi,
						int type, bool force)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);

	if (force)
		new_curseg_IFLBA(sbi, type, true);
	else
		new_curseg_IFLBA(sbi, type, false);

	stat_inc_seg_type(sbi, curseg);
}

void f2fs_allocate_segment_for_resize(struct f2fs_sb_info *sbi, int type,
					unsigned int start, unsigned int end)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	unsigned int segno;

	down_read(&SM_I(sbi)->curseg_lock);
	mutex_lock(&curseg->curseg_mutex);
	down_write(&SIT_I(sbi)->sentry_lock);

	segno = CURSEG_I(sbi, type)->segno;
	if (segno < start || segno > end)
		goto unlock;

	if (f2fs_need_SSR(sbi) && get_ssr_segment(sbi, type, SSR, 0))
		change_curseg(sbi, type, true);
	else
		new_curseg(sbi, type, true);

	stat_inc_seg_type(sbi, curseg);

	//locate_dirty_segment(sbi, segno);
unlock:
	up_write(&SIT_I(sbi)->sentry_lock);

	if (segno != curseg->segno)
		f2fs_notice(sbi, "For resize: curseg of type %d: %u ==> %u",
			    type, segno, curseg->segno);

	mutex_unlock(&curseg->curseg_mutex);
	up_read(&SM_I(sbi)->curseg_lock);
}

static void __allocate_new_segment(struct f2fs_sb_info *sbi, int type)
{
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	unsigned int old_segno;

	if (!curseg->inited)
		goto alloc;

	if (!curseg->next_blkoff)
		return;
	/*if (!curseg->next_blkoff &&
		!get_valid_blocks(sbi, curseg->segno, false) &&
		!get_ckpt_valid_blocks(sbi, curseg->segno))
		return;
	*/

alloc:
	old_segno = curseg->segno;
	SIT_I(sbi)->s_ops->allocate_segment(sbi, type, true);
	//locate_dirty_segment(sbi, old_segno);
}

void f2fs_allocate_new_segment(struct f2fs_sb_info *sbi, int type)
{
	down_write(&SIT_I(sbi)->sentry_lock);
	__allocate_new_segment(sbi, type);
	up_write(&SIT_I(sbi)->sentry_lock);
}

void f2fs_allocate_new_segments(struct f2fs_sb_info *sbi)
{
	int i;

	down_write(&SIT_I(sbi)->sentry_lock);
	for (i = CURSEG_HOT_DATA; i <= CURSEG_COLD_DATA; i++)
		__allocate_new_segment(sbi, i);
	up_write(&SIT_I(sbi)->sentry_lock);
}

static const struct segment_allocation default_salloc_ops = {
	.allocate_segment = allocate_segment_by_default,
};

static const struct segment_allocation IFLBA_salloc_ops = {
	.allocate_segment = append_only_allocate_segment,
};

bool f2fs_exist_trim_candidates(struct f2fs_sb_info *sbi,
						struct cp_control *cpc)
{
	__u64 trim_start = cpc->trim_start;
	bool has_candidate = false;

	down_write(&SIT_I(sbi)->sentry_lock);
	for (; cpc->trim_start <= cpc->trim_end; cpc->trim_start++) {
		
		if (add_discard_addrs(sbi, cpc, true)) {
			has_candidate = true;
			break;
		}
	}
	up_write(&SIT_I(sbi)->sentry_lock);

	cpc->trim_start = trim_start;
	return has_candidate;
}

static unsigned int __issue_discard_cmd_range(struct f2fs_sb_info *sbi,
					struct discard_policy *dpolicy,
					unsigned int start, unsigned int end)
{
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct discard_cmd *prev_dc = NULL, *next_dc = NULL;
	struct rb_node **insert_p = NULL, *insert_parent = NULL;
	struct discard_cmd *dc;
	struct blk_plug plug;
	int issued;
	unsigned int trimmed = 0;

next:
	issued = 0;

	mutex_lock(&dcc->cmd_lock);
	if (unlikely(dcc->rbtree_check))
		f2fs_bug_on(sbi, !f2fs_check_rb_tree_consistence(sbi,
							&dcc->root, false));

	dc = (struct discard_cmd *)f2fs_lookup_rb_tree_ret(&dcc->root,
					NULL, start,
					(struct rb_entry **)&prev_dc,
					(struct rb_entry **)&next_dc,
					&insert_p, &insert_parent, true, NULL);
	if (!dc)
		dc = next_dc;

	blk_start_plug(&plug);

	while (dc && dc->lstart <= end) {
		struct rb_node *node;
		int err = 0;

		if (dc->len < dpolicy->granularity)
			goto skip;

		if (dc->state != D_PREP) {
			list_move_tail(&dc->list, &dcc->fstrim_list);
			goto skip;
		}

		err = __submit_discard_cmd(sbi, dpolicy, dc, &issued);

		if (issued >= dpolicy->max_requests) {
			start = dc->lstart + dc->len;

			if (err)
				__remove_discard_cmd(sbi, dc);

			blk_finish_plug(&plug);
			mutex_unlock(&dcc->cmd_lock);
			trimmed += __wait_all_discard_cmd(sbi, NULL);
			congestion_wait(BLK_RW_ASYNC, DEFAULT_IO_TIMEOUT);
			goto next;
		}
skip:
		node = rb_next(&dc->rb_node);
		if (err)
			__remove_discard_cmd(sbi, dc);
		dc = rb_entry_safe(node, struct discard_cmd, rb_node);

		if (fatal_signal_pending(current))
			break;
	}

	blk_finish_plug(&plug);
	mutex_unlock(&dcc->cmd_lock);

	return trimmed;
}

int f2fs_trim_fs(struct f2fs_sb_info *sbi, struct fstrim_range *range)
{
	__u64 start = F2FS_BYTES_TO_BLK(range->start);
	__u64 end = start + F2FS_BYTES_TO_BLK(range->len) - 1;
	unsigned int start_segno, end_segno;
	block_t start_block, end_block;
	struct cp_control cpc;
	struct discard_policy dpolicy;
	unsigned long long trimmed = 0;
	int err = 0;
	bool need_align = f2fs_lfs_mode(sbi) && __is_large_section(sbi);

	if (start >= MAX_BLKADDR(sbi) || range->len < sbi->blocksize)
		return -EINVAL;

	if (end < MAIN_BLKADDR(sbi))
		goto out;

	if (is_sbi_flag_set(sbi, SBI_NEED_FSCK)) {
		f2fs_warn(sbi, "Found FS corruption, run fsck to fix.");
		return -EFSCORRUPTED;
	}

	/* start/end segment number in main_area */
	start_segno = (start <= MAIN_BLKADDR(sbi)) ? 0 : GET_SEGNO(sbi, start);
	end_segno = (end >= MAX_BLKADDR(sbi)) ? MAIN_SEGS(sbi) - 1 :
						GET_SEGNO(sbi, end);
	if (need_align) {
		start_segno = rounddown(start_segno, sbi->segs_per_sec);
		end_segno = roundup(end_segno + 1, sbi->segs_per_sec) - 1;
	}

	cpc.reason = CP_DISCARD;
	cpc.trim_minlen = max_t(__u64, 1, F2FS_BYTES_TO_BLK(range->minlen));
	cpc.trim_start = start_segno;
	cpc.trim_end = end_segno;

	if (sbi->discard_blks == 0)
		goto out;

	down_write(&sbi->gc_lock);
	err = f2fs_write_checkpoint(sbi, &cpc);
	up_write(&sbi->gc_lock);
	if (err)
		goto out;

	/*
	 * We filed discard candidates, but actually we don't need to wait for
	 * all of them, since they'll be issued in idle time along with runtime
	 * discard option. User configuration looks like using runtime discard
	 * or periodic fstrim instead of it.
	 */
	if (f2fs_realtime_discard_enable(sbi))
		goto out;

	start_block = START_BLOCK(sbi, start_segno);
	end_block = START_BLOCK(sbi, end_segno + 1);

	__init_discard_policy(sbi, &dpolicy, DPOLICY_FSTRIM, cpc.trim_minlen);
	trimmed = __issue_discard_cmd_range(sbi, &dpolicy,
					start_block, end_block);

	trimmed += __wait_discard_cmd_range(sbi, &dpolicy,
					start_block, end_block);
out:
	if (!err)
		range->len = F2FS_BLK_TO_BYTES(trimmed);
	return err;
}

static bool __has_curseg_space(struct f2fs_sb_info *sbi,
					struct curseg_info *curseg)
{
	return curseg->next_blkoff < f2fs_usable_blks_in_seg(sbi,
							curseg->segno);
}

int f2fs_rw_hint_to_seg_type(enum rw_hint hint)
{
	switch (hint) {
	case WRITE_LIFE_SHORT:
		return CURSEG_HOT_DATA;
	case WRITE_LIFE_EXTREME:
		return CURSEG_COLD_DATA;
	default:
		return CURSEG_WARM_DATA;
	}
}

/* This returns write hints for each segment type. This hints will be
 * passed down to block layer. There are mapping tables which depend on
 * the mount option 'whint_mode'.
 *
 * 1) whint_mode=off. F2FS only passes down WRITE_LIFE_NOT_SET.
 *
 * 2) whint_mode=user-based. F2FS tries to pass down hints given by users.
 *
 * User                  F2FS                     Block
 * ----                  ----                     -----
 *                       META                     WRITE_LIFE_NOT_SET
 *                       HOT_NODE                 "
 *                       WARM_NODE                "
 *                       COLD_NODE                "
 * ioctl(COLD)           COLD_DATA                WRITE_LIFE_EXTREME
 * extension list        "                        "
 *
 * -- buffered io
 * WRITE_LIFE_EXTREME    COLD_DATA                WRITE_LIFE_EXTREME
 * WRITE_LIFE_SHORT      HOT_DATA                 WRITE_LIFE_SHORT
 * WRITE_LIFE_NOT_SET    WARM_DATA                WRITE_LIFE_NOT_SET
 * WRITE_LIFE_NONE       "                        "
 * WRITE_LIFE_MEDIUM     "                        "
 * WRITE_LIFE_LONG       "                        "
 *
 * -- direct io
 * WRITE_LIFE_EXTREME    COLD_DATA                WRITE_LIFE_EXTREME
 * WRITE_LIFE_SHORT      HOT_DATA                 WRITE_LIFE_SHORT
 * WRITE_LIFE_NOT_SET    WARM_DATA                WRITE_LIFE_NOT_SET
 * WRITE_LIFE_NONE       "                        WRITE_LIFE_NONE
 * WRITE_LIFE_MEDIUM     "                        WRITE_LIFE_MEDIUM
 * WRITE_LIFE_LONG       "                        WRITE_LIFE_LONG
 *
 * 3) whint_mode=fs-based. F2FS passes down hints with its policy.
 *
 * User                  F2FS                     Block
 * ----                  ----                     -----
 *                       META                     WRITE_LIFE_MEDIUM;
 *                       HOT_NODE                 WRITE_LIFE_NOT_SET
 *                       WARM_NODE                "
 *                       COLD_NODE                WRITE_LIFE_NONE
 * ioctl(COLD)           COLD_DATA                WRITE_LIFE_EXTREME
 * extension list        "                        "
 *
 * -- buffered io
 * WRITE_LIFE_EXTREME    COLD_DATA                WRITE_LIFE_EXTREME
 * WRITE_LIFE_SHORT      HOT_DATA                 WRITE_LIFE_SHORT
 * WRITE_LIFE_NOT_SET    WARM_DATA                WRITE_LIFE_LONG
 * WRITE_LIFE_NONE       "                        "
 * WRITE_LIFE_MEDIUM     "                        "
 * WRITE_LIFE_LONG       "                        "
 *
 * -- direct io
 * WRITE_LIFE_EXTREME    COLD_DATA                WRITE_LIFE_EXTREME
 * WRITE_LIFE_SHORT      HOT_DATA                 WRITE_LIFE_SHORT
 * WRITE_LIFE_NOT_SET    WARM_DATA                WRITE_LIFE_NOT_SET
 * WRITE_LIFE_NONE       "                        WRITE_LIFE_NONE
 * WRITE_LIFE_MEDIUM     "                        WRITE_LIFE_MEDIUM
 * WRITE_LIFE_LONG       "                        WRITE_LIFE_LONG
 */

enum rw_hint f2fs_io_type_to_rw_hint(struct f2fs_sb_info *sbi,
				enum page_type type, enum temp_type temp)
{
	if (F2FS_OPTION(sbi).whint_mode == WHINT_MODE_USER) {
		if (type == DATA) {
			if (temp == WARM)
				return WRITE_LIFE_NOT_SET;
			else if (temp == HOT)
				return WRITE_LIFE_SHORT;
			else if (temp == COLD)
				return WRITE_LIFE_EXTREME;
		} else {
			return WRITE_LIFE_NOT_SET;
		}
	} else if (F2FS_OPTION(sbi).whint_mode == WHINT_MODE_FS) {
		if (type == DATA) {
			if (temp == WARM)
				return WRITE_LIFE_LONG;
			else if (temp == HOT)
				return WRITE_LIFE_SHORT;
			else if (temp == COLD)
				return WRITE_LIFE_EXTREME;
		} else if (type == NODE) {
			if (temp == WARM || temp == HOT)
				return WRITE_LIFE_NOT_SET;
			else if (temp == COLD)
				return WRITE_LIFE_NONE;
		} else if (type == META) {
			return WRITE_LIFE_MEDIUM;
		}
	}
	return WRITE_LIFE_NOT_SET;
}

static int __get_segment_type_2(struct f2fs_io_info *fio)
{
	if (fio->type == DATA)
		return CURSEG_HOT_DATA;
	else
		return CURSEG_HOT_NODE;
}

static int __get_segment_type_4(struct f2fs_io_info *fio)
{
	if (fio->type == DATA) {
		struct inode *inode = fio->page->mapping->host;

		if (S_ISDIR(inode->i_mode))
			return CURSEG_HOT_DATA;
		else
			return CURSEG_COLD_DATA;
	} else {
		if (IS_DNODE(fio->page) && is_cold_node(fio->page))
			return CURSEG_WARM_NODE;
		else
			return CURSEG_COLD_NODE;
	}
}

static int __get_segment_type_6(struct f2fs_io_info *fio)
{
	if (fio->type == DATA) {
		struct inode *inode = fio->page->mapping->host;

		if (is_cold_data(fio->page)) {
			if (fio->sbi->am.atgc_enabled)
				return CURSEG_ALL_DATA_ATGC;
			else
				return CURSEG_COLD_DATA;
		}
		if (file_is_cold(inode) || f2fs_need_compress_data(inode))
			return CURSEG_COLD_DATA;
		if (file_is_hot(inode) ||
				is_inode_flag_set(inode, FI_HOT_DATA) ||
				f2fs_is_atomic_file(inode) ||
				f2fs_is_volatile_file(inode))
			return CURSEG_HOT_DATA;
		return f2fs_rw_hint_to_seg_type(inode->i_write_hint);
	} else {
		if (IS_DNODE(fio->page))
			return is_cold_node(fio->page) ? CURSEG_WARM_NODE :
						CURSEG_HOT_NODE;
		return CURSEG_COLD_NODE;
	}
}

static int __get_segment_type(struct f2fs_io_info *fio)
{
	int type = 0;

	switch (F2FS_OPTION(fio->sbi).active_logs) {
	case 2:
		type = __get_segment_type_2(fio);
		break;
	case 4:
		type = __get_segment_type_4(fio);
		break;
	case 6:
		type = __get_segment_type_6(fio);
		break;
	default:
		f2fs_bug_on(fio->sbi, true);
	}

	if (IS_HOT(type))
		fio->temp = HOT;
	else if (IS_WARM(type))
		fio->temp = WARM;
	else
		fio->temp = COLD;
	return type;
}

void f2fs_allocate_data_block(struct f2fs_sb_info *sbi, struct page *page,
		block_t old_blkaddr, block_t *new_blkaddr,
		struct f2fs_summary *sum, int type,
		struct f2fs_io_info *fio)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct curseg_info *curseg = CURSEG_I(sbi, type);
	unsigned long long old_mtime;
	bool from_gc = (type == CURSEG_ALL_DATA_ATGC);
	struct seg_entry *se = NULL;

	down_read(&SM_I(sbi)->curseg_lock);

	mutex_lock(&curseg->curseg_mutex);
	down_write(&sit_i->sentry_lock);

	if (from_gc) {
		panic("f2fs_allocate_data_block(): from_gc = 1 not expected!!");
		//f2fs_bug_on(sbi, GET_SEGNO(sbi, old_blkaddr) == NULL_SEGNO);
		//se = get_seg_entry(sbi, GET_SEGNO(sbi, old_blkaddr));
		//sanity_check_seg_type(sbi, se->type);
		//f2fs_bug_on(sbi, IS_NODESEG(se->type));
	}
	*new_blkaddr = NEXT_FREE_BLKADDR(sbi, curseg);

	f2fs_bug_on(sbi, curseg->next_blkoff >= sbi->blocks_per_seg);

	f2fs_wait_discard_bio(sbi, *new_blkaddr);

	/*
	 * __add_sum_entry should be resided under the curseg_mutex
	 * because, this function updates a summary entry in the
	 * current summary block.
	 */
	//__add_sum_entry(sbi, type, sum);

	__refresh_next_blkoff(sbi, curseg);

	stat_inc_block_count(sbi, curseg);

	/*if (from_gc) {
		old_mtime = get_segment_mtime(sbi, old_blkaddr);
	} else {
		update_segment_mtime(sbi, old_blkaddr, 0);
		old_mtime = 0;
	}
	update_segment_mtime(sbi, *new_blkaddr, old_mtime);
	*/
	/*
	 * SIT information should be updated before segment allocation,
	 * since SSR needs latest valid block information.
	 */
	update_sit_entry(sbi, *new_blkaddr, 1);
	if (GET_SEGNO(sbi, old_blkaddr) != NULL_SEGNO)
		update_sit_entry(sbi, old_blkaddr, -1);

	if (!__has_curseg_space(sbi, curseg)) {
		if (from_gc)
			get_atssr_segment(sbi, type, se->type,
						AT_SSR, se->mtime);
		else
			sit_i->s_ops->allocate_segment(sbi, type, false);
	}
	/*
	 * segment dirty status should be updated after segment allocation,
	 * so we just need to update status only one time after previous
	 * segment being closed.
	 */
	//locate_dirty_segment(sbi, GET_SEGNO(sbi, old_blkaddr));
	//locate_dirty_segment(sbi, GET_SEGNO(sbi, *new_blkaddr));

	up_write(&sit_i->sentry_lock);

	if (page && IS_NODESEG(type)) {
		fill_node_footer_blkaddr(page, NEXT_FREE_BLKADDR(sbi, curseg));

		f2fs_inode_chksum_set(sbi, page);
	}

	if (F2FS_IO_ALIGNED(sbi))
		fio->retry = false;

	if (fio) {
		struct f2fs_bio_info *io;

		INIT_LIST_HEAD(&fio->list);
		fio->in_list = true;
		io = sbi->write_io[fio->type] + fio->temp;
		spin_lock(&io->io_lock);
		list_add_tail(&fio->list, &io->io_list);
		spin_unlock(&io->io_lock);
	}

	mutex_unlock(&curseg->curseg_mutex);

	up_read(&SM_I(sbi)->curseg_lock);
}

static void update_device_state(struct f2fs_io_info *fio)
{
	struct f2fs_sb_info *sbi = fio->sbi;
	unsigned int devidx;

	if (!f2fs_is_multi_device(sbi))
		return;

	devidx = f2fs_target_device_index(sbi, fio->new_blkaddr);

	/* update device state for fsync */
	f2fs_set_dirty_device(sbi, fio->ino, devidx, FLUSH_INO);

	/* update device state for checkpoint */
	if (!f2fs_test_bit(devidx, (char *)&sbi->dirty_device)) {
		spin_lock(&sbi->dev_lock);
		f2fs_set_bit(devidx, (char *)&sbi->dirty_device);
		spin_unlock(&sbi->dev_lock);
	}
}

static void do_write_page(struct f2fs_summary *sum, struct f2fs_io_info *fio)
{
	/*static block_t nid7_addr = 0;
	static int data_wrtcnt = 0;
	static int node_wrtcnt = 0;
	static int wrtcnt = 0;
	*/
	int type = __get_segment_type(fio);
	bool keep_order = (f2fs_lfs_mode(fio->sbi) && type == CURSEG_COLD_DATA);

	//struct node_info ni;
	struct f2fs_sb_info *sbi = F2FS_P_SB(fio->page);	

	if (keep_order)
		down_read(&fio->sbi->io_order_lock);
reallocate:
	f2fs_allocate_data_block(fio->sbi, fio->page, fio->old_blkaddr,
			&fio->new_blkaddr, sum, type, fio);
	if (GET_SEGNO(fio->sbi, fio->old_blkaddr) != NULL_SEGNO)
		invalidate_mapping_pages(META_MAPPING(fio->sbi),
					fio->old_blkaddr, fio->old_blkaddr);

	/* writeout dirty page into bdev */
	f2fs_submit_page_write(fio);
	if (fio->retry) {
		fio->old_blkaddr = fio->new_blkaddr;
		goto reallocate;
	}
	//
	//f2fs_get_node_info(sbi, nid_of_node(fio->page), &ni);
	/*if ((fio->new_blkaddr == nid7_addr) || (fio->old_blkaddr == nid7_addr) && nid7_addr != 0){
		printk("[JW DBG] %s: other detected!! fio type is NODE %d, ino: %u, oldblkaddr: %u, newblkaddr: %u,  \n",
				 __func__, fio->type == NODE, fio->ino, fio->old_blkaddr , fio->new_blkaddr);
	}
	if (nid_of_node(fio->page) == 7){
		printk("[JW DBG] %s: fio type is NODE %d, ino: %u, oldblkaddr: %u, newblkaddr: %u,  \n",
				 __func__, fio->type == NODE, fio->ino, fio->old_blkaddr , fio->new_blkaddr);
		if (fio->type == NODE){
			printk("\t nodefooter[nid:%u,ino%u,ofs:%u,cpver:%llu,blkaddr:%u]", 
			  nid_of_node(fio->page), ino_of_node(fio->page),
			  ofs_of_node(fio->page), cpver_of_node(fio->page),
			  next_blkaddr_of_node(fio->page));
			//panic("[JW DBG] %s: Just to check stackframe\n", __func__);
			//printk("[JW DBG] %s: Intended Bug\n", __func__);
			nid7_addr = fio->new_blkaddr;
			//f2fs_bug_on(sbi, 1);
		}
	}*/
	/*
	wrtcnt += 1;
	if (fio->type == NODE){
		node_wrtcnt += 1;
		if (node_wrtcnt % 50000 == 0)
			printk("[JW DBG] %s: %ds write: Node write cnt: %d : ino: %u, oldblkaddr: %u, newblkaddr: %u,  \n",
				 __func__, wrtcnt, node_wrtcnt, fio->ino, fio->old_blkaddr , fio->new_blkaddr);
		
	}

	else if (fio->type == DATA){
		data_wrtcnt += 1;
		if (data_wrtcnt % 50000 == 0)
			printk("[JW DBG] %s: %ds write: Data write cnt: %d : ino: %u, oldblkaddr: %u, newblkaddr: %u,  \n",
				 __func__, wrtcnt, data_wrtcnt, fio->ino, fio->old_blkaddr , fio->new_blkaddr);

	}
	if (wrtcnt%50000==0)//{
		printk("[JW DBG] %s: %ds write: is_NODE %d, ino: %u, oldblkaddr: %u, newblkaddr: %u,  \n",
				 __func__, wrtcnt, fio->type == NODE, fio->ino, fio->old_blkaddr , fio->new_blkaddr);
	//}*/
	update_device_state(fio);

	if (keep_order)
		up_read(&fio->sbi->io_order_lock);
}

void f2fs_do_write_meta_page(struct f2fs_sb_info *sbi, struct page *page,
					enum iostat_type io_type)
{
	struct f2fs_io_info fio = {
		.sbi = sbi,
		.type = META,
		.temp = HOT,
		.op = REQ_OP_WRITE,
		.op_flags = REQ_SYNC | REQ_META | REQ_PRIO,
		.old_blkaddr = page->index,
		.new_blkaddr = page->index,
		.page = page,
		.encrypted_page = NULL,
		.in_list = false,
	};

	if (unlikely(page->index >= MAIN_BLKADDR(sbi)))
		fio.op_flags &= ~REQ_META;

	set_page_writeback(page);
	ClearPageError(page);
	f2fs_submit_page_write(&fio);

	stat_inc_meta_count(sbi, page->index);
	f2fs_update_iostat(sbi, io_type, F2FS_BLKSIZE);
}

void f2fs_do_write_node_page(unsigned int nid, struct f2fs_io_info *fio)
{
	struct f2fs_summary sum;

	set_summary(&sum, nid, 0, 0);
	do_write_page(&sum, fio);

	f2fs_update_iostat(fio->sbi, fio->io_type, F2FS_BLKSIZE);
}

void f2fs_outplace_write_data(struct dnode_of_data *dn,
					struct f2fs_io_info *fio)
{
	struct f2fs_sb_info *sbi = fio->sbi;
	struct f2fs_summary sum;

	f2fs_bug_on(sbi, dn->data_blkaddr == NULL_ADDR);
	set_summary(&sum, dn->nid, dn->ofs_in_node, fio->version);
	do_write_page(&sum, fio);
	f2fs_update_data_blkaddr(dn, fio->new_blkaddr);

	f2fs_update_iostat(sbi, fio->io_type, F2FS_BLKSIZE);
}

int f2fs_inplace_write_data(struct f2fs_io_info *fio)
{
	int err;
	struct f2fs_sb_info *sbi = fio->sbi;
	unsigned int segno;

	fio->new_blkaddr = fio->old_blkaddr;
	/* i/o temperature is needed for passing down write hints */
	__get_segment_type(fio);

	segno = GET_SEGNO(sbi, fio->new_blkaddr);

	if (!IS_DATASEG(get_seg_entry(sbi, segno)->type)) {
		set_sbi_flag(sbi, SBI_NEED_FSCK);
		f2fs_warn(sbi, "%s: incorrect segment(%u) type, run fsck to fix.",
			  __func__, segno);
		return -EFSCORRUPTED;
	}

	stat_inc_inplace_blocks(fio->sbi);

	if (fio->bio && !(SM_I(sbi)->ipu_policy & (1 << F2FS_IPU_NOCACHE)))
		err = f2fs_merge_page_bio(fio);
	else
		err = f2fs_submit_page_bio(fio);
	if (!err) {
		update_device_state(fio);
		f2fs_update_iostat(fio->sbi, fio->io_type, F2FS_BLKSIZE);
	}

	return err;
}

static inline int __f2fs_get_curseg(struct f2fs_sb_info *sbi,
						unsigned int segno)
{
	int i;

	for (i = CURSEG_HOT_DATA; i < NO_CHECK_TYPE; i++) {
		if (CURSEG_I(sbi, i)->segno == segno)
			break;
	}
	return i;
}

void f2fs_do_replace_block(struct f2fs_sb_info *sbi, struct f2fs_summary *sum,
				block_t old_blkaddr, block_t new_blkaddr,
				bool recover_curseg, bool recover_newaddr,
				bool from_gc)
{
	//struct sit_info *sit_i = SIT_I(sbi);
	//struct curseg_info *curseg;
	//unsigned int segno, old_cursegno;
	//struct seg_entry *se;
	//int type;
	//unsigned short old_blkoff;

	//segno = GET_SEGNO(sbi, new_blkaddr);
	//se = get_seg_entry(sbi, segno);
	//type = se->type;

	//down_write(&SM_I(sbi)->curseg_lock);

	/*if (!recover_curseg) {
		// for recovery flow 
		if (se->valid_blocks == 0 && !IS_CURSEG(sbi, segno)) {
			if (old_blkaddr == NULL_ADDR)
				type = CURSEG_COLD_DATA;
			else
				type = CURSEG_WARM_DATA;
		}
	} else {
		if (IS_CURSEG(sbi, segno)) {
			// se->type is volatile as SSR allocation 
			type = __f2fs_get_curseg(sbi, segno);
			f2fs_bug_on(sbi, type == NO_CHECK_TYPE);
		} else {
			type = CURSEG_WARM_DATA;
		}
	}*/

	//f2fs_bug_on(sbi, !IS_DATASEG(type));
	//curseg = CURSEG_I(sbi, type);

	//mutex_lock(&curseg->curseg_mutex);
	//down_write(&sit_i->sentry_lock);

	//old_cursegno = curseg->segno;
	//old_blkoff = curseg->next_blkoff;

	/* change the current segment */
	/* make these lines comment because change_curseg() is called only for changing current segment. 
	if (segno != curseg->segno) {
		curseg->next_segno = segno;
		change_curseg(sbi, type, true);
	}

	curseg->next_blkoff = GET_BLKOFF_FROM_SEG0(sbi, new_blkaddr);
	__add_sum_entry(sbi, type, sum);
	*/
	if (!recover_curseg || recover_newaddr) {
		//if (!from_gc)
		//	update_segment_mtime(sbi, new_blkaddr, 0);
		update_sit_entry(sbi, new_blkaddr, 1);
	}
	if (GET_SEGNO(sbi, old_blkaddr) != NULL_SEGNO) {
		invalidate_mapping_pages(META_MAPPING(sbi),
					old_blkaddr, old_blkaddr);
		//if (!from_gc)
			//update_segment_mtime(sbi, old_blkaddr, 0);
		update_sit_entry(sbi, old_blkaddr, -1);
	}

	//locate_dirty_segment(sbi, GET_SEGNO(sbi, old_blkaddr));
	//locate_dirty_segment(sbi, GET_SEGNO(sbi, new_blkaddr));

	//locate_dirty_segment(sbi, old_cursegno);

	/*if (recover_curseg) {
		if (old_cursegno != curseg->segno) {
			curseg->next_segno = old_cursegno;
			change_curseg(sbi, type, true);
		}
		curseg->next_blkoff = old_blkoff;
	}*/

	//up_write(&sit_i->sentry_lock);
	//mutex_unlock(&curseg->curseg_mutex);
	//up_write(&SM_I(sbi)->curseg_lock);
}

void f2fs_replace_block(struct f2fs_sb_info *sbi, struct dnode_of_data *dn,
				block_t old_addr, block_t new_addr,
				unsigned char version, bool recover_curseg,
				bool recover_newaddr)
{
	struct f2fs_summary sum;

	set_summary(&sum, dn->nid, dn->ofs_in_node, version);

	f2fs_do_replace_block(sbi, &sum, old_addr, new_addr,
					recover_curseg, recover_newaddr, false);

	f2fs_update_data_blkaddr(dn, new_addr);
}

void f2fs_wait_on_page_writeback(struct page *page,
				enum page_type type, bool ordered, bool locked)
{
	if (PageWriteback(page)) {
		struct f2fs_sb_info *sbi = F2FS_P_SB(page);

		/* submit cached LFS IO */
		f2fs_submit_merged_write_cond(sbi, NULL, page, 0, type);
		/* sbumit cached IPU IO */
		f2fs_submit_merged_ipu_write(sbi, NULL, page);
		if (ordered) {
			wait_on_page_writeback(page);
			f2fs_bug_on(sbi, locked && PageWriteback(page));
		} else {
			wait_for_stable_page(page);
		}
	}
}

void f2fs_wait_on_block_writeback(struct inode *inode, block_t blkaddr)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct page *cpage;

	if (!f2fs_post_read_required(inode))
		return;

	if (!__is_valid_data_blkaddr(blkaddr))
		return;

	cpage = find_lock_page(META_MAPPING(sbi), blkaddr);
	if (cpage) {
		f2fs_wait_on_page_writeback(cpage, DATA, true, true);
		f2fs_put_page(cpage, 1);
	}
}

void f2fs_wait_on_block_writeback_range(struct inode *inode, block_t blkaddr,
								block_t len)
{
	block_t i;

	for (i = 0; i < len; i++)
		f2fs_wait_on_block_writeback(inode, blkaddr + i);
}

static int read_compacted_summaries(struct f2fs_sb_info *sbi)
{
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	struct curseg_info *seg_i;
	unsigned char *kaddr;
	struct page *page;
	block_t start;
	int i, j, offset;

	start = start_sum_block(sbi);

	page = f2fs_get_meta_page(sbi, start++);
	if (IS_ERR(page))
		return PTR_ERR(page);
	kaddr = (unsigned char *)page_address(page);

	/* Step 1: restore nat cache */
	seg_i = CURSEG_I(sbi, CURSEG_HOT_DATA);
	memcpy(seg_i->journal, kaddr, SUM_JOURNAL_SIZE);

	/* Step 2: restore sit cache */
	seg_i = CURSEG_I(sbi, CURSEG_COLD_DATA);
	memcpy(seg_i->journal, kaddr + SUM_JOURNAL_SIZE, SUM_JOURNAL_SIZE);
	offset = 2 * SUM_JOURNAL_SIZE;

	/* Step 3: restore summary entries */
	for (i = CURSEG_HOT_DATA; i <= CURSEG_COLD_DATA; i++) {
		unsigned short blk_off;
		unsigned int segno;

		seg_i = CURSEG_I(sbi, i);
		segno = le32_to_cpu(ckpt->cur_data_segno[i]);
		blk_off = le16_to_cpu(ckpt->cur_data_blkoff[i]);
		seg_i->next_segno = segno;
		reset_curseg(sbi, i, 0);
		seg_i->alloc_type = ckpt->alloc_type[i];
		seg_i->next_blkoff = blk_off;

		if (seg_i->alloc_type == SSR)
			blk_off = sbi->blocks_per_seg;

		for (j = 0; j < blk_off; j++) {
			struct f2fs_summary *s;
			s = (struct f2fs_summary *)(kaddr + offset);
			seg_i->sum_blk->entries[j] = *s;
			offset += SUMMARY_SIZE;
			if (offset + SUMMARY_SIZE <= PAGE_SIZE -
						SUM_FOOTER_SIZE)
				continue;

			f2fs_put_page(page, 1);
			page = NULL;

			page = f2fs_get_meta_page(sbi, start++);
			if (IS_ERR(page))
				return PTR_ERR(page);
			kaddr = (unsigned char *)page_address(page);
			offset = 0;
		}
	}
	f2fs_put_page(page, 1);
	return 0;
}

static int read_normal_summaries(struct f2fs_sb_info *sbi, int type)
{
	struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
	struct f2fs_summary_block *sum;
	struct curseg_info *curseg;
	struct page *new;
	unsigned short blk_off;
	unsigned int segno = 0;
	block_t blk_addr = 0;
	int err = 0;

	/* get segment number and block addr */
	if (IS_DATASEG(type)) {
		segno = le32_to_cpu(ckpt->cur_data_segno[type]);
		blk_off = le16_to_cpu(ckpt->cur_data_blkoff[type -
							CURSEG_HOT_DATA]);
		if (__exist_node_summaries(sbi))
			blk_addr = sum_blk_addr(sbi, NR_CURSEG_PERSIST_TYPE, type);
		else
			blk_addr = sum_blk_addr(sbi, NR_CURSEG_DATA_TYPE, type);
	} else {
		segno = le32_to_cpu(ckpt->cur_node_segno[type -
							CURSEG_HOT_NODE]);
		blk_off = le16_to_cpu(ckpt->cur_node_blkoff[type -
							CURSEG_HOT_NODE]);
		if (__exist_node_summaries(sbi))
			blk_addr = sum_blk_addr(sbi, NR_CURSEG_NODE_TYPE,
							type - CURSEG_HOT_NODE);
		else
			blk_addr = GET_SUM_BLOCK(sbi, segno);
		//GET_SUM_BLOCK part must be modified. I disabled updating summary block so getting sum block form SSA part would cause trash SUM block. But it's okay since The content of SSA is actually not used. Thus, holding trash sum block for node type as curseg doesn't really matter. 
	}

	new = f2fs_get_meta_page(sbi, blk_addr);
	if (IS_ERR(new))
		return PTR_ERR(new);
	sum = (struct f2fs_summary_block *)page_address(new);
	/*
	if (IS_NODESEG(type)) {
		if (__exist_node_summaries(sbi)) {
			struct f2fs_summary *ns = &sum->entries[0];
			int i;
			for (i = 0; i < sbi->blocks_per_seg; i++, ns++) {
				ns->version = 0;
				ns->ofs_in_node = 0;
			}
		} else {
			err = f2fs_restore_node_summary(sbi, segno, sum);
			if (err)
				goto out;
		}
	}
	*/

	/* set uncompleted segment to curseg */
	curseg = CURSEG_I(sbi, type);
	mutex_lock(&curseg->curseg_mutex);

	/* update journal info */
	down_write(&curseg->journal_rwsem);
	memcpy(curseg->journal, &sum->journal, SUM_JOURNAL_SIZE);
	up_write(&curseg->journal_rwsem);
	
	memcpy(curseg->sum_blk->entries, sum->entries, SUM_ENTRY_SIZE);
	memcpy(&curseg->sum_blk->footer, &sum->footer, SUM_FOOTER_SIZE);
	
	curseg->next_segno = segno;
	reset_curseg(sbi, type, 0);
	curseg->alloc_type = ckpt->alloc_type[type];
	curseg->next_blkoff = blk_off;
	mutex_unlock(&curseg->curseg_mutex);
//out:
	f2fs_put_page(new, 1);
	return err;
}

static int restore_curseg_summaries(struct f2fs_sb_info *sbi)
{
	struct f2fs_journal *sit_j = CURSEG_I(sbi, CURSEG_COLD_DATA)->journal;
	struct f2fs_journal *nat_j = CURSEG_I(sbi, CURSEG_HOT_DATA)->journal;
	int type = CURSEG_HOT_DATA;
	int err;

	if (is_set_ckpt_flags(sbi, CP_COMPACT_SUM_FLAG)) {
		int npages = f2fs_npages_for_summary_flush(sbi, true);

		if (npages >= 2)
			f2fs_ra_meta_pages(sbi, start_sum_block(sbi), npages,
							META_CP, true);

		/* restore for compacted data summary */
		err = read_compacted_summaries(sbi);
		if (err)
			return err;
		type = CURSEG_HOT_NODE;
	}

	if (__exist_node_summaries(sbi))
		f2fs_ra_meta_pages(sbi,
				sum_blk_addr(sbi, NR_CURSEG_PERSIST_TYPE, type),
				NR_CURSEG_PERSIST_TYPE - type, META_CP, true);

	for (; type <= CURSEG_COLD_NODE; type++) {
		err = read_normal_summaries(sbi, type);
		if (err)
			return err;
	}

	/* sanity check for summary blocks */
	if (nats_in_cursum(nat_j) > NAT_JOURNAL_ENTRIES ||
			sits_in_cursum(sit_j) > SIT_JOURNAL_ENTRIES) {
		f2fs_err(sbi, "invalid journal entries nats %u sits %u\n",
			 nats_in_cursum(nat_j), sits_in_cursum(sit_j));
		return -EINVAL;
	}

	return 0;
}

static void write_compacted_summaries(struct f2fs_sb_info *sbi, block_t blkaddr)
{
	struct page *page;
	unsigned char *kaddr;
	struct f2fs_summary *summary;
	struct curseg_info *seg_i;
	int written_size = 0;
	int i, j;

	page = f2fs_grab_meta_page(sbi, blkaddr++);
	kaddr = (unsigned char *)page_address(page);
	memset(kaddr, 0, PAGE_SIZE);

	/* Step 1: write nat cache */
	seg_i = CURSEG_I(sbi, CURSEG_HOT_DATA);
	memcpy(kaddr, seg_i->journal, SUM_JOURNAL_SIZE);
	written_size += SUM_JOURNAL_SIZE;

	/* Step 2: write sit cache */
	seg_i = CURSEG_I(sbi, CURSEG_COLD_DATA);
	memcpy(kaddr + written_size, seg_i->journal, SUM_JOURNAL_SIZE);
	written_size += SUM_JOURNAL_SIZE;

	/* Step 3: write summary entries */
	for (i = CURSEG_HOT_DATA; i <= CURSEG_COLD_DATA; i++) {
		unsigned short blkoff;
		seg_i = CURSEG_I(sbi, i);
		if (sbi->ckpt->alloc_type[i] == SSR)
			blkoff = sbi->blocks_per_seg;
		else
			blkoff = curseg_blkoff(sbi, i);

		for (j = 0; j < blkoff; j++) {
			if (!page) {
				page = f2fs_grab_meta_page(sbi, blkaddr++);
				kaddr = (unsigned char *)page_address(page);
				memset(kaddr, 0, PAGE_SIZE);
				written_size = 0;
			}
			summary = (struct f2fs_summary *)(kaddr + written_size);
			*summary = seg_i->sum_blk->entries[j];
			written_size += SUMMARY_SIZE;

			if (written_size + SUMMARY_SIZE <= PAGE_SIZE -
							SUM_FOOTER_SIZE)
				continue;

			set_page_dirty(page);
			f2fs_put_page(page, 1);
			page = NULL;
		}
	}
	if (page) {
		set_page_dirty(page);
		f2fs_put_page(page, 1);
	}
}

static void write_normal_summaries(struct f2fs_sb_info *sbi,
					block_t blkaddr, int type)
{
	int i, end;
	if (IS_DATASEG(type))
		end = type + NR_CURSEG_DATA_TYPE;
	else
		end = type + NR_CURSEG_NODE_TYPE;

	for (i = type; i < end; i++)
		write_current_sum_page(sbi, i, blkaddr + (i - type));
}

void f2fs_write_data_summaries(struct f2fs_sb_info *sbi, block_t start_blk)
{
	if (is_set_ckpt_flags(sbi, CP_COMPACT_SUM_FLAG))
		write_compacted_summaries(sbi, start_blk);
	else
		write_normal_summaries(sbi, start_blk, CURSEG_HOT_DATA);
}

void f2fs_write_node_summaries(struct f2fs_sb_info *sbi, block_t start_blk)
{
	write_normal_summaries(sbi, start_blk, CURSEG_HOT_NODE);
}

/* Write every discard bitmap journal to blk */
static block_t write_discard_bitmap_journals(struct f2fs_sb_info *sbi, block_t *blk)
{
	struct dynamic_discard_map_control *ddmc = SM_I(sbi)->ddmc_info;
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	//struct list_head *head = &dcc->entry_list;
	struct list_head *head = &ddmc->discard_map_head;
	struct discard_entry *entry, *this;
	struct page *page = NULL;
	struct discard_journal_block *dst_dj_blk;
	struct discard_journal_block_info *dst_dj_blk_info;
	unsigned int didx = 0;
	block_t tmp_blkcnt = 0;
	/* write discard journal: bitmap-type */
	list_for_each_entry_safe(entry, this, head, list) {
		struct discard_journal_bitmap *dst_dj_map;
		if (!page) {
			page = f2fs_grab_meta_page(sbi, (*blk)++);
			dst_dj_blk = (struct discard_journal_block *)page_address(page);
			memset(dst_dj_blk, 0, sizeof(*dst_dj_blk));
			dst_dj_blk_info = &dst_dj_blk->dj_block_info;
			dst_dj_blk_info->type = (unsigned char) DJ_BLOCK_BITMAP;
			didx = 0;
			tmp_blkcnt++;
		}
		dst_dj_map = (struct discard_journal_bitmap *) &dst_dj_blk->bitmap_entries[didx++];
		dst_dj_map->start_blkaddr = cpu_to_le32(entry->start_blkaddr);
		//printk("[JW DBG] %s: cnt: %d, start_sector: %u, start_blkaddr%u\n", __func__, cnt, entry->start_blkaddr*8, entry->start_blkaddr);	
		memcpy(dst_dj_map->discard_map, entry->discard_map, DISCARD_BLOCK_MAP_SIZE);

		if (didx == DJ_BITMAP_ENTRIES_IN_DJ_BLOCK){
			dst_dj_blk_info->entry_cnt = cpu_to_le32(didx);
			set_page_dirty(page);
			f2fs_put_page(page, 1);
			didx = 0;
			page = NULL;
		}
		//release_discard_addr(entry);
	}
	if (didx > 0){
		dst_dj_blk_info->entry_cnt = cpu_to_le32(didx);
		set_page_dirty(page);
		f2fs_put_page(page, 1);
	}
	return tmp_blkcnt;
}

static void release_discard_range(struct discard_range_entry *entry)
{
	list_del(&entry->ddm_list);
	list_del(&entry->list);
	kmem_cache_free(discard_range_slab, entry);
}

/* Write every discard range journal to blk */
static block_t write_discard_range_journals(struct f2fs_sb_info *sbi, block_t *blk)
{
	struct dynamic_discard_map_control *ddmc = SM_I(sbi)->ddmc_info;
	struct list_head *dr_head = &ddmc->discard_range_head;
	struct list_head *issued_discard_head = &ddmc->issued_discard_head;
	struct discard_range_entry *entry, *this;
	struct page *page = NULL;
	struct discard_journal_block *dst_dj_blk;
	struct discard_journal_block_info *dst_dj_blk_info;
	unsigned int didx = 0;
	block_t tmp_blkcnt = 0;
	int i;

	/* write discard journal, which is not issued */
	list_for_each_entry_safe(entry, this, dr_head, list) {
		unsigned int dr_cnt_in_dre = entry->cnt;
		for (i = 0; i < dr_cnt_in_dre; i++){
			struct discard_range *dr;
			struct discard_journal_range *dst_dj_range;
			dr = (struct discard_range *) &entry->discard_range_array[i];

			if (!page) {
				page = f2fs_grab_meta_page(sbi, (*blk)++);
				dst_dj_blk = (struct discard_journal_block *)page_address(page);
				memset(dst_dj_blk, 0, sizeof(*dst_dj_blk));
				dst_dj_blk_info = &dst_dj_blk->dj_block_info;
				dst_dj_blk_info->type = (unsigned char) DJ_BLOCK_RANGE;
				didx = 0;
				tmp_blkcnt += 1;
			}
			dst_dj_range = (struct discard_journal_range *) &dst_dj_blk->range_entries[didx++];
			dst_dj_range->start_blkaddr = cpu_to_le32(dr->start_blkaddr);
			dst_dj_range->len = cpu_to_le32(dr->len);
			//printk("[JW DBG] %s: cnt: %d, start_sector: %u, start_blkaddr%u\n", __func__, cnt, entry->start_blkaddr*8, entry->start_blkaddr);	
	
			if (didx == DJ_RANGE_ENTRIES_IN_DJ_BLOCK){
				dst_dj_blk_info->entry_cnt = cpu_to_le32(didx);
				set_page_dirty(page);
				f2fs_put_page(page, 1);
				didx = 0;
				page = NULL;
			}
		}
		//release_discard_range(entry);
	}

	/* write pending discard journal, which is issued */
	list_for_each_entry_safe(entry, this, issued_discard_head, list) {
		unsigned int dr_cnt_in_dre = entry->cnt;
		for (i = 0; i < dr_cnt_in_dre; i++){
			struct discard_range *dr;
			struct discard_journal_range *dst_dj_range;
			dr = (struct discard_range *) &entry->discard_range_array[i];

			if (!page) {
				page = f2fs_grab_meta_page(sbi, (*blk)++);
				dst_dj_blk = (struct discard_journal_block *)page_address(page);
				memset(dst_dj_blk, 0, sizeof(*dst_dj_blk));
				dst_dj_blk_info = &dst_dj_blk->dj_block_info;
				dst_dj_blk_info->type = (unsigned char) DJ_BLOCK_RANGE;
				didx = 0;
				tmp_blkcnt += 1;
			}
			dst_dj_range = (struct discard_journal_range *) &dst_dj_blk->range_entries[didx++];
			dst_dj_range->start_blkaddr = cpu_to_le32(dr->start_blkaddr);
			dst_dj_range->len = cpu_to_le32(dr->len);
			//printk("[JW DBG] %s: cnt: %d, start_sector: %u, start_blkaddr%u\n", __func__, cnt, entry->start_blkaddr*8, entry->start_blkaddr);	
	
			if (didx == DJ_RANGE_ENTRIES_IN_DJ_BLOCK){
				dst_dj_blk_info->entry_cnt = cpu_to_le32(didx);
				set_page_dirty(page);
				f2fs_put_page(page, 1);
				didx = 0;
				page = NULL;
			}
		}
		//release_discard_range(entry);
	}

	if (didx > 0){
		dst_dj_blk_info->entry_cnt = cpu_to_le32(didx);
		set_page_dirty(page);
		f2fs_put_page(page, 1);
	}
	return tmp_blkcnt;
}


block_t f2fs_write_discard_journals(struct f2fs_sb_info *sbi, 
					block_t start_blk, block_t journal_limit_addr)
{
	struct dynamic_discard_map_control *ddmc = SM_I(sbi)->ddmc_info;
	unsigned int discard_bitmap_segcnt = (unsigned int) atomic_read(&ddmc->dj_seg_cnt);
	unsigned int discard_range_cnt = (unsigned int) atomic_read(&ddmc->dj_range_cnt);
	static int cnt = 0;
	block_t dblkcnt_check = (discard_bitmap_segcnt % DJ_BITMAP_ENTRIES_IN_DJ_BLOCK)? 
			discard_bitmap_segcnt / DJ_BITMAP_ENTRIES_IN_DJ_BLOCK + 1 : 
			discard_bitmap_segcnt / DJ_BITMAP_ENTRIES_IN_DJ_BLOCK;
	
	block_t total_dblkcnt, bitmap_dblkcnt, range_dblkcnt;
	bitmap_dblkcnt = DISCARD_JOURNAL_BITMAP_BLOCKS(discard_bitmap_segcnt);
	range_dblkcnt = DISCARD_JOURNAL_RANGE_BLOCKS(discard_range_cnt);
	total_dblkcnt = bitmap_dblkcnt + range_dblkcnt;
	//printk("[JW DBG] %s: total_djblk cnt: %d, djblk capacity: %d, map_djblk: %d, range_djblk: %d \n", __func__, total_dblkcnt, journal_limit_addr - start_blk , bitmap_dblkcnt, range_dblkcnt);

	cnt += 1; 
	if (start_blk + total_dblkcnt >= journal_limit_addr){
		//panic("[JW DBG] %s: discard seg exceeded cp pack capacity\n", __func__);
		printk("[JW DBG] %s: discard seg exceeded cp pack capacity\n", __func__);
		//atomic_set(&ddmc->dj_seg_cnt, 0);//reset blk_cnt to zero; blk_cnt is for debugging
		//atomic_set(&ddmc->dj_range_cnt, 0);
		return 0;
	}
		
	if (is_set_ckpt_flags(sbi, CP_COMPACT_SUM_FLAG))
		panic("[JW DBG] %s: must not be compact ckpt", __func__);
	
	block_t blk, tmp_dblkcnt;
        blk = start_blk;
	tmp_dblkcnt = 0;
	
	/* write discard journal: bitmap-type*/
	tmp_dblkcnt += write_discard_bitmap_journals(sbi, &blk);

	/* write discard journal: range-type*/
	tmp_dblkcnt += write_discard_range_journals(sbi, &blk);

	if (tmp_dblkcnt != total_dblkcnt)
		printk("[JW DBG] %s: total discard journal blk cnts not matching: real djblkcnt: %d, expected djblkcnt: %d", __func__, tmp_dblkcnt, total_dblkcnt);

	//printk("[JW DBG] %s: discard journal blk cnt: %u, real dblkcnt: %u, remaind entry cnt: %u\n", __func__, dblkcnt, tmp_dblkcnt, didx);	

	//atomic_set(&ddmc->dj_seg_cnt, 0);//reset blk_cnt to zero; blk_cnt is for debugging
	//atomic_set(&ddmc->dj_range_cnt, 0);//reset blk_cnt to zero; blk_cnt is for debugging

	return blk;
}

int f2fs_lookup_journal_in_cursum(struct f2fs_journal *journal, int type,
					unsigned int val, int alloc)
{
	int i;

	if (type == NAT_JOURNAL) {
		for (i = 0; i < nats_in_cursum(journal); i++) {
			if (le32_to_cpu(nid_in_journal(journal, i)) == val)
				return i;
		}
		if (alloc && __has_cursum_space(journal, 1, NAT_JOURNAL))
			return update_nats_in_cursum(journal, 1);
	} else if (type == SIT_JOURNAL) {
		for (i = 0; i < sits_in_cursum(journal); i++)
			if (le32_to_cpu(segno_in_journal(journal, i)) == val)
				return i;
		if (alloc && __has_cursum_space(journal, 1, SIT_JOURNAL))
			return update_sits_in_cursum(journal, 1);
	}
	return -1;
}

static struct page *get_current_sit_page(struct f2fs_sb_info *sbi,
					unsigned int segno)
{
	return f2fs_get_meta_page(sbi, current_sit_addr(sbi, segno));
}

static struct page *get_next_sit_page(struct f2fs_sb_info *sbi,
					unsigned int start)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct page *page;
	pgoff_t src_off, dst_off;

	src_off = current_sit_addr(sbi, start);
	dst_off = next_sit_addr(sbi, src_off);

	page = f2fs_grab_meta_page(sbi, dst_off);
	seg_info_to_sit_page(sbi, page, start);

	set_page_dirty(page);
	set_to_next_sit(sit_i, start);

	return page;
}

static struct sit_entry_set *grab_sit_entry_set(void)
{
	struct sit_entry_set *ses =
			f2fs_kmem_cache_alloc(sit_entry_set_slab, GFP_NOFS);

	ses->entry_cnt = 0;
	INIT_LIST_HEAD(&ses->set_list);
	return ses;
}

static void release_sit_entry_set(struct sit_entry_set *ses)
{
	list_del(&ses->set_list);
	kmem_cache_free(sit_entry_set_slab, ses);
}

static void adjust_sit_entry_set(struct sit_entry_set *ses,
						struct list_head *head)
{
	struct sit_entry_set *next = ses;

	if (list_is_last(&ses->set_list, head))
		return;

	list_for_each_entry_continue(next, head, set_list)
		if (ses->entry_cnt <= next->entry_cnt)
			break;

	list_move_tail(&ses->set_list, &next->set_list);
}

static void add_sit_entry(unsigned int segno, struct list_head *head)
{
	struct sit_entry_set *ses;
	unsigned int start_segno = START_SEGNO(segno);

	list_for_each_entry(ses, head, set_list) {
		if (ses->start_segno == start_segno) {
			ses->entry_cnt++;
			adjust_sit_entry_set(ses, head);
			return;
		}
	}

	ses = grab_sit_entry_set();

	ses->start_segno = start_segno;
	ses->entry_cnt++;
	list_add(&ses->set_list, head);
}

static void add_sits_in_set(struct f2fs_sb_info *sbi)
{
	struct f2fs_sm_info *sm_info = SM_I(sbi);
	struct list_head *set_list = &sm_info->sit_entry_set;
	unsigned long *bitmap = SIT_I(sbi)->dirty_sentries_bitmap;
	unsigned int segno;

	for_each_set_bit(segno, bitmap, MAIN_SEGS(sbi))
		add_sit_entry(segno, set_list);
}

static void remove_sits_in_journal(struct f2fs_sb_info *sbi)
{
	struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_COLD_DATA);
	struct f2fs_journal *journal = curseg->journal;
	int i;

	down_write(&curseg->journal_rwsem);
	for (i = 0; i < sits_in_cursum(journal); i++) {
		unsigned int segno;
		bool dirtied;

		segno = le32_to_cpu(segno_in_journal(journal, i));
		dirtied = __mark_sit_entry_dirty(sbi, segno);

		if (!dirtied)
			add_sit_entry(segno, &SM_I(sbi)->sit_entry_set);
	}
	update_sits_in_cursum(journal, -i);
	up_write(&curseg->journal_rwsem);
}


static void recover_info_from_ddm(struct f2fs_sb_info *sbi, unsigned long long ddmkey, 
		unsigned int ddm_offset, unsigned long long *p_segno, unsigned int *p_offset)
{
	unsigned int segs_per_ddm = SM_I(sbi)->ddmc_info->segs_per_node;
	unsigned int blocks_per_seg = sbi->blocks_per_seg;
	unsigned int start_segno = ddmkey * segs_per_ddm;
	unsigned int delta_segno = ddm_offset / blocks_per_seg ;
	*p_segno = start_segno + delta_segno;
	*p_offset = ddm_offset % blocks_per_seg;
}


static unsigned long *get_seg_dmap(struct f2fs_sb_info *sbi, unsigned int p_segno){
	unsigned long *cur_map;
	unsigned long *ckpt_map;
	unsigned long *dmap;
	struct seg_entry *se;
	int entries = SIT_VBLOCK_MAP_SIZE / sizeof(unsigned long);
	int i;

	se = get_seg_entry(sbi, p_segno);
	cur_map = (unsigned long *)se->cur_valid_map;
	ckpt_map = (unsigned long *)se->ckpt_valid_map;
	dmap = SIT_I(sbi)->tmp_map;

	for (i = 0; i < entries; i++)
		dmap[i] = (cur_map[i] ^ ckpt_map[i]) & ckpt_map[i];
	return dmap;
}

				
static void check_discarded_addr(block_t start_baddr, int offs, block_t target_addr){
	if (target_addr == start_baddr + offs)
		printk("[JW DBG] %s: target addr %u is discarded!!\n",__func__, target_addr);
}

static struct discard_range_entry *__create_discard_range_entry(void)
{
	struct discard_range_entry *dre;

	dre = f2fs_kmem_cache_alloc(discard_range_slab, GFP_NOFS);
	INIT_LIST_HEAD(&dre->list);
	INIT_LIST_HEAD(&dre->ddm_list);
	dre->cnt = 0;
	
	return dre;
}

static void update_discard_range_entry(struct discard_range_entry *dre, unsigned int target_idx, 
				block_t lstart, block_t len)
{
	struct discard_range *dr;
	dr = (struct discard_range *) &dre->discard_range_array[target_idx];
	dr->start_blkaddr = lstart;
	dr->len = len;
	dre->cnt += 1;
}

static void add_discard_range_journal(struct f2fs_sb_info *sbi, block_t lstart, block_t len, struct dynamic_discard_map *ddm)
{
	struct dynamic_discard_map_control *ddmc = SM_I(sbi)->ddmc_info;
	struct list_head *total_drange_head = &ddmc->discard_range_head;
	struct list_head *ddm_drange_list = &ddm->drange_journal_list;
	struct discard_range_entry *dre;
	unsigned int target_idx;

	if (list_empty(total_drange_head) && !list_empty(ddm_drange_list)){
		printk("[JW DBG] %s: total drange list is empty but ddms drange list not empty!!", __func__);
		return;
	}
	if (list_empty(ddm_drange_list) || 
		list_last_entry(ddm_drange_list, struct discard_range_entry, ddm_list)->cnt 
								== DISCARD_RANGE_MAX_NUM)
	{
		dre = __create_discard_range_entry();
		list_add_tail(&dre->list, total_drange_head);
		list_add_tail(&dre->ddm_list, ddm_drange_list);
	}
	dre = list_last_entry(ddm_drange_list, struct discard_range_entry, ddm_list);
	target_idx = dre->cnt;
	update_discard_range_entry(dre, target_idx, lstart, len);
	atomic_inc(&ddmc->dj_range_cnt);
}



static void remove_issued_discard_cmds(struct f2fs_sb_info *sbi)
{
	struct dynamic_discard_map_control *ddmc = SM_I(sbi)->ddmc_info;
	struct list_head *issued_cmd_head = &ddmc->issued_discard_head;

	/* remove ddm's discard range journal entry */
	struct discard_range_entry *dre, *tmpdre;
	list_for_each_entry_safe(dre, tmpdre, issued_cmd_head, list) {
		atomic_set(&ddmc->dj_range_cnt, atomic_read(&ddmc->dj_range_cnt) - dre->cnt);
		// since release_discard_range deletes ddm_list, 
		// which is not used for issued discad cmds list, 
		// release_discard_range is not used in this case. 
		list_del(&dre->list);
		kmem_cache_free(discard_range_slab, dre);
	}

	/* remove ddm's discard bitmap journal entry */
	if (!list_empty(issued_cmd_head))
		printk("[JW DBG] %s: issued_cmd_head list not empty!!", __func__);
}


static void journal_issued_discard_cmd(struct f2fs_sb_info *sbi, block_t lstart, block_t len)
{
	struct dynamic_discard_map_control *ddmc = SM_I(sbi)->ddmc_info;
	struct list_head *head = &ddmc->issued_discard_head;
	struct discard_range_entry *dre;
	unsigned int target_idx;

	if (list_empty(head) ||
		list_last_entry(head, struct discard_range_entry, list)->cnt 
								== DISCARD_RANGE_MAX_NUM)
	{
		dre = __create_discard_range_entry();
		list_add_tail(&dre->list, head);
	}
	dre = list_last_entry(head, struct discard_range_entry, list);
	target_idx = dre->cnt;
	update_discard_range_entry(dre, target_idx, lstart, len);
	atomic_inc(&ddmc->dj_range_cnt);
}

/* To save into discard journal, obtain previously issued but not yet submitted dicsard cmds */
static int journal_issued_discard_cmds(struct f2fs_sb_info *sbi)
{
	struct dynamic_discard_map_control *ddmc = SM_I(sbi)->ddmc_info;
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	struct list_head *pend_list;
	struct discard_cmd *dc, *tmp;
	int i, cmd_cnt;
	cmd_cnt = 0;
	
	struct list_head *issued_cmd_head = &ddmc->issued_discard_head;
	if (!list_empty(issued_cmd_head)){
		printk("[JW DBG] %s: not expected!!", __func__);
	}

	for (i = 0; i <= MAX_PLIST_NUM - 1; i++) {
		pend_list = &dcc->pend_list[i];

		mutex_lock(&dcc->cmd_lock);
		if (list_empty(pend_list))
			goto next;
		if (unlikely(dcc->rbtree_check))
			f2fs_bug_on(sbi, !f2fs_check_rb_tree_consistence(sbi,
							&dcc->root, false));
		list_for_each_entry_safe(dc, tmp, pend_list, list) {
			journal_issued_discard_cmd(sbi, dc->lstart, dc->len);
			cmd_cnt += 1;
		}
next:
		mutex_unlock(&dcc->cmd_lock);
	}
	return cmd_cnt;
}

static bool is_empty_ddm(struct f2fs_sb_info *sbi, struct dynamic_discard_map_control *ddmc,
					struct dynamic_discard_map *ddm)
{
        int max_blocks = sbi->blocks_per_seg * ddmc->segs_per_node;
	unsigned int start = 0, end = -1;
	unsigned long *ddmap = (unsigned long *)ddm->dc_map;

	start = __find_rev_next_bit(ddmap, max_blocks, end + 1);
        return start >= max_blocks;
}

static void remove_ddm_journals(struct f2fs_sb_info *sbi, struct dynamic_discard_map *ddm)
{
	struct list_head *drange_journal_head = &ddm->drange_journal_list;
	struct list_head *dmap_journal_head = &ddm->dmap_journal_list;
	struct dynamic_discard_map_control *ddmc = SM_I(sbi)->ddmc_info;

	/* remove ddm's discard range journal entry */
	struct discard_range_entry *dre, *tmpdre;
	list_for_each_entry_safe(dre, tmpdre, drange_journal_head, ddm_list) {
		atomic_set(&ddmc->dj_range_cnt, atomic_read(&ddmc->dj_range_cnt) - dre->cnt);
		release_discard_range(dre);
	}

	/* remove ddm's discard bitmap journal entry */
	struct discard_entry *de, *tmpde;
	list_for_each_entry_safe(de, tmpde, dmap_journal_head, ddm_list) {
		release_discard_addr(de);
		atomic_dec(&ddmc->dj_seg_cnt);
	}
	if (!list_empty(drange_journal_head))
		printk("[JW DBG] %s: drange_journal_head list not empty!!", __func__);
	if (!list_empty(dmap_journal_head))
		printk("[JW DBG] %s: dmap_journal_head list not empty!!", __func__);
}

static int flush_one_ddm(struct f2fs_sb_info *sbi, struct dynamic_discard_map_control *ddmc,
					struct dynamic_discard_map *ddm, int print_history,
					int small_nr_issued, bool issue_all)
{
        int max_blocks = sbi->blocks_per_seg * ddmc->segs_per_node;
	unsigned int start = 0, end = -1;
        struct discard_entry *de = NULL;
	unsigned long *ddmap = (unsigned long *)ddm->dc_map;
	unsigned long long ddmkey = ddm->key, tmp_ddmkey;
	unsigned long long start_segno, end_segno; 
	unsigned int start_offset, end_offset;
        //struct list_head *head = &SM_I(sbi)->dcc_info->entry_list;
	struct list_head *head = &ddmc->discard_map_head;
	struct list_head *ddm_dmap_list = &ddm->dmap_journal_list;
	int i;
        bool first = true;
	unsigned int last_target_segno;
	unsigned int p_segno;
	unsigned int start_in_seg, end_in_seg;
	unsigned int offset_in_ddm;
	unsigned static int cnt_list[128];
	int nr_issued = 0;
	bool small_force = (small_nr_issued > 0);
	static int rmv_by_small_discard = 0;
	if (print_history){
		for (i = 0; i < 128; i ++){
			cnt_list[i] = 0;
		}
	}
	/*
	if (!list_empty(&ddm->drange_journal_list))
		printk("[JW DBG] %s: ddm's drange list must be empty!!", __func__);
	if (!list_empty(&ddm->dmap_journal_list))
		printk("[JW DBG] %s: ddm's dmap list must be empty!!", __func__);
	*/
	//unsigned int segcnt = 0;
	//int localcnt = 0;
        if (!f2fs_hw_support_discard(sbi)){
		panic("Why HW not support discard!!");
                return -1;
        }
        if (!f2fs_realtime_discard_enable(sbi)){
                panic("Why discard not accepted?");
                return -1;
        }
	while(1){
                start = __find_rev_next_bit(ddmap, max_blocks, end + 1);
                if (start >= max_blocks)
                        break;

                end = __find_rev_next_zero_bit(ddmap, max_blocks, start + 1);
		
		recover_info_from_ddm(sbi, ddmkey, start, &start_segno, &start_offset);
		recover_info_from_ddm(sbi, ddmkey, end-1, &end_segno, &end_offset);
		
		/*set bitmap for each segment*/
		unsigned int startLBA, endLBA, len;
		startLBA = START_BLOCK(sbi, start_segno) + start_offset;
		endLBA = START_BLOCK(sbi, end_segno) + end_offset;
		len = endLBA - startLBA + 1;
		
		if (print_history){
			if (len > 1024)
				cnt_list[127] += 1;
			else if (len > 0)
				cnt_list[(len-1)/8] += 1;
			else if (len <= 0)
				printk("[JW DBG] %s: weird! len must be positive", __func__);
			continue;
		}
		/* issue discard cmd to discard thread */
		if (!print_history && !small_force){
			/* Use discard range journal to reduce number of discard bitmap journal*/
			if (len > 64){
				//journal_discard_cmd(sbi, startLBA, len);
				add_discard_range_journal(sbi, startLBA, len, ddm);
				/* issue every long discard cmd */
				if (len > 512 || issue_all){
					for (i = start; i < end; i ++){
						if (!f2fs_test_and_clear_bit(i, ddm->dc_map))
							panic("[JW DBG] %s: weird. must be one but zero bit. offset: %d, segno: %d, ddmkey: %d", __func__, i, p_segno, ddmkey );
	
					}
					
					f2fs_issue_discard(sbi, startLBA, len);
					nr_issued += 1;
				}
				continue;
			}
			else if (issue_all){
				/* issue but dj_bitmap format*/
				for (i = start; i < end; i ++){
					if (!f2fs_test_and_clear_bit(i, ddm->dc_map))
						panic("[JW DBG] %s: weird. must be one but zero bit. offset: %d, segno: %d, ddmkey: %d", __func__, i, p_segno, ddmkey );
				}
				f2fs_issue_discard(sbi, startLBA, len);
				nr_issued += 1;
			}
		} else if (small_force){
			/* issue small discard in ascending order. */
			/* This helps to reduce dynamic discard map node having small discards. */
			//if (small_nr_issued - nr_issued > 0){
			for (i = start; i < end; i ++){
				if (!f2fs_test_and_clear_bit(i, ddm->dc_map))
					panic("[JW DBG] %s: weird. must be one but zero bit. offset: %d, segno: %d, ddmkey: %d", __func__, i, p_segno, ddmkey );

			}
			f2fs_issue_discard(sbi, startLBA, len);
			nr_issued += 1;
			continue;
			//} else {
			//	return nr_issued;
			//}
		}

		start_in_seg = start_offset;
		for (p_segno = start_segno; p_segno <= end_segno; p_segno++){
			int dcmd_created = 0;

			if (end_segno - p_segno){
				end_in_seg = sbi->blocks_per_seg-1;
			} else {
				end_in_seg = end_offset;
			}

			if (first || last_target_segno != p_segno){
				dcmd_created = 1;
         			de = f2fs_kmem_cache_alloc(discard_entry_slab,
                                                 GFP_F2FS_ZERO);
        			de->start_blkaddr = START_BLOCK(sbi, p_segno);
         			list_add_tail(&de->list, head);
				list_add_tail(&de->ddm_list, ddm_dmap_list);
				atomic_inc(&ddmc->dj_seg_cnt);
				
			}
                	for (i = start_in_seg; i <= end_in_seg; i++){
                		__set_bit_le(i, (void *)de->discard_map);
			}
			
			last_target_segno = p_segno;
			start_in_seg = 0;

		}
		first = false;
        }

	if (print_history){
		for (i = 0; i < 128; i ++){
			if (cnt_list[i] > 0)
				printk("[JW DBG] %s: ddmkey: %u len: %u ~ %u: count: %u ", __func__, ddmkey, 8*i+1, 8*i+8, cnt_list[i]);
		}
		return 0;
	}

	if (small_force){
		rmv_by_small_discard += 1;
		
		if (!is_empty_ddm(sbi, ddmc, ddm))
			printk("[JW DBG] %s: 1: not empty ddm!!, must not be removed!\n", __func__, rmv_by_small_discard);

		remove_ddm_journals(sbi, ddm);
		__remove_dynamic_discard_map(sbi, ddm);
	}
	else if (!small_force){
		if (is_empty_ddm(sbi, ddmc, ddm)){
			__remove_dynamic_discard_map(sbi, ddm);
		}
	}
	else if(issue_all){
		if (!is_empty_ddm(sbi, ddmc, ddm))
			printk("[JW DBG] %s: 3: not empty ddm!!, must not be removed!\n", __func__, rmv_by_small_discard);
        	__remove_dynamic_discard_map(sbi, ddm);
	}

        return nr_issued;
}



//Notice!! This function always frees DDM. This can cause problem when number of blocks to be discarded is more than max_discards. The while loop stops when numblks to be discarded exceeds max_disacrds. This means DDM is freed while some of blks are not disacrded. This can cause orphan blocks. So this must be fixed. 
static int construct_ddm_journals(struct f2fs_sb_info *sbi, struct dynamic_discard_map *ddm)
{
	struct dynamic_discard_map_control *ddmc = SM_I(sbi)->ddmc_info;
        int max_blocks = sbi->blocks_per_seg * ddmc->segs_per_node;
	unsigned int start = 0, end = -1;
        struct discard_entry *de = NULL;
	unsigned long *ddmap = (unsigned long *)ddm->dc_map;
	unsigned long long ddmkey = ddm->key, tmp_ddmkey;
	unsigned long long start_segno, end_segno; 
	unsigned int start_offset, end_offset;
        //struct list_head *head = &SM_I(sbi)->dcc_info->entry_list;
	struct list_head *head = &ddmc->discard_map_head;
	struct list_head *ddm_dmap_list = &ddm->dmap_journal_list;
	int i;
        bool first = true;
	unsigned int last_target_segno;
	unsigned int p_segno;
	unsigned int start_in_seg, end_in_seg;
	unsigned int offset_in_ddm;
	int nr_issued = 0;
	
	if (!list_empty(&ddm->drange_journal_list))
		printk("[JW DBG] %s: ddm's drange list must be empty!!", __func__);
	if (!list_empty(&ddm->dmap_journal_list))
		printk("[JW DBG] %s: ddm's dmap list must be empty!!", __func__);
	//unsigned int segcnt = 0;
	//int localcnt = 0;
        if (!f2fs_hw_support_discard(sbi)){
		panic("Why HW not support discard!!");
                return -1;
        }
        if (!f2fs_realtime_discard_enable(sbi)){
                panic("Why discard not accepted?");
                return -1;
        }
	while(1){
                start = __find_rev_next_bit(ddmap, max_blocks, end + 1);
                if (start >= max_blocks)
                        break;

                end = __find_rev_next_zero_bit(ddmap, max_blocks, start + 1);
		
		recover_info_from_ddm(sbi, ddmkey, start, &start_segno, &start_offset);
		recover_info_from_ddm(sbi, ddmkey, end-1, &end_segno, &end_offset);
		
		/*set bitmap for each segment*/
		unsigned int startLBA, endLBA, len;
		startLBA = START_BLOCK(sbi, start_segno) + start_offset;
		endLBA = START_BLOCK(sbi, end_segno) + end_offset;
		len = endLBA - startLBA + 1;
		
		/* issue discard cmd to discard thread */
		/* Use discard range journal to reduce number of discard bitmap journal*/
		if (len > 64){
			/* issue every long discard cmd */
			/* Do not journal long discard cuz it is journalized when journaling pend_list */
			if (len > 512){
				for (i = start; i < end; i ++){
					if (!f2fs_test_and_clear_bit(i, ddm->dc_map))
						panic("[JW DBG] %s: weird. must be one but zero bit. offset: %d, segno: %d, ddmkey: %d", __func__, i, p_segno, ddmkey );
	
				}
				
				f2fs_issue_discard(sbi, startLBA, len);
				nr_issued += 1;
			}
			else{
				//journal_discard_cmd(sbi, startLBA, len);
				add_discard_range_journal(sbi, startLBA, len, ddm);
			}
			continue;
		}

		start_in_seg = start_offset;
		for (p_segno = start_segno; p_segno <= end_segno; p_segno++){
			int dcmd_created = 0;

			if (end_segno - p_segno){
				end_in_seg = sbi->blocks_per_seg-1;
			} else {
				end_in_seg = end_offset;
			}

			if (first || last_target_segno != p_segno){
				dcmd_created = 1;
         			de = f2fs_kmem_cache_alloc(discard_entry_slab,
                                                 GFP_F2FS_ZERO);
        			de->start_blkaddr = START_BLOCK(sbi, p_segno);
         			list_add_tail(&de->list, head);
				list_add_tail(&de->ddm_list, ddm_dmap_list);
				atomic_inc(&ddmc->dj_seg_cnt);
				
			}
                	for (i = start_in_seg; i <= end_in_seg; i++){
                		__set_bit_le(i, (void *)de->discard_map);
			}
			
			last_target_segno = p_segno;
			start_in_seg = 0;

		}
		first = false;
        }


        return nr_issued;
}


static void issue_all_discard_journals(struct f2fs_sb_info *sbi)
{
	struct dynamic_discard_map_control *ddmc = SM_I(sbi)->ddmc_info;
	struct list_head *total_dre_list = &ddmc->discard_range_head;
	struct list_head *total_dmap_list = &ddmc->discard_map_head;
	int i;

	struct discard_range_entry *dre, *tmpdre;
	list_for_each_entry_safe(dre, tmpdre, total_dre_list, list) {
		for (i = 0; i < dre->cnt; i++){
			struct discard_range *dr;
			dr = (struct discard_range *) &dre->discard_range_array[i];
			f2fs_issue_discard(sbi, dr->start_blkaddr, dr->len);
		}
		release_discard_range(dre);
	}

	struct discard_entry *de, *tmpde;
	list_for_each_entry_safe(de, tmpde, total_dmap_list, list) {
		unsigned int cur_pos = 0, next_pos, len, total_len = 0;
		bool is_valid = test_bit_le(0, de->discard_map);
find_next:
		if (is_valid) {
			next_pos = find_next_zero_bit_le(de->discard_map,
					sbi->blocks_per_seg, cur_pos);
			len = next_pos - cur_pos;

			f2fs_issue_discard(sbi, de->start_blkaddr + cur_pos,
									len);
			total_len += len;
		} else {
			next_pos = find_next_bit_le(de->discard_map,
					sbi->blocks_per_seg, cur_pos);
		}
skip:
		cur_pos = next_pos;
		is_valid = !is_valid;

		if (cur_pos < sbi->blocks_per_seg)
			goto find_next;

		release_discard_addr(de);
	}
}

static int update_dirty_dynamic_discard_map(struct f2fs_sb_info *sbi)
{
	struct dynamic_discard_map_control *ddmc = SM_I(sbi)->ddmc_info;
	struct list_head *dirty_head = &ddmc->dirty_head;
	struct dynamic_discard_map *ddm, *tmpddm;
	int nr_issued = 0;
	int len = 0;
	/*
	list_for_each_entry_safe(ddm, tmpddm, dirty_head, dirty_list) {
		len += 1;	
		printk("[JW DBG] %s: 4", __func__);
		list_del(&ddm->dirty_list);
		printk("[JW DBG] %s: 5", __func__);
	}
	printk("[JW DBG] %s: dirty list length %u", __func__, len);
	*/
	list_for_each_entry_safe(ddm, tmpddm, dirty_head, dirty_list) {
		atomic_set(&ddm->is_dirty, 0);
		//printk("[JW DBG] %s: start removing dj of ddm %u", __func__, ddm->key);
		remove_ddm_journals(sbi, ddm);
		//printk("[JW DBG] %s: 2", __func__);
		//printk("[JW DBG] %s: start construction dj of ddm %u", __func__, ddm->key);
                nr_issued += construct_ddm_journals(sbi, ddm);
		//printk("[JW DBG] %s: del dirty list of ddm %u", __func__, ddm->key);
		list_del(&ddm->dirty_list);
		//printk("[JW DBG] %s: ddm %u handling done", __func__, ddm->key);
		if (is_empty_ddm(sbi, ddmc, ddm)){
			if (!list_empty(&ddm->drange_journal_list)){
				printk("[JW DBG] %s: ddm's drange list isn't empty, impossible to remove ddm!!", __func__);
			}else if (!list_empty(&ddm->dmap_journal_list)){
				printk("[JW DBG] %s: ddm's dmap list isn't empty, impossible to remove ddm!!", __func__);
			}else{
				//printk("[JW DBG] %s: ddm %u removed!!!", __func__, ddm->key);
				__remove_dynamic_discard_map(sbi, ddm);
			}
		}
	}

	
	//list_for_each_entry_safe(ddm, tmpddm, dirty_head, dirty_list) {
	//	printk("[JW DBG] %s: 4", __func__);
	//	list_del(&ddm->dirty_list);
	//	printk("[JW DBG] %s: 5", __func__);

	//}
	if (!list_empty(dirty_head))
		printk("[JW DBG] %s:  dirty list not empty!!", __func__);
		

	return nr_issued;
}
void flush_dynamic_discard_maps(struct f2fs_sb_info *sbi, struct cp_control *cpc)
{
	struct dynamic_discard_map_control *ddmc = SM_I(sbi)->ddmc_info;
	struct dynamic_discard_map *ddm, *tmpddm;
	struct list_head *history_head_ddm = &ddmc->history_head;
	struct list_head *p;
	bool force = (cpc->reason & CP_DISCARD);
	bool issue_all = (cpc->reason & CP_UMOUNT);
	int lpcnt = 0;
        struct list_head *head = &SM_I(sbi)->dcc_info->entry_list;
	int tmp, nr_discard, nr_issued = 0, cur_dcmd_cnt;
	struct discard_cmd_control *dcc = SM_I(sbi)->dcc_info;
	static int callcnt = 0, discard_limit = 0;
	static int prev_dcmd_cnt = 0;
	static int small_dcmd_cnt = 0;
	callcnt += 1;
	
	//printk("[JW DBG] %s: start!", __func__);
	/* check submitted discard cmd and advise how many small discard will be submitted */
	cur_dcmd_cnt = (int) atomic_read(&dcc->discard_cmd_cnt );
	nr_discard = prev_dcmd_cnt - cur_dcmd_cnt;
	//printk("[JW DBG] %s: umount: bef discard cmd count: %d submitted_discard: %d , \n", __func__, cur_dcmd_cnt, nr_discard);
	if (nr_discard == 0 && prev_dcmd_cnt > 0){
		printk("[JW DBG] %s: someting wrong. discard got stuck!!, dcmd cnt: %d \n", __func__, prev_dcmd_cnt);
	}
	if (cur_dcmd_cnt == 0){
		discard_limit = discard_limit *6/5 + 5;
	} else{
		discard_limit = nr_discard - cur_dcmd_cnt;
		if (discard_limit < 0)
			discard_limit = 0;
	}

	/*
	atomic_set(&ddmc->history_seg_cnt, 0);
	int dj_seg_cnt = atomic_read(&ddmc->dj_seg_cnt);
	int dj_range_cnt = atomic_read(&ddmc->dj_range_cnt);
	if (atomic_read(&ddmc->dj_seg_cnt) != 0 || atomic_read(&ddmc->dj_range_cnt) != 0)
		panic("[JW DBG] %s: must be zero. dj_seg_cnt: %d, dj_range_cnt: %d!\n", __func__, dj_seg_cnt, dj_range_cnt);
	if (!list_empty(head))
		printk("[JW DBG] %s: dcc entry list not initialized!! \n", __func__);
	*/

	/* large discard */
	//printk("[JW DBG] %s: 1", __func__);
	nr_issued += update_dirty_dynamic_discard_map(sbi);
	//printk("[JW DBG] %s: 1-1 ", __func__);
	
	/*list_for_each_entry_safe(ddm, tmpddm, history_head_ddm, history_list) {
		if (force){
			panic("flush_dynamic_discard_maps: not expected!!");
        		__remove_dynamic_discard_map(sbi, ddm);
		} else {
                	nr_issued += flush_one_ddm(sbi, ddmc, ddm, 0, 0, issue_all);
		}
	}*/

	/* UNMOUNT case */	
	if (issue_all){
		/* for umount, issue all discard journals, because the journals have every discard blocks information*/
		remove_issued_discard_cmds(sbi);
		journal_issued_discard_cmds(sbi);
		goto finish;
	}

	/* small discard */
	list_for_each_entry_safe(ddm, tmpddm, history_head_ddm, history_list) {
		if (discard_limit - nr_issued > 0){
			//printk("[JW DBG] %s 2", __func__);
                	tmp = flush_one_ddm(sbi, ddmc, ddm, 0, discard_limit - nr_issued, 0);
			//printk("[JW DBG] %s 2-1", __func__);
			nr_issued += tmp;
			small_dcmd_cnt += tmp;
			//if (callcnt % 30 == 0)
				//printk("[JW DBG] %s: small discard occurs: %d !!\n", __func__, small_dcmd_cnt);
		} else {
			break;
		}
	}
	
	/* Journal pending discard cmds */
	//printk("[JW DBG] %s 3", __func__);
	remove_issued_discard_cmds(sbi);
	//printk("[JW DBG] %s 3-1", __func__);
	
	/* To save into discard journal, obtain issued but not completed dicsard cmds*/
	//printk("[JW DBG] %s 4", __func__);
	journal_issued_discard_cmds(sbi);
	//printk("[JW DBG] %s 4-1", __func__);
	
	/*if (callcnt % 60 == 0){
		list_for_each_entry_safe(ddm, tmpddm, history_head_ddm, history_list) {
			//p = history_head_ddm->next;
			//list_del(p);
			//ddm = dynamic_discard_map(p, struct dynamic_discard_map, list);
	                //printk("flush_dynamic_discard_maps: DDM node_cnt: %d\n", ddmc->node_cnt);
			if (force){
				panic("flush_dynamic_discard_maps: not expected!!");
	        		__remove_dynamic_discard_map(sbi, ddm);
			} else {
	                	flush_one_ddm(sbi, ddmc, ddm, callcnt % 60 == 0 , 0);
			}
			//lpcnt += 1;
		}
	}*/
	//printk("[JW DBG] history end");
finish:
	tmp = (int) atomic_read(&dcc->discard_cmd_cnt );
	int tmp2 = (int) atomic_read(&ddmc->node_cnt);
	prev_dcmd_cnt = tmp;
	//printk("[JW DBG] %s end!!", __func__);
	//printk("[JW DBG] %s: aft discard cmd count: %d in rbtree, discard seg cnt: %d , ddm node cnt: %d \n", __func__, tmp, ddmc->dj_seg_cnt, tmp2);
	//atomic_set(&ddmc->history_seg_cnt, 0);

}

static unsigned long *get_one_seg_bitmap_from_extended_ddm(struct f2fs_sb_info *sbi, 
							struct dynamic_discard_map *ddm, 
							unsigned long long ddmkey, 
							unsigned long long segno)
{
        int entries = SIT_VBLOCK_MAP_SIZE / sizeof(unsigned long);
	unsigned int segs_per_ddm = SM_I(sbi)->ddmc_info->segs_per_node;
        unsigned int start_segno = ddmkey * segs_per_ddm;
        unsigned int delta_segno = segno - start_segno;
	unsigned long *dc_map = (unsigned long *) ddm->dc_map;

	dc_map += entries * delta_segno;
	
	return dc_map;


}


static unsigned long *get_ddmap_from_extended_ddm_hash(struct f2fs_sb_info *sbi, 
							unsigned long long segno)
{
	struct dynamic_discard_map *ddm;
	unsigned long long ex_ddmkey, recovered_segno;
	unsigned int ex_ddm_offset, recovered_offset;
	unsigned long *dc_map;
	unsigned int height;
	
	/*get extended ddm from segno*/
	get_ddm_info(sbi, segno, 0, &ex_ddmkey, &ex_ddm_offset);
        ddm = f2fs_lookup_hash(sbi, ex_ddmkey, &height);
	if (ddm == NULL)
		return NULL;
	
	/*recovery check*/
	recover_info_from_ddm(sbi, ex_ddmkey, ex_ddm_offset, &recovered_segno, &recovered_offset);
	if (recovered_segno != segno || recovered_offset != 0){
		panic("get_ddmap_from_extended_ddm_hash: recover failed! ex vs recov : key %lld != %lld or offset %d != %d", ex_ddmkey, recovered_segno, ex_ddm_offset, recovered_offset);
	}
	dc_map = get_one_seg_bitmap_from_extended_ddm(sbi, ddm, ex_ddmkey, segno);
	return dc_map;

}



static unsigned long *get_ddmap_from_extended_ddm_rb(struct f2fs_sb_info *sbi, 
							unsigned long long segno)
{
	struct dynamic_discard_map_control *ddmc = SM_I(sbi)->ddmc_info;
	struct rb_node **p, *parent = NULL;
	struct rb_entry *re;
	bool leftmost, exist;
	struct dynamic_discard_map *ddm;
	int height=0;
	unsigned long long ex_ddmkey, recovered_segno;
	unsigned int ex_ddm_offset, recovered_offset;
	unsigned long *dc_map;
	/*get extended ddm from segno*/
	get_ddm_info(sbi, segno, 0, &ex_ddmkey, &ex_ddm_offset);
        p = f2fs_lookup_pos_rb_tree_ext(sbi, &ddmc->root, &parent, ex_ddmkey, &leftmost, &height, &exist);
	if (!exist){
		return NULL;
	}
	printk("%d", height);
	re = rb_entry_safe(*p, struct rb_entry, rb_node);
        ddm = dynamic_discard_map(re, struct dynamic_discard_map, rbe);
	
	/*recovery check*/
	recover_info_from_ddm(sbi, ex_ddmkey, ex_ddm_offset, &recovered_segno, &recovered_offset);
	if (recovered_segno != segno || recovered_offset != 0){
		panic("get_ddmap_from_extended_ddm_rb: recover failed! ex vs recov : key %lld != %lld or offset %d != %d", ex_ddmkey, recovered_segno, ex_ddm_offset, recovered_offset);
	}
	dc_map = get_one_seg_bitmap_from_extended_ddm(sbi, ddm, ex_ddmkey, segno);
	return dc_map;

}


static bool check_ddm_sanity(struct f2fs_sb_info *sbi, struct cp_control *cpc)
{
	int entries = SIT_VBLOCK_MAP_SIZE / sizeof(unsigned long);
	int max_blocks = sbi->blocks_per_seg;
	unsigned long long segno = (unsigned long long) cpc->trim_start;
	struct seg_entry *se = get_seg_entry(sbi, cpc->trim_start);
	unsigned long *cur_map = (unsigned long *)se->cur_valid_map;
	unsigned long *ckpt_map = (unsigned long *)se->ckpt_valid_map;
	unsigned long *discard_map = (unsigned long *)se->discard_map;
	unsigned long *dmap = SIT_I(sbi)->tmp_map;

	unsigned int start = 0, end = -1, start_ddm = 0, end_ddm = -1;
	bool force = (cpc->reason & CP_DISCARD);
	int i;
	unsigned long *ddmap;
	bool ori_blk_exst = true;

	if (force)
		panic("FITRIM occurs!!!\n");


	if (se->valid_blocks == max_blocks || !f2fs_hw_support_discard(sbi)){
		return false;
	} 
	if (!force) {
		if (!f2fs_realtime_discard_enable(sbi) || !se->valid_blocks ||
			SM_I(sbi)->dcc_info->nr_discards >=
				SM_I(sbi)->dcc_info->max_discards){
			
			return false;
		}
	}

	
	/* SIT_VBLOCK_MAP_SIZE should be multiple of sizeof(unsigned long) */
	for (i = 0; i < entries; i++)
		dmap[i] = force ? ~ckpt_map[i] & ~discard_map[i] :
				(cur_map[i] ^ ckpt_map[i]) & ckpt_map[i];
	
	start = __find_rev_next_bit(dmap, max_blocks, end+1);
	if (start >= max_blocks)
		ori_blk_exst = false;

	ddmap = get_ddmap_from_extended_ddm_hash(sbi, segno);
	if (ddmap == NULL){
		if (ori_blk_exst){
			panic("check_ddm_sanity: no ddmap but ori_blk_exst");
		}
		return false;
	}
	
	/* check existence of discarded block in original version dmap*/
	while (SM_I(sbi)->dcc_info->nr_discards <=
				SM_I(sbi)->dcc_info->max_discards) {
		start = __find_rev_next_bit(dmap, max_blocks, end + 1);
		if (start >= max_blocks)
			break;
		start_ddm = __find_rev_next_bit(ddmap, max_blocks, end_ddm + 1);

		end = __find_rev_next_zero_bit(dmap, max_blocks, start + 1);
		end_ddm = __find_rev_next_zero_bit(ddmap, max_blocks, start_ddm +1);

		if (start != start_ddm || end != end_ddm)
			panic("start end not match in add_discard_addrs");
			//f2fs_bug_on(sbi, start != start_ddm || end != end_ddm);

	}
	return false;
}



/*
 * CP calls this function, which flushes SIT entries including sit_journal,
 * and moves prefree segs to free segs.
 */
void f2fs_flush_sit_entries(struct f2fs_sb_info *sbi, struct cp_control *cpc)
{
	struct sit_info *sit_i = SIT_I(sbi);
	unsigned long *bitmap = sit_i->dirty_sentries_bitmap;
	struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_COLD_DATA);
	//struct f2fs_journal *journal = curseg->journal;
	struct sit_entry_set *ses, *tmp;
	struct list_head *head = &SM_I(sbi)->sit_entry_set;
	bool to_journal = !is_sbi_flag_set(sbi, SBI_IS_RESIZEFS);
	struct seg_entry *se;

	down_write(&sit_i->sentry_lock);

	if (!sit_i->dirty_sentries)
		goto out;

	/*
	 * add and account sit entries of dirty bitmap in sit entry
	 * set temporarily
	 */
	//add_sits_in_set(sbi);

	/*
	 * if there are no enough space in journal to store dirty sit
	 * entries, remove all entries from journal and add and account
	 * them in sit entry set.
	 */
	/*if (!__has_cursum_space(journal, sit_i->dirty_sentries, SIT_JOURNAL) ||
								!to_journal)
		remove_sits_in_journal(sbi);
	*/
	/*
	 * there are two steps to flush sit entries:
	 * #1, flush sit entries to journal in current cold data summary block.
	 * #2, flush sit entries to sit page.
	 */
	/*
	list_for_each_entry_safe(ses, tmp, head, set_list) {
		struct page *page = NULL;
		struct f2fs_sit_block *raw_sit = NULL;
		unsigned int start_segno = ses->start_segno;
		unsigned int end = min(start_segno + SIT_ENTRY_PER_BLOCK,
						(unsigned long)MAIN_SEGS(sbi));
		unsigned int segno = start_segno;

		if (to_journal &&
			!__has_cursum_space(journal, ses->entry_cnt, SIT_JOURNAL))
			to_journal = false;

		if (to_journal) {
			down_write(&curseg->journal_rwsem);
		} else {
			page = get_next_sit_page(sbi, start_segno);
			raw_sit = page_address(page);
		}

		// flush dirty sit entries in region of current sit set 
		for_each_set_bit_from(segno, bitmap, end) {
			int offset, sit_offset;

			se = get_seg_entry(sbi, segno);
#ifdef CONFIG_F2FS_CHECK_FS
			if (memcmp(se->cur_valid_map, se->cur_valid_map_mir,
						SIT_VBLOCK_MAP_SIZE))
				f2fs_bug_on(sbi, 1);
#endif

			if (to_journal) {
				offset = f2fs_lookup_journal_in_cursum(journal,
							SIT_JOURNAL, segno, 1);
				f2fs_bug_on(sbi, offset < 0);
				segno_in_journal(journal, offset) =
							cpu_to_le32(segno);
				seg_info_to_raw_sit(se,
					&sit_in_journal(journal, offset));
				check_block_count(sbi, segno,
					&sit_in_journal(journal, offset));
			} else {
				//sit_offset = SIT_ENTRY_OFFSET(sit_i, segno);
				//seg_info_to_raw_sit(se,
				//		&raw_sit->entries[sit_offset]);
				//check_block_count(sbi, segno,
				//		&raw_sit->entries[sit_offset]);
			}

			__clear_bit(segno, bitmap);
			sit_i->dirty_sentries--;
			ses->entry_cnt--;
		}

		if (to_journal)
			up_write(&curseg->journal_rwsem);
		else
			f2fs_put_page(page, 1);

		f2fs_bug_on(sbi, ses->entry_cnt);
		release_sit_entry_set(ses);
	}

	f2fs_bug_on(sbi, !list_empty(head));
	f2fs_bug_on(sbi, sit_i->dirty_sentries);
	*/
out:
	if (cpc->reason & CP_DISCARD) {
		panic("f2fs_flush_sit_entries: didn't expect CP_DISCARD\n");
		__u64 trim_start = cpc->trim_start;

		for (; cpc->trim_start <= cpc->trim_end; cpc->trim_start++){
			add_discard_addrs(sbi, cpc, false);
		}

		cpc->trim_start = trim_start;
	}
	//mutex_lock(&SM_I(sbi)->ddmc_info->ddm_lock);	
	//flush_dynamic_discard_maps(sbi, cpc);
	//mutex_unlock(&SM_I(sbi)->ddmc_info->ddm_lock);	

	up_write(&sit_i->sentry_lock);

	//set_prefree_as_free_segments(sbi);
}

static int build_sit_info(struct f2fs_sb_info *sbi)
{
	struct f2fs_super_block *raw_super = F2FS_RAW_SUPER(sbi);
	struct sit_info *sit_i;
	unsigned int sit_segs, start;
	char *src_bitmap, *bitmap;
	unsigned int bitmap_size, main_bitmap_size, sit_bitmap_size;

	/* allocate memory for SIT information */
	sit_i = f2fs_kzalloc(sbi, sizeof(struct sit_info), GFP_KERNEL);
	if (!sit_i)
		return -ENOMEM;

	SM_I(sbi)->sit_info = sit_i;

	sit_i->sentries =
		f2fs_kvzalloc(sbi, array_size(sizeof(struct seg_entry),
					      MAIN_SEGS(sbi)),
			      GFP_KERNEL);
	if (!sit_i->sentries)
		return -ENOMEM;

	main_bitmap_size = f2fs_bitmap_size(MAIN_SEGS(sbi));
	//sit_i->dirty_sentries_bitmap = f2fs_kvzalloc(sbi, main_bitmap_size,
	//							GFP_KERNEL);
	//if (!sit_i->dirty_sentries_bitmap)
	//	return -ENOMEM;

#ifdef CONFIG_F2FS_CHECK_FS
	bitmap_size = MAIN_SEGS(sbi) * SIT_VBLOCK_MAP_SIZE * 4;
#else
	bitmap_size = MAIN_SEGS(sbi) * SIT_VBLOCK_MAP_SIZE * 3;
#endif
	sit_i->bitmap = f2fs_kvzalloc(sbi, bitmap_size, GFP_KERNEL);
	if (!sit_i->bitmap)
		return -ENOMEM;

	bitmap = sit_i->bitmap;

	for (start = 0; start < MAIN_SEGS(sbi); start++) {
		sit_i->sentries[start].cur_valid_map = bitmap;
		bitmap += SIT_VBLOCK_MAP_SIZE;

		sit_i->sentries[start].ckpt_valid_map = bitmap;
		bitmap += SIT_VBLOCK_MAP_SIZE;

#ifdef CONFIG_F2FS_CHECK_FS
		sit_i->sentries[start].cur_valid_map_mir = bitmap;
		bitmap += SIT_VBLOCK_MAP_SIZE;
#endif

		sit_i->sentries[start].discard_map = bitmap;
		bitmap += SIT_VBLOCK_MAP_SIZE;
	}

	sit_i->tmp_map = f2fs_kzalloc(sbi, SIT_VBLOCK_MAP_SIZE, GFP_KERNEL);
	if (!sit_i->tmp_map)
		return -ENOMEM;

	if (__is_large_section(sbi)) {
		sit_i->sec_entries =
			f2fs_kvzalloc(sbi, array_size(sizeof(struct sec_entry),
						      MAIN_SECS(sbi)),
				      GFP_KERNEL);
		if (!sit_i->sec_entries)
			return -ENOMEM;
	}

	/* get information related with SIT */
	sit_segs = le32_to_cpu(raw_super->segment_count_sit) >> 1;

	/* setup SIT bitmap from ckeckpoint pack */
	sit_bitmap_size = __bitmap_size(sbi, SIT_BITMAP);
	src_bitmap = __bitmap_ptr(sbi, SIT_BITMAP);

	sit_i->sit_bitmap = kmemdup(src_bitmap, sit_bitmap_size, GFP_KERNEL);
	if (!sit_i->sit_bitmap)
		return -ENOMEM;

#ifdef CONFIG_F2FS_CHECK_FS
	sit_i->sit_bitmap_mir = kmemdup(src_bitmap,
					sit_bitmap_size, GFP_KERNEL);
	if (!sit_i->sit_bitmap_mir)
		return -ENOMEM;

	sit_i->invalid_segmap = f2fs_kvzalloc(sbi,
					main_bitmap_size, GFP_KERNEL);
	if (!sit_i->invalid_segmap)
		return -ENOMEM;
#endif

	/* init SIT information */
	//sit_i->s_ops = &default_salloc_ops;
	sit_i->s_ops = &IFLBA_salloc_ops;

	sit_i->sit_base_addr = le32_to_cpu(raw_super->sit_blkaddr);
	sit_i->sit_blocks = sit_segs << sbi->log_blocks_per_seg;
	sit_i->written_valid_blocks = 0;
	sit_i->bitmap_size = sit_bitmap_size;
	//sit_i->dirty_sentries = 0;
	sit_i->sents_per_block = SIT_ENTRY_PER_BLOCK;
	sit_i->elapsed_time = le64_to_cpu(sbi->ckpt->elapsed_time);
	sit_i->mounted_time = ktime_get_boottime_seconds();
	init_rwsem(&sit_i->sentry_lock);
	return 0;
}

static int build_free_segmap(struct f2fs_sb_info *sbi)
{
	struct free_segmap_info *free_i;
	unsigned int bitmap_size, sec_bitmap_size;

	/* allocate memory for free segmap information */
	free_i = f2fs_kzalloc(sbi, sizeof(struct free_segmap_info), GFP_KERNEL);
	if (!free_i)
		return -ENOMEM;

	SM_I(sbi)->free_info = free_i;

	bitmap_size = f2fs_bitmap_size(MAIN_SEGS(sbi));
	free_i->free_segmap = f2fs_kvmalloc(sbi, bitmap_size, GFP_KERNEL);
	if (!free_i->free_segmap)
		return -ENOMEM;

	sec_bitmap_size = f2fs_bitmap_size(MAIN_SECS(sbi));
	free_i->free_secmap = f2fs_kvmalloc(sbi, sec_bitmap_size, GFP_KERNEL);
	if (!free_i->free_secmap)
		return -ENOMEM;

	/* set all segments as dirty temporarily */
	memset(free_i->free_segmap, 0xff, bitmap_size);
	memset(free_i->free_secmap, 0xff, sec_bitmap_size);

	/* init free segmap information */
	free_i->start_segno = GET_SEGNO_FROM_SEG0(sbi, MAIN_BLKADDR(sbi));
	free_i->free_segments = 0;
	free_i->free_sections = 0;
	spin_lock_init(&free_i->segmap_lock);
	return 0;
}

static int build_curseg(struct f2fs_sb_info *sbi)
{
       struct curseg_info *array;
       int i;

       array = f2fs_kzalloc(sbi, array_size(NR_CURSEG_TYPE,
                                       sizeof(*array)), GFP_KERNEL);
       if (!array)
               return -ENOMEM;

       SM_I(sbi)->curseg_array = array;

       for (i = 0; i < NO_CHECK_TYPE; i++) {
               mutex_init(&array[i].curseg_mutex);
               array[i].sum_blk = f2fs_kzalloc(sbi, PAGE_SIZE, GFP_KERNEL);
               if (!array[i].sum_blk)
                       return -ENOMEM;
               init_rwsem(&array[i].journal_rwsem);
               array[i].journal = f2fs_kzalloc(sbi,
                               sizeof(struct f2fs_journal), GFP_KERNEL);
               if (!array[i].journal)
                       return -ENOMEM;
               if (i < NR_PERSISTENT_LOG)
                       array[i].seg_type = CURSEG_HOT_DATA + i;
               else if (i == CURSEG_COLD_DATA_PINNED)
                       array[i].seg_type = CURSEG_COLD_DATA;
               else if (i == CURSEG_ALL_DATA_ATGC)
                       array[i].seg_type = CURSEG_COLD_DATA;
               array[i].segno = NULL_SEGNO;
               array[i].next_blkoff = 0;
               array[i].inited = false;
       }
       return restore_curseg_summaries(sbi);
}

static int build_sit_entries(struct f2fs_sb_info *sbi)
{
       struct sit_info *sit_i = SIT_I(sbi);
       struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_COLD_DATA);
       struct f2fs_journal *journal = curseg->journal;
       struct seg_entry *se;
       struct f2fs_sit_entry sit;
       int sit_blk_cnt = SIT_BLK_CNT(sbi);
       unsigned int i, start, end;
       unsigned int readed, start_blk = 0;
       int err = 0;
       block_t total_node_blocks = 0;


       do {
               readed = f2fs_ra_meta_pages(sbi, start_blk, BIO_MAX_PAGES,
                                                       META_SIT, true);

               start = start_blk * sit_i->sents_per_block;
               end = (start_blk + readed) * sit_i->sents_per_block;

               for (; start < end && start < MAIN_SEGS(sbi); start++) {
                       struct f2fs_sit_block *sit_blk;
                       struct page *page;

                       se = &sit_i->sentries[start];
                       page = get_current_sit_page(sbi, start);
                       if (IS_ERR(page))
                               return PTR_ERR(page);
                       sit_blk = (struct f2fs_sit_block *)page_address(page);
                       sit = sit_blk->entries[SIT_ENTRY_OFFSET(sit_i, start)];
                       f2fs_put_page(page, 1);

                       err = check_block_count(sbi, start, &sit);
                       if (err)
                               return err;
                       seg_info_from_raw_sit(se, &sit);
                       if (IS_NODESEG(se->type))
                               total_node_blocks += se->valid_blocks;

                       /* build discard map only one time */
                       if (is_set_ckpt_flags(sbi, CP_TRIMMED_FLAG)) {
                               memset(se->discard_map, 0xff,
                                       SIT_VBLOCK_MAP_SIZE);
                       } else {
                               memcpy(se->discard_map,
                                       se->cur_valid_map,
                                       SIT_VBLOCK_MAP_SIZE);
                               sbi->discard_blks +=
                                       sbi->blocks_per_seg -
                                       se->valid_blocks;
                       }

                       if (__is_large_section(sbi))
                               get_sec_entry(sbi, start)->valid_blocks +=
                                                       se->valid_blocks;
               }
               start_blk += readed;
       } while (start_blk < sit_blk_cnt);

       down_read(&curseg->journal_rwsem);
       for (i = 0; i < sits_in_cursum(journal); i++) {
               unsigned int old_valid_blocks;

               start = le32_to_cpu(segno_in_journal(journal, i));
               if (start >= MAIN_SEGS(sbi)) {
                       f2fs_err(sbi, "Wrong journal entry on segno %u",
                                start);
                       err = -EFSCORRUPTED;
                       break;
               }

               se = &sit_i->sentries[start];
               sit = sit_in_journal(journal, i);

               old_valid_blocks = se->valid_blocks;
               if (IS_NODESEG(se->type))
                       total_node_blocks -= old_valid_blocks;

               err = check_block_count(sbi, start, &sit);
               if (err)
                       break;
               seg_info_from_raw_sit(se, &sit);
               if (IS_NODESEG(se->type))
                       total_node_blocks += se->valid_blocks;

               if (is_set_ckpt_flags(sbi, CP_TRIMMED_FLAG)) {
                       memset(se->discard_map, 0xff, SIT_VBLOCK_MAP_SIZE);
               } else {
                       memcpy(se->discard_map, se->cur_valid_map,
                                               SIT_VBLOCK_MAP_SIZE);
                       sbi->discard_blks += old_valid_blocks;
                       sbi->discard_blks -= se->valid_blocks;
               }

               if (__is_large_section(sbi)) {
                       get_sec_entry(sbi, start)->valid_blocks +=
                                                       se->valid_blocks;
                       get_sec_entry(sbi, start)->valid_blocks -=
                                                       old_valid_blocks;
               }
       }
       up_read(&curseg->journal_rwsem);

       if (!err && total_node_blocks != valid_node_count(sbi)) {
               f2fs_err(sbi, "SIT is corrupted node# %u vs %u",
                        total_node_blocks, valid_node_count(sbi));
               err = -EFSCORRUPTED;
       }

       return err;
}

static void init_free_segmap(struct f2fs_sb_info *sbi)
{
       unsigned int start;
       int type;
       struct seg_entry *sentry;

       for (start = 0; start < MAIN_SEGS(sbi); start++) {
               if (f2fs_usable_blks_in_seg(sbi, start) == 0)
                       continue;
               sentry = get_seg_entry(sbi, start);
               if (!sentry->valid_blocks)
                       __set_free(sbi, start);
               else
                       SIT_I(sbi)->written_valid_blocks +=
                                               sentry->valid_blocks;
       }

       /* set use the current segments */
       for (type = CURSEG_HOT_DATA; type <= CURSEG_COLD_NODE; type++) {
               struct curseg_info *curseg_t = CURSEG_I(sbi, type);
               __set_test_and_inuse(sbi, curseg_t->segno);
       }
}

static void init_dirty_segmap(struct f2fs_sb_info *sbi)
{
       struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
       struct free_segmap_info *free_i = FREE_I(sbi);
       unsigned int segno = 0, offset = 0, secno;
       block_t valid_blocks, usable_blks_in_seg;
       block_t blks_per_sec = BLKS_PER_SEC(sbi);

       while (1) {
               /* find dirty segment based on free segmap */
               segno = find_next_inuse(free_i, MAIN_SEGS(sbi), offset);
               if (segno >= MAIN_SEGS(sbi))
                       break;
               offset = segno + 1;
               valid_blocks = get_valid_blocks(sbi, segno, false);
               usable_blks_in_seg = f2fs_usable_blks_in_seg(sbi, segno);
               if (valid_blocks == usable_blks_in_seg || !valid_blocks)
                       continue;
               if (valid_blocks > usable_blks_in_seg) {
                       f2fs_bug_on(sbi, 1);
                       continue;
               }
               mutex_lock(&dirty_i->seglist_lock);
               //__locate_dirty_segment(sbi, segno, DIRTY);
               mutex_unlock(&dirty_i->seglist_lock);
       }

       if (!__is_large_section(sbi))
               return;

       mutex_lock(&dirty_i->seglist_lock);
       for (segno = 0; segno < MAIN_SEGS(sbi); segno += sbi->segs_per_sec) {
               valid_blocks = get_valid_blocks(sbi, segno, true);
               secno = GET_SEC_FROM_SEG(sbi, segno);

               if (!valid_blocks || valid_blocks == blks_per_sec)
                       continue;
               if (IS_CURSEC(sbi, secno))
                       continue;
               set_bit(secno, dirty_i->dirty_secmap);
       }
       mutex_unlock(&dirty_i->seglist_lock);
}

static int init_victim_secmap(struct f2fs_sb_info *sbi)
{
       struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
       unsigned int bitmap_size = f2fs_bitmap_size(MAIN_SECS(sbi));

       dirty_i->victim_secmap = f2fs_kvzalloc(sbi, bitmap_size, GFP_KERNEL);
       if (!dirty_i->victim_secmap)
               return -ENOMEM;
       return 0;
}

static int build_dirty_segmap(struct f2fs_sb_info *sbi)
{
       struct dirty_seglist_info *dirty_i;
       unsigned int bitmap_size, i;

       /* allocate memory for dirty segments list information */
       dirty_i = f2fs_kzalloc(sbi, sizeof(struct dirty_seglist_info),
                                                               GFP_KERNEL);
       if (!dirty_i)
               return -ENOMEM;

       SM_I(sbi)->dirty_info = dirty_i;
       mutex_init(&dirty_i->seglist_lock);

       bitmap_size = f2fs_bitmap_size(MAIN_SEGS(sbi));

       for (i = 0; i < NR_DIRTY_TYPE; i++) {
               dirty_i->dirty_segmap[i] = f2fs_kvzalloc(sbi, bitmap_size,
                                                               GFP_KERNEL);
               if (!dirty_i->dirty_segmap[i])
                       return -ENOMEM;
       }

       if (__is_large_section(sbi)) {
               bitmap_size = f2fs_bitmap_size(MAIN_SECS(sbi));
               dirty_i->dirty_secmap = f2fs_kvzalloc(sbi,
                                               bitmap_size, GFP_KERNEL);
               if (!dirty_i->dirty_secmap)
                       return -ENOMEM;
       }

       init_dirty_segmap(sbi);
       return init_victim_secmap(sbi);
}

static int sanity_check_curseg(struct f2fs_sb_info *sbi)
{
       int i;

       /*
        * In LFS/SSR curseg, .next_blkoff should point to an unused blkaddr;
        * In LFS curseg, all blkaddr after .next_blkoff should be unused.
        */
       for (i = 0; i < NR_PERSISTENT_LOG; i++) {
               struct curseg_info *curseg = CURSEG_I(sbi, i);
               struct seg_entry *se = get_seg_entry(sbi, curseg->segno);
               unsigned int blkofs = curseg->next_blkoff;

               sanity_check_seg_type(sbi, curseg->seg_type);

               if (f2fs_test_bit(blkofs, se->cur_valid_map))
                       goto out;

               if (curseg->alloc_type == SSR)
                       continue;

               for (blkofs += 1; blkofs < sbi->blocks_per_seg; blkofs++) {
                       if (!f2fs_test_bit(blkofs, se->cur_valid_map))
                               continue;
out:
                       f2fs_err(sbi,
                                "Current segment's next free block offset is inconsistent with bitmap, logtype:%u, segno:%u, type:%u, next_blkoff:%u, blkofs:%u",
                                i, curseg->segno, curseg->alloc_type,
                                curseg->next_blkoff, blkofs);
                       return -EFSCORRUPTED;
               }
       }
       return 0;
}

#ifdef CONFIG_BLK_DEV_ZONED

static int check_zone_write_pointer(struct f2fs_sb_info *sbi,
                                   struct f2fs_dev_info *fdev,
                                   struct blk_zone *zone)
{
       unsigned int wp_segno, wp_blkoff, zone_secno, zone_segno, segno;
       block_t zone_block, wp_block, last_valid_block;
       unsigned int log_sectors_per_block = sbi->log_blocksize - SECTOR_SHIFT;
       int i, s, b, ret;
       struct seg_entry *se;

       if (zone->type != BLK_ZONE_TYPE_SEQWRITE_REQ)
               return 0;

       wp_block = fdev->start_blk + (zone->wp >> log_sectors_per_block);
       wp_segno = GET_SEGNO(sbi, wp_block);
       wp_blkoff = wp_block - START_BLOCK(sbi, wp_segno);
       zone_block = fdev->start_blk + (zone->start >> log_sectors_per_block);
       zone_segno = GET_SEGNO(sbi, zone_block);
       zone_secno = GET_SEC_FROM_SEG(sbi, zone_segno);

       if (zone_segno >= MAIN_SEGS(sbi))
               return 0;

       /*
        * Skip check of zones cursegs point to, since
        * fix_curseg_write_pointer() checks them.
        */
       for (i = 0; i < NO_CHECK_TYPE; i++)
               if (zone_secno == GET_SEC_FROM_SEG(sbi,
                                                  CURSEG_I(sbi, i)->segno))
                       return 0;

       /*
        * Get last valid block of the zone.
        */
       last_valid_block = zone_block - 1;
       for (s = sbi->segs_per_sec - 1; s >= 0; s--) {
               segno = zone_segno + s;
               se = get_seg_entry(sbi, segno);
               for (b = sbi->blocks_per_seg - 1; b >= 0; b--)
                       if (f2fs_test_bit(b, se->cur_valid_map)) {
                               last_valid_block = START_BLOCK(sbi, segno) + b;
                               break;
                       }
               if (last_valid_block >= zone_block)
                       break;
       }

       /*
        * If last valid block is beyond the write pointer, report the
        * inconsistency. This inconsistency does not cause write error
        * because the zone will not be selected for write operation until
        * it get discarded. Just report it.
        */

       if (last_valid_block >= wp_block) {
               f2fs_notice(sbi, "Valid block beyond write pointer: "
                           "valid block[0x%x,0x%x] wp[0x%x,0x%x]",
                           GET_SEGNO(sbi, last_valid_block),
                           GET_BLKOFF_FROM_SEG0(sbi, last_valid_block),
                           wp_segno, wp_blkoff);
               return 0;
       }

       /*
        * If there is no valid block in the zone and if write pointer is
        * not at zone start, reset the write pointer.
        */
       if (last_valid_block + 1 == zone_block && zone->wp != zone->start) {
               f2fs_notice(sbi,
                           "Zone without valid block has non-zero write "
                           "pointer. Reset the write pointer: wp[0x%x,0x%x]",
                           wp_segno, wp_blkoff);
               ret = __f2fs_issue_discard_zone(sbi, fdev->bdev, zone_block,
                                       zone->len >> log_sectors_per_block);
               if (ret) {
                       f2fs_err(sbi, "Discard zone failed: %s (errno=%d)",
                                fdev->path, ret);
                       return ret;
               }
       }

       return 0;
}

static struct f2fs_dev_info *get_target_zoned_dev(struct f2fs_sb_info *sbi,
                                                 block_t zone_blkaddr)
{
       int i;

       for (i = 0; i < sbi->s_ndevs; i++) {
               if (!bdev_is_zoned(FDEV(i).bdev))
                       continue;
               if (sbi->s_ndevs == 1 || (FDEV(i).start_blk <= zone_blkaddr &&
                               zone_blkaddr <= FDEV(i).end_blk))
                       return &FDEV(i);
       }

       return NULL;
}

static int report_one_zone_cb(struct blk_zone *zone, unsigned int idx,
                             void *data) {
       memcpy(data, zone, sizeof(struct blk_zone));
       return 0;
}

static int fix_curseg_write_pointer(struct f2fs_sb_info *sbi, int type)
{
       struct curseg_info *cs = CURSEG_I(sbi, type);
       struct f2fs_dev_info *zbd;
       struct blk_zone zone;
       unsigned int cs_section, wp_segno, wp_blkoff, wp_sector_off;
       block_t cs_zone_block, wp_block;
       unsigned int log_sectors_per_block = sbi->log_blocksize - SECTOR_SHIFT;
       sector_t zone_sector;
       int err;

       cs_section = GET_SEC_FROM_SEG(sbi, cs->segno);
       cs_zone_block = START_BLOCK(sbi, GET_SEG_FROM_SEC(sbi, cs_section));

       zbd = get_target_zoned_dev(sbi, cs_zone_block);
       if (!zbd)
               return 0;

       /* report zone for the sector the curseg points to */
       zone_sector = (sector_t)(cs_zone_block - zbd->start_blk)
               << log_sectors_per_block;
       err = blkdev_report_zones(zbd->bdev, zone_sector, 1,
                                 report_one_zone_cb, &zone);
       if (err != 1) {
               f2fs_err(sbi, "Report zone failed: %s errno=(%d)",
                        zbd->path, err);
               return err;
       }

       if (zone.type != BLK_ZONE_TYPE_SEQWRITE_REQ)
               return 0;

       wp_block = zbd->start_blk + (zone.wp >> log_sectors_per_block);
       wp_segno = GET_SEGNO(sbi, wp_block);
       wp_blkoff = wp_block - START_BLOCK(sbi, wp_segno);
       wp_sector_off = zone.wp & GENMASK(log_sectors_per_block - 1, 0);

       if (cs->segno == wp_segno && cs->next_blkoff == wp_blkoff &&
               wp_sector_off == 0)
               return 0;

       f2fs_notice(sbi, "Unaligned curseg[%d] with write pointer: "
                   "curseg[0x%x,0x%x] wp[0x%x,0x%x]",
                   type, cs->segno, cs->next_blkoff, wp_segno, wp_blkoff);

       f2fs_notice(sbi, "Assign new section to curseg[%d]: "
                   "curseg[0x%x,0x%x]", type, cs->segno, cs->next_blkoff);
       allocate_segment_by_default(sbi, type, true);

       /* check consistency of the zone curseg pointed to */
       if (check_zone_write_pointer(sbi, zbd, &zone))
               return -EIO;

       /* check newly assigned zone */
       cs_section = GET_SEC_FROM_SEG(sbi, cs->segno);
       cs_zone_block = START_BLOCK(sbi, GET_SEG_FROM_SEC(sbi, cs_section));

       zbd = get_target_zoned_dev(sbi, cs_zone_block);
       if (!zbd)
               return 0;

       zone_sector = (sector_t)(cs_zone_block - zbd->start_blk)
               << log_sectors_per_block;
       err = blkdev_report_zones(zbd->bdev, zone_sector, 1,
                                 report_one_zone_cb, &zone);
       if (err != 1) {
               f2fs_err(sbi, "Report zone failed: %s errno=(%d)",
                        zbd->path, err);
               return err;
       }

       if (zone.type != BLK_ZONE_TYPE_SEQWRITE_REQ)
               return 0;

       if (zone.wp != zone.start) {
               f2fs_notice(sbi,
                           "New zone for curseg[%d] is not yet discarded. "
                           "Reset the zone: curseg[0x%x,0x%x]",
                           type, cs->segno, cs->next_blkoff);
               err = __f2fs_issue_discard_zone(sbi, zbd->bdev,
                               zone_sector >> log_sectors_per_block,
                               zone.len >> log_sectors_per_block);
               if (err) {
                       f2fs_err(sbi, "Discard zone failed: %s (errno=%d)",
                                zbd->path, err);
                       return err;
               }
       }

       return 0;
}

int f2fs_fix_curseg_write_pointer(struct f2fs_sb_info *sbi)
{
       int i, ret;
       panic("f2fs_fix_curseg_write_pointer(): not expected!!\n");

       for (i = 0; i < NR_PERSISTENT_LOG; i++) {
               ret = fix_curseg_write_pointer(sbi, i);
               if (ret)
                       return ret;
       }

       return 0;
}

struct check_zone_write_pointer_args {
       struct f2fs_sb_info *sbi;
       struct f2fs_dev_info *fdev;
};

static int check_zone_write_pointer_cb(struct blk_zone *zone, unsigned int idx,
                                     void *data) {
       struct check_zone_write_pointer_args *args;
       args = (struct check_zone_write_pointer_args *)data;

       return check_zone_write_pointer(args->sbi, args->fdev, zone);
}

int f2fs_check_write_pointer(struct f2fs_sb_info *sbi)
{
       int i, ret;
       struct check_zone_write_pointer_args args;
       panic("f2fs_check_write_pointer(): not expected!!\n");
       for (i = 0; i < sbi->s_ndevs; i++) {
               if (!bdev_is_zoned(FDEV(i).bdev))
                       continue;

               args.sbi = sbi;
               args.fdev = &FDEV(i);
               ret = blkdev_report_zones(FDEV(i).bdev, 0, BLK_ALL_ZONES,
                                         check_zone_write_pointer_cb, &args);
               if (ret < 0)
                       return ret;
       }

       return 0;
}

static bool is_conv_zone(struct f2fs_sb_info *sbi, unsigned int zone_idx,
                                               unsigned int dev_idx)
{
       if (!bdev_is_zoned(FDEV(dev_idx).bdev))
               return true;
       return !test_bit(zone_idx, FDEV(dev_idx).blkz_seq);
}


/* Return the zone index in the given device */
static unsigned int get_zone_idx(struct f2fs_sb_info *sbi, unsigned int secno,
                                       int dev_idx)
{
       block_t sec_start_blkaddr = START_BLOCK(sbi, GET_SEG_FROM_SEC(sbi, secno));

       return (sec_start_blkaddr - FDEV(dev_idx).start_blk) >>
                                               sbi->log_blocks_per_blkz;
}

/*
 * Return the usable segments in a section based on the zone's
 * corresponding zone capacity. Zone is equal to a section.
 */
static inline unsigned int f2fs_usable_zone_segs_in_sec(
               struct f2fs_sb_info *sbi, unsigned int segno)
{
       unsigned int dev_idx, zone_idx, unusable_segs_in_sec;

       dev_idx = f2fs_target_device_index(sbi, START_BLOCK(sbi, segno));
       zone_idx = get_zone_idx(sbi, GET_SEC_FROM_SEG(sbi, segno), dev_idx);

       /* Conventional zone's capacity is always equal to zone size */
       if (is_conv_zone(sbi, zone_idx, dev_idx))
               return sbi->segs_per_sec;

       /*
        * If the zone_capacity_blocks array is NULL, then zone capacity
        * is equal to the zone size for all zones
        */
       if (!FDEV(dev_idx).zone_capacity_blocks)
               return sbi->segs_per_sec;

       /* Get the segment count beyond zone capacity block */
       unusable_segs_in_sec = (sbi->blocks_per_blkz -
                               FDEV(dev_idx).zone_capacity_blocks[zone_idx]) >>
                               sbi->log_blocks_per_seg;
       return sbi->segs_per_sec - unusable_segs_in_sec;
}

/*
 * Return the number of usable blocks in a segment. The number of blocks
 * returned is always equal to the number of blocks in a segment for
 * segments fully contained within a sequential zone capacity or a
 * conventional zone. For segments partially contained in a sequential
 * zone capacity, the number of usable blocks up to the zone capacity
 * is returned. 0 is returned in all other cases.
 */
static inline unsigned int f2fs_usable_zone_blks_in_seg(
                       struct f2fs_sb_info *sbi, unsigned int segno)
{
       block_t seg_start, sec_start_blkaddr, sec_cap_blkaddr;
       unsigned int zone_idx, dev_idx, secno;

       secno = GET_SEC_FROM_SEG(sbi, segno);
       seg_start = START_BLOCK(sbi, segno);
       dev_idx = f2fs_target_device_index(sbi, seg_start);
       zone_idx = get_zone_idx(sbi, secno, dev_idx);

       /*
        * Conventional zone's capacity is always equal to zone size,
        * so, blocks per segment is unchanged.
        */
       if (is_conv_zone(sbi, zone_idx, dev_idx))
               return sbi->blocks_per_seg;

       if (!FDEV(dev_idx).zone_capacity_blocks)
               return sbi->blocks_per_seg;

       sec_start_blkaddr = START_BLOCK(sbi, GET_SEG_FROM_SEC(sbi, secno));
       sec_cap_blkaddr = sec_start_blkaddr +
                               FDEV(dev_idx).zone_capacity_blocks[zone_idx];

       /*
        * If segment starts before zone capacity and spans beyond
        * zone capacity, then usable blocks are from seg start to
        * zone capacity. If the segment starts after the zone capacity,
        * then there are no usable blocks.
        */
       if (seg_start >= sec_cap_blkaddr)
               return 0;
       if (seg_start + sbi->blocks_per_seg > sec_cap_blkaddr)
               return sec_cap_blkaddr - seg_start;

       return sbi->blocks_per_seg;
}
#else
int f2fs_fix_curseg_write_pointer(struct f2fs_sb_info *sbi)
{
       return 0;
}

int f2fs_check_write_pointer(struct f2fs_sb_info *sbi)
{
       return 0;
}

static inline unsigned int f2fs_usable_zone_blks_in_seg(struct f2fs_sb_info *sbi,
                                                       unsigned int segno)
{
       return 0;
}

static inline unsigned int f2fs_usable_zone_segs_in_sec(struct f2fs_sb_info *sbi,
                                                       unsigned int segno)
{
       return 0;
}
#endif
unsigned int f2fs_usable_blks_in_seg(struct f2fs_sb_info *sbi,
                                       unsigned int segno)
{
       if (f2fs_sb_has_blkzoned(sbi)){
               panic("f2fs_usable_blks_in_seg(): f2fs_sb_has_blkzoned is True. not expected\n");
               return f2fs_usable_zone_blks_in_seg(sbi, segno);
       }
       return sbi->blocks_per_seg;
}

unsigned int f2fs_usable_segs_in_sec(struct f2fs_sb_info *sbi,
                                       unsigned int segno)
{
       if (f2fs_sb_has_blkzoned(sbi))
               return f2fs_usable_zone_segs_in_sec(sbi, segno);

       return sbi->segs_per_sec;
}

/*
 * Update min, max modified time for cost-benefit GC algorithm
 */
static void init_min_max_mtime(struct f2fs_sb_info *sbi)
{
       struct sit_info *sit_i = SIT_I(sbi);
       unsigned int segno;

       down_write(&sit_i->sentry_lock);

       sit_i->min_mtime = ULLONG_MAX;

       for (segno = 0; segno < MAIN_SEGS(sbi); segno += sbi->segs_per_sec) {
               unsigned int i;
               unsigned long long mtime = 0;

               for (i = 0; i < sbi->segs_per_sec; i++)
                       mtime += get_seg_entry(sbi, segno + i)->mtime;

               mtime = div_u64(mtime, sbi->segs_per_sec);

               if (sit_i->min_mtime > mtime)
                       sit_i->min_mtime = mtime;
       }
       sit_i->max_mtime = get_mtime(sbi, false);
       sit_i->dirty_max_mtime = 0;
       up_write(&sit_i->sentry_lock);
}

int f2fs_build_segment_manager(struct f2fs_sb_info *sbi)
{
       struct f2fs_super_block *raw_super = F2FS_RAW_SUPER(sbi);
       struct f2fs_checkpoint *ckpt = F2FS_CKPT(sbi);
       struct f2fs_sm_info *sm_info;
       int err;

       sm_info = f2fs_kzalloc(sbi, sizeof(struct f2fs_sm_info), GFP_KERNEL);
       if (!sm_info)
               return -ENOMEM;

       /* init sm info */
       sbi->sm_info = sm_info;
       sm_info->seg0_blkaddr = le32_to_cpu(raw_super->segment0_blkaddr);
       sm_info->main_blkaddr = le32_to_cpu(raw_super->main_blkaddr);
       sm_info->segment_count = le32_to_cpu(raw_super->segment_count);
       sm_info->reserved_segments = le32_to_cpu(ckpt->rsvd_segment_count);
       sm_info->ovp_segments = le32_to_cpu(ckpt->overprov_segment_count);
       sm_info->main_segments = le32_to_cpu(raw_super->segment_count_main);
       sm_info->ssa_blkaddr = le32_to_cpu(raw_super->ssa_blkaddr);
       sm_info->rec_prefree_segments = sm_info->main_segments *
                                       DEF_RECLAIM_PREFREE_SEGMENTS / 100;
       sm_info->start_segno = GET_SEGNO_FROM_SEG0(sbi, MAIN_BLKADDR(sbi));
       if (sm_info->rec_prefree_segments > DEF_MAX_RECLAIM_PREFREE_SEGMENTS)
               sm_info->rec_prefree_segments = DEF_MAX_RECLAIM_PREFREE_SEGMENTS;

       if (!f2fs_lfs_mode(sbi))
               sm_info->ipu_policy = 1 << F2FS_IPU_FSYNC;
       sm_info->min_ipu_util = DEF_MIN_IPU_UTIL;
       sm_info->min_fsync_blocks = DEF_MIN_FSYNC_BLOCKS;
       sm_info->min_seq_blocks = sbi->blocks_per_seg * sbi->segs_per_sec;
       sm_info->min_hot_blocks = DEF_MIN_HOT_BLOCKS;
       sm_info->min_ssr_sections = reserved_sections(sbi);

       INIT_LIST_HEAD(&sm_info->sit_entry_set);

       init_rwsem(&sm_info->curseg_lock);
       init_rwsem(&sm_info->curseg_zone_lock);

       if (!f2fs_readonly(sbi->sb)) {
               err = f2fs_create_flush_cmd_control(sbi);
               if (err)
                       return err;
       }

       err = create_discard_cmd_control(sbi);
       if (err)
               return err;

       err = create_dynamic_discard_map_control(sbi);
       if (err)
               return err;

       err = build_sit_info(sbi);
       if (err)
               return err;
       err = build_free_segmap(sbi);
       if (err)
               return err;

       err = build_curseg(sbi);
       if (err)
               return err;

       /* reinit free segmap based on SIT */
       err = build_sit_entries(sbi);
       if (err)
               return err;

       //init_free_segmap(sbi);
       //err = build_dirty_segmap(sbi);
       //if (err)
       //      return err;

       /*err = sanity_check_curseg(sbi);
       if (err)
               return err;
       */
       //init_min_max_mtime(sbi);
       return 0;
}

/*
static void discard_dirty_segmap(struct f2fs_sb_info *sbi,
               enum dirty_type dirty_type)
{
       struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);

       mutex_lock(&dirty_i->seglist_lock);
       kvfree(dirty_i->dirty_segmap[dirty_type]);
       dirty_i->nr_dirty[dirty_type] = 0;
       mutex_unlock(&dirty_i->seglist_lock);
}

static void destroy_victim_secmap(struct f2fs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	kvfree(dirty_i->victim_secmap);
}

static void destroy_dirty_segmap(struct f2fs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	int i;

	if (!dirty_i)
		return;

	// discard pre-free/dirty segments list 
	for (i = 0; i < NR_DIRTY_TYPE; i++)
		discard_dirty_segmap(sbi, i);

	if (__is_large_section(sbi)) {
		mutex_lock(&dirty_i->seglist_lock);
		kvfree(dirty_i->dirty_secmap);
		mutex_unlock(&dirty_i->seglist_lock);
	}

	destroy_victim_secmap(sbi);
	SM_I(sbi)->dirty_info = NULL;
	kfree(dirty_i);
}
*/

static void destroy_curseg(struct f2fs_sb_info *sbi)
{
	struct curseg_info *array = SM_I(sbi)->curseg_array;
	int i;

	if (!array)
		return;
	SM_I(sbi)->curseg_array = NULL;
	for (i = 0; i < NR_CURSEG_TYPE; i++) {
		kfree(array[i].sum_blk);
		kfree(array[i].journal);
	}
	kfree(array);
}

static void destroy_free_segmap(struct f2fs_sb_info *sbi)
{
	struct free_segmap_info *free_i = SM_I(sbi)->free_info;
	if (!free_i)
		return;
	SM_I(sbi)->free_info = NULL;
	kvfree(free_i->free_segmap);
	kvfree(free_i->free_secmap);
	kfree(free_i);
}

static void destroy_sit_info(struct f2fs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);

	if (!sit_i)
		return;

	if (sit_i->sentries)
		kvfree(sit_i->bitmap);
	kfree(sit_i->tmp_map);

	kvfree(sit_i->sentries);
	kvfree(sit_i->sec_entries);
	kvfree(sit_i->dirty_sentries_bitmap);

	SM_I(sbi)->sit_info = NULL;
	kvfree(sit_i->sit_bitmap);
#ifdef CONFIG_F2FS_CHECK_FS
	kvfree(sit_i->sit_bitmap_mir);
	kvfree(sit_i->invalid_segmap);
#endif
	kfree(sit_i);
}

void f2fs_destroy_segment_manager(struct f2fs_sb_info *sbi)
{
	struct f2fs_sm_info *sm_info = SM_I(sbi);

	if (!sm_info)
		return;
	f2fs_destroy_flush_cmd_control(sbi, true);
	destroy_discard_cmd_control(sbi);
	destroy_dynamic_discard_map_control(sbi);
	//destroy_dirty_segmap(sbi);
	destroy_curseg(sbi);
	destroy_free_segmap(sbi);
	destroy_sit_info(sbi);
	sbi->sm_info = NULL;
	kfree(sm_info);
}

int __init f2fs_create_segment_manager_caches(void)
{
	discard_entry_slab = f2fs_kmem_cache_create("f2fs_discard_entry",
			sizeof(struct discard_entry));
	if (!discard_entry_slab)
		goto fail;

	discard_cmd_slab = f2fs_kmem_cache_create("f2fs_discard_cmd",
			sizeof(struct discard_cmd));
	if (!discard_cmd_slab)
		goto destroy_discard_entry;

	sit_entry_set_slab = f2fs_kmem_cache_create("f2fs_sit_entry_set",
			sizeof(struct sit_entry_set));
	if (!sit_entry_set_slab)
		goto destroy_discard_cmd;

	inmem_entry_slab = f2fs_kmem_cache_create("f2fs_inmem_page_entry",
			sizeof(struct inmem_pages));
	if (!inmem_entry_slab)
		goto destroy_sit_entry_set;
	
	discard_map_slab = f2fs_kmem_cache_create("f2fs_discard_map",
			sizeof(struct dynamic_discard_map));
	if (!discard_map_slab)
		goto destroy_inmem_page_entry;
	
	discard_range_slab = f2fs_kmem_cache_create("f2fs_range_map",
			sizeof(struct discard_range_entry));
	if (!discard_range_slab)
		goto destroy_discard_map;
	return 0;

destroy_discard_map:
	kmem_cache_destroy(discard_map_slab);
destroy_inmem_page_entry:
	kmem_cache_destroy(inmem_entry_slab);
destroy_sit_entry_set:
	kmem_cache_destroy(sit_entry_set_slab);
destroy_discard_cmd:
	kmem_cache_destroy(discard_cmd_slab);
destroy_discard_entry:
	kmem_cache_destroy(discard_entry_slab);
fail:
	return -ENOMEM;
}

void f2fs_destroy_segment_manager_caches(void)
{
	kmem_cache_destroy(sit_entry_set_slab);
	kmem_cache_destroy(discard_cmd_slab);
	kmem_cache_destroy(discard_entry_slab);
	kmem_cache_destroy(inmem_entry_slab);
	kmem_cache_destroy(discard_map_slab);
	kmem_cache_destroy(discard_range_slab);
}
