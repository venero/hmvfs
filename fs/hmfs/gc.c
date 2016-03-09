#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/freezer.h>

#include "hmfs.h"
#include "hmfs_fs.h"
#include "gc.h"
#include "segment.h"
#include "node.h"
#include "xattr.h"

/*
 * Setup arguments for GC and GC recovery
 */
void prepare_move_argument(struct gc_move_arg *arg,
				struct hmfs_sb_info *sbi, seg_t mv_segno, unsigned mv_offset,
				struct hmfs_summary *sum, int type)
{
	arg->start_version = get_summary_start_version(sum);
	arg->nid = get_summary_nid(sum);
	arg->ofs_in_node = get_summary_offset(sum);
	arg->src_addr = __cal_page_addr(sbi, mv_segno, mv_offset);
	arg->src = ADDR(sbi, arg->src_addr);

	arg->cp_i = get_checkpoint_info(sbi, arg->start_version, true);

	if (sbi->recovery_doing)
		return;

	if (type == TYPE_DATA) {
		arg->dest = alloc_new_data_block(sbi, NULL, 0);
	} else {
		arg->dest = alloc_new_node(sbi, 0, NULL, 0, true);
	}
	
	hmfs_bug_on(sbi, IS_ERR(arg->dest));

	arg->dest_addr = L_ADDR(sbi, arg->dest);
	arg->dest_sum = get_summary_by_addr(sbi, arg->dest_addr);
	
	hmfs_memcpy(arg->dest, arg->src, HMFS_PAGE_SIZE);
}

static unsigned int get_cb_cost(struct hmfs_sb_info *sbi, unsigned int segno)
{
	struct sit_info *sit_i = SIT_I(sbi);
	unsigned long long mtime = 0;
	unsigned int vblocks;
	unsigned char age = 0;
	unsigned char u;

	mtime = get_seg_entry(sbi, segno)->mtime;
	vblocks = get_seg_entry(sbi, segno)->valid_blocks;

	u = (vblocks * 100) >> HMFS_PAGE_PER_SEG_BITS;

	if (mtime < sit_i->min_mtime)
		sit_i->min_mtime = mtime;
	if (mtime > sit_i->max_mtime)
		sit_i->max_mtime = mtime;
	if (sit_i->max_mtime != sit_i->min_mtime)
		age = 100 - div64_u64(100 * (mtime - sit_i->min_mtime),
			     			sit_i->max_mtime - sit_i->min_mtime);

	return UINT_MAX - ((100 * (100 - u) * age) / (100 + u));
}

static unsigned int get_max_cost(struct hmfs_sb_info *sbi,
				 struct victim_sel_policy *p)
{
	if (p->gc_mode == GC_GREEDY)
		return HMFS_PAGE_PER_SEG;
	else if (p->gc_mode == GC_CB)
		return UINT_MAX;
	else
		return 0;
}

static unsigned int get_gc_cost(struct hmfs_sb_info *sbi, unsigned int segno,
				struct victim_sel_policy *p)
{
//	if (p->gc_mode == GC_GREEDY)
		return get_seg_entry(sbi, segno)->valid_blocks;
//	else
//		return get_cb_cost(sbi, segno);
}

/*
 * Select a victim segment from dirty_segmap. We don't lock dirty_segmap here.
 * Because we could tolerate somewhat inconsistency of it. start_segno is used
 * for FG_GC, i.e. we scan the whole space of NVM atmost once in a FG_GC. Therefore,
 * we take down the first victim segment as start_segno
 */
//TODO: We might need to collect many segments in one victim searching
static int get_victim(struct hmfs_sb_info *sbi, seg_t *result, int gc_type)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	struct hmfs_checkpoint *hmfs_cp = CM_I(sbi)->last_cp_i->cp;
	struct victim_sel_policy p;
	unsigned int max_cost;
	unsigned long cost;
	seg_t segno;
	int nsearched = 0;
	int total_segs = TOTAL_SEGS(sbi);
	struct curseg_info *seg_i0 = &(CURSEG_I(sbi)[0]);
	struct curseg_info *seg_i1 = &(CURSEG_I(sbi)[1]);

	p.gc_mode = gc_type == BG_GC ? GC_CB : GC_GREEDY;
	p.offset = sbi->last_victim[p.gc_mode];
	p.min_segno = NULL_SEGNO;
	p.min_cost = max_cost = get_max_cost(sbi, &p);

	while (1) {
		segno = find_next_bit(dirty_i->dirty_segmap, total_segs, p.offset);

		if (segno >= total_segs) {
			if (sbi->last_victim[p.gc_mode]) {
				sbi->last_victim[p.gc_mode] = 0;
				p.offset = 0;
				continue;
			}
			break;
		} else {
			p.offset = segno + 1;
		}

		if (segno == atomic_read(&seg_i0->segno) || 
					segno == atomic_read(&seg_i1->segno)) {
			continue;
		}

		/*
		 * It's not allowed to move node segment where last checkpoint
		 * locate. Because we need to log GC segments in it.
		 */
		if (segno == le32_to_cpu(hmfs_cp->cur_node_segno)) {
			continue;
		}

		/* Stop if we find a segment whose cost is small enough */
		if (get_seg_entry(sbi, segno)->valid_blocks < NR_GC_MIN_BLOCK) {
			p.min_segno = segno;
			hmfs_dbg("Get victim:%lu vblocks:%d gc_type:%s\n", (unsigned long)segno, get_seg_entry(sbi, segno)->valid_blocks,
					gc_type == BG_GC ? "BG" : "FG");
			break;
		}

		cost = get_gc_cost(sbi, segno, &p);
	//	hmfs_dbg("%lu %lu %s\n", (unsigned long)segno, cost, gc_type == BG_GC ? "BG" : "FG");
		if (p.min_cost > cost) {
			p.min_segno = segno;
			p.min_cost = cost;
		}

		if (cost == max_cost)
			continue;

		if (nsearched++ >= MAX_SEG_SEARCH) {
			break;
		}
	}

	sbi->last_victim[p.gc_mode] = segno;

	if (p.min_segno != NULL_SEGNO) {
		*result = p.min_segno;
	}
	
	hmfs_dbg("Select %d\n", p.min_segno == NULL_SEGNO ? -1 : p.min_segno);
	return (p.min_segno == NULL_SEGNO) ? 0 : 1;
}

static void update_dest_summary(struct hmfs_summary *src_sum,
				struct hmfs_summary *dest_sum)
{
	hmfs_memcpy(dest_sum, src_sum, sizeof(struct hmfs_summary));
}

static void move_data_block(struct hmfs_sb_info *sbi, seg_t src_segno,
			    int src_off, struct hmfs_summary *src_sum)
{
	struct gc_move_arg args;
	struct hmfs_node *last = NULL, *this = NULL;
	struct hmfs_summary *par_sum = NULL;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	bool is_current;
	block_t addr_in_par;
	int par_type;

	is_current = get_summary_start_version(src_sum) == cm_i->new_version;

	/* 1. read summary of source blocks */
	/* 2. move blocks */
	prepare_move_argument(&args, sbi, src_segno, src_off, src_sum,
			TYPE_DATA);

	while (1) {
		/* 3. get the parent node which hold the pointer point to source node */
		this = __get_node(sbi, args.cp_i, args.nid);

		par_sum = get_summary_by_addr(sbi, L_ADDR(sbi, this));

		if (IS_ERR(this)) {
			/* the node(args.nid) has been deleted */
			break;
		}

		hmfs_dbg_on(get_summary_type(par_sum) != SUM_TYPE_INODE &&
				get_summary_type(par_sum) != SUM_TYPE_DN, "Invalid summary type:"
				" nid(%u) Address(%p)[%lu %d] Version(%d) Type(%d)\n", args.nid, 
				par_sum, GET_SEGNO(sbi, L_ADDR(sbi, this)), GET_SEG_OFS(sbi, L_ADDR(sbi, this)), 
				args.cp_i->version, get_summary_type(par_sum));

		hmfs_bug_on(sbi, get_summary_type(par_sum) != SUM_TYPE_INODE &&
				get_summary_type(par_sum) != SUM_TYPE_DN);

		/* Now the pointer contains in direct node have been changed last time */
		if (this == last)
			goto next;

		par_type = get_summary_type(par_sum);

		/* Now src data block has been COW or parent node has been removed */
		if (par_type == SUM_TYPE_INODE) {
			addr_in_par = le64_to_cpu(this->i.i_addr[args.ofs_in_node]);
		} else {
			addr_in_par = le64_to_cpu(this->dn.addr[args.ofs_in_node]);
		}

		/*
		 * In normal GC, we should stop when addr_in_par != src_addr,
		 * now direct node or inode in laster checkpoint would never
		 * refer to this data block
		 */
		if (addr_in_par != args.src_addr) 
			break;

		/* 
		 * We should use atomic write here, otherwise, if system crash
		 * during wrting address, i.i_addr and dn.addr would be invalid,
		 * whose value is neither args.dest_addr nor args.src_addr. Therefore,
		 * if recovery process, it would terminate in this checkpoint
		 */
		if (par_type == SUM_TYPE_INODE) {
			hmfs_memcpy_atomic(&this->i.i_addr[args.ofs_in_node], 
					&args.dest_addr, 8);
		} else {
			hmfs_memcpy_atomic(&this->dn.addr[args.ofs_in_node],
					&args.dest_addr, 8);
		}
		
		last = this;

next:
		/* cp_i is the lastest checkpoint, stop */
		if (args.cp_i == cm_i->last_cp_i || is_current) {
			break;
		}
		args.cp_i = get_next_checkpoint_info(sbi, args.cp_i);
	}

	/* 5. Update summary infomation of dest block */
	update_dest_summary(src_sum, args.dest_sum);
}

static void recycle_segment(struct hmfs_sb_info *sbi, seg_t segno, bool none_valid)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct free_segmap_info *free_i = FREE_I(sbi);
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	struct seg_entry *seg_entry;

	lock_sentry(sit_i);

	/* clean dirty bit */
	if (!test_and_set_bit(segno, sit_i->dirty_sentries_bitmap)) {
		sit_i->dirty_sentries++;
	}
	seg_entry = get_seg_entry(sbi, segno);
	seg_entry->valid_blocks = 0;
	seg_entry->mtime = get_seconds();

	unlock_sentry(sit_i);

	/* clear dirty bit */
	if (!test_and_clear_bit(segno, dirty_i->dirty_segmap))
		hmfs_bug_on(sbi, 1);

	if (none_valid) {
		lock_write_segmap(free_i);
		if (test_and_clear_bit(segno, free_i->free_segmap)) {
			free_i->free_segments++;
		}
		unlock_write_segmap(free_i);
	} else {
		/* set prefree bit */
		if (test_and_set_bit(segno, free_i->prefree_segmap))
			hmfs_bug_on(sbi, 1);
	}

	/* Now we have recycle HMFS_PAGE_PER_SEG blocks and update cm_i */
	lock_cm(cm_i);
	cm_i->alloc_block_count -= HMFS_PAGE_PER_SEG;
	unlock_cm(cm_i);
}

static void move_xdata_block(struct hmfs_sb_info *sbi, seg_t src_segno,
				int src_off, struct hmfs_summary *src_sum)
{
	struct gc_move_arg arg;
	struct hmfs_node *last = NULL, *this = NULL;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	block_t addr_in_par;
	int x_tag;
	bool is_current;
	
	is_current = get_summary_start_version(src_sum) == cm_i->new_version;

	prepare_move_argument(&arg, sbi, src_segno, src_off, src_sum,
			TYPE_DATA);

	while(1) {
		this = __get_node(sbi, arg.cp_i, arg.nid);

		if (IS_ERR(this))
			break;

		hmfs_bug_on(sbi, get_summary_type(get_summary_by_addr(sbi, L_ADDR(sbi, this)))
				!= SUM_TYPE_INODE);

		if (this == last)
			goto next;

		x_tag = le64_to_cpu(XATTR_HDR(arg.src)->h_magic);
		addr_in_par = XBLOCK_ADDR(this, x_tag);
		
		if (addr_in_par != arg.src_addr) {
			break;
		}
		
		hmfs_memcpy_atomic(JUMP(this, x_tag), &arg.dest_addr, 8);

		last = this;

next:
		if (arg.cp_i == cm_i->last_cp_i || is_current)
			break;
		arg.cp_i = get_next_checkpoint_info(sbi, arg.cp_i);
	}

	update_dest_summary(src_sum, arg.dest_sum);
}

static void move_node_block(struct hmfs_sb_info *sbi, seg_t src_segno,
			    unsigned int src_off, struct hmfs_summary *src_sum)
{
	struct hmfs_nat_block *last = NULL, *this = NULL;
	struct gc_move_arg args;
	block_t addr_in_par;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	bool is_current;

	is_current = get_summary_start_version(src_sum) == cm_i->new_version;

	prepare_move_argument(&args, sbi, src_segno, src_off, src_sum, TYPE_NODE);

	if (is_current) {
		//update NAT cache
		gc_update_nat_entry(NM_I(sbi), args.nid, args.dest_addr);
		return;
	}

	while (1) {
		this = get_nat_entry_block(sbi, args.cp_i->version, args.nid);
		if (IS_ERR(this))
			break;

		if (this == last)
			goto next;

		addr_in_par = le64_to_cpu(this->entries[args.ofs_in_node].block_addr);
		/* Src node has been COW or removed */
		if (addr_in_par != args.src_addr) {
			break;
		}

		hmfs_memcpy_atomic(&this->entries[args.ofs_in_node].block_addr,
				&args.dest_addr, 8);
		last = this;

next:
		if (args.cp_i == CM_I(sbi)->last_cp_i)
			break;
		args.cp_i = get_next_checkpoint_info(sbi, args.cp_i);
	}

	update_dest_summary(src_sum, args.dest_sum);
}

static void move_nat_block(struct hmfs_sb_info *sbi, seg_t src_segno, int src_off,
			   struct hmfs_summary *src_sum)
{
	void *last = NULL, *this = NULL;
	struct hmfs_checkpoint *hmfs_cp;
	struct hmfs_nat_node *nat_node;
	struct gc_move_arg args;
	nid_t par_nid;
	block_t addr_in_par;

	prepare_move_argument(&args, sbi, src_segno, src_off, src_sum, TYPE_NODE);

	while (1) {
		if (IS_NAT_ROOT(args.nid))
			this = args.cp_i->cp;
		else {
			par_nid = MAKE_NAT_NODE_NID(GET_NAT_NODE_HEIGHT(args.nid) - 1, 
							GET_NAT_NODE_OFS(args.nid)); 
			this = get_nat_node(sbi, args.cp_i->version, par_nid);
		}

		hmfs_bug_on(sbi, !this);
		if (this == last)
			goto next;

		if (IS_NAT_ROOT(args.nid)) {
			hmfs_cp = HMFS_CHECKPOINT(this);
			addr_in_par = le64_to_cpu(hmfs_cp->nat_addr);
		} else {
			nat_node = HMFS_NAT_NODE(this);
			addr_in_par = le64_to_cpu(nat_node->addr[args.ofs_in_node]);
		}

		if (addr_in_par != args.src_addr) {
			break;
		}

		if (IS_NAT_ROOT(args.nid)) {
			hmfs_memcpy_atomic(&hmfs_cp->nat_addr, &args.dest_addr, 8);
		} else {
			hmfs_memcpy_atomic(&nat_node->addr[args.ofs_in_node], 
					&args.dest_addr, 8);
		}

		last = this;

next:
		if (args.cp_i == CM_I(sbi)->last_cp_i)
			break;
		args.cp_i = get_next_checkpoint_info(sbi, args.cp_i);
	}

	update_dest_summary(src_sum, args.dest_sum);
}

/* Orphan blocks is not shared */
static void move_orphan_block(struct hmfs_sb_info *sbi, seg_t src_segno, 
				int src_off, struct hmfs_summary *src_sum)
{
	struct gc_move_arg args;
	struct hmfs_checkpoint *hmfs_cp;
	block_t cp_addr;
	prepare_move_argument(&args, sbi, src_segno, src_off, src_sum,
			TYPE_NODE);
	hmfs_cp = args.cp_i->cp;
	cp_addr = le64_to_cpu(hmfs_cp->orphan_addrs[get_summary_offset(src_sum)]);
	hmfs_bug_on(sbi, cp_addr != L_ADDR(args.src));
	hmfs_cp->orphan_addrs[get_summary_offset(src_sum)] = 
			cpu_to_le64(args.dest_addr);

	update_dest_summary(src_sum, args.dest_sum);
}

static void move_checkpoint_block(struct hmfs_sb_info *sbi, seg_t src_segno,
				int src_off, struct hmfs_summary *src_sum)
{
	struct gc_move_arg args;
	struct hmfs_checkpoint *prev_cp, *next_cp, *this_cp;
	struct checkpoint_info *cp_i;
	int i;
	block_t orphan_addr;
	__le64 *orphan;

	prepare_move_argument(&args, sbi, src_segno, src_off, src_sum,
			TYPE_NODE);

	cp_i = get_checkpoint_info(sbi, args.start_version, false);
	hmfs_bug_on(sbi, !cp_i);

	this_cp = HMFS_CHECKPOINT(args.src);
	next_cp = ADDR(sbi, le64_to_cpu(this_cp->next_cp_addr));
	prev_cp = ADDR(sbi, le64_to_cpu(this_cp->prev_cp_addr));

	hmfs_memcpy_atomic(&next_cp->prev_cp_addr, &args.dest_addr, 8);
	hmfs_memcpy_atomic(&prev_cp->next_cp_addr, &args.dest_addr, 8);
	cp_i->cp = HMFS_CHECKPOINT(args.dest);
	
	for (i = 0; i < NUM_ORPHAN_BLOCKS; i++) {
		orphan_addr = le64_to_cpu(this_cp->orphan_addrs[i]);
		if (orphan_addr == NULL_ADDR)
			break;
		orphan = ADDR(sbi, orphan_addr);
		hmfs_memcpy_atomic(orphan, &args.dest_addr, 8);
	}

	update_dest_summary(src_sum, args.dest_sum);
}

static void garbage_collect(struct hmfs_sb_info *sbi, seg_t segno)
{
	int off = 0;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	bool is_current, none_valid;
	nid_t nid;
	struct hmfs_summary_block *sum_blk;
	struct hmfs_summary *sum;
	int tmp=0;

	none_valid = !get_seg_entry(sbi, segno)->valid_blocks;

	if (none_valid)
		goto recycle;

	sum_blk = get_summary_block(sbi, segno);
	sum = sum_blk->entries;

	for (off = 0; off < HMFS_PAGE_PER_SEG; ++off, sum++) {
		is_current  = get_summary_start_version(sum) == cm_i->new_version;
		
		/*
		 * We ignore two kinds of blocks:
		 * 	- invalid blocks in older version
		 * 	- newest blocks in newest version(checkpoint is not written)
		 */
		if (!get_summary_valid_bit(sum) && !is_current)
			continue;

		if (is_current) {
			nid = get_summary_nid(sum);
			if (IS_ERR(get_node(sbi, nid)))
				continue;
		}

		hmfs_bug_on(sbi, get_summary_valid_bit(sum) && is_current);

		switch (get_summary_type(sum)) {
		case SUM_TYPE_DATA:
			move_data_block(sbi, segno, off, sum);
			break;
		case SUM_TYPE_XDATA:
			move_xdata_block(sbi, segno, off, sum);
			break;
		case SUM_TYPE_INODE:
		case SUM_TYPE_DN:
		case SUM_TYPE_IDN:
			move_node_block(sbi, segno, off, sum);
			break;
		case SUM_TYPE_NATN:
		case SUM_TYPE_NATD:
			hmfs_bug_on(sbi, is_current);
			move_nat_block(sbi, segno, off, sum);
			continue;
		case SUM_TYPE_ORPHAN:
			hmfs_bug_on(sbi, is_current);
			move_orphan_block(sbi, segno, off, sum);
			continue;
		case SUM_TYPE_CP:
			hmfs_bug_on(sbi, is_current);
			move_checkpoint_block(sbi, segno, off, sum);
			continue;
		default:
			hmfs_bug_on(sbi, 1);
			break;
		}
	}

	hmfs_dbg("tmp:%d\n",tmp);
recycle:
	recycle_segment(sbi, segno, none_valid);
}

int hmfs_gc(struct hmfs_sb_info *sbi, int gc_type)
{
	int ret = -1;
	seg_t segno, start_segno = NULL_SEGNO;
	struct hmfs_checkpoint *hmfs_cp = CM_I(sbi)->last_cp_i->cp;
	bool do_cp = false;
	int total_segs = TOTAL_SEGS(sbi);
	int time_retry = 0;
	int max_retry = (total_segs + MAX_SEG_SEARCH - 1) / MAX_SEG_SEARCH;

	hmfs_dbg("Enter GC\n");
	INC_GC_TRY(STAT_I(sbi));
	if (!(sbi->sb->s_flags & MS_ACTIVE))
		goto out;

	if (hmfs_cp->state == HMFS_NONE)
		set_fs_state(hmfs_cp, HMFS_GC);

	if (gc_type == BG_GC && has_not_enough_free_segs(sbi)) {
		gc_type = FG_GC;
	}

gc_more:
	hmfs_dbg("Before get victim:%ld %ld %ld\n", (unsigned long)total_valid_blocks(sbi),
			(unsigned long)CM_I(sbi)->alloc_block_count, 
			(unsigned long)CM_I(sbi)->valid_block_count);
	if (!get_victim(sbi, &segno, gc_type))
		goto out;
	ret = 0;

	hmfs_dbg("GC Victim:%d %d\n", (int)segno, get_valid_blocks(sbi, segno));
	INC_GC_REAL(STAT_I(sbi));

	/*
	 * If a segment does not contains any valid blocks, we do not 
	 * need to set it as PREFREE. And we could reuse it right now, which
	 * could improve GC efficiency
	 */
	if (get_seg_entry(sbi, segno)->valid_blocks) {
		hmfs_memcpy_atomic(sbi->gc_logs, &segno, 4);		
		sbi->gc_logs++;
		sbi->nr_gc_segs++;
		hmfs_memcpy_atomic(&hmfs_cp->nr_gc_segs, &sbi->nr_gc_segs, 4);
	}

	COUNT_GC_BLOCKS(STAT_I(sbi), HMFS_PAGE_PER_SEG - 
			get_valid_blocks(sbi, segno));

	hmfs_bug_on(sbi, total_valid_blocks(sbi) != CM_I(sbi)->valid_block_count);
	garbage_collect(sbi, segno);

	hmfs_dbg("GC:%ld %ld %ld\n", (unsigned long)total_valid_blocks(sbi),
			(unsigned long)CM_I(sbi)->alloc_block_count, 
			(unsigned long)CM_I(sbi)->valid_block_count);
	hmfs_bug_on(sbi, total_valid_blocks(sbi) != CM_I(sbi)->valid_block_count);

	if (start_segno == NULL_SEGNO)
		start_segno = segno;

	/* If space is limited, we might need to scan the whole NVM */
	if (need_deep_scan(sbi)) {
		do_cp = true;
		time_retry++;
		if (time_retry < max_retry)
			goto gc_more;
		goto out;
	}

	/* In FG_GC, we atmost scan sbi->nr_max_fg_segs segments */
	if (has_not_enough_free_segs(sbi) && need_more_scan(sbi, segno, start_segno))
		goto gc_more;

out:
	if (do_cp) {
		ret= write_checkpoint(sbi, true);
		hmfs_bug_on(sbi, ret);
		hmfs_dbg("Write checkpoint done\n");
	}

	unlock_gc(sbi);
	hmfs_dbg("Exit GC:%ld %ld %ld\n", (unsigned long)total_valid_blocks(sbi),
			(unsigned long)CM_I(sbi)->alloc_block_count, 
			(unsigned long)CM_I(sbi)->valid_block_count);
	return ret;
}

static int gc_thread_func(void *data)
{
	struct hmfs_sb_info *sbi = data;
	wait_queue_head_t *wq = &(sbi->gc_thread->gc_wait_queue_head);
	long wait_ms = 0;
	printk(KERN_INFO "start gc thread\n");
	wait_ms = sbi->gc_thread_min_sleep_time;

	do {
		if (try_to_freeze())
			continue;
		else
			wait_event_interruptible_timeout(*wq, kthread_should_stop(),
					msecs_to_jiffies(wait_ms));

		if (kthread_should_stop())
			break;

		if (sbi->sb->s_writers.frozen >= SB_FREEZE_WRITE) {
			wait_ms = sbi->gc_thread_max_sleep_time;
			continue;
		}

		if (!trylock_gc(sbi))
			continue;

		if (has_enough_invalid_blocks(sbi))
			wait_ms = decrease_sleep_time(sbi, wait_ms);
		else
			wait_ms = increase_sleep_time(sbi, wait_ms);

		if (hmfs_gc(sbi, BG_GC)) {
//			if (wait_ms == sbi->gc_thread_max_sleep_time)
//				wait_ms = GC_THREAD_NOGC_SLEEP_TIME;
		}
	} while (!kthread_should_stop());
	return 0;
}

int start_gc_thread(struct hmfs_sb_info *sbi)
{
	struct hmfs_gc_kthread *gc_thread = NULL;
	int err = 0;
	unsigned long start_addr, end_addr;

	start_addr = sbi->phys_addr;
	end_addr = sbi->phys_addr + sbi->initsize;
	sbi->last_victim[GC_CB] = 0;
	sbi->last_victim[GC_GREEDY] = 0;

	gc_thread = kmalloc(sizeof(struct hmfs_gc_kthread), GFP_KERNEL);
	if (!gc_thread) {
		err = -ENOMEM;
		goto out;
	}

	sbi->gc_thread = gc_thread;
	init_waitqueue_head(&(sbi->gc_thread->gc_wait_queue_head));
	sbi->gc_thread->hmfs_gc_task = kthread_run(gc_thread_func, sbi,
										"hmfs_gc-%lu:->%lu",
										start_addr, end_addr);
	if (IS_ERR(gc_thread->hmfs_gc_task)) {
		err = PTR_ERR(gc_thread->hmfs_gc_task);
		kfree(gc_thread);
		sbi->gc_thread = NULL;
	}
out:
	return err;
}

void stop_gc_thread(struct hmfs_sb_info *sbi)
{
	struct hmfs_gc_kthread *gc_thread = sbi->gc_thread;
	if (!gc_thread)
		return;
	kthread_stop(gc_thread->hmfs_gc_task);
	kfree(gc_thread);
	sbi->gc_thread = NULL;
}

int init_gc_logs(struct hmfs_sb_info *sbi)
{
	seg_t segno;
	int ret;
	block_t addr;
	struct hmfs_checkpoint *hmfs_cp = CM_I(sbi)->last_cp_i->cp;

	ret = get_new_segment(sbi, &segno);
	if (!ret) {
		addr = __cal_page_addr(sbi, segno, 0);
		sbi->gc_logs = ADDR(sbi, addr);
		sbi->nr_gc_segs = 0;
		hmfs_cp->gc_logs = cpu_to_le32(segno);
		hmfs_cp->nr_gc_segs = 0;
	}

	return ret;
}

/* Must call move_to_next_checkpoint() before this function */
void reinit_gc_logs(struct hmfs_sb_info *sbi)
{
	seg_t old_segno;
	block_t old_addr;
	struct free_segmap_info *free_i = FREE_I(sbi);
	struct hmfs_checkpoint *hmfs_cp = CM_I(sbi)->last_cp_i->cp;

	old_addr = L_ADDR(sbi, sbi->gc_logs);
	old_segno = GET_SEGNO(sbi, old_addr);

	/* 
	 * We try to get a different segments for gc logs in order to protect
	 * NVM area. And we have make a checkpoint now. We need to set gc_logs
	 * and nr_gc_segs for new 'last checkpoint'
	 */
	if (!init_gc_logs(sbi)) {
		lock_write_segmap(free_i);
		if (test_and_clear_bit(old_segno, free_i->free_segmap))
			free_i->free_segments++;
		unlock_write_segmap(free_i);
	} else {
		hmfs_cp->gc_logs = cpu_to_le32(old_segno);
		hmfs_cp->nr_gc_segs = 0;
	}
}

void init_gc_stat(struct hmfs_sb_info *sbi) {
	struct hmfs_stat_info *si = STAT_I(sbi);
	int i;

	si->nr_gc_try = 0;
	si->nr_gc_real = 0;
	si->nr_gc_blocks = 0;
	for (i = 0; i < SIZE_GC_RANGE; i++) {
		si->nr_gc_blocks_range[i] = 0;
	}
}

