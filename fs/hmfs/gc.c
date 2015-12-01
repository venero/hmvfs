#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/freezer.h>

#include "hmfs.h"
#include "hmfs_fs.h"
#include "gc.h"
#include "segment.h"
#include "node.h"
#include "xattr.h"

static void select_policy(struct hmfs_sb_info *sbi, int gc_type,
			  struct victim_sel_policy *p)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);

	p->gc_mode = gc_type == BG_GC ? GC_CB : GC_GREEDY;
	p->dirty_segmap = dirty_i->dirty_segmap;
	p->offset = sbi->last_victim[p->gc_mode];
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
	if (p->gc_mode == GC_GREEDY)
		return get_seg_entry(sbi, segno)->valid_blocks;
	else
		return get_cb_cost(sbi, segno);
}

static int __get_victim(struct hmfs_sb_info *sbi, seg_t *result,
			int gc_type)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	struct victim_sel_policy p;
	unsigned int max_cost;
	unsigned long cost;
	seg_t segno;
	struct hmfs_summary_block *sum_blk = NULL;
	int nsearched = 0;

	select_policy(sbi, gc_type, &p);
	p.min_segno = NULL_SEGNO;
	p.min_cost = max_cost = get_max_cost(sbi, &p);
	mutex_lock(&dirty_i->seglist_lock);

	while (1) {
		segno = find_next_bit(p.dirty_segmap, TOTAL_SEGS(sbi), p.offset);

		hmfs_bug_on(sbi, segno == CURSEG_I(sbi)[0].segno || 
						segno ==CURSEG_I(sbi)[1].segno);
		if (segno >= TOTAL_SEGS(sbi)) {
			if (sbi->last_victim[p.gc_mode]) {
				sbi->last_victim[p.gc_mode] = 0;
				p.offset = 0;
				continue;
			}
			break;
		}
		else {
			p.offset = segno + 1;
		}

		sum_blk = get_summary_block(sbi, segno);
		/* Don't collect segment which is current segment */
		if (get_summary_start_version(&sum_blk->entries[0]) == 
						CM_I(sbi)->new_version) {
			WARN_ON(1);
			continue;
		}

		cost = get_gc_cost(sbi, segno, &p);

		if (p.min_cost > cost) {
			p.min_segno = segno;
			p.min_cost = cost;
		}

		if (cost == max_cost)
			continue;

		if (nsearched++ >= MAX_SEG_SEARCH) {
			sbi->last_victim[p.gc_mode] = segno;
			break;
		}
	}

	if (p.min_segno != NULL_SEGNO) {
		*result = p.min_segno;
	}
	mutex_unlock(&dirty_i->seglist_lock);

	return (p.min_segno == NULL_SEGNO) ? 0 : 1;
}

static int get_victim(struct hmfs_sb_info *sbi, seg_t *result, int gc_type)
{
	int ret;
	struct sit_info *sit_i = SIT_I(sbi);

	mutex_lock(&sit_i->sentry_lock);
	ret = __get_victim(sbi, result, gc_type);
	mutex_unlock(&sit_i->sentry_lock);
	return ret;
}

static int prepare_move_argument(struct gc_move_arg *arg,
				  struct hmfs_sb_info *sbi, seg_t mv_segno,
				  unsigned mv_offset, struct hmfs_summary *sum,
				  int type)
{
	seg_t test_segno;
	int test_segoff;
	struct hmfs_checkpoint *hmfs_cp = CM_I(sbi)->last_cp_i->cp;
	u64 state_arg;

	arg->start_version = get_summary_start_version(sum);
	arg->nid = get_summary_nid(sum);
	arg->ofs_in_node = get_summary_offset(sum);

	arg->cp_i = get_checkpoint_info(sbi, arg->start_version, true);
	if (type == TYPE_DATA) {
		get_current_segment_state(sbi, &test_segno, &test_segoff,
						CURSEG_DATA);
		arg->dest = alloc_new_data_block(NULL, 0);
	} else {
		get_current_segment_state(sbi, &test_segno, &test_segoff, 
						CURSEG_NODE);
		arg->dest = alloc_new_node(sbi, 0, NULL, 0);
	}
	
	//TODO: handle error
	if (IS_ERR(arg->dest))
		return -ENOSPC;

	if ((!hmfs_cp->state_arg || !test_segoff) &&
			likely(!sbi->recovery_doing)){
		state_arg = test_segno + 1;
		state_arg = state_arg << 32;
		state_arg |= mv_segno & 0xffffffff;
		set_fs_state_arg(hmfs_cp, state_arg);
	}

	arg->dest_addr = L_ADDR(sbi, arg->dest);
	arg->dest_sum = get_summary_by_addr(sbi, arg->dest_addr);
	arg->src_addr = __cal_page_addr(sbi, mv_segno, mv_offset);
	arg->src = ADDR(sbi, arg->src_addr);
	return 0;
}

static void update_dest_summary(struct hmfs_summary *src_sum,
				struct hmfs_summary *dest_sum)
{
	dest_sum->start_version = src_sum->start_version;
	dest_sum->nid = src_sum->nid;
	dest_sum->ofs_in_node = src_sum->ofs_in_node;
	/* should not set valid bit */
	set_summary_type(dest_sum, get_summary_type(src_sum));
}

static void move_data_block(struct hmfs_sb_info *sbi, seg_t src_segno,
			    int src_off, struct hmfs_summary *src_sum)
{
	struct gc_move_arg args;
	struct hmfs_node *last = NULL, *this = NULL;
	struct hmfs_summary *par_sum = NULL;
	block_t addr_in_par;

	/* 1. read summary of source blocks */
	prepare_move_argument(&args, sbi, src_segno, src_off, src_sum,
			       TYPE_DATA);

	/* 2. move blocks */
	hmfs_memcpy(args.dest, args.src, HMFS_PAGE_SIZE);

	while (1) {
		/* 3. get the parent node which hold the pointer point to source node */
		this = __get_node(sbi, args.cp_i, args.nid);
		par_sum = get_summary_by_addr(sbi, L_ADDR(sbi, this));

		if (IS_ERR(this)) {
			/* the node(args.nid) has been deleted */
			break;
		}

		hmfs_bug_on(sbi, get_summary_type(par_sum) != SUM_TYPE_INODE &&
						get_summary_type(par_sum) != SUM_TYPE_DN);

		/* Now the pointer contains in direct node have been changed last time */
		if (this == last)
			goto next;

		/* Now src data block has been COW or parent node has been removed */
		if (get_summary_type(par_sum) == SUM_TYPE_INODE) {
			addr_in_par = le64_to_cpu(this->i.i_addr[args.ofs_in_node]);
		} else {
			addr_in_par = le64_to_cpu(this->dn.addr[args.ofs_in_node]);
		}

		/*
		 * In recovery, the address stored in parent node would be
		 * arg.src_addr or arg.dest_addr. Because GC might terminate
		 * in the loop change this address.
		 * In normal GC, we should stop when addr_in_par != src_addr,
		 * now direct node or inode in laster checkpoint would never
		 * refer to this data block
		 */
		if ((!sbi->recovery_doing && addr_in_par != args.src_addr) ||
				(sbi->recovery_doing && addr_in_par != args.src_addr &&
				addr_in_par != args.dest_addr)) {
			break;
		}

		/* 
		 * We should use atomic write here, otherwise, if system crash
		 * during wrting address, i.i_addr and dn.addr would be invalid,
		 * whose value is neither args.dest_addr nor args.src_addr. Therefore,
		 * if recovery process, it would terminate in this checkpoint
		 */
		if (get_summary_type(par_sum) == SUM_TYPE_INODE) {
			hmfs_memcpy_atomic(&this->i.i_addr[args.ofs_in_node], 
							&args.dest_addr, 8);
		} else {
			hmfs_memcpy_atomic(&this->dn.addr[args.ofs_in_node],
							&args.dest_addr, 8);
		}

		last = this;

next:
		/* cp_i is the lastest checkpoint, stop */
		if (args.cp_i == CM_I(sbi)->last_cp_i) {
			break;
		}
		args.cp_i = get_next_checkpoint_info(sbi, args.cp_i);
	}

	/* 5. Update summary infomation of dest block */
	update_dest_summary(src_sum, args.dest_sum);
}

static void recycle_segment(struct hmfs_sb_info *sbi, seg_t segno)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct free_segmap_info *free_i = FREE_I(sbi);
	struct seg_entry *seg_entry;

	mutex_lock(&sit_i->sentry_lock);

	/* clean dirty bit */
	if (!test_and_set_bit(segno, sit_i->dirty_sentries_bitmap)) {
		sit_i->dirty_sentries++;
	}
	seg_entry = get_seg_entry(sbi, segno);
	seg_entry->valid_blocks = 0;
	seg_entry->mtime = get_seconds();

	mutex_unlock(&sit_i->sentry_lock);

	write_lock(&free_i->segmap_lock);
	/* set free bit */
	if (!test_and_set_bit(segno, free_i->free_segmap))
		free_i->free_segments++;
	write_unlock(&free_i->segmap_lock);

	/* Now we have recycle HMFS_PAGE_PER_SEG blocks and update cm_i */
	spin_lock(&cm_i->stat_lock);
	cm_i->alloc_block_count -= HMFS_PAGE_PER_SEG;
	spin_unlock(&cm_i->stat_lock);
}

static void move_xdata_block(struct hmfs_sb_info *sbi, seg_t src_segno,
				int src_off, struct hmfs_summary *src_sum)
{
	struct gc_move_arg arg;
	struct hmfs_node *last = NULL, *this = NULL;
	struct hmfs_summary *par_sum = NULL;
	block_t addr_in_par;
	int x_tag;

	prepare_move_argument(&arg, sbi, src_segno, src_off, src_sum,
					TYPE_DATA);

	hmfs_memcpy(arg.dest, arg.src, HMFS_PAGE_SIZE);

	while(1) {
		this = __get_node(sbi, arg.cp_i, arg.nid);
		par_sum = get_summary_by_addr(sbi, L_ADDR(sbi, this));

		if (IS_ERR(this))
			break;

		hmfs_bug_on(sbi, get_summary_type(par_sum) != SUM_TYPE_INODE);

		if (this == last)
			goto next;

		x_tag = le64_to_cpu(XATTR_HDR(arg.src)->h_magic);
		addr_in_par = le64_to_cpu(*(__le64 *)((char *)this + x_tag));
		
		if ((!sbi->recovery_doing && addr_in_par != arg.src_addr) ||
				(sbi->recovery_doing && addr_in_par != arg.src_addr &&
				addr_in_par != arg.dest_addr)) {
			break;
		}
		
		hmfs_memcpy_atomic((char *)this + x_tag, &arg.dest_addr, 8);

		last = this;

next:
		if (arg.cp_i == CM_I(sbi)->last_cp_i)
			break;
		arg.cp_i = get_next_checkpoint_info(sbi, arg.cp_i);
	}

	update_dest_summary(src_sum, arg.dest_sum);

}

static void gc_data_segment(struct hmfs_sb_info *sbi, struct hmfs_summary *sum,
			     unsigned int segno)
{
	int off = 0;
	struct hmfs_checkpoint *hmfs_cp = CM_I(sbi)->last_cp_i->cp;

	if (!sbi->recovery_doing)
		set_fs_state(hmfs_cp, HMFS_GC_DATA);
	
	for (off = 0; off < HMFS_PAGE_PER_SEG; ++off, sum++) {
		if (!get_summary_valid_bit(sum))
			continue;

		switch (get_summary_type(sum)) {
		case SUM_TYPE_DATA:
			move_data_block(sbi, segno, off, sum);
			break;
		case SUM_TYPE_XDATA:
			move_xdata_block(sbi, segno, off, sum);
		default:
			hmfs_bug_on(sbi, 1);
		}
	}
}

static void move_node_block(struct hmfs_sb_info *sbi, seg_t src_segno,
			    unsigned int src_off, struct hmfs_summary *src_sum)
{
	struct hmfs_nat_block *last = NULL, *this = NULL;
	struct gc_move_arg args;
	block_t addr_in_par;

	prepare_move_argument(&args, sbi, src_segno, src_off, src_sum, TYPE_NODE);

	hmfs_memcpy(args.dest, args.src, HMFS_PAGE_SIZE);

	while (1) {
		this = get_nat_entry_block(sbi, args.cp_i->version, args.nid);
		if (IS_ERR(this))
			break;

		if (this == last)
			goto next;

		addr_in_par = le64_to_cpu(this->entries[args.ofs_in_node].block_addr);
		/* Src node has been COW or removed */
		if ((!sbi->recovery_doing && addr_in_par != args.src_addr) ||
				(sbi->recovery_doing && addr_in_par != args.src_addr &&
				addr_in_par != args.dest_addr)) {
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

	hmfs_memcpy(args.dest, args.src, HMFS_PAGE_SIZE);

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
			hmfs_cp = (struct hmfs_checkpoint *)this;
			addr_in_par = le64_to_cpu(hmfs_cp->nat_addr);
		} else {
			nat_node = (struct hmfs_nat_node *)this;
			addr_in_par = le64_to_cpu(nat_node->addr[args.ofs_in_node]);
		}

		if ((!sbi->recovery_doing && addr_in_par != args.src_addr) ||
				(sbi->recovery_doing && addr_in_par != args.src_addr &&
				addr_in_par != args.dest_addr)) {
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

static void move_checkpoint_block(struct hmfs_sb_info *sbi, seg_t src_segno,
				  int src_off, struct hmfs_summary *src_sum)
{
	struct gc_move_arg args;
	struct hmfs_checkpoint *prev_cp, *next_cp, *this_cp;
	struct checkpoint_info *cp_i;

	prepare_move_argument(&args, sbi, src_segno, src_off, src_sum,
			       TYPE_NODE);
	hmfs_memcpy(args.dest, args.src, HMFS_PAGE_SIZE);

	cp_i = get_checkpoint_info(sbi, args.start_version, false);
	hmfs_bug_on(sbi, !cp_i);

	this_cp = (struct hmfs_checkpoint *)args.src;
	next_cp = ADDR(sbi, le64_to_cpu(this_cp->next_cp_addr));
	prev_cp = ADDR(sbi, le64_to_cpu(this_cp->prev_cp_addr));

	next_cp->prev_cp_addr = cpu_to_le64(args.dest_addr);
	prev_cp->next_cp_addr = cpu_to_le64(args.dest_addr);

	update_dest_summary(src_sum, args.dest_sum);
	cp_i->cp = (struct hmfs_checkpoint *)args.dest_addr;
}

static void gc_node_segment(struct hmfs_sb_info *sbi, struct hmfs_summary *sum,
			     seg_t segno)
{
	int off = 0;
	struct hmfs_checkpoint *hmfs_cp = CM_I(sbi)->last_cp_i->cp;

	if (!sbi->recovery_doing)
		set_fs_state(hmfs_cp, HMFS_GC_NODE);

	for (off = 0; off < HMFS_PAGE_PER_SEG; ++off, sum++) {
		if (!get_summary_valid_bit(sum))
			continue;

		switch (get_summary_type(sum)) {
		case SUM_TYPE_IDN:
			move_node_block(sbi, segno, off, sum);
			break;
		case SUM_TYPE_INODE:
			move_node_block(sbi, segno, off, sum);
			break;
		case SUM_TYPE_DN:
			move_node_block(sbi, segno, off, sum);
			break;
		case SUM_TYPE_NATN:
			move_nat_block(sbi, segno, off, sum);
			break;
		case SUM_TYPE_NATD:
			move_nat_block(sbi, segno, off, sum);
			break;
		case SUM_TYPE_CP:
			move_checkpoint_block(sbi, segno, off, sum);
			break;
		default:
			hmfs_bug_on(sbi, 1);
			break;
		}
	}
}

static void garbage_collect(struct hmfs_sb_info *sbi, seg_t segno)
{
	struct hmfs_summary_block *sum_blk;
	int type;

	sum_blk = get_summary_block(sbi, segno);

	type = get_summary_type(&(sum_blk->entries[0]));
	if (type == SUM_TYPE_DATA || type == SUM_TYPE_XDATA) {
		gc_data_segment(sbi, sum_blk->entries, segno);
	} else {
		gc_node_segment(sbi, sum_blk->entries, segno);
	}
	recycle_segment(sbi, segno);
}

void recovery_gc_crash(struct hmfs_sb_info *sbi, struct hmfs_checkpoint *hmfs_cp)
{
	seg_t victim_segno, dest_segno;
	u64 state_arg;
	u8 state;
	struct curseg_info *seg_i = NULL;
	struct hmfs_summary_block *sum_blk;

	state_arg = le64_to_cpu(hmfs_cp->state_arg);

	if (!state_arg)
		return;

	dest_segno = (state_arg >> 32) - 1;
	victim_segno = state_arg | ~0xffffffff;
	state = hmfs_cp->state;
	sum_blk = get_summary_block(sbi, victim_segno);
	hmfs_dbg("GC recover:%d with state:%c\n", (int)victim_segno, state);

	sbi->recovery_doing = 1;
	switch (state) {
	case HMFS_GC_DATA:
		seg_i = &(CURSEG_I(sbi)[CURSEG_DATA]);

		/* Test whether GC crash in new segment */
		if (seg_i->segno != dest_segno) {
			seg_i->next_segno = dest_segno;
			seg_i->use_next_segno = true;
		}
		gc_data_segment(sbi, sum_blk->entries, victim_segno);
		break;
	case HMFS_GC_NODE:
		seg_i = &(CURSEG_I(sbi)[CURSEG_NODE]);

		if (seg_i->segno != dest_segno) {
			seg_i->next_segno = dest_segno;
			seg_i->use_next_segno = true;
		}
		gc_node_segment(sbi, sum_blk->entries, victim_segno);
		break;
	default:
		hmfs_bug_on(sbi, 1);
	}
	sbi->recovery_doing = 0;
}

int hmfs_gc(struct hmfs_sb_info *sbi, int gc_type)
{
	int ret = -1;
	seg_t segno;
	struct sit_info *sit_i = SIT_I(sbi);
	struct hmfs_stat_info *stat_i = sbi->stat_info;

	hmfs_dbg("Enter GC\n");
	stat_i->nr_gc_try++;
	if (!(sbi->sb->s_flags & MS_ACTIVE))
		goto out;
	
	/* Write checkpoint before GC */
	if (sit_i->dirty_sentries) {
		ret = write_checkpoint(sbi, false);
		if (ret)
			goto out;
	}

gc_more:
	if (gc_type == BG_GC && has_not_enough_free_segs(sbi)) {
		gc_type = FG_GC;
	}

	if (!get_victim(sbi, &segno, gc_type))
		goto out;
	ret = 0;

	hmfs_dbg("GC Victim:%d\n", (int)segno);
	stat_i->nr_gc_real++;
	garbage_collect(sbi, segno);
	
	if (sit_i->sentries) {
		ret = write_checkpoint(sbi, true);
		if (ret)
			goto out;
	}
	
	if (has_not_enough_free_segs(sbi))
		goto gc_more;

out:
	mutex_unlock(&sbi->gc_mutex);
	hmfs_dbg("Exit GC\n");
	return ret;
}

static int gc_thread_func(void *data)
{
	struct hmfs_sb_info *sbi = data;
	wait_queue_head_t *wq = &(sbi->gc_thread->gc_wait_queue_head);
	long wait_ms = 0;
	printk(KERN_INFO "start gc thread\n");
	wait_ms = GC_THREAD_MIN_SLEEP_TIME;

	do {
		if (try_to_freeze())
			continue;
		else
			wait_event_interruptible_timeout(*wq, kthread_should_stop(),
							 msecs_to_jiffies(wait_ms));

		if (kthread_should_stop())
			break;

		if (sbi->sb->s_writers.frozen >= SB_FREEZE_WRITE) {
			wait_ms = GC_THREAD_MAX_SLEEP_TIME;
			continue;
		}

		if (!mutex_trylock(&sbi->gc_mutex))
			continue;

		if (has_enough_invalid_blocks(sbi))
			wait_ms = decrease_sleep_time(wait_ms);
		else
			wait_ms = increase_sleep_time(wait_ms);

		if (hmfs_gc(sbi, BG_GC))
			wait_ms = GC_THREAD_NOGC_SLEEP_TIME;
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
