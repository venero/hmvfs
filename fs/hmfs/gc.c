#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/freezer.h>

#include "hmfs.h"
#include "hmfs_fs.h"
#include "gc.h"
#include "segment.h"
#include "node.h"

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
		age = 100
		 - div64_u64(100 * (mtime - sit_i->min_mtime),
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

static int prepare_move_arguments(struct gc_move_arg *arg,
				  struct hmfs_sb_info *sbi, seg_t segno,
				  unsigned offset, struct hmfs_summary *sum,
				  int type)
{
	arg->start_version = get_summary_start_version(sum);
	arg->dead_version = get_summary_dead_version(sum);
	arg->nid = get_summary_nid(sum);
	arg->ofs_in_node = get_summary_offset(sum);
	arg->count = get_summary_count(sum);

	if (!arg->dead_version)
		arg->dead_version = CM_I(sbi)->new_version;

	arg->cp_i = get_checkpoint_info(sbi, arg->start_version);
	if (type == TYPE_DATA)
		arg->dest = alloc_new_data_block(NULL, 0);
	else
		arg->dest = alloc_new_node(sbi, 0, NULL, 0);

	if (IS_ERR(arg->dest))
		return -ENOSPC;

	arg->dest_addr = L_ADDR(sbi, arg->dest);
	arg->dest_sum = get_summary_by_addr(sbi, arg->dest_addr);
	arg->src_addr = __cal_page_addr(sbi, segno, offset);
	arg->src = ADDR(sbi, arg->src_addr);
	return 0;
}

static void update_dest_summary(struct hmfs_summary *src_sum,
				struct hmfs_summary *dest_sum)
{
	dest_sum->start_version = src_sum->start_version;
	dest_sum->nid = src_sum->nid;
	dest_sum->dead_version = src_sum->dead_version;
	dest_sum->count = src_sum->count;
	dest_sum->ont = src_sum->ont;
}

static void move_data_block(struct hmfs_sb_info *sbi, seg_t src_segno,
			    int src_off, struct hmfs_summary *src_sum)
{
	struct gc_move_arg args;
	struct hmfs_node *last = NULL, *this = NULL;
	struct hmfs_summary *par_sum = NULL;

	/* 1. read summary of source blocks */
	prepare_move_arguments(&args, sbi, src_segno, src_off, src_sum,
			       SUM_TYPE_DATA);

	/* 2. move blocks */
	hmfs_memcpy(args.dest, args.src, HMFS_PAGE_SIZE);

	while (args.start_version < args.dead_version) {
		/* 3. get the parent node which hold the pointer point to source node */
		this = __get_node(sbi, args.cp_i, args.nid);
		par_sum = get_summary_by_addr(sbi, L_ADDR(sbi, this));
		hmfs_bug_on(sbi, IS_ERR(this));
		hmfs_bug_on(sbi, get_summary_type(par_sum) != SUM_TYPE_INODE &&
						get_summary_type(par_sum) != SUM_TYPE_DN);

		/* Now the pointer contains in direct node have been changed last time */
		if (this == last)
			goto next;

		hmfs_bug_on(sbi, le64_to_cpu(this->dn.addr[args.ofs_in_node]) !=
		       args.src_addr);

		if (get_summary_type(par_sum) == SUM_TYPE_INODE)
			this->i.i_addr[args.ofs_in_node] = args.dest_addr;
		else
			this->dn.addr[args.ofs_in_node] = args.dest_addr;

		last = this;

		/* Update counter */
		if (++args.nrchange >= args.count)
			break;

next:
		args.parent_addr = L_ADDR(sbi, this);
		args.parent_sum = get_summary_by_addr(sbi, args.parent_addr);

		args.start_version = get_summary_dead_version(args.parent_sum);
		if (!args.start_version)
			break;

		args.cp_i = get_checkpoint_info(sbi, args.start_version);
	}

	/* 5. Update summary infomation of dest block */
	update_dest_summary(src_sum, args.dest_sum);
}

static void recycle_segment(struct hmfs_sb_info *sbi, seg_t segno)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct free_segmap_info *free_i = FREE_I(sbi);
	struct hmfs_sit_entry *sit_entry;
	struct seg_entry *seg_entry;

	mutex_lock(&sit_i->sentry_lock);

	/* clean dirty bit */
	if (test_and_clear_bit(segno, sit_i->dirty_sentries_bitmap)) {
		sit_i->dirty_sentries--;
	}
	sit_entry = get_sit_entry(sbi, segno);
	seg_entry = get_seg_entry(sbi, segno);
	seg_entry->valid_blocks = 0;
	seg_entry->mtime = get_seconds();
	seg_info_to_raw_sit(seg_entry, sit_entry);

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

static void gc_data_segments(struct hmfs_sb_info *sbi, struct hmfs_summary *sum,
			     unsigned int segno)
{
	int off = 0;

	for (off = 0; off < HMFS_PAGE_PER_SEG; ++off, sum++) {
		if (!le16_to_cpu(sum->count))
			continue;

		move_data_block(sbi, segno, off, sum);
	}
}

static void move_node_block(struct hmfs_sb_info *sbi, seg_t src_segno,
			    unsigned int src_off, struct hmfs_summary *src_sum,
			    int type)
{
	struct hmfs_nat_block *last = NULL, *this = NULL;
	struct gc_move_arg args;

	prepare_move_arguments(&args, sbi, src_segno, src_off, src_sum, type);

	hmfs_memcpy(args.dest, args.src, HMFS_PAGE_SIZE);

	while (args.start_version < args.dead_version) {
		this = get_nat_entry_block(sbi, args.cp_i->version, args.nid);
		if (IS_ERR(this) || this == last)
			goto next;

		hmfs_bug_on(sbi, le64_to_cpu(this->entries[args.ofs_in_node].block_addr)
		       != args.src_addr);

		this->entries[args.ofs_in_node].block_addr = cpu_to_le64(args.dest_addr);
		last = this;

		if (++args.nrchange >= args.count)
			break;
next:
		args.parent_addr = L_ADDR(sbi, this);
		args.parent_sum = get_summary_by_addr(sbi, args.parent_addr);

		args.start_version = get_summary_dead_version(args.parent_sum);
		if (!args.start_version)
			break;
		args.cp_i = get_checkpoint_info(sbi, args.start_version);
	}

	update_dest_summary(src_sum, args.dest_sum);
}

static void move_nat_block(struct hmfs_sb_info *sbi, seg_t src_segno, int src_off,
			   struct hmfs_summary *src_sum, int type)
{
	void *last = NULL, *this = NULL;
	struct hmfs_checkpoint *hmfs_cp;
	struct hmfs_nat_node *nat_node;
	struct gc_move_arg args;
	nid_t par_nid;

	prepare_move_arguments(&args, sbi, src_segno, src_off, src_sum, type);

	hmfs_memcpy(args.dest, args.src, HMFS_PAGE_SIZE);

	while (args.start_version < args.dead_version) {
		if (IS_NAT_ROOT(args.nid))
			this = args.cp_i->cp;
		else {
			par_nid = MAKE_NAT_NODE_NID(GET_NAT_NODE_HEIGHT(args.nid) - 1, 
							GET_NAT_NODE_OFS(args.nid)); 
			this = get_nat_node(sbi, args.cp_i->version, par_nid);
		}

		if (this == last)
			goto next;

		if (IS_NAT_ROOT(args.nid)) {
			hmfs_cp = (struct hmfs_checkpoint *)this;
			hmfs_cp->nat_addr = cpu_to_le64(args.dest_addr);
		} else {
			nat_node = (struct hmfs_nat_node *)this;
			nat_node->addr[args.ofs_in_node] = cpu_to_le64(args.dest_addr);
		}

		last = this;

		if (++args.nrchange >= args.count)
			break;
next:
		args.parent_addr = L_ADDR(sbi, this);
		args.parent_sum = get_summary_by_addr(sbi, args.parent_addr);

		args.start_version = get_summary_dead_version(args.parent_sum);
		if (!args.start_version)
			break;
		args.cp_i = get_checkpoint_info(sbi, args.start_version);
	}

	update_dest_summary(src_sum, args.dest_sum);
}

static void move_checkpoint_block(struct hmfs_sb_info *sbi, seg_t src_segno,
				  int src_off, struct hmfs_summary *src_sum)
{
	struct gc_move_arg args;
	struct hmfs_checkpoint *prev_cp, *next_cp, *this_cp;
	struct checkpoint_info *cp_i;

	prepare_move_arguments(&args, sbi, src_segno, src_off, src_sum,
			       SUM_TYPE_CP);
	hmfs_memcpy(args.dest, args.src, HMFS_PAGE_SIZE);

	cp_i = get_checkpoint_info(sbi, args.start_version);

	this_cp = (struct hmfs_checkpoint *)args.src;
	next_cp = ADDR(sbi, le64_to_cpu(this_cp->next_cp_addr));
	prev_cp = ADDR(sbi, le64_to_cpu(this_cp->prev_cp_addr));

	next_cp->prev_cp_addr = cpu_to_le64(args.dest_addr);
	prev_cp->next_cp_addr = cpu_to_le64(args.dest_addr);

	update_dest_summary(src_sum, args.dest_sum);
	cp_i->cp = (struct hmfs_checkpoint *)args.dest_addr;
}

static void gc_node_segments(struct hmfs_sb_info *sbi, struct hmfs_summary *sum,
			     seg_t segno)
{
	int off = 0;

	for (off = 0; off < HMFS_PAGE_PER_SEG; ++off, sum++) {
		if (!le16_to_cpu(sum->count))
			continue;

		switch (get_summary_type(sum)) {
		case SUM_TYPE_IDN:
			move_node_block(sbi, segno, off, sum, SUM_TYPE_IDN);
			break;
		case SUM_TYPE_INODE:
			move_node_block(sbi, segno, off, sum, SUM_TYPE_INODE);
			break;
		case SUM_TYPE_DN:
			move_node_block(sbi, segno, off, sum, SUM_TYPE_DN);
			break;
		case SUM_TYPE_NATN:
			move_nat_block(sbi, segno, off, sum, SUM_TYPE_NATN);
			break;
		case SUM_TYPE_NATD:
			move_nat_block(sbi, segno, off, sum, SUM_TYPE_NATD);
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

static void garbage_collect(struct hmfs_sb_info *sbi, seg_t segno, int gc_type)
{
	struct hmfs_summary_block *sum_blk;

	sum_blk = get_summary_block(sbi, segno);

	if (get_summary_type(&(sum_blk->entries[0])) == SUM_TYPE_DATA) {
		gc_data_segments(sbi, sum_blk->entries, segno);
	} else {
		gc_node_segments(sbi, sum_blk->entries, segno);
	}
	recycle_segment(sbi, segno);
}

int hmfs_gc(struct hmfs_sb_info *sbi, int gc_type)
{
	int nfree = 0;
	int ret = -1;
	seg_t segno;
	struct sit_info *sit_i = SIT_I(sbi);

gc_more:
	if (!(sbi->sb->s_flags & MS_ACTIVE))
		goto out;

	if (gc_type == BG_GC && has_not_enough_free_segs(sbi)) {
		gc_type = FG_GC;
		if (sit_i->dirty_sentries) {
			ret = write_checkpoint(sbi);
			if (ret)
				goto out;
		}
	}

	if (!get_victim(sbi, &segno, gc_type))
		goto out;
	ret = 0;

	garbage_collect(sbi, segno, gc_type);

	if (gc_type == FG_GC) {
		nfree++;
	}

	if (has_not_enough_free_segs(sbi))
		goto gc_more;

	if (sit_i->sentries) {
		ret = write_checkpoint(sbi);
		if (ret)
			goto out;
	}
out:
	mutex_unlock(&sbi->gc_mutex);

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
			wait_event_interruptible_timeout(*wq,
							 kthread_should_stop(),
							 msecs_to_jiffies
							 (wait_ms));

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
