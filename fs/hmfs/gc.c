#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/delay.h>

#include "hmfs.h"
#include "hmfs_fs.h"
#include "gc.h"
#include "segment.h"
#include "node.h"
#include "xattr.h"

/*
 * Setup arguments for GC and GC recovery
 */
void prepare_move_argument(struct gc_move_arg *arg,	struct hmfs_sb_info *sbi, seg_t mv_segno,
				unsigned mv_off, int64_t d_segno, unsigned d_off, int type)
{
	arg->src_addr = __cal_page_addr(sbi, mv_segno, mv_off);
	arg->src = ADDR(sbi, arg->src_addr);
	arg->src_sum = get_summary_by_addr(sbi, arg->src_addr);
	arg->start_version = get_summary_start_version(arg->src_sum);
	arg->nid = get_summary_nid(arg->src_sum);
	arg->ofs_in_node = get_summary_offset(arg->src_sum);

	arg->cp_i = get_checkpoint_info(sbi, arg->start_version, true);

	if (sbi->recovery_doing)
		return;

	if (d_segno < 0) {
		if (type != SEG_NODE_INDEX) {
			arg->dest = alloc_new_data_block(sbi, NULL, type);
		} else {
			arg->dest = alloc_new_node(sbi, 0, NULL, 0, true);
		}
	} else {
		arg->dest = ADDR(sbi, __cal_page_addr(sbi, d_segno, d_off));
	}
	
	hmfs_bug_on(sbi, IS_ERR(arg->dest));

	arg->dest_addr = L_ADDR(sbi, arg->dest);
	arg->dest_sum = get_summary_by_addr(sbi, arg->dest_addr);
	
	hmfs_memcpy(arg->dest, arg->src, HMFS_BLOCK_SIZE[type]);
}

static unsigned int get_gc_cost(struct hmfs_sb_info *sbi, unsigned int segno,
				struct victim_info *p)
{
	uint64_t mtime;
	/* Stop if we find a segment whose cost is small enough */
	if (get_valid_blocks(sbi, segno) < NR_GC_MIN_BLOCK && (p->gc_mode == GC_GREEDY ||
			p->gc_mode == GC_COMPACT))
		return 0;

	switch (p->gc_mode) {
	case GC_GREEDY:
		return get_seg_entry(sbi, segno)->valid_blocks;
	case GC_OLD:
		return get_seg_entry(sbi, segno)->mtime;
	case GC_COMPACT:
		mtime = get_seg_entry(sbi, segno)->mtime;
		if (get_valid_blocks(sbi, segno) < NR_GC_MIN_BLOCK)
			return 0;
		if (mtime < SIT_I(sbi)->min_mtime)
			SIT_I(sbi)->min_mtime = mtime;

		return div64_u64(get_valid_blocks(sbi, segno), (mtime - SIT_I(sbi)->min_mtime)); 
	default:
		hmfs_bug_on(sbi, 1);
		return 0;
	}
}

static void set_victim_policy(struct hmfs_sb_info *sbi, struct victim_info *p, int gc_type)
{
	sbi->gc_type_info <<= 1;
	sbi->gc_type_info |= (gc_type == FG_GC);
	sbi->gc_old_token--;

	if (gc_type == FG_GC) {
		p->gc_mode = GC_GREEDY;	
	} else {
		if (!sbi->gc_type_info && !sbi->gc_old_token)
			p->gc_mode = GC_OLD;
		else
			p->gc_mode = GC_COMPACT;
	}

	if (!sbi->gc_old_token)
		sbi->gc_old_token = DEFAULT_GC_TOKEN;
	p->offset = sbi->last_victim[p->gc_mode];
	p->min_segno = NULL_SEGNO;
	p->buddy_segno = NULL_SEGNO;
}

/*
 * Select a victim segment from dirty_segmap. We don't lock dirty_segmap here.
 * Because we could tolerate somewhat inconsistency of it. And we get buddy segment
 * for victim segment in GC_OLD mode here.
 */
static int get_victim(struct hmfs_sb_info *sbi, struct victim_info *vi, int gc_type)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	unsigned long cost;
	seg_t segno;
	int nsearched = 0;
	int total_segs = TOTAL_SEGS(sbi);
	bool retry = false;

	vi->min_segno = NULL_SEGNO;
	vi->buddy_segno = NULL_SEGNO;
	vi->min_cost = UINT_MAX;
	vi->offset = sbi->last_victim[vi->gc_mode];
	while (1) {
		segno = find_next_bit(dirty_i->dirty_segmap, total_segs, vi->offset);

		if (segno >= total_segs) {
			if (sbi->last_victim[vi->gc_mode]) {
				sbi->last_victim[vi->gc_mode] = 0;
				vi->offset = 0;
				retry = true;
				continue;
			}
			break;
		} else {
			vi->offset = segno + 1;
		}

		if (test_bit(segno, SIT_I(sbi)->new_segmap))
			continue;

		hmfs_bug_on(sbi, get_valid_blocks(sbi, segno) == SM_I(sbi)->page_4k_per_seg);
		cost = get_gc_cost(sbi, segno, vi);

		if (vi->min_cost > cost) {
			vi->min_segno = segno;
			vi->min_cost = cost;
		}

		if (!cost)
			break;

		if (nsearched++ >= MAX_SEG_SEARCH) {
			if (vi->gc_mode == GC_OLD && vi->buddy_segno == NULL_SEGNO && !retry && 
					segno < sbi->last_victim[vi->gc_mode])
				continue;
			break;
		}
	}

	sbi->last_victim[vi->gc_mode] = segno;
	
	if (vi->min_segno == NULL_SEGNO)
		return 0;

	hmfs_dbg("Select %d\n", vi->min_segno);
	return 1;
}

static void update_dest_summary(struct hmfs_summary *src_sum, struct hmfs_summary *dest_sum)
{
	hmfs_memcpy(dest_sum, src_sum, sizeof(struct hmfs_summary));
}

static void move_data_block(struct hmfs_sb_info *sbi, seg_t src_segno, unsigned src_off, 
				seg_t dest_segno, unsigned dest_off)
{
	struct gc_move_arg args;
	struct hmfs_node *last = NULL, *this = NULL;
	struct hmfs_summary *par_sum = NULL;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	block_t addr_in_par;
	int par_type;

	/* 1. read summary of source blocks */
	/* 2. move blocks */
	prepare_move_argument(&args, sbi, src_segno, src_off, dest_segno, dest_off,
			get_seg_entry(sbi, src_segno)->type);

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
			hmfs_memcpy_atomic(&this->i.i_addr[args.ofs_in_node], &args.dest_addr, 8);
		} else {
			hmfs_memcpy_atomic(&this->dn.addr[args.ofs_in_node], &args.dest_addr, 8);
		}
		
		last = this;

next:
		/* cp_i is the lastest checkpoint, stop */
		if (args.cp_i == cm_i->last_cp_i) {
			break;
		}
		args.cp_i = get_next_checkpoint_info(sbi, args.cp_i);
	}

	/* 5. Update summary infomation of dest block */
	update_dest_summary(args.src_sum, args.dest_sum);
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
		void *ssa = get_summary_block(sbi, segno);
		lock_write_segmap(free_i);
		if (test_and_clear_bit(segno, free_i->free_segmap)) {
			free_i->free_segments++;
		}
		unlock_write_segmap(free_i);
		memset(ssa, 0, SM_I(sbi)->summary_block_size);
	} else {
		/* set prefree bit */
		if (test_and_set_bit(segno, free_i->prefree_segmap))
			hmfs_bug_on(sbi, 1);
	}

	/* Now we have recycle HMFS_PAGE_PER_SEG blocks and update cm_i */
	lock_cm(cm_i);
	cm_i->alloc_block_count -= SM_I(sbi)->page_4k_per_seg;
	unlock_cm(cm_i);
}

static void move_xdata_block(struct hmfs_sb_info *sbi, seg_t src_segno,	unsigned src_off,
				seg_t dest_segno, unsigned dest_off)
{
	struct gc_move_arg arg;
	struct hmfs_node *last = NULL, *this = NULL;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	block_t addr_in_par;
	int x_tag;

	prepare_move_argument(&arg, sbi, src_segno, src_off, dest_segno, dest_off,
			SEG_DATA_INDEX);

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
		if (arg.cp_i == cm_i->last_cp_i)
			break;
		arg.cp_i = get_next_checkpoint_info(sbi, arg.cp_i);
	}

	update_dest_summary(arg.src_sum, arg.dest_sum);
}

static void move_node_block(struct hmfs_sb_info *sbi, seg_t src_segno, unsigned src_off,
				seg_t dest_segno, unsigned dest_off)
{
	struct hmfs_nat_block *last = NULL, *this = NULL;
	struct gc_move_arg args;
	block_t addr_in_par;

	prepare_move_argument(&args, sbi, src_segno, src_off, dest_segno, dest_off, SEG_NODE_INDEX);

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

		hmfs_memcpy_atomic(&this->entries[args.ofs_in_node].block_addr,	&args.dest_addr, 8);
		last = this;

next:
		if (args.cp_i == CM_I(sbi)->last_cp_i)
			break;
		args.cp_i = get_next_checkpoint_info(sbi, args.cp_i);
	}

	update_dest_summary(args.src_sum, args.dest_sum);
}

static void move_nat_block(struct hmfs_sb_info *sbi, seg_t src_segno, int src_off,
			   seg_t dest_segno, unsigned dest_off)
{
	void *last = NULL, *this = NULL;
	struct hmfs_checkpoint *hmfs_cp;
	struct hmfs_nat_node *nat_node;
	struct gc_move_arg args;
	nid_t par_nid;
	block_t addr_in_par;

	prepare_move_argument(&args, sbi, src_segno, src_off, dest_segno,
			dest_off, SEG_NODE_INDEX);

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
			hmfs_memcpy_atomic(&nat_node->addr[args.ofs_in_node], &args.dest_addr, 8);
		}

		last = this;

next:
		if (args.cp_i == CM_I(sbi)->last_cp_i)
			break;
		args.cp_i = get_next_checkpoint_info(sbi, args.cp_i);
	}

	update_dest_summary(args.src_sum, args.dest_sum);
}

/* Orphan blocks is not shared */
static void move_orphan_block(struct hmfs_sb_info *sbi, seg_t src_segno, int src_off,
				seg_t dest_segno, unsigned dest_off)
{
	struct gc_move_arg args;
	struct hmfs_checkpoint *hmfs_cp;
	block_t cp_addr;

	prepare_move_argument(&args, sbi, src_segno, src_off, dest_segno, 
			dest_off, SEG_NODE_INDEX);
	cp_addr = le64_to_cpu(*((__le64 *)args.src));
	hmfs_cp = ADDR(sbi, cp_addr);
	hmfs_cp->orphan_addrs[get_summary_offset(args.src_sum)] = cpu_to_le64(args.dest_addr);

	update_dest_summary(args.src_sum, args.dest_sum);
}

static void move_checkpoint_block(struct hmfs_sb_info *sbi, seg_t src_segno,
				int src_off, seg_t dest_segno, unsigned dest_off)
{
	struct gc_move_arg args;
	struct hmfs_checkpoint *prev_cp, *next_cp, *this_cp;
	struct checkpoint_info *cp_i;
	int i;
	block_t orphan_addr;
	__le64 *orphan;

	prepare_move_argument(&args, sbi, src_segno, src_off, dest_segno,
			dest_off, SEG_NODE_INDEX);

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
		if (orphan_addr == 0)
			break;
		orphan = ADDR(sbi, orphan_addr);
		hmfs_memcpy_atomic(orphan, &args.dest_addr, 8);
	}

	update_dest_summary(args.src_sum, args.dest_sum);
}

static void get_buddy_segment(struct hmfs_sb_info *sbi, struct victim_info *vi)
{
	struct hmfs_summary *v_sum = NULL;
	int value, temp_value, best_value = INT_MAX;
	seg_t segno, start_segno, best_segno = NULL_SEGNO;
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	bool retry = false;
	uint8_t seg_type = -1;

	if (vi->gc_mode == GC_COMPACT) {
		v_sum = get_summary_block(sbi, vi->min_segno);
		seg_type = get_seg_entry(sbi, vi->min_segno)->type;
		value = find_first_valid_version(v_sum, seg_type);
		start_segno = vi->min_segno;
		vi->buddy_segno = NULL_SEGNO;
	} else {
		value = get_seg_entry(sbi, vi->buddy_segno)->mtime;
		seg_type = get_seg_entry(sbi, vi->buddy_segno)->type;
		start_segno = vi->buddy_segno;
		vi->min_segno = NULL_SEGNO;
	}
	segno = start_segno + 1;

	if (segno >= TOTAL_SEGS(sbi))
		segno = 0;

	while (1) {
		segno = find_next_bit(dirty_i->dirty_segmap, TOTAL_SEGS(sbi), segno);

		if (segno >= TOTAL_SEGS(sbi)) {
			if (!retry) {
				retry = true;
				segno = 0;
				continue;
			}
			break;
		}

		if (get_seg_entry(sbi, segno)->type != seg_type)
			goto next;

		if (test_bit(segno, SIT_I(sbi)->new_segmap))
			goto next;

		if (retry && segno >= start_segno) {
			break;
		}

		if (get_valid_blocks(sbi, segno) <= NR_GC_MIN_BLOCK)
			goto next;

		if (vi->gc_mode == GC_COMPACT) {
			v_sum = get_summary_block(sbi, segno);
			temp_value = find_first_valid_version(v_sum, seg_type);
			if (temp_value == value) {
				best_segno = segno;
				break;
			}
		} else {
			temp_value = get_seg_entry(sbi, segno)->mtime;
		}
		if (ABS(temp_value, value) < ABS(best_value, value)) {
			best_value = temp_value;
			best_segno = segno;
		}
next:
		segno++;
	}
	if (vi->gc_mode == GC_COMPACT) {
		vi->buddy_segno = best_segno;	
	} else {
		vi->min_segno = best_segno;
	}
}

//TODO: Fix mtime when merge two segments
static void garbage_collect(struct hmfs_sb_info *sbi, struct victim_info *vi)
{
	struct hmfs_summary *d_sum, *s_sum;
	seg_t d_segno, s_segno;
	int d_off = 0, s_off = 0;
	bool none_valid;
	uint8_t seg_type;

	switch (vi->gc_mode) {
	case GC_GREEDY:
		d_segno = -1;
	case GC_COMPACT:
		s_sum = get_summary_block(sbi, vi->min_segno);
		seg_type = get_seg_entry(sbi, vi->min_segno)->type;
		none_valid = !get_valid_blocks(sbi, vi->min_segno);
		s_segno = vi->min_segno;
		d_sum = NULL; 
		break;
	case GC_OLD:
		get_buddy_segment(sbi, vi);
		s_sum = get_summary_block(sbi, vi->buddy_segno);
		d_sum = get_summary_block(sbi, vi->min_segno);
		seg_type = get_seg_entry(sbi, vi->buddy_segno)->type;
		none_valid = !get_valid_blocks(sbi, vi->buddy_segno);
		d_segno = vi->min_segno;
		s_segno = vi->buddy_segno;
		break;
	default:
		return;
	}

	if (none_valid)
		goto recycle;

	for (s_off = 0; s_off < SM_I(sbi)->page_4k_per_seg; s_off += HMFS_BLOCK_SIZE_4K[seg_type],
			s_sum += HMFS_BLOCK_SIZE_4K[seg_type]) {
		if (!get_summary_valid_bit(s_sum))
			continue;

		if (vi->gc_mode == GC_COMPACT && d_sum == NULL) {
			get_buddy_segment(sbi, vi);
			if (vi->buddy_segno != NULL_SEGNO) {
				d_sum = get_summary_block(sbi, vi->buddy_segno);
				d_segno = vi->buddy_segno;
			} else
				break;
		}

		if (vi->gc_mode != GC_GREEDY) {
			while (d_off < SM_I(sbi)->page_4k_per_seg) {
				if (!get_summary_valid_bit(d_sum))
					break;
				d_sum += HMFS_BLOCK_SIZE_4K[seg_type];
				d_off += HMFS_BLOCK_SIZE_4K[seg_type];
			}
			if (d_off == SM_I(sbi)->page_4k_per_seg) {
				if (vi->gc_mode == GC_OLD)
					break;
				d_sum = NULL;
			}
		} else {
			d_segno = -1;
			d_off = -1;
		}

		switch (get_summary_type(s_sum)) {
		case SUM_TYPE_DATA:
			move_data_block(sbi, s_segno, s_off, d_segno, d_off);
			break;
		case SUM_TYPE_XDATA:
			move_xdata_block(sbi, s_segno, s_off, d_segno, d_off);
			break;
		case SUM_TYPE_INODE:
		case SUM_TYPE_DN:
		case SUM_TYPE_IDN:
			move_node_block(sbi, s_segno, s_off, d_segno, d_off);
			break;
		case SUM_TYPE_NATN:
		case SUM_TYPE_NATD:
			move_nat_block(sbi, s_segno, s_off, d_segno, d_off);
			break;
		case SUM_TYPE_ORPHAN:
			move_orphan_block(sbi, s_segno, s_off, d_segno, d_off);
			break;
		case SUM_TYPE_CP:
			move_checkpoint_block(sbi, s_segno, s_off, d_segno, d_off);
			break;
		default:
			hmfs_bug_on(sbi, 1);
		}
	}

	if (s_off < SM_I(sbi)->page_4k_per_seg)
		return;
recycle:
	if (vi->gc_mode == GC_OLD) {
		recycle_segment(sbi, vi->buddy_segno, none_valid);
		COUNT_GC_BLOCKS(STAT_I(sbi), SM_I(sbi)->page_4k_per_seg - 
				get_valid_blocks(sbi, vi->buddy_segno));
	} else {
		recycle_segment(sbi, vi->min_segno, none_valid);
		COUNT_GC_BLOCKS(STAT_I(sbi), SM_I(sbi)->page_4k_per_seg - 
				get_valid_blocks(sbi, vi->min_segno));
	}
}

int hmfs_gc(struct hmfs_sb_info *sbi, int gc_type)
{
	int ret = -1;
	seg_t start_segno = NULL_SEGNO;
	struct hmfs_checkpoint *hmfs_cp = CM_I(sbi)->last_cp_i->cp;
	bool do_cp = false;
	int total_segs = TOTAL_SEGS(sbi);
	int time_retry = 0;
	int max_retry = div64_u64((total_segs + MAX_SEG_SEARCH - 1), MAX_SEG_SEARCH);
	struct victim_info vi;

	hmfs_dbg("Enter GC\n");
	INC_GC_TRY(STAT_I(sbi));
	if (!(sbi->sb->s_flags & MS_ACTIVE) || !test_opt(sbi, GC))
		goto out;

	if (hmfs_cp->state == HMFS_NONE)
		set_fs_state(hmfs_cp, HMFS_GC);

	set_victim_policy(sbi, &vi, gc_type);
gc_more:
	hmfs_dbg("Before get victim:%ld %ld %ld\n", (unsigned long)total_valid_blocks(sbi),
			(unsigned long)CM_I(sbi)->alloc_block_count, 
			(unsigned long)CM_I(sbi)->valid_block_count);
	if (!get_victim(sbi, &vi, gc_type))
		goto out;
	ret = 0;

	hmfs_dbg("GC Victim:%d %d\n", (int)vi.min_segno, get_valid_blocks(sbi, vi.min_segno));
	//FIXME: the statistic is not true in GC_COMPACT and GC_OLD
	INC_GC_REAL(STAT_I(sbi));

	/*
	 * If a segment does not contains any valid blocks, we do not 
	 * need to set it as PREFREE. And we could reuse it right now, which
	 * could improve GC efficiency
	 */
	if (get_seg_entry(sbi, vi.min_segno)->valid_blocks) {
		hmfs_memcpy_atomic(sbi->gc_logs, &vi.min_segno, 4);		
		sbi->gc_logs++;
		sbi->nr_gc_segs++;
		hmfs_memcpy_atomic(&hmfs_cp->nr_gc_segs, &sbi->nr_gc_segs, 4);
	}


	hmfs_bug_on(sbi, total_valid_blocks(sbi) != CM_I(sbi)->valid_block_count);
	garbage_collect(sbi, &vi);

	hmfs_dbg("GC:%ld %ld %ld\n", (unsigned long)total_valid_blocks(sbi),
			(unsigned long)CM_I(sbi)->alloc_block_count, 
			(unsigned long)CM_I(sbi)->valid_block_count);
	hmfs_bug_on(sbi, total_valid_blocks(sbi) != CM_I(sbi)->valid_block_count);

	if (start_segno == NULL_SEGNO)
		start_segno = vi.min_segno;

	/* If space is limited, we might need to scan the whole NVM */
	if (need_deep_scan(sbi, vi.gc_mode)) {
		do_cp = true;
		time_retry++;
		if (time_retry < max_retry)
			goto gc_more;
		goto out;
	}

	/* In FG_GC, we atmost scan sbi->nr_max_fg_segs segments */
	if (need_more_scan(sbi, vi.min_segno, start_segno, vi.gc_mode))
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

//TODO: Setup threshold of calling bc
inline void start_bc(struct hmfs_sb_info *sbi) {
	if (sbi->gc_thread) {
		smp_wmb();
		wake_up_process(sbi->gc_thread->hmfs_task);
	}
}

/* Collect truncated blocks in current version */
void hmfs_collect_blocks(struct hmfs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct seg_entry *seg_entry;
	uint64_t nr_bc = 0;
	seg_t segno = 0;
	int total_segs = TOTAL_SEGS(sbi);
	uint16_t vb;
	int8_t type;
	bool retry = false;
	struct allocator *allocator;
	uint16_t read, write, block_index = 0;

	hmfs_dbg("Start BC:%llu\n", CM_I(sbi)->alloc_block_count);

	while (1) {
		segno = find_next_bit(sit_i->new_segmap, total_segs, segno);

		if (segno >= total_segs) {
			if (!retry) {
				retry = true;
				segno = 0;
				continue;
			}
			break;
		}

		seg_entry = get_seg_entry(sbi, segno);
			
		if (!seg_entry->invalid_bitmap)
			goto next_seg;

		vb = get_valid_blocks(sbi, segno);
		type = seg_entry->type;
		allocator = ALLOCATOR(sbi, type);

		/* Collect the whole segments directly */
		if (!vb) {
			block_index = find_next_zero_bit(seg_entry->invalid_bitmap, 
								allocator->nr_pages, 0);
			if (block_index >= allocator->nr_pages) {
				struct free_segmap_info *free_i = FREE_I(sbi);
				void *ssa = get_summary_block(sbi, segno);

				if (!test_and_clear_bit(segno, DIRTY_I(sbi)->dirty_segmap))
					hmfs_bug_on(sbi, 1);
				lock_write_segmap(free_i);
				if (test_and_clear_bit(segno, free_i->free_segmap))
					free_i->free_segments++;
				unlock_write_segmap(free_i);
				nr_bc += SM_I(sbi)->page_4k_per_seg;
				memset(ssa, 0, SM_I(sbi)->summary_block_size);
				clear_bit(segno, sit_i->new_segmap);
				goto next_seg;
			}
		}

		block_index = 0;

		if (atomic_read(&allocator->segno) == segno)
			goto next_seg;
		read = atomic_read(&allocator->read);
		write = atomic_read(&allocator->write);

		/* Buffer is full */
		if (write - read == allocator->buffer_index_mask)
			goto next_seg;

		hmfs_dbg("Collect %d\n", segno);
		hmfs_bug_on(sbi, write - read > allocator->buffer_index_mask);
			
		for (; write - read < allocator->buffer_index_mask; write++, block_index++) {
			block_index = find_next_bit(seg_entry->invalid_bitmap, 
							allocator->nr_pages, block_index);
			if (block_index >= allocator->nr_pages)
				break;
			allocator->buffer[write & allocator->buffer_index_mask] = 
					__cal_page_addr(sbi, segno, block_index);
			clear_bit(block_index, seg_entry->invalid_bitmap);
			nr_bc += HMFS_BLOCK_SIZE_4K[type];
		}
		atomic_set(&allocator->write, write);

next_seg:
		segno++;
	}

	spin_lock(&CM_I(sbi)->cm_lock);
	CM_I(sbi)->alloc_block_count -= nr_bc;
	spin_unlock(&CM_I(sbi)->cm_lock);

	hmfs_dbg("Stop BC:%llu\n", CM_I(sbi)->alloc_block_count);
}

static int gc_thread_func(void *data)
{
	struct hmfs_sb_info *sbi = data;
	long wait_ms = 0;
	long jiffies = 0;

	wait_ms = sbi->gc_thread_min_sleep_time;

	do {
		if (try_to_freeze())
			continue;

		set_current_state(TASK_INTERRUPTIBLE);

		if (jiffies)
			jiffies = schedule_timeout_interruptible(jiffies);
		else
			jiffies = schedule_timeout_interruptible(msecs_to_jiffies(wait_ms));

		if (kthread_should_stop())
			break;

		if (sbi->sb->s_writers.frozen >= SB_FREEZE_WRITE) {
			wait_ms = sbi->gc_thread_max_sleep_time;
			continue;
		}

		continue;
		if (!trylock_gc(sbi))
			continue;

		hmfs_collect_blocks(sbi);

		if (jiffies) {
			unlock_gc(sbi);
			continue;
		}

		if (has_enough_invalid_blocks(sbi))
			wait_ms = decrease_sleep_time(sbi, wait_ms);
		else
			wait_ms = increase_sleep_time(sbi, wait_ms);

		if (hmfs_gc(sbi, BG_GC)) {
			if (wait_ms == sbi->gc_thread_max_sleep_time)
				wait_ms = GC_THREAD_NOGC_SLEEP_TIME;
		}
	} while (!kthread_should_stop());
	return 0;
}

int start_gc_thread(struct hmfs_sb_info *sbi)
{
	struct hmfs_kthread *gc_thread = NULL;
	int err = 0;
	unsigned long start_addr, end_addr;

	start_addr = sbi->phys_addr;
	end_addr = sbi->phys_addr + sbi->initsize;
	sbi->last_victim[GC_COMPACT] = 0;
	sbi->last_victim[GC_OLD] = 0;
	sbi->last_victim[GC_GREEDY] = 0;

	sbi->gc_thread = NULL;
	/* Initialize GC kthread */
	gc_thread = kmalloc(sizeof(struct hmfs_kthread), GFP_KERNEL);
	if (!gc_thread) {
		return -ENOMEM;
	}

	init_waitqueue_head(&(gc_thread->wait_queue_head));
	gc_thread->hmfs_task = kthread_run(gc_thread_func, sbi, "hmfs_gc-%lu:->%lu",
									start_addr, end_addr);
	sbi->gc_thread = gc_thread;
	if (IS_ERR(gc_thread->hmfs_task)) {
		err = PTR_ERR(gc_thread->hmfs_task);
		goto free_gc;
	}

	return 0;

free_gc:
	kfree(gc_thread);
	return err;
}

void stop_gc_thread(struct hmfs_sb_info *sbi)
{
	if (sbi->gc_thread) {
		kthread_stop(sbi->gc_thread->hmfs_task);
		kfree(sbi->gc_thread);
		sbi->gc_thread = NULL;
	}
}

int init_gc_logs(struct hmfs_sb_info *sbi)
{
	seg_t segno = 0;
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

#ifdef CONFIG_HMFS_DEBUG_GC
int init_gc_stat(struct hmfs_sb_info *sbi) {
	struct hmfs_stat_info *si = STAT_I(sbi);
	int i;

	si->nr_gc_try = 0;
	si->nr_gc_real = 0;
	si->nr_gc_blocks = 0;
	si->size_gc_range = ((SM_I(sbi)->segment_size >> HMFS_MIN_PAGE_SIZE_BITS)
			+ STAT_GC_RANGE - 1) / STAT_GC_RANGE;
	si->nr_gc_blocks_range = kmalloc(sizeof(int) * si->size_gc_range, GFP_KERNEL);
	if (!si->nr_gc_blocks_range)
		return -ENOMEM;

	for (i = 0; i < si->size_gc_range; i++) {
		si->nr_gc_blocks_range[i] = 0;
	}
	return 0;
}

void destroy_gc_stat(struct hmfs_sb_info *sbi) {
	kfree(STAT_I(sbi)->nr_gc_blocks_range);
	STAT_I(sbi)->nr_gc_blocks_range = NULL;
}
#endif
