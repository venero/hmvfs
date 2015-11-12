#ifndef GC_H
#define GC_H
#include <linux/wait.h>
#include "segment.h"
#include "hmfs.h"
#include "hmfs_fs.h"

#define GC_THREAD_MIN_SLEEP_TIME	3000	/* milliseconds */
#define GC_THREAD_MAX_SLEEP_TIME	6000
#define GC_THREAD_NOGC_SLEEP_TIME	3000	/* 5 min */

#define MAX_SEG_SEARCH				16

struct hmfs_gc_kthread {
	struct task_struct *hmfs_gc_task;
	wait_queue_head_t gc_wait_queue_head;
};

struct gc_move_arg {
	unsigned int start_version;
	unsigned int dead_version;
	unsigned int nid;
	unsigned int ofs_in_node;
	int nrchange;
	int count;
	block_t src_addr, dest_addr, parent_addr;
	char *dest, *src;
	struct hmfs_summary *dest_sum, *parent_sum;
	struct checkpoint_info *cp_i;
};

struct victim_sel_policy {
	int gc_mode;
	unsigned long *dirty_segmap;
	unsigned int offset;
	unsigned int min_cost;
	unsigned int min_segno;
};

/**
 * BG_GC means the background cleaning job.
 * FG_GC means the on-demand cleaning job.
 */
enum {
	BG_GC = 0, FG_GC
};

enum {
	GC_GREEDY = 0, GC_CB
};

static inline unsigned long long free_user_blocks(struct hmfs_sb_info *sbi)
{
	if (free_segments(sbi) < overprovision_segments(sbi))
		return 0;
	else
		return (free_segments(sbi) - overprovision_segments(sbi))
		 << HMFS_PAGE_PER_SEG_BITS;
}

static inline bool has_enough_invalid_blocks(struct hmfs_sb_info *sbi)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct hmfs_sm_info *sm_i = SM_I(sbi);
	unsigned long invalid_user_blocks = cm_i->alloc_block_count
	 - cm_i->valid_block_count;

	hmfs_bug_on(sbi, cm_i->alloc_block_count < cm_i->valid_block_count);

	if (invalid_user_blocks > sm_i->limit_invalid_blocks
	    && free_user_blocks(sbi) < sm_i->limit_free_blocks)
		return true;
	return false;
}

static inline bool has_not_enough_free_segs(struct hmfs_sb_info *sbi)
{
	return free_user_blocks(sbi) < SM_I(sbi)->limit_free_blocks;
}

static inline long increase_sleep_time(long wait)
{
	if (wait == GC_THREAD_NOGC_SLEEP_TIME)
		return wait;

	wait += GC_THREAD_MIN_SLEEP_TIME;
	if (wait > GC_THREAD_MAX_SLEEP_TIME)
		wait = GC_THREAD_MAX_SLEEP_TIME;
	return wait;
}

static inline long decrease_sleep_time(long wait)
{
	if (wait == GC_THREAD_NOGC_SLEEP_TIME)
		wait = GC_THREAD_MAX_SLEEP_TIME;

	wait -= GC_THREAD_MIN_SLEEP_TIME;
	if (wait <= GC_THREAD_MIN_SLEEP_TIME)
		wait = GC_THREAD_MIN_SLEEP_TIME;
	return wait;
}

#endif
