#ifndef HMFS_GC_H
#define HMFS_GC_H
#include <linux/wait.h>
#include "segment.h"
#include "hmfs.h"
#include "hmfs_fs.h"

#define GC_THREAD_MIN_SLEEP_TIME	3000	/* milliseconds */
#define GC_THREAD_MAX_SLEEP_TIME	60000
#define GC_THREAD_NOGC_SLEEP_TIME	300000	/* 5 min */

#define MAX_SEG_SEARCH				16

/* 
 * If number of invalid blocks of segment is less than xx, GC process
 * would stop scaning
 */
#define NR_GC_MIN_BLOCK				100

struct hmfs_gc_kthread {
	struct task_struct *hmfs_gc_task;
	wait_queue_head_t gc_wait_queue_head;
};

struct gc_move_arg {
	unsigned int start_version;
	unsigned int nid;
	unsigned int ofs_in_node;
	int nrchange;
	block_t src_addr, dest_addr, parent_addr;
	char *dest, *src;
	struct hmfs_summary *dest_sum, *parent_sum;
	struct checkpoint_info *cp_i;
};

struct victim_sel_policy {
	int gc_mode;
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

void prepare_move_argument(struct gc_move_arg *arg, struct hmfs_sb_info *sbi,
				seg_t mv_segno, unsigned mv_offset, struct hmfs_summary *sum,
				int type);

#ifdef CONFIG_HMFS_DEBUG_GC
#define INC_GC_TRY(si)					(si)->nr_gc_try++
#define INC_GC_REAL(si)					(si)->nr_gc_real++
#define COUNT_GC_BLOCKS(si, ivblocks)	do {	\
											(si)->nr_gc_blocks += ivblocks;\
											(si)->nr_gc_blocks_range[div64_u64(ivblocks, STAT_GC_RANGE)]++;\
										} while (0)	

#else
#define INC_GC_TRY(si)
#define INC_GC_REAL(si)
#define COUNT_GC_BLOCKS(si, ivblocks)
#endif

static inline bool need_deep_scan(struct hmfs_sb_info *sbi)
{
	return free_user_blocks(sbi) < SM_I(sbi)->severe_free_blocks;
}

static inline bool need_more_scan(struct hmfs_sb_info *sbi, seg_t segno,
				seg_t start_segno)
{
	if (segno >= start_segno)
		return segno - start_segno < sbi->nr_max_fg_segs;
	return segno + TOTAL_SEGS(sbi) - start_segno< sbi->nr_max_fg_segs; 
}

static inline long increase_sleep_time(struct hmfs_sb_info *sbi, long wait)
{
	if (wait == GC_THREAD_NOGC_SLEEP_TIME)
		return wait;

	wait += sbi->gc_thread_time_step;
	if (wait > sbi->gc_thread_max_sleep_time)
		wait = sbi->gc_thread_max_sleep_time;
	return wait;
}

static inline long decrease_sleep_time(struct hmfs_sb_info *sbi, long wait)
{
	if (wait == GC_THREAD_NOGC_SLEEP_TIME)
		wait = sbi->gc_thread_max_sleep_time;

	wait -= sbi->gc_thread_time_step;
	if (wait <= sbi->gc_thread_min_sleep_time)
		wait = sbi->gc_thread_min_sleep_time;
	return wait;
}

#endif
