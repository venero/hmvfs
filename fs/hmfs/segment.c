#include <linux/vmalloc.h>
#include "segment.h"

/*
 * Judge whether an address is a valid address. i.e.
 * it fall into space where we have actually writen data
 * into. It's different from valid bits in summary entry
 */
bool is_valid_address(struct hmfs_sb_info *sbi, block_t addr)
{
	seg_t segno = GET_SEGNO(sbi, addr);
	struct hmfs_checkpoint *hmfs_cp = CM_I(sbi)->last_cp_i->cp;
	
	if (segno == le32_to_cpu(hmfs_cp->cur_data_segno))
		return GET_SEG_OFS(sbi, addr) <= le16_to_cpu(hmfs_cp->cur_data_blkoff);
	else if (segno == le32_to_cpu(hmfs_cp->cur_node_segno))
		return GET_SEG_OFS(sbi, addr) <= le16_to_cpu(hmfs_cp->cur_node_blkoff);
	else
		return get_seg_entry(sbi, segno)->valid_blocks > 0;
}

unsigned long total_valid_blocks(struct hmfs_sb_info *sbi)
{
	int i;
	unsigned long sum = 0;

	for (i = 0; i < TOTAL_SEGS(sbi); i++) {
		sum += get_valid_blocks(sbi, i);
	}

	return sum;
}

unsigned long get_seg_vblocks_in_summary(struct hmfs_sb_info *sbi, seg_t segno)
{
	struct hmfs_summary_block *sum_blk;
	struct hmfs_summary *sum;
	int off = 0;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	bool is_current;
	int count = 0;
	nid_t nid;
	
	sum_blk = get_summary_block(sbi, segno);
	sum = sum_blk->entries;

	//TODO: Set same part in garbage_collect as function
	for (off = 0; off < HMFS_PAGE_PER_SEG; ++off, sum++) {
		is_current = get_summary_start_version(sum) == cm_i->new_version;

		if (!get_summary_valid_bit(sum) && !is_current)
			continue;

		if (is_current) {
			nid = get_summary_nid(sum);
			if (IS_ERR(get_node(sbi, nid)))
				continue;
		}

		count++;
	}
	return count;
}

static void __mark_sit_entry_dirty(struct sit_info *sit_i, seg_t segno)
{
	if (!__test_and_set_bit(segno, sit_i->dirty_sentries_bitmap))
		sit_i->dirty_sentries++;
}

/* Return amount of blocks which has been invalidated */
int invalidate_delete_block(struct hmfs_sb_info *sbi, block_t addr)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct hmfs_summary *summary;
	seg_t segno;

	if (!is_new_block(sbi, addr))
		return 0;
	
	summary = get_summary_by_addr(sbi, addr);
	set_summary_nid(summary, NULL_NID);
	segno = GET_SEGNO(sbi, addr);
	lock_sentry(sit_i);
	update_sit_entry(sbi, segno, -1);
	unlock_sentry(sit_i);

	test_and_set_bit(segno, DIRTY_I(sbi)->dirty_segmap);
	return 1;
}

static void init_min_max_mtime(struct hmfs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);
	seg_t segno;
	unsigned long long mtime;


	lock_sentry(sit_i);
	sit_i->min_mtime = LLONG_MAX;

	for (segno = 0; segno < TOTAL_SEGS(sbi); segno++) {
		mtime = get_seg_entry(sbi, segno)->mtime;

		if (sit_i->min_mtime > mtime)
			sit_i->min_mtime = mtime;
	}
	sit_i->max_mtime = get_mtime(sbi);
	unlock_sentry(sit_i);
}

void update_sit_entry(struct hmfs_sb_info *sbi, seg_t segno,
				int del)
{
	struct seg_entry *se;
	struct sit_info *sit_i = SIT_I(sbi);
	long new_vblocks;

	se = get_seg_entry(sbi, segno);
	new_vblocks = se->valid_blocks + del;

	hmfs_dbg_on(new_vblocks < 0 || new_vblocks > HMFS_PAGE_PER_SEG,
			"Invalid value of valid_blocks: %ld free:%d prefree:%d dirty:%d\n",
			new_vblocks, test_bit(segno, FREE_I(sbi)->free_segmap),
			test_bit(segno, FREE_I(sbi)->prefree_segmap), 
			test_bit(segno, DIRTY_I(sbi)->dirty_segmap));
	hmfs_bug_on(sbi, new_vblocks < 0 || new_vblocks > HMFS_PAGE_PER_SEG);

	se->valid_blocks = new_vblocks;
	se->mtime = get_mtime(sbi);
	__mark_sit_entry_dirty(sit_i, segno);
}

static void reset_curseg(struct curseg_info *seg_i)
{
	atomic_set(&seg_i->segno, seg_i->next_segno);
	seg_i->next_blkoff = 0;
	seg_i->next_segno = NULL_SEGNO;
}

inline block_t __cal_page_addr(struct hmfs_sb_info *sbi, seg_t segno,
				int blkoff)
{
	return (segno << HMFS_SEGMENT_SIZE_BITS) +
					(blkoff << HMFS_PAGE_SIZE_BITS)
					+ sbi->main_addr_start;
}

static inline unsigned long cal_page_addr(struct hmfs_sb_info *sbi,
				struct curseg_info *seg_i)
{
	return __cal_page_addr(sbi, atomic_read(&seg_i->segno),
				seg_i->next_blkoff);
}

/*
 * get_new_segment -- Find a new segment from the free segments bitmap
 * @newseg returns the found segment
 * must be success (otherwise cause error)
 */
int get_new_segment(struct hmfs_sb_info *sbi, seg_t *newseg)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	seg_t segno;
	bool retry = false;
	int ret = 0;
	void *ssa;

	lock_write_segmap(free_i);
retry:
	segno = find_next_zero_bit(free_i->free_segmap,
				   TOTAL_SEGS(sbi), *newseg);
	if(segno >= TOTAL_SEGS(sbi)) {
		*newseg = 0;
		if(!retry) {
			retry = true;
			goto retry;
		}
		ret = -ENOSPC;
		goto unlock;
	}

	hmfs_bug_on(sbi, test_bit(segno, free_i->free_segmap));
	__set_inuse(sbi, segno);
	*newseg = segno;
	/* Need to clear SSA */
	ssa = get_summary_block(sbi, segno);
	memset_nt(ssa, 0, HMFS_SUMMARY_BLOCK_SIZE);
unlock:
	unlock_write_segmap(free_i);
	return ret;
}

static int move_to_new_segment(struct hmfs_sb_info *sbi,
				struct curseg_info *seg_i)
{
	seg_t segno = atomic_read(&seg_i->segno);
	int ret = get_new_segment(sbi, &segno);

	if (ret)
		return ret;
	seg_i->next_segno = segno;
	reset_curseg(seg_i);
	return 0;
}

static block_t get_free_block(struct hmfs_sb_info *sbi, int seg_type, 
				bool sit_lock)
{
	block_t page_addr = 0;
	struct sit_info *sit_i = SIT_I(sbi);
	struct curseg_info *seg_i = &(CURSEG_I(sbi)[seg_type]);
	int ret;

	lock_curseg(seg_i);
	
	if (seg_i->next_blkoff == HMFS_PAGE_PER_SEG) {
		ret = move_to_new_segment(sbi, seg_i);
		if (ret) {
			unlock_curseg(seg_i);
			return NULL_ADDR;
		}
	}

	page_addr = cal_page_addr(sbi, seg_i);

	if (sit_lock)
		lock_sentry(sit_i);
	update_sit_entry(sbi, atomic_read(&seg_i->segno), 1);
	
	if (sit_lock)
		unlock_sentry(sit_i);

	seg_i->next_blkoff++;

	unlock_curseg(seg_i);

	return page_addr;
}

block_t alloc_free_data_block(struct hmfs_sb_info * sbi)
{
	return get_free_block(sbi, CURSEG_DATA, true);
}

block_t alloc_free_node_block(struct hmfs_sb_info * sbi, bool sit_lock)
{
	return get_free_block(sbi, CURSEG_NODE, sit_lock);
}

void recovery_sit_entries(struct hmfs_sb_info *sbi,
				struct hmfs_checkpoint *hmfs_cp)
{
	int nr_logs, i, nr_segs, num = 0;
	struct hmfs_sit_log_entry *sit_log;
	struct hmfs_sit_entry *sit_entry;
	block_t seg_addr;
	seg_t sit_segno, segno;

	nr_logs = le16_to_cpu(hmfs_cp->nr_logs);
	nr_segs = hmfs_cp->nr_segs;
	for (i = 0; i < nr_segs; i++) {
		sit_segno = le32_to_cpu(hmfs_cp->sit_logs[i]);
		seg_addr = __cal_page_addr(sbi, sit_segno, 0);
		sit_log = ADDR(sbi, seg_addr);
		while (num < nr_logs) {
			segno = le32_to_cpu(sit_log->segno);
			sit_entry = get_sit_entry(sbi, segno);
			sit_entry->mtime = sit_log->mtime;
			sit_entry->vblocks = sit_log->vblocks;
			
			num++;
			sit_log++;
			if (num % LOGS_ENTRY_PER_SEG == 0)
				break;
		}
	}
}

/* Update SIT area after deleting a checkpoint */
void flush_sit_entries_rmcp(struct hmfs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);
	pgc_t total_segs = TOTAL_SEGS(sbi);
	struct hmfs_sit_entry *sit_entry;
	struct seg_entry *seg_entry;
	unsigned long *bitmap = sit_i->dirty_sentries_bitmap;
	struct hmfs_summary *summary;
	struct free_segmap_info *free_i = FREE_I(sbi);
	int i;
	int offset = 0;

	while(1) {
		offset = find_next_bit(bitmap, total_segs, offset);
		if (offset < total_segs) {
			seg_entry = get_seg_entry(sbi, offset);
			sit_entry = get_sit_entry(sbi, offset);
			/*
			 * In recovery process, the valid blocks in original
			 * SIT area might be invalid. Because system might crash during
			 * writing SIT. Thus, we need to calculate valid blocks by
			 * scaning SSA area
			 */
			if (sbi->recovery_doing) {
				seg_entry->valid_blocks = 0;
				summary = get_summary_block(sbi, offset)->entries;
				for (i = 0; i < SUM_ENTRY_PER_BLOCK; i++, summary++) {
					if (get_summary_valid_bit(summary))
						seg_entry->valid_blocks++;
				}
			}
			if (!seg_entry->valid_blocks) {
				lock_write_segmap(free_i);
				clear_bit(offset, free_i->free_segmap);
				free_i->free_segmap++;
				unlock_write_segmap(free_i);
			}

			seg_info_to_raw_sit(seg_entry, sit_entry);
			offset++;
		} else
			break;
	}
	sit_i->dirty_sentries = 0;
	memset_nt(sit_i->dirty_sentries_bitmap, 0, sit_i->bitmap_size);
}


void flush_sit_entries(struct hmfs_sb_info *sbi, block_t new_cp_addr,
				void *new_nat_root)
{
	struct sit_info *sit_i = SIT_I(sbi);
	unsigned long offset = 0;
	pgc_t total_segs = TOTAL_SEGS(sbi);
	struct hmfs_sit_entry *sit_entry;
	struct seg_entry *seg_entry;
	unsigned long *bitmap = sit_i->dirty_sentries_bitmap;
	int nr_logs = 0, i = 0, nr_segs;
	struct hmfs_sit_log_entry *sit_log;
	struct hmfs_checkpoint *hmfs_cp = CM_I(sbi)->last_cp_i->cp;
	struct free_segmap_info *free_i = FREE_I(sbi);
	seg_t sit_segno;
	block_t seg_addr;

#ifdef CONFIG_HMFS_DEBUG
	pgc_t nrdirty = 0;

	while (1) {
		offset = find_next_bit(bitmap, total_segs, offset);
		if (offset < total_segs)
			nrdirty++;
		else
			break;
		offset++;
	}
	offset = 0;
	hmfs_bug_on(sbi, nrdirty != sit_i->dirty_sentries);
#endif

	/* First, prepare free segments to store dirty sit logs */
	nr_logs = sit_i->dirty_sentries;
	nr_segs = (nr_logs + LOGS_ENTRY_PER_SEG - 1) / LOGS_ENTRY_PER_SEG - 1;
	sit_segno = le32_to_cpu(hmfs_cp->cur_data_segno);
	do {
retry:
		sit_segno = find_next_zero_bit(free_i->free_segmap, total_segs,
							sit_segno);
		if (sit_segno >= total_segs) {
			sit_segno = 0;
			goto retry;
		}
		hmfs_cp->sit_logs[nr_segs--] = cpu_to_le32(sit_segno);
		sit_segno++;
	} while(nr_segs >= 0);

	/* Then, copy all dirty seg_entry to cp */
	i = 0;
	nr_segs = 0;
	nr_logs = 0;
	sit_log = NULL;
	while (1) {
		offset = find_next_bit(bitmap, total_segs, offset);
		if (i == 0) {
			seg_addr = __cal_page_addr(sbi, 
							le32_to_cpu(hmfs_cp->sit_logs[nr_segs]), 0);
			sit_log = ADDR(sbi, seg_addr);
			i = LOGS_ENTRY_PER_SEG;
			nr_segs++;
		}
		if (offset < total_segs) {
			seg_entry = get_seg_entry(sbi, offset);
			sit_log->segno = cpu_to_le32(offset);
			sit_log->mtime = cpu_to_le32(seg_entry->mtime);
			sit_log->vblocks = cpu_to_le32(seg_entry->valid_blocks);
			sit_log++;
			nr_logs++;
			i--;
			offset = offset + 1;
		} else
			break;
	}
	offset = 0;
	hmfs_cp->nr_logs = cpu_to_le16(nr_logs);
	hmfs_cp->nr_segs = nr_segs;

	set_fs_state_arg_2(hmfs_cp, new_cp_addr);
	set_fs_state(hmfs_cp, HMFS_ADD_CP);

	/* Then, copy all dirty seg_entry to SIT area */
	while (1) {
		offset = find_next_bit(bitmap, total_segs, offset);
		if (offset < total_segs) {
			sit_entry = get_sit_entry(sbi, offset);
			seg_entry = get_seg_entry(sbi, offset);
			offset = offset + 1;
			seg_info_to_raw_sit(seg_entry, sit_entry);
		} else
			break;
	}

	/* Finally, set valid bit in SSA */
	mark_block_valid(sbi, new_nat_root, ADDR(sbi, new_cp_addr));
	sit_i->dirty_sentries = 0;
	memset_nt(sit_i->dirty_sentries_bitmap, 0, sit_i->bitmap_size);
}

static inline void __set_test_and_inuse(struct hmfs_sb_info *sbi,
				seg_t segno)
{
	struct free_segmap_info *free_i = FREE_I(sbi);

	lock_write_segmap(free_i);
	if (!test_and_set_bit(segno, free_i->free_segmap)) {
		free_i->free_segments--;
	}
	unlock_write_segmap(free_i);
}

/*
 * routines for build segment manager
 */
static int build_sit_info(struct hmfs_sb_info *sbi)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct hmfs_checkpoint *hmfs_cp = cm_i->last_cp_i->cp;
	struct sit_info *sit_i;
	unsigned long long bitmap_size;

	/* allocate memory for SIT information */
	sit_i = kzalloc(sizeof(struct sit_info), GFP_KERNEL);
	if (!sit_i)
		return -ENOMEM;

	SM_I(sbi)->sit_info = sit_i;

	sit_i->sentries = vzalloc(TOTAL_SEGS(sbi) * sizeof(struct seg_entry));
	if (!sit_i->sentries)
		return -ENOMEM;

	bitmap_size = hmfs_bitmap_size(TOTAL_SEGS(sbi));
	sit_i->bitmap_size = bitmap_size;
	sit_i->dirty_sentries_bitmap = kzalloc(bitmap_size, GFP_KERNEL);
	if (!sit_i->dirty_sentries_bitmap)
		return -ENOMEM;

	memset_nt(sit_i->dirty_sentries_bitmap, 0, bitmap_size);

	sit_i->dirty_sentries = 0;

	sit_i->elapsed_time = le32_to_cpu(hmfs_cp->elapsed_time);
	sit_i->mounted_time = CURRENT_TIME_SEC.tv_sec;
	mutex_init(&sit_i->sentry_lock);
	return 0;
}

void free_prefree_segments(struct hmfs_sb_info *sbi)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	int total_segs = TOTAL_SEGS(sbi);
	unsigned long *bitmap = free_i->prefree_segmap;
	seg_t segno = 0;

	lock_write_segmap(free_i);
	while (1) {
		segno =find_next_bit(bitmap, total_segs, segno);
		if (segno >= total_segs)
			break;
		clear_bit(segno, bitmap);
		if (test_and_clear_bit(segno, free_i->free_segmap)) {
			free_i->free_segments++;
		}
		segno++;
	}
	unlock_write_segmap(free_i);
}

static int build_free_segmap(struct hmfs_sb_info *sbi)
{
	struct free_segmap_info *free_i;
	unsigned int bitmap_size;

	/* allocate memory for free segmap information */
	free_i = kzalloc(sizeof(struct free_segmap_info), GFP_KERNEL);
	if (!free_i)
		return -ENOMEM;

	SM_I(sbi)->free_info = free_i;

	bitmap_size = hmfs_bitmap_size(TOTAL_SEGS(sbi));
	free_i->free_segmap = kmalloc(bitmap_size, GFP_KERNEL);
	if (!free_i->free_segmap) {
		goto free_i;
	}
	free_i->prefree_segmap = kmalloc(bitmap_size, GFP_KERNEL);
	if (!free_i->prefree_segmap)
		goto free_segmap;

	/* set all segments as dirty temporarily */
	memset(free_i->free_segmap, 0xff, bitmap_size);
	memset(free_i->prefree_segmap, 0, bitmap_size);

	/* init free segmap information */
	free_i->free_segments = 0;
	rwlock_init(&free_i->segmap_lock);
	return 0;

free_segmap:
	kfree(free_i->free_segmap);
free_i:
	kfree(free_i);
	return -ENOMEM;
}

static int build_curseg(struct hmfs_sb_info *sbi)
{
	struct curseg_info *array;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct hmfs_checkpoint *hmfs_cp = cm_i->last_cp_i->cp;
	unsigned short node_blkoff, data_blkoff;

	array = kzalloc(sizeof(struct curseg_info) * NR_CURSEG_TYPE,
					GFP_KERNEL);
	if (!array)
		return -ENOMEM;

	SM_I(sbi)->curseg_array = array;

	mutex_init(&array[CURSEG_NODE].curseg_mutex);
	mutex_init(&array[CURSEG_DATA].curseg_mutex);

	lock_curseg(&array[CURSEG_NODE]);
	node_blkoff = le16_to_cpu(hmfs_cp->cur_node_blkoff);
	array[CURSEG_NODE].next_blkoff = node_blkoff;
	atomic_set(&array[CURSEG_NODE].segno, le32_to_cpu(hmfs_cp->cur_node_segno));
	array[CURSEG_NODE].next_segno = NULL_SEGNO;
	unlock_curseg(&array[CURSEG_NODE]);

	lock_curseg(&array[CURSEG_DATA]);
	data_blkoff = le16_to_cpu(hmfs_cp->cur_data_blkoff);
	array[CURSEG_DATA].next_blkoff = data_blkoff;
	atomic_set(&array[CURSEG_DATA].segno, le32_to_cpu(hmfs_cp->cur_data_segno));
	array[CURSEG_DATA].next_segno = NULL_SEGNO;
	unlock_curseg(&array[CURSEG_DATA]);

	return 0;
}

static void build_sit_entries(struct hmfs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct seg_entry *seg_entry;
	struct hmfs_sit_entry *sit_entry;
	unsigned int start;

	lock_sentry(sit_i);
	for (start = 0; start < TOTAL_SEGS(sbi); start++) {
		seg_entry = get_seg_entry(sbi, start);
		sit_entry = get_sit_entry(sbi, start);
		seg_info_from_raw_sit(seg_entry, sit_entry);
	}
	unlock_sentry(sit_i);
}

static void init_free_segmap(struct hmfs_sb_info *sbi)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	unsigned int start;
	struct curseg_info *curseg_t = NULL;
	struct seg_entry *sentry = NULL;
	int i;

	for (start = 0; start < TOTAL_SEGS(sbi); start++) {
		sentry = get_seg_entry(sbi, start);
		if (!sentry->valid_blocks) {
			lock_write_segmap(free_i);
			clear_bit(start, free_i->free_segmap);
			free_i->free_segments++;
			unlock_write_segmap(free_i);
		}
	}

	/* set use the current segments */
	curseg_t = CURSEG_I(sbi);
	for (i = 0; i < NR_CURSEG_TYPE; i++)
		__set_test_and_inuse(sbi, atomic_read(&curseg_t[i].segno));
}

static void init_dirty_segmap(struct hmfs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	struct free_segmap_info *free_i = FREE_I(sbi);
	struct curseg_info *curseg_t = CURSEG_I(sbi);
	seg_t segno, total_segs = TOTAL_SEGS(sbi), offset = 0;
	unsigned short valid_blocks;
	int i;

	while (1) {
		/* find dirty segmap based on free segmap */
		segno = find_next_inuse(free_i, total_segs, offset);
		if (segno >= total_segs)
			break;
		offset = segno + 1;
		valid_blocks = get_seg_entry(sbi, segno)->valid_blocks;
		if (valid_blocks >= HMFS_PAGE_PER_SEG || !valid_blocks)
			continue;
		test_and_set_bit(segno, dirty_i->dirty_segmap);
	}

	/* Clear the current segments */
	for (i = 0; i < NR_CURSEG_TYPE; i++)
		clear_bit(atomic_read(&curseg_t[i].segno), dirty_i->dirty_segmap);
}

static int build_dirty_segmap(struct hmfs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i;
	unsigned int bitmap_size;

	dirty_i = kzalloc(sizeof(struct dirty_seglist_info), GFP_KERNEL);
	if (!dirty_i)
		return -ENOMEM;

	SM_I(sbi)->dirty_info = dirty_i;

	bitmap_size = (BITS_TO_LONGS(TOTAL_SEGS(sbi)) * sizeof(unsigned long));

	dirty_i->dirty_segmap = kzalloc(bitmap_size, GFP_KERNEL);

	if (!dirty_i->dirty_segmap)
		return -ENOMEM;

	init_dirty_segmap(sbi);
	return 0;
}

int build_segment_manager(struct hmfs_sb_info *sbi)
{
	struct hmfs_super_block *raw_super = HMFS_RAW_SUPER(sbi);
	struct hmfs_sm_info *sm_info;
	int err;
	pgc_t user_segments, main_segments;

	sm_info = kzalloc(sizeof(struct hmfs_sm_info), GFP_KERNEL);
	if (!sm_info)
		return -ENOMEM;

	/* init sm info */
	sbi->sm_info = sm_info;
	sm_info->segment_count = le64_to_cpu(raw_super->segment_count);
	main_segments = le64_to_cpu(raw_super->segment_count_main);
	sm_info->main_segments = main_segments;
	user_segments = sm_info->main_segments * (100 - DEF_OP_SEGMENTS) / 100;
	sm_info->ovp_segments = sm_info->main_segments - user_segments;
	sm_info->limit_invalid_blocks = main_segments * HMFS_PAGE_PER_SEG
			* LIMIT_INVALID_BLOCKS / 100;
	sm_info->limit_free_blocks = main_segments * HMFS_PAGE_PER_SEG 
			* LIMIT_FREE_BLOCKS / 100;
	sm_info->severe_free_blocks = main_segments * HMFS_PAGE_PER_SEG 
			* SEVERE_FREE_BLOCKS / 100;

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
	build_sit_entries(sbi);

	init_free_segmap(sbi);
	err = build_dirty_segmap(sbi);
	if (err)
		return err;

	init_min_max_mtime(sbi);
	return 0;
}

static void destroy_dirty_segmap(struct hmfs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);

	if (!dirty_i)
		return;

	kfree(dirty_i->dirty_segmap);

	SM_I(sbi)->dirty_info = NULL;
	kfree(dirty_i);
}

static void destroy_curseg(struct hmfs_sb_info *sbi)
{
	struct curseg_info *array = SM_I(sbi)->curseg_array;

	if (!array)
		return;
	SM_I(sbi)->curseg_array = NULL;
	kfree(array);
}

static void destroy_free_segmap(struct hmfs_sb_info *sbi)
{
	struct free_segmap_info *free_i = SM_I(sbi)->free_info;

	if (!free_i)
		return;
	SM_I(sbi)->free_info = NULL;
	kfree(free_i->free_segmap);
	kfree(free_i->prefree_segmap);
	kfree(free_i);
}

static void destroy_sit_info(struct hmfs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);

	if (!sit_i)
		return;

	vfree(sit_i->sentries);
	kfree(sit_i->dirty_sentries_bitmap);

	SM_I(sbi)->sit_info = NULL;
	kfree(sit_i);
}

void destroy_segment_manager(struct hmfs_sb_info *sbi)
{
	struct hmfs_sm_info *sm_info = SM_I(sbi);
	
	destroy_dirty_segmap(sbi);
	destroy_curseg(sbi);
	destroy_free_segmap(sbi);
	destroy_sit_info(sbi);
	sbi->sm_info = NULL;
	kfree(sm_info);
}

struct hmfs_summary_block *get_summary_block(struct hmfs_sb_info *sbi,
				seg_t segno)
{
	struct hmfs_summary_block *summary_blk;
	
	summary_blk = HMFS_SUMMARY_BLOCK(sbi->ssa_entries);
	return &summary_blk[segno];
}

struct hmfs_summary *get_summary_by_addr(struct hmfs_sb_info *sbi,
				block_t blk_addr)
{
	seg_t segno;
	unsigned int blkoff;
	struct hmfs_summary_block *summary_blk = NULL;

	segno = GET_SEGNO(sbi, blk_addr);
	blkoff = GET_SEG_OFS(sbi, blk_addr);
	summary_blk = get_summary_block(sbi, segno);

	return &summary_blk->entries[blkoff];
}
