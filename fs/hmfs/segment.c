#include "segment.h"		//hmfs.h is included

static void __mark_sit_entry_dirty(struct sit_info *sit_i, seg_t segno)
{
	if (!__test_and_set_bit(segno, sit_i->dirty_sentries_bitmap))
		sit_i->dirty_sentries++;
}

static void init_min_max_mtime(struct hmfs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);
	seg_t segno;
	unsigned long long mtime;

	mutex_lock(&sit_i->sentry_lock);

	sit_i->min_mtime = LLONG_MAX;

	for (segno = 0; segno < TOTAL_SEGS(sbi); segno++) {
		mtime = get_seg_entry(sbi, segno)->mtime;

		if (sit_i->min_mtime > mtime)
			sit_i->min_mtime = mtime;
	}
	sit_i->max_mtime = get_mtime(sbi);
	mutex_unlock(&sit_i->sentry_lock);
}

static void update_sit_entry(struct hmfs_sb_info *sbi, seg_t segno,
			     int del)
{
	struct seg_entry *se;
	struct sit_info *sit_i = SIT_I(sbi);
	long new_vblocks;

	se = get_seg_entry(sbi, segno);
	new_vblocks = se->valid_blocks + del;

	hmfs_bug_on(sbi, new_vblocks < 0 || new_vblocks > HMFS_PAGE_PER_SEG);

	se->valid_blocks = new_vblocks;
	se->mtime = get_mtime(sbi);
	__mark_sit_entry_dirty(sit_i, segno);
}

static void reset_curseg(struct curseg_info *seg_i)
{
	seg_i->segno = seg_i->next_segno;
	seg_i->next_blkoff = 0;
	seg_i->next_segno = 0;
}

inline block_t __cal_page_addr(struct hmfs_sb_info *sbi,
					  seg_t segno, int blkoff)
{
	return (segno << HMFS_SEGMENT_SIZE_BITS) +
	 (blkoff << HMFS_PAGE_SIZE_BITS)
	 + sbi->main_addr_start;
}

static inline unsigned long cal_page_addr(struct hmfs_sb_info *sbi,
					  struct curseg_info *seg_i)
{
	return __cal_page_addr(sbi, seg_i->segno, seg_i->next_blkoff);
}

/*
 * get_new_segment -- Find a new segment from the free segments bitmap
 * @newseg returns the found segment
 * must be success (otherwise cause error)
 */
static void get_new_segment(struct hmfs_sb_info *sbi, seg_t *newseg)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	seg_t segno;
	bool retry = false;

	write_lock(&free_i->segmap_lock);

retry:
	segno = find_next_zero_bit(free_i->free_segmap,
				   TOTAL_SEGS(sbi), *newseg);
	if(segno >= TOTAL_SEGS(sbi)) {
		*newseg = 0;
		if(!retry) {
			retry = true;
			goto retry;
		}
		hmfs_bug_on(sbi, 1);
	}

	hmfs_bug_on(sbi, test_bit(segno, free_i->free_segmap));
	__set_inuse(sbi, segno);
	*newseg = segno;
	write_unlock(&free_i->segmap_lock);
}

static void move_to_new_segment(struct hmfs_sb_info *sbi,
				struct curseg_info *seg_i)
{
	seg_t segno = seg_i->segno;

	get_new_segment(sbi, &segno);
	seg_i->next_segno = segno;
	reset_curseg(seg_i);
}

static block_t get_free_block(struct hmfs_sb_info *sbi, int seg_type)
{
	block_t page_addr = 0;
	struct sit_info *sit_i = SIT_I(sbi);
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct curseg_info *seg_i = &(CURSEG_I(sbi)[seg_type]);

	mutex_lock(&seg_i->curseg_mutex);
	page_addr = cal_page_addr(sbi, seg_i);

	mutex_lock(&sit_i->sentry_lock);
	update_sit_entry(sbi, seg_i->segno, 1);
	mutex_unlock(&sit_i->sentry_lock);

	seg_i->next_blkoff++;
	if (seg_i->next_blkoff == HMFS_PAGE_PER_SEG) {
		move_to_new_segment(sbi, seg_i);

		spin_lock(&cm_i->stat_lock);
		cm_i->left_blocks_count[seg_type] += HMFS_PAGE_PER_SEG;
		spin_unlock(&cm_i->stat_lock);
	}
	mutex_unlock(&seg_i->curseg_mutex);

	return page_addr;
}

block_t alloc_free_data_block(struct hmfs_sb_info * sbi)
{
	return get_free_block(sbi, CURSEG_DATA);
}

block_t alloc_free_node_block(struct hmfs_sb_info * sbi)
{
	return get_free_block(sbi, CURSEG_NODE);
}

static int restore_curseg_summaries(struct hmfs_sb_info *sbi)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct curseg_info *seg_i = CURSEG_I(sbi), *node_seg_i, *data_seg_i;
	struct hmfs_checkpoint *hmfs_cp = cm_i->last_cp_i->cp;
	unsigned short node_next_blkoff, data_next_blkoff;

	node_seg_i = &seg_i[CURSEG_NODE];
	mutex_lock(&node_seg_i->curseg_mutex);
	node_seg_i->segno = le32_to_cpu(hmfs_cp->cur_node_segno);
	node_next_blkoff = le16_to_cpu(hmfs_cp->cur_node_blkoff);
	node_seg_i->next_blkoff = node_next_blkoff;
	node_seg_i->next_segno = 0;
	mutex_unlock(&node_seg_i->curseg_mutex);

	data_seg_i = &seg_i[CURSEG_DATA];
	mutex_lock(&data_seg_i->curseg_mutex);
	data_seg_i->segno = le32_to_cpu(hmfs_cp->cur_data_segno);
	data_next_blkoff = le16_to_cpu(hmfs_cp->cur_data_blkoff);
	data_seg_i->next_blkoff = data_next_blkoff;
	data_seg_i->next_segno = 0;
	mutex_unlock(&data_seg_i->curseg_mutex);

	spin_lock(&cm_i->stat_lock);
	node_next_blkoff = HMFS_PAGE_PER_SEG - node_next_blkoff;
	data_next_blkoff = HMFS_PAGE_PER_SEG - data_next_blkoff;
	cm_i->left_blocks_count[CURSEG_NODE] = node_next_blkoff;
	cm_i->left_blocks_count[CURSEG_DATA] = data_next_blkoff;
	spin_unlock(&cm_i->stat_lock);
	return 0;
}

/* 
 * new_curseg -- Allocate a current working segment.
 * XXX : use this instead of s_op 
 *
 */
static void new_curseg(struct hmfs_sb_info *sbi)
{
	struct curseg_info *curseg = CURSEG_I(sbi);
	seg_t segno = curseg->segno;

	get_new_segment(sbi, &segno);
	curseg->next_segno = segno;
}

void flush_sit_entries(struct hmfs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);
	unsigned long offset = 0;
	pgc_t total_segs = TOTAL_SEGS(sbi);
	struct hmfs_sit_entry *sit_entry;
	struct seg_entry *seg_entry;
	unsigned long *bitmap = sit_i->dirty_sentries_bitmap;
#ifdef CONFIG_HMFS_DEBUG
	pgc_t nrdirty = 0;

	mutex_lock(&sit_i->sentry_lock);
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
	mutex_unlock(&sit_i->sentry_lock);
#endif
	mutex_lock(&sit_i->sentry_lock);

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
	sit_i->dirty_sentries = 0;
	memset_nt(sit_i->dirty_sentries_bitmap, 0, sit_i->bitmap_size);
	mutex_unlock(&sit_i->sentry_lock);
}

void allocate_new_segments(struct hmfs_sb_info *sbi)
{
	struct curseg_info *curseg;
	seg_t old_curseg;

	curseg = CURSEG_I(sbi);
	old_curseg = curseg->segno;
	new_curseg(sbi);
}

static inline void __set_test_and_inuse(struct hmfs_sb_info *sbi,
					seg_t segno)
{
	struct free_segmap_info *free_i = FREE_I(sbi);

	write_lock(&free_i->segmap_lock);
	if (!test_and_set_bit(segno, free_i->free_segmap)) {
		free_i->free_segments--;
	}
	write_unlock(&free_i->segmap_lock);
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
	if (!free_i->free_segmap)
		return -ENOMEM;

	/* set all segments as dirty temporarily */
	memset(free_i->free_segmap, 0xff, bitmap_size);

	/* init free segmap information */
	free_i->free_segments = 0;
	rwlock_init(&free_i->segmap_lock);
	return 0;
}

static int build_curseg(struct hmfs_sb_info *sbi)
{
	struct curseg_info *array;
	int i;

	array = kzalloc(sizeof(struct curseg_info) * NR_CURSEG_TYPE,
					GFP_KERNEL);
	if (!array)
		return -ENOMEM;

	SM_I(sbi)->curseg_array = array;

	for (i = 0; i < NR_CURSEG_TYPE; i++) {
		mutex_init(&array[i].curseg_mutex);
		array[i].segno = NULL_SEGNO;
		array[i].next_blkoff = 0;
	}
	return restore_curseg_summaries(sbi);
}

static void build_sit_entries(struct hmfs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct seg_entry *seg_entry;
	struct hmfs_sit_entry *sit_entry;
	unsigned int start;

	mutex_lock(&sit_i->sentry_lock);
	for (start = 0; start < TOTAL_SEGS(sbi); start++) {
		seg_entry = get_seg_entry(sbi, start);
		sit_entry = get_sit_entry(sbi, start);
		seg_info_from_raw_sit(seg_entry, sit_entry);
	}
	mutex_unlock(&sit_i->sentry_lock);
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
			write_lock(&free_i->segmap_lock);
			clear_bit(start, free_i->free_segmap);
			free_i->free_segments++;
			write_unlock(&free_i->segmap_lock);
		}
	}

	/* set use the current segments */
	curseg_t = CURSEG_I(sbi);
	for (i = 0; i < NR_CURSEG_TYPE; i++)
		__set_test_and_inuse(sbi, curseg_t[i].segno);
}

static void init_dirty_segmap(struct hmfs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	struct free_segmap_info *free_i = FREE_I(sbi);
	seg_t segno, total_segs = TOTAL_SEGS(sbi), offset = 0;
	unsigned short valid_blocks;

	while (1) {
		/* find dirty segmap based on free segmap */
		segno = find_next_inuse(free_i, total_segs, offset);
		if (segno >= total_segs)
			break;
		offset = segno + 1;
		valid_blocks = get_seg_entry(sbi, segno)->valid_blocks;
		if (valid_blocks >= HMFS_PAGE_PER_SEG || !valid_blocks)
			continue;
		mutex_lock(&dirty_i->seglist_lock);
		test_and_set_bit(segno, dirty_i->dirty_segmap);
		mutex_unlock(&dirty_i->seglist_lock);
	}
}

static int build_dirty_segmap(struct hmfs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i;
	unsigned int bitmap_size;

	dirty_i = kzalloc(sizeof(struct dirty_seglist_info), GFP_KERNEL);
	if (!dirty_i)
		return -ENOMEM;

	SM_I(sbi)->dirty_info = dirty_i;
	mutex_init(&dirty_i->seglist_lock);

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
	sm_info->limit_invalid_blocks = main_segments * LIMIT_INVALID_BLOCKS / 100;
	sm_info->limit_free_blocks = main_segments * LIMIT_FREE_BLOCKS / 100;

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

	mutex_lock(&dirty_i->seglist_lock);
	kfree(dirty_i->dirty_segmap);
	mutex_unlock(&dirty_i->seglist_lock);

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
	struct hmfs_summary_block *summary_blk =
			(struct hmfs_summary_block *)sbi->ssa_entries;

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

void invalidate_block_after_dc(struct hmfs_sb_info *sbi, block_t blk_addr)
{
	struct sit_info *sit_i = SIT_I(sbi);
	seg_t segno = GET_SEGNO(sbi, blk_addr);

	mutex_lock(&sit_i->sentry_lock);
	update_sit_entry(sbi, segno, -1);
	mutex_unlock(&sit_i->sentry_lock);
}

// Counter operations
//      dc: decrease counter by one
/*
 * Workflow:
 * [1] Decrease the count of this block
 * [2] If the count is greater than 0, RETURN
 * [3] Initial invalidate_block() to claim this block is now invalid
 * [4] Traverse each pointer of its children, GOTO [1] with its block address
 */

//      Decrease the count of NAT root block
//      Should be triggered by checkpoint deletion only
//      Output: The block which decreasing operation ends
void dc_nat_root(struct hmfs_sb_info *sbi, block_t nat_root_addr)
{
	return dc_block(sbi, nat_root_addr);
}

//      Decrease the count of checkpoint block itself
//      Should be triggered by checkpoint deletion only
void dc_checkpoint(struct hmfs_sb_info *sbi, block_t cp_addr)
{
	return dc_checkpoint_block(sbi, cp_addr);
}

//      Entrance function for decreasing block count
//      Switch blk_addr to 7 different handlers
void dc_block(struct hmfs_sb_info *sbi, block_t blk_addr)
{
	struct hmfs_summary *summary;
	int type;

	summary = get_summary_by_addr(sbi, blk_addr);
	type = get_summary_type(summary);

	switch (type) {
	case SUM_TYPE_DATA:
		dc_data(sbi, blk_addr);
	case SUM_TYPE_INODE:
		dc_inode(sbi, blk_addr);
	case SUM_TYPE_IDN:
		dc_indirect(sbi, blk_addr);
	case SUM_TYPE_DN:
		dc_direct(sbi, blk_addr);
	case SUM_TYPE_CP:
		dc_checkpoint_block(sbi, blk_addr);
	case SUM_TYPE_NATN:
		dc_nat_branch(sbi, blk_addr);
	case SUM_TYPE_NATD:
		dc_nat_block(sbi, blk_addr);
	}
}

//      Decrease the count of a block
//      In this design version, here is the only ADDR in DC operations
void dc_itself(struct hmfs_sb_info *sbi, block_t blk_addr)
{
	struct hmfs_summary *summary;
	int count;

	summary = get_summary_by_addr(sbi, blk_addr);
	count = le32_to_cpu(summary->count);
	count = count - 1;
	if (unlikely(count < 0)) {
		hmfs_bug_on(sbi, 1);
	}

	summary->count = cpu_to_le32(count);
}

void dc_nat_branch(struct hmfs_sb_info *sbi, block_t nat_branch_addr)
{
	int i = 0;
	struct hmfs_nat_node *nb = ADDR(sbi, nat_branch_addr);

	dc_itself(sbi, nat_branch_addr);
//      If count has decreased to 0
	invalidate_block_after_dc(sbi, nat_branch_addr);
	for (i = 0; i < ADDRS_PER_BLOCK; ++i) {
		dc_block(sbi, nb->addr[i]);
	}
}

void dc_nat_block(struct hmfs_sb_info *sbi, block_t nat_block_addr)
{
	int i = 0;
	struct hmfs_nat_node *nb = ADDR(sbi, nat_block_addr);

	dc_itself(sbi, nat_block_addr);
//      If count has decreased to 0
	invalidate_block_after_dc(sbi, nat_block_addr);
	for (i = 0; i < ADDRS_PER_BLOCK; ++i) {
		dc_block(sbi, nb->addr[i]);
	}
}

void dc_checkpoint_block(struct hmfs_sb_info *sbi,
			 block_t checkpoint_block_addr)
{
	dc_itself(sbi, checkpoint_block_addr);
//      If count has decreased to 0
	invalidate_block_after_dc(sbi, checkpoint_block_addr);
}

void dc_direct(struct hmfs_sb_info *sbi, block_t direct_block_addr)
{
	int i = 0;
	struct direct_node *dn = ADDR(sbi, direct_block_addr);
	dc_itself(sbi, direct_block_addr);
//      If count has decreased to 0
	invalidate_block_after_dc(sbi, direct_block_addr);
	for (i = 0; i < ADDRS_PER_BLOCK; ++i) {
		dc_block(sbi, dn->addr[i]);
	}
}

void dc_indirect(struct hmfs_sb_info *sbi, block_t idn_addr)
{
	dc_itself(sbi, idn_addr);
//      If count has decreased to 0
	invalidate_block_after_dc(sbi, idn_addr);
}

void dc_inode(struct hmfs_sb_info *sbi, block_t inode_block_addr)
{
	int i = 0;
	struct hmfs_inode *hi = ADDR(sbi, inode_block_addr);
	dc_itself(sbi, inode_block_addr);
//      If count has decreased to 0
	invalidate_block_after_dc(sbi, inode_block_addr);
	for (i = 0; i < NORMAL_ADDRS_PER_INODE; ++i) {
		dc_block(sbi, hi->i_addr[i]);
	}
}

void dc_data(struct hmfs_sb_info *sbi, block_t data_block_addr)
{
	dc_itself(sbi, data_block_addr);
//      If count has decreased to 0
	invalidate_block_after_dc(sbi, data_block_addr);
}

//      ic: increase counter by one
//      Increase the count of a block
int ic_block(struct hmfs_sb_info *sbi, block_t blk_addr)
{
	struct hmfs_summary *summary;
	int count = 0;

	summary = get_summary_by_addr(sbi, blk_addr);
	count = get_summary_count(summary);
	count = count + 1;
	if (unlikely(count >> 15 == 1))
		hmfs_bug_on(sbi, 1);

	set_summary_count(summary, count);
	return count;
}
