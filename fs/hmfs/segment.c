#include <linux/vmalloc.h>
#include "segment.h"
#include "node.h"

/*
 * Judge whether an address is a valid address. i.e.
 * it fall into space where we have actually writen data
 * into. It's different from valid bits in summary entry
 */
bool is_valid_address(struct hmfs_sb_info *sbi, block_t addr)
{
	seg_t segno = GET_SEGNO(sbi, addr);
	struct hmfs_checkpoint *hmfs_cp = CM_I(sbi)->last_cp_i->cp;
	int i;

	for (i = 0; i < HMFS_MAX_CUR_SEG_COUNT; i++) {
		if (segno == le32_to_cpu(hmfs_cp->cur_segno[i]))
			return GET_SEG_OFS(sbi, addr) <= le32_to_cpu(hmfs_cp->cur_blkoff[i]);
	}
	
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

void reset_new_segmap(struct hmfs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct seg_entry *se;
	seg_t segno = 0;
	int i;
	uint32_t block_throw = 0;

	while (1) {
		segno = find_next_bit(sit_i->new_segmap, TOTAL_SEGS(sbi), segno);

		if (segno >= TOTAL_SEGS(sbi))
			break;
		
		se = get_seg_entry(sbi, segno);
		if (likely(se->invalid_bitmap)) {
			struct allocator *allocator = ALLOCATOR(sbi, se->type);
			if (atomic_read(&allocator->segno) != segno || 
					allocator->next_blkoff == SM_I(sbi)->page_4k_per_seg) {
				kfree(se->invalid_bitmap);
				se->invalid_bitmap = NULL;
			} else {
				memset(se->invalid_bitmap, 0, hmfs_bitmap_size(allocator->nr_pages));
			}
		}
		segno++;
	}
	memset(sit_i->new_segmap, 0, sit_i->bitmap_size);
	for (i = 0; i < sbi->nr_page_types; i++) {
		struct allocator *allocator = ALLOCATOR(sbi, i);
		uint32_t read = atomic_read(&allocator->read);
		uint32_t write = atomic_read(&allocator->write);

		block_throw += (write - read) << HMFS_BLOCK_SIZE_4K_BITS[i];
		hmfs_bug_on(sbi, write - read > allocator->buffer_index_mask);
		atomic_set(&allocator->read, write);
		if (allocator->next_blkoff != SM_I(sbi)->page_4k_per_seg) {
			set_bit(atomic_read(&allocator->segno), sit_i->new_segmap);
		}
		allocator->nr_cur_invalid = 0;
	}
	CM_I(sbi)->alloc_block_count += block_throw;
}

unsigned long get_seg_vblocks_in_summary(struct hmfs_sb_info *sbi, seg_t segno)
{
	struct hmfs_summary *sum;
	int off = 0;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	bool is_current;
	int count = 0;
	nid_t nid;
	const unsigned char seg_type = get_seg_entry(sbi, segno)->type;
	const unsigned int block_size = HMFS_BLOCK_SIZE_4K[seg_type];
	
	sum = get_summary_block(sbi, segno);

	//TODO: Set same part in garbage_collect as function
	for (off = 0; off < SM_I(sbi)->page_4k_per_seg; off += block_size, sum++) {
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
int invalidate_delete_block(struct hmfs_sb_info *sbi, block_t addr, 
				unsigned long vblocks)
{
	struct sit_info *sit_i = SIT_I(sbi);
	struct hmfs_summary *summary;
	struct seg_entry *se;
	seg_t segno;

	if (!is_new_block(sbi, addr))
		return 0;
	
	summary = get_summary_by_addr(sbi, addr);
	set_summary_nid(summary, NULL_NID);
	segno = GET_SEGNO(sbi, addr);
	lock_sentry(sit_i);
	update_sit_entry(sbi, segno, -vblocks);
	unlock_sentry(sit_i);

	se = get_seg_entry(sbi, segno);
	if (se->invalid_bitmap) {
		uint16_t ofs = GET_SEG_OFS(sbi, addr) >> HMFS_BLOCK_SIZE_4K_BITS[SEG_DATA_INDEX];
		set_bit(ofs, se->invalid_bitmap);
	}

	test_and_set_bit(segno, DIRTY_I(sbi)->dirty_segmap);
	return vblocks;
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

void update_sit_entry(struct hmfs_sb_info *sbi, seg_t segno, int del)
{
	struct seg_entry *se;
	struct sit_info *sit_i = SIT_I(sbi);
	long new_vblocks;

	se = get_seg_entry(sbi, segno);
	new_vblocks = se->valid_blocks + del;

	hmfs_dbg_on(new_vblocks < 0 || new_vblocks > SM_I(sbi)->segment_size >> HMFS_BLOCK_SIZE_BITS(0),
			"Invalid value of valid_blocks: %ld free:%d prefree:%d dirty:%d\n",
			new_vblocks, test_bit(segno, FREE_I(sbi)->free_segmap),
			test_bit(segno, FREE_I(sbi)->prefree_segmap), 
			test_bit(segno, DIRTY_I(sbi)->dirty_segmap));
	hmfs_bug_on(sbi, new_vblocks < 0 || new_vblocks > 
			SM_I(sbi)->segment_size >> HMFS_BLOCK_SIZE_BITS(0));

	se->valid_blocks = new_vblocks;
	se->mtime = get_mtime(sbi);
	__mark_sit_entry_dirty(sit_i, segno);
}

static void reset_curseg(struct allocator *allocator)
{
	atomic_set(&allocator->segno, allocator->next_segno);
	allocator->next_blkoff = 0;
	allocator->next_segno = NULL_SEGNO;
}

//TODO:check blkoff
inline block_t __cal_page_addr(struct hmfs_sb_info *sbi, seg_t segno, uint16_t blkoff)
{
	return ((uint64_t)segno << SM_I(sbi)->segment_size_bits) + (blkoff << HMFS_MIN_PAGE_SIZE_BITS)
				+ sbi->main_addr_start;
}

static inline unsigned long cal_page_addr(struct hmfs_sb_info *sbi,	struct allocator *allocator)
{
	return __cal_page_addr(sbi, atomic_read(&allocator->segno),	allocator->next_blkoff);
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
	segno = find_next_zero_bit(free_i->free_segmap, TOTAL_SEGS(sbi), *newseg);
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
	/* TODO: Need not to clear SSA */
	ssa = get_summary_block(sbi, segno);
	memset(ssa, 0, SM_I(sbi)->summary_block_size);
unlock:
	unlock_write_segmap(free_i);
	return ret;
}

static int move_to_new_segment(struct hmfs_sb_info *sbi, struct allocator *allocator)
{
	seg_t segno = atomic_read(&allocator->segno);
	int ret = get_new_segment(sbi, &segno);
	uint8_t seg_type = allocator - SM_I(sbi)->allocators;
	uint16_t bitmap_size;
	
	if (ret)
		return ret;
	get_seg_entry(sbi, segno)->type = seg_type;
	bitmap_size = hmfs_bitmap_size(allocator->nr_pages);
	get_seg_entry(sbi, segno)->invalid_bitmap = kzalloc(bitmap_size, GFP_KERNEL);
	
	/* Set new segment bit */
	/* We use the new_segmap to collect segments newly created in current version.
	 * And then we could collect the truncated blocks under the help of new_segmap.
	 * And we don't want the blocks in older version. 
	 */
	set_bit(segno, SIT_I(sbi)->new_segmap);


	allocator->next_segno = segno;
	reset_curseg(allocator);
	return 0;
}

static block_t get_free_block(struct hmfs_sb_info *sbi, int seg_type, bool sit_lock)
{
	block_t page_addr = 0;
	struct sit_info *sit_i;
	struct allocator *allocator = ALLOCATOR(sbi, seg_type);
	int ret;

alloc_buf:
	if (allocator->mode & ALLOC_BUF) {
		uint32_t write = atomic_read(&allocator->write);
		uint32_t read = __atomic_add_unless(&allocator->read, 1, write);

		if (write - read < allocator->bg_bc_limit) {
			start_bc(sbi);	
		}
		
		if (read == write) {
			if (has_not_enough_free_segs(sbi)) {
				if (allocator->nr_cur_invalid > allocator->bc_threshold) {
					if (trylock_gc(sbi)) {
						hmfs_collect_blocks(sbi);
						unlock_gc(sbi);
						goto alloc_buf;
					}
				}
			}
			goto alloc_log;
		}
		
		hmfs_bug_on(sbi, read > write);
		return allocator->buffer[read & allocator->buffer_index_mask];
	}

alloc_log:
	sit_i = SIT_I(sbi);

	lock_allocator(allocator);
	
	if (allocator->next_blkoff == SM_I(sbi)->page_4k_per_seg) {
		if ((allocator->mode & ALLOC_LOG) && sbi->gc_thread) {
			allocator->mode = ALLOC_BUF;
			unlock_allocator(allocator);
			goto alloc_buf;
		}

		ret = move_to_new_segment(sbi, allocator);
		if (ret) {
			unlock_allocator(allocator);
			return 0;
		}
		allocator->mode = ALLOC_LOG;
	}

	page_addr = cal_page_addr(sbi, allocator);

	if (sit_lock)
		lock_sentry(sit_i);
	update_sit_entry(sbi, atomic_read(&allocator->segno), HMFS_BLOCK_SIZE_4K[seg_type]);
	
	if (sit_lock)
		unlock_sentry(sit_i);

	allocator->next_blkoff += HMFS_BLOCK_SIZE_4K[seg_type];

	unlock_allocator(allocator);

	return page_addr;
}

inline block_t alloc_free_data_block(struct hmfs_sb_info *sbi, char seg_type)
{
	return get_free_block(sbi, seg_type, true);
}

inline block_t alloc_free_node_block(struct hmfs_sb_info *sbi, bool sit_lock)
{
	return get_free_block(sbi, SEG_NODE_INDEX, true);
}

void recovery_sit_entries(struct hmfs_sb_info *sbi, struct hmfs_checkpoint *hmfs_cp)
{
	int nr_logs, i, nr_segs, num = 0;
	struct hmfs_sit_log_entry *sit_log;
	struct hmfs_sit_entry *sit_entry;
	block_t seg_addr;
	seg_t sit_segno, segno;
	const unsigned long logs_entry_per_seg = LOGS_ENTRY_PER_SEG(sbi);

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
			if (num % logs_entry_per_seg == 0)
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
				summary = get_summary_block(sbi, offset);
				for (i = 0; i < SM_I(sbi)->page_4k_per_seg; i++, summary++) {
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
	memset(sit_i->dirty_sentries_bitmap, 0, sit_i->bitmap_size);
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
	const unsigned long logs_entry_per_seg = LOGS_ENTRY_PER_SEG(sbi);

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
	nr_segs = (nr_logs + logs_entry_per_seg - 1) / logs_entry_per_seg - 1;
	sit_segno = le32_to_cpu(hmfs_cp->cur_segno[SEG_NODE_INDEX]);
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
			i = logs_entry_per_seg;
			nr_segs++;
		}
		if (offset < total_segs) {
			seg_entry = get_seg_entry(sbi, offset);
			sit_log->segno = cpu_to_le32(offset);
			sit_log->mtime = cpu_to_le32(seg_entry->mtime);
			sit_log->vblocks = cpu_to_le32(seg_entry->valid_blocks);
			sit_log->type = seg_entry->type;
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
	memset(sit_i->dirty_sentries_bitmap, 0, sit_i->bitmap_size);
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
	uint64_t bitmap_size;

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

	sit_i->new_segmap = kzalloc(bitmap_size, GFP_KERNEL);
	if (!sit_i->new_segmap)
		return -ENOMEM;

	memset(sit_i->dirty_sentries_bitmap, 0, bitmap_size);
	memset(sit_i->new_segmap, 0, bitmap_size);

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
	void *ssa;

	lock_write_segmap(free_i);
	while (1) {
		segno =find_next_bit(bitmap, total_segs, segno);
		if (segno >= total_segs)
			break;
		clear_bit(segno, bitmap);
		if (test_and_clear_bit(segno, free_i->free_segmap)) {
			free_i->free_segments++;
		}
		ssa = get_summary_block(sbi, segno);
		memset(ssa, 0, SM_I(sbi)->summary_block_size);
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
	if (!free_i->free_segmap)
		return -ENOMEM;
	
	free_i->prefree_segmap = kmalloc(bitmap_size, GFP_KERNEL);
	if (!free_i->prefree_segmap)
		return -ENOMEM;

	/* set all segments as dirty temporarily */
	memset(free_i->free_segmap, 0xff, bitmap_size);
	memset(free_i->prefree_segmap, 0, bitmap_size);

	/* init free segmap information */
	free_i->free_segments = 0;
	rwlock_init(&free_i->segmap_lock);
	return 0;
}

static int build_allocators(struct hmfs_sb_info *sbi)
{
	struct allocator *array;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct hmfs_checkpoint *hmfs_cp = cm_i->last_cp_i->cp;
	int pages_per_buffer;
	int i;
	long buffer_size;

	array = kzalloc(sizeof(struct allocator) * sbi->nr_page_types, GFP_KERNEL);
	if (!array)
		return -ENOMEM;

	SM_I(sbi)->allocators = array;
	
	for (i = 0; i < sbi->nr_page_types; i++) {
		mutex_init(&array[i].alloc_lock);
		array[i].next_blkoff = le32_to_cpu(hmfs_cp->cur_blkoff[i]);
		atomic_set(&array[i].segno, le32_to_cpu(hmfs_cp->cur_segno[i]));
		array[i].next_segno = NULL_SEGNO;
		array[i].nr_cur_invalid = 0;

		/* Initialize truncated blocks structure */
		array[i].mode = ALLOC_LOG;
		array[i].nr_pages = SM_I(sbi)->segment_size >> HMFS_BLOCK_SIZE_BITS(i);
		atomic_set(&array[i].write, 0);
		atomic_set(&array[i].read, 0);
		pages_per_buffer = SM_I(sbi)->segment_size >> HMFS_BLOCK_SIZE_BITS(i);

		buffer_size = pages_per_buffer * sizeof(block_t);
		if (buffer_size > MAX_BUFFER_PAGES << PAGE_SHIFT) {
			buffer_size = MAX_BUFFER_PAGES << PAGE_SHIFT;
		} else if (buffer_size < MIN_BUFFER_PAGES << PAGE_SHIFT) {
			buffer_size = MIN_BUFFER_PAGES << PAGE_SHIFT;
		}

		array[i].buffer = kzalloc(buffer_size, GFP_KERNEL);
		if (!array[i].buffer)
			return -ENOMEM;
		
		pages_per_buffer = buffer_size / sizeof(block_t);
		array[i].buffer_index_mask = pages_per_buffer - 1;

		array[i].bg_bc_limit = pages_per_buffer >> 1;
		array[i].bc_threshold = SM_I(sbi)->page_4k_per_seg >> 2;
	}

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
	struct seg_entry *sentry = NULL;
	seg_t segno;
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
	for (i = 0; i < sbi->nr_page_types; i++) {
		struct allocator *allocator = ALLOCATOR(sbi, i);
		segno = atomic_read(&allocator->segno);
		if (segno != NULL_SEGNO) {
			__set_test_and_inuse(sbi, segno);
			/* Set bit of head segments is OK. Even if it contains blocks of
			 * older version, those blocks would not be mark as invalid and BC
			 * would not collect them in buffer of allocator
			 */
			set_bit(segno, SIT_I(sbi)->new_segmap);
			if (allocator->next_blkoff != SM_I(sbi)->page_4k_per_seg) {
				get_seg_entry(sbi, segno)->invalid_bitmap = kzalloc(
						hmfs_bitmap_size(allocator->nr_pages), GFP_KERNEL);
			}
		}
	}
}

static void init_dirty_segmap(struct hmfs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i = DIRTY_I(sbi);
	struct free_segmap_info *free_i = FREE_I(sbi);
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
		if (valid_blocks >= SM_I(sbi)->page_4k_per_seg || !valid_blocks)
			continue; //MZX : a segment is not dirty <=> either all or none of the blocks in the segment is valid.
		test_and_set_bit(segno, dirty_i->dirty_segmap);
	}

	/* Clear the current segments */
	for (i = 0; i < sbi->nr_page_types; i++) {
		segno = atomic_read(&ALLOCATOR(sbi, i)->segno);
		if (segno != NULL_SEGNO)
			clear_bit(segno, dirty_i->dirty_segmap);
	}
}

static int build_dirty_segmap(struct hmfs_sb_info *sbi)
{
	struct dirty_seglist_info *dirty_i;

	dirty_i = kzalloc(sizeof(struct dirty_seglist_info), GFP_KERNEL);
	if (!dirty_i)
		return -ENOMEM;

	SM_I(sbi)->dirty_info = dirty_i;

	dirty_i->dirty_segmap = kzalloc(hmfs_bitmap_size(TOTAL_SEGS(sbi)), GFP_KERNEL);

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
	main_segments = le64_to_cpu(raw_super->segment_count_main);
	user_segments = main_segments * (100 - DEF_OP_SEGMENTS) / 100;
	sm_info->segment_size_bits = calculate_segment_size_bits(sbi->max_page_size_bits);
	sm_info->segment_size = 1 << sm_info->segment_size_bits;
	sm_info->segment_size_mask = ~(sm_info->segment_size - 1);
	sm_info->page_4k_per_seg = sm_info->segment_size >> HMFS_MIN_PAGE_SIZE_BITS;
	sm_info->page_4k_per_seg_bits = sm_info->segment_size_bits
			- HMFS_MIN_PAGE_SIZE_BITS;

	sm_info->ovp_segments = main_segments - user_segments;
	sm_info->limit_invalid_blocks = main_segments * sm_info->page_4k_per_seg *
			LIMIT_INVALID_BLOCKS / 100;
	sm_info->limit_free_blocks = main_segments * sm_info->page_4k_per_seg
			* LIMIT_FREE_BLOCKS / 100;
	sm_info->severe_free_blocks = main_segments * sm_info->page_4k_per_seg
			* SEVERE_FREE_BLOCKS / 100;
	sm_info->summary_block_size = sm_info->page_4k_per_seg * sizeof(struct hmfs_summary);

	err = build_sit_info(sbi);
	if (err)
		return err;
	err = build_free_segmap(sbi);
	if (err)
		return err;
	err = build_allocators(sbi);
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

	if (dirty_i->dirty_segmap)
		kfree(dirty_i->dirty_segmap);

	SM_I(sbi)->dirty_info = NULL;
	kfree(dirty_i);
}

static void destroy_allocators(struct hmfs_sb_info *sbi)
{
	struct allocator *array = SM_I(sbi)->allocators;
	int i;

	if (!array)
		return;
	for (i = 0; i < sbi->nr_page_types; i++) {
		if (!array[i].buffer)
			break;
		kfree(array[i].buffer);
		array[i].buffer = NULL;
	}
	SM_I(sbi)->allocators = NULL;
	kfree(array);
}

static void destroy_free_segmap(struct hmfs_sb_info *sbi)
{
	struct free_segmap_info *free_i = SM_I(sbi)->free_info;

	if (!free_i)
		return;
	SM_I(sbi)->free_info = NULL;
	if (free_i->free_segmap)
		kfree(free_i->free_segmap);
	if (free_i->prefree_segmap)
		kfree(free_i->prefree_segmap);
	kfree(free_i);
}

static void destroy_sit_info(struct hmfs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);
	int i;

	if (!sit_i)
		return;

	if (sit_i->sentries) {
		for (i = 0; i < TOTAL_SEGS(sbi); i++) {
			if (get_seg_entry(sbi, i)->invalid_bitmap) {
				hmfs_bug_on(sbi, !test_bit(i, sit_i->new_segmap));
				kfree(get_seg_entry(sbi, i)->invalid_bitmap);
			}
		}
		vfree(sit_i->sentries);
	}

	if (sit_i->new_segmap)
		kfree(sit_i->new_segmap);
	if (sit_i->dirty_sentries_bitmap)
		kfree(sit_i->dirty_sentries_bitmap);

	SM_I(sbi)->sit_info = NULL;
	kfree(sit_i);
}

void destroy_segment_manager(struct hmfs_sb_info *sbi)
{
	struct hmfs_sm_info *sm_info = SM_I(sbi);
	
	destroy_dirty_segmap(sbi);
	destroy_allocators(sbi);
	destroy_free_segmap(sbi);
	destroy_sit_info(sbi);
	sbi->sm_info = NULL;
	kfree(sm_info);
}

struct hmfs_summary *get_summary_block(struct hmfs_sb_info *sbi, seg_t segno)
{
	return sbi->ssa_entries + (segno << SM_I(sbi)->page_4k_per_seg_bits);
}

struct hmfs_summary *get_summary_by_addr(struct hmfs_sb_info *sbi, block_t blk_addr)
{
	return sbi->ssa_entries + ((blk_addr - sbi->main_addr_start) >> HMFS_MIN_PAGE_SIZE_BITS);
}

struct hmfs_summary *get_summary_by_ni(struct hmfs_sb_info *sbi, struct node_info *ni) {
	return get_summary_by_addr(sbi, ni->blk_addr);
}