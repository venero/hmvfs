#ifndef HMFS_SEGMENT_H
#define HMFS_SEGMENT_H

#include "hmfs.h"

#define SIT_ENTRY_CLEAN			0
#define SIT_ENTRY_DIRTY				1

#define MAX_SIT_ITEMS_FOR_GANG_LOOKUP		10240

#define hmfs_bitmap_size(nr)			\
	(BITS_TO_LONGS(nr) * sizeof(unsigned long))
#define TOTAL_SEGS(sbi)	(sbi->segment_count_main)

/* constant macro */
#define NULL_SEGNO			((unsigned int)(~0))

#define LIMIT_INVALID_BLOCKS	25	/* percentage over total user space */
#define LIMIT_FREE_BLOCKS		60	/* percentage of free blocks over total user space */
#define SEVERE_FREE_BLOCKS		45	/* percentage of free blocks over total in emergency case */
#define NR_MAX_FG_SEGS			200

#define LOGS_ENTRY_PER_SEG(sbi)	(SM_I(sbi)->segment_size / sizeof(struct hmfs_sit_log_entry))

#define MAX_BUFFER_PAGES		4	/* Maximum pages for saving truncated block address in buffer */
#define MIN_BUFFER_PAGES		1	/* Minimum pages ... */

struct seg_entry {
	unsigned long mtime;			/* modification time of the segment */
	unsigned long *invalid_bitmap;	/* Bitmap of invalid blocks */
	uint16_t valid_blocks;			/* # of valid blocks */
	unsigned char type;				/* Type of segments */
};

struct sit_info {
	uint64_t bitmap_size;

	unsigned long *dirty_sentries_bitmap;	/* bitmap for dirty sentries */
	unsigned long *new_segmap;				/* bitmap of segments in current version */
	unsigned int dirty_sentries;			/* # of dirty sentries */
	struct mutex sentry_lock;				/* to protect SIT cache */
	struct seg_entry *sentries;				/* SIT segment-level cache */

	/* for cost-benefit valuing */
	//TODO: Remove xxx_time
	unsigned long long elapsed_time;	/* The elapsed time from FS format */
	unsigned long long mounted_time;	/* Timestamp for FS mounted */
	unsigned long long min_mtime;		/* Minimum mtime in SIT */
	unsigned long long max_mtime;		/* Maximum mtime in SIT */

};

/* Dirty segment is the segment which has both valid blocks and invalid blocks */
struct dirty_seglist_info {
	unsigned long *dirty_segmap;		/* bitmap for dirty segment */
};

/* Free segment is the segment which does not have valid blocks */
struct free_segmap_info {
	pgc_t free_segments;			/* # of free segments */
	rwlock_t segmap_lock;				/* free segmap lock */
	unsigned long *free_segmap;			/* free segment bitmap */
	unsigned long *prefree_segmap;
};

struct truncate_block {
	uint64_t addr;
	struct truncate_block *next;
}; 

enum {
	ALLOC_LOG = 0x01,	/* Allocate blocks in log */
	ALLOC_BUF = 0x10,	/* Allocate blocks in ring buffer */
};

/* For block allocation */
struct allocator {
	struct mutex alloc_lock;
	atomic_t segno;
	uint32_t next_blkoff;
	seg_t next_segno;
	uint32_t nr_cur_invalid;	/* # of invalid blocks in new version */
	volatile char mode;
	uint16_t nr_pages;	/* Constants: page number per segments */
	uint16_t bg_bc_limit;	/* # of buffer entries to start bg BC */
	uint16_t bc_threshold;	/* minimum # of nr_cur_invalid to start BC */
	
	block_t *buffer;
	atomic_t write;		/* write index of buffer ring */
	atomic_t read;		/* read index of buffer ring */
	uint32_t buffer_index_mask;
};

struct hmfs_sm_info {
	struct sit_info *sit_info;				/* whole segment information */
	struct free_segmap_info *free_info;		/* free segment information */
	struct dirty_seglist_info *dirty_info;	/* dirty segment information */
	struct allocator *allocators;		/* active block allocation information */

	pgc_t reserved_segments;			/* # of reserved segments */
	pgc_t ovp_segments;				/* # of overprovision segments */
	pgc_t limit_invalid_blocks;		/* # of limit invalid blocks */
	pgc_t limit_free_blocks;		/* # of limit free blocks */
	pgc_t severe_free_blocks;		/* # of free blocks in emergency case */
	uint32_t summary_block_size;
	unsigned long page_4k_per_seg;
	unsigned int page_4k_per_seg_bits;
	unsigned long segment_size;
	unsigned long segment_size_bits;
	unsigned long segment_size_mask;
};

/* Segment inlined functions */
static inline void lock_read_segmap(struct free_segmap_info *free_i)
{
	read_lock(&free_i->segmap_lock);
}

static inline void unlock_read_segmap(struct free_segmap_info *free_i)
{
	read_unlock(&free_i->segmap_lock);
}

static inline void lock_write_segmap(struct free_segmap_info *free_i)
{
	write_lock(&free_i->segmap_lock);
}

static inline void unlock_write_segmap(struct free_segmap_info *free_i)
{
	write_unlock(&free_i->segmap_lock);
}

static inline void lock_sentry(struct sit_info *sit_i)
{
	mutex_lock(&sit_i->sentry_lock);
}

static inline void unlock_sentry(struct sit_info *sit_i)
{
	mutex_unlock(&sit_i->sentry_lock);
}

static inline void lock_allocator(struct allocator *allocator)
{
	mutex_lock(&allocator->alloc_lock);
}

static inline void unlock_allocator(struct allocator *allocator)
{
	mutex_unlock(&allocator->alloc_lock);
}

static inline struct hmfs_sm_info *SM_I(struct hmfs_sb_info *sbi)
{
	return sbi->sm_info;
}

static inline struct sit_info *SIT_I(struct hmfs_sb_info *sbi)
{
	return (SM_I(sbi)->sit_info);
}

static inline struct seg_entry *get_seg_entry(struct hmfs_sb_info *sbi, seg_t segno)
{
	return &(SIT_I(sbi)->sentries[segno]);
}

static inline unsigned int get_valid_blocks(struct hmfs_sb_info *sbi, seg_t segno)
{
	return get_seg_entry(sbi, segno)->valid_blocks;
}

static inline struct hmfs_sit_entry *get_sit_entry(struct hmfs_sb_info *sbi,
						   seg_t segno)
{
	return &sbi->sit_entries[segno];
}

static inline struct allocator *ALLOCATOR(struct hmfs_sb_info *sbi, int i)
{
	return SM_I(sbi)->allocators + i;
}

static inline struct free_segmap_info *FREE_I(struct hmfs_sb_info *sbi)
{
	return SM_I(sbi)->free_info;
}

static inline struct dirty_seglist_info *DIRTY_I(struct hmfs_sb_info *sbi)
{
	return SM_I(sbi)->dirty_info;
}

static inline unsigned int calculate_segment_size_bits(unsigned int max_page_size_bits)
{
	return max_page_size_bits < HMFS_MIN_SEGMENT_SIZE_BITS ? HMFS_MIN_SEGMENT_SIZE_BITS :
				max_page_size_bits;
}

static inline bool is_new_block(struct hmfs_sb_info *sbi, block_t addr) {
	struct hmfs_summary *sum = get_summary_by_addr(sbi, addr);
	ver_t version = get_summary_start_version(sum);
	
	return version == CM_I(sbi)->new_version;
}

static inline unsigned long GET_SEGNO(struct hmfs_sb_info *sbi, block_t addr)
{
	return (addr - sbi->main_addr_start) >> SM_I(sbi)->segment_size_bits;
}

static inline unsigned int GET_SEG_OFS(struct hmfs_sb_info *sbi, block_t addr)
{
	return ((addr - sbi->main_addr_start) & (~SM_I(sbi)->segment_size_mask)) >>
				HMFS_MIN_PAGE_SIZE_BITS;
}

static inline seg_t find_next_inuse(struct free_segmap_info *free_i,
					   seg_t max, seg_t segno)
{
	seg_t ret;

	lock_read_segmap(free_i);
	ret = find_next_bit(free_i->free_segmap, max, segno);
	unlock_read_segmap(free_i);
	return ret;
}

static inline pgc_t overprovision_segments(struct hmfs_sb_info *sbi)
{
	return SM_I(sbi)->ovp_segments;
}

static inline pgc_t free_segments(struct hmfs_sb_info *sbi)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	pgc_t free_segs;

	lock_read_segmap(free_i);
	free_segs = free_i->free_segments;
	unlock_read_segmap(free_i);

	return free_segs;
}

static inline pgc_t free_user_blocks(struct hmfs_sb_info *sbi)
{
	if (free_segments(sbi) < overprovision_segments(sbi))
		return 0;
	else
		return (free_segments(sbi) - overprovision_segments(sbi))
						<< (SM_I(sbi)->page_4k_per_seg_bits);
}

static inline bool has_enough_invalid_blocks(struct hmfs_sb_info *sbi)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct hmfs_sm_info *sm_i = SM_I(sbi);
	unsigned long invalid_user_blocks = cm_i->alloc_block_count
						- cm_i->valid_block_count;

	if (cm_i->alloc_block_count < cm_i->valid_block_count) {
		int i;
		int count = 0;
		for (i = 0; i < TOTAL_SEGS(sbi); ++i) {
			count += get_valid_blocks(sbi, i);
		}
	}
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

static inline unsigned long long get_mtime(struct hmfs_sb_info *sbi)
{
	struct sit_info *sit_i = SIT_I(sbi);

	return sit_i->elapsed_time + CURRENT_TIME_SEC.tv_sec -
	 sit_i->mounted_time;
}

static inline void seg_info_from_raw_sit(struct seg_entry *se,
					 struct hmfs_sit_entry *raw_entry)
{
	se->valid_blocks = le16_to_cpu(raw_entry->vblocks);
	se->mtime = le32_to_cpu(raw_entry->mtime);
	se->type = raw_entry->type;
	se->invalid_bitmap = NULL;
}

//TODO:use memcpy?
static inline void seg_info_to_raw_sit(struct seg_entry *se,
				       struct hmfs_sit_entry *raw_entry)
{
	raw_entry->vblocks = cpu_to_le16(se->valid_blocks);
	raw_entry->mtime = cpu_to_le32(se->mtime);
	raw_entry->type = se->type;
}

static inline void __set_inuse(struct hmfs_sb_info *sbi, seg_t segno)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	set_bit(segno, free_i->free_segmap);
	free_i->free_segments--;
}

#endif
