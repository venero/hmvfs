#ifndef SEGMENT_H
#define SEGMENT_H

#include "hmfs.h"

#define SIT_ENTRY_CLEAN			0
#define SIT_ENTRY_DIRTY				1

#define MAX_SIT_ITEMS_FOR_GANG_LOOKUP		10240

#define hmfs_bitmap_size(nr)			\
	(BITS_TO_LONGS(nr) * sizeof(unsigned long))
#define TOTAL_SEGS(sbi)	(SM_I(sbi)->main_segments)

/* constant macro */
#define NULL_SEGNO			((unsigned int)(~0))

#define LIMIT_INVALID_BLOCKS	50	/* percentage over total user space */
#define LIMIT_FREE_BLOCKS		50	/* percentage of free blocks over total user space */

struct seg_entry {
	unsigned short valid_blocks;	/* # of valid blocks */
	unsigned long mtime;	/* modification time of the segment */
};

struct sit_info {
	unsigned long long bitmap_size;

	unsigned long *dirty_sentries_bitmap;	/* bitmap for dirty sentries */
	unsigned int dirty_sentries;			/* # of dirty sentries */
	struct mutex sentry_lock;				/* to protect SIT cache */
	struct seg_entry *sentries;				/* SIT segment-level cache */

	/* for cost-benefit valuing */
	unsigned long long elapsed_time;	/* The elapsed time from FS format */
	unsigned long long mounted_time;	/* Timestamp for FS mounted */
	unsigned long long min_mtime;		/* Minimum mtime in SIT */
	unsigned long long max_mtime;		/* Maximum mtime in SIT */
};

/* Dirty segment is the segment which has both valid blocks and invalid blocks */
struct dirty_seglist_info {
	unsigned long *dirty_segmap;		/* bitmap for dirty segment */
	struct mutex seglist_lock;
};

/* Free segment is the segment which does not have valid blocks */
struct free_segmap_info {
	pgc_t free_segments;			/* # of free segments */
	rwlock_t segmap_lock;				/* free segmap lock */
	unsigned long *free_segmap;			/* free segment bitmap */
};

/* for active log information */
struct curseg_info {
	struct mutex curseg_mutex;	/* lock for consistency */
	seg_t segno;				/* current segment number */
	unsigned short next_blkoff;	/* next block offset to write */
	seg_t next_segno;			/* preallocated segment */
};

struct hmfs_sm_info {
	struct sit_info *sit_info;				/* whole segment information */
	struct free_segmap_info *free_info;		/* free segment information */
	struct dirty_seglist_info *dirty_info;	/* dirty segment information */
	struct curseg_info *curseg_array;		/* active segment information */

	pgc_t segment_count;				/* total # of segments */
	pgc_t main_segments;				/* # of segments in main area */
	pgc_t reserved_segments;			/* # of reserved segments */
	pgc_t ovp_segments;				/* # of overprovision segments */
	pgc_t limit_invalid_blocks;		/* # of limit invalid blocks */
	pgc_t limit_free_blocks;		/* # of limit free blocks */
};

/* Segment inlined functions */
static inline struct hmfs_sm_info *SM_I(struct hmfs_sb_info *sbi)
{
	return sbi->sm_info;
}

static inline struct sit_info *SIT_I(struct hmfs_sb_info *sbi)
{
	return (SM_I(sbi)->sit_info);
}

static inline struct seg_entry *get_seg_entry(struct hmfs_sb_info *sbi,
					      seg_t segno)
{
	return &(SIT_I(sbi)->sentries[segno]);
}

static inline unsigned int get_valid_blocks(struct hmfs_sb_info *sbi,
					    seg_t segno)
{
	return get_seg_entry(sbi, segno)->valid_blocks;
}

static inline struct hmfs_sit_entry *get_sit_entry(struct hmfs_sb_info *sbi,
						   seg_t segno)
{
	return &sbi->sit_entries[segno];
}

static inline struct curseg_info *CURSEG_I(struct hmfs_sb_info *sbi)
{
	return SM_I(sbi)->curseg_array;
}

static inline struct free_segmap_info *FREE_I(struct hmfs_sb_info *sbi)
{
	return SM_I(sbi)->free_info;
}

static inline struct dirty_seglist_info *DIRTY_I(struct hmfs_sb_info *sbi)
{
	return SM_I(sbi)->dirty_info;
}

static inline seg_t find_next_inuse(struct free_segmap_info *free_i,
					   seg_t max, seg_t segno)
{
	seg_t ret;

	read_lock(&free_i->segmap_lock);
	ret = find_next_bit(free_i->free_segmap, max, segno);
	read_unlock(&free_i->segmap_lock);
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

	read_lock(&free_i->segmap_lock);
	free_segs = free_i->free_segments;
	read_unlock(&free_i->segmap_lock);

	return free_segs;
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
}

static inline void seg_info_to_raw_sit(struct seg_entry *se,
				       struct hmfs_sit_entry *raw_entry)
{
	raw_entry->vblocks = cpu_to_le16(se->valid_blocks);
	raw_entry->mtime = cpu_to_le32(se->mtime);
}

static inline void __set_inuse(struct hmfs_sb_info *sbi, seg_t segno)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	//FIXME: do we need lock here?
	set_bit(segno, free_i->free_segmap);
	free_i->free_segments--;
}

#endif
