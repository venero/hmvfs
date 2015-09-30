#ifndef SEGMENT_H
#define SEGMENT_H

#include "hmfs.h"

#define CURSEG_DATA			1
#define CURSEG_NODE			0
#define	NR_CURSEG_DATA_TYPE	(1)
#define NR_CURSEG_NODE_TYPE	(1)
#define NR_CURSEG_TYPE	(NR_CURSEG_DATA_TYPE + NR_CURSEG_NODE_TYPE)

//#define SIT_ENTRY_NOT_EXIST		3
//#define SIT_ENTRY_NOT_SET		2
#define SIT_ENTRY_CLEAN			0
#define SIT_ENTRY_DIRTY				1

#define MAX_SIT_ITEMS_FOR_GANG_LOOKUP		10240


#define hmfs_bitmap_size(nr)			\
	(BITS_TO_LONGS(nr) * sizeof(unsigned long))
#define TOTAL_SEGS(sbi)	(SM_I(sbi)->main_segments)

/* constant macro */
#define NULL_SEGNO			((unsigned int)(~0))
#define SIT_ENTRY_OFFSET(sit_i, segno)					\
	(segno % sit_i->sents_per_block)
#define SIT_BLOCK_OFFSET(sit_i, segno)					\
	(segno / SIT_ENTRY_PER_BLOCK)
#define START_SEGNO(sit_i, segno)					\
	(SIT_BLOCK_OFFSET(sit_i, segno) * SIT_ENTRY_PER_BLOCK)


struct seg_entry {
	unsigned short valid_blocks;	/* # of valid blocks */
	unsigned char *cur_valid_map;	/* validity bitmap of blocks */
	unsigned long long mtime;	/* modification time of the segment */
};

struct sit_info {
	const struct segment_allocation *s_ops;

	block_t sit_blocks;	/* # of blocks used by SIT file */
	block_t written_valid_blocks;	/* # of valid blocks in main area */
	unsigned long long bitmap_size;

	unsigned long *dirty_sentries_bitmap;	/* bitmap for dirty sentries */
	unsigned int dirty_sentries;	/* # of dirty sentries */
	unsigned int sents_per_block;	/* # of SIT entries per block */
	struct mutex sentry_lock;	/* to protect SIT cache */
	struct radix_tree_root sentries_root;
	rwlock_t sit_tree_rcu_rw_lock;	/* protect radix tree */
//	not sure if this is still necessary
	struct seg_entry *sentries;	/* SIT segment-level cache */
};

struct free_segmap_info {
	unsigned int start_segno;	/* start segment number logically */
	unsigned int free_segments;	/* # of free segments */
	rwlock_t segmap_lock;	/* free segmap lock */
	unsigned long *free_segmap;	/* free segment bitmap */
};
/* for active log information */
struct curseg_info {
	struct mutex curseg_mutex;	/* lock for consistency */
	struct hmfs_summary_block *sum_blk;	/* cached summary block */
	//unsigned char alloc_type;               /* current allocation type */
	u64 segno;		/* current segment number */
	unsigned short next_blkoff;	/* next block offset to write */
	u64 next_segno;		/* preallocated segment */
};

struct hmfs_sm_info {
	struct sit_info *sit_info;	/* whole segment information */
	struct free_segmap_info *free_info;	/* free segment information */
	struct curseg_info *curseg_array;	/* active segment information */

	struct list_head wblist_head;	/* list of under-writeback pages */
	spinlock_t wblist_lock;	/* lock for checkpoint */

	block_t seg0_blkaddr;	/* TODO:block address of 0'th segment */
	block_t main_blkaddr;	/* start block address of main area */
	block_t ssa_blkaddr;	/* start block address of SSA area */

	unsigned int segment_count;	/* total # of segments */
	unsigned int main_segments;	/* # of segments in main area */
	unsigned int reserved_segments;	/* # of reserved segments */
	unsigned int ovp_segments;	/* # of overprovision segments */
};

/* Segment inlined functions */
static inline struct hmfs_sm_info *SM_I(struct hmfs_sb_info *sbi)
{
	return sbi->sm_info;
}

static inline struct sit_info *SIT_I(struct hmfs_sb_info *sbi)
{
	return (struct sit_info *)(SM_I(sbi)->sit_info);
}

static inline struct seg_entry *get_seg_entry(struct hmfs_sb_info *sbi,
					      unsigned int segno)
{
	struct sit_info *sit_i = SIT_I(sbi);
	return &sit_i->sentries[segno];
}

static inline struct curseg_info *CURSEG_I(struct hmfs_sb_info *sbi)
{
	return SM_I(sbi)->curseg_array;
}

static inline struct free_segmap_info *FREE_I(struct hmfs_sb_info *sbi)
{
	return SM_I(sbi)->free_info;
}

static inline void __set_free(struct hmfs_sb_info *sbi, unsigned int segno)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	//unsigned int start_segno = segno;
	//unsigned int next;
	/* lock -- free&cnt -- unlock */
	write_lock(&free_i->segmap_lock);
	clear_bit(segno, free_i->free_segmap);
	free_i->free_segments++;
	write_unlock(&free_i->segmap_lock);
}

static inline void seg_info_from_raw_sit(struct seg_entry *se,
					struct hmfs_sit_entry *raw_entry){
	se->valid_blocks = le16_to_cpu(raw_entry->vblocks);
	memcpy(se->cur_valid_map, raw_entry->valid_map, SIT_VBLOCK_MAP_SIZE);
	se->mtime = le64_to_cpu(raw_entry->mtime);
}

static inline void seg_info_to_raw_sit(struct seg_entry *se,
					struct hmfs_sit_entry *raw_entry)
{
	raw_entry->vblocks = cpu_to_le16(se->valid_blocks);
	memcpy(raw_entry->valid_map, se->cur_valid_map, SIT_VBLOCK_MAP_SIZE);
	raw_entry->mtime = cpu_to_le64(se->mtime);
}


static inline void __set_inuse(struct hmfs_sb_info *sbi, unsigned int segno)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	//FIXME: do we need lock here?
	set_bit(segno, free_i->free_segmap);
	free_i->free_segments--;
}

static inline u8 hmfs_get_sit_height(u64 init_size)
{
	if (init_size > SIT_MAX_SIZE(4))
		return 4;
	else if (init_size > SIT_MAX_SIZE(3))
		return 3;
	else if (init_size > SIT_MAX_SIZE(2))
		return 2;
	else if (init_size > SIT_MAX_SIZE(1))
		return 1;
	return 0;
}
#endif
