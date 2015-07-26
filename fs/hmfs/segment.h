#include "hmfs.h"
typedef u64 block_t;		//bits per NVM page address 

#define hmfs_bitmap_size(nr)			\
	(BITS_TO_LONGS(nr) * sizeof(unsigned long))
#define TOTAL_SEGS(sbi)	(SM_I(sbi)->main_segments)

/* constant macro */
#define NULL_SEGNO			((unsigned int)(~0))
#define SIT_ENTRY_OFFSET(sit_i, segno)					\
	(segno % sit_i->sents_per_block)
#define SIT_BLOCK_OFFSET(sit_i, segno)					\
	(segno / SIT_ENTRY_PER_BLOCK)

struct seg_entry {
	unsigned short valid_blocks;	/* # of valid blocks */
	unsigned char *cur_valid_map;	/* validity bitmap of blocks */

	unsigned char type;		/* segment type like CURSEG_XXX_TYPE */
	unsigned long long mtime;	/* modification time of the segment */
};

struct sit_info {
	const struct segment_allocation *s_ops;

	block_t sit_root;	/* root node address of SIT file */
	block_t sit_blocks;	/* # of blocks used by SIT file */
	block_t written_valid_blocks;	/* # of valid blocks in main area */
	char *sit_bitmap;	/* SIT bitmap pointer */
	unsigned int bitmap_size;	/* SIT bitmap size */

	unsigned long *dirty_sentries_bitmap;	/* bitmap for dirty sentries */
	unsigned int dirty_sentries;		/* # of dirty sentries */
	unsigned int sents_per_block;	/* # of SIT entries per block */
	struct mutex sentry_lock;	/* to protect SIT cache */
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
	struct hmfs_summary_block *sum_blk;     /* cached summary block */
	//unsigned char alloc_type;               /* current allocation type */
	unsigned int segno;	/* current segment number */
	unsigned short next_blkoff;	/* next block offset to write */
	unsigned int next_segno;	/* preallocated segment */
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
	unsigned int start_segno = segno;
	unsigned int next;
	/* lock -- free&cnt -- unlock */
	write_lock(&free_i->segmap_lock);
	clear_bit(segno, free_i->free_segmap);
	free_i->free_segments++;
	write_unlock(&free_i->segmap_lock);
}

static inline void __set_inuse(struct hmfs_sb_info *sbi, unsigned int segno)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	//FIXME: do we need lock here?
	set_bit(segno, free_i->free_segmap);
	free_i->free_segments--;
}
