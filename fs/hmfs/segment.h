#include "hmfs.h"
typedef u64 block_t;		//bits per NVM page address 

#define TOTAL_SEGS(sbi)	(SM_I(sbi)->main_segments)

struct sit_info {
	const struct segment_allocation *s_ops;

	block_t sit_base_addr;	/* start block address of SIT area */
	block_t sit_blocks;	/* # of blocks used by SIT area */
	block_t written_valid_blocks;	/* # of valid blocks in main area */
	char *sit_bitmap;	/* SIT bitmap pointer */
	unsigned int bitmap_size;	/* SIT bitmap size */

	unsigned int sents_per_block;	/* # of SIT entries per block */
	struct mutex sentry_lock;	/* to protect SIT cache */
	struct seg_entry *sentries;	/* SIT segment-level cache */
	struct sec_entry *sec_entries;	/* SIT section-level cache */
};

struct free_segmap_info {
	unsigned int start_segno;	/* start segment number logically */
	unsigned int free_segments;	/* # of free segments */
//      unsigned int free_sections;     /* # of free sections */
	rwlock_t segmap_lock;	/* free segmap lock */
	unsigned long *free_segmap;	/* free segment bitmap */
//      unsigned long *free_secmap;     /* free section bitmap */
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
/* for active log information */
struct curseg_info {
	struct mutex curseg_mutex;	/* lock for consistency */
	//TODO:add=>struct hmfs_summary_block *sum_blk;     /* cached summary block */
	//unsigned char alloc_type;               /* current allocation type */
	unsigned int segno;	/* current segment number */
	unsigned short next_blkoff;	/* next block offset to write */
	unsigned int next_segno;	/* preallocated segment */
};

static inline struct hmfs_sm_info *SM_I(struct hmfs_sb_info *sbi)
{
	return sbi->sm_info;
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
