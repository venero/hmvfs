#include "hmfs.h"
const struct address_space_operations hmfs_sit_aops;
const struct address_space_operations hmfs_ssa_aops;

struct hmfs_summary *get_summary_by_addr(struct hmfs_sb_info *sbi,
					 void *blk_addr)
{
	u64 logic_addr;
	u64 segno;
	int blkoff;
	struct hmfs_summary_block *summary_blk = NULL;

	logic_addr = blk_addr - sbi->virt_addr;
	segno = logic_addr >> HMFS_SEGMENT_SIZE_BITS;
	summary_blk = ADDR(sbi, segno * HMFS_SUMMARY_BLOCK_SIZE);

	blkoff = (logic_addr & ~HMFS_SEGMENT_MASK) >> HMFS_PAGE_SIZE_BITS;

	return &summary_blk->entries[blkoff];
}
