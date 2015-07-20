#include "segment.h"		//hmfs.h is included
//TODO: MOVE ME
const struct address_space_operations hmfs_sit_aops;
const struct address_space_operations hmfs_ssa_aops;

/*
 * get_new_segment -- Find a new segment from the free segments bitmap
 * @newseg returns the found segment
 * must be success (otherwise cause error)
 */
static void get_new_segment(struct hmfs_sb_info *sbi, unsigned int *newseg)
{
	struct free_segmap_info *free_i = FREE_I(sbi);
	unsigned int segno;

	int i;

	write_lock(&free_i->segmap_lock);
	segno = find_next_zero_bit(free_i->free_segmap, TOTAL_SEGS(sbi), *newseg - 1);	//FIXME: always look forward?

	BUG_ON(test_bit(segno, free_i->free_segmap));
	__set_inuse(sbi, segno);
	*newseg = segno;
	write_unlock(&free_i->segmap_lock);
}

/* 
 * new_curseg -- Allocate a current working segment. 
 *
 */
static void new_curseg(struct hmfs_sb_info *sbi)
{
	struct curseg_info *curseg = CURSEG_I(sbi);
	unsigned int segno = curseg->segno;

	//TODO:write-back 
	//write_sum_page(sbi, curseg->sum_blk, 
	//                        GET_SUM_BLOCK(sbi, segno)); 

	get_new_segment(sbi, &segno);
	curseg->next_segno = segno;
	//TODO: set current seg to segno
	//reset_curseg(sbi, type, 1); 
}
