#include "hmfs.h"
#include "hmfs_fs.h"

int init_checkpoint_manager(struct hmfs_sb_info *sbi)
{
	struct checkpoint_info *cp;
	struct hmfs_super_block *super = ADDR(sbi, 0);
	struct hmfs_checkpoint *hmfs_cp;
	struct page *new_hmfs_cp_page;
	unsigned long cp_addr;
	int i;

	cp = kzalloc(sizeof(struct checkpoint_info), GFP_KERNEL);
	if (cp == NULL) {
		printk("[HMFS] No space for checkpoint_info");
		return -ENOMEM;
	}
	new_hmfs_cp_page = alloc_page(GFP_KERNEL);
	if (new_hmfs_cp_page == NULL) {
		printk("[HMFS] No space for new checkpoint");
		kfree(cp);
		return -ENOMEM;
	}

	cp_addr = le64_to_cpu(super->cp_page_addr);
	hmfs_cp = ADDR(sbi, cp_addr);

	//TODO: deal with checkpoint version
	cp->cur_node_segno = le64_to_cpu(hmfs_cp->cur_node_segno);
	cp->cur_node_blkoff = le64_to_cpu(hmfs_cp->cur_node_blkoff);
	cp->cur_data_segno = le64_to_cpu(hmfs_cp->cur_data_segno);
	cp->cur_data_blkoff = le64_to_cpu(hmfs_cp->cur_data_blkoff);
	cp->valid_inode_count = le64_to_cpu(hmfs_cp->valid_inode_count);
	cp->last_checkpoint_addr = cp_addr;
	cp->cp = kmap(new_hmfs_cp_page);
	cp->cp_page = new_hmfs_cp_page;
	printk(KERN_INFO "current-cp:%d-%d %d-%d\n", cp->cur_node_segno,
	       cp->cur_node_blkoff, cp->cur_data_segno, cp->cur_data_blkoff);
	//FIXME: copy all sit journals and nat journals to DRAM
	for (i = 0; i < NUM_SIT_JOURNALS_IN_CP; ++i)
		cp->cp->sit_journals[i] = hmfs_cp->sit_journals[i];

	for (i = 0; i < NUM_NAT_JOURNALS_IN_CP; ++i)
		cp->cp->nat_journals[i] = hmfs_cp->nat_journals[i];

	sbi->cp_info = cp;
	return 0;
}

int destroy_checkpoint_manager(struct hmfs_sb_info *sbi)
{
	struct checkpoint_info *cp = sbi->cp_info;

	kunmap(cp->cp_page);
	kfree(cp);
	return 0;
}

int lookup_journal_in_cp(struct checkpoint_info *cp_info, unsigned int type,
			 nid_t nid, int alloc)
{
	struct hmfs_checkpoint *cp = cp_info->cp;
	int i;

	if (type == NAT_JOURNAL) {
		for (i = 0; i < NUM_NAT_JOURNALS_IN_CP; ++i) {
			if (nid == le64_to_cpu(cp->nat_journals[i].nid))
				return i;
		}
	}

	return -1;
}

struct hmfs_nat_entry nat_in_journal(struct checkpoint_info *cp_info, int index)
{
	struct hmfs_checkpoint *cp = cp_info->cp;
	return cp->nat_journals[index].entry;
}
