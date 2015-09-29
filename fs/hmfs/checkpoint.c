#include "hmfs.h"
#include "hmfs_fs.h"
#include "segment.h"
#include <linux/crc16.h>

static struct kmem_cache *orphan_entry_slab;

static u32 next_checkpoint_ver(u32 version)
{
//	TODO: version GC
	return version + 1;
}

static u32 find_this_version(struct hmfs_sb_info *sbi)
{
	return sbi->cp_info->load_version;
}

static void init_orphan_manager(struct checkpoint_info *cp_i)
{
	/* init orphan manager */
	mutex_init(&cp_i->orphan_inode_mutex);
	INIT_LIST_HEAD(&cp_i->orphan_inode_list);
	cp_i->n_orphans = 0;
}

void add_orphan_inode(struct hmfs_sb_info *sbi, nid_t ino)
{
	struct list_head *head, *this;
	struct orphan_inode_entry *new = NULL, *orphan = NULL;
	struct checkpoint_info *cp_i = CURCP_I(sbi);

	mutex_lock(&cp_i->orphan_inode_mutex);
	head = &cp_i->orphan_inode_list;
	list_for_each(this, head) {
		orphan = list_entry(this, struct orphan_inode_entry, list);
		if (orphan->ino == ino)
			goto out;
		if (orphan->ino > ino)
			break;
		orphan = NULL;
	}
retry:
	new = kmem_cache_alloc(orphan_entry_slab, GFP_ATOMIC);
	if (!new) {
		cond_resched();
		goto retry;
	}
	new->ino = ino;

	if (orphan)
		list_add(&new->list, this->prev);
	else
		list_add_tail(&new->list, head);
	cp_i->n_orphans++;
out:
	mutex_unlock(&cp_i->orphan_inode_mutex);
}

void remove_orphan_inode(struct hmfs_sb_info *sbi, nid_t ino)
{
	struct list_head *this, *next, *head;
	struct orphan_inode_entry *orphan;
	struct checkpoint_info *cp_i = CURCP_I(sbi);

	mutex_lock(&cp_i->orphan_inode_mutex);
	head = &cp_i->orphan_inode_list;
	list_for_each_safe(this, next, head) {
		orphan = list_entry(this, struct orphan_inode_entry, list);
		if (orphan->ino == ino) {
			list_del(&orphan->list);
			kmem_cache_free(orphan_entry_slab, orphan);
			cp_i->n_orphans--;
			break;
		}
	}
	mutex_unlock(&cp_i->orphan_inode_mutex);
}

int check_orphan_space(struct hmfs_sb_info *sbi)
{
	struct checkpoint_info *cp_i = CURCP_I(sbi);
	int err = 0;

	mutex_lock(&cp_i->orphan_inode_mutex);
	if (cp_i->n_orphans >= HMFS_MAX_ORPHAN_NUM)
		err = -ENOSPC;
	BUG_ON(cp_i->n_orphans > HMFS_MAX_ORPHAN_NUM);
	mutex_unlock(&cp_i->orphan_inode_mutex);
	return err;
}

int init_checkpoint_manager(struct hmfs_sb_info *sbi)
{
	struct checkpoint_info *cp;
	struct hmfs_super_block *super = ADDR(sbi, 0);
	struct hmfs_checkpoint *hmfs_cp;
	struct page *new_hmfs_cp_page;
	u64 cp_addr;
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
	cp->load_version = le32_to_cpu(hmfs_cp->checkpoint_ver);
	cp->store_version = next_checkpoint_ver(le32_to_cpu(hmfs_cp->checkpoint_ver));
	cp->cur_node_segno = le64_to_cpu(hmfs_cp->cur_node_segno);
	cp->cur_node_blkoff = le64_to_cpu(hmfs_cp->cur_node_blkoff);
	cp->cur_data_segno = le64_to_cpu(hmfs_cp->cur_data_segno);
	cp->cur_data_blkoff = le64_to_cpu(hmfs_cp->cur_data_blkoff);
	cp->valid_inode_count = le64_to_cpu(hmfs_cp->valid_inode_count);
	cp->valid_node_count = le64_to_cpu(hmfs_cp->valid_node_count);
	cp->valid_block_count = le64_to_cpu(hmfs_cp->valid_block_count);
	cp->user_block_count = le64_to_cpu(hmfs_cp->user_block_count);
	cp->load_checkpoint_addr = cp_addr;
	cp->cp = kmap(new_hmfs_cp_page);
	cp->cp_page = new_hmfs_cp_page;

	init_orphan_manager(cp);

	printk(KERN_INFO "current-cp:%d-%d %d-%d\n", (int)cp->cur_node_segno,
	       (int)cp->cur_node_blkoff, (int)cp->cur_data_segno,
	       (int)cp->cur_data_blkoff);
	//FIXME: copy all sit journals and nat journals to DRAM
	for (i = 0; i < NUM_SIT_JOURNALS_IN_CP; ++i)
		cp->cp->sit_journals[i] = hmfs_cp->sit_journals[i];

	for (i = 0; i < NUM_NAT_JOURNALS_IN_CP; ++i)
		cp->cp->nat_journals[i] = hmfs_cp->nat_journals[i];

	rwlock_init(&cp->journal_lock);
	spin_lock_init(&cp->stat_lock);

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

	read_lock(&cp_info->journal_lock);
	if (type == NAT_JOURNAL) {
		for (i = 0; i < NUM_NAT_JOURNALS_IN_CP; ++i) {
			if (nid == le64_to_cpu(cp->nat_journals[i].nid))
				goto found;
		}
	}

	return -1;
found:
	read_unlock(&cp_info->journal_lock);
	return i;
}

struct hmfs_nat_entry nat_in_journal(struct checkpoint_info *cp_info, int index)
{
	struct hmfs_checkpoint *cp = cp_info->cp;
	struct hmfs_nat_entry entry;
	read_lock(&cp_info->journal_lock);
	entry = cp->nat_journals[index].entry;
	read_unlock(&cp_info->journal_lock);

	return entry;
}

int create_checkpoint_caches(void)
{
	orphan_entry_slab =
	    kmem_cache_create("hmfs_orphan_entry",
			      sizeof(struct orphan_inode_entry), 0,
			      SLAB_RECLAIM_ACCOUNT, NULL);
	if (unlikely(!orphan_entry_slab))
		return -ENOMEM;
	return 0;
}

void destroy_checkpoint_caches(void)
{
	kmem_cache_destroy(orphan_entry_slab);
}

//	TODO: Find checkpoint by given version number
int find_checkpoint_version(struct hmfs_sb_info *sbi, u32 version, struct hmfs_checkpoint *checkpoint)
{
	struct hmfs_checkpoint *cp;
	u32 ver;
	cp = ADDR(sbi, sbi->cp_info->load_checkpoint_addr);
	ver = cp->checkpoint_ver;
	while(ver != version)
	{
		cp = ADDR(sbi, cp->prev_checkpoint_addr);
		ver = le32_to_cpu(cp->checkpoint_ver);
		if (cp->prev_checkpoint_addr == 0)
			return version;
	}
	checkpoint = cp;
	return 0;
}

//	Step1: calculate info and write sit and nat to NVM
//	Step2: write CP itself to NVM
//	Step3: remaining job
block_t write_checkpoint(struct hmfs_sb_info *sbi)
{
	printk(KERN_INFO "Write checkpoint stage 1.\n");
	u16 cp_checksum;
	int length;
//	TODO: Stop writing to current file system
	u32 load_version = 0;
	u32 store_version = 0;

	block_t store_checkpoint_addr = 0;
	nid_t * store_checkpoint_nid;

	block_t sit_bt_entries_root;
//	u64 nat_bt_entries_root;
	struct hmfs_checkpoint *load_checkpoint;
	struct hmfs_checkpoint *store_checkpoint;
	load_version = sbi->cp_info->load_version;
	store_version = sbi->cp_info->store_version;


	if(!find_checkpoint_version(sbi, load_version, load_checkpoint))
	{
		printk("Load version of CP not found.\n");
		return -1;
	}
	if(!alloc_nid(sbi, store_checkpoint_nid))
	{
		printk("Not enough nid for CP.\n");
		return -1;
	}
	store_checkpoint_addr=get_free_node_block(sbi);

	store_checkpoint = ADDR(sbi, store_checkpoint_addr);

	sit_bt_entries_root = save_sit_entries(sbi);

//	TODO: NAT part
//	nat_bt_entries_root = save_nat_entries(sbi);

	printk(KERN_INFO "Write checkpoint stage 2.\n");
//	Deal with checkpoint itself
	set_struct(store_checkpoint,checkpoint_ver,store_version);

	set_struct(store_checkpoint,prev_checkpoint_addr,cpu_to_le64(load_checkpoint));

	set_struct(store_checkpoint,user_block_count,sbi->cp_info->user_block_count);
	set_struct(store_checkpoint,valid_block_count,sbi->cp_info->valid_block_count);
	set_struct(store_checkpoint,free_segment_count, cpu_to_le64(sbi->sm_info->free_info->free_segments));

	set_struct(store_checkpoint,cur_node_segno,sbi->cp_info->cur_node_segno);
	set_struct(store_checkpoint,cur_node_blkoff,sbi->cp_info->cur_node_blkoff);
	set_struct(store_checkpoint,cur_data_segno,sbi->cp_info->cur_data_segno);
	set_struct(store_checkpoint,cur_data_blkoff,sbi->cp_info->cur_data_blkoff);

	set_struct(store_checkpoint,valid_inode_count,sbi->cp_info->valid_inode_count);
	set_struct(store_checkpoint,valid_node_count,sbi->cp_info->valid_node_count);

//	These two are traditional way of expressing sit and nat, should be replaced with b-tree root
//	set_struct(store_checkpoint,sit_addr,sbi->cp_info->si->sit_root);
//	set_struct(store_checkpoint,nat_addr,sbi->cp_info);

	set_struct(store_checkpoint,next_scan_nid,sbi->nm_info->next_scan_nid);

	set_struct(store_checkpoint, sit_addr, sit_bt_entries_root);

	length = (void *)(&store_checkpoint->checksum) - (void *)store_checkpoint;
	cp_checksum = crc16(~0, (void *)store_checkpoint, length);
	set_struct(store_checkpoint,checksum,cp_checksum);

//	Main part of checkpoint is done, begin to deal with add-ons

	printk(KERN_INFO "Write checkpoint stage 3.\n");
	//TODO:cp_info lock
	sbi->cp_info->load_version = store_version;
	sbi->cp_info->store_version = next_checkpoint_ver(store_version);
	sbi->cp_info->load_checkpoint_addr = store_checkpoint_addr;

	printk(KERN_INFO "Write checkpoint end.\n");
	return store_checkpoint_addr;
	//TODO: link this unattached CP to raw_super
}

//	Step1: read cp to cpi
//	Step2: set B-tree root to this checkpoint
int read_checkpoint(struct hmfs_sb_info *sbi, u32 version)
{

	printk(KERN_INFO "Read checkpoint stage 3.\n");
	struct hmfs_checkpoint *checkpoint = NULL;
	struct checkpoint_info *cpi = NULL;
	struct hmfs_super_block *super;
	int ret;
	super = ADDR(sbi, 0);
	ret = find_checkpoint_version(sbi, version, checkpoint);
	if ( ret != 0)
	{
		printk("Version %d not found.\n",ret);
		return -1;
	}
	cpi = kzalloc(sizeof(struct checkpoint_info), GFP_KERNEL);
	cpi->load_version = version;
	cpi->store_version = next_checkpoint_ver(super->latest_cp_version);

	cpi->cur_node_segno = checkpoint->cur_node_segno;
	cpi->cur_node_blkoff = checkpoint->cur_node_blkoff;
	cpi->cur_data_segno = checkpoint->cur_data_segno;
	cpi->cur_data_blkoff= checkpoint->cur_data_blkoff;

	cpi->valid_inode_count = checkpoint->valid_inode_count;
	cpi->valid_node_count = checkpoint->valid_node_count;

	cpi->valid_block_count = checkpoint->valid_block_count;
	cpi->user_block_count = checkpoint->user_block_count;

//	FIXME: [Goku]
//	cpi->alloc_valid_block_count =

	cpi->load_checkpoint_addr = checkpoint->prev_checkpoint_addr;

//	FIXME: [Goku] Orphan part

	cpi->cp = checkpoint;

//	FIXME: [Goku] cp_page

//	cpi->si should be changed when sit is initialed.

	printk(KERN_INFO "Read checkpoint end.\n");
}





