#include "hmfs.h"
#include "hmfs_fs.h"
#include "segment.h"
#include <linux/crc16.h>

static struct kmem_cache *orphan_entry_slab;

static struct kmem_cache *cp_info_entry_slab;

static u32 next_checkpoint_ver(u32 version)
{
	//TODO
	return version + 1;
}

static void init_orphan_manager(struct hmfs_cm_info *cm_i)
{
	/* init orphan manager */
	mutex_init(&cm_i->orphan_inode_mutex);
	INIT_LIST_HEAD(&cm_i->orphan_inode_list);
	cm_i->n_orphans = 0;
}

void add_orphan_inode(struct hmfs_sb_info *sbi, nid_t ino)
{
	struct list_head *head, *this;
	struct orphan_inode_entry *new = NULL, *orphan = NULL;
	struct hmfs_cm_info *cm_i = CM_I(sbi);

	mutex_lock(&cm_i->orphan_inode_mutex);
	head = &cm_i->orphan_inode_list;
	list_for_each(this, head) {
		orphan = list_entry(this, struct orphan_inode_entry, list);
		if (orphan->ino == ino)
			goto out;
		if (orphan->ino > ino)
			break;
		orphan = NULL;
	}
retry:	new = kmem_cache_alloc(orphan_entry_slab, GFP_ATOMIC);
	if (!new) {
		cond_resched();
		goto retry;
	}
	new->ino = ino;

	if (orphan)
		list_add(&new->list, this->prev);
	else
		list_add_tail(&new->list, head);
	cm_i->n_orphans++;
out:	mutex_unlock(&cm_i->orphan_inode_mutex);
}

void remove_orphan_inode(struct hmfs_sb_info *sbi, nid_t ino)
{
	struct list_head *this, *next, *head;
	struct orphan_inode_entry *orphan;
	struct hmfs_cm_info *cm_i = CM_I(sbi);

	mutex_lock(&cm_i->orphan_inode_mutex);
	head = &cm_i->orphan_inode_list;
	list_for_each_safe(this, next, head) {
		orphan = list_entry(this, struct orphan_inode_entry, list);
		if (orphan->ino == ino) {
			list_del(&orphan->list);
			kmem_cache_free(orphan_entry_slab, orphan);
			cm_i->n_orphans--;
			break;
		}
	}
	mutex_unlock(&cm_i->orphan_inode_mutex);
}

int check_orphan_space(struct hmfs_sb_info *sbi)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	int err = 0;

	mutex_lock(&cm_i->orphan_inode_mutex);
	if (cm_i->n_orphans >= HMFS_MAX_ORPHAN_NUM)
		err = -ENOSPC;
	BUG_ON(cm_i->n_orphans > HMFS_MAX_ORPHAN_NUM);
	mutex_unlock(&cm_i->orphan_inode_mutex);
	return err;
}

static void sync_checkpoint_info(struct hmfs_sb_info *sbi,
				 struct hmfs_checkpoint *hmfs_cp,
				 struct checkpoint_info *cp)
{
	cp->version = le32_to_cpu(hmfs_cp->checkpoint_ver);
	cp->next_version = le32_to_cpu(hmfs_cp->next_version);
	cp->nat_root = ADDR(sbi, le64_to_cpu(hmfs_cp->nat_addr));
	cp->cp = hmfs_cp;
}

static void move_to_next_checkpoint(struct hmfs_sb_info *sbi,
				    struct hmfs_checkpoint *prev_checkpoint)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	void *tmp_addr = NULL;

	mutex_lock(&cm_i->cp_tree_lock);
	cm_i->last_cp_i = cm_i->cur_cp_i;
	tmp_addr = cm_i->cur_cp_i->cp;

	sync_checkpoint_info(sbi, prev_checkpoint, cm_i->cur_cp_i);
	radix_tree_insert(&cm_i->cp_tree_root, cm_i->new_version,
			  cm_i->cur_cp_i);
	list_add(&cm_i->last_cp_i->list, &cm_i->cur_cp_i->list);
	cm_i->new_version = next_checkpoint_ver(cm_i->new_version);
	cm_i->cur_cp_i = kmem_cache_alloc(cp_info_entry_slab, GFP_KERNEL);

	//TODO
	if (!cm_i->cur_cp_i)
		BUG();

	cm_i->cur_cp_i->version = cm_i->new_version;
	cm_i->cur_cp_i->nat_root = NULL;
	cm_i->cur_cp_i->cp = tmp_addr;

	//TODO:deal with journals
	mutex_unlock(&cm_i->cp_tree_lock);
}

struct checkpoint_info *get_next_cp_i(struct hmfs_sb_info *sbi,
				      struct checkpoint_info *cp_i)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct hmfs_checkpoint *hmfs_cp;
	unsigned long long next_addr;
	struct checkpoint_info *next_cp_i;
	unsigned int next_version;

	next_version = cp_i->next_version;

	mutex_lock(&cm_i->cp_tree_lock);
	next_cp_i = radix_tree_lookup(&cm_i->cp_tree_root, next_version);

	if (!next_cp_i) {
		next_addr = le64_to_cpu(cp_i->cp->next_cp_addr);
		hmfs_cp = ADDR(sbi, next_addr);

		next_cp_i = kmem_cache_alloc(cp_info_entry_slab, GFP_KERNEL);

		sync_checkpoint_info(sbi, hmfs_cp, next_cp_i);

		list_add(&next_cp_i->list, &cm_i->last_cp_i->list);
		radix_tree_insert(&cm_i->cp_tree_root, next_cp_i->version,
				  next_cp_i);
	}
	mutex_unlock(&cm_i->cp_tree_lock);
	return next_cp_i;

}

struct checkpoint_info *get_checkpoint_info(struct hmfs_sb_info *sbi,
					    unsigned int version)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct checkpoint_info *cp_i, *entry;
	struct list_head *this, *head;
	struct hmfs_checkpoint *hmfs_cp;
	unsigned long long next_addr;

	mutex_lock(&cm_i->cp_tree_lock);
	cp_i = radix_tree_lookup(&cm_i->cp_tree_root, version);
	if (!cp_i) {
		cp_i = cm_i->last_cp_i;
		head = &cp_i->list;
		list_for_each(this, head) {
			entry = list_entry(this, struct checkpoint_info, list);
			if (entry->version < version
			    && entry->version > cp_i->version) {
				cp_i = entry;
			}
		}

		do {
			next_addr = le64_to_cpu(cp_i->cp->next_cp_addr);

			hmfs_cp = ADDR(sbi, next_addr);
			entry =
			 kmem_cache_alloc(cp_info_entry_slab, GFP_KERNEL);

			sync_checkpoint_info(sbi, hmfs_cp, entry);

			list_add(&entry->list, &cm_i->last_cp_i->list);
			radix_tree_insert(&cm_i->cp_tree_root, entry->version,
					  entry);
			cp_i = entry;
		} while (cp_i->version != version);

	}
	mutex_unlock(&cm_i->cp_tree_lock);
	return cp_i;
}

int init_checkpoint_manager(struct hmfs_sb_info *sbi)
{
	struct hmfs_cm_info *cm_i;
	struct checkpoint_info *cp_i;
	struct hmfs_super_block *super = ADDR(sbi, 0);
	struct hmfs_checkpoint *hmfs_cp;
	struct page *new_hmfs_cp_page;
	unsigned long long cp_addr;
	int i;

	cm_i = kzalloc(sizeof(struct hmfs_cm_info), GFP_KERNEL);

	if (!cm_i) {
		goto out_cm_i;
	}

	/* allocate and init last checkpoint_info */
	cp_i = kmem_cache_alloc(cp_info_entry_slab, GFP_ATOMIC);
	if (!cp_i) {
		goto out_cp_i;
	}
	new_hmfs_cp_page = alloc_page(GFP_KERNEL);
	if (new_hmfs_cp_page == NULL) {
		goto out_cp_page;
	}

	/* Init checkpoint_info list */
	cp_addr = le64_to_cpu(super->cp_page_addr);
	hmfs_cp = ADDR(sbi, cp_addr);

	cm_i->valid_inode_count = le32_to_cpu(hmfs_cp->valid_inode_count);
	cm_i->valid_node_count = le32_to_cpu(hmfs_cp->valid_node_count);
	cm_i->valid_block_count = le32_to_cpu(hmfs_cp->valid_block_count);
	cm_i->user_block_count =
	 le32_to_cpu(HMFS_RAW_SUPER(sbi)->user_block_count);
	cm_i->alloc_block_count = le32_to_cpu(hmfs_cp->alloc_block_count);
	sync_checkpoint_info(sbi, hmfs_cp, cp_i);
	cm_i->last_cp_i = cp_i;

	rwlock_init(&cm_i->journal_lock);
	spin_lock_init(&cm_i->stat_lock);
	INIT_LIST_HEAD(&cp_i->list);
	INIT_RADIX_TREE(&cm_i->cp_tree_root, GFP_ATOMIC);
	mutex_init(&cm_i->cp_tree_lock);
	mutex_init(&cm_i->cp_mutex);

	mutex_lock(&cm_i->cp_tree_lock);
	radix_tree_insert(&cm_i->cp_tree_root, cp_i->version, cp_i);
	mutex_unlock(&cm_i->cp_tree_lock);

	/* Allocate and Init current checkpoint_info */
	cp_i = kmem_cache_alloc(cp_info_entry_slab, GFP_KERNEL);
	cm_i->new_version =
	 next_checkpoint_ver(le32_to_cpu(hmfs_cp->checkpoint_ver));
	cp_i->version = cm_i->new_version;
	cp_i->nat_root = NULL;
	cp_i->cp = kmap(new_hmfs_cp_page);
	cm_i->cp_page = new_hmfs_cp_page;

	init_orphan_manager(cm_i);

	//FIXME: copy all sit journals and nat journals to DRAM
	for (i = 0; i < NUM_NAT_JOURNALS_IN_CP; ++i)
		cp_i->cp->nat_journals[i] = hmfs_cp->nat_journals[i];

	cm_i->cur_cp_i = cp_i;

	sbi->cm_info = cm_i;
	return 0;

out_cp_page:kfree(cp_i);
out_cp_i:kfree(cm_i);
out_cm_i:return -ENOMEM;
}

static void destroy_checkpoint_info(struct hmfs_cm_info *cm_i)
{
	struct checkpoint_info *cp_i = cm_i->last_cp_i, *entry;
	struct list_head *head, *this;

	head = &cp_i->list;
	list_for_each(this, head) {
		entry = list_entry(this, struct checkpoint_info, list);
		list_del(this);
		radix_tree_delete(&cm_i->cp_tree_root, entry->version);
		kmem_cache_free(cp_info_entry_slab, entry);
	}
	kmem_cache_free(cp_info_entry_slab, cp_i);
	radix_tree_delete(&cm_i->cp_tree_root, cp_i->version);
	kmem_cache_free(cp_info_entry_slab, cm_i->cur_cp_i);
}

int destroy_checkpoint_manager(struct hmfs_sb_info *sbi)
{
	struct hmfs_cm_info *cm_i = sbi->cm_info;

	mutex_lock(&cm_i->cp_tree_lock);
	destroy_checkpoint_info(cm_i);
	mutex_unlock(&cm_i->cp_tree_lock);

//FIXME:Need lock here?
	kunmap(cm_i->cp_page);
	__free_page(cm_i->cp_page);
	cm_i->cp_page = NULL;
	kfree(cm_i);
	return 0;
}

/*
 * Caller must hold hmfs_cm_info.journal_lock
 */
int lookup_journal_in_cp(struct checkpoint_info *cp_info, unsigned int type,
			 nid_t nid, int alloc)
{
	struct hmfs_checkpoint *cp = cp_info->cp;
	int i;

	if (type == NAT_JOURNAL) {
		for (i = 0; i < NUM_NAT_JOURNALS_IN_CP; ++i) {
			if (nid == le64_to_cpu(cp->nat_journals[i].nid))
				goto found;
		}
	}

	return -1;
found:	return i;
}

/*
 * Caller must hold hmfs_cm_info.journal_lock
 */
struct hmfs_nat_entry nat_in_journal(struct checkpoint_info *cp_info, int index)
{
	struct hmfs_checkpoint *cp = cp_info->cp;
	struct hmfs_nat_entry entry;

	entry = cp->nat_journals[index].entry;

	return entry;
}

int create_checkpoint_caches(void)
{
	orphan_entry_slab = kmem_cache_create("hmfs_orphan_entry",
					      sizeof(struct orphan_inode_entry),
					      0, SLAB_RECLAIM_ACCOUNT, NULL);
	if (unlikely(!orphan_entry_slab))
		return -ENOMEM;
	cp_info_entry_slab = kmem_cache_create("hmfs_checkpoint_info_entry",
					       sizeof(struct checkpoint_info),
					       0, SLAB_RECLAIM_ACCOUNT, NULL);
	if (cp_info_entry_slab == NULL) {
		kmem_cache_destroy(cp_info_entry_slab);
		return -ENOMEM;
	}
	return 0;
}

void destroy_checkpoint_caches(void)
{
	kmem_cache_destroy(orphan_entry_slab);
	kmem_cache_destroy(cp_info_entry_slab);
}

//      Find checkpoint by given version number
u32 find_checkpoint_version(struct hmfs_sb_info *sbi, u32 version,
			    struct hmfs_checkpoint *checkpoint)
{
	struct hmfs_checkpoint *cp = NULL;
	struct hmfs_cm_info *cm_i = CM_I(sbi);

	u32 ver;
	cp = cm_i->last_cp_i->cp;
	ver = cp->checkpoint_ver;
	while (ver != version) {
		cp = ADDR(sbi, le64_to_cpu(cp->next_cp_addr));
		ver = le32_to_cpu(cp->checkpoint_ver);
		if (cp->prev_cp_addr == 0)
			return version;
	}
	checkpoint = cp;
	return 0;
}

static void block_operations(struct hmfs_sb_info *sbi)
{
	mutex_lock_all(sbi);

	//TODO:write dirty pages and dirty inodes
}

static void unblock_operations(struct hmfs_sb_info *sbi)
{
	mutex_unlock_all(sbi);
}

//      Find checkpoint whose prev_checkpoint version is given version number
u32 find_next_checkpoint_version(struct hmfs_sb_info *sbi, u32 version,
				 struct hmfs_checkpoint *checkpoint)
{
	struct hmfs_checkpoint *cp_next = NULL;
	struct hmfs_checkpoint *cp = NULL;
	struct hmfs_cm_info *cm_i = CM_I(sbi);

	u32 ver;
	cp_next = ADDR(sbi, le64_to_cpu(cm_i->last_cp_i->cp->prev_cp_addr));
	cp = ADDR(sbi, cp_next->prev_cp_addr);
	ver = cp->checkpoint_ver;
	while (ver != version) {
		cp_next = cp;
		cp = ADDR(sbi, cp->prev_cp_addr);
		ver = le32_to_cpu(cp->checkpoint_ver);
		if (cp->prev_cp_addr == 0)
			return version;
	}
	checkpoint = cp_next;
	return 0;
}

static block_t flush_orphan_inodes(struct hmfs_sb_info *sbi)
{
	return 0;
}

void do_checkpoint(struct hmfs_sb_info *sbi)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct free_segmap_info *free_i = FREE_I(sbi);
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct hmfs_super_block *raw_super = HMFS_RAW_SUPER(sbi);
	struct hmfs_summary *summary;
	unsigned int cp_checksum, sb_checksum;
	unsigned store_version;
	int length;

	block_t store_checkpoint_addr = 0;

	block_t nat_root, orphan_blocks;
	struct hmfs_checkpoint *prev_checkpoint, *next_checkpoint;
	struct hmfs_checkpoint *store_checkpoint;
	struct curseg_info *curseg_i = SM_I(sbi)->curseg_array;

	prev_checkpoint = cm_i->last_cp_i->cp;
	next_checkpoint = ADDR(sbi, le64_to_cpu(prev_checkpoint->next_cp_addr));

	nat_root = flush_nat_entries(sbi);
	orphan_blocks = flush_orphan_inodes(sbi);

	store_version = cm_i->new_version;
	store_checkpoint_addr = alloc_free_node_block(sbi);
	summary = get_summary_by_addr(sbi, store_checkpoint_addr);
	make_summary_entry(summary, 0, cm_i->new_version, 1, 0, SUM_TYPE_CP);
	store_checkpoint = ADDR(sbi, store_checkpoint_addr);
	flush_sit_entries(sbi);
	set_struct(store_checkpoint, checkpoint_ver, store_version);
	set_struct(store_checkpoint, valid_block_count,
		   cm_i->valid_block_count);
	set_struct(store_checkpoint, valid_inode_count,
		   cm_i->valid_inode_count);
	set_struct(store_checkpoint, valid_node_count, cm_i->valid_node_count);
	set_struct(store_checkpoint, alloc_block_count,
		   cm_i->alloc_block_count);
	set_struct(store_checkpoint, nat_addr, nat_root);
	set_struct(store_checkpoint, free_segment_count, free_i->free_segments);
	set_struct(store_checkpoint, cur_node_segno,
		   curseg_i[CURSEG_NODE].segno);
	set_struct(store_checkpoint, cur_node_blkoff,
		   curseg_i[CURSEG_NODE].next_blkoff);
	set_struct(store_checkpoint, cur_data_segno,
		   curseg_i[CURSEG_DATA].segno);
	set_struct(store_checkpoint, cur_data_blkoff,
		   curseg_i[CURSEG_DATA].next_blkoff);
	set_struct(store_checkpoint, orphan_addr, orphan_blocks);
	set_struct(store_checkpoint, next_scan_nid, nm_i->next_scan_nid);
	set_struct(store_checkpoint, elapsed_time, get_mtime(sbi));

	store_checkpoint->next_cp_addr = prev_checkpoint->next_cp_addr;
	store_checkpoint->prev_cp_addr = next_checkpoint->prev_cp_addr;
	store_checkpoint->next_version = next_checkpoint->checkpoint_ver;

	//FIXME:Atomic write?
	next_checkpoint->prev_cp_addr = cpu_to_le64(store_checkpoint_addr);
	prev_checkpoint->next_cp_addr = cpu_to_le64(store_checkpoint_addr);
	prev_checkpoint->next_version = store_checkpoint->checkpoint_ver;
	raw_super->cp_page_addr = cpu_to_le64(store_checkpoint_addr);

	length =
	 (char *)(&store_checkpoint->checksum) - (char *)store_checkpoint;
	cp_checksum = crc16(~0, (void *)store_checkpoint, length);
	set_struct(store_checkpoint, checksum, cp_checksum);

	length = (char *)(&raw_super->checksum) - (char *)raw_super;
	sb_checksum = crc16(~0, (char *)raw_super, length);
	set_struct(raw_super, checksum, sb_checksum);

	//TODO: memory barrier?
	raw_super = next_super_block(raw_super);
	hmfs_memcpy(raw_super, ADDR(sbi, 0), sizeof(struct hmfs_super_block));

	move_to_next_checkpoint(sbi, store_checkpoint);
}

//      Step1: calculate info and write sit and nat to NVM
//      Step2: write CP itself to NVM
//      Step3: remaining job
void write_checkpoint(struct hmfs_sb_info *sbi)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);

	mutex_lock(&cm_i->cp_mutex);
	block_operations(sbi);
	do_checkpoint(sbi);

	unblock_operations(sbi);
	mutex_unlock(&cm_i->cp_mutex);

}

//      Step1: read cp to cpi
//      Step2: set B-tree root to this checkpoint
int read_checkpoint(struct hmfs_sb_info *sbi, u32 version)
{

	struct hmfs_checkpoint *checkpoint = NULL;
	struct checkpoint_info *cpi = NULL;
	struct hmfs_super_block *super;
	int ret = 0;
	printk(KERN_INFO "Read checkpoint stage 3.\n");
	super = ADDR(sbi, 0);
	ret = find_checkpoint_version(sbi, version, checkpoint);
	if (ret != 0) {
		printk("Version %d not found.\n", ret);
		return -1;
	}
	/*
	   cpi = kzalloc(sizeof(struct checkpoint_info), GFP_KERNEL);
	   cpi->load_version = version;
	   cpi->store_version = next_checkpoint_ver(super->latest_cp_version);

	   cpi->cur_node_segno = checkpoint->cur_node_segno;
	   cpi->cur_node_blkoff = checkpoint->cur_node_blkoff;
	   cpi->cur_data_segno = checkpoint->cur_data_segno;
	   cpi->cur_data_blkoff = checkpoint->cur_data_blkoff;

	   cpi->valid_inode_count = checkpoint->valid_inode_count;
	   cpi->valid_node_count = checkpoint->valid_node_count;

	   cpi->valid_block_count = checkpoint->valid_block_count;
	   cpi->user_block_count = checkpoint->user_block_count;
	 */
//      FIXME: [Goku]
//      cpi->alloc_valid_block_count =
	/*
	   cpi->load_checkpoint_addr = checkpoint->prev_checkpoint_addr;
	 */
//      FIXME: [Goku] Orphan part
	cpi->cp = checkpoint;

//      FIXME: [Goku] cp_page

//      cpi->si should be changed when sit is initialed.

	printk(KERN_INFO "Read checkpoint end.\n");
	return 0;
}

//      Step1: delete all valid counter
//      Step2: construct bypass link
//      Step3: delete checkpoint itself
int delete_checkpoint(struct hmfs_sb_info *sbi, u32 version)
{
	struct hmfs_checkpoint *checkpoint = NULL;
	struct hmfs_checkpoint *next_checkpoint = NULL;
	block_t nat_root_addr;
	int ret = 0;
	printk(KERN_INFO "Delete checkpoint stage 1.\n");
	ret = find_checkpoint_version(sbi, version, checkpoint);
	if (ret != 0) {
		printk("Version %d not found.\n", ret);
		return -1;
	}
	nat_root_addr = le64_to_cpu(checkpoint->nat_addr);
	dc_nat_root(sbi, nat_root_addr);

	printk(KERN_INFO "Delete checkpoint stage 2.\n");
	ret = find_next_checkpoint_version(sbi, version, next_checkpoint);
	if (ret != 0) {
		printk("Version %d not found.\n", ret);
		return -1;
	}
	next_checkpoint->prev_cp_addr = checkpoint->prev_cp_addr;
	printk(KERN_INFO "Delete checkpoint stage 3.\n");
	dc_checkpoint(sbi, (char *)checkpoint - (char *)sbi->virt_addr);
	return 0;
}
