#include <linux/fs.h>
#include <linux/types.h>
#include "hmfs.h"
#include "hmfs_fs.h"
#include "node.h"

static struct kmem_cache *nat_entry_slab;

const struct address_space_operations hmfs_nat_aops;

static nid_t hmfs_max_nid(void)
{
	nid_t nid = 1;
	int height = 0;
	while (++height < NAT_TREE_MAX_HEIGHT)
		nid *= NAT_ADDR_PER_BLOCK;
	nid *= NAT_ENTRY_PER_BLOCK;
	return nid;
}

static struct nat_entry *__lookup_nat_cache(struct hmfs_nm_info *nm_i, nid_t n)
{
	return radix_tree_lookup(&nm_i->nat_root, n);
}

static int init_node_manager(struct hmfs_sb_info *sbi)
{
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct checkpoint_info *cp_i = CURCP_I(sbi);
	struct hmfs_checkpoint *cp = ADDR(sbi, cp_i->last_checkpoint_addr);

	nm_i->max_nid = hmfs_max_nid();
	nm_i->nat_cnt = 0;
	nm_i->free_nids = kzalloc(HMFS_PAGE_SIZE * 2, GFP_KERNEL);
	nm_i->next_scan_nid = le64_to_cpu(cp->next_scan_nid);
	if (nm_i->free_nids == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&nm_i->nat_entries);
	INIT_LIST_HEAD(&nm_i->dirty_nat_entries);
	INIT_LIST_HEAD(&nm_i->free_nid_list);
	INIT_RADIX_TREE(&nm_i->nat_root, GFP_ATOMIC);
	rwlock_init(&nm_i->nat_tree_lock);
	spin_lock_init(&nm_i->free_nid_list_lock);
	mutex_init(&nm_i->build_lock);
	return 0;
}

void alloc_nid_failed(struct hmfs_sb_info *sbi, nid_t nid)
{
	struct hmfs_nm_info *nm_i = NM_I(sbi);

	mutex_lock(&nm_i->build_lock);
	spin_lock(&nm_i->free_nid_list_lock);
	/*
	 * here, we have lost free bit of nid, therefore, we set
	 * free bit of nid for every nid which is fail in
	 * allocation
	 */
	nm_i->free_nids[nm_i->fcnt].nid = make_free_nid(nid, 1);
	nm_i->fcnt++;
	inc_valid_node_count(sbi, NULL, -1);
	spin_unlock(&nm_i->free_nid_list_lock);
	mutex_unlock(&nm_i->build_lock);
}

int build_node_manager(struct hmfs_sb_info *sbi)
{
	struct hmfs_nm_info *info;
	struct super_block *sb = sbi->sb;
	int err;

	info = kzalloc(sizeof(struct hmfs_nm_info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;
	sbi->nm_info = info;

	err = init_node_manager(sbi);
	if (err) {
		goto free_nm;
	}

	info->nat_inode = hmfs_iget(sb, HMFS_NAT_INO);

	if (IS_ERR(info->nat_inode)) {
		err = PTR_ERR(info->nat_inode);
		goto free_nm;
	}

	return 0;
free_nm:
	kfree(info);
	return err;
}

static struct hmfs_nat_block *get_current_nat_block(struct hmfs_sb_info *sbi,
						    nid_t nid)
{
	//TODO:
	return NULL;
}

static struct nat_entry *grab_nat_entry(struct hmfs_nm_info *nm_i, nid_t nid)
{
	struct nat_entry *new;

	new = kmem_cache_alloc(nat_entry_slab, GFP_ATOMIC);
	if (!new)
		return NULL;
	if (radix_tree_insert(&nm_i->nat_root, nid, new)) {
		kmem_cache_free(nat_entry_slab, new);
		return NULL;
	}
	memset(new, 0, sizeof(struct nat_entry));
	write_lock(&nm_i->nat_tree_lock);
	new->ni.nid = nid;
	list_add_tail(&new->list, &nm_i->nat_entries);
	nm_i->nat_cnt++;
	write_unlock(&nm_i->nat_tree_lock);
	return new;
}

static void cache_nat_entry(struct hmfs_nm_info *nm_i, nid_t nid,
			    struct hmfs_nat_entry *ne)
{
	struct nat_entry *e;
retry:
	e = __lookup_nat_cache(nm_i, nid);
	if (!e) {
		e = grab_nat_entry(nm_i, nid);
		if (!e) {
			goto retry;
		}
		write_lock(&nm_i->nat_tree_lock);
		e->ni.nid = nid;
		e->ni.ino = le64_to_cpu(ne->ino);
		e->ni.blk_addr = le64_to_cpu(ne->block_addr);
		e->ni.version = le32_to_cpu(ne->version);
		write_unlock(&nm_i->nat_tree_lock);
	}
}

void update_nat_entry(struct hmfs_nm_info *nm_i, nid_t nid, nid_t ino,
		      unsigned long blk_addr, unsigned int version, bool dirty)
{
	struct nat_entry *e;
retry:
	e = __lookup_nat_cache(nm_i, nid);
	if (!e) {
		e = grab_nat_entry(nm_i, nid);
		if (!e) {
			goto retry;
		}
	}
	write_lock(&nm_i->nat_tree_lock);
	e->ni.ino = ino;
	e->ni.nid = nid;
	e->ni.blk_addr = blk_addr;
	e->ni.version = version;
	if (dirty) {
		list_del(&e->list);
		list_add_tail(&e->list, &nm_i->dirty_nat_entries);
	}
	write_unlock(&nm_i->nat_tree_lock);
	printk(KERN_INFO "cache nat nid:%lu ino:%lu blk:%lu-%lu\n",
	       (unsigned long)nid, (unsigned long)ino,
	       blk_addr >> HMFS_SEGMENT_SIZE_BITS,
	       (blk_addr & ~HMFS_SEGMENT_MASK) >> HMFS_PAGE_SIZE_BITS);

}

static u64 get_new_node_page(struct hmfs_sb_info *sbi)
{
	struct checkpoint_info *cp_i = CURCP_I(sbi);
	u64 page_addr = 0;

	page_addr = cal_page_addr(cp_i->cur_node_segno, cp_i->cur_node_blkoff);

	cp_i->cur_node_blkoff++;
	return page_addr;
}

/*
 * return node address in NVM by nid, would not allocate
 * new node
 */
void *get_node(struct hmfs_sb_info *sbi, nid_t nid)
{
	struct node_info ni;
	int err;

	err = get_node_info(sbi, nid, &ni);
	printk("get node:%lu\n", (unsigned long)nid);
	if (err)
		return ERR_PTR(err);
	printk(KERN_INFO "blk_addr:%lu-%lu\n",
	       ni.blk_addr >> HMFS_SEGMENT_SIZE_BITS,
	       (ni.blk_addr & ~HMFS_SEGMENT_MASK) >> HMFS_PAGE_SIZE_BITS);
	if (ni.blk_addr == NULL_ADDR)
		return ERR_PTR(-ENODATA);
	else if (ni.blk_addr == NEW_ADDR || ni.blk_addr == FREE_ADDR) {
		return ERR_PTR(-EINVAL);
	}
	return ADDR(sbi, ni.blk_addr);
}

void *get_new_node(struct hmfs_sb_info *sbi, nid_t nid, nid_t ino)
{
	void *src;
	unsigned long block;
	void *dest;
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct checkpoint_info *cp_i = CURCP_I(sbi);
	struct hmfs_summary *summary = NULL;
	printk(KERN_INFO "get_new_node:%lu %lu\n", (unsigned long)nid,
	       (unsigned long)ino);
	src = get_node(sbi, nid);

	if (!IS_ERR(src)) {
		summary = get_summary_by_addr(sbi, src);
		if (get_summary_version(summary) == cp_i->version)
			return src;
	}

	block = get_new_node_page(sbi);
	dest = ADDR(sbi, block);
	if (!IS_ERR(src)) {
		hmfs_memcpy(dest, src, HMFS_PAGE_SIZE);
	}

	summary = get_summary_by_addr(sbi, dest);
	make_summary_entry(summary, ino, cp_i->version, 0, SUM_TYPE_NODE);

	//TODO: cache nat
	printk(KERN_INFO "blk_addr:%lu-%lu\n", block >> HMFS_SEGMENT_SIZE_BITS,
	       (block & ~HMFS_SEGMENT_MASK) >> HMFS_PAGE_SIZE_BITS);
	update_nat_entry(nm_i, nid, ino, block, cp_i->version, true);
	return dest;
}

int get_node_info(struct hmfs_sb_info *sbi, nid_t nid, struct node_info *ni)
{
	struct checkpoint_info *cp_info = CURCP_I(sbi);
	struct hmfs_nat_entry ne;
	nid_t start_nid = START_NID(nid);
	struct nat_entry *e;
	struct hmfs_nat_block *nat_block;
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	int i;
	bool dirty;

	/* search in nat cache */
	e = __lookup_nat_cache(nm_i, nid);
	printk(KERN_ERR "lookup in nat cache:%d\n", (int)nid);
	if (e) {
		read_lock(&nm_i->nat_tree_lock);
		ni->ino = e->ni.ino;
		ni->blk_addr = e->ni.blk_addr;
		ni->version = e->ni.version;
		read_unlock(&nm_i->nat_tree_lock);
		return 0;
	}

	/* search nat journals */
	i = lookup_journal_in_cp(cp_info, NAT_JOURNAL, nid, 0);
	printk(KERN_ERR "lookup in cp cache:%d\n", (int)nid);
	if (i >= 0) {
		ne = nat_in_journal(cp_info, i);
		node_info_from_raw_nat(ni, &ne);
		dirty = true;
		goto cache;
	}

	/* search in main area */
	nat_block = get_current_nat_block(sbi, start_nid);
	printk(KERN_ERR "lookup in block:%d\n", (int)nid);
	if (nat_block == NULL)
		return -ENODATA;
	printk(KERN_ERR "lookup right:%d\n", (int)nid);
	ne = nat_block->entries[nid - start_nid];
	node_info_from_raw_nat(ni, &ne);
	dirty = false;
cache:
	//TODO: add nat cache
	return 0;
}

static void add_free_nid(struct hmfs_nm_info *nm_i, nid_t nid, u64 free,
			 int *pos)
{
	spin_lock(&nm_i->free_nid_list_lock);
	nm_i->free_nids[*pos].nid = make_free_nid(nid, free);
	spin_unlock(&nm_i->free_nid_list_lock);
}

static void recycle_nat_journals(struct hmfs_sb_info *sbi,
				 struct hmfs_nm_info *nm_i, int *pos)
{
	struct checkpoint_info *cp_i = CURCP_I(sbi);
	struct hmfs_checkpoint *hmfs_cp = cp_i->cp;
	int i;
	nid_t nid;
	u64 blk_addr;

	write_lock(&cp_i->journal_lock);
	for (i = 0; i < NUM_NAT_JOURNALS_IN_CP && *pos >= 0; ++i) {
		nid = le64_to_cpu(hmfs_cp->nat_journals[i].nid);
		blk_addr =
		    le64_to_cpu(hmfs_cp->nat_journals[i].entry.block_addr);
		if (blk_addr == FREE_ADDR && nid > HMFS_ROOT_INO) {
			add_free_nid(nm_i, nid, 1, pos);
			*pos = *pos - 1;
		}
	}
	write_unlock(&cp_i->journal_lock);
}

static nid_t scan_nat_block(struct hmfs_nm_info *nm_i,
			    struct hmfs_nat_block *nat_blk, nid_t start_nid,
			    int *pos)
{
	int i = start_nid % NAT_ENTRY_PER_BLOCK;
	u64 blk_addr;

	for (; i < NAT_ENTRY_PER_BLOCK && *pos >= 0; i++, start_nid++) {
		if (start_nid > nm_i->max_nid)
			break;

		if (nat_blk != NULL)
			blk_addr = le64_to_cpu(nat_blk->entries[i].block_addr);
		else
			goto found;

		if (blk_addr == FREE_ADDR) {
found:
			add_free_nid(nm_i, start_nid, 0, pos);
			*pos = *pos - 1;
		}
	}
	return start_nid;
}

static int build_free_nids(struct hmfs_sb_info *sbi)
{
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct hmfs_nat_block *nat_block = NULL;
	nid_t nid = nm_i->next_scan_nid;
	int pos = BUILD_FREE_NID_COUNT - 1;

	if (nm_i->fcnt >= BUILD_FREE_NID_COUNT)
		return nm_i->fcnt;

	BUG_ON(nm_i->fcnt != 0);

	recycle_nat_journals(sbi, nm_i, &pos);

	while (pos >= 0 && nid < nm_i->max_nid) {
		nat_block = get_current_nat_block(sbi, nid);
		nid = scan_nat_block(nm_i, nat_block, nid, &pos);
	}

	nm_i->next_scan_nid = nid;
	return BUILD_FREE_NID_COUNT - 1 - pos;
}

bool alloc_nid(struct hmfs_sb_info * sbi, nid_t * nid)
{
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct checkpoint_info *cp_i = CURCP_I(sbi);
	int num;

retry:
	if (cp_i->valid_node_count + 1 >= nm_i->max_nid)
		return false;

	spin_lock(&nm_i->free_nid_list_lock);

	if (nm_i->fcnt > 0) {
		*nid = get_free_nid(nm_i->free_nids[nm_i->fcnt - 1].nid);
		nm_i->fcnt--;
		inc_valid_node_count(sbi, NULL, 1);
		spin_unlock(&nm_i->free_nid_list_lock);
		return true;
	}
	spin_unlock(&nm_i->free_nid_list_lock);

	//FIXME: Is there deadlock here?
	mutex_lock(&nm_i->build_lock);
	num = build_free_nids(sbi);
	spin_lock(&nm_i->free_nid_list_lock);
	nm_i->fcnt = num;
	spin_unlock(&nm_i->free_nid_list_lock);
	mutex_unlock(&nm_i->build_lock);
	goto retry;
}

void destroy_node_manager(struct hmfs_sb_info *sbi)
{
	struct hmfs_nm_info *info = NM_I(sbi);
	kfree(info->free_nids);
	iput(info->nat_inode);
	kfree(info);
}

int create_node_manager_caches(void)
{
	nat_entry_slab = hmfs_kmem_cache_create("nat_entry",
						sizeof(struct nat_entry), NULL);
	if (!nat_entry_slab)
		return -ENOMEM;

	return 0;
}

void destroy_node_manager_caches(void)
{
	kmem_cache_destroy(nat_entry_slab);
}
