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

	nm_i->max_nid = hmfs_max_nid();

	return 0;
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
	if (err)
	{
		goto free_nm;
	}		

	info->nat_inode = hmfs_iget(sb, HMFS_NAT_INO);

	if (IS_ERR(info->nat_inode)) {
err=PTR_ERR(info->nat_inode);
	goto free_nm;
	}

	return 0;
free_nm:
	kfree(info);
	return err;
}

static struct hmfs_nat_block *get_current_nat_block(struct hmfs_sb_info *sbi,
						    uid_t uid)
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
	new->ni.nid = nid;
	list_add_tail(&new->list, &nm_i->nat_entries);
	nm_i->nat_cnt++;
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
		e->ni.ino = le64_to_cpu(ne->ino);
		e->ni.blk_addr = le64_to_cpu(ne->block_addr);
		e->ni.version = le32_to_cpu(ne->version);
	}
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
	if (err)
		return ERR_PTR(err);
	return ADDR(sbi, ni.blk_addr);
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

	/* search in nat cache */
	e = __lookup_nat_cache(nm_i, nid);
printk(KERN_ERR"lookup in nat cache:%d\n",nid);
	if (e) {
		ni->ino = e->ni.ino;
		ni->blk_addr = e->ni.blk_addr;
		ni->version = e->ni.version;
		return 0;
	}

	/* search nat journals */
	i = lookup_journal_in_cp(cp_info, NAT_JOURNAL, nid, 0);
printk(KERN_ERR"lookup in cp cache:%d\n",nid);
	if (i >= 0) {
		ne = nat_in_journal(cp_info, i);
		node_info_from_raw_nat(ni, &ne);
	}
	if (i >= 0)
		goto cache;

	/* search in main area */
	nat_block = get_current_nat_block(sbi, start_nid);
printk(KERN_ERR"lookup in block:%d\n",nid);
	if (IS_ERR(nat_block))
		return PTR_ERR(nat_block);
printk(KERN_ERR"lookup right:%d\n",nid);
	ne = nat_block->entries[nid - start_nid];
	node_info_from_raw_nat(ni, &ne);
cache:
	//TODO: add nat cache
	return 0;
}

void destroy_node_manager(struct hmfs_sb_info *sbi)
{
	struct hmfs_nm_info *info = NM_I(sbi);
	kfree(info);
	iput(info->nat_inode);
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
