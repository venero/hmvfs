#include <linux/fs.h>
#include <linux/types.h>
#include "hmfs.h"
#include "hmfs_fs.h"
#include "node.h"
#include "segment.h"

static struct kmem_cache *nat_entry_slab;

const struct address_space_operations hmfs_nat_aops;

static inline bool inc_valid_node_count(struct hmfs_sb_info *sbi,
				struct inode *inode, int count, bool force)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	pgc_t alloc_valid_block_count;
	pgc_t free_blocks = free_user_blocks(sbi);

	lock_cm(cm_i);

	alloc_valid_block_count = cm_i->alloc_block_count + count;

	if (unlikely(!free_blocks && !force)) {
		unlock_cm(cm_i);
		return false;
	}

	if (inode)
		inode->i_blocks += count;

	cm_i->valid_node_count += count;
	cm_i->valid_block_count += count;
	cm_i->alloc_block_count = alloc_valid_block_count;
	unlock_cm(cm_i);

	return true;
}

static inline void dec_valid_node_count(struct hmfs_sb_info *sbi,
				struct inode *inode, int count, bool dec_valid)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	lock_cm(cm_i);
	cm_i->valid_node_count -= count;
	if (likely(inode))
		inode->i_blocks -= count;
	if (dec_valid)
		cm_i->valid_block_count -= count;
	unlock_cm(cm_i);
}

static nid_t hmfs_max_nid(struct hmfs_sb_info *sbi)
{
	nid_t nid = 1;
	int height = 0;

	while (++height <= sbi->nat_height)
		nid *= NAT_ADDR_PER_NODE;
	nid *= NAT_ENTRY_PER_BLOCK;
	return nid;
}

void set_new_dnode(struct dnode_of_data *dn, struct inode *inode,
				struct hmfs_inode *hi, struct direct_node *db, nid_t nid)
{
	dn->inode = inode;
	dn->inode_block = hi;
	dn->node_block = db;
	dn->nid = nid;
}

/**
 * The maximum depth is 4.
 */
int get_node_path(long block, int offset[4], unsigned int noffset[4])
{
	const long direct_index = NORMAL_ADDRS_PER_INODE;
	const long direct_blks = ADDRS_PER_BLOCK;
	const long dptrs_per_blk = NIDS_PER_BLOCK;
	const long indirect_blks = ADDRS_PER_BLOCK * NIDS_PER_BLOCK;
	const long dindirect_blks = indirect_blks * NIDS_PER_BLOCK;
	int n = 0;
	int level = 0;

	noffset[0] = 0;

	if (block < direct_index) {
		offset[n] = block;
		goto got;
	}

	/* direct block 1 */
	block -= direct_index;
	if (block < direct_blks) {
		offset[n++] = NODE_DIR1_BLOCK;
		noffset[n] = 1;
		offset[n] = block;
		level = 1;
		goto got;
	}

	/* direct block 2 */
	block -= direct_blks;
	if (block < direct_blks) {
		offset[n++] = NODE_DIR2_BLOCK;
		noffset[n] = 2;
		offset[n] = block;
		level = 1;
		goto got;
	}

	/* indirect block 1 */
	block -= direct_blks;
	if (block < indirect_blks) {
		offset[n++] = NODE_IND1_BLOCK;
		noffset[n] = 3;
		offset[n++] = block / direct_blks;
		noffset[n] = 4 + offset[n - 1];
		offset[n] = block % direct_blks;
		level = 2;
		goto got;
	}

	/* indirect block 2 */
	block -= indirect_blks;
	if (block < indirect_blks) {
		offset[n++] = NODE_IND2_BLOCK;
		noffset[n] = 4 + dptrs_per_blk;
		offset[n++] = block / direct_blks;
		noffset[n] = 5 + dptrs_per_blk + offset[n - 1];
		offset[n] = block % direct_blks;
		level = 2;
		goto got;
	}

	/* double indirect block */
	block -= indirect_blks;
	if (block < dindirect_blks) {
		offset[n++] = NODE_DIND_BLOCK;
		noffset[n] = 5 + (dptrs_per_blk * 2);
		offset[n++] = block / indirect_blks;
		noffset[n] = 6 + (dptrs_per_blk * 2)
		 + offset[n - 1] * (dptrs_per_blk + 1);
		offset[n++] = (block / direct_blks) % dptrs_per_blk;
		noffset[n] = 7 + (dptrs_per_blk * 2)
		 + offset[n - 2] * (dptrs_per_blk + 1) + offset[n - 1];
		offset[n] = block % direct_blks;
		level = 3;
		goto got;

	} else {
		BUG();
	}
got:
	return level;
}

static struct nat_entry *__lookup_nat_cache(struct hmfs_nm_info *nm_i, nid_t n)
{
	return radix_tree_lookup(&nm_i->nat_root, n);
}

void destroy_node_manager(struct hmfs_sb_info *sbi)
{
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct nat_entry *result[NATVEC_SIZE], *entry;
	nid_t nid = HMFS_ROOT_INO;
	int found, i;

	lock_write_nat(nm_i);
	while (1) {
		found = radix_tree_gang_lookup(&nm_i->nat_root, (void **)result, nid,
						NATVEC_SIZE);
		if (!found)
			break;
		for (i = 0; i < found; i++) {
			entry = result[i];
			nid = entry->ni.nid + 1;
			list_del(&entry->list);
			kmem_cache_free(nat_entry_slab, entry);
		}
	}
	unlock_write_nat(nm_i);

	hmfs_bug_on(sbi, !list_empty(&nm_i->nat_entries));
	hmfs_bug_on(sbi, !list_empty(&nm_i->dirty_nat_entries));

	kfree(nm_i->free_nids);
	kfree(nm_i);
}

static int init_node_manager(struct hmfs_sb_info *sbi)
{
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct checkpoint_info *cp_i = cm_i->last_cp_i;
	struct hmfs_checkpoint *cp = cp_i->cp;

	nm_i->max_nid = hmfs_max_nid(sbi);
	nm_i->nat_cnt = 0;
	nm_i->free_nids = kzalloc(PAGE_SIZE * 2, GFP_KERNEL);
	nm_i->next_scan_nid = le32_to_cpu(cp->next_scan_nid);
	nm_i->journaling_threshold = HMFS_JOURNALING_THRESHOLD;
	nm_i->nid_wrapped = 0;
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

	lock_free_nid(nm_i);
	/*
	 * here, we have lost free bit of nid, therefore, we set
	 * free bit of nid for every nid which is fail in
	 * allocation
	 */
	nm_i->free_nids[nm_i->fcnt].nid = make_free_nid(nid, 1);
	nm_i->fcnt++;
	unlock_free_nid(nm_i);
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

void truncate_node(struct dnode_of_data *dn)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(dn->inode);
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct node_info ni;

	get_node_info(sbi, dn->nid, &ni);
	if (dn->inode->i_blocks == 0) {
		hmfs_bug_on(sbi, ni.blk_addr != NULL_ADDR);
		goto invalidate;
	}

	hmfs_bug_on(sbi, ni.blk_addr == NULL_ADDR);

	dec_valid_node_count(sbi, dn->inode, 1, is_new_block(sbi, ni.blk_addr));
	update_nat_entry(nm_i, dn->nid, dn->inode->i_ino, NULL_ADDR,
			 true);

	if (dn->nid == dn->inode->i_ino) {
		remove_orphan_inode(sbi, dn->nid);
		dec_valid_inode_count(sbi);
	} else {
		mark_inode_dirty(dn->inode);
	}

	invalidate_delete_block(sbi, ni.blk_addr, 1);

invalidate:
	dn->node_block = NULL;
}

static int truncate_dnode(struct dnode_of_data *dn)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(dn->inode);
	struct direct_node *hn;

	if (dn->nid == 0)
		return 1;

	hn = get_node(sbi, dn->nid);
	if (IS_ERR(hn) && PTR_ERR(hn) == -ENODATA)
		return 1;
	else if (IS_ERR(hn))
		return PTR_ERR(hn);

	dn->node_block = hn;
	dn->ofs_in_node = 0;
	truncate_data_blocks(dn);
	truncate_node(dn);
	return 1;
}

/*
 * We're about to truncate the whole nodes. Therefore, we don't need to COW
 * the old node. We just mark the its nid slot in parent node to be 0
 */
static int truncate_nodes(struct dnode_of_data *dn, unsigned int nofs, int ofs,
				int depth)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(dn->inode);
	struct dnode_of_data rdn;
	struct hmfs_node *hn;
	nid_t child_nid;
	unsigned int child_nofs;
	int freed = 0;
	int i, ret;
	struct node_info ni;

	if (dn->nid == 0)
		return NIDS_PER_BLOCK + 1;

	/* hn is read-only, but it's ok here */
	hn = get_node(sbi, dn->nid);
	if (IS_ERR(hn))
		return PTR_ERR(hn);

	if (depth < 3) {
		for (i = ofs; i < NIDS_PER_BLOCK; i++, freed++) {
			child_nid = le32_to_cpu(hn->in.nid[i]);
			if (child_nid == 0)
				continue;
			/* We don't mark hn->in.nid[i] to be 0 */
			rdn.nid = child_nid;
			rdn.inode = dn->inode;

			ret = get_node_info(sbi, rdn.nid, &ni);
			if (ret)
				continue;

			ret = truncate_dnode(&rdn);
			if (ret < 0)
				goto out_err;
		}
	} else {
		child_nofs = nofs + ofs * (NIDS_PER_BLOCK + 1) + 1;
		for (i = ofs; i < NIDS_PER_BLOCK; i++) {
			child_nid = le32_to_cpu(hn->in.nid[i]);
			if (child_nid == 0) {
				child_nofs += NIDS_PER_BLOCK + 1;
				continue;
			}
			rdn.nid = child_nid;
			rdn.inode = dn->inode;

			ret = get_node_info(sbi, rdn.nid, &ni);
			if (ret)
				continue;

			ret = truncate_nodes(&rdn, child_nofs, 0, depth - 1);
			if (ret == (NIDS_PER_BLOCK + 1)) {
				child_nofs += ret;
			} else if (ret && ret != -ENODATA)
				goto out_err;
		}
		freed = child_nofs;
	}

	if (!ofs) {
		truncate_node(dn);
		freed++;
	}
	return freed;
out_err:
	return ret;
}

/* return address of node in historic checkpoint */
struct hmfs_node *__get_node(struct hmfs_sb_info *sbi,
				struct checkpoint_info *cp_i, nid_t nid)
{
	struct hmfs_nat_entry *nat_entry;
	block_t node_addr;

	if (cp_i->version == CM_I(sbi)->new_version)
		return get_node(sbi, nid);

	nat_entry = get_nat_entry(sbi, cp_i->version, nid);
	if (!nat_entry)
		return NULL;
	node_addr = le64_to_cpu(nat_entry->block_addr);

	return ADDR(sbi, node_addr);
}

static int truncate_partial_nodes(struct dnode_of_data *dn,
				struct hmfs_inode *hi, int *offset, int depth)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(dn->inode);
	nid_t nid[3];
	struct hmfs_node *nodes[2];
	nid_t child_nid;
	int err = 0;
	int i;
	int idx = depth - 2;
	struct node_info ni;

	nid[0] = le32_to_cpu(hi->i_nid[offset[0] - NODE_DIR1_BLOCK]);
	if (!nid[0])
		return 0;

	/* get indirect nodes in the path */
	for (i = 0; i < depth - 1; i++) {
		nodes[i] = get_node(sbi, nid[i]);
		if (IS_ERR(nodes[i])) {
			depth = i + 1;
			err = PTR_ERR(nodes[i]);
			goto fail;
		}
		nid[i + 1] = get_nid(nodes[i], offset[i + 1], false);
	}

	/* free direct nodes linked to a partial indirect node */
	for (i = offset[depth - 1]; i < NIDS_PER_BLOCK; i++) {
		child_nid = get_nid(nodes[idx], i, false);
		if (!child_nid)
			continue;
		dn->nid = child_nid;

		err = get_node_info(sbi, child_nid, &ni);
		if (err) {
			hmfs_bug_on(sbi, 1);
			continue;
		}

		err = truncate_dnode(dn);
		if (err < 0)
			goto fail;
		nodes[idx] = alloc_new_node(sbi, nid[idx], dn->inode, SUM_TYPE_IDN, false);
		if (IS_ERR(nodes[idx])) {
			err = PTR_ERR(nodes[idx]);
			goto fail;
		}
		set_nid(nodes[idx], i, 0, false);
	}

	hmfs_bug_on(sbi, !offset[depth - 1]);
	/*
	if (offset[depth - 1] == 0) {
		dn->nid = nid[idx];
		truncate_node(dn);
	}
	*/

	offset[idx]++;
	offset[depth - 1] = 0;
fail:
	return err;
}

int truncate_inode_blocks(struct inode *inode, pgoff_t from)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	int err = 0, cont = 1;
	int level, offset[4], noffset[4];
	unsigned int nofs = 0;
	struct hmfs_node *hn;
	struct dnode_of_data dn;

	level = get_node_path(from, offset, noffset);
	hn = get_node(sbi, inode->i_ino);
	if (IS_ERR(hn))
		return PTR_ERR(hn);

	set_new_dnode(&dn, inode, &hn->i, NULL, 0);
	switch (level) {
	case 0:
	case 1:
		nofs = noffset[1];
		break;
	case 2:
		nofs = noffset[1];
		if (!offset[level - 1])
			goto skip_partial;
		err = truncate_partial_nodes(&dn, &hn->i, offset, level);
		if (err < 0 && err != -ENODATA)
			goto fail;
		nofs += 1 + NIDS_PER_BLOCK;
		break;
	case 3:
		nofs = 5 + 2 * NIDS_PER_BLOCK;
		if (!offset[level - 1])
			goto skip_partial;
		err = truncate_partial_nodes(&dn, &hn->i, offset, level);
		if (err < 0 && err != -ENODATA)
			goto fail;
		break;
	default:
		hmfs_bug_on(sbi, 1);
	}
skip_partial:
	while (cont) {
		dn.nid = le32_to_cpu(hn->i.i_nid[offset[0] - NODE_DIR1_BLOCK]);

		switch (offset[0]) {
		case NODE_DIR1_BLOCK:
		case NODE_DIR2_BLOCK:
			err = truncate_dnode(&dn);
			break;
		case NODE_IND1_BLOCK:
		case NODE_IND2_BLOCK:
			err = truncate_nodes(&dn, nofs, offset[1], 2);
			break;
		case NODE_DIND_BLOCK:
			err = truncate_nodes(&dn, nofs, offset[1], 3);
			cont = 0;
			break;
		default:
			hmfs_bug_on(sbi, 1);
		}
		if (err < 0 && err != -ENODATA)
			goto fail;
		if (offset[1] == 0 && hn->i.i_nid[offset[0] - NODE_DIR1_BLOCK]) {
			hn = alloc_new_node(sbi, inode->i_ino, inode, SUM_TYPE_INODE, false);
			if (IS_ERR(hn)) {
				err = PTR_ERR(hn);
				goto fail;
			}
			hn->i.i_nid[offset[0] - NODE_DIR1_BLOCK] = 0;
		}
		offset[1] = 0;
		offset[0]++;
		nofs += err;
	}
fail:
	return err > 0 ? 0 : err;
}

void gc_update_nat_entry(struct hmfs_nm_info *nm_i, nid_t nid,
				block_t blk_addr)
{
	struct nat_entry *entry;

	lock_write_nat(nm_i);
	entry = __lookup_nat_cache(nm_i, nid);
	if (entry) {
		entry->ni.blk_addr = blk_addr;
	}

	unlock_write_nat(nm_i);
}

void update_nat_entry(struct hmfs_nm_info *nm_i, nid_t nid, nid_t ino,
		      block_t blk_addr, bool dirty)
{
	struct nat_entry *e, *le;

	lock_write_nat(nm_i);
retry:
	e = __lookup_nat_cache(nm_i, nid);

	if (!e) {
		e = grab_nat_entry(nm_i, nid);
		if (!e) {
			goto retry;
		}
	}
	e->ni.ino = ino;
	e->ni.nid = nid;
	e->ni.blk_addr = blk_addr;
	e->ni.flag = 0;

	if (dirty) {
		list_del(&e->list);
		INIT_LIST_HEAD(&e->list);
		if (nm_i->dirty_nat_entries.next == &nm_i->dirty_nat_entries) {
			list_add_tail(&e->list, &nm_i->dirty_nat_entries);
			goto unlock;
		}
		list_for_each_entry(le, &nm_i->dirty_nat_entries, list) {
			if (e->ni.nid < le->ni.nid) {
				list_add_tail(&e->list, &le->list);
				goto unlock;
			}
		}
		list_add_tail(&e->list, &nm_i->dirty_nat_entries);
	}
unlock:
	unlock_write_nat(nm_i);
}

/*
 * return node address in NVM by nid, would not allocate
 * new node
 */
void *get_node(struct hmfs_sb_info *sbi, nid_t nid)
{
	struct node_info ni;
	int err;

	if (nid == NULL_NID)
		return ERR_PTR(-ENODATA);

	err = get_node_info(sbi, nid, &ni);

	if (err) {
		return ERR_PTR(err);
	}
	if (ni.blk_addr == NULL_ADDR) {
		return ERR_PTR(-ENODATA);
	}
	/* 
	 * accelerate speed to grab nat entry, 
	 * we don't need to search nat entry block
	 */

	return ADDR(sbi, ni.blk_addr);
}

static void setup_summary_of_new_node(struct hmfs_sb_info *sbi,
				block_t new_node_addr, block_t src_addr, nid_t ino,
				unsigned int ofs_in_node, char sum_type)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct hmfs_summary *dest_sum = NULL;

	dest_sum = get_summary_by_addr(sbi, new_node_addr);
	make_summary_entry(dest_sum, ino, cm_i->new_version, ofs_in_node,
			sum_type);
}

static struct hmfs_node *__alloc_new_node(struct hmfs_sb_info *sbi, nid_t nid,
				struct inode *inode, char sum_type, bool force)
{
	void *src;
	block_t blk_addr, src_addr;
	struct hmfs_node *dest;
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct checkpoint_info *cp_i = CURCP_I(sbi);
	struct hmfs_summary *summary = NULL;
	unsigned int ofs_in_node = NID_TO_BLOCK_OFS(nid);

	src = get_node(sbi, nid);

	if (!IS_ERR(src)) {
		src_addr = L_ADDR(sbi, src);
		summary = get_summary_by_addr(sbi, src_addr);
		if (get_summary_start_version(summary) == cp_i->version &&
					!is_inode_flag_set(HMFS_I(inode), FI_CONVERT_INLINE))
			return src;
	} else
		src_addr = 0;

	if (is_inode_flag_set(HMFS_I(inode), FI_NO_ALLOC))
		return ERR_PTR(-EPERM);

	if (!inc_valid_node_count(sbi, get_stat_object(inode, !IS_ERR(src)), 1, force))
		return ERR_PTR(-ENOSPC);

	blk_addr = alloc_free_node_block(sbi, true);

	if (blk_addr == NULL_ADDR) {
		inc_valid_node_count(sbi, get_stat_object(inode, !IS_ERR(src)), -1, true);
		return ERR_PTR(-ENOSPC);
	}

	dest = ADDR(sbi, blk_addr);
	if (!IS_ERR(src)) {
		hmfs_memcpy(dest, src, HMFS_BLOCK_SIZE[SEG_NODE_INDEX]);
	} else {
		memset_nt(dest, 0, HMFS_BLOCK_SIZE[SEG_NODE_INDEX]);
	}

	setup_summary_of_new_node(sbi, blk_addr, src_addr, nid,
			ofs_in_node, sum_type);
	update_nat_entry(nm_i, nid, inode->i_ino, blk_addr,	true);

	return dest;
}

void *alloc_new_node(struct hmfs_sb_info *sbi, nid_t nid, struct inode *inode,
				char sum_type, bool force)
{
	block_t addr;

	if (likely(inode))
		return __alloc_new_node(sbi, nid, inode, sum_type, force);

	if (is_checkpoint_node(sum_type)) {
		if (!inc_valid_node_count(sbi, NULL, 1, true))
			return ERR_PTR(-ENOSPC);
		addr = alloc_free_node_block(sbi, false);
		if (sum_type == SUM_TYPE_CP)
			memset_nt(ADDR(sbi, addr), 0, HMFS_BLOCK_SIZE[SEG_NODE_INDEX]);
		return ADDR(sbi, addr);
	}

	if (!inc_gc_block_count(sbi, SEG_NODE_INDEX))
		return ERR_PTR(-ENOSPC);
	addr = alloc_free_node_block(sbi, true);
	return ADDR(sbi, addr);
}

int get_node_info(struct hmfs_sb_info *sbi, nid_t nid, struct node_info *ni)
{
	struct hmfs_nat_entry *ne_local;
	struct nat_entry *e;
	struct hmfs_nm_info *nm_i = NM_I(sbi);

	/* search in nat cache */
	e = __lookup_nat_cache(nm_i, nid);
	if (e) {
		lock_read_nat(nm_i);
		ni->ino = e->ni.ino;
		ni->blk_addr = e->ni.blk_addr;
		unlock_read_nat(nm_i);
		return 0;
	}

	/* search in main area */
	ne_local = get_nat_entry(sbi, CM_I(sbi)->last_cp_i->version, nid);
	if (ne_local == NULL)
		return -ENODATA;
	node_info_from_raw_nat(ni, ne_local);

	update_nat_entry(nm_i, nid, ni->ino, ni->blk_addr, false);
	return 0;
}

static void add_free_nid(struct hmfs_nm_info *nm_i, nid_t nid, u64 free,
				int *pos)
{
	nm_i->free_nids[*pos].nid = make_free_nid(nid, free);
}

/* Get free nid from journals of loaded checkpoint */
static void init_free_nids(struct hmfs_sb_info *sbi)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct hmfs_checkpoint *hmfs_cp = cm_i->last_cp_i->cp;
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	int i, pos = 0;
	block_t blk_addr;
	nid_t nid;

	
	lock_free_nid(nm_i);
	for (i = 0; i < NUM_NAT_JOURNALS_IN_CP; ++i) {
		nid = le32_to_cpu(hmfs_cp->nat_journals[i].nid);
		blk_addr = le64_to_cpu(hmfs_cp->nat_journals[i].entry.block_addr);
		if (blk_addr == NULL_ADDR && nid > HMFS_ROOT_INO) {
			add_free_nid(nm_i, nid, 1, &pos);
			pos++;
		}
		if (nid >= HMFS_ROOT_INO)
			cm_i->nr_nat_journals = i + 1;
	}
	
	nm_i->fcnt = pos;
	unlock_free_nid(nm_i);
}

/* Check whether block_addr of nid in journal is NULL_ADDR */
static int is_valid_free_nid(struct hmfs_sb_info *sbi, nid_t nid)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct hmfs_checkpoint *hmfs_cp = cm_i->last_cp_i->cp;
	int i;
	nid_t local_nid;

	if (!nm_i->nid_wrapped)
		goto check_value;

	/* Check journal */
	for (i = 0; i < cm_i->nr_nat_journals; ++i) {
		local_nid = le32_to_cpu(hmfs_cp->nat_journals[i].nid);
		if (local_nid == nid)
			return 0;
	}

	/*
	 * If we scan nat block wrapped around, we might add a nid to free 
	 * nid list twice. Because a nid might always exist in journal and
	 * mark as NULL. In addition, the value of it in NAT block is also 
	 * NULL_ADDR
	 */
	for (i = nm_i->delete_nid_index; i < BUILD_FREE_NID_COUNT; ++i) {
		if (nid == get_free_nid(nm_i->free_nids[i].nid))
			return 0;
	}

	lock_read_nat(nm_i);
	if (__lookup_nat_cache(nm_i, nid)) {
		unlock_read_nat(nm_i);
		return 0;
	}
	unlock_read_nat(nm_i);
check_value:
	return nid > HMFS_ROOT_INO;
}

static nid_t scan_nat_block(struct hmfs_sb_info *sbi,
				struct hmfs_nat_block *nat_blk, nid_t start_nid, int *pos)
{
	int i = start_nid % NAT_ENTRY_PER_BLOCK;
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	block_t blk_addr;

	for (; i < NAT_ENTRY_PER_BLOCK && *pos >= 0; i++, start_nid++) {
		if (start_nid > nm_i->max_nid)
			break;

		if (nat_blk != NULL)
			blk_addr = le64_to_cpu(nat_blk->entries[i].block_addr);
		else
			goto found;

		if (blk_addr == NULL_ADDR) {
found:
			if (!is_valid_free_nid(sbi, start_nid))
				continue;
			add_free_nid(nm_i, start_nid, 0, pos);
			*pos = *pos - 1;
		}
	}
	return start_nid;
}

/* Scan free nid from dirty nat entries */
static int scan_delete_nid(struct hmfs_sb_info *sbi, int *pos)
{
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct nat_entry *ne;
	struct list_head *head, *this, *next;

	head = &nm_i->dirty_nat_entries;
	lock_write_nat(nm_i);

	list_for_each_safe(this, next, head) {
		ne = list_entry(this, struct nat_entry, list);
		if (ne->ni.blk_addr == NULL_ADDR) {
			/*
			 * The nid is from the dirty nat entries. Thus, we should mark the
			 * free bit of nid and we should always write the nid to NVM when 
			 * flushing it
			 */
			add_free_nid(nm_i, ne->ni.nid, 1, pos);	
			list_del(&ne->list);
			radix_tree_delete(&nm_i->nat_root, ne->ni.nid);
			kmem_cache_free(nat_entry_slab, ne);
			nm_i->nat_cnt--;

			*pos = *pos - 1;
			if (*pos < 0)
				break;
		}
	}

	nm_i->delete_nid_index = *pos;
	unlock_write_nat(nm_i);
	return *pos;
}

static int build_free_nids(struct hmfs_sb_info *sbi)
{
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct hmfs_nat_block *nat_block = NULL;
	nid_t nid = nm_i->next_scan_nid;
	int pos = BUILD_FREE_NID_COUNT - 1;
	int count;

	if (nm_i->fcnt > 0)
		return 0;

	pos = scan_delete_nid(sbi, &pos);
	
	if (pos < 0)
		return BUILD_FREE_NID_COUNT;

	while (pos >= 0 && nid < nm_i->max_nid) {
		nat_block = get_nat_entry_block(sbi, CM_I(sbi)->last_cp_i->version,
							nid);
		nid = scan_nat_block(sbi, nat_block, nid, &pos);
	}

	count = BUILD_FREE_NID_COUNT - 1 - pos;
	if (nid > nm_i->max_nid) {
		pos++;
		while (pos < BUILD_FREE_NID_COUNT) {
			nm_i->free_nids[nm_i->fcnt++] =	nm_i->free_nids[pos++];
		}	
		hmfs_bug_on(sbi, nm_i->fcnt != count);
		nid = 0;
		nm_i->nid_wrapped = 1;
	}

	nm_i->next_scan_nid = nid;
	return count;
}

bool alloc_nid(struct hmfs_sb_info *sbi, nid_t *nid)
{
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	int num;

retry:
	if (cm_i->valid_node_count + 1 >= nm_i->max_nid)
		return false;

	lock_free_nid(nm_i);
	if (nm_i->fcnt > 0) {
		nm_i->fcnt--;
		*nid = get_free_nid(nm_i->free_nids[nm_i->fcnt].nid);
		unlock_free_nid(nm_i);
		return true;
	}
	unlock_free_nid(nm_i);

	mutex_lock(&nm_i->build_lock);
	num = build_free_nids(sbi);
	if (num) {
		lock_free_nid(nm_i);
		nm_i->fcnt = num;
		unlock_free_nid(nm_i);
	}
	mutex_unlock(&nm_i->build_lock);

	goto retry;
}

int create_node_manager_caches(void)
{
	nat_entry_slab = hmfs_kmem_cache_create("hmfs_nat_entry",
							sizeof(struct nat_entry), NULL);
	if (!nat_entry_slab)
		return -ENOMEM;

	return 0;
}

void destroy_node_manager_caches(void)
{
	kmem_cache_destroy(nat_entry_slab);
}

/* get a nat/nat page from nat/nat in-NVM tree */
static void *__get_nat_page(struct hmfs_sb_info *sbi, block_t cur_node_addr,
				unsigned int order, unsigned char height)
{
	block_t child_node_addr;
	struct hmfs_nat_node *cur_node;
	unsigned ofs;

	if (!cur_node_addr) {
		return NULL;
	}

	cur_node = ADDR(sbi, cur_node_addr);
	if (!height)
		return (void *)cur_node;

	ofs = (height - 1) * LOG2_NAT_ADDRS_PER_NODE;
	child_node_addr = le64_to_cpu(cur_node->addr[order >> ofs]);

	return __get_nat_page(sbi, child_node_addr, order & ((1 << ofs) - 1),
				height - 1);
}

struct hmfs_nat_block *get_nat_entry_block(struct hmfs_sb_info *sbi,
				ver_t version, nid_t nid)
{
	struct checkpoint_info *cp_i = get_checkpoint_info(sbi, version, false);
	unsigned int blk_id = nid / NAT_ENTRY_PER_BLOCK;
	struct hmfs_nat_node *nat_root = cp_i->nat_root;
	char nat_height = sbi->nat_height;
	
	hmfs_bug_on(sbi, !cp_i);
	return __get_nat_page(sbi, L_ADDR(sbi, nat_root), blk_id, nat_height);
}

struct hmfs_nat_entry *get_nat_entry(struct hmfs_sb_info *sbi,
				ver_t version, nid_t nid)
{
	struct hmfs_nat_block *nat_block;
	unsigned int rem = nid % NAT_ENTRY_PER_BLOCK;

	nat_block = get_nat_entry_block(sbi, version, nid);
	if (!nat_block)
		return NULL;
	return &nat_block->entries[rem];
}

struct hmfs_nat_node *get_nat_node(struct hmfs_sb_info *sbi,
				ver_t version, unsigned int index)
{
	struct checkpoint_info *cp_i = get_checkpoint_info(sbi, version, false);
	struct hmfs_nat_node *nat_root = cp_i->nat_root;
	unsigned int height = 0, block_id;

	height = GET_NAT_NODE_HEIGHT(index);
	block_id = GET_NAT_NODE_OFS(index);
	hmfs_bug_on(sbi, !cp_i);

	return __get_nat_page(sbi, L_ADDR(sbi, nat_root), block_id, height);
}

static block_t __flush_nat_entries(struct hmfs_sb_info *sbi,
				struct hmfs_nat_node *old_nat_node, 
				struct hmfs_nat_node *cur_nat_node,	unsigned int blk_order,
				char height, void *nat_entry_page, int ofs_in_par)
{
	//FIXME : cannot handle no NVM space for nat tree
	struct hmfs_nat_node *cur_stored_node, *old_child_node = NULL, 
			*cur_child_node = NULL;
	struct hmfs_summary *summary;
	unsigned char blk_type;
	block_t cur_stored_addr, child_stored_addr, child_node_addr;
	nid_t nid;
	unsigned int cur_version, _ofs, new_blk_order;

	/* preparation for summary update */
	nid = MAKE_NAT_NODE_NID(height, blk_order);
	cur_version = CM_I(sbi)->new_version;
	blk_type = ((height == 1) ? SUM_TYPE_NATD : SUM_TYPE_NATN);

	/* leaf, alloc & copy nat entry block  */
	if (!height) {
		cur_stored_node = alloc_new_node(sbi, nid, NULL, SUM_TYPE_NATD, true);
		cur_stored_addr = L_ADDR(sbi, cur_stored_node);

		hmfs_bug_on(sbi, IS_ERR(cur_stored_node) || !cur_stored_node);
		hmfs_bug_on(sbi, !nat_entry_page);

		hmfs_memcpy(cur_stored_node, nat_entry_page, HMFS_BLOCK_SIZE[SEG_NODE_INDEX]);
		summary = get_summary_by_addr(sbi, cur_stored_addr);
		make_summary_entry(summary, nid, cur_version, ofs_in_par, SUM_TYPE_NATD);
		
		/*
		for(i=0; i < NAT_ENTRY_PER_BLOCK; i++){
			if(!nat_entry_blk->entries[i].ino){
				//nid not allocated yet
				continue;
			}
			_addr = le64_to_cpu(nat_entry_blk->entries[i].block_addr); 
			raw_summary = get_summary_by_addr(sbi, _addr);
			make_summary_entry(raw_summary, nid, cur_version, i, blk_type);
		}
		*/

		return cur_stored_addr;
	}

	cur_stored_node = cur_nat_node;
	cur_stored_addr = NULL_ADDR;

	if (cur_nat_node == NULL || cur_nat_node == old_nat_node) {
		cur_stored_node = alloc_new_node(sbi, nid, NULL, SUM_TYPE_NATN, true);
		cur_stored_addr = L_ADDR(sbi, cur_stored_node);
		hmfs_bug_on(sbi, IS_ERR(cur_stored_node) || !cur_stored_node);

		if (cur_nat_node) {
			hmfs_memcpy(cur_stored_node, old_nat_node, HMFS_BLOCK_SIZE[SEG_NODE_INDEX]);
		} else {
			memset_nt(cur_stored_node, 0, HMFS_BLOCK_SIZE[SEG_NODE_INDEX]);
		}

		summary = get_summary_by_addr(sbi, cur_stored_addr);
		make_summary_entry(summary, nid, cur_version, ofs_in_par, SUM_TYPE_NATN);
	}

	//go to child
	_ofs = blk_order >> ((height - 1) * LOG2_NAT_ADDRS_PER_NODE);
	new_blk_order = blk_order & ((1 << ((height - 1) * LOG2_NAT_ADDRS_PER_NODE)) - 1);

	if (old_nat_node != NULL) {
		child_node_addr = le64_to_cpu(old_nat_node->addr[_ofs]);
		if (child_node_addr)
			old_child_node = ADDR(sbi, child_node_addr);
		else
			old_child_node = NULL;
	}

	if (cur_stored_node != NULL) {
		child_node_addr = le64_to_cpu(cur_stored_node->addr[_ofs]);
		if (child_node_addr)
			cur_child_node = ADDR(sbi, child_node_addr);
		else
			cur_child_node = NULL;
	}

	child_stored_addr = __flush_nat_entries(sbi, old_child_node,
								cur_child_node, new_blk_order, height - 1,
								nat_entry_page, _ofs);

	if (child_stored_addr) {
		/* child COWed, change addr to new block */
		cur_stored_node->addr[_ofs] = cpu_to_le64(child_stored_addr);
	}
	return cur_stored_addr;
}

static void clean_free_nid(struct hmfs_sb_info *sbi, nid_t nid)
{
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	int i;
	
	nid = make_free_nid(nid, 1);
	for (i = 0; i < nm_i->fcnt; i++) {
		if (nid == nm_i->free_nids[i].nid) {
			nm_i->free_nids[i].nid = get_free_nid(nid);
			return;
		}
	}
	hmfs_bug_on(sbi, 1);
}

static inline void clean_dirty_nat_entries(struct hmfs_sb_info *sbi) 
{
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct nat_entry *ne;
	struct list_head *head, *this, *next;
	
	head = &nm_i->dirty_nat_entries;
	list_for_each_safe(this, next, head) {
		ne = list_entry(this, struct nat_entry, list);

		if (ne->ni.flag & NAT_FLAG_FREE_NID) {
			clean_free_nid(sbi, ne->ni.nid);
			list_del(&ne->list);
			kmem_cache_free(nat_entry_slab, ne);
		} else {
			list_del(&ne->list);
			INIT_LIST_HEAD(&ne->list);
			ne->ni.flag = 0;
			list_add_tail(&ne->list, &nm_i->nat_entries);
		}
	}

	/* 
	 * Move journaling nat into dirty list and they are in order
	 * in nat_entries list because we add them in order in flush_nat_entries
	 */
	list_for_each_safe(this, next, &nm_i->nat_entries) {
		ne = list_entry(this, struct nat_entry, list);
		if (ne->ni.flag & NAT_FLAG_JOURNAL) {
			list_del(&ne->list);
			ne->ni.flag = 0;
			INIT_LIST_HEAD(&ne->list);
			list_add_tail(&ne->list, &nm_i->dirty_nat_entries);
		}
	}
}

static void cache_nat_journals_entries(struct hmfs_sb_info *sbi)
{
	struct hmfs_checkpoint *hmfs_cp = CM_I(sbi)->last_cp_i->cp;
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct hmfs_nat_journal *ne;
	nid_t nid, ino;
	block_t blk_addr;
	int i;

	for (i = 0; i < cm_i->nr_nat_journals; ++i) {
		ne = &hmfs_cp->nat_journals[i];
		nid = le32_to_cpu(ne->nid);
		ino = le32_to_cpu(ne->entry.ino);
		blk_addr = le64_to_cpu(ne->entry.block_addr);
		if (nid >= HMFS_ROOT_INO && blk_addr != NULL_ADDR)
			update_nat_entry(nm_i, nid, ino, blk_addr, true);
	}
}

int build_node_manager(struct hmfs_sb_info *sbi)
{
	struct hmfs_nm_info *info;
	int err;

	info = kzalloc(sizeof(struct hmfs_nm_info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;
	sbi->nm_info = info;

	err = init_node_manager(sbi);
	if (err) {
		goto free_nm;
	}

	init_free_nids(sbi);
	cache_nat_journals_entries(sbi);
	
	return 0;
free_nm:
	kfree(info);
	return err;
}

static int __flush_nat_journals(struct hmfs_checkpoint *hmfs_cp, 
				struct nat_entry *entry, int nr_dirty_nat, int* journal_pos)
{
	struct hmfs_nat_journal *nat_journal;

	if (nr_dirty_nat > NUM_NAT_JOURNALS_IN_CP - *journal_pos)
		return 1;

	nat_journal = &hmfs_cp->nat_journals[*journal_pos];

	while (nr_dirty_nat > 0) {
		entry = list_entry(entry->list.prev, struct nat_entry, list);
		nat_journal->nid = cpu_to_le32(entry->ni.nid);
		nat_journal->entry.ino = cpu_to_le32(entry->ni.ino);
		nat_journal->entry.block_addr = cpu_to_le64(entry->ni.blk_addr);
		nr_dirty_nat--;
		nat_journal++;
		entry->ni.flag |= NAT_FLAG_JOURNAL;
	}
	*journal_pos = *journal_pos + nr_dirty_nat;
	return 0;
}


/*
 * Caller should obtain hmfs_nm_info.nat_tree_lock.
 * And the journaling nat entries should always in dirty_nat_entries
 * list in runtime of fs. When flushing nat journals, we just move some
 * of them to nat_entries temporary
 */
static void flush_nat_journals(struct hmfs_sb_info *sbi, 
				struct hmfs_checkpoint *hmfs_cp)
{
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	int i, full;
	nid_t nid;
	struct nat_entry *new, *entry;
	struct list_head *this, *next;
	long new_blk_order, old_blk_order = -1;
	int nr_dirty_nat = 0;

	/* We should also flush dirty free nids */
	for (i = 0; i < nm_i->fcnt; i++) {
		nid = nm_i->free_nids[i].nid;

		if (is_dirty_free_nid(nid)) {
retry:
			new = kmem_cache_alloc(nat_entry_slab, GFP_ATOMIC);

			if (!new) {
				cond_resched();
				goto retry;
			}
			new->ni.nid = get_free_nid(nid);
			new->ni.blk_addr = NULL_ADDR;
			new->ni.flag = NAT_FLAG_FREE_NID;
			INIT_LIST_HEAD(&new->list);

			list_for_each_entry(entry, &nm_i->dirty_nat_entries, list) {
				if (new->ni.nid < entry->ni.nid) {
					list_add_tail(&new->list, &entry->list);
					break;
				}
			}
		}
	}

	if (nm_i->nid_wrapped) {
		nm_i->nid_wrapped = 0;
		return;
	}

	cm_i->nr_nat_journals = 0;
	entry = list_entry(nm_i->dirty_nat_entries.next, struct nat_entry, list);
	old_blk_order = (entry->ni.nid) / NAT_ENTRY_PER_BLOCK;
	list_for_each_entry(entry, &nm_i->dirty_nat_entries, list) {
		new_blk_order = (entry->ni.nid) / NAT_ENTRY_PER_BLOCK;
		if (new_blk_order != old_blk_order) {
			update_nat_stat(sbi, nr_dirty_nat);
			if (nr_dirty_nat && nr_dirty_nat <= nm_i->journaling_threshold) {
				full = __flush_nat_journals(hmfs_cp, entry, nr_dirty_nat,
								&cm_i->nr_nat_journals);
				if (full) {
					if (nm_i->journaling_threshold > 1)
						nm_i->journaling_threshold--;
					if (cm_i->nr_nat_journals >= NUM_NAT_JOURNALS_IN_CP)
						goto del_journal;
				}
			}
			nr_dirty_nat = 0;
			old_blk_order = new_blk_order;
		}
		if (nr_dirty_nat > nm_i->journaling_threshold)
			nm_i->journaling_threshold++;
		nr_dirty_nat++;
	}
	nm_i->journaling_threshold++;

del_journal:

	/* Delete journaling nat */
	list_for_each_safe(this, next, &nm_i->dirty_nat_entries) {
		entry = list_entry(this, struct nat_entry, list);
		if (entry->ni.flag & NAT_FLAG_JOURNAL) {
			list_del(&entry->list);
			if (entry->ni.flag & NAT_FLAG_FREE_NID) {
				kmem_cache_free(nat_entry_slab, entry);
			} else {
				INIT_LIST_HEAD(&entry->list);
				list_add_tail(&entry->list, &nm_i->nat_entries);
			}
		}
	}
}

struct hmfs_nat_node *flush_nat_entries(struct hmfs_sb_info *sbi,
				struct hmfs_checkpoint *hmfs_cp)
{
	struct hmfs_nat_node *old_root_node, *new_root_node;
	struct hmfs_nat_block *old_entry_block, *new_entry_block;
	struct hmfs_summary *summary;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct nat_entry *ne;
	struct page *empty_page;
	unsigned char nat_height;
	block_t old_blk_order, new_blk_order = 0, _ofs;
	block_t new_nat_root_addr;

	if (list_empty(&nm_i->dirty_nat_entries)) {
		return cm_i->last_cp_i->nat_root;
	}
	empty_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!empty_page) {
		return ERR_PTR(-ENOMEM);
	}
	new_entry_block = kmap(empty_page);	

	/* FIXME : no space */

	/* do real NAT flush */
	nat_height = sbi->nat_height;
	new_root_node = old_root_node = CM_I(sbi)->last_cp_i->nat_root;

	lock_write_nat(nm_i);

	flush_nat_journals(sbi, hmfs_cp);

	/* All nat entries have been written in journals */
	if (list_empty(&nm_i->dirty_nat_entries)) {
		new_root_node = cm_i->last_cp_i->nat_root;
		goto out;
	}

	ne = list_entry(nm_i->dirty_nat_entries.next, struct nat_entry, list);
	old_blk_order = (ne->ni.nid) >> LOG2_NAT_ENTRY_PER_BLOCK;
	unlock_write_nat(nm_i);
	old_entry_block = get_nat_entry_block(sbi, CM_I(sbi)->last_cp_i->version, 
							ne->ni.nid);
	lock_write_nat(nm_i);

	if (old_entry_block)
		hmfs_memcpy(new_entry_block, old_entry_block, HMFS_BLOCK_SIZE[SEG_NODE_INDEX]);

	list_for_each_entry_from(ne, &nm_i->dirty_nat_entries, list) {
		new_blk_order = (ne->ni.nid) / NAT_ENTRY_PER_BLOCK;

		if (new_blk_order != old_blk_order) {
			/*
			 * It's safe to unlock write to nat. Because fs have
			 * obtained all mutex_lock_op. And there'is only read operation
			 * in fs. The structure of list would not be changed
			 */
			unlock_write_nat(nm_i);
			
			/* one page done, flush it */
			new_nat_root_addr = __flush_nat_entries(sbi, 
										old_root_node, new_root_node, 
										old_blk_order, nat_height, 
										new_entry_block, 0);
			if (new_nat_root_addr != 0) {
				/* root node not be COWed */
				new_root_node = ADDR(sbi, new_nat_root_addr);
			}
			old_blk_order = new_blk_order;
			
			old_entry_block = get_nat_entry_block(sbi, CM_I(sbi)->last_cp_i->version,
					     			old_blk_order * NAT_ENTRY_PER_BLOCK);

			if (old_entry_block) {
				memcpy(new_entry_block, old_entry_block, HMFS_BLOCK_SIZE[SEG_NODE_INDEX]);
			} else {
				memset_nt(new_entry_block, 0, HMFS_BLOCK_SIZE[SEG_NODE_INDEX]);
			}
			lock_write_nat(nm_i);
		}

		/* add the entry to the page */
		_ofs = NID_TO_BLOCK_OFS(ne->ni.nid);
		node_info_to_raw_nat(&ne->ni, &new_entry_block->entries[_ofs]);
	}

	/* the last one page done, flush it */
	unlock_write_nat(nm_i);
	new_nat_root_addr = __flush_nat_entries(sbi, old_root_node,
				   new_root_node, new_blk_order, nat_height,
				   new_entry_block, 0);
	lock_write_nat(nm_i);
	if (new_nat_root_addr != NULL_ADDR) {
		// root node COWed
		new_root_node = ADDR(sbi, new_nat_root_addr);
	}

	hmfs_bug_on(sbi,new_root_node==NULL || new_root_node == old_root_node);
	new_nat_root_addr = L_ADDR(sbi, new_root_node);
	summary = get_summary_by_addr(sbi, new_nat_root_addr);
	make_summary_entry(summary, 0, cm_i->new_version, 0, SUM_TYPE_NATN);

out:
	clean_dirty_nat_entries(sbi);

	unlock_write_nat(nm_i);

	kunmap(empty_page);
	__free_page(empty_page);
	return new_root_node;
}

void mark_block_valid_type(struct hmfs_sb_info *sbi, block_t addr)
{
	struct hmfs_summary *summary;
	int type;
	int i;

	summary = get_summary_by_addr(sbi, addr);
	type = get_summary_type(summary);
	set_summary_valid_bit(summary);

	if (type == SUM_TYPE_DN) {
		struct direct_node *dn = ADDR(sbi, addr);

		for (i = 0; i < ADDRS_PER_BLOCK; i++) {
			addr = le64_to_cpu(dn->addr[i]);
			if (addr) {
				summary = get_summary_by_addr(sbi, addr);
				set_summary_valid_bit(summary);
			}
		}
	} else if (type == SUM_TYPE_INODE) {
		struct hmfs_inode *hi = ADDR(sbi, addr);
		unsigned long flag;

		flag = le32_to_cpu(hi->i_flags);
		if (test_bit(FI_INLINE_DATA, &flag))
			return;

		for (i = 0; i < NORMAL_ADDRS_PER_INODE; i++) {
			addr = le64_to_cpu(hi->i_addr[i]);
			if (addr) {
				summary = get_summary_by_addr(sbi, addr);
				set_summary_valid_bit(summary);
			}
		}
	}
}

static void __mark_block_valid(struct hmfs_sb_info *sbi,	 
				struct hmfs_nat_node *cur_nat_node, unsigned int blk_order,
				unsigned int version, u8 height)
{
	//FIXME : cannot handle no NVM space for nat tree
	struct hmfs_nat_node *cur_child_node = NULL;
	struct hmfs_nat_block *nat_entry_blk = NULL;
	struct hmfs_summary *raw_summary;
	block_t cur_node_addr, child_node_addr;
	unsigned int i, new_blk_order, _ofs;

	BUG_ON(!cur_nat_node);
	cur_node_addr = L_ADDR(sbi, cur_nat_node);
	raw_summary = get_summary_by_addr(sbi, cur_node_addr);
	if (get_summary_start_version(raw_summary) != version) {
		//not this version created
		return;
	}

	//leaf, alloc & copy nat entry block 
	if (!height) {
		hmfs_bug_on(sbi, get_summary_type(raw_summary) != SUM_TYPE_NATD);
		nat_entry_blk = HMFS_NAT_BLOCK(cur_nat_node); 
		for (i = 0; i < NAT_ENTRY_PER_BLOCK; i++) {
			if (!nat_entry_blk->entries[i].ino)
				continue;
			child_node_addr = le64_to_cpu(nat_entry_blk->entries[i].block_addr);
			if (child_node_addr)
				mark_block_valid_type(sbi, child_node_addr);
		}
		return;
	} else
		set_summary_valid_bit(raw_summary);

	//go to child
	new_blk_order = blk_order & ((1 << ((height - 1) *
			LOG2_NAT_ADDRS_PER_NODE)) - 1);

	for (i = 0; i < NAT_ADDR_PER_NODE; i++) {
		child_node_addr = le64_to_cpu(cur_nat_node->addr[i]);
		if(child_node_addr) {
			_ofs = (i << ((height-1) * LOG2_NAT_ADDRS_PER_NODE)) +
					new_blk_order;
			cur_child_node = ADDR(sbi, child_node_addr);
			__mark_block_valid(sbi, cur_child_node, _ofs, version ,
					height-1); 
		}
	}
}

void mark_block_valid(struct hmfs_sb_info *sbi, struct hmfs_nat_node *nat_root,
				struct hmfs_checkpoint *hmfs_cp)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct hmfs_nat_journal *nat_journal;
	int i;
	nid_t nid;
	block_t blk_addr;
	int nr_nat_journals;
	ver_t sto_version;

	nat_journal = hmfs_cp->nat_journals;
	if (sbi->recovery_doing) {
		nr_nat_journals = NUM_NAT_JOURNALS_IN_CP;
		sto_version = le32_to_cpu(hmfs_cp->checkpoint_ver);
	} else {
		nr_nat_journals = cm_i->nr_nat_journals;
		sto_version = CM_I(sbi)->new_version;
	}

	for (i = 0; i < nr_nat_journals; ++i, nat_journal++) {
		nid = le32_to_cpu(nat_journal->nid);
		blk_addr = le64_to_cpu(nat_journal->entry.block_addr);
		if (nid >= HMFS_ROOT_INO && blk_addr != NULL_ADDR) {
			mark_block_valid_type(sbi, blk_addr);
		
			if (sbi->recovery_doing) {
				cm_i->nr_nat_journals = i + 1;
			}
		}
	}

	__mark_block_valid(sbi, nat_root, 0, sto_version, 
			sbi->nat_height);
}
