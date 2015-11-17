#include <linux/fs.h>
#include <linux/types.h>
#include "hmfs.h"
#include "hmfs_fs.h"
#include "node.h"

static struct kmem_cache *nat_entry_slab;

const struct address_space_operations hmfs_nat_aops;

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
	struct hmfs_nm_info *info = NM_I(sbi);
	kfree(info->free_nids);
	kfree(info);
}

static int init_node_manager(struct hmfs_sb_info *sbi)
{
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct checkpoint_info *cp_i = cm_i->last_cp_i;
	struct hmfs_checkpoint *cp = cp_i->cp;

	nm_i->max_nid = hmfs_max_nid(sbi);
	nm_i->nat_cnt = 0;
	nm_i->free_nids = kzalloc(HMFS_PAGE_SIZE * 2, GFP_KERNEL);
	nm_i->next_scan_nid = le32_to_cpu(cp->next_scan_nid);
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
	spin_unlock(&nm_i->free_nid_list_lock);
	mutex_unlock(&nm_i->build_lock);
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

/*
 * when truncate an inode, we should call setup_summary_of_delete_node
 * after this function
 */
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

	dec_valid_node_count(sbi, dn->inode, 1);
	update_nat_entry(nm_i, dn->nid, dn->inode->i_ino, NULL_ADDR,
			 CM_I(sbi)->new_version, true);

	/*
	 * ????
	 */
	if (dn->nid == dn->inode->i_ino) {
		remove_orphan_inode(sbi, dn->nid);
		dec_valid_inode_count(sbi);
	} else {
		mark_inode_dirty(dn->inode);
	}
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

	hn = alloc_new_node(sbi, dn->nid, dn->inode, SUM_TYPE_IDN);
	if (IS_ERR(hn))
		return PTR_ERR(hn);

	if (depth < 3) {
		for (i = ofs; i < NIDS_PER_BLOCK; i++, freed++) {
			child_nid = le32_to_cpu(hn->in.nid[i]);
			if (child_nid == 0)
				continue;
			rdn.nid = child_nid;
			rdn.inode = dn->inode;

			/* 
			 * Now we just decrease count of child, and count of this node
			 * would be decreased by its father node. And we should call
			 * this function before another truncate_xxx()
			 */
			ret = get_node_info(sbi, rdn.nid, &ni);
			if (ret)
				continue;

			ret = truncate_dnode(&rdn);
			if (ret < 0)
				goto out_err;
			set_nid(hn, i, 0, false);
			setup_summary_of_delete_node(sbi, ni.blk_addr);
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

			/* 
			 * Now we just decrease count of child, and count of this node
			 * would be decreased by its father node. And we should call
			 * this function before another truncate_xxx()
			 */
			ret = get_node_info(sbi, rdn.nid, &ni);
			if (ret)
				continue;

			ret = truncate_nodes(&rdn, child_nofs, 0, depth - 1);
			if (ret == (NIDS_PER_BLOCK + 1)) {
				set_nid(hn, i, 0, false);
				setup_summary_of_delete_node(sbi, ni.blk_addr);
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

	hmfs_bug_on(sbi, cp_i->version == CM_I(sbi)->new_version);

	nat_entry = get_nat_entry(sbi, cp_i->version, nid);
	if (!nat_entry)
		return NULL;
	node_addr = le64_to_cpu(nat_entry->block_addr);

	return (struct hmfs_node *)ADDR(sbi, node_addr);
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
		nodes[idx] =
		 alloc_new_node(sbi, nid[idx], dn->inode, SUM_TYPE_IDN);
		if (IS_ERR(nodes[idx])) {
			err = PTR_ERR(nodes[idx]);
			goto fail;
		}
		setup_summary_of_delete_node(sbi, ni.blk_addr);
		set_nid(nodes[idx], i, 0, false);
	}

	/* FIXME: should skip check in truncate_inode_blocks? */
	if (offset[depth - 1] == 0) {
		dn->nid = nid[idx];
		truncate_node(dn);
	}

	offset[idx]++;
	offset[depth - 1] = 0;
fail:
	return err;
}

void setup_summary_of_delete_node(struct hmfs_sb_info *sbi, block_t blk_addr)
{
	struct hmfs_summary *sum;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	int count;

	sum = get_summary_by_addr(sbi, blk_addr);
	count = get_summary_count(sum) - 1;

	hmfs_bug_on(sbi, count < 0);

	set_summary_count(sum, count);

	if (!count) {
		set_summary_dead_version(sum, cm_i->new_version);
		invalidate_block_after_dc(sbi, blk_addr);
	}
}

int truncate_inode_blocks(struct inode *inode, pgoff_t from)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	int err = 0, cont = 1;
	int level, offset[4], noffset[4];
	unsigned int nofs = 0;
	struct hmfs_node *hn;
	struct dnode_of_data dn;
	struct node_info ni;

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
		err = get_node_info(sbi, dn.nid, &ni);

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
			hn = alloc_new_node(sbi, inode->i_ino, inode, SUM_TYPE_INODE);
			if (IS_ERR(hn)) {
				err = PTR_ERR(hn);
				goto fail;
			}
			setup_summary_of_delete_node(sbi, ni.blk_addr);
			hn->i.i_nid[offset[0] - NODE_DIR1_BLOCK] = 0;
		}
		offset[1] = 0;
		offset[0]++;
		nofs += err;
	}
fail:
	return err > 0 ? 0 : err;
}

void update_nat_entry(struct hmfs_nm_info *nm_i, nid_t nid, nid_t ino,
		      block_t blk_addr, ver_t version, bool dirty)
{
	struct nat_entry *e, *le;
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
	write_unlock(&nm_i->nat_tree_lock);
}

static inline unsigned long cal_page_addr(struct hmfs_sb_info *sbi,
					  seg_t cur_node_segno,
					  unsigned int cur_node_blkoff)
{
	return (cur_node_segno << HMFS_SEGMENT_SIZE_BITS)
	 + (cur_node_blkoff << HMFS_PAGE_SIZE_BITS) + sbi->main_addr_start;
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
	else if (ni.blk_addr == NEW_ADDR) {
		return ERR_PTR(-EINVAL);
	}
	return ADDR(sbi, ni.blk_addr);
}

static void alloc_direct_node_success(struct hmfs_sb_info *sbi,
				      struct direct_node *dn)
{
	int i;
	block_t blk_addr;
	struct hmfs_summary *summary;

	for (i = 0; i < ADDRS_PER_BLOCK; i++) {
		if (dn->addr[i]) {
			blk_addr = le64_to_cpu(dn->addr[i]);
			summary = get_summary_by_addr(sbi, blk_addr);
			inc_summary_count(summary);
		}
	}
}

static void alloc_indirect_node_success(struct hmfs_sb_info *sbi,
					struct indirect_node *idn)
{
	int i, ret;
	struct hmfs_summary *summary;
	nid_t nid;
	struct node_info ni;

	for (i = 0; i < NIDS_PER_BLOCK; i++) {
		if (idn->nid[i]) {
			nid = le32_to_cpu(idn->nid[i]);
			ret = get_node_info(sbi, nid, &ni);
			if (!ret)
				continue;

			summary = get_summary_by_addr(sbi, ni.blk_addr);
			inc_summary_count(summary);
		}
	}
}

static void alloc_inode_success(struct hmfs_sb_info *sbi, struct hmfs_inode *hi)
{
	int i, ret;
	struct hmfs_summary *summary;
	nid_t nid;
	struct node_info ni;
	for (i = 0; i < NORMAL_ADDRS_PER_INODE; ++i) {
		if (hi->i_addr[i]) {
			ni.blk_addr = le64_to_cpu(hi->i_addr[i]);
			summary = get_summary_by_addr(sbi, ni.blk_addr);
			inc_summary_count(summary);
		}
	}
	for (i = NODE_DIR1_BLOCK; i < NODE_DIND_BLOCK; ++i) {
		nid = le32_to_cpu(hi->i_nid[i - NODE_DIR1_BLOCK]);
		if (nid) {
			ret = get_node_info(sbi, nid, &ni);
			if (!ret)
				continue;

			summary = get_summary_by_addr(sbi, ni.blk_addr);
			inc_summary_count(summary);
		}
	}
}

/*
 * Call this function when allocating a new node successfully
 * for direct node, indirect node, inode, nat node and nat block
 */
void alloc_new_node_success(struct hmfs_sb_info *sbi, void *new_node, int type)
{
	switch (type) {
	case SUM_TYPE_DN:
		alloc_direct_node_success(sbi, new_node);
		break;
	case SUM_TYPE_IDN:
		alloc_indirect_node_success(sbi, new_node);
		break;
	case SUM_TYPE_INODE:
		alloc_inode_success(sbi, new_node);
		break;
	case SUM_TYPE_NATN:
	case SUM_TYPE_NATD:
	default:
		hmfs_bug_on(sbi, 1);
	}
}

static void setup_summary_of_new_node(struct hmfs_sb_info *sbi,
				      block_t new_node_addr, block_t src_addr,
				      nid_t ino, unsigned int ofs_in_node,
				      char sum_type)
{
	struct hmfs_summary *src_sum, *dest_sum;
	struct hmfs_cm_info *cm_i = CM_I(sbi);

	dest_sum = get_summary_by_addr(sbi, new_node_addr);
	make_summary_entry(dest_sum, ino, cm_i->new_version, 1, ofs_in_node,
			   sum_type);
	alloc_new_node_success(sbi, ADDR(sbi, new_node_addr), sum_type);

	/* Now we could set dead_version of source node  */
	if (src_addr) {
		src_sum = get_summary_by_addr(sbi, src_addr);
		set_summary_dead_version(src_sum, cm_i->new_version);
	}
}

static struct hmfs_node *__alloc_new_node(struct hmfs_sb_info *sbi, nid_t nid,
					  struct inode *inode, char sum_type)
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
		if (get_summary_start_version(summary) == cp_i->version)
			return src;
	} else
		src_addr = 0;

	if (!inc_valid_node_count(sbi, inode, 1))
		return ERR_PTR(-ENOSPC);

	if (is_inode_flag_set(HMFS_I(inode), FI_NO_ALLOC))
		return ERR_PTR(-EPERM);

	blk_addr = alloc_free_node_block(sbi);
	dest = ADDR(sbi, blk_addr);
	if (!IS_ERR(src)) {
		hmfs_memcpy(dest, src, HMFS_PAGE_SIZE);
	} else {
		memset_nt(dest, 0, HMFS_PAGE_SIZE - sizeof(struct node_footer));
		dest->footer.ino = cpu_to_le32(inode->i_ino);
		dest->footer.nid = cpu_to_le32(nid);
		dest->footer.cp_ver = cpu_to_le32(cp_i->version);
	}

	setup_summary_of_new_node(sbi, blk_addr, src_addr, inode->i_ino,
				  ofs_in_node, sum_type);
	update_nat_entry(nm_i, nid, inode->i_ino, blk_addr, cp_i->version,
			 true);
	return dest;
}

void *alloc_new_node(struct hmfs_sb_info *sbi, nid_t nid, struct inode *inode,
		     char sum_type)
{
	block_t addr;

	if (likely(inode))
		return __alloc_new_node(sbi, nid, inode, sum_type);

	if (sum_type == SUM_TYPE_NATD || sum_type == SUM_TYPE_NATN) {
		if (!inc_valid_node_count(sbi, NULL, 1))
			return ERR_PTR(-ENOSPC);
		addr = alloc_free_node_block(sbi);
		return ADDR(sbi, addr);
	}

	if (!inc_gc_block_count(sbi, CURSEG_NODE))
		return ERR_PTR(-ENOSPC);
	sbi = HMFS_I_SB(inode);
	addr = alloc_free_node_block(sbi);
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
		read_lock(&nm_i->nat_tree_lock);
		ni->ino = e->ni.ino;
		ni->blk_addr = e->ni.blk_addr;
		ni->version = e->ni.version;
		read_unlock(&nm_i->nat_tree_lock);
		return 0;
	}

	/* search in main area */
	ne_local = get_nat_entry(sbi, CM_I(sbi)->last_cp_i->version, nid);
	if (ne_local == NULL)
		return -ENODATA;
	node_info_from_raw_nat(ni, ne_local);

	update_nat_entry(nm_i, nid, ni->ino, ni->blk_addr, ni->version, false);
	return 0;
}

static void add_free_nid(struct hmfs_nm_info *nm_i, nid_t nid, u64 free,
			 int *pos)
{
	spin_lock(&nm_i->free_nid_list_lock);
	nm_i->free_nids[*pos].nid = make_free_nid(nid, free);
	spin_unlock(&nm_i->free_nid_list_lock);
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

	mutex_lock(&nm_i->build_lock);
	read_lock(&cm_i->journal_lock);
	
	for (i = 0; i < NUM_NAT_JOURNALS_IN_CP; ++i) {
		nid = le32_to_cpu(hmfs_cp->nat_journals[i].nid);
		blk_addr = le64_to_cpu(hmfs_cp->nat_journals[i].entry.block_addr);
		if (blk_addr == NULL_ADDR && nid > HMFS_ROOT_INO) {
			add_free_nid(nm_i, nid, 1, &pos);
			pos++;
		}
		if (nid > HMFS_ROOT_INO)
			cm_i->nr_nat_journals = i + 1;
	}

	read_unlock(&cm_i->journal_lock);
	mutex_unlock(&nm_i->build_lock);
	
	spin_lock(&nm_i->free_nid_list_lock);
	nm_i->fcnt = pos;
	spin_unlock(&nm_i->free_nid_list_lock);
}

/* Check whether block_addr of nid in journal is NULL_ADDR */
static int is_valid_free_nid(struct hmfs_sb_info *sbi, nid_t nid)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct hmfs_checkpoint *hmfs_cp = cm_i->last_cp_i->cp;
	int i;
	nid_t local_nid;

	read_lock(&cm_i->journal_lock);
	for (i = 0; i < cm_i->nr_nat_journals; ++i) {
		local_nid = le32_to_cpu(hmfs_cp->nat_journals[i].nid);
		if (local_nid == nid)
			return 0;
	}
	read_unlock(&cm_i->journal_lock);

	return nid > HMFS_ROOT_INO;
}

static nid_t scan_nat_block(struct hmfs_sb_info *sbi,
			    struct hmfs_nat_block *nat_blk, nid_t start_nid,
			    int *pos)
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

static int build_free_nids(struct hmfs_sb_info *sbi)
{
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct hmfs_nat_block *nat_block = NULL;
	nid_t nid = nm_i->next_scan_nid;
	int pos = BUILD_FREE_NID_COUNT - 1;
	int count;

	if (nm_i->fcnt >= BUILD_FREE_NID_COUNT)
		return nm_i->fcnt;

	hmfs_bug_on(sbi, nm_i->fcnt != 0);

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
	}

	nm_i->next_scan_nid = nid;
	return count;
}

bool alloc_nid(struct hmfs_sb_info * sbi, nid_t * nid)
{
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	int num;

retry:
	if (cm_i->valid_node_count + 1 >= nm_i->max_nid)
		return false;

	spin_lock(&nm_i->free_nid_list_lock);

	if (nm_i->fcnt > 0) {
		*nid = get_free_nid(nm_i->free_nids[nm_i->fcnt - 1].nid);
		nm_i->fcnt--;
		spin_unlock(&nm_i->free_nid_list_lock);
		return true;
	}
	spin_unlock(&nm_i->free_nid_list_lock);

	mutex_lock(&nm_i->build_lock);
	num = build_free_nids(sbi);
	spin_lock(&nm_i->free_nid_list_lock);
	nm_i->fcnt = num;
	spin_unlock(&nm_i->free_nid_list_lock);
	mutex_unlock(&nm_i->build_lock);
	goto retry;
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

/* get a nat/nat page from nat/nat in-NVM tree */
static void *__get_nat_page(struct hmfs_sb_info *sbi,
			    block_t cur_node_addr,
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
	struct checkpoint_info *cp_i = get_checkpoint_info(sbi, version);
	unsigned int blk_id = nid / NAT_ENTRY_PER_BLOCK;
	struct hmfs_nat_node *nat_root = cp_i->nat_root;
	char nat_height = sbi->nat_height;

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
	struct checkpoint_info *cp_i = get_checkpoint_info(sbi, version);
	struct hmfs_nat_node *nat_root = cp_i->nat_root;
	unsigned int height = 0, block_id;

	height = GET_NAT_NODE_HEIGHT(index);
	block_id = GET_NAT_NODE_OFS(index);

	return __get_nat_page(sbi, L_ADDR(sbi, nat_root), block_id, height);
}

static block_t recursive_flush_nat_pages(struct hmfs_sb_info *sbi,
					 struct hmfs_nat_node *old_nat_node,
					 struct hmfs_nat_node *cur_nat_node,
					 unsigned int blk_order, u8 height,
					 void *nat_entry_page,
					 unsigned short *alloc_cnt)
{
	//FIXME : cannot handle no NVM space for nat tree
	struct hmfs_nat_node *cur_stored_node, *old_child_node = NULL,
	 *cur_child_node = NULL;
	block_t old_nat_addr, cur_stored_addr, child_stored_addr, _addr,
	 child_node_addr;
	unsigned int i, cur_version, _ofs, new_blk_order;
	nid_t nid;
	struct hmfs_summary *raw_summary;
	unsigned char blk_type;

	//preparation for summary update
	nid = MAKE_NAT_NODE_NID(height, blk_order);
	cur_version = CM_I(sbi)->new_version;
	blk_type = ((height == 1) ? SUM_TYPE_NATD : SUM_TYPE_NATN);

	//leaf, alloc & copy nat info block 
	if (!height) {
		cur_stored_node = alloc_new_node(sbi, nid, NULL, SUM_TYPE_NATD);
		cur_stored_addr = L_ADDR(sbi, cur_stored_node);

		hmfs_bug_on(sbi, IS_ERR(cur_stored_node) || !cur_stored_node);
		hmfs_bug_on(sbi, !nat_entry_page);

		hmfs_memcpy(cur_stored_node, nat_entry_page, HMFS_PAGE_SIZE);
		(*alloc_cnt) += 1;
		if (old_nat_node != NULL) {
			//set old entry block as dead
			old_nat_addr = L_ADDR(sbi, old_nat_node);
			raw_summary = get_summary_by_addr(sbi, old_nat_addr);
			set_summary_dead_version(raw_summary, cur_version);
		}
		return cur_stored_addr;
	}

	cur_stored_node = cur_nat_node;
	cur_stored_addr = NULL_ADDR;

	if (cur_nat_node == NULL) {
		//only allocate new node_blk
		cur_stored_node = alloc_new_node(sbi, nid, NULL, SUM_TYPE_NATN);
		cur_stored_addr = L_ADDR(sbi, cur_stored_node);
		memset_nt(cur_stored_node, 0, HMFS_PAGE_SIZE);
		(*alloc_cnt) += 1;
	} else if (old_nat_node == cur_nat_node) {
		//this node is not wandered before, COW
		cur_stored_node = alloc_new_node(sbi, nid, NULL, SUM_TYPE_NATN);
		cur_stored_addr = L_ADDR(sbi, cur_stored_node);
		hmfs_bug_on(sbi, IS_ERR(cur_stored_node) || !cur_stored_node);
		hmfs_memcpy(cur_stored_node, old_nat_node, HMFS_PAGE_SIZE);
		(*alloc_cnt) += 1;
		//set old node as dead
		old_nat_addr = L_ADDR(sbi, old_nat_node);
		raw_summary = get_summary_by_addr(sbi, old_nat_addr);
		set_summary_dead_version(raw_summary, cur_version);
	}
	//go to child
	_ofs = blk_order >> ((height - 1) * LOG2_NAT_ADDRS_PER_NODE);
	new_blk_order = blk_order & ((1 << _ofs) - 1);

	if (old_nat_node != NULL) {
		child_node_addr = le64_to_cpu(old_nat_node->addr[blk_order >> _ofs]);
		if (child_node_addr)
			old_child_node = ADDR(sbi, child_node_addr);
		else
			old_child_node = NULL;
	}
	if (cur_stored_node != NULL) {
		child_node_addr =
		 le64_to_cpu(cur_stored_node->addr[blk_order >> _ofs]);
		if (child_node_addr)
			cur_child_node = ADDR(sbi, child_node_addr);
		else
			cur_child_node = NULL;
	}
	child_stored_addr = recursive_flush_nat_pages(sbi, old_child_node,
						      cur_child_node, new_blk_order, height - 1,
						      nat_entry_page, alloc_cnt);

	if (child_stored_addr) {
		cur_stored_node->addr[_ofs] = cpu_to_le64(child_stored_addr);	//change addr to new block

		for (i = 0; i < NAT_ADDR_PER_NODE; i++) {
			_addr = cur_stored_node->addr[i];
			if (_addr == NULL_ADDR) {
				//block no allocated yet
				continue;
			}
			raw_summary = get_summary_by_addr(sbi, _addr);
			if (i == _ofs) {
				//this entry COWed
				printk(KERN_INFO"%s: h-t %d:%d\n", __FUNCTION__, height, blk_type);
				make_summary_entry(raw_summary, nid,
						   cur_version, 1, i, blk_type);
			} else if (old_nat_node != NULL
				   && old_nat_node == cur_nat_node) {
				//brother COWed
				inc_summary_count(raw_summary);
			}
		}
	}
	return cur_stored_addr;
}

static inline void clean_dirty_nat_entries(struct hmfs_sb_info *sbi) 
{
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct nat_entry *ne;
	struct list_head *head, *this, *next;
	
	head = &nm_i->dirty_nat_entries;
	list_for_each_safe(this, next, head) {
		ne = list_entry(this, struct nat_entry, list);
		list_del(&ne->list);
		INIT_LIST_HEAD(&ne->list);
		list_add_tail(&ne->list, &nm_i->nat_entries);
	}
}

static void cache_nat_journals_entries(struct hmfs_sb_info *sbi)
{
	struct hmfs_checkpoint *hmfs_cp = CM_I(sbi)->last_cp_i->cp;
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct hmfs_nat_journal *ne;
	nid_t nid, ino;
	block_t blk_addr;
	int i;
	unsigned int version = CM_I(sbi)->new_version;

	read_lock(&CM_I(sbi)->journal_lock);
	for (i = 0; i < NUM_NAT_JOURNALS_IN_CP; ++i) {
		ne = &hmfs_cp->nat_journals[i];
		nid = le32_to_cpu(ne->nid);
		ino = le32_to_cpu(ne->entry.ino);
		blk_addr = le64_to_cpu(ne->entry.block_addr);
		
		if (ino >= HMFS_ROOT_INO && blk_addr != NULL_ADDR)
			update_nat_entry(nm_i, nid, ino, blk_addr, version, true);
	}
	read_unlock(&CM_I(sbi)->journal_lock);
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

struct hmfs_nat_node *flush_nat_entries(struct hmfs_sb_info *sbi)
{
	struct hmfs_nat_node *old_root_node, *new_root_node;
	struct hmfs_nat_block *old_entry_block, *new_entry_block;
	struct hmfs_summary *summary;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	block_t new_nat_root_addr;
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct nat_entry *ne;
	struct page *empty_page;
	unsigned short alloc_cnt;
	unsigned char nat_height;
	block_t old_blk_order, new_blk_order = 0, _ofs;

	if (list_empty(&nm_i->dirty_nat_entries)) {
		hmfs_bug_on(sbi, 1);
		return NULL;
	}
	empty_page = alloc_page(GFP_KERNEL|__GFP_ZERO);
	if (!empty_page) {
		return ERR_PTR(-ENOMEM);
	}
	new_entry_block = kmap(empty_page);	

	nat_height = sbi->nat_height;
	alloc_cnt = 0;
	new_root_node = old_root_node = CM_I(sbi)->last_cp_i->nat_root;

	write_lock(&nm_i->nat_tree_lock);

	//init first page
	ne = list_entry(nm_i->dirty_nat_entries.next, struct nat_entry, list);
	old_blk_order = (ne->ni.nid) >> LOG2_NAT_ENTRY_PER_BLOCK;
	old_entry_block = get_nat_entry_block(sbi, CM_I(sbi)->last_cp_i->version, 
					ne->ni.nid);
	if(old_entry_block)
		hmfs_memcpy(new_entry_block, old_entry_block, HMFS_PAGE_SIZE);

	/* FIXME :
	 * 1) no space
	 */
	list_for_each_entry_from(ne, &nm_i->dirty_nat_entries, list) {
		new_blk_order = (ne->ni.nid) >> LOG2_NAT_ENTRY_PER_BLOCK;
		if (new_blk_order != old_blk_order) {
			// one page done, flush it
			new_nat_root_addr = recursive_flush_nat_pages(sbi, 
							old_root_node, new_root_node, old_blk_order, 
							nat_height, new_entry_block, &alloc_cnt);
			if (new_nat_root_addr != 0) {
				// root node not COWed
				new_root_node = ADDR(sbi, new_nat_root_addr);
			}
			old_blk_order = new_blk_order;
			old_entry_block = get_nat_entry_block(sbi, CM_I(sbi)->last_cp_i->version ,
					     old_blk_order * NAT_ENTRY_PER_BLOCK);
			if(old_entry_block){
				memcpy(new_entry_block, old_entry_block, HMFS_PAGE_SIZE);
			} else {
				memset_nt(new_entry_block, 0, HMFS_PAGE_SIZE);
			}
		}
		//add a entry to a page
		_ofs = (ne->ni.nid) % LOG2_NAT_ENTRY_PER_BLOCK;
		node_info_to_raw_nat(&ne->ni, &new_entry_block->entries[_ofs]);
	}

	// one page done, flush it
	new_nat_root_addr = recursive_flush_nat_pages(sbi, old_root_node,
				   new_root_node, new_blk_order, nat_height,
				   new_entry_block, &alloc_cnt);
	if (new_nat_root_addr != NULL_ADDR) {
		// root node COWed
		new_root_node = ADDR(sbi, new_nat_root_addr);
	}

	BUG_ON( new_root_node==NULL || new_root_node == old_root_node);
	new_nat_root_addr = L_ADDR(sbi, new_root_node);
	printk("%s: new nat tree, root %p\n", __FUNCTION__, (void *)new_nat_root_addr);
	summary = get_summary_by_addr(sbi, new_nat_root_addr);
	make_summary_entry(summary, 0, cm_i->new_version, 1, 0, SUM_TYPE_NATN);

	clean_dirty_nat_entries(sbi);

	write_unlock(&nm_i->nat_tree_lock);

	kunmap(empty_page);
	__free_page(empty_page);
	return new_root_node;
}
