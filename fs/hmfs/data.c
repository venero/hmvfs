#include "hmfs.h"
#include "node.h"
#include "segment.h"

/*
 * return the last block index in current node/inode
 */
static int get_end_blk_index(int block, int level)
{
	int start_blk;

	if (level) {
		start_blk = (block - NORMAL_ADDRS_PER_INODE) % ADDRS_PER_BLOCK;
		start_blk = block - start_blk;
		return start_blk + ADDRS_PER_BLOCK - 1;
	}
	return NORMAL_ADDRS_PER_INODE - 1;
}

static bool inc_valid_block_count(struct hmfs_sb_info *sbi,
				struct inode *inode, int count)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	pgc_t alloc_block_count;
	pgc_t free_blocks = free_user_blocks(sbi);

	lock_cm(cm_i);
	alloc_block_count = cm_i->alloc_block_count + count;

	if (unlikely(!free_blocks && count > 0)) {
		unlock_cm(cm_i);
		return false;
	}
	if (inode)
		inode->i_blocks += count;

	cm_i->alloc_block_count = alloc_block_count;
	cm_i->valid_block_count += count;
	unlock_cm(cm_i);
	return true;
}

/*
 *	Return the direct node of specified data block(index th)
 *	@offset[i]: is a path to direct node, i.e. the address in @offset[i] slots
 *			of indirect/dindirect node is next node to find direct node
 *	@noffset[i]: is the node offset of the node in the path. For example, noffset
 *			of inode is 0, noffset of hmfs_inode->nid[0] is 1.
 *	@index: index of data block. In this function, we want to find the direct node
 *			of this data block.
 *	@mode: ALLOC_NODE and LOOKUP_NODE.
 *			-ALLOC_NODE: If node in the path is not exist, create it
 *			-LOOKUP_NODE: If not exist, stop.
 */
int get_dnode_of_data(struct dnode_of_data *dn, int index, int mode)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(dn->inode);
	void *blocks[4];
	void *parent;
	nid_t nid[4];
	int offset[4];
	unsigned int noffset[4];
	int level, i;
	int err = 0;
	char sum_type;

	level = get_node_path(index, offset, noffset);

	nid[0] = dn->inode->i_ino;
	blocks[0] = dn->inode_block;
	if (!blocks[0]) {
		blocks[0] = get_node(sbi, nid[0]);
		if (IS_ERR(blocks[0]))
			return PTR_ERR(blocks[0]);
		dn->inode_block = blocks[0];
	}
	parent = blocks[0];
	if (level != 0) {
		nid[1] = get_nid(parent, offset[0], true);
	}

	for (i = 1; i <= level; ++i) {
		if (!nid[i] && mode == ALLOC_NODE) {
			if (!alloc_nid(sbi, &(nid[i]))) {
				err = -ENOSPC;
				goto out;
			}
			dn->nid = nid[i];
			sum_type = i == level ? SUM_TYPE_DN : SUM_TYPE_IDN;
			hmfs_bug_on(sbi, !IS_ERR(get_node(sbi, nid[i])));
			blocks[i] = alloc_new_node(sbi, nid[i], dn->inode, sum_type, false);
			if (IS_ERR(blocks[i])) {
				err = PTR_ERR(blocks[i]);
				goto out;
			}

			if (i == 1) {
				blocks[0] = alloc_new_node(sbi, nid[0], dn->inode,
									SUM_TYPE_INODE, false);

				if (IS_ERR(blocks[i])) {
					err = PTR_ERR(blocks[i]);
					goto out;
				}

				parent = blocks[0];
			}
			set_nid(parent, offset[i - 1], nid[i], i == 1);
		} else if (nid[i] && mode == LOOKUP_NODE) {
			blocks[i] = get_node(sbi, nid[i]);
			if (IS_ERR(blocks[i])) {
				err = PTR_ERR(blocks[i]);
				goto out;
			}
		} else if (nid[i]) {
			blocks[i] = get_node(sbi, nid[i]);
			if (IS_ERR(blocks[i])) {
				err = PTR_ERR(blocks[i]);
				goto out;
			}
		} else {
			return -ENODATA;
		}
		if (i < level) {
			parent = blocks[i];
			nid[i + 1] = get_nid(parent, offset[i], false);
		}
	}

	dn->nid = nid[level];
	dn->ofs_in_node = offset[level];
	dn->node_block = blocks[level];
	dn->level = level;
	return 0;
out:
	return err;
}

/**
 * get data blocks address from start(block index) to end(block index)
 * @start:		start block index to read
 * @end:		end block index(not included)
 * @blocks:		pointer buffer, data blocks address
 * @mode:		read ahead mode
 */
int get_data_blocks(struct inode *inode, int start, int end, void **blocks,
				int *size, int mode)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	struct dnode_of_data dn;
	block_t addr;
	block_t max_blk = hmfs_max_file_size() >> HMFS_PAGE_SIZE_BITS;
	int i;
	int ofs_in_node = 0;
	int end_blk_id = -1;
	int err = 0;
	bool init = true;

	set_new_dnode(&dn, inode, NULL, NULL, 0);
	for (i = start, *size = 0; i < end; ++i) {
		if (i > end_blk_id) {
			if (!init && mode == RA_DB_END) {
				return 0;
			}
			err = get_dnode_of_data(&dn, i, LOOKUP_NODE);
			if (err) {
				if (err == -ENODATA)
					goto fill_null;
				return err;
			}
			end_blk_id = get_end_blk_index(i, dn.level);
			ofs_in_node = dn.ofs_in_node;
			init = false;
		}
		if (i > max_blk)
			return -EINVAL;
		if (!dn.level) {
			hmfs_bug_on(sbi, dn.inode_block == NULL
			       || dn.inode_block->i_addr == NULL);
			addr = dn.inode_block->i_addr[ofs_in_node++];
		} else {
			hmfs_bug_on(sbi, dn.node_block == NULL
			       || dn.node_block->addr == NULL);
			addr = dn.node_block->addr[ofs_in_node++];
		}
		if (addr == NULL_ADDR) {
fill_null:		
			blocks[*size] = NULL;
			err = -ENODATA;
		} else
			blocks[*size] = ADDR(sbi, addr);
		*size = *size + 1;
	}
	return err;
}

static void setup_summary_of_new_data_block(struct hmfs_sb_info *sbi,
				block_t new_addr, unsigned int ino, unsigned int ofs_in_node)
{
	struct hmfs_summary *dest_sum;
	struct hmfs_cm_info *cm_i = CM_I(sbi);

	dest_sum = get_summary_by_addr(sbi, new_addr);
	make_summary_entry(dest_sum, ino, cm_i->new_version, ofs_in_node,
			SUM_TYPE_DATA);
}

/*
 * get a writable data block of inode, if specified block exists,
 * copy its data with range [start,start+size) to newly allocated 
 * block
 */
void *alloc_new_data_partial_block(struct inode *inode, int block, int left,
				int right, bool fill_zero)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	struct dnode_of_data dn;
	struct checkpoint_info *cp_i = CURCP_I(sbi);
	struct hmfs_node *hn = NULL;
	block_t new_addr, src_addr = 0;
	char *src = NULL, *dest;
	int err;
	struct hmfs_summary *summary = NULL;
	char sum_type;

	set_new_dnode(&dn, inode, NULL, NULL, 0);
	err = get_dnode_of_data(&dn, block, ALLOC_NODE);

	if (err)
		return ERR_PTR(err);

	if (is_inode_flag_set(HMFS_I(inode), FI_NO_ALLOC))
		return ERR_PTR(-EPERM);

	sum_type = dn.level ? SUM_TYPE_DN : SUM_TYPE_INODE;
	hn = alloc_new_node(sbi, dn.nid, inode, sum_type, false);
	if (IS_ERR(hn))
		return hn;

	if (dn.level)
		src_addr = hn->dn.addr[dn.ofs_in_node];
	else
		src_addr = hn->i.i_addr[dn.ofs_in_node];

	if (src_addr != NULL_ADDR) {
		src = ADDR(sbi, src_addr);
		summary = get_summary_by_addr(sbi, src_addr);
		if (get_summary_start_version(summary) == cp_i->version)
			return src;
	}

	if (!inc_valid_block_count(sbi, get_stat_object(inode, 
				src_addr != NULL_ADDR), 1))
		return ERR_PTR(-ENOSPC);

	new_addr = alloc_free_data_block(sbi);

	if (new_addr == NULL_ADDR) {
		inc_valid_block_count(sbi, get_stat_object(inode,
				src_addr != NULL_ADDR), -1);
		return ERR_PTR(-ENOSPC);
	}
	if (dn.level)
		hn->dn.addr[dn.ofs_in_node] = new_addr;
	else
		hn->i.i_addr[dn.ofs_in_node] = new_addr;

	dest = ADDR(sbi, new_addr);

	if (src_addr != NULL_ADDR) {
		if (left)
			hmfs_memcpy(dest, src, left);
		if (right < HMFS_PAGE_SIZE)
			hmfs_memcpy(dest + right, src + right,
					HMFS_PAGE_SIZE - right);
	} else if (fill_zero) {
		left = 0;
		right = HMFS_PAGE_SIZE;
	}

	if (fill_zero)
		memset_nt(dest + left, 0, right - left);

	setup_summary_of_new_data_block(sbi, new_addr, dn.nid,
			dn.ofs_in_node);
	return dest;
}

static void *__alloc_new_data_block(struct inode *inode, int block)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	struct dnode_of_data dn;
	struct checkpoint_info *cp_i = CURCP_I(sbi);
	struct hmfs_node *hn = NULL;
	block_t new_addr, src_addr = 0;
	void *src = NULL, *dest;
	int err;
	struct hmfs_summary *summary = NULL;
	char sum_type;

	set_new_dnode(&dn, inode, NULL, NULL, 0);
	err = get_dnode_of_data(&dn, block, ALLOC_NODE);

	if (err)
		return ERR_PTR(err);

	sum_type = dn.level ? SUM_TYPE_DN : SUM_TYPE_INODE;
	hn = alloc_new_node(sbi, dn.nid, inode, sum_type, false);
	if (IS_ERR(hn))
		return hn;

	if (dn.level)
		src_addr = hn->dn.addr[dn.ofs_in_node];
	else
		src_addr = hn->i.i_addr[dn.ofs_in_node];

	if (src_addr != NULL_ADDR) {
		src = ADDR(sbi, src_addr);
		summary = get_summary_by_addr(sbi, src_addr);
		if (get_summary_start_version(summary) == cp_i->version)
			return src;
	}

	if (is_inode_flag_set(HMFS_I(inode), FI_NO_ALLOC))
		return ERR_PTR(-EPERM);

	if (!inc_valid_block_count(sbi, get_stat_object(inode, src_addr
				!= NULL_ADDR), 1))
		return ERR_PTR(-ENOSPC);

	new_addr = alloc_free_data_block(sbi);

	if (new_addr == NULL_ADDR) {
		inc_valid_block_count(sbi, get_stat_object(inode, src_addr
				!= NULL_ADDR), -1);
		return ERR_PTR(-ENOSPC);
	}

	if (dn.level)
		hn->dn.addr[dn.ofs_in_node] = new_addr;
	else
		hn->i.i_addr[dn.ofs_in_node] = new_addr;

	dest = ADDR(sbi, new_addr);

	if (src_addr != NULL_ADDR)
		hmfs_memcpy(dest, src, HMFS_PAGE_SIZE);
	else memset_nt(dest, 0, HMFS_PAGE_SIZE);

	setup_summary_of_new_data_block(sbi, new_addr, dn.nid,
			dn.ofs_in_node);
	return dest;
}

void *alloc_new_data_block(struct hmfs_sb_info *sbi, struct inode *inode, 
				int block)
{
	block_t addr;

	if (likely(inode))
		return __alloc_new_data_block(inode, block);

	if (!inc_gc_block_count(sbi, CURSEG_DATA))
		return ERR_PTR(-ENOSPC);

	addr = alloc_free_data_block(sbi);
	return ADDR(sbi, addr);
}

/*
 * Return the extended block of inode
 * @x_tag: is the member offset base on start address of inode block
 */
void *alloc_new_x_block(struct inode *inode, int x_tag, bool need_copy)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	struct hmfs_inode *inode_block;
	__le64 tag_value;
	block_t src_addr, dst_addr;
	void *src, *dst;
	struct hmfs_summary *summary = NULL;

	inode_block = alloc_new_node(sbi, inode->i_ino, inode, SUM_TYPE_INODE, false);
	if (IS_ERR(inode_block))
		return inode_block;

	tag_value = *((__le64 *)JUMP(inode_block, x_tag));
	src_addr = le64_to_cpu(tag_value);
	src = ADDR(sbi, src_addr);
	if (src_addr != NULL_ADDR) {
		summary = get_summary_by_addr(sbi, src_addr);
		if (get_summary_start_version(summary) == CURCP_I(sbi)->version)
			return src;
	}
	
	if (is_inode_flag_set(HMFS_I(inode), FI_NO_ALLOC))
		return ERR_PTR(-EPERM);

	if (!inc_valid_block_count(sbi, get_stat_object(inode, src_addr 
				!= NULL_ADDR), 1))
		return ERR_PTR(-ENOSPC);

	dst_addr = alloc_free_data_block(sbi);

	if (dst_addr == NULL_ADDR) {
		inc_valid_block_count(sbi, get_stat_object(inode, src_addr
				!= NULL_ADDR), -1);
		return ERR_PTR(-ENOSPC);
	}

	dst = ADDR(sbi, dst_addr);

	if (need_copy && src_addr != NULL_ADDR)
		hmfs_memcpy(dst, src, HMFS_PAGE_SIZE);
	else
		memset_nt(dst, 0, HMFS_PAGE_SIZE);

	summary = get_summary_by_addr(sbi, dst_addr);
	make_summary_entry(summary, inode->i_ino, CM_I(sbi)->new_version, 0,
			SUM_TYPE_XDATA);

	return dst;
}
