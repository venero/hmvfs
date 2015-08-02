#include "hmfs.h"
#include "node.h"
const struct address_space_operations hmfs_dblock_aops;

/**
 * The maximum depth is 4.
 */
static int get_node_path(long block, int offset[4], unsigned int noffset[4])
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
		noffset[n] = 6 + (dptrs_per_blk * 2) +
		    offset[n - 1] * (dptrs_per_blk + 1);
		offset[n++] = (block / direct_blks) % dptrs_per_blk;
		noffset[n] = 7 + (dptrs_per_blk * 2) +
		    offset[n - 2] * (dptrs_per_blk + 1) + offset[n - 1];
		offset[n] = block % direct_blks;
		level = 3;
		goto got;

	} else {
		BUG();
	}
got:
	return level;
}

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

int get_dnode_of_data(struct dnode_of_data *dn, int index, int mode)
{
	struct hmfs_sb_info *sbi = HMFS_SB(dn->inode->i_sb);
	void *blocks[4];
	void *parent;
	nid_t nid[4];
	int offset[4];
	unsigned int noffset[4];
	int level, i;
	int err = 0;

	level = get_node_path(index, offset, noffset);

	nid[0] = dn->inode->i_ino;
	blocks[0] = dn->inode_block;
	printk(KERN_INFO "index:%d\n", index);
	if (!blocks[0]) {
		printk(KERN_INFO "get node:%d\n", nid[0]);
		blocks[0] = get_node(sbi, nid[0]);
		if (IS_ERR(blocks[0]))
			return PTR_ERR(blocks[0]);
		printk(KERN_INFO "get node success\n");
		dn->inode_block = blocks[0];
	}
	parent = blocks[0];
	if (level != 0) {
		nid[1] = get_nid(parent, offset[0], true);
	}
	printk(KERN_INFO "get node level:%d\n", level);

	for (i = 1; i <= level; ++i) {
		if (!nid[i] && mode == ALLOC_NODE) {
			if (!alloc_nid(sbi, &(nid[i]), &dn->inode->i_ino)) {
				err = -ENOSPC;
				goto out;
			}
			dn->nid = nid[i];
			blocks[i] = get_new_node(sbi, nid[i], dn->inode->i_ino);
			if (IS_ERR(blocks[i])) {
				err = PTR_ERR(blocks[i]);
				goto out;
			}

			if (i == 1) {
				blocks[0] =
				    get_new_node(sbi, nid[0], dn->inode->i_ino);
				parent = blocks[0];
			}
			set_nid(parent, offset[i - 1], nid[i], i == 1);
		} else if (nid[i] && mode == LOOKUP_NODE) {
			blocks[i] = get_node(sbi, nid[i]);
			if (IS_ERR(blocks[i])) {
				err = PTR_ERR(blocks[i]);
				goto out;
			}
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

static void set_new_dnode(struct dnode_of_data *dn, struct inode *inode,
			  struct hmfs_inode *hi, struct direct_node *db,
			  nid_t nid)
{
	dn->inode = inode;
	dn->inode_block = hi;
	dn->node_block = db;
	dn->nid = nid;
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
	int i;
	int ofs_in_node = 0;
	int end_blk_id = -1;
	struct dnode_of_data dn;
	int err;
	unsigned long addr;
	bool init = true;
	unsigned long max_blk = hmfs_max_size() >> HMFS_PAGE_SIZE_BITS;

	set_new_dnode(&dn, inode, NULL, NULL, 0);
	printk(KERN_INFO "get_data_blocks:[%d,%d)\n", start, end);
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
			BUG_ON(dn.inode_block == NULL);
			addr = dn.inode_block->i_addr[ofs_in_node++];
		} else {
			BUG_ON(dn.node_block == NULL);
			addr = dn.node_block->addr[ofs_in_node++];
		}
		printk(KERN_INFO "blk_addr:%lu-%d\n",
		       addr >> HMFS_SEGMENT_SIZE_BITS,
		       (addr & ~HMFS_SEGMENT_MASK) >> HMFS_PAGE_SIZE_BITS);
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

static unsigned long get_new_data_block_addr(struct hmfs_sb_info *sbi)
{
	struct checkpoint_info *cp_i = CURCP_I(sbi);
	unsigned long page_addr = 0;
	page_addr = cal_page_addr(cp_i->cur_data_segno, cp_i->cur_data_blkoff);
	cp_i->cur_data_blkoff++;
	return page_addr;
}

void *get_new_data_block(struct inode *inode, int block)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	struct dnode_of_data dn;
	struct hmfs_node *hn = NULL;
	unsigned long new_addr, src_addr;
	void *src, *dest;
	int err;
	printk(KERN_INFO "get_new_data_block:%lu\n", inode->i_ino);
	set_new_dnode(&dn, inode, NULL, NULL, 0);
	err = get_dnode_of_data(&dn, block, ALLOC_NODE);

	if (err)
		return ERR_PTR(err);

	hn = get_new_node(sbi, dn.nid, inode->i_ino);
	if (IS_ERR(hn))
		return hn;

	new_addr = get_new_data_block_addr(sbi);

	if (dn.level) {
		src_addr = hn->dn.addr[dn.ofs_in_node];
		hn->dn.addr[dn.ofs_in_node] = new_addr;
	} else {
		src_addr = hn->i.i_addr[dn.ofs_in_node];
		hn->i.i_addr[dn.ofs_in_node] = new_addr;
	}
	printk(KERN_INFO "src_blk_addr:%lu-%d\n",
	       src_addr >> HMFS_SEGMENT_SIZE_BITS,
	       (src_addr & ~HMFS_SEGMENT_MASK) >> HMFS_PAGE_SIZE_BITS);
	printk(KERN_INFO "dest_blk_addr:%lu-%d\n",
	       new_addr >> HMFS_SEGMENT_SIZE_BITS,
	       (new_addr & ~HMFS_SEGMENT_MASK) >> HMFS_PAGE_SIZE_BITS);
	src = ADDR(sbi, src_addr);
	dest = ADDR(sbi, new_addr);
	hmfs_memcpy(dest, src, HMFS_PAGE_SIZE);
	return dest;
}
