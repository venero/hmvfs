#include "hmfs.h"
#include "node.h"

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
			update_nat_entry(NM_I(sbi), nid[i], dn->inode->i_ino,
							NEW_ADDR, CM_I(sbi)->new_version, true);
			sum_type = i == level ? SUM_TYPE_DN : SUM_TYPE_IDN;
			blocks[i] =
			 alloc_new_node(sbi, nid[i], dn->inode, sum_type);
			if (IS_ERR(blocks[i])) {
				err = PTR_ERR(blocks[i]);
				goto out;
			}

			if (i == 1) {
				blocks[0] =
				 alloc_new_node(sbi, nid[0], dn->inode,
						SUM_TYPE_INODE);

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
	block_t max_blk = hmfs_max_size() >> HMFS_PAGE_SIZE_BITS;
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
					    block_t new_addr, block_t src_addr,
					    unsigned int ino,
					    unsigned int ofs_in_node)
{
	struct hmfs_summary *src_sum, *dest_sum;
	struct hmfs_cm_info *cm_i = CM_I(sbi);

	dest_sum = get_summary_by_addr(sbi, new_addr);
	make_summary_entry(dest_sum, ino, cm_i->new_version, 1, ofs_in_node,
			   SUM_TYPE_DATA);

	if (src_addr != NULL_ADDR) {
		src_sum = get_summary_by_addr(sbi, src_addr);
		set_summary_dead_version(src_sum, cm_i->new_version);
	}
}

/**
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
	hn = alloc_new_node(sbi, dn.nid, inode, sum_type);
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

		/* 
		 * Here we need to copy content from source data to dest data block
		 * Because we have increase count of src_addr in alloc_new_node,
		 * we need to decrease count of it.
		 */
		dec_summary_count(summary);
	}

	if (!inc_valid_block_count(sbi, inode, 1))
		return ERR_PTR(-ENOSPC);

	new_addr = alloc_free_data_block(sbi);
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

	setup_summary_of_new_data_block(sbi, new_addr, src_addr, inode->i_ino,
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
	hn = alloc_new_node(sbi, dn.nid, inode, sum_type);
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

		/* 
		 * Here we need to copy content from source data to dest data block
		 * Because we have increase count of src_addr in alloc_new_node,
		 * we need to decrease count of it.
		 */
		dec_summary_count(summary);
	}

	if (!inc_valid_block_count(sbi, inode, 1))
		return ERR_PTR(-ENOSPC);

	if (is_inode_flag_set(HMFS_I(inode), FI_NO_ALLOC))
		return ERR_PTR(-EPERM);

	new_addr = alloc_free_data_block(sbi);
	if (dn.level)
		hn->dn.addr[dn.ofs_in_node] = new_addr;
	else
		hn->i.i_addr[dn.ofs_in_node] = new_addr;

	dest = ADDR(sbi, new_addr);

	if (src_addr != NULL_ADDR)
		hmfs_memcpy(dest, src, HMFS_PAGE_SIZE);
	else memset_nt(dest, 0, HMFS_PAGE_SIZE);

	setup_summary_of_new_data_block(sbi, new_addr, src_addr, inode->i_ino,
					dn.ofs_in_node);
	return dest;
}

void *alloc_new_data_block(struct inode *inode, int block)
{
	block_t addr;
	struct hmfs_sb_info *sbi = NULL;

	if (likely(inode))
		return __alloc_new_data_block(inode, block);

	if (!inc_gc_block_count(sbi, CURSEG_DATA))
		return ERR_PTR(-ENOSPC);
	sbi = HMFS_I_SB(inode);
	addr = alloc_free_data_block(sbi);
	return ADDR(sbi, addr);
}

static int hmfs_read_data_page(struct file *file, struct page *page)
{
	struct inode *inode = file->f_inode;
	int bidx = page->index;
	void *data_blk[1];
	void *page_addr;
	int err;
	int size = 0;

	hmfs_bug_on(HMFS_I_SB(inode), HMFS_PAGE_SIZE_BITS != PAGE_CACHE_SHIFT);
	err = get_data_blocks(inode, bidx, bidx + 1, data_blk, &size,
					RA_DB_END);
	if (size != 1 || (err && err != -ENODATA))
		return err;

	page_addr = kmap_atomic(page);
	if (data_blk[0] == NULL) {
		memset_nt(page_addr, 0, PAGE_CACHE_SIZE);
	} else {
		hmfs_memcpy(page_addr, data_blk[0], PAGE_CACHE_SIZE);
	}
	kunmap_atomic(page_addr);

	SetPageUptodate(page);
	unlock_page(page);
	return 0;
}

static int do_write_data_page(struct page *page)
{
	struct inode *inode = page->mapping->host;
	void *dest = NULL, *src = NULL;

	dest = alloc_new_data_block(inode, page->index);
	if (IS_ERR(dest)) {
		if (PTR_ERR(dest) == -ENOSPC)
			return -ENOSPC;
		else
			return -ENOENT;
	}

	src = kmap_atomic(page);
	hmfs_memcpy(dest, src, HMFS_PAGE_SIZE);
	kunmap_atomic(src);

	return 0;
}

int hmfs_write_data_page(struct page *page,
				struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	loff_t i_size = i_size_read(inode);
	const pgoff_t end_index =
	 ((unsigned long long)i_size) >> PAGE_CACHE_SHIFT;
	unsigned offset;
	int err = 0;
	int ilock;

	if (page->index < end_index)
		goto write;

	offset = i_size & (PAGE_CACHE_SIZE - 1);
	if ((page->index >= end_index + 1) || !offset) {
		if (S_ISDIR(inode->i_mode)) {
			hmfs_bug_on(sbi, 1);
			//dec_page_count(sbi,HMFS_DIRTY_DENTS);
			//inode_dec_dirty_dents(inode);
		}
		goto out;
	}

	zero_user_segment(page, offset, PAGE_CACHE_SIZE);
write:
	//FIXME: need por_doing
	if (sbi->por_doing) {
		err = AOP_WRITEPAGE_ACTIVATE;
		goto redirty_out;
	}

	if (S_ISDIR(inode->i_mode)) {
		hmfs_bug_on(sbi, 1);
	}

	ilock = mutex_lock_op(sbi);
	err = do_write_data_page(page);
	mutex_unlock_op(sbi, ilock);

	if (err == -ENOENT)
		goto out;
	else if (err)
		goto redirty_out;
	dec_dirty_map_pages_count(sbi);
	inode_dec_dirty_map_pages_count(inode);
	
	if(!atomic_read(&HMFS_I(inode)->nr_dirty_map_pages))
		remove_dirty_map_inode(inode);

out:
	unlock_page(page);
	return 0;
redirty_out:
	wbc->pages_skipped++;
	set_page_dirty(page);
	return err;
}

static int hmfs_write_begin(struct file *file, struct address_space *mapping,
			    loff_t pos, unsigned len, unsigned flags,
			    struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	struct page *page;
	void *src[1];
	void *dest;
	int size;
	unsigned start = pos & (PAGE_CACHE_SIZE - 1);
	unsigned end = start + len;
	pgoff_t index = ((unsigned long long)pos) >> PAGE_CACHE_SHIFT;
	int err = 0;

	*fsdata = NULL;
repeat:page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;
	if (page->mapping != mapping) {
		page_cache_release(page);
		goto repeat;
	}
	*pagep = page;

	if ((len == PAGE_CACHE_SIZE) || PageUptodate(page))
		return 0;

	if ((pos & PAGE_CACHE_MASK) >= i_size_read(inode)) {
		zero_user_segments(page, 0, start, end, PAGE_CACHE_SIZE);
		goto out;
	}

	err = get_data_blocks(inode, start, start + 1, src, &size, RA_DB_END);
	if (err || size != 1 || src[0] == NULL)
		return 0;

	dest = kmap_atomic(page);
	hmfs_memcpy(dest, src, PAGE_CACHE_SIZE);
	kunmap_atomic(dest);
	lock_page(page);
out:
	SetPageUptodate(page);
	return 0;
}

static int hmfs_write_end(struct file *file, struct address_space *mapping,
			  loff_t pos, unsigned len, unsigned copied,
			  struct page *page, void *fsdata)
{
	struct inode *inode = page->mapping->host;

	SetPageUptodate(page);
	set_page_dirty(page);

	if (pos + copied > i_size_read(inode)) {
		mark_size_dirty(inode, pos + copied);
	}

	unlock_page(page);
	page_cache_release(page);
	return copied;
}

static int hmfs_set_data_page_dirty(struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode = mapping->host;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);

	SetPageUptodate(page);
	if (!PageDirty(page)) {
		__set_page_dirty_nobuffers(page);
		if (S_ISDIR(inode->i_mode))
			hmfs_bug_on(sbi, 1);
		add_dirty_map_inode(inode);
		inc_dirty_map_pages_count(sbi);
		inode_inc_dirty_map_pages_count(inode);
		SetPagePrivate(page);
		return 1;
	}
	return 0;
}

static void hmfs_invalidate_data_page(struct page *page, unsigned int offset,
				      unsigned int length)
{
	ClearPagePrivate(page);
}

static int hmfs_release_data_page(struct page *page, gfp_t wait)
{
	ClearPagePrivate(page);
	return 1;
}

const struct address_space_operations hmfs_dblock_aops = {
	.readpage = hmfs_read_data_page,
	.writepage = hmfs_write_data_page,
	.write_begin = hmfs_write_begin,
	.write_end = hmfs_write_end,
	.set_page_dirty = hmfs_set_data_page_dirty,
	.invalidatepage = hmfs_invalidate_data_page,
	.releasepage = hmfs_release_data_page,
	.direct_IO = NULL,
};
