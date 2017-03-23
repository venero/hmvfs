#include "hmfs.h"
#include "node.h"
#include "segment.h"

/*
 * return the last block index in current node/inode
 */
static inline int64_t get_end_data_block_index(int64_t index)
{
	if (index < NORMAL_ADDRS_PER_INODE)
		return NORMAL_ADDRS_PER_INODE - 1;
	index = index - NORMAL_ADDRS_PER_INODE;
	index &= ~(ADDRS_PER_BLOCK - 1);
	return NORMAL_ADDRS_PER_INODE + index + ADDRS_PER_BLOCK - 1;
}

static bool inc_valid_block_count(struct hmfs_sb_info *sbi,	struct inode *inode, int count)
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

static int build_internal_node(struct inode *inode, nid_t par_nid, int16_t ofs, char sum_type)
{
	nid_t nid;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	void *par_node, *child;
	char par_type;

	if (!alloc_nid(sbi, &nid))
		return -ENOSPC;
	par_type = par_nid == inode->i_ino ? SUM_TYPE_INODE : SUM_TYPE_IDN;
	par_node = alloc_new_node(sbi, par_nid, inode, par_type, false);
	if (IS_ERR(par_node))
		return PTR_ERR(par_node);
	child = alloc_new_node(sbi, nid, inode, sum_type, false);
	if (IS_ERR(child)) {
		alloc_nid_failed(sbi, nid);
		return PTR_ERR(child);
	}

	if (par_type == SUM_TYPE_INODE)
		HMFS_INODE(par_node)->i_nid = cpu_to_le32(nid);
	else
		INDIRECT_NODE(par_node)->nid[ofs] = cpu_to_le32(nid);
	return 0;
}

/* 
 * Return the infomation of specific data block
 * @mode: LOOKUP and ALLOC
 * @index: index of data block
 */
int get_data_block_info(struct db_info *di, int64_t index, int mode)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(di->inode);
	struct indirect_node *node;
	struct hmfs_inode *hi;
	struct node_info *ni;
	int ret = 0;
	uint8_t height = HMFS_I(di->inode)->i_height, set_height = height;
	uint8_t i = 0;
	nid_t nid;
	ver_t bv;
	struct hmfs_inode_info* hii = HMFS_I(di->inode);
	// struct node_info *ni = hmfs_get_node_info(&hii->vfs_inode, index);
	// ver_t bv = ni->begin_version;

	if (index < NORMAL_ADDRS_PER_INODE) {
		di->local = 1;
		di->nid = di->inode->i_ino;
		if (mode == ALLOC)
			di->node_block = alloc_new_node(sbi, di->nid, di->inode, SUM_TYPE_INODE, false);
		else
			di->node_block = get_node(sbi, di->nid);
		di->ofs_in_node = index;
		if (IS_ERR(di->node_block))
			return PTR_ERR(di->node_block);
		return 0;
	}
	
	index -= NORMAL_ADDRS_PER_INODE;
	if (!set_height)
		set_height = 1;
	while ((1 << (ADDRS_PER_BLOCK_BITS + (set_height - 1) * NIDS_PER_BLOCK_BITS)) <= index)
		set_height++;


	if (!height && mode == ALLOC) {
		ret = build_internal_node(di->inode, di->inode->i_ino, 0, SUM_TYPE_DN);
		if (ret)
			return ret;
		HMFS_I(di->inode)->i_height = ++height;
	}

	hi = get_node(sbi, di->inode->i_ino);
	if (IS_ERR(hi))
		return PTR_ERR(hi);

	if (mode == ALLOC) {
		while (height++ < set_height) {
			struct indirect_node *in;
			nid = hi->i_nid;
			ret = build_internal_node(di->inode, di->inode->i_ino, 0, SUM_TYPE_IDN);
			if (ret)
				return ret;

			in = get_node(sbi, le32_to_cpu(hi->i_nid));
			if (IS_ERR(in))
				return PTR_ERR(in);
			in->nid[0] = nid;
			HMFS_I(di->inode)->i_height = height;
		}
	}
	

	nid = le32_to_cpu(hi->i_nid);
	node = get_node(sbi, nid);
	if (IS_ERR(node))
		return PTR_ERR(node);

	height = set_height;
	while (i < height - 1) {
		uint16_t ofs;
		nid_t next_nid;

		ofs = index >> (ADDRS_PER_BLOCK_BITS + (height - 2 - i) * NIDS_PER_BLOCK_BITS);	
		ofs &= (NIDS_PER_BLOCK - 1);
		next_nid = le32_to_cpu(node->nid[ofs]);
		
		if (!next_nid && mode == ALLOC) {
			uint8_t sum_type = i == height - 2 ? SUM_TYPE_DN : SUM_TYPE_IDN;
			ret = build_internal_node(di->inode, nid, ofs, sum_type);
			if (ret)
				return ret;
			node = get_node(sbi, nid);
			next_nid = le32_to_cpu(node->nid[ofs]);
		} 
		
		node = get_node(sbi, next_nid);
		if (IS_ERR(node))
			return PTR_ERR(node);

		nid = next_nid;
		i++;
	}

	if (mode == ALLOC) {
		ni = get_node_info_by_nid(sbi, nid);
		bv = ni->begin_version;
		di->node_block = alloc_new_node(sbi, nid, di->inode, SUM_TYPE_DN, false);
		ni = hmfs_get_node_info(&hii->vfs_inode, index);
		bv = ni->begin_version;
	}
	else
		di->node_block = HMFS_NODE(node);

	if (IS_ERR(di->node_block))
		return PTR_ERR(di->node_block);

	di->local = 0;
	di->nid = nid;
	di->ofs_in_node = index & (ADDRS_PER_BLOCK - 1);

	// ni = hmfs_get_node_info(&hii->vfs_inode, index);
	// ni->begin_version = bv;

	return 0;
}

void *get_data_block(struct inode *inode, int64_t index)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	struct db_info di;
	block_t addr;
	int err;
	// nid_t nid = inode->i_ino;
	// WARP-write

	struct node_info *ni = hmfs_get_node_info(inode, index);
	struct wp_data_page_entry *wdp;

	if (ni->current_warp == FLAG_WARP_WRITE) {
		wdp = search_wp_data_block(sbi->nm_info,inode,index);
		if (likely(wdp)) {
			// hmfs_dbg("Get data block from wdg: inode:%u, index:%d.\n",nid,(int)index); 
			return wdp->dp_addr;
		}
	}

	di.inode = inode;
	err = get_data_block_info(&di, index, LOOKUP);
	if (err) 
		return ERR_PTR(err);

	addr = read_address(di.node_block, di.ofs_in_node, di.local);
	if (!addr)
		return ERR_PTR(-ENODATA);
	return ADDR(sbi, addr);
}

/* Caller should restrict value of end within size of inode */
int get_data_blocks_ahead(struct inode *inode, int64_t start, int64_t end,
				void **blocks)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	struct db_info di;
	int64_t end_db_id = -1;
	int err;
	bool null = false;

	di.inode = inode;
	hmfs_bug_on(sbi, start >= end);
	while (start < end) {
		if (start > end_db_id) {
			err = get_data_block_info(&di, start, LOOKUP);
			if (err && err != -ENODATA) 
				return err;
			end_db_id = get_end_data_block_index(start);
			null = err == -ENODATA;
		}

		if (null)
			*blocks++ = NULL;
		else {
			block_t addr;
			addr = read_address(di.node_block, di.ofs_in_node++, di.local);
			*blocks++ = addr ? ADDR(sbi, addr) : NULL;
		}
		start++;
	}
	return 0;
}

void *pw_alloc_new_data_block(struct inode *inode, int block, unsigned long pw_start, unsigned long pw_end, int mode)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	struct checkpoint_info *cp_i = CURCP_I(sbi);
	struct hmfs_node *hn = NULL;
	block_t new_addr, src_addr = 0;
	void *src = NULL, *dest;
	int err;
	struct wp_nat_entry *wne;
	struct wp_data_page_entry *wdp;
	struct hmfs_summary *summary = NULL;
	struct db_info di;
	const unsigned char seg_type = HMFS_I(inode)->i_blk_type;

	// if (mode==WRITEBACK) {
	// 	hmfs_dbg("inside WRITEBACK\n");
	// }

	di.inode = inode;
	/*
	 *	Normal write:	If wdp exists, write to wdp. (just return the in-DRAM address)
	 *					If not, commence full write procedure.
	 *	Write back:		Commence partial write procedure.
	 */
	if (mode==NORMAL) {
		wdp = search_wp_data_block(sbi->nm_info, inode, block);
		if (wdp!=NULL) {
			wne = search_wp_inode_entry(sbi->nm_info, inode);
			// hmfs_dbg("WARP write ino:%lu block:%d\n",inode->i_ino,block);
			radix_tree_tag_set(&sbi->nm_info->wp_inode_root,wne->ino,1);
			return wdp->dp_addr;
		}
	} 

	// hmfs_dbg("PT write ino:%lu block:%d\n",inode->i_ino,block);

	err = get_data_block_info(&di, block, ALLOC);
	if (err)
		return ERR_PTR(err);

	hn = di.node_block;

	src_addr = read_address(hn, di.ofs_in_node, di.local);

	// If this data block is created in this version, just write to it.
	if (src_addr != 0) {
		src = ADDR(sbi, src_addr);
		summary = get_summary_by_addr(sbi, src_addr);
		if (get_summary_start_version(summary) == cp_i->version)
			return src;
	}

	if (is_inode_flag_set(HMFS_I(inode), FI_NO_ALLOC))
		return ERR_PTR(-EPERM);

	if (!inc_valid_block_count(sbi, get_stat_object(inode, src_addr != 0),
			HMFS_BLOCK_SIZE_4K[seg_type]))
		return ERR_PTR(-ENOSPC);

	new_addr = alloc_free_data_block(sbi, seg_type);

	if (new_addr == 0) {
		inc_valid_block_count(sbi, get_stat_object(inode, src_addr != 0),
				-HMFS_BLOCK_SIZE_4K[seg_type]);
		return ERR_PTR(-ENOSPC);
	}

	if (di.local)
		hn->i.i_addr[di.ofs_in_node] = cpu_to_le64(new_addr);
	else
		hn->dn.addr[di.ofs_in_node] = cpu_to_le64(new_addr);

	dest = ADDR(sbi, new_addr);

	if (mode==WRITEBACK) {
		inode_write_lock(inode);
		// hmfs_dbg("dest %llx;src %llx\n",(unsigned long long)dest,(unsigned long long)src);
		wdp = search_wp_data_block(sbi->nm_info, inode, block);
		if (wdp!=NULL) {
			src = wdp->dp_addr;
		}
		// hmfs_dbg("%s\n",(char*)src);
		memcpy(dest, src, HMFS_BLOCK_SIZE[seg_type]);
		// hmfs_dbg("%s\n",(char*)dest);
		inode_write_unlock(inode);
		goto out;
	}

	if (src_addr != 0) {
		if ( (HMFS_BLOCK_SIZE[seg_type] - pw_end - pw_start) >> PW_THRESHOLD == 0 ) {
			hmfs_memcpy(dest, src, HMFS_BLOCK_SIZE[seg_type]);
		}
		else {
			if (pw_start != 0) {
				hmfs_memcpy(dest, src, pw_start);
			}
			if (pw_end != 0) {
				hmfs_memcpy(dest + HMFS_BLOCK_SIZE[seg_type] - pw_end, src + HMFS_BLOCK_SIZE[seg_type] - pw_end, pw_end);
			}
		}
	}		
	else memset(dest, 0, HMFS_BLOCK_SIZE[seg_type]);
	
out:
	summary = get_summary_by_addr(sbi, new_addr);
	make_summary_entry(summary, di.nid, CM_I(sbi)->new_version, di.ofs_in_node, SUM_TYPE_DATA, 0);

	return dest;
}

/*
 * @block: 	-- index of data block for NORMAL inode;
 * 			-- type of data block for GC
 */
void *alloc_new_data_block(struct hmfs_sb_info *sbi, struct inode *inode, 
				int block)
{
	block_t addr;
	const unsigned char seg_type = HMFS_I(inode)->i_blk_type;

	if (likely(inode))
		return pw_alloc_new_data_block(inode, block,HMFS_BLOCK_SIZE[seg_type],0,NORMAL);

	if (!inc_gc_block_count(sbi, block))
		return ERR_PTR(-ENOSPC);
	// inode = NULL? 
	// In GC?
	addr = alloc_free_data_block(sbi, block);
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
	block_t src_addr, dst_addr;
	void *src, *dst;
	struct hmfs_summary *summary = NULL;

	inode_block = alloc_new_node(sbi, inode->i_ino, inode, SUM_TYPE_INODE, false);
	if (IS_ERR(inode_block))
		return inode_block;

	src_addr = le64_to_cpu(*((__le64 *)JUMP(inode_block, x_tag)));
	src = ADDR(sbi, src_addr);
	if (src_addr != 0) {
		summary = get_summary_by_addr(sbi, src_addr);
		if (get_summary_start_version(summary) == CURCP_I(sbi)->version)
			return src;
	}
	
	if (is_inode_flag_set(HMFS_I(inode), FI_NO_ALLOC))
		return ERR_PTR(-EPERM);

	if (!inc_valid_block_count(sbi, get_stat_object(inode, src_addr != 0), 1))
		return ERR_PTR(-ENOSPC);

	dst_addr = alloc_free_data_block(sbi, SEG_DATA_INDEX);

	if (dst_addr == 0) {
		inc_valid_block_count(sbi, get_stat_object(inode, src_addr != 0), -1);
		return ERR_PTR(-ENOSPC);
	}

	dst = ADDR(sbi, dst_addr);
	*((__le64 *)JUMP(inode_block, x_tag)) = cpu_to_le64(dst_addr);

	if (need_copy && src_addr != 0)
		hmfs_memcpy(dst, src, HMFS_BLOCK_SIZE[SEG_DATA_INDEX]);
	else
		memset(dst, 0, HMFS_BLOCK_SIZE[SEG_DATA_INDEX]);

	summary = get_summary_by_addr(sbi, dst_addr);
	make_summary_entry(summary, inode->i_ino, CM_I(sbi)->new_version, 0,
			SUM_TYPE_XDATA,0);

	return dst;
}
