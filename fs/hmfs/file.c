/*
 * fs/hmfs/file.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 * Copyright (c) 2015 SJTU RadLab
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
 
#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/falloc.h>
#include <linux/time.h>
#include <linux/stat.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/mount.h>
#include <linux/compat.h>
#include <linux/xattr.h>
#include <uapi/linux/magic.h>
#include <linux/hrtimer.h>
#include <asm-generic/current.h>

#include "hmfs_fs.h"
#include "hmfs.h"
#include "node.h"
#include "segment.h"
#include "util.h"
#include "gc.h"

/*
int getPpath(struct task_struct *cur_task){
    char *path = NULL,*ptr = NULL;
    char *read_buf = NULL;
    read_buf = kmalloc(PAGE_SIZE,GFP_KERNEL);
    if(!read_buf){
        printk("read_buf alloc error!\n");
        goto error1;
    }
    path = kmalloc(PAGE_SIZE,GFP_KERNEL);
    if(!path){
        printk("path alloc error!\n");
        goto error2;
    }

    if(cur_task && cur_task->mm && cur_task->mm->exe_file){
         ptr = d_path(&cur_task->mm->exe_file->f_path,path,PAGE_SIZE);        
    }
    else{
         printk("task is null!\n");
    }
    
    printk("ProcName:%s PID: %d\n",cur_task->comm, cur_task->pid);
    printk("ProcPath:%s \n",ptr);
error1:
    kfree(read_buf);
error2:
    kfree(path);
    return 0;
}*/

static struct kmem_cache *mmap_block_slab;

static int64_t start_block(int64_t i)
{
	if (i < NORMAL_ADDRS_PER_INODE)
		return 0;
	i = i - NORMAL_ADDRS_PER_INODE;
	i &= ~(ADDRS_PER_BLOCK - 1);
	return NORMAL_ADDRS_PER_INODE + i;
}

static int dec_valid_block_count(struct hmfs_sb_info *sbi,
	struct inode *inode, int count)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);

	lock_cm(cm_i);
	inode->i_blocks -= count;
	cm_i->valid_block_count -= count;
	unlock_cm(cm_i);

	return 0;
}

void truncate_file_block_bitmap(struct inode *inode, loff_t from)
{
	unsigned char *bitmap = HMFS_I(inode)->block_bitmap;
	uint64_t start;
	
	if (bitmap) {
		start = (from + PAGE_SIZE - 1) >> PAGE_SHIFT;
		if (start & 7) {
			bitmap[start >> 3] = bitmap[start >> 3] & ((1 << start) - 1);
			start++;
		}
		memset(bitmap + start, 0, HMFS_I(inode)->bitmap_size - start);
	}
}

/* Find the last index of data block which is meaningful*/
int64_t hmfs_dir_seek_data_reverse(struct inode *dir, int64_t end_blk)
{
	struct direct_node *direct_node = NULL;
	struct hmfs_inode *inode_block = NULL;
	int err, j;
	block_t addr;
	int64_t start_blk;
	struct db_info di;

	di.inode = dir;
	hmfs_bug_on(HMFS_I_SB(dir), is_inline_inode(dir));
	while (end_blk >= 0) {
		di.node_block = NULL;
		di.nid = 0;
		err = get_data_block_info(&di, end_blk, LOOKUP);
		if (err) {
			if (!di.local)
				end_blk = start_block(end_blk) - 1;
			else
				hmfs_bug_on(HMFS_I_SB(dir), 1);
			continue;
		}
		start_blk = start_block(end_blk);
		if (!di.local) {
			direct_node = DIRECT_NODE(di.node_block);
			hmfs_bug_on(HMFS_I_SB(dir), !direct_node);

			for (j = end_blk - start_blk; j >= 0; j--) {
				addr = le64_to_cpu(direct_node->addr[j]);
				if (addr)
					return start_blk + j;
			}
		} else {
			inode_block = HMFS_INODE(di.node_block);
			hmfs_bug_on(HMFS_I_SB(dir), !inode_block);

			for (j = end_blk - start_blk; j >= 0; j--) {
				addr = le64_to_cpu(inode_block->i_addr[j]);
				if (addr)
					return start_blk + j;
			}
		}
		end_blk = start_blk - 1;
	}
	hmfs_bug_on(HMFS_I_SB(dir), 1);
	return 0;
}

/*
 * I think it's ok to seek hole or data but not to obtain a fs lock,
 * i.e. user could seek hole or data of file when fs is doing checkpoint
 */
static unsigned int hmfs_file_seek_hole_data(struct inode *inode, 
				int64_t end_blk, loff_t start_pos, char type)
{
	unsigned char seg_type = HMFS_I(inode)->i_blk_type;
	int i = start_pos >> HMFS_BLOCK_SIZE_BITS(seg_type), j = 0;
	struct direct_node *direct_node = NULL;
	struct hmfs_inode *inode_block = NULL;
	int err;
	unsigned start_blk = end_blk;
	block_t addr;
	struct db_info di;

	di.inode = inode;
	while (i < end_blk) {
		di.node_block = NULL;
		di.nid = 0;
		err = get_data_block_info(&di, i, LOOKUP);
		if (err) {
			if (type == SEEK_HOLE)
				return i;
			if (!di.local)
				i = start_block(i) + ADDRS_PER_BLOCK;
			else 
				hmfs_bug_on(HMFS_I_SB(inode), 1);
			continue;
		}
	
		start_blk = start_block(i);
		if (!di.local) {
			direct_node = DIRECT_NODE(di.node_block);
			hmfs_bug_on(HMFS_I_SB(inode), !direct_node);

			for (j = start_blk - i; j < ADDRS_PER_BLOCK; j++) {
				addr = le64_to_cpu(direct_node->addr[j]);
				if (!addr && type == SEEK_HOLE)
					goto found;
				else if (addr && type == SEEK_DATA)
					goto found;
			}
			i = start_blk + ADDRS_PER_BLOCK;
		} else {
			/* level 0, inode */
			inode_block = HMFS_INODE(di.node_block);
			hmfs_bug_on(HMFS_I_SB(inode), !inode_block);

			for (j = start_blk - i; j < NORMAL_ADDRS_PER_INODE; j++) {
				addr = le64_to_cpu(inode_block->i_addr[j]);
				if (!addr && type == SEEK_HOLE)
					goto found;
				else if (addr && type == SEEK_DATA)
					goto found;
			}
			i = start_blk + NORMAL_ADDRS_PER_INODE;
		}
	}
found:
	return start_blk + j < end_blk? start_blk + j : end_blk;
}

// Switch to WARP compatible mode as a unified entrance of read
static ssize_t __hmfs_xip_file_read(struct file *filp, char __user *buf,
				size_t len, loff_t *ppos)
{
	/* from do_XIP_mapping_read */
	// hmfs_dbg("Time B %llu\n", ktime_get().tv64);
	struct inode *inode = filp->f_inode;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	pgoff_t index, end_index;
	pgoff_t index_hint = 0;
	unsigned long offset;
	loff_t isize, pos;
	size_t copied = 0, error = 0;
	struct hmfs_inode *inode_block;
	unsigned char seg_type = HMFS_I(inode)->i_blk_type;
	struct node_info *ni;
	const unsigned long long block_size = HMFS_BLOCK_SIZE[seg_type];
	const unsigned int block_size_bits = HMFS_BLOCK_SIZE_BITS(seg_type);
	const unsigned long long block_ofs_mask = block_size - 1;
	struct hmfs_summary *summary;

	pos = *ppos;
	isize = i_size_read(inode);

	if (is_inline_inode(inode)) {
		inode_block = get_node(HMFS_I_SB(inode), inode->i_ino);
		if (IS_ERR(inode_block)) {
			error = PTR_ERR(inode_block);
			goto out;
		}

		if (pos + len > isize)
			copied = isize - pos;
		else
			copied = len;

		if (__copy_to_user(buf, (__u8 *)inode_block->inline_content + pos,
					copied)) {
			copied = 0;
			error = -EFAULT;
		}
		goto out;
	}

	index = pos >> block_size_bits;	
	offset = pos & block_ofs_mask;

	end_index = (isize - 1) >> block_size_bits;

	/*
	 * nr : read length for this loop
	 * offset : start inner-blk offset this loop
	 * index : start inner-file blk number this loop
	 * copied : read length so far
	 */

	// hmfs_dbg("Time C %llu\n", ktime_get().tv64);
	do {
		unsigned long nr, left;
		void *xip_mem;
		int zero = 0;

		/* nr is the maximum number of bytes to copy from this page */

		// index_hint indicates that the direct node covering block [_,index_hint] is NOT WARP_READ now.
		if ( index_hint >= index ) goto normal;

		ni = hmfs_get_node_info(inode, (int64_t)index);
		if ( ni == NULL ) goto normal;
		summary = get_summary_by_addr(sbi, ni->blk_addr);
		if (get_summary_type(summary) == SUM_TYPE_DN) index_hint = ni->index + ADDRS_PER_BLOCK - 1;
		else if (get_summary_type(summary) == SUM_TYPE_INODE) index_hint = ni->index + NORMAL_ADDRS_PER_INODE - 1;
		
		if ( index_hint > end_index) index_hint = end_index;
		if ( ni->current_warp != FLAG_WARP_READ ) {
			goto normal;
		}
		nr = block_size*(index_hint-index+1);
		
		if (index > end_index) goto out;
		if (index == end_index) {
			nr = ((isize - 1) & block_ofs_mask) + 1;
			if (nr <= offset) {
				goto out;
			}
		}
		else {
			if (index_hint == end_index) {
				nr = nr - block_size + ((isize - 1) & block_ofs_mask) + 1;
			}
		}

		// hmfs_dbg("[WARP Read] Inode:%lu index:[%lu,%lu]\n", inode->i_ino,index,index_hint);
		nr = nr - offset;
		if (nr > len - copied)
			nr = len - copied;

		xip_mem = HMFS_I(inode)->rw_addr + index * block_size;
		goto copy;
		

normal:

		// hmfs_dbg("[Normal Read] Inode:%lu index:%lu\n", inode->i_ino, index);
		nr = block_size;
		if (index >= end_index) {
			if (index > end_index)
				goto out;
			nr = ((isize - 1) & block_ofs_mask) + 1;
			if (nr <= offset) {
				goto out;
			}
		}
		nr = nr - offset;
		if (nr > len - copied)
			nr = len - copied;
		hmfs_bug_on(HMFS_I_SB(inode), nr > block_size);
		xip_mem = get_data_block(inode, index);

		if (unlikely(IS_ERR(xip_mem))) {
			error = PTR_ERR(xip_mem);
			if (error == -ENODATA)
				zero = 1;
			else
				goto out;
		}

		/* copy to user space */
copy:
	// hmfs_dbg("Time D %llu\n", ktime_get().tv64);
		if (!zero) {
			left = __copy_to_user(buf + copied, xip_mem + offset, nr);
			// if (index>460 && index<470)hmfs_dbg("index:%ld offset:%ld buf:%p\n",index,offset,xip_mem + offset);
			// if (index>972 && index<982)hmfs_dbg("index:%ld offset:%ld buf:%p\n",index,offset,xip_mem + offset);
		}
		else
			left = __clear_user(buf + copied, nr);

		if (left) {
			error = -EFAULT;
			goto out;
		}
		// in byte
		copied += (nr - left);
		offset += (nr - left);
		// new offset is now set.
		index += offset >> block_size_bits;
		offset &= block_ofs_mask;

	// hmfs_dbg("Time E %llu\n", ktime_get().tv64);
		// hmfs_dbg("copied:%lu, nr:%lu, left:%lu\n",copied,nr,left);
	} while (copied < len);

out:
	*ppos = pos + copied;
	if (filp)
		file_accessed(filp);

	return (copied ? copied : error);
}

int get_empty_page_struct(struct inode *inode, struct page **pages, int64_t count) {
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	int p_index = 0;
	while (p_index < count) {
		pages[p_index] = sbi->map_zero_page;
		p_index++;
	}
	return 0;
}
/*
 *	Map data blocks of inode to **pages;
 *	index, count indicates file range to map [index, index+count-1]
 *	pageoff, count indicates page range to map [pageoff, pageoff+count-1]
 */
int get_file_page_struct(struct inode *inode, struct page **pages, int64_t index, int64_t count, int64_t pageoff)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	uint8_t blk_type = HMFS_I(inode)->i_blk_type;
	// the total block number of an inode
	uint64_t end_index = (i_size_read(inode) + HMFS_BLOCK_SIZE[blk_type] - 1) >>
			HMFS_BLOCK_SIZE_BITS(blk_type);
	const int max_buf_size = 32;
	void *blocks_buf[max_buf_size];
	int buf_size = 0;
	int b_index = 0;	/* index of buffer */
	int f_index = index;	/* index of file data */
	uint64_t pfn;
	int err = 0;
	int i;

	do {
		if (b_index >= buf_size) {
			uint64_t r_st, r_ed;
			b_index = 0;
			r_st = f_index >> (HMFS_BLOCK_SIZE_BITS(blk_type) - PAGE_SHIFT);
			r_ed = r_st + max_buf_size;
			if (r_st < NORMAL_ADDRS_PER_INODE && r_ed > NORMAL_ADDRS_PER_INODE) {
				r_ed = NORMAL_ADDRS_PER_INODE;
			}
			if (r_ed > end_index)
				r_ed = end_index;
			if (r_st >= r_ed)
				goto out;
			buf_size = r_ed - r_st;
			
			// Write addresses to blocks_buf
			err = get_data_blocks_ahead(inode, r_st, r_ed, blocks_buf);
			if (err)
				goto out;
		}
		i = 0;
		if (blocks_buf[b_index]) {
			pfn = pfn_from_vaddr(sbi, blocks_buf[b_index]);
			while (i++ < HMFS_BLOCK_SIZE_4K[blk_type]) {
				pages[f_index-pageoff] = pfn_to_page(pfn++);
				f_index++;	
			}
		} else {
			while (i++ < HMFS_BLOCK_SIZE_4K[blk_type]) {
				pages[f_index-pageoff] = sbi->map_zero_page;
				f_index++;
			}
		}

		b_index++;
	} while (f_index < index + count);

out:
	while (f_index < index + count) {
		pages[f_index-pageoff] = sbi->map_zero_page;
		f_index++;
	}
	return err;
}

int add_wp_node_info(struct hmfs_sb_info *sbi, struct node_info *ni) {
	loff_t pos = (loff_t)ni->index;
	struct inode *ino = hmfs_iget(sbi->sb, ni->ino);
	loff_t isize;
	int i;
	struct wp_nat_entry *wne;
	struct wp_data_page_entry *wdp;
	void *data;
	void *src = NULL;
	struct hmfs_inode_info *fi = HMFS_I(ino);
	unsigned int count = 0;
	unsigned char seg_type = fi->i_blk_type;
	const unsigned int block_size_bits = HMFS_BLOCK_SIZE_BITS(seg_type);
	struct db_info di;
	struct hmfs_node *hn = NULL;
	int err;
	block_t src_addr = 0;

	struct hmfs_summary *summary = NULL;
	summary = get_summary_by_addr(sbi, ni->blk_addr);
	if (get_summary_type(summary) == SUM_TYPE_DN) count = ADDRS_PER_BLOCK;
	else if (get_summary_type(summary) == SUM_TYPE_INODE) count = NORMAL_ADDRS_PER_INODE;
	
	di.inode = ino;

	isize = i_size_read(ino);
	isize = (( isize + ((1<<block_size_bits)-1) )>> block_size_bits);
	if (isize - pos < count) count = isize - pos;
	//hmfs_dbg("addwp count:%u pos:%llu isize:%llu\n",count,pos,isize);

	wne = search_wp_inode_entry(sbi->nm_info,ino);
	if (!wne) init_wp_inode_entry(sbi->nm_info,ino);

	for (i=(unsigned long)ni->index;i<((unsigned long)ni->index) + count;++i) {
		err = get_data_block_info(&di, i, LOOKUP);
		if (err) continue;

		hn = di.node_block;
		src_addr = read_address(hn, di.ofs_in_node, di.local);

		if (src_addr != 0) { src = ADDR(sbi, src_addr); }

		wdp = search_wp_data_block(sbi->nm_info,ino,i);
 		if (!wdp) add_wp_data_block(sbi->nm_info,ino,i,src);
		 
		wdp = search_wp_data_block(sbi->nm_info,ino,i);
		data = wdp->dp_addr;
		if(i<1000)
			hmfs_dbg("data [%d] in %llx: len:%u\n",i,(unsigned long long)(char*)data,(unsigned int)strlen((char*)data));
		if (!data) return ERR_WARP_WRITE_PRE;
	}
	return 0;
}

int clean_wp_node_info(struct hmfs_sb_info *sbi, struct node_info *ni) {
	loff_t pos = (loff_t)ni->index;
	struct inode *ino = hmfs_iget(sbi->sb, ni->ino);
	loff_t isize;
	int i;
	struct wp_nat_entry *wne;
	struct wp_data_page_entry *wdp;
	struct hmfs_inode_info *fi = HMFS_I(ino);
	unsigned int count = 0;
	unsigned char seg_type = fi->i_blk_type;
	const unsigned int block_size_bits = HMFS_BLOCK_SIZE_BITS(seg_type);
	struct hmfs_summary *summary = NULL;
	summary = get_summary_by_addr(sbi, ni->blk_addr);
	if (get_summary_type(summary) == SUM_TYPE_DN) count = ADDRS_PER_BLOCK;
	else if (get_summary_type(summary) == SUM_TYPE_INODE) count = NORMAL_ADDRS_PER_INODE;
	isize = i_size_read(ino);
	isize = (( isize + ((1<<block_size_bits)-1) )>> block_size_bits);
	if (isize - pos < count) count = isize - pos;
	//hmfs_dbg("delwp count:%u pos:%llu isize:%llu",count,pos,isize);

	wne = search_wp_inode_entry(sbi->nm_info,ino);
	if (!wne) return ERR_WARP_WRITE_POST;

	// Conservative solution here:
	// TODO: delay cleanup to checkpoint
	cleanup_wp_inode_entry(sbi, wne);

	for (i=(unsigned long)ni->index;i<((unsigned long)ni->index) + count;++i) {
		wdp = search_wp_data_block(sbi->nm_info,ino,i);
 		if (!wdp) continue;
		kfree(wdp->dp_addr);
		rb_erase(&wdp->node, &wne->rr);
		kfree(wdp);
	}
	return 0;
}

/*
int debug_test(struct inode *inode, struct file *filp) {
	struct wp_nat_entry *wne;
	struct wp_data_page_entry *wdp;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	void *data;
	int i;
	loff_t isize = i_size_read(inode);
	uint8_t blk_type = HMFS_I(inode)->i_blk_type;
	unsigned long long bits = HMFS_BLOCK_SIZE_BITS(blk_type);
	unsigned long long page_bits = 1<<bits;
	unsigned long long page_size = (unsigned long long)(page_bits -1 + (unsigned long long)isize) >> bits;
	if (sbi->cm_info->new_version<300) return 0;
	hmfs_dbg("----------Entering debug test---------\n");
	hmfs_dbg("page_size:%llu,blk_type:%d,isize:%llu,bits:%llu\n",page_size,blk_type,isize,bits);
		
	for (i=0;i<page_size;++i) {
		wne = search_wp_inode_entry(sbi->nm_info,inode);
		if (!wne) init_wp_inode_entry(sbi->nm_info,inode);
		wdp = search_wp_data_block(sbi->nm_info,inode,i);
 		if (!wdp) add_wp_data_block(sbi->nm_info,inode,i,NULL);
		wdp = search_wp_data_block(sbi->nm_info,inode,i);
		data = wdp->dp_addr;
		hmfs_dbg("data [%d] in %llx: len:%u\n",i,(unsigned long long)(char*)data,(unsigned int)strlen((char*)data));
		hmfs_dbg("%s\n",(char*)data);
	}

	hmfs_dbg("----------Leaving debug test----------\n");
	return 0;
}
*/

/* 
 * Open file for hmfs, if it's a read-only file, then remap it into 
 * VMALLOC area to accelerate reading
 */
//  This could be improved to select frequently read files (not only ro) by Prediction.
int hmfs_file_open(struct inode *inode, struct file *filp)
{
	int ret;
	struct hmfs_inode_info *fi = HMFS_I(inode);
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	// ktime_t kt = ktime_get();

	hmfs_dbg("Open inode:%lu\n", filp->f_inode->i_ino);
	ret = generic_file_open(inode, filp);

	// hmfs_dbg("Time %llu\n", kt.tv64);
	// hmfs_dbg("Time %llu\n", kt.tv64);

        getPpath(current);
	nm_i->last_visited_type = FLAG_WARP_NORMAL;

	// debug_test(inode, filp);
	// vmap_file_read_only(inode,0,1);

	if (ret || is_inline_inode(inode))
		return ret;

	//FIXME:
	// Invoke Prediction and calls vmap.
	return ret;
	if (atomic_add_return(1, &fi->nr_open) != 1) {
		return 0;
	}
	inode_write_lock(inode);
	
		/* Data have been mapped into kernel space */
	if (fi->rw_addr) {
		hmfs_bug_on(HMFS_I_SB(inode), !fi->block_bitmap);
		goto out;
	}

	hmfs_bug_on(HMFS_I_SB(inode), fi->block_bitmap);
	

	// Originally used for mapping in goku version
	// vmap_file_range(inode);
out:
	inode_write_unlock(inode);
	return 0;
}

static int hmfs_release_file(struct inode *inode, struct file *filp)
{
	int ret = 0;
	struct hmfs_inode_info *fi = HMFS_I(inode);

	hmfs_dbg("Release inode:%lu\n", filp->f_inode->i_ino);

	/* FIXME: Is the value of i_count correct */
	// To active long term mapping in kernel virtual address space, remove the code below
	if (!atomic_sub_return(1, &fi->nr_open)) {
		//TODO: Use lazy free
		unsigned char *bitmap = fi->block_bitmap;
		void *rw_addr = fi->rw_addr;
		uint64_t nr_map_page = fi->nr_map_page;

		inode_write_lock(inode);
		fi->rw_addr = NULL;
		fi->block_bitmap = NULL;
		fi->nr_map_page = 0;
		inode_write_unlock(inode);
		
		if (bitmap)
			kfree(bitmap);
		if (rw_addr)
			vm_unmap_ram(rw_addr, nr_map_page);
	}
	// TODO: Consistency
	// Unmap should be done elsewhere (ie. WARP switch)
	// if ( is_partially_mapped_inode(inode) || is_fully_mapped_inode(inode)) unmap_file_read_only(inode);

	// hmfs_dbg("[After release] Addr:%llx PageNumber:%llu\n", (unsigned long long)fi->rw_addr, (unsigned long long)fi->nr_map_page);

	if (is_inode_flag_set(fi, FI_DIRTY_INODE))
		ret = sync_hmfs_inode(inode, false);
	else if (is_inode_flag_set(fi, FI_DIRTY_SIZE))
		ret = sync_hmfs_inode_size(inode, false);
	else if (is_inode_flag_set(fi, FI_DIRTY_PROC))
		ret = sync_hmfs_inode_proc(inode, false);


	return ret;
}

static ssize_t hmfs_file_fast_read(struct file *filp, char __user *buf,
				size_t len, loff_t *ppos)
{
	struct inode *inode = filp->f_inode;
	loff_t isize = i_size_read(inode);
	size_t copied = len;
	unsigned long left;
	int err = 0;
	loff_t pos = *ppos;

	if (*ppos + len > isize)
		copied = isize - *ppos;

	if (!copied)
		return 0;

	inode_read_unlock(inode);

	left = __copy_to_user(buf, HMFS_I(inode)->rw_addr + pos, copied);
	inode_read_lock(inode);

	if (left == copied)
		err = -EFAULT;

	*ppos = *ppos + copied;
	return err ? err : copied - left;
}

static ssize_t hmfs_xip_file_read(struct file *filp, char __user *buf,
				size_t len, loff_t *ppos)
{
	// hmfs_dbg("Time A %llu\n", ktime_get().tv64);
	int ret = 0;	

	struct inode *inode = filp->f_inode;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	
	// debug display
	struct hmfs_inode_info *fi = HMFS_I(inode);
	uint8_t blk_type = fi->i_blk_type;
	pgoff_t pgstart = 0;
	pgstart = *ppos >> HMFS_BLOCK_SIZE_BITS(blk_type);

	nm_i->last_visited_type = FLAG_WARP_READ;
	// hmfs_dbg("hmfs_xip_file_read() Inode:%lu, len:%lu, ppos:%lld\n", filp->f_inode->i_ino, len, *ppos);

	/* Full mapping */
	// vmap_file_read_only(filp->f_inode,0,0);
	/* Partial mapping (block API and byte API, byte API is recommended)*/
	// vmap_file_read_only(filp->f_inode,0,i_size_read(filp->f_inode)>> HMFS_BLOCK_SIZE_BITS(blk_type));
	// ret=vmap_file_read_only_byte(filp->f_inode,*ppos,len);
	// if (ret==0) hmfs_dbg("hmfs_xip_file_read() Successfully mapped\n");
	// if (ret==1) hmfs_dbg("hmfs_xip_file_read() Not successfully mapped\n");
	// if (ret==2) hmfs_dbg("hmfs_xip_file_read() No mapping at all\n");
	
	inode_read_lock(filp->f_inode);
	if (!i_size_read(filp->f_inode))
		goto out;

	// if (likely(HMFS_I(filp->f_inode)->rw_addr) && !is_inline_inode(filp->f_inode)){
	
	//hmfs_dbg("[Read] Inode:%lu node No.%lu\n", filp->f_inode->i_ino, pgstart);
	ret = __hmfs_xip_file_read(filp, buf, len, ppos);

	if (false) 	ret = hmfs_file_fast_read(filp, buf, len, ppos);
	// This is the original entrance for read
	// File can only be either fully/partially mapped or no mapping at all
	/*
	if ( (is_fully_mapped_inode(filp->f_inode) || is_partially_mapped_inode(filp->f_inode)) && !is_inline_inode(filp->f_inode)){
		if (is_fully_mapped_inode(filp->f_inode)) hmfs_dbg("[Full read] Inode:%lu\n", filp->f_inode->i_ino);
		if (is_partially_mapped_inode(filp->f_inode)) hmfs_dbg("[Partial read] Inode:%lu node No.%lu\n", filp->f_inode->i_ino, pgstart);
		ret = hmfs_file_fast_read(filp, buf, len, ppos);
		}
	else{
		// hmfs_dbg("[Normal read] Inode:%lu\n", filp->f_inode->i_ino);
		hmfs_dbg("[Normal read] Inode:%lu node No.%lu\n", filp->f_inode->i_ino, pgstart);
		ret = __hmfs_xip_file_read(filp, buf, len, ppos);
	}
	*/

	if(!sbi->turn_off_warp) hmfs_warp_type_range_update(filp, len, ppos, FLAG_WARP_READ);
out:
	inode_read_unlock(filp->f_inode);

	// hmfs_dbg("Time F %llu\n", ktime_get().tv64);
	return ret;
}

static ssize_t __hmfs_xip_file_write(struct inode *inode, const char __user *buf,
				size_t count, loff_t *ppos)
{
	// struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	loff_t pos = *ppos;
	long status = 0;
	size_t bytes;
	ssize_t written = 0;
	struct hmfs_inode *inode_block;
	unsigned char seg_type = HMFS_I(inode)->i_blk_type;
	const unsigned long long block_size = HMFS_BLOCK_SIZE[seg_type];
	const unsigned int block_size_bits = HMFS_BLOCK_SIZE_BITS(seg_type);
	const unsigned long long block_ofs_mask = block_size - 1;

	if (is_inline_inode(inode)) {
		if (pos + count > HMFS_INLINE_SIZE) {
			status = hmfs_convert_inline_inode(inode);
			if (status) {
				goto out;
			}
			goto normal_write;
		}
		// write a new inode
		inode_block = alloc_new_node(HMFS_I_SB(inode), inode->i_ino, inode,
							SUM_TYPE_INODE, false);
		if (IS_ERR(inode_block)) {
			status = PTR_ERR(inode_block);
			goto out;
		}
		written = count - __copy_from_user_nocache((__u8 *)inode_block->inline_content 
								+ pos, buf, count);
		if (unlikely(written != count)) {
			status = -EFAULT;
			written = 0;
		} else {
			pos += count;
		}
		goto out;
	}

normal_write:
	/*
	 *	WARP write - Block size
	 *	Devide normal write into 4 types (write in #, from pw_start to page_size-pw_end)
	 *	Type A: ####_
	 *	Type B: _####
	 *	Type C: _###_
	 *	Type D: #####
	 */ 
	/*
	 * 	WARP write - DRAM cache
	 *	Normal write:	If wdp exists, write to wdp.
	 *					If not, commence full write procedure.
	 *	Write back:		Commence full write procedure, use the page of wdg instead of buf.
	 */
	do {
		unsigned long index;
		unsigned long offset;

		size_t copied;
		void *xip_mem;

		offset = pos & block_ofs_mask;
		index = pos >> block_size_bits;
		bytes = block_size - offset;
		if (bytes > count)
			bytes = count;
			
		// return the destination of TRUE write
		xip_mem = pw_alloc_new_data_block(inode, index, offset, block_size-offset-bytes, NORMAL);
		// xip_mem = alloc_new_data_block(sbi, inode, index);
		if (unlikely(IS_ERR(xip_mem))) {
			status = -ENOSPC;
			break;
		}

		/* To avoid deadlock between fi->i_lock and mm->mmap_sem in mmap */
		inode_write_unlock(inode);
		copied = bytes - __copy_from_user_nocache(xip_mem + offset,	buf, bytes);
		// if (index>460 && index<470)hmfs_dbg("index:%ld offset:%ld buf:%p\n",index,offset,xip_mem + offset);
		// if (index>972 && index<982)hmfs_dbg("index:%ld offset:%ld buf:%p\n",index,offset,xip_mem + offset);
		inode_write_lock(inode);

		if (likely(copied > 0)) {
			status = copied;

			if (status >= 0) {
				written += status;
				count -= status;
				pos += status;
				buf += status;
			}
		}
		if (unlikely(copied != bytes))
			if (status >= 0)
				status = -EFAULT;
		if (status < 0)
			break;
	} while (count);
out:
	*ppos = pos;

	if (pos > inode->i_size) {
		mark_size_dirty(inode, pos);
	}
	return written ? written : status;
}

void* hmfs_wp_wdp_write_back(struct inode *inode, struct wp_data_page_entry *wdp) {
	uint8_t blk_type = HMFS_I(inode)->i_blk_type;
	size_t page_size = 1 << HMFS_BLOCK_SIZE_BITS(blk_type);
	void *xip_mem;
	xip_mem = pw_alloc_new_data_block(inode, wdp->index, 0, 0, WRITEBACK);
	// No metadata operation, therefore no lock is needed here
	return memcpy(xip_mem,wdp->dp_addr,page_size);
}

void* hmfs_wp_data_block_write_back(struct inode *inode, int index) {
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	struct wp_data_page_entry *wdp;
	wdp = search_wp_data_block(sbi->nm_info, inode, index);
	if ( wdp==NULL ) return ERR_PTR(-ENOENT);
	return hmfs_wp_wdp_write_back(inode, wdp);
}


static ssize_t hmfs_file_fast_write(struct inode *inode, const char __user *buf,
				size_t len, loff_t *ppos)
{
	struct hmfs_inode_info *fi = HMFS_I(inode);
	uint8_t seg_type = fi->i_blk_type;
	uint64_t start = *ppos >> HMFS_BLOCK_SIZE_BITS(seg_type);
	uint64_t end = (*ppos + len + HMFS_BLOCK_SIZE[seg_type] - 1) >> HMFS_BLOCK_SIZE_BITS(seg_type);
	size_t copied;
	unsigned long rw_addr;

retry:
	if (end >= (fi->nr_map_page >> (HMFS_BLOCK_SIZE_BITS(seg_type) - PAGE_SHIFT))) {
		if (!vmap_file_range(inode))
			goto retry;
		else
			return __hmfs_xip_file_write(inode, buf, len, ppos);
	}

	//TODO: allocate ahead
	start &= ~7;
	rw_addr = ((unsigned long) fi->rw_addr) + (start << PAGE_SHIFT);
	while (start < end) {
		if (fi->block_bitmap[start >> 3] != 0xff) {
			int i = start;
			int ret;
			
			while ((((unsigned char)fi->block_bitmap[start >> 3]) >> (i - start)) & 1)
				i++;
			if (i - start >= 8 || i >= end)
				goto next_8;

			ret = remap_data_blocks_for_write(inode, rw_addr + ((i - start) << PAGE_SHIFT),
					i, start + 8 < end ? start + 8 : end);
			if (ret == -ENOMEM)
				return __hmfs_xip_file_write(inode, buf, len, ppos);
			else if (ret)
				return ret;
			if (start + 8 <= end)
				fi->block_bitmap[start >> 3] = 0xff;
			else {
				fi->block_bitmap[start >> 3] |= (1 << (end - start)) - 1;
			}
		}
next_8:
		start += 8;
		rw_addr += 8 << PAGE_SHIFT;
	}

	copied = len - __copy_from_user_nocache(fi->rw_addr + *ppos, buf, len);
	*ppos += copied;
	
	if (*ppos > inode->i_size)
		mark_size_dirty(inode, *ppos);
	return copied ? copied : -EFAULT;
}

/**
 * hmfs_file_llseek - llseek implementation for in-memory files
 * @file:	file structure to seek on
 * @offset:	file offset to seek to
 * @whence:	type of seek
 *
 * This is a generic implemenation of ->llseek useable for all normal local
 * filesystems.  It just updates the file offset to the value specified by
 * @offset and @whence.
 */
loff_t hmfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;
	int ret;
	loff_t maxsize = inode->i_sb->s_maxbytes;
	loff_t eof = i_size_read(inode);
	unsigned pg_index, end_blk;
	unsigned char seg_type = HMFS_I(inode)->i_blk_type;
	const unsigned long long block_size = HMFS_BLOCK_SIZE[seg_type];
	const unsigned int block_size_bits = HMFS_BLOCK_SIZE_BITS(seg_type);

	mutex_lock(&inode->i_mutex);

	end_blk = (eof + block_size - 1) >> block_size_bits;

	switch (whence) {
	case SEEK_END:		
		/* size of the file plus offset [bytes] */
		offset += eof;
		break;
	case SEEK_CUR:
		/* current location plus offset [bytes] */
		spin_lock(&file->f_lock);
		offset = vfs_setpos(file, file->f_pos + offset, maxsize);
		spin_unlock(&file->f_lock);
		ret = offset;
		goto out;
	case SEEK_DATA:	
		/* move to position of data where >= offset */
		if (offset >= eof) {
			ret = -ENXIO;
			goto out;
		}
		if (is_inline_inode(inode)) {
			offset = 0;
			break;
		}
		pg_index = hmfs_file_seek_hole_data(inode, end_blk, offset, SEEK_DATA);
		offset = pg_index << block_size_bits;
		break;
	case SEEK_HOLE:
		/*
		 * There is a virtual hole at the end of the file, so as long as
		 * offset isn't i_size or larger, return i_size.
		 */
		if (offset >= eof) {
			ret = -ENXIO;
			goto out;
		}
		if (is_inline_inode(inode)) {
			offset = eof;
			break;
		}
		pg_index = hmfs_file_seek_hole_data(inode, end_blk, offset, SEEK_HOLE);
		offset = pg_index << block_size_bits;
		break;
	}

	ret = vfs_setpos(file, offset, maxsize);
out:
	mutex_unlock(&inode->i_mutex);
	return ret;
}

ssize_t hmfs_xip_file_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = filp->f_inode;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	size_t count = 0, ret;
	loff_t pos;
	int ilock;

	struct hmfs_nm_info *nm_i = NM_I(sbi);
	nm_i->last_visited_type = FLAG_WARP_WRITE;


	if (!access_ok(VERIFY_READ, buf, len)) {
		ret = -EFAULT;
		goto out_up;
	}

	pos = *ppos;
	count = len;

	current->backing_dev_info = mapping->backing_dev_info;

	ret = generic_write_checks(filp, &pos, &count, S_ISBLK(inode->i_mode));

	if (ret)
		goto out_backing;

	if (count == 0)
		goto out_backing;

	ret = file_remove_suid(filp);
	if (ret)
		goto out_backing;
	// Duplicate with the later two lines of code
	ret = file_update_time(filp);
	if (ret)
		goto out_backing;

	inode->i_ctime = inode->i_mtime = CURRENT_TIME_SEC;

	mark_inode_dirty(inode);

	ilock = mutex_lock_op(sbi);
	inode_write_lock(inode);

	// Normal write only for now (probably for a long time)
	if (true) ret = __hmfs_xip_file_write(inode, buf, count, ppos);
	else ret = hmfs_file_fast_write(inode, buf, count, ppos);

	// if (likely(HMFS_I(inode)->rw_addr) && !is_inline_inode(inode))
	// 	ret = hmfs_file_fast_write(inode, buf, count, ppos);
	// else {
	// 	ret = __hmfs_xip_file_write(inode, buf, count, ppos);
	// }

	inode_write_unlock(inode);
	mutex_unlock_op(sbi, ilock);

	if(!sbi->turn_off_warp) hmfs_warp_type_range_update(filp, len, ppos, FLAG_WARP_WRITE);
out_backing:
	current->backing_dev_info = NULL;
out_up:
	return ret;
}

/* dn->node_block should be writable */
int truncate_data_blocks_range(struct db_info *di, int count)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(di->inode);
	int nr_free = 0, ofs = di->ofs_in_node;
	block_t addr;
	uint8_t seg_type = HMFS_I(di->inode)->i_blk_type;

	for (; count > 0; count--, ofs++) {
		if (di->local)
			addr = le64_to_cpu(di->node_block->i.i_addr[ofs]);
		else
			addr = le64_to_cpu(di->node_block->dn.addr[ofs]);

		if (addr == 0)
			continue;

		nr_free += invalidate_delete_block(sbi, addr, HMFS_BLOCK_SIZE_4K[seg_type]);

		if (di->local)
			di->node_block->i.i_addr[ofs] = 0;
		else
			di->node_block->dn.addr[ofs] = 0;
	}

	if (nr_free) {
		struct allocator *allocator = ALLOCATOR(sbi, seg_type);

		allocator->nr_cur_invalid += nr_free >> HMFS_BLOCK_SIZE_4K_BITS[seg_type];
		dec_valid_block_count(sbi, di->inode, nr_free);
		mark_inode_dirty(di->inode);
	}

	return nr_free;
}

/*
 * Because we truncate whole direct node, we don't mark the
 * addr in direct node. Instead, we set the address of direct node
 * in its parent indirect node to be 0
 */
int truncate_data_blocks(struct db_info *di)
{
	struct direct_node *node_block = &di->node_block->dn;
	struct hmfs_sb_info *sbi = HMFS_I_SB(di->inode);
	int count = ADDRS_PER_BLOCK;
	int nr_free = 0, ofs = 0;
	__le64 *entry = node_block->addr;
	uint8_t seg_type = HMFS_I(di->inode)->i_blk_type;

	for (; ofs < ADDRS_PER_BLOCK; ofs++, count--, entry++) {
		if (*entry != 0) {
			nr_free += invalidate_delete_block(sbi, le64_to_cpu(*entry),
							HMFS_BLOCK_SIZE_4K[seg_type]);
		}
	}

	if (nr_free) {
		/* It's better to update allocator->nr_cur_invalid outside 
		 * the function invalidate_delete_block, because updating
		 * member nr_cur_invalid is not atomic. We could reduce the probability
		 * of hazard by reducing writing to it.
		 */
		struct allocator *allocator = ALLOCATOR(sbi, seg_type);

		allocator->nr_cur_invalid += nr_free >> HMFS_BLOCK_SIZE_4K_BITS[seg_type];
		dec_valid_block_count(sbi, di->inode, nr_free);
		mark_inode_dirty(di->inode);
	}
	return nr_free;
}

static int truncate_blocks(struct inode *inode, loff_t from)
{
	struct hmfs_inode *inode_block;

	if (is_inline_inode(inode)) {
		inode_block = alloc_new_node(HMFS_I_SB(inode), inode->i_ino,
							inode, SUM_TYPE_INODE, false);
		if (IS_ERR(inode_block))
			return PTR_ERR(inode_block);
		memset((__u8 *)inode_block->inline_content, 0, HMFS_INLINE_SIZE - from);
		return 0;
	}

	return truncate_inode_blocks(inode, from);
}

void hmfs_truncate(struct inode *inode)
{
	if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) || S_ISLNK(inode->i_mode)))
		return;

	if (!truncate_blocks(inode, i_size_read(inode))) {
		inode->i_mtime = inode->i_ctime = CURRENT_TIME;
		mark_inode_dirty(inode);
	}

	start_bc(HMFS_I_SB(inode));
}

int truncate_hole(struct inode *inode, pgoff_t start, pgoff_t end)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	int err;
	struct db_info di;
	uint8_t sum_type;
	int count;

	di.inode = inode;
	while (start < end) {
		err = get_data_block_info(&di, start, LOOKUP);
		if (err) {
			if (err == -ENODATA)
				continue;
			return err;
		}

		if (di.local) {
			sum_type = SUM_TYPE_INODE;
			count = NORMAL_ADDRS_PER_INODE - di.ofs_in_node;
		} else {
			sum_type = SUM_TYPE_DN;
			count = ADDRS_PER_BLOCK - di.ofs_in_node;
		}
		di.node_block = alloc_new_node(sbi, di.nid, inode, sum_type, false);
		if (IS_ERR(di.node_block))
			return PTR_ERR(di.node_block);
		
		if (count > end - start)
			count = end - start;

		truncate_data_blocks_range(&di, count);
		start += count;
	}
	return 0;
}

static void fill_zero(struct inode *inode, pgoff_t index, loff_t start, loff_t len)
{
	void *data_block;
	if (!len)
		return;

	data_block = alloc_new_data_block(HMFS_I_SB(inode), inode, index);
	if (IS_ERR(data_block))
		return;
	memset(data_block + start, 0, len);
}

static int punch_hole(struct inode *inode, loff_t offset, loff_t len, int mode)
{
	pgoff_t pg_start, pg_end;
	loff_t off_start, off_end;
	loff_t blk_start, blk_end;
	int ret = 0;
	const uint8_t seg_type = HMFS_I(inode)->i_blk_type;
	const uint8_t block_size_bits = HMFS_BLOCK_SIZE_BITS(seg_type);
	const uint64_t block_size = HMFS_BLOCK_SIZE[seg_type];

	pg_start = offset >> block_size_bits;
	pg_end = (offset + len) >> block_size_bits;
	off_start = offset & (block_size - 1);
	off_end = (offset + len) & (block_size - 1);

	if (is_inline_inode(inode)) {
		if (offset + len > HMFS_INLINE_SIZE) {
			ret = hmfs_convert_inline_inode(inode);
			if (ret)
				return ret;
			goto punch;
		}
		/* 
		 * We don't need to memset 0 of inode->inline_content. Because 
		 * it has been initialized when creating
		 */
		goto out;
	}

punch:
	if (pg_start == pg_end) {
		fill_zero(inode, pg_start, off_start, off_end - off_start);
	} else {
		if (off_start)
			fill_zero(inode, pg_start++, off_start, block_size - off_start);
		if (off_end)
			fill_zero(inode, pg_end, 0, off_end);

		if (pg_start < pg_end) {
			blk_start = pg_start << block_size_bits;
			blk_end = pg_end << block_size_bits;

			ret = truncate_hole(inode, pg_start, pg_end);
		}
	}

out:
	if (!(mode & FALLOC_FL_KEEP_SIZE) && i_size_read(inode) <= (offset + len)) {
		mark_size_dirty(inode, offset + len);
	}

	return ret;
}

static int expand_inode_data(struct inode *inode, loff_t offset, loff_t len, int mode)
{
	pgoff_t index, pg_start, pg_end;
	loff_t new_size = i_size_read(inode);
	loff_t off_start, off_end;
	struct db_info di;
	int ret;
	const uint8_t seg_type = HMFS_I(inode)->i_blk_type;
	const uint8_t block_size_bits = HMFS_BLOCK_SIZE_BITS(seg_type);
	const uint64_t block_size = HMFS_BLOCK_SIZE[seg_type];

	ret = inode_newsize_ok(inode, (len + offset));
	if (ret)
		return ret;

	pg_start = offset >> block_size_bits;
	pg_end = (offset + len) >> block_size_bits;

	off_start = offset & (block_size - 1);
	off_end = (offset + len) & (block_size - 1);

	if (is_inline_inode(inode)) {
		if (offset + len > HMFS_INLINE_SIZE) {
			ret = hmfs_convert_inline_inode(inode);
			if (ret)
				return ret;
			goto expand;
		}
		/* If it's inline inode, we don;t need to memset 0 */
		goto out;
	}

expand:
	di.inode = inode;
	index = NORMAL_ADDRS_PER_INODE;
	while (index <= pg_end) {
		ret = get_data_block_info(&di, index, ALLOC);
		if (ret)
			break;
		index += ADDRS_PER_BLOCK;
	}

	if (index > pg_end)
		index = pg_end;
	if (pg_start == pg_end)
		new_size = offset + len;
	else if (index == pg_end)
		new_size = (pg_end << block_size_bits) + off_end;
	else
		new_size = index << block_size_bits;

out:
	if (!(mode & FALLOC_FL_KEEP_SIZE) && i_size_read(inode) < new_size) {
		mark_size_dirty(inode, new_size);
	}

	return ret;
}

static int hmfs_get_mmap_block(struct inode *inode, pgoff_t index, 
				unsigned long *pfn, int vm_type)
{
	void *data_block;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	block_t data_block_addr;

//	if (vm_type & VM_WRITE) {
		data_block = alloc_new_data_block(sbi, inode, index);
		if (IS_ERR(data_block))
			return PTR_ERR(data_block);
/*	} else {
		hmfs_bug_on(sbi, !(vm_type & VM_READ));
		data_block = get_data_block(inode, index);

		if (IS_ERR(data_block) && PTR_ERR(data_block) != -ENODATA)
			return PTR_ERR(data_block);
*/
		/* A hole in file */
/*		if (IS_ERR(data_block)) {
			*pfn = sbi->map_zero_page_number;
			goto out;
		}
	}
*/	data_block_addr = L_ADDR(sbi, data_block);
	*pfn = (sbi->phys_addr + data_block_addr) >> PAGE_SHIFT;
// out:
	return 0;
}

static void hmfs_filemap_close(struct vm_area_struct *vma)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	unsigned long pg_start, pg_end;
	unsigned long vm_start, vm_end;

	vm_start = vma->vm_start & PAGE_MASK;
	vm_end = vma->vm_end & PAGE_MASK;
	if (vm_end < vm_start)
		return;
	pg_start = vma->vm_pgoff;
	pg_end = ((vm_end - vm_start) >> PAGE_SHIFT) + pg_start;


	while (pg_start <= pg_end) {
		remove_mmap_block(sbi, vma->vm_mm, pg_start);
		pg_start++;
	}
}

int add_mmap_block(struct hmfs_sb_info *sbi, struct mm_struct *mm,
				unsigned long vaddr, unsigned long pgoff)
{
	struct hmfs_mmap_block *entry;

	entry = kmem_cache_alloc(mmap_block_slab, GFP_ATOMIC);
	if (!entry) {
		return -ENOMEM;
	}

	entry->mm = mm;
	entry->vaddr = vaddr;
	entry->pgoff = pgoff;
	INIT_LIST_HEAD(&entry->list);
	/* No check for duplicate */
	lock_mmap(sbi);
	list_add_tail(&entry->list, &sbi->mmap_block_list);
	unlock_mmap(sbi);
	return 0;
}

int remove_mmap_block(struct hmfs_sb_info *sbi, struct mm_struct *mm,
				unsigned long pgoff)
{
	struct hmfs_mmap_block *entry;
	struct list_head *head, *this, *next;
	
	head = &sbi->mmap_block_list;
	lock_mmap(sbi);
	list_for_each_safe(this, next, head) {
		entry = list_entry(this, struct hmfs_mmap_block, list);
		if (entry->mm == mm && entry->pgoff == pgoff) {
			list_del(&entry->list);
			kmem_cache_free(mmap_block_slab, entry);
		}
	}
	unlock_mmap(sbi);
	return 0;
}

int migrate_mmap_block(struct hmfs_sb_info *sbi)
{
	struct hmfs_mmap_block *entry;
	struct list_head *head, *this, *next;
	pte_t *pte;
	spinlock_t *ptl;

	head = &sbi->mmap_block_list;
	lock_mmap(sbi);
	list_for_each_safe(this, next, head) {
		entry = list_entry(this, struct hmfs_mmap_block, list);

		__cond_lock(ptl, pte = (*hmfs_get_locked_pte) (entry->mm, entry->vaddr,
									&ptl));

		if (!pte)
			goto free;
		if (pte_none(*pte))
			goto next;
		pte->pte = 0;
next:
		pte_unmap_unlock(pte, ptl);
free:
		list_del(&entry->list);
	}
	unlock_mmap(sbi);
	return 0;
}

static int hmfs_filemap_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;
	// struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	pgoff_t offset = vmf->pgoff, size;
	unsigned long pfn = 0;
	int err = 0;

	size = (i_size_read(inode) + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	if (offset >= size) {
		return VM_FAULT_SIGBUS;
	}

	inode_write_lock(inode);
	err = hmfs_get_mmap_block(inode, offset, &pfn, vma->vm_flags);
	inode_write_unlock(inode);
	if (unlikely(err)) {
		return VM_FAULT_SIGBUS;
	}

/*
	err = add_mmap_block(sbi, vma->vm_mm, (unsigned long)vmf->virtual_address,
				vmf->pgoff);
	if (err)
		return VM_FAULT_SIGBUS;
*/
	err = vm_insert_mixed(vma, (unsigned long)vmf->virtual_address, pfn);

	if (err == -ENOMEM) {
		return VM_FAULT_SIGBUS;
	}

	if (err != -EBUSY) {
		hmfs_bug_on(HMFS_I_SB(inode), err);
	}

	return VM_FAULT_NOPAGE;
}

static const struct vm_operations_struct hmfs_file_vm_ops = {
	.close = hmfs_filemap_close,
	.fault = hmfs_filemap_fault,
};

static int hmfs_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	file_accessed(file);
	vma->vm_flags |= VM_MIXEDMAP;
	vma->vm_ops = &hmfs_file_vm_ops;
	return 0;
}

int hmfs_sync_file(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file->f_mapping->host;
	struct hmfs_inode_info *fi = HMFS_I(inode);
	int ret = 0, ilock;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);

	if (hmfs_readonly(inode->i_sb))
		return 0;

	ilock = mutex_lock_op(sbi);
	inode_write_lock(inode);

	/* We don't need to sync data pages */
	if (is_inode_flag_set(fi, FI_DIRTY_INODE))
		ret = sync_hmfs_inode(inode, false);
	else if (is_inode_flag_set(fi, FI_DIRTY_SIZE))
		ret = sync_hmfs_inode_size(inode, false);
	else if (is_inode_flag_set(fi, FI_DIRTY_PROC))
		ret = sync_hmfs_inode_size(inode, false);

	inode_write_unlock(inode);
	mutex_unlock_op(sbi, ilock);

	return ret;
}

/* Pre-allocate space for file from offset to offset + len */
static long hmfs_fallocate(struct file *file, int mode, loff_t offset,
			   loff_t len)
{
	struct inode *inode = file_inode(file);
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	long ret = 0;
	int ilock;

	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE))
		return -EOPNOTSUPP;

	if (S_ISDIR(inode->i_mode))
		return -ENODEV;

	ilock = mutex_lock_op(sbi);
	inode_write_lock(inode);
	if (mode & FALLOC_FL_PUNCH_HOLE)
		ret = punch_hole(inode, offset, len, mode);
	else
		ret = expand_inode_data(inode, offset, len, mode);
	inode_write_unlock(inode);
	mutex_unlock_op(sbi, ilock);

	if (!ret) {
		inode->i_mtime = inode->i_ctime = CURRENT_TIME;
		mark_inode_dirty(inode);
	}

	return ret;
}

#define HMFS_REG_FLMASK		(~(FS_DIRSYNC_FL | FS_TOPDIR_FL))
#define HMFS_OTHER_FLMASK	(FS_NODUMP_FL | FS_NOATIME_FL)

static inline __u32 hmfs_mask_flags(umode_t mode, __u32 flags)
{
	if (S_ISDIR(mode))
		return flags;
	else if (S_ISREG(mode))
		return flags & HMFS_REG_FLMASK;
	else 
		return flags & HMFS_OTHER_FLMASK;
}

long hmfs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct hmfs_inode_info *fi = HMFS_I(inode);
	unsigned int flags, oldflags;
	int ret;

	switch (cmd) {
	case HMFS_IOC_GETFLAGS:
		flags = fi->i_flags & FS_FL_USER_VISIBLE;
		return put_user(flags, (int __user *) arg);
	case HMFS_IOC_SETFLAGS:
		ret = mnt_want_write_file(filp);
		if (ret)
			return ret;

		if (!inode_owner_or_capable(inode)) {
			ret = -EACCES;
			goto out;
		}

		if (get_user(flags, (int __user *) arg)) {
			ret = -EFAULT;
			goto out;
		}

		flags = hmfs_mask_flags(inode->i_mode, flags);

		mutex_lock(&inode->i_mutex);

		oldflags = fi->i_flags;

		if ((flags ^ oldflags) & (FS_APPEND_FL | FS_IMMUTABLE_FL)) {
			if (!capable(CAP_LINUX_IMMUTABLE)) {
				mutex_unlock(&inode->i_mutex);
				ret = -EPERM;
				goto out;
			}
		}

		flags = flags & FS_FL_USER_MODIFIABLE;
		flags|= oldflags & ~FS_FL_USER_MODIFIABLE;
		fi->i_flags = flags;
		mutex_unlock(&inode->i_mutex);
		hmfs_set_inode_flags(inode);
		inode->i_ctime = CURRENT_TIME;
		mark_inode_dirty(inode);
out:
		mnt_drop_write_file(filp);
		return ret;
	case HMFS_IOC_GETVERSION:
		return put_user(inode->i_generation, (int __user *)arg);
	default:
		return -ENOTTY;
	}
}

#ifdef CONFIG_COMPAT
long hmfs_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case HMFS_IOC32_GETFLAGS:
		cmd = HMFS_IOC_GETFLAGS;
		break;
	case HMFS_IOC32_SETFLAGS:
		cmd = HMFS_IOC_SETFLAGS;
		break;
	case HMFS_IOC32_GETVERSION:
		cmd = HMFS_IOC_GETVERSION;
		break;
	default:
		return -ENOIOCTLCMD;
	}

	return hmfs_ioctl(file, cmd, (unsigned long) compat_ptr(arg));
}
#endif

const struct file_operations hmfs_file_operations = {
	.llseek = hmfs_file_llseek,
	.read = hmfs_xip_file_read,
	.write = hmfs_xip_file_write,
	//.aio_read       = xip_file_aio_read,
	//.aio_write      = xip_file_aio_write,
	.open = hmfs_file_open,
	.release = hmfs_release_file,
	.mmap = hmfs_file_mmap,
	.fsync = hmfs_sync_file,
	.fallocate = hmfs_fallocate,
	.unlocked_ioctl = hmfs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = hmfs_compat_ioctl,
#endif
};

const struct inode_operations hmfs_file_inode_operations = {
	.getattr = hmfs_getattr,
	.setattr = hmfs_setattr,
#ifdef CONFIG_HMFS_XATTR
	.setxattr = generic_setxattr,
	.getxattr = generic_getxattr,
	.listxattr = hmfs_listxattr,
	.removexattr = generic_removexattr,
#endif 
};

int create_mmap_struct_cache(void)
{
	mmap_block_slab = hmfs_kmem_cache_create("hmfs_mmap_block",
							sizeof(struct hmfs_mmap_block), NULL);
	if (!mmap_block_slab)
		return -ENOMEM;
	return 0;
}

void destroy_mmap_struct_cache(void)
{
	kmem_cache_destroy(mmap_block_slab);
}
