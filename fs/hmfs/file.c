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

#include "hmfs_fs.h"
#include "hmfs.h"
#include "util.h"

static struct kmem_cache *ro_file_address_cachep;

static unsigned int start_block(unsigned int i, int level)
{
	if (level)
		return i - ((i - NORMAL_ADDRS_PER_INODE) % ADDRS_PER_BLOCK);
	return 0;
}

/* Find the last index of data block which is meaningful*/
unsigned int hmfs_dir_seek_data_reverse(struct inode *dir, unsigned int end_blk)
{
	struct dnode_of_data dn;
	struct direct_node *direct_node = NULL;
	struct hmfs_inode *inode_block = NULL;
	int err, j;
	block_t addr;
	unsigned start_blk;

	set_new_dnode(&dn, dir, NULL, NULL, 0);
	while (end_blk >= 0) {
		dn.node_block = NULL;
		dn.nid = 0;
		err = get_dnode_of_data(&dn, end_blk, LOOKUP_NODE);
		if (err) {
			if (dn.level)
				end_blk = start_block(end_blk, dn.level) - 1;
			else
				hmfs_bug_on(HMFS_I_SB(dir), 1);
			continue;
		}
		start_blk = start_block(end_blk, dn.level);
		if (dn.level) {
			direct_node = dn.node_block;
			hmfs_bug_on(HMFS_I_SB(dir), !direct_node);

			for (j = end_blk - start_blk; j >= 0; j--) {
				addr = le64_to_cpu(direct_node->addr[j]);
				if (addr)
					return start_blk + j;
			}
		} else {
			inode_block = dn.inode_block;
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

static unsigned int hmfs_file_seek_hole_data(struct inode *inode, 
				unsigned int end_blk, unsigned int start_pos, char type)
{
	int i = start_pos >> HMFS_PAGE_SIZE_BITS, j = 0;
	struct dnode_of_data dn;
	struct direct_node *direct_node = NULL;
	struct hmfs_inode *inode_block = NULL;
	int err;
	unsigned start_blk = end_blk;
	block_t addr;

	set_new_dnode(&dn, inode, NULL, NULL, 0);
	while (i < end_blk) {
		dn.node_block = NULL;
		dn.nid = 0;
		err = get_dnode_of_data(&dn, i, LOOKUP_NODE);
		if (err) {
			if (type == SEEK_HOLE)
				return start_block(i, dn.level);
			if (dn.level)
				i = start_block(i, dn.level) + ADDRS_PER_BLOCK;
			else 
				hmfs_bug_on(HMFS_I_SB(inode), 1);
			continue;
		}
	
		start_blk = start_block(i, dn.level);
		if (dn.level) {
			direct_node = dn.node_block;
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
			inode_block = dn.inode_block;
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

static ssize_t __hmfs_xip_file_read(struct file *filp, char __user *buf,
				size_t len, loff_t *ppos)
{
	/* from do_XIP_mapping_read */
	struct inode *inode = filp->f_inode;
	pgoff_t index, end_index;
	unsigned long offset;
	loff_t isize, pos;
	size_t copied = 0, error = 0;

	pos = *ppos;
	index = pos >> HMFS_PAGE_SIZE_BITS;	
	offset = pos & ~HMFS_PAGE_MASK;

	isize = i_size_read(inode);
	end_index = (isize - 1) >> HMFS_PAGE_SIZE_BITS;
	/*
	 * nr : read length for this loop
	 * offset : start inner-blk offset this loop
	 * index : start inner-file blk number this loop
	 * copied : read length so far
	 * FIXME: pending for write_lock? anything like access_ok()
	 */

	do {
		unsigned long nr, left;
		void *xip_mem[1];
		int zero = 0;
		int size;

		/* nr is the maximum number of bytes to copy from this page */
		nr = HMFS_PAGE_SIZE;	//HMFS_SIZE
		if (index >= end_index) {
			if (index > end_index)
				goto out;
			nr = ((isize - 1) & ~HMFS_PAGE_MASK) + 1;
			if (nr <= offset) {
				goto out;
			}
		}
		nr = nr - offset;
		if (nr > len - copied)
			nr = len - copied;
		hmfs_bug_on(HMFS_I_SB(inode), nr > HMFS_PAGE_SIZE);
		error = get_data_blocks(inode, index, index + 1, xip_mem, 
						&size, RA_END);

		if (unlikely(error || size != 1)) {
			if (error == -ENODATA) {
				/* sparse */
				zero = 1;
			} else
				goto out;
		}

		/* copy to user space */
		if (!zero)
			left = __copy_to_user(buf + copied, xip_mem[0] + offset, nr);
		else
			left = __clear_user(buf + copied, nr);

		if (left) {
			error = -EFAULT;
			goto out;
		}
		copied += (nr - left);
		offset += (nr - left);
		index += offset >> HMFS_PAGE_SIZE_BITS;
		offset &= ~HMFS_PAGE_MASK;
	} while (copied < len);

out:
	*ppos = pos + copied;
	if (filp)
		file_accessed(filp);

	return (copied ? copied : error);
}

#ifdef CONFIG_HMFS_FAST_READ
static inline bool is_fast_read_file(struct ro_file_address *addr_struct)
{
	return addr_struct && (addr_struct->magic == HMFS_SUPER_MAGIC);
}

static struct ro_file_address *new_ro_file_address(void *addr)
{
	struct ro_file_address *addr_struct;

	addr_struct = kmem_cache_alloc(ro_file_address_cachep, GFP_KERNEL);

	if (addr_struct) {
		addr_struct->magic = HMFS_SUPER_MAGIC;
		addr_struct->start_addr = addr;
	}
	return addr_struct;
}

static void free_ro_file_address(struct file *filp)
{
	kmem_cache_free(ro_file_address_cachep, filp->private_data);
	filp->private_data = NULL;
}

static int remap_pte_file_range(struct inode *inode, pmd_t *pmd, 
				unsigned long addr, unsigned long end, void** blocks, 
				int *block_size, int *index)
{
	pte_t *pte;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	u64 pfn;
	int st_index;
	int err;

	pte = hmfs_pte_alloc_kernel(pmd, addr);
	if (!pte)
		return -ENOMEM;
	do {
		hmfs_bug_on(sbi, !pte_none(*pte));

		if (*index >= *block_size) {
			*block_size = 0;
			*index = 0;
			st_index = addr >> HMFS_PAGE_SIZE_BITS;
			hmfs_bug_on(sbi, st_index >= INT_MAX / 2);
			err = get_data_blocks(inode, st_index, INT_MAX / 2, blocks,
							block_size, RA_DB_END);
			if (!*block_size)
				return err;
		}
		if (blocks[*index])
			pfn = pfn_from_vaddr(sbi, blocks[*index]);
		else
			pfn = sbi->map_zero_page_number;
		set_pte_at(hmfs_init_mm, addr, pte, pfn_pte(pfn, PAGE_KERNEL_IO_NOCACHE));
		(*index) += 1;
	} while(pte++, addr += PAGE_SIZE, addr != end);
	return 0;
}

static int remap_pmd_file_range(struct inode *inode, pud_t *pud, 
				unsigned long addr, unsigned long end, void **blocks,
				int *block_size, int *index)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = hmfs_pmd_alloc(hmfs_init_mm, pud, addr);
	if (!pmd)
		return -ENOMEM;
	do {
		next = pmd_addr_end(addr, end);
		if (remap_pte_file_range(inode, pmd, addr, next, blocks, block_size,
								index))
			return -ENOMEM;
	} while(pmd++, addr = next, addr != end);
	return 0;
}

static int remap_pud_file_range(struct inode *inode, pgd_t *pgd,
				unsigned long addr, unsigned long end, void** blocks,
				int *block_size, int *index)
{
	pud_t *pud;
	unsigned long next;

	pud = hmfs_pud_alloc(hmfs_init_mm, pgd, addr);
	if (!pud)
		return -ENOMEM;
	do {
		next = pud_addr_end(addr, end);
		if (remap_pmd_file_range(inode, pud, addr, next, blocks, block_size, 
								index))
			return -ENOMEM;
	} while(pud++, addr = next, addr != end);
	return 0;
}

static int remap_ro_file_range(struct inode *inode, unsigned long addr,
				unsigned long end)
{
	pgd_t *pgd;
	unsigned long start, next;
	int err;
	void *blocks;
	struct page *page;
	int block_size, index;

	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	blocks = kmap(page);
	memset(blocks, 0, PAGE_CACHE_SIZE);
	block_size = 0;
	index = 0;
	start = addr;
	pgd = pgd_offset(hmfs_init_mm, (addr));

	
	do {
		next = pgd_addr_end(addr, end);
		err = remap_pud_file_range(inode, pgd, addr, next, (void **)blocks,
						&block_size, &index);
		if (err)
			break;
	} while(pgd++, addr = next, addr != end);

	flush_cache_vmap(start, end);

	kunmap(blocks);
	__free_page(page);
	return err;
}

/* 
 * Open file for hmfs, if it's a read-only file, then remap it into 
 * VMALLOC area to accelerate reading
 */
int hmfs_file_open(struct inode *inode, struct file *filp)
{
	int ret;
	unsigned long size;
	struct hmfs_inode_info *fi;
	struct vm_struct *area;
	unsigned vaddr;

	ret = generic_file_open(inode, filp);
	if (ret || (filp->f_flags & O_ACCMODE) != O_RDONLY)
		return ret;;

	if (filp->private_data)
		goto out;

	/* Do not map an empty file */
	size = i_size_read(inode);
	fi = HMFS_I(inode);
	if (!size || fi->read_addr)
		goto out;

	/* Search a VMALLOC area */
	size = PAGE_CACHE_ALIGN(size);
	area = hmfs_get_vm_area(size, VM_IOREMAP);
	if (!area)
		goto out;
	vaddr = (unsigned long) area->addr;

	ret = remap_ro_file_range(inode, vaddr, vaddr + size); 
	if (!ret)
		filp->private_data = new_ro_file_address(area->addr);
out:
	return ret;
}

static int hmfs_release_file(struct inode *inode, struct file *filp)
{
	int ret = 0;
	struct hmfs_inode_info *fi = HMFS_I(inode);
	struct ro_file_address *addr_struct = NULL;
	struct vm_struct *area;

	addr_struct = filp->private_data;
	if (is_fast_read_file(addr_struct)) {
		hmfs_bug_on(HMFS_I_SB(inode), (filp->f_flags & O_ACCMODE)
						!= O_RDONLY);

		/* 
		 * Use the vm area unlocked, assuming the caller unsures there isn't
		 * another iounmap for the same address in parallel. Reuse of the virtual
		 * address is prevented by leaving it in the global lists 
		 * until we're done with it.
		 */
		area = hmfs_find_vm_area((void __force *)addr_struct->start_addr);
		if (!area) {
			hmfs_bug_on(HMFS_I_SB(inode), 1);
			goto check_mmap;
		}
		
		/* Now, do it */
		area = hmfs_remove_vm_area((void __force *)addr_struct->start_addr);
		kfree(area);
		free_ro_file_address(filp);
	}

check_mmap:
	filemap_fdatawrite(inode->i_mapping);
	
	if (is_inode_flag_set(fi, FI_DIRTY_INODE))
		ret = sync_hmfs_inode(inode);
	else if (is_inode_flag_set(fi, FI_DIRTY_SIZE))
		ret = sync_hmfs_inode_size(inode);

	return ret;
}

static ssize_t hmfs_file_fast_read(struct file *filp, char __user *buf,
				size_t len, loff_t *ppos)
{
	loff_t isize = i_size_read(filp->f_inode);
	size_t copied = len;
	unsigned long left;
	struct ro_file_address *addr_struct = filp->private_data;
	int err = 0;

	if (*ppos + len > isize)
		copied = isize - *ppos;
	
	left = __copy_to_user(buf, addr_struct->start_addr, copied);

	if (left)
		err = -EFAULT;

	return err ? err : copied;
}

static ssize_t hmfs_xip_file_read(struct file *filp, char __user *buf,
				size_t len, loff_t *ppos)
{
	int ret = 0;

	mutex_lock(&filp->f_inode->i_mutex);

	if (!i_size_read(filp->f_inode))
		goto out;

	if (likely(!is_fast_read_file((struct ro_file_address *)
									filp->private_data)))
		ret = __hmfs_xip_file_read(filp, buf, len, ppos);
	else
		ret = hmfs_file_fast_read(filp, buf, len, ppos);

out:
	mutex_unlock(&filp->f_inode->i_mutex);
	return ret;
}

#else

static ssize_t hmfs_xip_file_read(struct file *filp, char __user *buf,
				size_t len, loff_t *ppos)
{
	int ret = 0;

	mutex_lock(&filp->f_inode->i_mutex);
	if (!i_size_read(filp->f_inode))
		goto out;

	ret = __hmfs_xip_file_read(filp, buf, len, ppos);

out:
	mutex_unlock(&filp->f_inode->i_mutex);
	return ret;
}

int hmfs_file_open(struct inode *inode, struct file *filp)
{
	return generic_file_open(inode, filp);
}

static int hmfs_release_file(struct inode *inode, struct file *filp)
{
	int ret = 0;
	struct hmfs_inode_info *fi = HMFS_I(inode);

	filemap_fdatawrite(inode->i_mapping);
	
	if (is_inode_flag_set(fi, FI_DIRTY_INODE))
		ret = sync_hmfs_inode(inode);
	else if (is_inode_flag_set(fi, FI_DIRTY_SIZE))
		ret = sync_hmfs_inode_size(inode);

	return ret;
}
#endif

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

	mutex_lock(&inode->i_mutex);

	end_blk = (eof + HMFS_PAGE_SIZE - 1) >> HMFS_PAGE_SIZE_BITS;

	switch (whence) {
	case SEEK_END:		//size of the file plus offset [bytes]
		offset += eof;
		break;
	case SEEK_CUR:		//current location plus offset [bytes] 
		//extra lseek(fd, 0, SEEK_CUR) can be used
		spin_lock(&file->f_lock);
		offset = vfs_setpos(file, file->f_pos + offset, maxsize);
		spin_unlock(&file->f_lock);
		ret = offset;
		goto out;
	case SEEK_DATA:	//move to data where data.offset >= offset
		if (offset >= eof) {
			ret = -ENXIO;
			goto out;
		}
		pg_index = hmfs_file_seek_hole_data(inode, end_blk, offset, SEEK_DATA);
		offset = pg_index << HMFS_PAGE_SIZE_BITS;
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
		pg_index = hmfs_file_seek_hole_data(inode, end_blk, offset, SEEK_HOLE);
		offset = pg_index << HMFS_PAGE_SIZE_BITS;
		break;
	}

	ret = vfs_setpos(file, offset, maxsize);	//FIXME:SEEK_HOLE/DATA/SET don't need lock?
out:
	mutex_unlock(&inode->i_mutex);
	return ret;
}

static ssize_t __hmfs_xip_file_write(struct file *filp, const char __user *buf,
				     size_t count, loff_t pos, loff_t *ppos)
{
	struct inode *inode = filp->f_inode;
	long status = 0;
	size_t bytes;
	ssize_t written = 0;

	//FIXME: file inode lock
	do {
		unsigned long index;
		unsigned long offset;
		size_t copied;
		void *xip_mem;

		offset = pos & ~HMFS_PAGE_MASK;
		index = pos >> HMFS_PAGE_SIZE_BITS;
		bytes = HMFS_PAGE_SIZE - offset;
		if (bytes > count)
			bytes = count;

		xip_mem = alloc_new_data_block(inode, index);
		if (unlikely(IS_ERR(xip_mem)))
			break;

		copied = bytes - __copy_from_user_nocache(xip_mem + offset, 
						buf, bytes);

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
	*ppos = pos;

	if (pos > inode->i_size) {
		mark_size_dirty(inode, pos);
	}
	return written ? written : status;

}

ssize_t hmfs_xip_file_write(struct file * filp, const char __user * buf,
			    size_t len, loff_t * ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = filp->f_inode;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	size_t count = 0, ret;
	loff_t pos;
	int ilock;

	mutex_lock(&inode->i_mutex);

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

	ret = file_update_time(filp);
	if (ret)
		goto out_backing;

	inode->i_ctime = inode->i_mtime = CURRENT_TIME_SEC;

	ilock = mutex_lock_op(sbi);
	ret = __hmfs_xip_file_write(filp, buf, count, pos, ppos);
	mutex_unlock_op(sbi, ilock);

	mark_inode_dirty(inode);
out_backing:
	current->backing_dev_info = NULL;
out_up:
	mutex_unlock(&inode->i_mutex);
	return ret;

}

/* dn->node_block should be writable */
int truncate_data_blocks_range(struct dnode_of_data *dn, int count)
{
	int nr_free = 0, ofs = dn->ofs_in_node;
	struct hmfs_sb_info *sbi = HMFS_I_SB(dn->inode);
	struct hmfs_node *raw_node = (struct hmfs_node *)dn->node_block;
	struct hmfs_node *new_node = NULL;
	block_t addr;
	struct hmfs_summary *node_sum = NULL;
	nid_t nid;
	char sum_type;

	node_sum = get_summary_by_addr(sbi, L_ADDR(sbi, raw_node));
	nid = get_summary_nid(node_sum);
	sum_type = dn->level ? SUM_TYPE_DN : SUM_TYPE_INODE;
	hmfs_bug_on(sbi, sum_type != get_summary_type(node_sum));
	new_node = alloc_new_node(sbi, nid, dn->inode, sum_type);

	if (IS_ERR(new_node))
		return PTR_ERR(new_node);
	for (; count > 0; count--, ofs++) {
		if (dn->level)
			addr = raw_node->dn.addr[ofs];
		else
			addr = raw_node->i.i_addr[ofs];

		if (addr == NULL_ADDR)
			continue;

		if (dn->level)
			new_node->dn.addr[ofs] = NULL_ADDR;
		else
			new_node->i.i_addr[ofs] = NULL_ADDR;

		nr_free++;
	}
	if (nr_free) {
		dec_valid_block_count(sbi, dn->inode, nr_free);
		mark_inode_dirty(dn->inode);
	}

	return nr_free;
}

void truncate_data_blocks(struct dnode_of_data *dn)
{
	truncate_data_blocks_range(dn, ADDRS_PER_BLOCK);
}

static void truncate_partial_data_page(struct inode *inode, block_t from)
{
	unsigned offset = from & (HMFS_PAGE_SIZE - 1);

	if (!offset)
		return;
	alloc_new_data_partial_block(inode, from >> HMFS_PAGE_SIZE_BITS, offset,
				     HMFS_PAGE_SIZE, true);
	return;
}

static int truncate_blocks(struct inode *inode, block_t from)
{
	struct dnode_of_data dn;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	int count, err;
	block_t free_from;
	int ilock;

	free_from = (from + HMFS_PAGE_SIZE - 1) >> HMFS_PAGE_SIZE_BITS;

	ilock = mutex_lock_op(sbi);

	set_new_dnode(&dn, inode, NULL, NULL, 0);
	err = get_dnode_of_data(&dn, free_from, LOOKUP_NODE);

	if (err) {
		goto free_next;
	}
	if (!dn.level)
		count = NORMAL_ADDRS_PER_INODE;
	else
		count = ADDRS_PER_BLOCK;

	count -= dn.ofs_in_node;
	hmfs_bug_on(sbi, count < 0);

	if (dn.ofs_in_node || !dn.level) {
		truncate_data_blocks_range(&dn, count);
		free_from += count;
	}

free_next:
	err = truncate_inode_blocks(inode, free_from);
	truncate_partial_data_page(inode, from);

	mutex_unlock_op(sbi, ilock);
	return err;
}

void hmfs_truncate(struct inode *inode)
{
	if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode)
	      || S_ISLNK(inode->i_mode)))
		return;

	if (!truncate_blocks(inode, i_size_read(inode))) {
		inode->i_mtime = inode->i_ctime = CURRENT_TIME;
		mark_inode_dirty(inode);
	}
}

int truncate_hole(struct inode *inode, pgoff_t start, pgoff_t end)
{
	pgoff_t index;
	int err;
	struct dnode_of_data dn;

	for (index = start; index < end; index++) {
		set_new_dnode(&dn, inode, NULL, NULL, 0);
		err = get_dnode_of_data(&dn, index, LOOKUP_NODE);
		if (err) {
			if (err == -ENODATA)
				continue;
			return err;
		}
		truncate_data_blocks_range(&dn, 1);
	}
	return 0;
}

static void fill_zero(struct inode *inode, pgoff_t index, loff_t start,
		      loff_t len)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	int ilock;

	if (!len)
		return;

	ilock = mutex_lock_op(sbi);
	alloc_new_data_partial_block(inode, index, start, start + len, true);
	mutex_unlock_op(sbi, ilock);
}

static int punch_hole(struct inode *inode, loff_t offset, loff_t len, int mode)
{
	pgoff_t pg_start, pg_end;
	loff_t off_start, off_end;
	loff_t blk_start, blk_end;
	int ret = 0, ilock;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);

	pg_start = ((unsigned long long) offset) >> HMFS_PAGE_SIZE_BITS;
	pg_end = ((unsigned long long) offset + len) >> HMFS_PAGE_SIZE_BITS;
	off_start = offset & (HMFS_PAGE_SIZE - 1);
	off_end = (offset + len) & (HMFS_PAGE_SIZE - 1);

	if (pg_start == pg_end) {
		fill_zero(inode, pg_start, off_start, off_end - off_start);
	} else {
		if (off_start)
			fill_zero(inode, pg_start++, off_start,
				  HMFS_PAGE_SIZE - off_start);
		if (off_end)
			fill_zero(inode, pg_end, 0, off_end);

		if (pg_start < pg_end) {
			blk_start = pg_start << HMFS_PAGE_SIZE_BITS;
			blk_end = pg_end << HMFS_PAGE_SIZE_BITS;
			//FIXME: need this in mmap?
			//truncate_inode_pages_range(inode,blk_start,blk_end);

			ilock = mutex_lock_op(sbi);
			ret = truncate_hole(inode, pg_start, pg_end);
			mutex_unlock_op(sbi, ilock);
		}
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE)
	    && i_size_read(inode) <= (offset + len)) {
		mark_size_dirty(inode, offset + len);
	}

	return ret;
}

static int expand_inode_data(struct inode *inode, loff_t offset, loff_t len,
			     int mode)
{
	pgoff_t index, pg_start, pg_end;
	loff_t new_size = i_size_read(inode);
	loff_t off_start, off_end;
	struct dnode_of_data dn;
	int ret, ilock;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);

	ret = inode_newsize_ok(inode, (len + offset));
	if (ret)
		return ret;

	pg_start = ((unsigned long long) offset) >> HMFS_PAGE_SIZE_BITS;
	pg_end = ((unsigned long long) offset + len) >> HMFS_PAGE_SIZE_BITS;

	off_start = offset & (HMFS_PAGE_SIZE - 1);
	off_end = (offset + len) & (HMFS_PAGE_SIZE - 1);

	for (index = pg_start; index <= pg_end; index++) {
		ilock = mutex_lock_op(sbi);
		set_new_dnode(&dn, inode, NULL, NULL, 0);

		ret = get_dnode_of_data(&dn, index, ALLOC_NODE);
		mutex_unlock_op(sbi, ilock);
		if (ret) {
			break;
		}

		if (pg_start == pg_end)
			new_size = offset + len;
		else if (index == pg_start && off_start)
			new_size = (index + 1) << HMFS_PAGE_SIZE_BITS;
		else if (index == pg_end)
			new_size = (index << HMFS_PAGE_SIZE_BITS) + off_end;
		else
			new_size += HMFS_PAGE_SIZE;
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE) && i_size_read(inode) < new_size) {
		mark_size_dirty(inode, new_size);
	}

	return ret;
}

static const struct vm_operations_struct hmfs_file_vm_ops = {
	.fault = filemap_fault,
};

static int hmfs_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	file_accessed(file);
	vma->vm_ops = &hmfs_file_vm_ops;
	return 0;
}

int hmfs_sync_file(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file->f_mapping->host;
	struct hmfs_inode_info *fi = HMFS_I(inode);
	int ret = 0;

	if (hmfs_readonly(inode->i_sb))
		return 0;

	ret = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (ret) 
		return ret;
	
	mutex_lock(&inode->i_mutex);

	/* We don't need to sync data pages */
	if (is_inode_flag_set(fi, FI_DIRTY_INODE))
		ret = sync_hmfs_inode(inode);
	else if (is_inode_flag_set(fi, FI_DIRTY_SIZE))
		ret = sync_hmfs_inode_size(inode);

	mutex_unlock(&inode->i_mutex);

	return ret;
}

//      Allocate space for file from offset to offset+len
static long hmfs_fallocate(struct file *file, int mode, loff_t offset,
			   loff_t len)
{
	struct inode *inode = file_inode(file);
	long ret = 0;

	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE))
		return -EOPNOTSUPP;

	if (S_ISDIR(inode->i_mode))
		return -ENODEV;
	if (mode & FALLOC_FL_PUNCH_HOLE)
		ret = punch_hole(inode, offset, len, mode);
	else
		ret = expand_inode_data(inode, offset, len, mode);

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

int init_ro_file_address_cache(void)
{
	ro_file_address_cachep = hmfs_kmem_cache_create("hmfs_ro_address_cache",
					sizeof(struct ro_file_address), NULL)	;
	if (!ro_file_address_cachep)
		return -ENOMEM;
	return 0;
}

void destroy_ro_file_address_cache(void)
{
	kmem_cache_destroy(ro_file_address_cachep);
}
