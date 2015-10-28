#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/falloc.h>
#include <linux/time.h>
#include <linux/stat.h>
#include <linux/fs.h>
#include "hmfs_fs.h"
#include "hmfs.h"

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

	mutex_lock(&inode->i_mutex);
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
		offset = eof;
		break;
	}

	ret = vfs_setpos(file, offset, maxsize);	//FIXME:SEEK_HOLE/DATA/SET don't need lock?
out:	mutex_unlock(&inode->i_mutex);
	return ret;
}

ssize_t hmfs_xip_file_read(struct file * filp, char __user * buf, size_t len,
			   loff_t * ppos)
{
	/* from do_XIP_mapping_read */
	struct inode *inode = filp->f_inode;
	pgoff_t index, end_index;
	unsigned long offset;
	loff_t isize, pos;
	size_t copied = 0, error = 0;

	pos = *ppos;
	index = pos >> HMFS_PAGE_SIZE_BITS;	//TODO: shift is HMFS_BLK_SHIFT
	offset = pos & ~HMFS_PAGE_MASK;	//^

	mutex_lock(&inode->i_mutex);
	isize = i_size_read(inode);
	if (!isize)
		goto out;

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
		BUG_ON(nr > HMFS_PAGE_SIZE);
		//TODO: get XIP by get inner-file blk_offset & look through NAT
		error =
		 get_data_blocks(inode, index, index + 1, xip_mem, &size,
				 RA_END);

		if (unlikely(error || size != 1)) {
			if (error == -ENODATA) {
				/* sparse */
				zero = 1;
			} else
				goto out;
		}

		/* copy to user space */
		if (!zero)
			left =
			 __copy_to_user(buf + copied, xip_mem[0] + offset, nr);
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
	mutex_unlock(&inode->i_mutex);
	*ppos = pos + copied;
	if (filp)
		file_accessed(filp);

	return (copied ? copied : error);
}

static ssize_t __hmfs_xip_file_write(struct file *filp, const char __user * buf,
				     size_t count, loff_t pos, loff_t * ppos)
{
	struct inode *inode = filp->f_inode;
	long status = 0;
	size_t bytes;
	ssize_t written = 0;

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

		copied =
		 bytes - __copy_from_user_nocache(xip_mem + offset, buf, bytes);

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
		i_size_write(inode, pos);
	}
	return written ? written : status;

}

ssize_t hmfs_xip_file_write(struct file * filp, const char __user * buf,
			    size_t len, loff_t * ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = filp->f_inode;
	struct hmfs_sb_info *sbi = HMFS_SB(inode->i_sb);
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

static void setup_summary_of_delete_block(struct hmfs_sb_info *sbi,
					  block_t blk_addr)
{
	struct hmfs_summary *sum;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	int count;

	sum = get_summary_by_addr(sbi, blk_addr);
	count = get_summary_count(sum) - 1;
	set_summary_count(sum, count);
	set_summary_dead_version(sum, cm_i->new_version);
#ifdef CONFIG_DEBUG
	BUG_ON(count < 0);
#endif

	if (!count) {
		invalidate_block_after_dc(sbi, blk_addr);
	}
}

/* dn->node_block should be writable */
int truncate_data_blocks_range(struct dnode_of_data *dn, int count)
{
	int nr_free = 0, ofs = dn->ofs_in_node;
	struct hmfs_sb_info *sbi = HMFS_SB(dn->inode->i_sb);
	struct hmfs_node *raw_node = (struct hmfs_node *)dn->node_block;
	struct hmfs_node *new_node = NULL;
	void *data_blk;
	block_t addr;
	nid_t nid;
	char sum_type;

	nid = le32_to_cpu(raw_node->footer.nid);
	sum_type = dn->level ? SUM_TYPE_DN : SUM_TYPE_INODE;
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
		BUG_ON(addr == FREE_ADDR || addr == NEW_ADDR);
		data_blk = ADDR(sbi, addr);
		if (dn->level)
			new_node->dn.addr[ofs] = NULL_ADDR;
		else
			new_node->i.i_addr[ofs] = NULL_ADDR;

		setup_summary_of_delete_block(sbi, addr);
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

static void truncate_partial_data_page(struct inode *inode, u64 from)
{
	unsigned offset = from & (HMFS_PAGE_SIZE - 1);

	if (!offset)
		return;
	alloc_new_data_partial_block(inode, from >> HMFS_PAGE_SIZE_BITS, offset,
				     HMFS_PAGE_SIZE, true);
	return;
}

static int truncate_blocks(struct inode *inode, u64 from)
{
	struct dnode_of_data dn;
	struct hmfs_sb_info *sbi = HMFS_SB(inode->i_sb);
	int count, err;
	u64 free_from;
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
	BUG_ON(count < 0);

	if (dn.ofs_in_node || !dn.level) {
		truncate_data_blocks_range(&dn, count);
		free_from += count;
	}

free_next:err = truncate_inode_blocks(inode, free_from);
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
	struct hmfs_sb_info *sbi = HMFS_SB(inode->i_sb);
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
	struct hmfs_sb_info *sbi = HMFS_SB(inode->i_sb);

	pg_start = ((u64) offset) >> HMFS_PAGE_SIZE_BITS;
	pg_end = ((u64) offset + len) >> HMFS_PAGE_SIZE_BITS;
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
		i_size_write(inode, offset);
		mark_inode_dirty(inode);
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
	struct hmfs_sb_info *sbi = HMFS_SB(inode->i_sb);

	ret = inode_newsize_ok(inode, (len + offset));
	if (ret)
		return ret;

	pg_start = ((u64) offset) >> HMFS_PAGE_SIZE_BITS;
	pg_end = ((u64) offset + len) >> HMFS_PAGE_SIZE_BITS;

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
		i_size_write(inode, new_size);
		mark_inode_dirty(inode);
	}

	return ret;
}

static const struct vm_operations_struct hmfs_file_vm_ops = {
	.fault = filemap_fault,
};

static int hmfs_release_file(struct inode *inode, struct file *filp)
{
//      TODO: Separate atomic and volatile or not
//      If we do separate /* some remained atomic pages should discarded */
//      Else:
//      set_inode_flag(HMFS_I(inode), FI_DROP_CACHE);
	filemap_fdatawrite(inode->i_mapping);
//      clear_inode_flag(HMFS_I(inode), FI_DROP_CACHE);
	return 0;
}

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
//      struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
//      nid_t ino = inode->i_ino;
	int ret = 0;

//      TODO: In Place Update
//      i.e., If dirty page number is below threshold, commit random write to page cache.
//      [Inode Flag] HMFS Inode Info should contain # of dirty pages and sbi should contain min # of dirty pages for inode to write back.

//      If the inode itself is dirty, go to go_write straightly
	if (!datasync && is_inode_flag_set(fi, FI_DIRTY_INODE)) {
//     TODO: [inode] update inode page
		goto go_write;
	}
//      TODO: [CP] Check whether both inode and data are unmodified, if so, go to out.

//      Prepare to write
go_write:

//      TODO: [Segment] (Balance) Check if there exists enough space (If not, GC.)

//      TODO: [CP] Check if making check point is necessary
//      There should be a boolean for each inode to indicate the need for CP.

//              Synchronize all the nodes

//      TODO: [Node] Make sure all the nodes in inode is up-to-date

//      TODO: [Node] Write back all the dirty nodes in inode
//      XXX: Write back is required to make this function work

//      TODO: [CP] Remove this dirty inode from dirty inode list of sbi

//      TODO: [Inode Flag] Clear inode flags if necessary

//      TODO: [Segment] Flush sbi

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

//      Put i_generation of inode to user.
static int hmfs_ioc_getversion(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);

	return put_user(inode->i_generation, (int __user *)arg);
}

long hmfs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
//      TODO: Inode flag operations
//      [Inode Flag]
/*
 case HMFS_IOC_GETFLAGS:
 return hmfs_ioc_getflags(filp, arg);
 case HMFS_IOC_SETFLAGS:
 return hmfs_ioc_setflags(filp, arg);
 */
	case HMFS_IOC_GETVERSION:
		return hmfs_ioc_getversion(filp, arg);
	default:
		return -ENOTTY;
	}
}

const struct file_operations hmfs_file_operations = {
	.llseek = hmfs_file_llseek,
	.read = hmfs_xip_file_read,
	.write = hmfs_xip_file_write,
	//.aio_read       = xip_file_aio_read,
	//.aio_write      = xip_file_aio_write,

	.open = generic_file_open,
//      There's no '.release' in f2fs of kernel 3.11
	.release = hmfs_release_file,
	.mmap = hmfs_file_mmap,
	.fsync = hmfs_sync_file,
	.fallocate = hmfs_fallocate,
	.unlocked_ioctl = hmfs_ioctl,
};

const struct inode_operations hmfs_file_inode_operations = {
	.getattr = hmfs_getattr,
	.setattr = hmfs_setattr,
};
