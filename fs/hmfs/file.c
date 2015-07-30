#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/falloc.h>
#include <linux/time.h>
#include <linux/stat.h>
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
	//TODO:loff_t maxsize = inode->i_sb->s_maxbytes;
	loff_t maxsize = hmfs_max_size();
	loff_t eof = i_size_read(inode);
	switch (whence) {
	case SEEK_END:		//size of the file plus offset [bytes]
		offset += eof;
		break;
	case SEEK_CUR:		//current location plus offset [bytes] 
		//extra lseek(fd, 0, SEEK_CUR) can be used
		spin_lock(&file->f_lock);
		offset = vfs_setpos(file, file->f_pos + offset, maxsize);
		spin_unlock(&file->f_lock);
		return offset;
	case SEEK_DATA:	//move to data where data.offset >= offset
		if (offset >= eof)
			return -ENXIO;
		break;
	case SEEK_HOLE:
		/*
		 * There is a virtual hole at the end of the file, so as long as
		 * offset isn't i_size or larger, return i_size.
		 */
		if (offset >= eof)
			return -ENXIO;
		offset = eof;
		break;
	}
	return vfs_setpos(file, offset, maxsize);	//FIXME:SEEK_HOLE/DATA/SET don't need lock?
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
			    __copy_to_user(buf + copied, xip_mem[0] + offset,
					   nr);
		else
			left = __clear_user(buf + copied, nr);

		if (left) {
			error = -EFAULT;
			goto out;
		}

		copied += (nr - left);
		offset += (nr - left);
		index += offset >> PAGE_CACHE_SHIFT;
		offset &= ~PAGE_CACHE_MASK;
	} while (copied < len);

out:
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

		xip_mem = get_new_data_block(inode, index);
		if (unlikely(IS_ERR(xip_mem)))
			break;

		copied =
		    bytes - __copy_from_user_nocache(xip_mem + offset, buf,
						     bytes);

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
		hmfs_update_isize(inode);
	}
	return written ? written : status;

}

ssize_t hmfs_xip_file_write(struct file * filp, const char __user * buf,
			    size_t len, loff_t * ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = filp->f_inode;
	size_t count = 0, ret;
	loff_t pos;

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

	ret = __hmfs_xip_file_write(filp, buf, count, pos, ppos);
out_backing:
	current->backing_dev_info = NULL;
out_up:
	mutex_unlock(&inode->i_mutex);
	return ret;

}

//verno
static const struct vm_operations_struct hmfs_file_vm_ops = {
//       .fault should be redefined
//       Ask qweeah: PMFS uses pmfs_get_xip_mem to get page, however, f2fs uses 'BUG()'. I don't know why.
	.fault = filemap_fault,

//      I have no idea what this is about.
//      .map_pages      = filemap_map_pages,

//      .page_mkwrite should be redefined to write data from DRAM to NVM with structure and function defined in node.
//      .page_mkwrite   = hmfs_vm_page_mkwrite,
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
//      TODO: Inline data

	file_accessed(file);
	vma->vm_ops = &hmfs_file_vm_ops;
//      Ask Goku: Whether xip part should be coded by now
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
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	pgoff_t index, pg_start, pg_end;
	loff_t off_start, off_end;
	long ret = 0;

//      PMFS supports FALLOC_FL_KEEP_SIZE while F2FS supports both.
//      FALLOC_FL_KEEP_SIZE: Allocate 'virtual' space but keep file size unchanged
//      FALLOC_FL_PUNCH_HOLE is ignored for the time being.
	if (mode & ~FALLOC_FL_KEEP_SIZE)
		return -EOPNOTSUPP;

	if (S_ISDIR(inode->i_mode))
		return -ENODEV;

	mutex_lock(&inode->i_mutex);

//      ret = expand_inode_data(inode, offset, len, mode);

//      TODO: [Segment] (Balance) Check if there exists enough space (If not, GC.)

	ret = inode_newsize_ok(inode, (len + offset));
	if (ret)
		return ret;

//      TODO: Inline data

	pg_start = ((unsigned long long)offset) >> PAGE_CACHE_SHIFT;
	pg_end = ((unsigned long long)offset + len) >> PAGE_CACHE_SHIFT;

	off_start = offset & (PAGE_CACHE_SIZE - 1);
	off_end = (offset + len) & (PAGE_CACHE_SIZE - 1);

	hmfs_lock_op(sbi);

	for (index = pg_start; index <= pg_end; index++) {

//              TODO: [Data] Allocate a data node

//              TODO: [Data] Initialize data node

//              TODO: [Data] Reserve this data node

	}

	hmfs_unlock_op(sbi);

	if (!ret) {
		inode->i_mtime = inode->i_ctime = CURRENT_TIME;
		mark_inode_dirty(inode);
	}

	mutex_unlock(&inode->i_mutex);

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
//        .aio_read       = generic_file_aio_read,
//        .aio_write      = generic_file_aio_write,

	.open = generic_file_open,
//      There's no '.release' in f2fs of kernel 3.11
	.release = hmfs_release_file,
	.mmap = hmfs_file_mmap,
	.fsync = hmfs_sync_file,
	.fallocate = hmfs_fallocate,
	.unlocked_ioctl = hmfs_ioctl,
};
