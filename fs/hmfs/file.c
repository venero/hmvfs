#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/writeback.h>
#include <linux/kernel.h>
#include <linux/falloc.h>
#include <linux/types.h>
#include <linux/time.h>
#include <linux/pagemap.h>
#include <linux/stat.h>

#include "hmfs.h"

static const struct vm_operations_struct hmfs_file_vm_ops = {
	.fault = filemap_fault,
//      .map_pages      = filemap_map_pages,
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
		update_inode_page(inode);
		goto go_write;
	}
//      TODO: [CP] Check whether both inode and data are unmodified, if so, go to out.

//      Prepare to write
      go_write:

//      TODO: [Segment] (Balance) Check if there exists enough space (If not, GC.)

//      TODO: [CP] Check if making check point is necessary
//      There should be a boolean for each inode to indicate the need for CP.

      sync_nodes:

//      TODO: [Node] Make sure all the nodes in inode is up-to-date

//      TODO: [Node] Write back all the dirty nodes in inode
//      XXX: Write back is required to make this function work
//      If an error occurs, goto out.

// TODO: [CP] Remove this dirty inode from dirty inode list of sbi

//      TODO: [Inode Flag] Clear inode flags if necessary

//      TODO: [Segment] Flush sbi

      out:
	return ret;
}

static void fill_zero(struct inode *inode, pgoff_t index, loff_t start,
		      loff_t len)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	struct page *page;

	if (!len)
		return;

//      TODO: [Segment] (Balance) Check if there exists enough space (If not, GC.)

	hmfs_lock_op(sbi);
//      TODO: [Data] Get new data page
/*
	page = get_new_data_page(inode, NULL, index, false);
*/
	hmfs_unlock_op(sbi);

//      TODO: [Segment] Put this page back
}

//      将inode的data page从start到end全部truncate
int truncate_hole(struct inode *inode, pgoff_t pg_start, pgoff_t pg_end)
{
	pgoff_t index;
	int err;

	for (index = pg_start; index < pg_end; index++) {
		struct dnode_of_data dn;

		set_new_dnode(&dn, inode, NULL, NULL, 0);
		err = get_dnode_of_data(&dn, index, LOOKUP_NODE);
		if (err) {
			if (err == -ENOENT)
				continue;
			return err;
		}

		if (dn.data_blkaddr != NULL_ADDR)
			truncate_data_blocks_range(&dn, 1);
		f2fs_put_dnode(&dn);
	}
	return 0;
}

//      在inode的offset开始开辟一个长度为len的hole
static int punch_hole(struct inode *inode, loff_t offset, loff_t len)
{
	pgoff_t pg_start, pg_end;
	loff_t off_start, off_end;
	int ret = 0;

	if (!S_ISREG(inode->i_mode))
		return -EOPNOTSUPP;

	/* skip punching hole beyond i_size */
	if (offset >= inode->i_size)
		return ret;

//      TODO: Consider inline data

	pg_start = ((unsigned long long)offset) >> PAGE_CACHE_SHIFT;
	pg_end = ((unsigned long long)offset + len) >> PAGE_CACHE_SHIFT;

	off_start = offset & (PAGE_CACHE_SIZE - 1);
	off_end = (offset + len) & (PAGE_CACHE_SIZE - 1);
//      When start and end are in a same page
	if (pg_start == pg_end) {
		fill_zero(inode, pg_start, off_start, off_end - off_start);
	} else {
//              Fill three parts
		if (off_start)
			fill_zero(inode, pg_start++, off_start,
				  PAGE_CACHE_SIZE - off_start);
		if (off_end)
			fill_zero(inode, pg_end, 0, off_end);

		if (pg_start < pg_end) {
			struct address_space *mapping = inode->i_mapping;
			loff_t blk_start, blk_end;
			struct hmfs_sb_info *sbi = HMFS_I_SB(inode);

//      TODO: [Segment] (Balance) Check if there exists enough space (If not, GC.)

			blk_start = pg_start << PAGE_CACHE_SHIFT;
			blk_end = pg_end << PAGE_CACHE_SHIFT;
			truncate_inode_pages_range(mapping, blk_start,
						   blk_end - 1);

			hmfs_lock_op(sbi);
			ret = truncate_hole(inode, pg_start, pg_end);
			hmfs_unlock_op(sbi);
		}
	}
	return ret;
}

static int expand_inode_data(struct inode *inode, loff_t offset, loff_t len,
			     int mode)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	pgoff_t index, pg_start, pg_end;
	loff_t new_size = i_size_read(inode);
	loff_t off_start, off_end;
	int ret = 0;

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
		struct dnode_of_data dn;

		if (index == pg_end && !off_end)
			goto noalloc;

		set_new_dnode(&dn, inode, NULL, NULL, 0);
		ret = f2fs_reserve_block(&dn, index);
		if (ret)
			break;
	      noalloc:
		if (pg_start == pg_end)
			new_size = offset + len;
		else if (index == pg_start && off_start)
			new_size = (index + 1) << PAGE_CACHE_SHIFT;
		else if (index == pg_end)
			new_size = (index << PAGE_CACHE_SHIFT) + off_end;
		else
			new_size += PAGE_CACHE_SIZE;
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE) && i_size_read(inode) < new_size) {
		i_size_write(inode, new_size);
		mark_inode_dirty(inode);
		update_inode_page(inode);
	}
	hmfs_unlock_op(sbi);

	return ret;
}

//      Allocate space for file from offset to offset+len
static long hmfs_fallocate(struct file *file, int mode, loff_t offset,
			   loff_t len)
{
	struct inode *inode = file_inode(file);
	long ret;

	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE))
		return -EOPNOTSUPP;

	mutex_lock(&inode->i_mutex);

	if (mode & FALLOC_FL_PUNCH_HOLE)
		ret = punch_hole(inode, offset, len);
	else
		ret = expand_inode_data(inode, offset, len, mode);

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
	.open = generic_file_open,
//      There's no '.release' in f2fs of kernel 3.11
	.release = hmfs_release_file,
	.mmap = hmfs_file_mmap,
	.fsync = hmfs_sync_file,
	.fallocate = hmfs_fallocate,
	.unlocked_ioctl = hmfs_ioctl,
/*
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
*/
};
