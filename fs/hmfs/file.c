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
//       .fault should be redefined
//       Ask qweeah: PMFS uses pmfs_get_xip_mem to get page, however, f2fs uses 'BUG()'. I don't know why.
		.fault = filemap_fault,

//      I have no idea what this is about.
//      .map_pages      = filemap_map_pages,

//      .page_mkwrite should be redefined to write data from DRAM to NVM with structure and function defined in node.
//      .page_mkwrite   = hmfs_vm_page_mkwrite,
		};

static int hmfs_release_file(struct inode *inode, struct file *filp) {
//      TODO: Separate atomic and volatile or not
//      If we do separate /* some remained atomic pages should discarded */
//      Else:
//      set_inode_flag(HMFS_I(inode), FI_DROP_CACHE);
	filemap_fdatawrite(inode->i_mapping);
//      clear_inode_flag(HMFS_I(inode), FI_DROP_CACHE);
	return 0;
}

static int hmfs_file_mmap(struct file *file, struct vm_area_struct *vma) {
//      TODO: Inline data

	file_accessed(file);
	vma->vm_ops = &hmfs_file_vm_ops;
//      Ask Goku: Whether xip part should be coded by now
	return 0;
}

int hmfs_sync_file(struct file *file, loff_t start, loff_t end, int datasync) {
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
		loff_t len) {
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

	pg_start = ((unsigned long long) offset) >> PAGE_CACHE_SHIFT;
	pg_end = ((unsigned long long) offset + len) >> PAGE_CACHE_SHIFT;

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
static int hmfs_ioc_getversion(struct file *filp, unsigned long arg) {
	struct inode *inode = file_inode(filp);

	return put_user(inode->i_generation, (int __user * )arg);
}

long hmfs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
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

// File operations
const struct file_operations hmfs_file_operations = { .open = generic_file_open,
//      There's no '.release' in f2fs of kernel 3.11
		.release = hmfs_release_file, .mmap = hmfs_file_mmap, .fsync =
				hmfs_sync_file, .fallocate = hmfs_fallocate, .unlocked_ioctl =
				hmfs_ioctl, };
