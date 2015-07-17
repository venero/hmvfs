#include <linux/fs.h>                                                                                                                                  
#include <linux/writeback.h>
#include <linux/types.h>
#include <linux/pagemap.h> //xip_mapping_read & PAGE_MACRO

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
	loff_t maxsize = 0xffffffff;
	loff_t eof = i_size_read(inode);
	switch (whence) {
	case SEEK_END: 		//size of the file plus offset [bytes]
		offset += eof;
		break;
	case SEEK_CUR: 		//current location plus offset [bytes] 
		//extra lseek(fd, 0, SEEK_CUR) can be used
		spin_lock(&file->f_lock);
		offset = vfs_setpos(file, file->f_pos + offset, maxsize);
		spin_unlock(&file->f_lock);
		return offset;
	case SEEK_DATA: 	//move to data where data.offset >= offset
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
	return vfs_setpos(file, offset, maxsize); //FIXME:SEEK_HOLE/DATA/SET don't need lock?
}

size_t hmfs_xip_file_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
	/* from do_XIP_mapping_read */
	struct inode *inode = filp->f_inode;
	pgoff_t index, end_index;
	unsigned long offset;
	loff_t isize, pos;
	size_t copied = 0, error = 0;


	pos = *ppos;
	index = pos >> PAGE_CACHE_SHIFT; //TODO: shift is HMFS_BLK_SHIFT
	offset = pos & ~PAGE_CACHE_MASK; //^

	isize = i_size_read(inode);
	if (!isize)
		goto out;

	end_index = (isize - 1) >> PAGE_CACHE_SHIFT;
	/*
	 * nr : read length for this loop
	 * offset : start inner-blk offset this loop
	 * index : start inner-file blk number this loop
	 * copied : read length so far
	 * FIXME: pending for write_lock? anything like access_ok()
	 */
	do {
		unsigned long nr, left;
		void *xip_mem;
		int zero = 0;

		/* nr is the maximum number of bytes to copy from this page */
		nr = PAGE_CACHE_SIZE; 	//HMFS_SIZE
		if (index >= end_index) {
			if (index > end_index)
				goto out;
			nr = ((isize - 1) & ~PAGE_CACHE_MASK) + 1;
			if (nr <= offset) {
				goto out;
			}
		}
		nr = nr - offset;
		if (nr > len - copied)
			nr = len - copied;

		//TODO: get XIP by get inner-file blk_offset & look through NAT
		//[index] --> (NID)-->(ino) --> [xip_mem]

		if (unlikely(error)) {
			if (error == -ENODATA) {
				/* sparse */
				zero = 1;
			} else
				goto out;
		}

		/* copy to user space */
		if (!zero)
			left = __copy_to_user(buf+copied, xip_mem+offset, nr);
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
ssize_t hmfs_xip_file_write(struct file *filp, const char __user *buf,
          size_t len, loff_t *ppos)
{
	struct inode*inode = filp->f_inode;
	mutex_lock(&inode->i_mutex);
	//TODO:
	//1. address translation
	//2. space allocation
	//3. do real writting(__hmfs_xip_file_write)
	//4. undo fails
	mutex_unlock(&inode->i_mutex);

	return len;
}
const struct file_operations hmfs_file_operations = {                                                                                           
        .llseek         = hmfs_file_llseek,
        .read           = hmfs_xip_file_read,         
        .write          = hmfs_xip_file_write,
//        .aio_read       = generic_file_aio_read,
//        .aio_write      = generic_file_aio_write,
/*        .open           = generic_file_open,
        .mmap           = hmfs_file_mmap,
        .fsync          = hmfs_sync_file,
        .fallocate      = hmfs_fallocate,
        .unlocked_ioctl = hmfs_ioctl,
#ifdef CONFIG_COMPAT
        .compat_ioctl   = hmfs_compat_ioctl,
#endif  
        .splice_read    = generic_file_splice_read,
        .splice_write   = generic_file_splice_write,
*/
}; 
