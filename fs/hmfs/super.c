#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/statfs.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <uapi/linux/magic.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <asm/io.h>

#include "hmfs_fs.h"
#include "gc.h"
#include "segment.h"
#include "node.h"
#include "util.h"

static struct kmem_cache *hmfs_inode_cachep;	//inode cachep

static void init_once(void *foo)
{
	struct hmfs_inode_info *fi = (struct hmfs_inode_info *)foo;

	inode_init_once(&fi->vfs_inode);
}

static struct inode *hmfs_alloc_inode(struct super_block *sb)
{
	struct hmfs_inode_info *fi;
	int i;

	fi = (struct hmfs_inode_info *)kmem_cache_alloc(hmfs_inode_cachep,
				GFP_NOFS | __GFP_ZERO);
	if (!fi)
		return NULL;
	init_once((void *)fi);
	fi->i_current_depth = 1;
	fi->i_flags = 0;
	fi->flags = 0;
	fi->i_advise = 0;
	fi->rw_addr = NULL;
	fi->i_node_block = NULL;
	fi->block_bitmap = NULL;
	fi->nr_map_page = 0;
	fi->i_height = 0;
	for(i=0;i<4;i++){
		fi->i_proc_info[i].proc_id=0;
		fi->i_proc_info[i].next_ino=0;
		fi->i_proc_info[i].next_nid=0;
	}
	atomic_set(&fi->nr_open, 0);
	init_rwsem(&fi->i_lock);
	set_inode_flag(fi, FI_NEW_INODE);
	INIT_LIST_HEAD(&fi->list);
	return &(fi->vfs_inode);
}

static void hmfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);

	kmem_cache_free(hmfs_inode_cachep, HMFS_I(inode));
}

static void hmfs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, hmfs_i_callback);
}

int __hmfs_write_inode(struct inode *inode, bool force)
{
	int err = 0, ilock;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);

	ilock = mutex_lock_op(sbi);
	inode_write_lock(inode);
	if (is_inode_flag_set(HMFS_I(inode), FI_DIRTY_INODE))
		err = sync_hmfs_inode(inode, force);
	else if(is_inode_flag_set(HMFS_I(inode), FI_DIRTY_SIZE))
		err = sync_hmfs_inode_size(inode, force);
	else if(is_inode_flag_set(HMFS_I(inode),FI_DIRTY_PROC))
		err = sync_hmfs_inode_proc(inode, force);
	else 
		hmfs_bug_on(sbi, 1);
	inode_write_unlock(inode);
	mutex_unlock_op(sbi, ilock);

	hmfs_bug_on(sbi, err && err != -ENOSPC);
	return err;
}

static int hmfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct hmfs_inode_info *fi = HMFS_I(inode);

	if (inode->i_ino < HMFS_ROOT_INO)
		return 0;

	if (!is_inode_flag_set(fi, FI_DIRTY_INODE) && !is_inode_flag_set(fi, FI_DIRTY_SIZE) &&
		!is_inode_flag_set(fi, FI_DIRTY_INODE))
		return 0;

	return __hmfs_write_inode(inode, false);
}

static void hmfs_dirty_inode(struct inode *inode, int flags)
{
	struct hmfs_inode_info *hi = HMFS_I(inode);
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);

	set_inode_flag(hi, FI_DIRTY_INODE);
	spin_lock(&sbi->dirty_inodes_lock);
	list_del(&hi->list);
	INIT_LIST_HEAD(&hi->list);
	list_add_tail(&hi->list, &sbi->dirty_inodes_list);
	spin_unlock(&sbi->dirty_inodes_lock);
}

static void hmfs_evict_inode(struct inode *inode)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	struct hmfs_node *hi;
	struct hmfs_inode_info *fi = HMFS_I(inode);

	if (inode->i_ino < HMFS_ROOT_INO)
		goto out;

	hi = get_node(sbi, inode->i_ino);
	if (IS_ERR(hi)) {
		goto out;
	}

	if (inode->i_nlink || is_bad_inode(inode))
		goto out;

	sb_start_intwrite(inode->i_sb);

	set_inode_flag(HMFS_I(inode), FI_NO_ALLOC);
	i_size_write(inode, 0);

	if (inode->i_blocks > 0)
		hmfs_truncate(inode);

	spin_lock(&sbi->dirty_inodes_lock);
	list_del(&fi->list);
	spin_unlock(&sbi->dirty_inodes_lock);
	INIT_LIST_HEAD(&fi->list);

	truncate_node(inode, inode->i_ino);

	start_bc(sbi);
	
	sb_end_intwrite(inode->i_sb);
out:
	clear_inode(inode);
}

static void hmfs_put_super(struct super_block *sb)
{
	struct hmfs_sb_info *sbi = HMFS_SB(sb);

	lock_gc(sbi);
	write_checkpoint(sbi, true);
	unlock_gc(sbi);

	hmfs_destroy_stats(sbi);
	destroy_map_zero_page(sbi);
	stop_gc_thread(sbi);
	if(!sbi->turn_off_warp) stop_warp_thread(sbi);
	destroy_segment_manager(sbi);
	destroy_node_manager(sbi);
	destroy_checkpoint_manager(sbi);

	sb->s_fs_info = NULL;
	kfree(sbi);

	if (sbi->virt_addr) {
		hmfs_iounmap(sbi->virt_addr);
	}
	hmfs_dbg("[HMFS] : put super block done!\n");
}

static int hmfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct hmfs_sb_info *sbi = HMFS_SB(dentry->d_sb);
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct free_segmap_info *free_i = FREE_I(sbi);
	pgc_t nr_segment_reserve = SM_I(sbi)->ovp_segments;

	hmfs_bug_on(sbi, nr_segment_reserve < 0);

	buf->f_type = HMFS_SUPER_MAGIC;
	buf->f_bsize = HMFS_MIN_PAGE_SIZE;
	buf->f_blocks = cm_i->user_block_count;
	buf->f_bfree = (free_i->free_segments - nr_segment_reserve) 
			<< SM_I(sbi)->page_4k_per_seg_bits;
	buf->f_bavail = cm_i->user_block_count - cm_i->valid_block_count;
	buf->f_files = cm_i->valid_inode_count;
	buf->f_ffree = cm_i->user_block_count - cm_i->valid_block_count;
	buf->f_namelen = HMFS_NAME_LEN;
	return 0;
}

int hmfs_sync_fs(struct super_block *sb, int sync)
{
	struct hmfs_sb_info *sbi = HMFS_SB(sb);
	int ret = 0;
	
	if (sync) {
		lock_gc(sbi);
		ret = write_checkpoint(sbi, true);
		unlock_gc(sbi);
	} else {
		if (has_not_enough_free_segs(sbi)) {
			lock_gc(sbi);
			ret = hmfs_gc(sbi, FG_GC);
		}
	}
	return ret;
}

static int hmfs_freeze(struct super_block *sb)
{
	int err;

	err = hmfs_sync_fs(sb, 1);

	return err;
}

static int hmfs_unfreeze(struct super_block *sb)
{
	return 0;
}

struct super_operations hmfs_sops = {
	.alloc_inode = hmfs_alloc_inode,
	.drop_inode = generic_drop_inode,
	.destroy_inode = hmfs_destroy_inode,
	.write_inode = hmfs_write_inode,
	.dirty_inode = hmfs_dirty_inode,
	.evict_inode = hmfs_evict_inode,
	.put_super = hmfs_put_super,
	.sync_fs = hmfs_sync_fs,
	.statfs = hmfs_statfs,
	.freeze_fs = hmfs_freeze,
	.unfreeze_fs = hmfs_unfreeze,
};

struct dentry *hmfs_mount(struct file_system_type *fs_type, int flags,
			  const char *dev_name, void *data)
{
	return mount_nodev(fs_type, flags, data, hmfs_fill_super);
}

struct file_system_type hmfs_fs_type = {
	.owner = THIS_MODULE,
	.name = "hmfs",
	.mount = hmfs_mount,
	.kill_sb = kill_anon_super,
};

#define AUTHOR_INFO "RADLAB SJTU"
#define DEVICE_TYPE "Hybrid in-Memory File System"

static int __init init_inodecache(void)
{
	hmfs_inode_cachep = hmfs_kmem_cache_create("hmfs_inode_cache",
					      sizeof(struct hmfs_inode_info), NULL);
	if (hmfs_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void destroy_inodecache(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(hmfs_inode_cachep);
}

static void hmfs_check_struct_size(void)
{
	BUILD_BUG_ON(sizeof(struct hmfs_super_block) > HMFS_MIN_PAGE_SIZE);
	BUILD_BUG_ON(sizeof(struct hmfs_inode) > HMFS_MIN_PAGE_SIZE);
	BUILD_BUG_ON(sizeof(struct direct_node) > HMFS_MIN_PAGE_SIZE);
	BUILD_BUG_ON(sizeof(struct indirect_node) > HMFS_MIN_PAGE_SIZE);
	BUILD_BUG_ON(sizeof(struct hmfs_node) > HMFS_MIN_PAGE_SIZE);
	BUILD_BUG_ON(sizeof(struct hmfs_nat_node) > HMFS_MIN_PAGE_SIZE);
	BUILD_BUG_ON(sizeof(struct hmfs_nat_block) > HMFS_MIN_PAGE_SIZE);
	BUILD_BUG_ON(sizeof(struct hmfs_dentry_block) > HMFS_MIN_PAGE_SIZE);
	BUILD_BUG_ON(sizeof(struct hmfs_checkpoint) > HMFS_MIN_PAGE_SIZE);
}

int init_hmfs(void)
{
	int err;

	hmfs_check_struct_size();
	err = init_util_function();
	if (err)
		goto fail;
	err = init_inodecache();
	if (err)
		goto fail;
	err = create_node_manager_caches();
	if (err)
		goto fail_node;
	err = create_checkpoint_caches();
	if (err)
		goto fail_cp;
	err = create_mmap_struct_cache();
	if (err)
		goto fail_mmap;
	err = register_filesystem(&hmfs_fs_type);
	if (err)
		goto fail_reg;
	hmfs_create_root_stat();
	return 0;
fail_reg:
	destroy_mmap_struct_cache();
fail_mmap:
	destroy_checkpoint_caches();
fail_cp:
	destroy_node_manager_caches();
fail_node:
	destroy_inodecache();
fail:
	return err;
}

void exit_hmfs(void)
{
	hmfs_dbg("[HMFS] : destroy_mmap_struct_cache()\n");
	destroy_mmap_struct_cache();
	hmfs_dbg("[HMFS] : destroy_inodecache()\n");
	destroy_inodecache();
	hmfs_dbg("[HMFS] : destroy_node_manager_caches()\n");
	destroy_node_manager_caches();
	hmfs_dbg("[HMFS] : destroy_checkpoint_caches()\n");
	destroy_checkpoint_caches();
	hmfs_dbg("[HMFS] : hmfs_destroy_root_stat()\n");
	hmfs_destroy_root_stat();
	hmfs_dbg("[HMFS] : unregister_filesystem()\n");
	unregister_filesystem(&hmfs_fs_type);
}

module_init(init_hmfs);
module_exit(exit_hmfs);
MODULE_LICENSE("GPL");
MODULE_AUTHOR(AUTHOR_INFO);
MODULE_DESCRIPTION(DEVICE_TYPE);
