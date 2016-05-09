#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/statfs.h>
#include <linux/parser.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/ctype.h>
#include <uapi/linux/magic.h>
#include <linux/crc16.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <asm/io.h>

#include "hmfs_fs.h"
#include "gc.h"
#include "segment.h"
#include "node.h"
#include "xattr.h"
#include "util.h"

static struct kmem_cache *hmfs_inode_cachep;	//inode cachep

/*
 * For mount
 */
enum {
	Opt_addr = 0,
	Opt_size,
	Opt_num_inodes,
	Opt_mode,
	Opt_uid,
	Opt_gid,
	Opt_bg_gc,
	Opt_gc_min_time,
	Opt_gc_max_time,
	Opt_gc_time_step,
	Opt_mnt_cp,
	Opt_user_xattr,
	Opt_acl,
	Opt_inline_data,
};

static const match_table_t tokens = {
	{Opt_addr, "physaddr=%x"},
	{Opt_size, "init=%s"},
	{Opt_num_inodes, "num_inodes=%u"},
	{Opt_mode, "mode=%o"},
	{Opt_uid, "uid=%u"},
	{Opt_gid, "gid=%u"},
	{Opt_bg_gc, "bg_gc=%u"},
	{Opt_gc_min_time, "gc_min_time=%u"},
	{Opt_gc_max_time, "gc_max_time=%u"},
	{Opt_gc_time_step, "gc_time_step=%u"},
	{Opt_mnt_cp, "mnt_cp=%u"},
	{Opt_user_xattr, "user_xattr=%u"},
	{Opt_acl, "acl=%u"},
	{Opt_inline_data, "inline=%u"},
};


/*
 * ioremap & iounmap
 */
static inline void *hmfs_ioremap(struct super_block *sb, phys_addr_t phys_addr, ssize_t size)
{
	void __iomem *retval = NULL;
	//TODO: try to use ioremap_nocache
	retval = ioremap_cache(phys_addr, size);
	return (void __force *)retval;
}

static inline int hmfs_iounmap(void *virt_addr)
{
	iounmap((void __iomem __force *)virt_addr);
	return 0;
}

/* 
 * hmfs_parse_options - format mount options from string @options to @sbi inner attributes
 * @option: options string from mount @data
 * @sbi: super block information for fs
 * @remount: is remount
 */
static int hmfs_parse_options(char *options, struct hmfs_sb_info *sbi, bool remount)
{
	char *p, *rest;
	int token;
	substring_t args[MAX_OPT_ARGS];
	phys_addr_t phys_addr = 0;
	int option;
	bool check_gc_time = false;
	struct hmfs_dev_info *dev_0 = DEV_INFO(sbi, 0);

	if (!options)
		return 0;

	sbi->initsize = 0;
	sbi->mnt_cp_version = 0;

	while ((p = strsep(&options, ",")) != NULL) {	//parse one option each time
		if (!*p)
			continue;

		token = match_token(p, tokens, args);

		switch (token) {
		case Opt_addr:
			if (remount)
				goto bad_opt;
			/* remount on another area isn't allowed */
			phys_addr = (phys_addr_t) simple_strtoull(args[0].from, NULL, 0);
			if (phys_addr == 0 || phys_addr == (phys_addr_t) ULLONG_MAX) {
				goto bad_val;
			}
			if (phys_addr & (HMFS_MIN_PAGE_SIZE - 1))
				goto bad_val;
			dev_0->phys_addr = phys_addr;
			break;
		case Opt_size:
			if (remount)
				goto bad_opt;
			/* change size isn't allowed */
			/* memparse() accepts a K/M/G without a digit */
			if (!isdigit(*args[0].from))
				goto bad_val;
			dev_0->initsize = memparse(args[0].from, &rest);
			break;
		case Opt_uid:
			if (remount)
				goto bad_opt;
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->uid = make_kuid(current_user_ns(), option);
			break;
		case Opt_gid:
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->gid = make_kgid(current_user_ns(), option);
			break;
		case Opt_inline_data:
			if (match_int(&args[0], &option))
				goto bad_val;
			if (option)
				set_opt(sbi, INLINE_DATA);
			break;
		case Opt_bg_gc:
			if (match_int(&args[0], &option))
				goto bad_val;
			if (option)
				set_opt(sbi, BG_GC);
			break;
		case Opt_gc_min_time:
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->gc_thread_min_sleep_time = option;
			check_gc_time = true;
			break;
		case Opt_gc_max_time:
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->gc_thread_max_sleep_time = option;
			check_gc_time = true;
			break;
		case Opt_gc_time_step:
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->gc_thread_time_step = option;
			check_gc_time = true;
			break;
#ifdef CONFIG_HMFS_XATTR
		case Opt_user_xattr:
			if (match_int(&args[0], &option))
				goto bad_val;
			if (option)
				set_opt(sbi, XATTR_USER);
			break;
#else
		case Opt_user_xattr:
			break;
#endif
#ifdef CONFIG_HMFS_ACL
		case Opt_acl:
			if (match_int(&args[0], &option))
				goto bad_val;
			if (option)
				set_opt(sbi, POSIX_ACL);
			break;
#else
		case Opt_acl:
			break;
#endif
		case Opt_mnt_cp:
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->mnt_cp_version = option;
			break;
		default:
			goto bad_opt;
		}
	}
	
	/* format fs and mount cp in the same time is invalid */
	if (dev_0->initsize && sbi->mnt_cp_version)
		goto bad_opt;

	if (check_gc_time) {
		if (sbi->gc_thread_min_sleep_time > sbi->gc_thread_max_sleep_time ||
				sbi->gc_thread_time_step > sbi->gc_thread_max_sleep_time)
			goto bad_val;
	} else {
		sbi->gc_thread_min_sleep_time = GC_THREAD_MIN_SLEEP_TIME;
		sbi->gc_thread_time_step = GC_THREAD_MIN_SLEEP_TIME;
		sbi->gc_thread_max_sleep_time = GC_THREAD_MAX_SLEEP_TIME;
	}

	return 0;

bad_val:
bad_opt:
	return -EINVAL;
}

static int hmfs_max_page_size_bits(unsigned long long initsize)
{
	int page_size_bits = 0;
	int max_page_size = initsize >> 4;

	while (max_page_size >>= 1) {
		page_size_bits++;
	}
	
	if (page_size_bits < HMFS_MAX_PAGE_SIZE_BITS) {
		return (page_size_bits - HMFS_MIN_PAGE_SIZE_BITS ) / 
				HMFS_PAGE_SIZE_BITS_INC * HMFS_PAGE_SIZE_BITS_INC
				+ HMFS_MIN_PAGE_SIZE_BITS;
	} else
		return HMFS_MAX_PAGE_SIZE_BITS;
}

static struct hmfs_super_block *get_valid_super_block(void *start_addr)
{
	struct hmfs_super_block *super_1, *super_2;
	u16 checksum_1, checksum_2, real_checksum_1, real_checksum_2;
	bool sb_1_valid = false, sb_2_valid = false;

	super_1 = start_addr;
	checksum_1 = hmfs_make_checksum(super_1);
	real_checksum_1 = le16_to_cpu(super_1->checksum);
	if (real_checksum_1 == checksum_1 && super_1->magic == HMFS_SUPER_MAGIC) {
		sb_1_valid = true;
	}

	super_2 = next_super_block(super_1);
	checksum_2 = hmfs_make_checksum(super_2);
	real_checksum_2 = le16_to_cpu(super_2->checksum);
	if (real_checksum_2 == checksum_2 && super_2->magic == HMFS_SUPER_MAGIC) {
		sb_2_valid = true;
	}

	if (sb_1_valid) {
		if (checksum_1 != checksum_2)
			hmfs_memcpy(super_2, super_1, sizeof(struct hmfs_super_block));
		return super_1;
	} else if (sb_2_valid) {
		hmfs_memcpy(super_1, super_2, sizeof(struct hmfs_super_block));
		return super_1;
	}
	
	return NULL;
}

/*
 * sop
 */
static void init_once(void *foo)
{
	struct hmfs_inode_info *fi = (struct hmfs_inode_info *)foo;

	inode_init_once(&fi->vfs_inode);
}

static struct inode *hmfs_alloc_inode(struct super_block *sb)
{
	struct hmfs_inode_info *fi;

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
	else 
		hmfs_bug_on(sbi, 1);
	inode_write_unlock(inode);
	mutex_unlock_op(sbi, ilock);

	hmfs_bug_on(sbi, err && err != -ENOSPC);
	return err;
}

static int hmfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	if (inode->i_ino < HMFS_ROOT_INO)
		return 0;

	if (!is_inode_flag_set(HMFS_I(inode), FI_DIRTY_INODE) &&
				!is_inode_flag_set(HMFS_I(inode), FI_DIRTY_SIZE))
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

static int init_map_zero_page(struct hmfs_sb_info *sbi)
{
	sbi->map_zero_page = alloc_page((GFP_KERNEL | __GFP_ZERO));

	if (!sbi->map_zero_page)
		return -ENOMEM;
	lock_page(sbi->map_zero_page);
	sbi->map_zero_page_number = page_to_pfn(sbi->map_zero_page);
	return 0;
}

static void destroy_map_zero_page(struct hmfs_sb_info *sbi)
{
	hmfs_bug_on(sbi, !PageLocked(sbi->map_zero_page));
	unlock_page(sbi->map_zero_page);
	__free_page(sbi->map_zero_page);
	sbi->map_zero_page = NULL;
	sbi->map_zero_page_number = 0;
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
	destroy_segment_manager(sbi);
	destroy_node_manager(sbi);
	destroy_checkpoint_manager(sbi);

	sb->s_fs_info = NULL;
	kfree(sbi);

	if (sbi->virt_addr) {
		hmfs_iounmap(sbi->virt_addr);
	}
}

static int hmfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct hmfs_sb_info *sbi = HMFS_SB(dentry->d_sb);
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct free_segmap_info *free_i = FREE_I(sbi);
	pgc_t nr_user_segment = cm_i->user_block_count >> SM_I(sbi)->page_4k_per_seg_bits;
	pgc_t nr_segment_reserve = sbi->segment_count_main - nr_user_segment;

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
		hmfs_dbg("write checkpoint\n");
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

static struct super_operations hmfs_sops = {
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

static inline void hmfs_init_sb_info(struct hmfs_sb_info *sbi)
{
	struct hmfs_super_block *super = DEV_INFO(sbi, 0)->virt_addr;
	uint8_t seg_sz_bits;

	sbi->nat_height = super->nat_height;
	sbi->nr_max_fg_segs = NR_MAX_FG_SEGS;
	sbi->max_page_size_bits = super->max_page_size_bits;
	sbi->max_page_size = 1 << sbi->max_page_size_bits;
	sbi->nr_page_types = (sbi->max_page_size_bits - HMFS_MIN_PAGE_SIZE_BITS) /
			HMFS_PAGE_SIZE_BITS_INC + 2;
	seg_sz_bits = calculate_segment_size_bits(sbi->max_page_size_bits);
	sbi->page_count_main =  sbi->segment_count_main << (seg_sz_bits - HMFS_MIN_PAGE_SIZE_BITS);
	sbi->gc_type_info = 0;
	sbi->gc_old_token = DEFAULT_GC_TOKEN;

	sbi->sb = sb;

	for (i = 0; i < NR_GLOBAL_LOCKS; ++i)
		mutex_init(&sbi->fs_lock[i]);
	mutex_init(&sbi->gc_mutex);
	sbi->next_lock_num = 0;

	sbi->s_dirty = 0;
	INIT_LIST_HEAD(&sbi->dirty_inodes_list);
	INIT_LIST_HEAD(&sbi->mmap_block_list);
	mutex_init(&sbi->mmap_block_lock);
	spin_lock_init(&sbi->dirty_inodes_lock);
	sb->s_magic = le32_to_cpu(super->magic);
	sb->s_op = &hmfs_sops;
	sb->s_xattr = hmfs_xattr_handlers;
	sb->s_maxbytes = hmfs_max_file_size();
	sb->s_flags |= MS_NOSEC;
}

static inline int hmfs_read_super_block(struct hmfs_sb_info *sbi)
{
	struct hmfs_dev_info *dev_0 = DEV_INFO(sbi, 0);
	struct hmfs_super_block *super = get_valid_super_block(dev_0->virt_addr);
	int i;

	dev_0->initsize = le64_to_cpu(super->devices[0].initsize);
	hmfs_iounmap(dev_0->virt_addr);
	dev_0->virt_addr = hmfs_ioremap(sb, dev_0->phys_addr, dev_0->initsize);
	if (dev_0->phys_addr != le64_to_cpu(super->devices[0].phys_addr) || !dev_0->virt_addr)
		return -EINVAL;
	super = dev_0->virt_addr;
	for (i = 0; i < NR_DEVICE; i++) {
		struct hmfs_dev_info *dev_i = DEV_INFO(sbi, i);
		dev_i->phys_addr = le64_to_cpu(super->devices[i].phys_addr);
		dev_i->initsize = le64_to_cpu(super->devices[i].initsize);
		if (!dev_i->initsize)
			continue;
		if (i != 0)
			dev_i->virt_addr = hmfs_ioremap(sb, dev_i->phys_addr, dev_i->initsize);
		if (!dev_i->virt_addr) {
			retval = -EINVAL;
		}
		dev_i->main_ofs = le64_to_cpu(super->devices[i].main_offset);
		dev_i->main_area = JUMP(dev_i->virt_addr, dev_i->main_ofs);
		dev_i->ssa_entries = JUMP(dev_i->virt_addr, le64_to_cpu(super->devices[i].ssa_offset));
		dev_i->sit_entries = JUMP(dev_i->virt_addr, le64_to_cpu(super->devices[i].sit_offset));
		sbi->segment_count += le64_to_cpu(super->devices[i].nr_segments);
		sbi->segment_count_main += le64_to_cpu(super->devices[i].nr_main_segments);
	}
}

static int hmfs_fill_super(struct super_block *sb, void *data, int slient)
{
	struct inode *root = NULL;
	struct hmfs_sb_info *sbi = NULL;
	struct hmfs_super_block *super = NULL;
	int retval = 0;
	int i = 0;
	uint64_t input_size;
	struct hmfs_dev_info *dev_0 = DEV_INFO(sbi, 0);

	/* sbi initialization */
	sbi = kzalloc(sizeof(struct hmfs_sb_info), GFP_KERNEL);
	if (sbi == NULL) {
		return -ENOMEM;
	}
	memset(sbi, 0, sizeof(struct hmfs_sb_info));

	/* get phys_addr from @data&virt_addr from ioremap */
	sb->s_fs_info = sbi;
	sbi->uid = current_fsuid();
	sbi->gid = current_fsgid();
	if (hmfs_parse_options((char *)data, sbi, 0)) {
		retval = -EINVAL;
		goto out;
	}

	input_size = dev_0->initsize;
	if (!input_size) {
		/* read from hypothetic super blocks */
		dev_0->initsize = HMFS_MIN_PAGE_SIZE << 1; 
	}

	dev_0->virt_addr = hmfs_ioremap(sb, dev_0->phys_addr, dev_0->initsize);
	if (!dev_0->virt_addr) {
		retval = -EINVAL;
		goto out;
	}

	super = get_valid_super_block(dev_0->virt_addr);
	if (input_size || !super) {
		retval = hmfs_format_device(sbi, 0);
		if (retval)
			goto out;
	}

	retval = hmfs_read_super_block(sbi);
	if (retval || (sbi->mnt_cp_version && !hmfs_readonly(sbi)))
		goto out

	hmfs_init_sb_info(sbi);

	/* init checkpoint */
	retval = init_checkpoint_manager(sbi);
	if (retval)
		goto out;

	/* init nat */
	retval = build_node_manager(sbi);
	if (retval)
		goto free_cp_mgr;

	retval = build_segment_manager(sbi);
	if (retval)
		goto free_segment_mgr;
	hmfs_bug_on(sbi, sbi->main_addr_end & (SM_I(sbi)->segment_size - 1));

	if (!sbi->mnt_cp_version)
		check_checkpoint_state(sbi);

	retval = init_gc_logs(sbi);
	if (retval)
		goto free_segment_mgr;

	if (test_opt(sbi, BG_GC) && !hmfs_readonly(sb)) {
		/* start gc kthread */
		retval = start_gc_thread(sbi);
		if (retval)
			goto free_segment_mgr;
	}
	
	retval = -EINVAL;
	if (recover_orphan_inodes(sbi))
		goto free_segment_mgr;

	root = hmfs_iget(sb, HMFS_ROOT_INO);
	if (IS_ERR(root)) {
		retval = PTR_ERR(root);
		goto free_segment_mgr;
	}

	if (!S_ISDIR(root->i_mode) || !root->i_blocks || !root->i_size) {
		retval = -EINVAL;
		goto free_root_inode;
	}

	sb->s_root = d_make_root(root);	
	if (!sb->s_root) {
		retval = -ENOMEM;
		goto free_root_inode;
	}

	retval = init_map_zero_page(sbi);
	if (retval)
		goto free_root_inode;

	/* create debugfs */
	retval = hmfs_build_stats(sbi);
	if (retval)
		goto free_zero_page;

	return 0;
free_zero_page:
	destroy_map_zero_page(sbi);
free_root_inode:
	iput(root);
	sb->s_root = NULL;
free_segment_mgr:
	destroy_segment_manager(sbi);
	destroy_node_manager(sbi);
free_cp_mgr:
	destroy_checkpoint_manager(sbi);
out:
	if (sbi->virt_addr) {
		hmfs_iounmap(sbi->virt_addr);
	}
	kfree(sbi);
	return retval;
}

struct dentry *hmfs_mount(struct file_system_type *fs_type, int flags,
			  const char *dev_name, void *data)
{
	struct dentry *entry;
	
	entry = mount_nodev(fs_type, flags, data, hmfs_fill_super);
	return entry;
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
	destroy_mmap_struct_cache();
	destroy_inodecache();
	destroy_node_manager_caches();
	destroy_checkpoint_caches();
	hmfs_destroy_root_stat();
	unregister_filesystem(&hmfs_fs_type);
}

module_init(init_hmfs);
module_exit(exit_hmfs);
MODULE_LICENSE("GPL");
MODULE_AUTHOR(AUTHOR_INFO);
MODULE_DESCRIPTION(DEVICE_TYPE);
