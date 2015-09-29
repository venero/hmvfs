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

#include "hmfs_fs.h"		//TODO:add to include/linux
#include "segment.h"

static struct kmem_cache *hmfs_inode_cachep;	//inode cachep

/*
 * For mount
 */
enum {
	Opt_addr = 0, Opt_size, Opt_num_inodes,
	Opt_mode, Opt_uid, Opt_gid
};

static const match_table_t tokens = {
	{Opt_addr, "physaddr=%x"},
	{Opt_size, "init=%s"},
	{Opt_num_inodes, "num_inodes=%u"},
	{Opt_mode, "mode=%o"},
	{Opt_uid, "uid=%u"},
	{Opt_gid, "gid=%u"},
};

/*
 * ioremap & iounmap
 */
static inline void *hmfs_ioremap(struct super_block *sb, phys_addr_t phys_addr,
				 ssize_t size)
{
	void __iomem *retval = NULL;
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
static int hmfs_parse_options(char *options, struct hmfs_sb_info *sbi,
			      bool remount)
{
	char *p, *rest;
	int token;
	substring_t args[MAX_OPT_ARGS];
	phys_addr_t phys_addr = 0;
	int option;

	if (!options)
		return 0;
	while ((p = strsep(&options, ",")) != NULL) {	//parse one option each time
		if (!*p)
			continue;

		token = match_token(p, tokens, args);

		switch (token) {
		case Opt_addr:
			if (remount)
				goto bad_opt;	//remount on another area isn't allowed
			phys_addr =
			    (phys_addr_t) simple_strtoull(args[0].from,
							  NULL, 0);
			if (phys_addr == 0
			    || phys_addr == (phys_addr_t) ULLONG_MAX) {
				goto bad_val;
			}
			//TODO: align
			sbi->phys_addr = phys_addr;
			break;
		case Opt_size:
			if (remount)
				goto bad_opt;	//change size isn't allowed
			/* memparse() accepts a K/M/G without a digit */
			if (!isdigit(*args[0].from))
				goto bad_val;
			sbi->initsize = memparse(args[0].from, &rest);
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
		default:
			goto bad_opt;
		}
	}

	return 0;

bad_val:
	return -EINVAL;
bad_opt:
	return -EINVAL;
}

static int hmfs_format(struct super_block *sb)
{
	u64 pages_count, user_segments_count, user_pages_count;
	u64 init_size;
	u64 area_addr, end_addr;
	u64 ssa_pages_count;
	u64 data_segaddr, node_segaddr;
	u64 root_node_addr, cp_addr;
	u64 ssa_addr, sit_addr, nat_addr, main_addr;
	int retval = 0;
	int data_blkoff, node_blkoff;
	int length;
	struct hmfs_super_block *super;
	struct hmfs_sb_info *sbi;
	struct hmfs_checkpoint *cp;
	struct hmfs_node *root_node;
	struct hmfs_sit_journal *sit_journals;
	struct hmfs_nat_journal *nat_journals;
	struct hmfs_dentry_block *dent_blk = NULL;
	struct hmfs_summary_block *node_summary_block, *data_summary_block;
	u16 cp_checksum, sb_checksum;

	sbi = HMFS_SB(sb);
	super = ADDR(sbi, 0);

	init_size = sbi->initsize;
	end_addr = align_segment_left(init_size);

	pages_count = init_size >> HMFS_PAGE_SIZE_BITS;

	/* prepare SSA area */
	area_addr = sizeof(struct hmfs_super_block);
	area_addr = align_page_right(area_addr);
	area_addr <<= 1;	/* two copy of super block */
	ssa_addr = area_addr;
	ssa_pages_count =
	    (pages_count + HMFS_PAGE_PER_SEG - 1) >> HMFS_PAGE_PER_SEG_BITS;
	ssa_pages_count <<= (SUM_SIZE_BITS - HMFS_PAGE_SIZE_BITS);

	/* prepare main area */
	area_addr += (ssa_pages_count << HMFS_PAGE_SIZE_BITS);
	area_addr = align_segment_right(area_addr);

	user_segments_count = (end_addr - area_addr) >> HMFS_SEGMENT_SIZE_BITS;
	user_pages_count = user_segments_count << HMFS_PAGE_PER_SEG_BITS;

	data_blkoff = 0;
	node_blkoff = 0;
	node_segaddr = area_addr;
	main_addr = area_addr;
	sbi->main_addr_start = main_addr;
	data_segaddr = area_addr + HMFS_SEGMENT_SIZE;

	/* setup root inode */
	root_node_addr = node_segaddr;
	root_node = ADDR(sbi, node_segaddr);
	node_blkoff += 1;
	root_node->footer.nid = cpu_to_le64(HMFS_ROOT_INO);
	root_node->footer.ino = cpu_to_le64(HMFS_ROOT_INO);
	root_node->footer.cp_ver = cpu_to_le64(HMFS_DEF_CP_VER);

	root_node->i.i_mode = cpu_to_le16(0x41ed);
	root_node->i.i_links = cpu_to_le32(2);

#ifdef CONFIG_UIDGID_STRICT_TYPE_CHECKS
	root_node->i.i_uid = cpu_to_le32(sbi->uid.val);
	root_node->i.i_gid = cpu_to_le32(sbi->gid.val);
#else
	root_node->i.i_uid = cpu_to_le32(sbi->uid);
	root_node->i.i_gid = cpu_to_le32(sbi->gid);
#endif

	root_node->i.i_size = cpu_to_le64(HMFS_PAGE_SIZE * 1);
	root_node->i.i_blocks = cpu_to_le64(2);

	root_node->i.i_atime = cpu_to_le64(get_seconds());
	root_node->i.i_ctime = cpu_to_le64(get_seconds());
	root_node->i.i_mtime = cpu_to_le64(get_seconds());
	root_node->i.i_generation = 0;
	root_node->i.i_flags = 0;
	root_node->i.i_current_depth = cpu_to_le32(1);
	root_node->i.i_dir_level = DEF_DIR_LEVEL;

	root_node->i.i_addr[0] = cpu_to_le64(data_segaddr);
	data_blkoff += 1;
	dent_blk = ADDR(sbi, data_segaddr);
	dent_blk->dentry[0].hash_code = HMFS_DOT_HASH;
	dent_blk->dentry[0].ino = cpu_to_le64(HMFS_ROOT_INO);
	dent_blk->dentry[0].name_len = cpu_to_le16(1);
	dent_blk->dentry[0].file_type = HMFS_FT_DIR;
	hmfs_memcpy(dent_blk->filename[0], ".", 1);

	dent_blk->dentry[1].hash_code = HMFS_DDOT_HASH;
	dent_blk->dentry[1].ino = cpu_to_le64(HMFS_ROOT_INO);
	dent_blk->dentry[1].name_len = cpu_to_le16(2);
	dent_blk->dentry[1].file_type = HMFS_FT_DIR;
	hmfs_memcpy(dent_blk->filename[1], "..", 2);

	dent_blk->dentry_bitmap[0] = (1 << 1) | (1 << 0);

	/* setup init nat sit */
	super->sit_height = hmfs_get_sit_height(init_size);
	sit_addr = node_segaddr + HMFS_PAGE_SIZE * node_blkoff;
	node_blkoff++;
	nat_addr = node_segaddr + HMFS_PAGE_SIZE * node_blkoff;
	node_blkoff++;
	memset_nt(ADDR(sbi, sit_addr), 0, HMFS_PAGE_SIZE * 2);

	cp_addr = nat_addr + HMFS_PAGE_SIZE * 1;
	cp = ADDR(sbi, cp_addr);
	node_blkoff += 1;

	/* segment 0 is first node segment */
	sit_journals = cp->sit_journals;
	nat_journals = cp->nat_journals;

	sit_journals[0].segno = cpu_to_le64(GET_SEGNO(sbi, node_segaddr));
	memset_nt(sit_journals[0].entry.valid_map, 0, SIT_VBLOCK_MAP_SIZE);
	hmfs_set_bit(0, (char *)sit_journals[0].entry.valid_map);	/* root inode */
	hmfs_set_bit(1, (char *)sit_journals[0].entry.valid_map);	/* sit inode */
	hmfs_set_bit(2, (char *)sit_journals[0].entry.valid_map);	/* nat inode */
	hmfs_set_bit(3, (char *)sit_journals[0].entry.valid_map);	/* cp */
	sit_journals[0].entry.vblocks = cpu_to_le64(node_blkoff);
	sit_journals[0].entry.mtime = cpu_to_le64(get_seconds());

	/* segment 1 is first data segment */
	sit_journals[1].segno = cpu_to_le64(GET_SEGNO(sbi, data_segaddr));
	memset_nt(sit_journals[1].entry.valid_map, 0, SIT_VBLOCK_MAP_SIZE);
	hmfs_set_bit(0, (char *)sit_journals[1].entry.valid_map);
	sit_journals[1].entry.vblocks = cpu_to_le64(data_blkoff);
	sit_journals[1].entry.mtime = cpu_to_le64(get_seconds());

	/* update nat journal */
	nat_journals[0].nid = cpu_to_le64(HMFS_ROOT_INO);
	nat_journals[0].entry.version = cpu_to_le64(HMFS_DEF_CP_VER);
	nat_journals[0].entry.ino = nat_journals[0].nid;
	nat_journals[0].entry.block_addr = root_node_addr;

	/* update SSA */
	node_summary_block = ADDR(sbi, ssa_addr);
	data_summary_block = ADDR(sbi, ssa_addr + HMFS_SUMMARY_BLOCK_SIZE);

	make_summary_entry(&data_summary_block->entries[0], HMFS_ROOT_INO,
			   HMFS_DEF_CP_VER, 0, SUM_TYPE_DATA);
	make_summary_entry(&node_summary_block->entries[0], HMFS_ROOT_INO,
			   HMFS_DEF_CP_VER, 0, SUM_TYPE_NODE);
	make_summary_entry(&node_summary_block->entries[1], HMFS_ROOT_INO,
			   HMFS_DEF_CP_VER, 0, SUM_TYPE_SIT);
	make_summary_entry(&node_summary_block->entries[2], HMFS_ROOT_INO,
			   HMFS_DEF_CP_VER, 0, SUM_TYPE_NAT);
	make_summary_entry(&node_summary_block->entries[3], HMFS_ROOT_INO,
			   HMFS_DEF_CP_VER, 0, SUM_TYPE_CP);
	/* prepare checkpoint */
	set_struct(cp, checkpoint_ver, HMFS_DEF_CP_VER);

	set_struct(cp, sit_addr, sit_addr);
	set_struct(cp, nat_addr, nat_addr);

	set_struct(cp, user_block_count, user_pages_count);
	set_struct(cp, valid_block_count, (node_blkoff + data_blkoff));
	set_struct(cp, free_segment_count, (user_segments_count - 2));
	set_struct(cp, cur_node_segno, GET_SEGNO(sbi, node_segaddr));
	set_struct(cp, cur_node_blkoff, node_blkoff);
	set_struct(cp, cur_data_segno, GET_SEGNO(sbi, data_segaddr));
	set_struct(cp, cur_data_blkoff, data_blkoff);
	set_struct(cp, valid_inode_count, 1);
	/* sit, nat, root */
	set_struct(cp, valid_node_count, 3);
	set_struct(cp, next_scan_nid, 4);

	length = (void *)(&cp->checksum) - (void *)cp;
	cp_checksum = crc16(~0, (void *)cp, length);
	cp->checksum = cpu_to_le16(cp_checksum);

	/* setup super block */
	set_struct(super, magic, HMFS_SUPER_MAGIC);
	set_struct(super, major_ver, HMFS_MAJOR_VERSION);
	set_struct(super, minor_ver, HMFS_MINOR_VERSION);

	set_struct(super, log_pagesize, HMFS_PAGE_SIZE_BITS);
	set_struct(super, log_pages_per_seg, HMFS_PAGE_PER_SEG_BITS);

	set_struct(super, page_count, user_pages_count);
	set_struct(super, segment_count, init_size >> HMFS_SEGMENT_SIZE_BITS);
	set_struct(super, segment_count_main, user_segments_count);
	set_struct(super, ssa_blkaddr, ssa_addr);
	set_struct(super, main_blkaddr, main_addr);
	set_struct(super, cp_page_addr, cp_addr);

	length = (void *)(&super->checksum) - (void *)super;
	sb_checksum = crc16(~0, (void *)super, length);
	set_struct(super, checksum, sb_checksum);

	/* copy another super block */
	area_addr = sizeof(struct hmfs_super_block);
	area_addr = align_page_right(area_addr);
	super = ADDR(sbi, area_addr);
	hmfs_memcpy(super, ADDR(sbi, 0), sizeof(struct hmfs_super_block));
	return retval;
}

static struct hmfs_super_block *get_valid_super_block(void *start_addr)
{
	int length;
	struct hmfs_super_block *super_1, *super_2;
	u16 checksum, real_checksum;

	super_1 = start_addr;
	length = (void *)(&super_1->checksum) - (void *)super_1;
	checksum = crc16(~0, (void *)super_1, length);
	real_checksum = le16_to_cpu(super_1->checksum);
	if (real_checksum == checksum && super_1->magic == HMFS_SUPER_MAGIC) {
		return super_1;
	}

	super_2 =
	    start_addr + align_page_right(sizeof(struct hmfs_super_block));
	checksum = crc16(~0, (void *)super_2, length);
	real_checksum = le16_to_cpu(super_2->checksum);
	if (real_checksum == checksum && super_2->magic == HMFS_SUPER_MAGIC) {
		return super_2;
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
	/* free me when umount */
	fi = (struct hmfs_inode_info *)kmem_cache_alloc(hmfs_inode_cachep,
							GFP_NOFS | __GFP_ZERO);
	if (!fi)
		return NULL;
	init_once((void *)fi);
	/*TODO: hmfs specific inode_info init work */
	fi->i_current_depth = 1;
	set_inode_flag(fi, FI_NEW_INODE);
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

static int hmfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct hmfs_sb_info *sbi = HMFS_SB(inode->i_sb);
	int err, ilock;

	if (inode->i_ino < HMFS_ROOT_INO)
		return 0;

	if (!is_inode_flag_set(HMFS_I(inode), FI_DIRTY_INODE))
		return 0;

	ilock = mutex_lock_op(sbi);
	err = sync_hmfs_inode(inode);
	mutex_unlock_op(sbi, ilock);

	return err;
}

static void hmfs_dirty_inode(struct inode *inode, int flags)
{
	set_inode_flag(HMFS_I(inode), FI_DIRTY_INODE);
	return;
}

static void hmfs_evict_inode(struct inode *inode)
{
	struct hmfs_sb_info *sbi = HMFS_SB(inode->i_sb);
	struct dnode_of_data dn;
	struct hmfs_node *hi;
	if (inode->i_ino < HMFS_ROOT_INO)
		goto out;

	hi = get_node(sbi, inode->i_ino);
	if (IS_ERR(hi)) {
		return;
	}


	if (inode->i_nlink || is_bad_inode(inode))
		goto out;

	sb_start_intwrite(inode->i_sb);

	set_inode_flag(HMFS_I(inode), FI_NO_ALLOC);
	i_size_write(inode, 0);

	if (inode->i_blocks > 0)
		hmfs_truncate(inode);

	set_new_dnode(&dn, inode, &hi->i, NULL, inode->i_ino);
	truncate_node(&dn);

	sb_end_intwrite(inode->i_sb);
out:
	clear_inode(inode);
}

static void hmfs_put_super(struct super_block *sb)
{
	struct hmfs_sb_info *sbi = HMFS_SB(sb);

	hmfs_destroy_stats(sbi);
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
	struct checkpoint_info *cp_i = CURCP_I(sbi);

	buf->f_type = HMFS_SUPER_MAGIC;
	buf->f_bsize = HMFS_PAGE_SIZE;
	buf->f_blocks = sbi->page_count;
	buf->f_bfree = sbi->page_count - cp_i->valid_block_count;
	buf->f_bavail = buf->f_bfree;
	buf->f_files = cp_i->user_block_count;
	buf->f_ffree = cp_i->user_block_count - cp_i->valid_block_count;
	buf->f_namelen = HMFS_NAME_LEN;
	return 0;
}

int hmfs_sync_fs(struct super_block *sb, int sync)
{
	//TODO:XXX fsync **important**
	//1. sync to NVM
	//2. checkpoint
	//...
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

};

static int hmfs_fill_super(struct super_block *sb, void *data, int slient)
{
	struct inode *root = NULL;
	struct hmfs_sb_info *sbi = NULL;
	struct hmfs_super_block *super = NULL;
	int retval = 0;
	int i = 0;
	unsigned long end_addr;

	/* sbi initialization */
	sbi = kzalloc(sizeof(struct hmfs_sb_info), GFP_KERNEL);
	if (sbi == NULL) {
		return -ENOMEM;
	}

	/* get phys_addr from @data&virt_addr from ioremap */
	sb->s_fs_info = sbi;	//link sb and sbi:
	sbi->uid = current_fsuid();
	sbi->gid = current_fsgid();
	if (hmfs_parse_options((char *)data, sbi, 0)) {
		retval = -EINVAL;
		goto out;
	}

	sbi->virt_addr = hmfs_ioremap(sb, sbi->phys_addr, sbi->initsize);
	if (!sbi->virt_addr) {
		retval = -EINVAL;
		goto out;
	}

	super = get_valid_super_block(sbi->virt_addr);
	if (sbi->initsize || !super) {
		hmfs_format(sb);
		super = get_valid_super_block(sbi->virt_addr);
	}
	if (!super) {
		retval = -EINVAL;
		goto out;
	}

	sbi->page_count = le64_to_cpu(super->page_count);
	sbi->segment_count = le64_to_cpu(super->segment_count);
	sbi->ssa_addr = le64_to_cpu(super->ssa_blkaddr);
	sbi->main_addr_start = le64_to_cpu(super->main_blkaddr);
	end_addr =
	    sbi->main_addr_start +
	    (sbi->segment_count << HMFS_SEGMENT_SIZE_BITS);
	sbi->main_addr_end = align_segment_left(end_addr);
	sbi->sb = sb;
	sbi->summary_blk = ADDR(sbi, sbi->ssa_addr);
	for (i = 0; i < NR_GLOBAL_LOCKS; ++i)
		mutex_init(&sbi->fs_lock[i]);
	sbi->next_lock_num = 0;

	sb->s_magic = le32_to_cpu(super->magic);
	sb->s_op = &hmfs_sops;
	sb->s_maxbytes = hmfs_max_size();
	sb->s_xattr = NULL;
	sb->s_flags |= MS_NOSEC;

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

	//TODO: further init sbi
	root = hmfs_iget(sb, HMFS_ROOT_INO);

	if (IS_ERR(root)) {
		retval = PTR_ERR(root);
		goto free_segment_mgr;
	}

	if (!S_ISDIR(root->i_mode) || !root->i_blocks || !root->i_size) {
		goto free_root_inode;
	}

	sb->s_root = d_make_root(root);	//kernel routin : makes a dentry for a root inode
	if (!sb->s_root) {
		goto free_root_inode;
	}
	// create debugfs
	hmfs_build_stats(sbi);

	return 0;
free_root_inode:
	iput(root);
free_segment_mgr:
	destroy_segment_manager(sbi);

	destroy_node_manager(sbi);
free_cp_mgr:
	destroy_checkpoint_manager(sbi);
out:
	//TODO:
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

/*
 * Module Specific Info
 * TODO: add your personal info here
 */

#define AUTHOR_INFO "RADLAB SJTU"
#define DEVICE_TYPE "Hybrid in-Memory File System"

static int __init init_inodecache(void)
{
	hmfs_inode_cachep = kmem_cache_create("hmfs_inode_cache",
					      sizeof(struct hmfs_inode_info), 0,
					      SLAB_RECLAIM_ACCOUNT, NULL);
	if (hmfs_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void destroy_inodecache(void)
{
	kmem_cache_destroy(hmfs_inode_cachep);
}

int init_hmfs(void)
{
	int err;

	err = init_inodecache();
	if (err)
		goto fail;
	err = create_node_manager_caches();
	if (err)
		goto fail_node;
	err = create_checkpoint_caches();
	if (err)
		goto fail_cp;
	err = register_filesystem(&hmfs_fs_type);
	if (err)
		goto fail_reg;
	hmfs_create_root_stat();
	return 0;
fail_reg:
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
	// TO BE FIXED
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
