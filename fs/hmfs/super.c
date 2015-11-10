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

#include "hmfs_fs.h"
#include "gc.h"
#include "segment.h"
#include "node.h"

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
	Opt_mnt_cp,
};

static const match_table_t tokens = {
	{Opt_addr, "physaddr=%x"},
	{Opt_size, "init=%s"},
	{Opt_num_inodes, "num_inodes=%u"},
	{Opt_mode, "mode=%o"},
	{Opt_uid, "uid=%u"},
	{Opt_gid, "gid=%u"},
	{Opt_bg_gc, "bg_gc=%u"},
	{Opt_mnt_cp, "mnt_cp=%u"},
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
			//remount on another area isn't allowed
			phys_addr = (phys_addr_t) simple_strtoull(args[0].from,
								  NULL, 0);
			if (phys_addr == 0
			    || phys_addr == (phys_addr_t) ULLONG_MAX) {
				goto bad_val;
			}
			if (phys_addr & (HMFS_PAGE_SIZE - 1))
				goto bad_val;
			sbi->phys_addr = phys_addr;
			break;
		case Opt_size:
			if (remount)
				goto bad_opt;
			//change size isn't allowed
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
		case Opt_bg_gc:
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->support_bg_gc = option;
			break;
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
	if (sbi->initsize && sbi->mnt_cp_version)
		goto bad_opt;

	return 0;

bad_val:
	return -EINVAL;
bad_opt:
	return -EINVAL;
}

static int hmfs_format(struct super_block *sb)
{
	u64 pages_count, main_segments_count, user_segments_count,
	 user_pages_count;
	u64 init_size;
	u64 area_addr, end_addr;
	unsigned long long ssa_pages_count, sit_area_size;
	u64 data_segaddr, node_segaddr;
	u64 root_node_addr, cp_addr;
	u64 ssa_addr, nat_addr, main_addr;
	u64 sit_addr;
	int retval = 0;
	int data_blkoff, node_blkoff;
	int length;
	struct hmfs_super_block *super;
	struct hmfs_sb_info *sbi;
	struct hmfs_checkpoint *cp;
	struct hmfs_node *root_node;
	struct hmfs_sit_entry *sit_entry;
	struct hmfs_nat_journal *nat_journals;
	struct hmfs_dentry_block *dent_blk = NULL;
	struct hmfs_summary_block *node_summary_block, *data_summary_block;
	struct hmfs_summary *summary;
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
	sbi->ssa_entries = ADDR(sbi, ssa_addr);
	main_segments_count = (end_addr - area_addr)
	 / (HMFS_SEGMENT_SIZE + SIT_ENTRY_SIZE +
	    HMFS_PAGE_PER_SEG * sizeof(struct hmfs_summary));
	ssa_pages_count = (main_segments_count * HMFS_SUMMARY_BLOCK_SIZE
			   + HMFS_PAGE_SIZE - 1) >> HMFS_PAGE_SIZE_BITS;

/* prepare SIT area */
	area_addr += (ssa_pages_count << HMFS_PAGE_SIZE_BITS);
	sit_addr = area_addr;
	sbi->sit_entries = ADDR(sbi, sit_addr);
	sit_area_size = main_segments_count * SIT_ENTRY_SIZE;
	memset_nt(ADDR(sbi, sit_addr), 0, sit_area_size);

/* prepare main area */
	area_addr += sit_area_size;
	area_addr = align_segment_right(area_addr);

	main_segments_count = (end_addr - area_addr) >> HMFS_SEGMENT_SIZE_BITS;
	user_segments_count =
	 main_segments_count * (100 - DEF_OP_SEGMENTS) / 100;
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
/* node[0]: root inode */
	node_blkoff += 1;
	root_node->footer.nid = cpu_to_le32(HMFS_ROOT_INO);
	root_node->footer.ino = cpu_to_le32(HMFS_ROOT_INO);
	root_node->footer.cp_ver = cpu_to_le32(HMFS_DEF_CP_VER);

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
	dent_blk->dentry[0].ino = cpu_to_le32(HMFS_ROOT_INO);
	dent_blk->dentry[0].name_len = cpu_to_le16(1);
	dent_blk->dentry[0].file_type = HMFS_FT_DIR;
	hmfs_memcpy(dent_blk->filename[0], ".", 1);

	dent_blk->dentry[1].hash_code = HMFS_DDOT_HASH;
	dent_blk->dentry[1].ino = cpu_to_le32(HMFS_ROOT_INO);
	dent_blk->dentry[1].name_len = cpu_to_le16(2);
	dent_blk->dentry[1].file_type = HMFS_FT_DIR;
	hmfs_memcpy(dent_blk->filename[1], "..", 2);

	dent_blk->dentry_bitmap[0] = (1 << 1) | (1 << 0);

/* setup & init nat */
	nat_addr = node_segaddr + HMFS_PAGE_SIZE * node_blkoff;
/* node[1]: nat root */
	node_blkoff++;
	memset_nt(ADDR(sbi, nat_addr), 0, HMFS_PAGE_SIZE);

	cp_addr = node_segaddr + HMFS_PAGE_SIZE * node_blkoff;
	cp = ADDR(sbi, cp_addr);
/* node[2]: init cp */
	node_blkoff += 1;

/* segment 0 is first node segment */
	nat_journals = cp->nat_journals;

/* update nat journal */
	nat_journals[0].nid = cpu_to_le32(HMFS_ROOT_INO);
	nat_journals[0].entry.ino = nat_journals[0].nid;
	nat_journals[0].entry.block_addr = root_node_addr;

/* update SIT */
	sit_entry = get_sit_entry(sbi, 0);
	sit_entry->mtime = cpu_to_le32(get_seconds());
	sit_entry->vblocks = cpu_to_le16(node_blkoff);

	sit_entry = get_sit_entry(sbi, 1);
	sit_entry->mtime = cpu_to_le32(get_seconds());
	sit_entry->vblocks = cpu_to_le16(data_blkoff);

/* update SSA */
	node_summary_block = get_summary_block(sbi, 0);
	data_summary_block = get_summary_block(sbi, 1);

	summary = &node_summary_block->entries[0];
	make_summary_entry(summary, HMFS_ROOT_INO, HMFS_DEF_CP_VER, 1, 0,
			   SUM_TYPE_INODE);
	summary = &node_summary_block->entries[1];
	make_summary_entry(summary, 0, HMFS_DEF_CP_VER, 1, 0, SUM_TYPE_NATN);
	summary = &node_summary_block->entries[2];
	make_summary_entry(summary, 0, HMFS_DEF_CP_VER, 1, 0, SUM_TYPE_CP);

	summary = &data_summary_block->entries[0];
	make_summary_entry(summary, HMFS_ROOT_INO, HMFS_DEF_CP_VER, 1, 0,
			   SUM_TYPE_DATA);

/* prepare checkpoint */
	set_struct(cp, checkpoint_ver, HMFS_DEF_CP_VER);

/* Previous address of the first checkpoint is itself */
	set_struct(cp, prev_cp_addr, cpu_to_le64(cp_addr));
	set_struct(cp, next_cp_addr, cpu_to_le64(cp_addr));
	set_struct(cp, nat_addr, nat_addr);

	set_struct(cp, alloc_block_count, (node_blkoff + data_blkoff));
	set_struct(cp, valid_block_count, (node_blkoff + data_blkoff));
	set_struct(cp, free_segment_count, (user_segments_count - 2));
	set_struct(cp, cur_node_segno, GET_SEGNO(sbi, node_segaddr));
	set_struct(cp, cur_node_blkoff, node_blkoff);
	set_struct(cp, cur_data_segno, GET_SEGNO(sbi, data_segaddr));
	set_struct(cp, cur_data_blkoff, data_blkoff);
	set_struct(cp, valid_inode_count, 1);
/* sit, nat, root */
	set_struct(cp, valid_node_count, node_blkoff);
	set_struct(cp, next_scan_nid, 4);
	set_struct(cp, elapsed_time, 0);

	length = (char *)(&cp->checksum) - (char *)cp;
	cp_checksum = crc16(~0, (void *)cp, length);
	cp->checksum = cpu_to_le16(cp_checksum);

/* setup super block */
	set_struct(super, magic, HMFS_SUPER_MAGIC);
	set_struct(super, major_ver, HMFS_MAJOR_VERSION);
	set_struct(super, minor_ver, HMFS_MINOR_VERSION);
	set_struct(super, nat_height, hmfs_get_nat_height(init_size));

	set_struct(super, log_pagesize, HMFS_PAGE_SIZE_BITS);
	set_struct(super, log_pages_per_seg, HMFS_PAGE_PER_SEG_BITS);

	set_struct(super, segment_count_main, main_segments_count);
	set_struct(super, init_size, init_size);
	set_struct(super, segment_count, init_size >> HMFS_SEGMENT_SIZE_BITS);
	set_struct(super, user_block_count, user_pages_count);
	set_struct(super, ssa_blkaddr, ssa_addr);
	set_struct(super, sit_blkaddr, sit_addr);
	set_struct(super, main_blkaddr, main_addr);
	set_struct(super, cp_page_addr, cp_addr);

	length = (char *)(&super->checksum) - (char *)super;
	sb_checksum = crc16(~0, (char *)super, length);
	set_struct(super, checksum, sb_checksum);

/* copy another super block */
	super = next_super_block(super);
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
	fi->i_current_depth = 1;
	fi->i_flags = 0;
	fi->flags = 0;
	set_inode_flag(fi, FI_NEW_INODE);
	atomic_set(&fi->nr_dirty_map_pages, 0);
	INIT_LIST_HEAD(&fi->list);
	return &(fi->vfs_inode);
}

static void hmfs_i_callback(struct rcu_head *head)
{
	struct inode
	*inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(hmfs_inode_cachep, HMFS_I(inode));
}

static void hmfs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, hmfs_i_callback);
}

int __hmfs_write_inode(struct inode *inode)
{
	int err = 0, ilock;
	struct hmfs_sb_info *sbi = HMFS_SB(inode->i_sb);
	ilock = mutex_lock_op(sbi);
	if (is_inode_flag_set(HMFS_I(inode), FI_DIRTY_INODE))
		err = sync_hmfs_inode(inode);
	else if(is_inode_flag_set(HMFS_I(inode), FI_DIRTY_SIZE))
		err = sync_hmfs_inode_size(inode);
	mutex_unlock_op(sbi, ilock);

	return err;
}

static int hmfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	if (inode->i_ino < HMFS_ROOT_INO)
		return 0;

	if (!is_inode_flag_set(HMFS_I(inode), FI_DIRTY_INODE) ||
				!is_inode_flag_set(HMFS_I(inode), FI_DIRTY_INODE))
		return 0;

	return __hmfs_write_inode(inode);
}

static void hmfs_dirty_inode(struct inode *inode, int flags)
{
	struct hmfs_inode_info *hi = HMFS_I(inode);
	struct hmfs_sb_info *sbi = HMFS_SB(inode->i_sb);

	set_inode_flag(hi, FI_DIRTY_INODE);
	list_del(&hi->list);
	list_add_tail(&hi->list, &sbi->dirty_inodes_list);
	return;
}

static void hmfs_evict_inode(struct inode *inode)
{
	struct hmfs_sb_info *sbi = HMFS_SB(inode->i_sb);
	struct dnode_of_data dn;
	struct hmfs_node *hi;
	struct node_info ni;
	int ret;

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
	ret = get_node_info(sbi, inode->i_ino, &ni);
	truncate_node(&dn);

	if (!ret) {
		setup_summary_of_delete_node(sbi, ni.blk_addr);
	}

	sb_end_intwrite(inode->i_sb);
out:
	clear_inode(inode);
}

static void hmfs_put_super(struct super_block *sb)
{
	struct hmfs_sb_info *sbi = HMFS_SB(sb);
	struct sit_info *sit_i = SIT_I(sbi);

	if (sit_i->dirty_sentries) {
		mutex_lock(&sbi->gc_mutex);
		write_checkpoint(sbi);
		mutex_unlock(&sbi->gc_mutex);
	}

	hmfs_destroy_stats(sbi);
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

	buf->f_type = HMFS_SUPER_MAGIC;
	buf->f_bsize = HMFS_PAGE_SIZE;
	buf->f_blocks = cm_i->user_block_count;
	buf->f_bfree = cm_i->user_block_count - cm_i->valid_block_count;
	buf->f_bavail = buf->f_bfree;
	buf->f_files = cm_i->valid_inode_count;
	buf->f_ffree = cm_i->user_block_count - cm_i->valid_block_count;
	buf->f_namelen = HMFS_NAME_LEN;
	return 0;
}

int hmfs_sync_fs(struct super_block *sb, int sync)
{
	struct hmfs_sb_info *sbi = HMFS_SB(sb);
	struct sit_info *sit_i = SIT_I(sbi);
	int ret = 0;

	if (!sit_i->dirty_sentries)
		return 0;

	if (sync) {
		mutex_lock(&sbi->gc_mutex);
		ret = write_checkpoint(sbi);
		mutex_unlock(&sbi->gc_mutex);
	} else {
		if (has_not_enough_free_segs(sbi)) {
			mutex_lock(&sbi->gc_mutex);
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

static int hmfs_fill_super(struct super_block *sb, void *data, int slient)
{
	struct inode *root = NULL;
	struct hmfs_sb_info *sbi = NULL;
	struct hmfs_super_block *super = NULL;
	int retval = 0;
	int i = 0;
	unsigned long end_addr;
	unsigned long long ssa_addr, sit_addr;
	unsigned long long input_size;

	/* sbi initialization */
	sbi = kzalloc(sizeof(struct hmfs_sb_info), GFP_KERNEL);
	if (sbi == NULL) {
		return -ENOMEM;
	}

	/* get phys_addr from @data&virt_addr from ioremap */
	sb->s_fs_info = sbi;
	sbi->uid = current_fsuid();
	sbi->gid = current_fsgid();
	if (hmfs_parse_options((char *)data, sbi, 0)) {
		retval = -EINVAL;
		goto out;
	}

	input_size = sbi->initsize;
	if(!input_size){
		//read from hypothetic super blocks
		sbi->initsize = HMFS_PAGE_SIZE << 1; 
	}

	sbi->virt_addr = hmfs_ioremap(sb, sbi->phys_addr, sbi->initsize);
	if (!sbi->virt_addr) {
		retval = -EINVAL;
		goto out;
	}

	super = get_valid_super_block(sbi->virt_addr);
	if (!input_size && super != NULL) {
		//old super exists, remount
		sbi->initsize = le64_to_cpu(super->init_size);
		hmfs_iounmap(sbi->virt_addr);
		sbi->virt_addr = hmfs_ioremap(sb, sbi->phys_addr, sbi->initsize);
		if (!sbi->virt_addr) {
			retval = -EINVAL;
			goto out;
		}
	} else if (input_size) {
		hmfs_format(sb);
	} else if (sbi->mnt_cp_version) {
		if (!hmfs_readonly(sb)) {
			retval = -EACCES;
			goto out;
		}
	}
	else {
		retval = -EINVAL;
		goto out;
	}

	super = get_valid_super_block(sbi->virt_addr);
	if (!super) {
		retval = -EINVAL;
		goto out;
	}

	sbi->segment_count = le64_to_cpu(super->segment_count);
	sbi->segment_count_main = le64_to_cpu(super->segment_count_main);
	sbi->page_count_main =  sbi->segment_count_main << HMFS_PAGE_PER_SEG_BITS;
	ssa_addr = le64_to_cpu(super->ssa_blkaddr);
	sit_addr = le64_to_cpu(super->sit_blkaddr);
	sbi->ssa_entries = ADDR(sbi, ssa_addr);
	sbi->sit_entries = ADDR(sbi, sit_addr);
	sbi->nat_height = super->nat_height;

	sbi->main_addr_start = le64_to_cpu(super->main_blkaddr);
	end_addr = sbi->main_addr_start
	 + (sbi->segment_count_main << HMFS_SEGMENT_SIZE_BITS);
	sbi->main_addr_end = align_segment_left(end_addr);
	sbi->sb = sb;

	for (i = 0; i < NR_GLOBAL_LOCKS; ++i)
		mutex_init(&sbi->fs_lock[i]);
	mutex_init(&sbi->gc_mutex);
	sbi->next_lock_num = 0;

	atomic_set(&sbi->nr_dirty_map_pages, 0);
	sbi->s_dirty = 0;
	spin_lock_init(&sbi->dirty_map_inodes_lock);
	INIT_LIST_HEAD(&sbi->dirty_map_inodes);
	INIT_LIST_HEAD(&sbi->dirty_inodes_list);
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

	if (sbi->support_bg_gc && !hmfs_readonly(sb)){
		/* start gc kthread */
		retval = start_gc_thread(sbi);
		if (retval)
			goto free_segment_mgr;
	}

	root = hmfs_iget(sb, HMFS_ROOT_INO);

	if (IS_ERR(root)) {
		retval = PTR_ERR(root);
		goto free_segment_mgr;
	}

	if (!S_ISDIR(root->i_mode) || !root->i_blocks || !root->i_size) {
		goto free_root_inode;
	}

	sb->s_root = d_make_root(root);	
	if (!sb->s_root) {
		goto free_root_inode;
	}
	/* create debugfs */
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
