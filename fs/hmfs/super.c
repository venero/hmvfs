#include <linux/module.h>	
#include <linux/kernel.h>
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
#include "hmfs.h"

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
				printk
				    ("Invalid phys addr specification: %s\n",
				     p);
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
		default:
			goto bad_opt;
		}
	}

	return 0;

bad_val:
	printk("Bad value '%s' for mount option '%s'\n", args[0].from, p);
	return -EINVAL;
bad_opt:
	printk("Bad mount option: \"%s\"\n", p);
	return -EINVAL;
}

static int hmfs_format(struct super_block *sb)
{
	struct hmfs_super_block *super;
	struct hmfs_sb_info *sbi;
	int retval = 0;
	unsigned long pages_count, user_segments_count, user_pages_count;
	unsigned long init_size;
	unsigned long area_addr, end_addr;
	unsigned long ssa_pages_count;
	unsigned long data_blkoff, node_blkoff;
	unsigned long data_segaddr, node_segaddr;
	unsigned long root_node_addr, cp_addr;
	unsigned long ssa_addr, sit_addr, nat_addr, main_addr;
	unsigned long length;
	u16 cp_checksum, sb_checksum;
	struct hmfs_checkpoint *cp;
	struct hmfs_node *root_node;
	struct hmfs_sit_journal *sit_journals;
	struct hmfs_nat_journal *nat_journals;
	struct hmfs_dentry_block *dent_blk = NULL;
	struct hmfs_summary_block *node_summary_block, *data_summary_block;

	sbi = sb->s_fs_info;
	super = sbi->virt_addr;

	init_size = sbi->initsize;
	end_addr = align_segment_left(init_size);

	pages_count = init_size >> HMFS_PAGE_SIZE_BITS;

	/* prepare SSA area */
	area_addr = sizeof(struct hmfs_super_block);
	area_addr = align_page_right(area_addr + HMFS_PAGE_SIZE);
	area_addr <<= 1;	/* two copy of super block */
	ssa_addr = area_addr;
	ssa_pages_count =
	    (pages_count + HMFS_PAGE_PER_SEG) >> HMFS_PAGE_PER_SEG_BITS;
	ssa_pages_count <<= 1;	/* summary summary block need two pages */

	/* prepare main area */
	area_addr += (ssa_pages_count << HMFS_PAGE_SIZE_BITS);
	area_addr = align_segment_right(area_addr);

	user_segments_count = (end_addr - area_addr) >> HMFS_SEGMENT_SIZE_BITS;
	user_pages_count = user_segments_count << HMFS_PAGE_PER_SEG_BITS;

	data_blkoff = 0;
	node_blkoff = 0;
	node_segaddr = area_addr;
	main_addr = area_addr;
	data_segaddr = area_addr + HMFS_SEGMENT_SIZE;

	/* setup root inode */
	root_node_addr = node_segaddr;
	root_node = sbi->virt_addr + node_segaddr;
	node_blkoff += 1;
	root_node->footer.nid = cpu_to_le64(HMFS_ROOT_INO);
	root_node->footer.ino = cpu_to_le64(HMFS_ROOT_INO);
	root_node->footer.cp_ver = cpu_to_le64(HMFS_DEF_CP_VER);

	root_node->i.i_mode = cpu_to_le16(0x41ed);
	root_node->i.i_links = cpu_to_le32(2);
	root_node->i.i_uid = cpu_to_le32(current_fsuid().val);
	root_node->i.i_gid = cpu_to_le32(current_fsgid().val);

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
	dent_blk = sbi->virt_addr + data_segaddr;
	dent_blk->dentry[0].hash_code = 0;
	dent_blk->dentry[0].ino = cpu_to_le64(HMFS_ROOT_INO);
	dent_blk->dentry[0].name_len = cpu_to_le16(1);
	dent_blk->dentry[0].file_type = HMFS_FT_DIR;
	hmfs_memcpy(dent_blk->filename[0], ".", 1);

	dent_blk->dentry[1].hash_code = 0;
	dent_blk->dentry[1].ino = cpu_to_le64(HMFS_ROOT_INO);
	dent_blk->dentry[1].name_len = cpu_to_le16(2);
	dent_blk->dentry[1].file_type = HMFS_FT_DIR;
	hmfs_memcpy(dent_blk->filename[1], "..", 2);

	dent_blk->dentry_bitmap[0] = (1 << 1) | (1 << 0);

	/* setup init nat sit */
	sit_addr = node_segaddr + HMFS_PAGE_SIZE;
	nat_addr = node_segaddr + HMFS_PAGE_SIZE * 2;
	node_blkoff += 2;
	memset_nt(sbi->virt_addr + sit_addr, 0, HMFS_PAGE_SIZE << 1);

	cp_addr = nat_addr + HMFS_PAGE_SIZE;
	cp = sbi->virt_addr + cp_addr;
	node_blkoff += 1;

	/* segment 0 is first node segment */
	sit_journals = cp->sit_journals;
	nat_journals = cp->nat_journals;

	sit_journals[0].segno = cpu_to_le64(0);
	memset(sit_journals[0].entry.valid_map, 0, SIT_VBLOCK_MAP_SIZE);
	set_bit(0, (void *)sit_journals[0].entry.valid_map);	/* root inode */
	set_bit(1, (void *)sit_journals[0].entry.valid_map);	/* sit inode */
	set_bit(2, (void *)sit_journals[0].entry.valid_map);	/* nat inode */
	set_bit(3, (void *)sit_journals[0].entry.valid_map);	/* cp */
	sit_journals[0].entry.vblocks = cpu_to_le64(node_blkoff);
	sit_journals[0].entry.mtime = cpu_to_le64(get_seconds());

	/* segment 1 is first data segment */
	sit_journals[1].segno = cpu_to_le64(1);
	memset(sit_journals[1].entry.valid_map, 0, SIT_VBLOCK_MAP_SIZE);
	set_bit(0, (void *)sit_journals[1].entry.valid_map);
	sit_journals[1].entry.vblocks = cpu_to_le64(data_blkoff);
	sit_journals[1].entry.mtime = cpu_to_le64(get_seconds());

	/* update nat journal */
	nat_journals[0].nid = cpu_to_le64(HMFS_ROOT_INO);
	nat_journals[0].entry.version = cpu_to_le64(HMFS_DEF_CP_VER);
	nat_journals[0].entry.ino = nat_journals[0].nid;
	nat_journals[0].entry.block_addr = root_node_addr;

	/* update SSA */
	node_summary_block = sbi->virt_addr + ssa_addr;
	data_summary_block =
	    (void *)data_summary_block + HMFS_SUMMARY_BLOCK_SIZE;

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
	set_struct(cp, cur_node_segno, 0);
	set_struct(cp, cur_node_blkoff, node_blkoff);
	set_struct(cp, cur_data_segno, 1);
	set_struct(cp, cur_data_blkoff, data_blkoff);
	set_struct(cp, valid_inode_count, 1);

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
	set_struct(super, segment_count, user_segments_count);
	set_struct(super, ssa_blkaddr, ssa_addr);
	set_struct(super, main_blkaddr, main_addr);
	set_struct(super, cp_page_addr, cp_addr);

	length = (void *)(&super->checksum) - (void *)super;
	sb_checksum =
	    crc16(~0, (void *)super,
		  (void *)(&super->checksum) - (void *)super);
	set_struct(super, checksum, sb_checksum);

	/* copy another super block */
	area_addr = sizeof(struct hmfs_super_block);
	area_addr = align_page_right(area_addr);
	super = sbi->virt_addr + area_addr;
	hmfs_memcpy(super, sbi->virt_addr, sizeof(struct hmfs_super_block));
	return retval;
}

static struct super_operations hmfs_sops;	//TODO:re-orgnize this declaration 

static int hmfs_fill_super(struct super_block *sb, void *data, int slient)
{
	struct inode *root = NULL;
	struct hmfs_sb_info *sbi = NULL;
	int retval;

	/* sbi initialization */
	sbi = kzalloc(sizeof(struct hmfs_sb_info), GFP_KERNEL);
	if (sbi == NULL) {
		printk("[HMFS] No space for sbi!!");
		return -ENOMEM;
	}
	//get phys_addr from @data&virt_addr from ioremap 
	sb->s_fs_info = sbi;	//link sb and sbi:
	if (hmfs_parse_options((char *)data, sbi, 0)) {
		retval = -EINVAL;
		goto out;
	}
	////TODO : this part will be move to hmfs_init
	sbi->virt_addr = hmfs_ioremap(sb, sbi->phys_addr, sbi->initsize);
	printk("virtual address is: 0x%08u", sbi->virt_addr);
	if (!sbi->virt_addr) {
		retval = -EINVAL;
		goto out;
	}

	sb->s_magic = HMFS_SUPER_MAGIC;
	sb->s_op = &hmfs_sops;
	//TODO: further init sbi
	root = new_inode(sb);
	if (!root) {
		printk("[HMFS] No space for root inode!!");
		return -ENOMEM;
	}

	root->i_ino = 0;
	root->i_sb = sb;
	root->i_atime = root->i_ctime = root->i_mtime = CURRENT_TIME;
	inode_init_owner(root, NULL, S_IFDIR);	//????

	sb->s_root = d_make_root(root);	//kernel routin : makes a dentry for a root inode
	if (!sb->s_root) {
		printk("[HMFS] No space for root dentry");
		return -ENOMEM;
	}
	// create debugfs
	hmfs_build_stats(sbi);

	return 0;
out:
	//TODO:
	if (sbi->virt_addr) {
		printk("unmapping virtual address!");
		hmfs_iounmap(sbi->virt_addr);
	}
	kfree(sbi);
	return retval;
}

struct dentry *hmfs_mount(struct file_system_type *fs_type, int flags,
			  const char *dev_name, void *data)
{
	struct dentry const *entry;
	entry = mount_nodev(fs_type, flags, data, hmfs_fill_super);
	if (IS_ERR(entry)) {
		printk("mounting failed!");
	} else {
		printk("hmfs mounted!");
	}
	return entry;
}

struct file_system_type hmfs_fs_type = {
	.owner = THIS_MODULE,
	.name = "hmfs",
	.mount = hmfs_mount,
	.kill_sb = kill_anon_super,
};

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
	fi = (struct hmfs_inode_info *)kmem_cache_alloc(hmfs_inode_cachep, GFP_NOFS | __GFP_ZERO);	//free me when unmount
	if (!fi)
		return NULL;
	init_once((void *)fi);
	/*TODO: hmfs specific inode_info init work */
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
	//TODO: write & update in-DRAM NAT to NVM
	return 0;
}

static void hmfs_dirty_inode(struct inode *inode, int flags)
{
	//TODO: set inode dirty for future witeback
	return;
}

static void hmfs_put_super(struct super_block *sb)
{
	struct hmfs_sb_info *sbi = HMFS_SB(sb);
	//TODO:XXX 
	//1. destroy stat
	//2. iounmap
	if (sbi->virt_addr) {
		tprint("unmapping virtual address!");
		hmfs_iounmap(sbi->virt_addr);
	}
	//3. free internal components
	kfree(sbi);
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
//      .evict_inode = hmfs_evict_inode,
	.put_super = hmfs_put_super,
	.sync_fs = hmfs_sync_fs,

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

int init_hmfs(void)
{
	int err;

	err = init_inodecache();
	if (err)
		goto fail;
	err = register_filesystem(&hmfs_fs_type);
	if (err)
		goto fail;
	hmfs_create_root_stat();
	return 0;
fail:
	return err;

}

void exit_hmfs(void)
{
	// TO BE FIXED
	//  hmfs_destroy_stats(&sbi);
	hmfs_destroy_root_stat();
	unregister_filesystem(&hmfs_fs_type);
	printk("HMFS is removed!");
}

// Module Init/Exit
module_init(init_hmfs);
module_exit(exit_hmfs);
// Module Information
MODULE_LICENSE("GPL");
MODULE_AUTHOR(AUTHOR_INFO);
MODULE_DESCRIPTION(DEVICE_TYPE);
