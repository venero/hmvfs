#include <linux/module.h>	//init/exit module
#include <linux/kernel.h>	//
#include <linux/parser.h>	//match_token
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/magic.h>
#include <linux/fs.h>
#include <linux/ctype.h>	//isdigit()
#include <uapi/linux/magic.h>

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
				print
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
	print("Bad value '%s' for mount option '%s'\n", args[0].from, p);
	return -EINVAL;
      bad_opt:
	print("Bad mount option: \"%s\"\n", p);
	return -EINVAL;
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
		print("[HMFS] No space for sbi!!");
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
	tprint("virtual address is: 0x%08u", sbi->virt_addr);
	if (!sbi->virt_addr) {
		retval = -EINVAL;
		goto out;
	}
//	vt
//	sb->s_magic = HMFS_SUPER_MAGIC;
	sb->s_op = &hmfs_sops;
	//TODO: further init sbi
	root = new_inode(sb);
	if (!root) {
		print("[HMFS] No space for root inode!!");
		return -ENOMEM;
	}

	root->i_ino = 0;
	root->i_sb = sb;
	root->i_atime = root->i_ctime = root->i_mtime = CURRENT_TIME;
	inode_init_owner(root, NULL, S_IFDIR);	//????

	sb->s_root = d_make_root(root);	//kernel routin : makes a dentry for a root inode
	if (!sb->s_root) {
		print("[HMFS] No space for root dentry");
		return -ENOMEM;
	}
	// create debugfs
	hmfs_build_stats(sbi);

	return 0;
      out:
	//TODO:
	if (sbi->virt_addr) {
		tprint("unmapping virtual address!");
		hmfs_iounmap(sbi->virt_addr);
	}
	kfree(sbi);
	return retval;
}

struct dentry *hmfs_mount(struct file_system_type *fs_type, int flags,
			  const char *dev_name, void *data)
{
	struct dentry * entry;
	entry = mount_nodev(fs_type, flags, data, hmfs_fill_super);
	if (IS_ERR(entry)) {
		print("mounting failed!");
	} else {
		print("hmfs mounted!");
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
static struct super_operations hmfs_sops = {
	.alloc_inode = hmfs_alloc_inode,
	.drop_inode = generic_drop_inode,
	.destroy_inode = hmfs_destroy_inode,
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
	print("HMFS is removed!");
}

// Module Init/Exit
module_init(init_hmfs);
module_exit(exit_hmfs);
// Module Information
MODULE_LICENSE("GPL");
MODULE_AUTHOR(AUTHOR_INFO);
MODULE_DESCRIPTION(DEVICE_TYPE);
