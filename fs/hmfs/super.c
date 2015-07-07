#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

#include "hmfs.h"

static struct hmfs_sb_info sbi;

static int __init init_hmfs_fs(void)
{
	int err;

	err=0;
	hmfs_create_root_stat();
	hmfs_build_stats(&sbi);
	return err;
}

static void __exit exit_hmfs_fs(void)
{
	hmfs_destroy_stats(&sbi);
	hmfs_destroy_root_stat();
}

module_init(init_hmfs_fs);
module_exit(exit_hmfs_fs);

MODULE_AUTHOR("SJTU RADLAB");
MODULE_DESCRIPTION("hybrid memory file system");
MODULE_LICENSE("GPL");
