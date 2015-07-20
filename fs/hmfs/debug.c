#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/pagemap.h>
#include "hmfs_fs.h"
#include "hmfs.h"

static LIST_HEAD(hmfs_stat_list);
static struct dentry *debugfs_root;
static DEFINE_MUTEX(hmfs_stat_mutex);

static int stat_show(struct seq_file *s, void *v)
{
	struct hmfs_stat_info *si;

	mutex_lock(&hmfs_stat_mutex);
	list_for_each_entry(si, &hmfs_stat_list, stat_list) {
		seq_printf(s, "=============General Infomation=============\n");
		seq_printf(s, "physical address:%lu\n",
			   (unsigned long)si->sbi->phys_addr);
		seq_printf(s, "virtual address:%p\n", si->sbi->virt_addr);
		seq_printf(s, "initial size:%lu\n", si->sbi->initsize);
		seq_printf(s, "page count:%lu\n", si->sbi->page_count);
		seq_printf(s, "segment count:%lu\n", si->sbi->segment_count);
		seq_printf(s, "SSA start address:%lu\n", si->sbi->ssa_addr);
		seq_printf(s, "main area range:%lu - %lu\n",
			   si->sbi->main_addr_start, si->sbi->main_addr_end);
	}
	mutex_unlock(&hmfs_stat_mutex);
	return 0;
}

static int stat_open(struct inode *inode, struct file *file)
{
	return single_open(file, stat_show, inode->i_private);
}

static const struct file_operations stat_fops = {
	.open = stat_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

int hmfs_build_stats(struct hmfs_sb_info *sbi)
{
	struct hmfs_stat_info *si;

	sbi->stat_info = kzalloc(sizeof(struct hmfs_stat_info), GFP_KERNEL);
	if (!sbi->stat_info)
		return -ENOMEM;

	si = sbi->stat_info;
	si->sbi = sbi;
	mutex_lock(&hmfs_stat_mutex);
	list_add_tail(&si->stat_list, &hmfs_stat_list);
	mutex_unlock(&hmfs_stat_mutex);

	return 0;
}

void hmfs_destroy_stats(struct hmfs_sb_info *sbi)
{
	struct hmfs_stat_info *si = sbi->stat_info;

	mutex_lock(&hmfs_stat_mutex);
	list_del(&si->stat_list);
	mutex_unlock(&hmfs_stat_mutex);

	kfree(si);
}

void hmfs_create_root_stat(void)
{
	debugfs_root = debugfs_create_dir("hmfs", NULL);
	if (debugfs_root)
		debugfs_create_file("status", S_IRUGO, debugfs_root, NULL,
				    &stat_fops);
}

void hmfs_destroy_root_stat(void)
{
	debugfs_remove_recursive(debugfs_root);
	debugfs_root = NULL;
}
