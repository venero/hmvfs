#include <linux/slab.h>
#include <linux/types.h>

struct hmfs_sb_info {
	struct hmfs_stat_info *stat_info;
};

struct hmfs_stat_info {
	struct list_head stat_list;
	struct hmfs_sb_info *sbi;
};


/**
 * debug.c
 */
void __init hmfs_create_root_stat(void);
void hmfs_destroy_root_stat(void);
int hmfs_build_stats(struct hmfs_sb_info *sbi);
void hmfs_destroy_stats(struct hmfs_sb_info *sbi);
