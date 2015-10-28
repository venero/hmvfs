#ifndef CHECKPOINT_H
#define CHECKPOINT_H

/* hmfs checkpoint manager */
struct hmfs_cm_info {
	struct checkpoint_info *cur_cp_i;
	int new_version;
	struct page *cp_page;

	struct checkpoint_info *last_cp_i;

	int valid_inode_count;
	int valid_node_count;

	/* block whose count in summary is > 0 */
	int valid_block_count;
	/* maximum # of blocks users could get */
	int user_block_count;
	/* # of blocks of all dirty ,full and current segments */
	int alloc_block_count;

	rwlock_t journal_lock;

	struct mutex orphan_inode_mutex;
	struct list_head orphan_inode_list;
	unsigned long long n_orphans;

	struct radix_tree_root cp_tree_root;
	struct mutex cp_tree_lock;

	spinlock_t stat_lock;

	struct mutex cp_mutex;
};

#endif
