#include <linux/slab.h>
#include <linux/types.h>

struct hmfs_sb_info {
	/* 1. location info  */
	phys_addr_t 	phys_addr; 	//get from user mount 			[hmfs_parse_options]
	void 		*virt_addr; 	//hmfs_superblock & also HMFS address 	[ioremap]
	/* 2. inner usage information [blocknode\list...] */
	/* 3. s_lock for updating usage info   */
	/* 4. mount options*/
	unsigned long initsize;
	unsigned long s_mount_opt;
	/* 5. ...*/
	/**/
	/**/
	
	/**
	 * statiatic infomation, for debugfs
	 */
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

#ifdef TEST
void printtty(const char *format, ...);
#define print printtty 		//print to TTY for debugging convience
#define tprint printtty 	//test print
#else
#define print printk
#define tprint printk
#endif
