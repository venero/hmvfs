#include <linux/kthread.h>
#include <linux/delay.h>
#include <asm-generic/current.h>
#include "hmfs.h"
#include "hmfs_fs.h"
#include "node.h"
#include "segment.h"

struct node_info *hmfs_get_node_info(struct inode *inode, int64_t index) {
	struct db_info di;
	int err = 0;
	struct node_info *ni;
	struct nat_entry *ne;
	struct direct_node *dn;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
    struct hmfs_nm_info *nm_i = sbi->nm_info;
	di.inode = inode;
	err = get_data_block_info(&di, index, LOOKUP);
	if (err) return NULL;
	dn = (struct direct_node *)di.node_block;
	ne = radix_tree_lookup(&nm_i->nat_root, di.nid);
    if (!ne) {
    	// hmfs_dbg("[HMFS] : radix_tree_lookup misses.\n");
		return NULL;
   	}
    return ni = &ne->ni;
}

int warp_clean_up_reading(struct hmfs_sb_info *sbi, struct node_info *ni) {
	// We use the metadata of a node_info to decide whether it is read/write frequent.
	// Thus there is somehow no need to unmap.
	// Because when the node_info is read-frequent again, it will remap its data.
	// unmap_file_read_only_node_info(sbi, ni);
	if(ni->current_warp != FLAG_WARP_READ) return 0;
	ni->current_warp = FLAG_WARP_NORMAL;
	return 0;
}
// Functionality is moved to hmfs_warp_update()
// case FLAG_WARP_NORMAL:
int warp_clean_up_writing(struct hmfs_sb_info *sbi, struct node_info *ni) {
	if(ni->current_warp != FLAG_WARP_WRITE) return 0;
	clean_wp_node_info(sbi, ni);
	ni->current_warp = FLAG_WARP_NORMAL;
	return 0;	
}

inline void wake_up_warp(struct hmfs_sb_info *sbi) {
	if (sbi->warp_thread) {
		smp_wmb();
		wake_up_process(sbi->warp_thread->hmfs_task);
	}
}


bool warp_is_new_node_info(struct hmfs_sb_info *sbi, struct node_info *ni) {
	if (sbi->cm_info->new_version > ni->begin_version + 1) return false;
	else return true;
}

int warp_prepare_for_reading(struct hmfs_sb_info *sbi, struct node_info *ni) {
	int ret = 0;	
	struct hmfs_summary *summary = NULL;
	summary = get_summary_by_addr(sbi, ni->blk_addr);
	// hmfs_dbg("[WARP] prepare reading ino:%d nid:%d index:%llu\n",ni->ino,ni->nid,ni->index);
	if (warp_is_new_node_info(sbi,ni)) {
		// hmfs_dbg("[WARP] ERR_WARP_TOO_NEW\n");
		return ERR_WARP_TOO_NEW;
	}
	if (ni->current_warp == FLAG_WARP_WRITE || get_warp_is_write_candidate(summary))	{
		// warp_clean_up_writing(sbi,ni);
		ni->current_warp = FLAG_WARP_NORMAL;
	}
	else {
		ret = vmap_file_read_only_node_info(sbi, ni);
		if (ret!=0) {
			// hmfs_dbg("[WARP] prepare reading for nid:%d failed.\n",ni->nid);
			return ret;
		}
		ni->current_warp = FLAG_WARP_READ;
	}
	return 0;
}

int warp_prepare_for_writing(struct hmfs_sb_info *sbi, struct node_info *ni) {
	struct hmfs_summary *summary = NULL;
	summary = get_summary_by_addr(sbi, ni->blk_addr);
	// hmfs_dbg("[WARP] prepare writing ino:%d nid:%d index:%llu\n",ni->ino,ni->nid,ni->index);
	if (warp_is_new_node_info(sbi,ni)) {
		// hmfs_dbg("[WARP] ERR_WARP_TOO_NEW\n");
		return ERR_WARP_TOO_NEW;
	}
	if (ni->current_warp == FLAG_WARP_READ || get_warp_is_read_candidate(summary))	{
		// warp_clean_up_reading(sbi,ni);
		ni->current_warp = FLAG_WARP_NORMAL;
	}
	else {		
		add_wp_node_info(sbi, ni);
		ni->current_warp = FLAG_WARP_WRITE;
	}
	return 0;	
}

int hmfs_warp_type_range_update(struct file *filp, size_t len, loff_t *ppos, unsigned long type) {
	struct inode *inode = filp->f_inode;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	struct db_info di;
	// uint16_t ofs_in_node;
	struct direct_node *dn;
	int err;
	struct nat_entry *ne;
	struct warp_candidate_entry *wce;
	struct node_info *ni;
	unsigned long long i;
	unsigned long long add=0;
	unsigned long long idx;
	uint64_t p_hash;
	int ret_proc, ret_tag;
   	struct hmfs_nm_info *nm_i = sbi->nm_info;
	struct hmfs_summary *summary = NULL;
	loff_t pos_start = *ppos >> (HMFS_BLOCK_SIZE_BITS(HMFS_I(inode)->i_blk_type));
	loff_t pos_end = (*ppos+ len) >> (HMFS_BLOCK_SIZE_BITS(HMFS_I(inode)->i_blk_type));
	unsigned long long range_start = *ppos;
	unsigned long long range_end;
	unsigned long long range_this;
	di.inode = inode;

	for (i=pos_start;i<pos_end;) {		
		err = get_data_block_info(&di, (int64_t)i, LOOKUP);
		// hmfs_dbg("warp type i:%lli oin:%u\n",i,(unsigned int)di.ofs_in_node);
		if (err) return -1;
		/* Useful!
		hmfs_dbg("i:%d nid:%d\n",(int)i,(int)di.nid);
		switch (type) {
			case FLAG_WARP_NORMAL:
				hmfs_dbg("norm nid:%d\n",(int)di.nid);
				break;
			case FLAG_WARP_READ:
				hmfs_dbg("read nid:%d\n",(int)di.nid);
				break;
			case FLAG_WARP_WRITE:
				hmfs_dbg("write nid:%d\n",(int)di.nid);
				break;
		}
		*/
		dn = (struct direct_node *)di.node_block;
		ne = radix_tree_lookup(&nm_i->nat_root, di.nid);
		// hmfs_dbg("Updating %u.\n",di.nid);
        if (unlikely(!ne)) {
            // hmfs_dbg("radix_tree_lookup misses.\n");
            continue;
        }
        ni = &ne->ni;

		summary = get_summary_by_addr(sbi, L_ADDR(sbi,dn));

		if (get_summary_type(summary) == SUM_TYPE_DN) add = ni->index + ADDRS_PER_BLOCK;
		else if (get_summary_type(summary) == SUM_TYPE_INODE) add = ni->index + NORMAL_ADDRS_PER_INODE;

		range_end = add << (HMFS_BLOCK_SIZE_BITS(HMFS_I(inode)->i_blk_type));
		if ( range_end > (*ppos+ len) ) range_end = *ppos + len;
		range_this = range_end - range_start;
		hmfs_dbg("s%llu,e%llu,this%llu\n",range_start,range_end,range_this);
		if ( range_end < range_start ) range_this=0;
		else range_start = range_end;

		switch (type) {
			case FLAG_WARP_NORMAL:
                // This case doesn't exist for now, bacause there is no operation can be called as NORMAL operation.
				clear_warp_read_candidate_bit(summary);
				clear_warp_write_candidate_bit(summary);
				clear_warp_read_bit(summary);
				clear_warp_write_bit(summary);
				break;
			case FLAG_WARP_READ:
				if (range_this!=0) {
					ni->nread+=(range_this >> (HMFS_BLOCK_SIZE_BITS(HMFS_I(inode)->i_blk_type)))>1?(range_this >> (HMFS_BLOCK_SIZE_BITS(HMFS_I(inode)->i_blk_type))):1;
					ni->sread+=range_this;
				}
                if (get_warp_read_pure(summary) && ni->current_warp==FLAG_WARP_READ) break;
                if (!get_warp_is_read_candidate(summary)) {
					idx = i-(unsigned long long)di.ofs_in_node;
					// hmfs_dbg("warp read i:%llu idx:%llu\n",i,idx);
					ni->index = idx;
					if (!get_warp_is_write_candidate(summary)) {
						wce = add_warp_candidate(sbi, ni);
        				if (unlikely(!wce)) {
							// hmfs_dbg("add_warp_candidate failed.\n");
        				}
					}
					// Why add_warp_pending inside switch?
					// Because we rather having less pending entries than having too much
					if (ni->current_warp!=FLAG_WARP_WRITE) wce = add_warp_pending(sbi, ni);
        			// if (unlikely(!wce)) {
					// 	break;
        			// }
				}
				set_warp_read_candidate_bit(summary);
				// set_warp_read_bit(summary);
				// clear_warp_write_bit(summary);
				break;
			case FLAG_WARP_WRITE:
				if (range_this!=0) {
					ni->nwrite+=(range_this >> (HMFS_BLOCK_SIZE_BITS(HMFS_I(inode)->i_blk_type)))>1?(range_this >> (HMFS_BLOCK_SIZE_BITS(HMFS_I(inode)->i_blk_type))):1;
					ni->swrite+=range_this;
				}
                if (get_warp_write_pure(summary) && ni->current_warp==FLAG_WARP_WRITE) break;
                if (!get_warp_is_write_candidate(summary)) {
					idx = i-(unsigned long long)di.ofs_in_node;
					// hmfs_dbg("warp write i:%llu idx:%llu\n",i,idx);
					ni->index = idx;
					if (!get_warp_is_read_candidate(summary)) {
						wce = add_warp_candidate(sbi, ni);
						if (unlikely(!wce)) {
							// hmfs_dbg("add_warp_candidate failed.\n");
						}
					}
					if (ni->current_warp!=FLAG_WARP_READ) wce = add_warp_pending(sbi, ni);
        			// if (unlikely(!wce)) {
					// 	break;
        			// }
				}
				set_warp_write_candidate_bit(summary);
				// clear_warp_read_bit(summary);
				// set_warp_write_bit(summary);
				break;
		}
		i=add;
		// i+=ADDRS_PER_BLOCK;
	}
	// Call warp-preparation after a range request
	wake_up_warp(sbi);

	p_hash= getPpath(current);
	printk("\nthe process exe path hash value is: %llu\n",p_hash);
	ret_proc= set_proc_info(p_hash, inode, ppos);
	ret_tag= radix_tree_tag_get(&nm_i->p_ino_root, inode->i_ino, 1);
	printk("ret_tag is:%d \n",ret_tag);
	if(ret_tag==1){
		mark_proc_dirty(inode);
		printk("find dirty inode proc\n");
		radix_tree_tag_clear(&nm_i->p_ino_root, inode->i_ino, 1);
	}
	return 0;
}

void print_update(int nid, int current_type, int next_type){
    char* cur="\0";
    char* nex="\0";
    switch(current_type){
    	case FLAG_WARP_NORMAL:
            cur = "normal";break;
	    case FLAG_WARP_READ:
            cur = "read";break;
	    case FLAG_WARP_WRITE:
            cur = "write";break;
	    case FLAG_WARP_HYBRID:
            cur = "hybrid";break;
    }
    switch(next_type){
    	case FLAG_WARP_NORMAL:
            nex = "normal";break;
	    case FLAG_WARP_READ:
            nex = "read";break;
	    case FLAG_WARP_WRITE:
            nex = "write";break;
	    case FLAG_WARP_HYBRID:
            nex = "hybrid";break;
    }
    // hmfs_dbg("Dealing with nid:%d [%s]->[%s].\n",nid,cur,nex);
}


int warp_prepare_node_info(struct hmfs_sb_info *sbi, struct node_info *ni) {
	struct hmfs_summary *summary;
	int type;
	int cur = ni->current_warp;
	summary = get_summary_by_ni(sbi, ni);
	// New direct node
	// hmfs_dbg("This %d %d\n", ni->begin_version, sbi->cm_info->new_version);
	if (ni->begin_version == sbi->cm_info->new_version) return 0;
	type = get_warp_current_type(summary);
	// No need to modify
	if (cur==type) return 0;
	// hmfs_dbg("[WARP] prepare ino:%d nid:%d type:%d\n",ni->ino,ni->nid,type);
	switch (type) {
		case FLAG_WARP_NORMAL:
			return 0;
		case FLAG_WARP_READ:
			return warp_prepare_for_reading(sbi, ni);
	    case FLAG_WARP_WRITE:
			return warp_prepare_for_writing(sbi, ni);
	}
	return 0;
}

int hmfs_warp_update(struct hmfs_sb_info *sbi){
    struct hmfs_nm_info *nm_i = sbi->nm_info;
	struct warp_candidate_entry *le;
	//struct warp_candidate_entry *tmp = (struct warp_candidate_entry *)kzalloc(sizeof(struct warp_candidate_entry),GFP_KERNEL);
	struct warp_candidate_entry *tmp;
	// struct hmfs_node *hn;
	struct hmfs_summary *summary = NULL;
    int current_type;
    int next_type;
	struct node_info *ni;
	unsigned long long mnormal, mread, mwrite;
    list_for_each_entry_safe(le, tmp, &nm_i->warp_candidate_list, list) {
        // hmfs_dbg("Dealing with nid:%d\n",le->nip->nid);
		ni = le->nip;
		summary = get_summary_by_addr(sbi, ni->blk_addr);
		// current_type here is about SUMMARY not NODE_INFO
        current_type = get_warp_current_type(summary);
        next_type = get_warp_next_type(summary);

		if ( next_type == FLAG_WARP_HYBRID ){
			mnormal = ni->nread * WARP_NVM_LREAD + ( ni->sread >> WARP_NVM_SREAD ) + ni->nwrite * WARP_NVM_LWRITE + ( ni->swrite >> WARP_NVM_SWRITE );
			mread = ( ni->sread >> WARP_NVM_SREAD ) + ni->nwrite * WARP_NVM_LWRITE + ( ni->swrite >> WARP_NVM_SWRITE );
			mwrite = ni->nread * WARP_DRAM_LREAD + ( ni->sread >> WARP_DRAM_SREAD ) + ni->nwrite * WARP_DRAM_LWRITE + ( ni->swrite >> WARP_DRAM_SWRITE );
			if (mread<mwrite && mread<mnormal) next_type = FLAG_WARP_READ;
			if (mwrite<mread && mwrite<mnormal) next_type = FLAG_WARP_WRITE;
		}

		switch(next_type){
    		case FLAG_WARP_NORMAL:
				// hmfs_dbg("[WARP] : normal update nid:%u\n",ni->nid);
				if (current_type==FLAG_WARP_WRITE) warp_clean_up_writing(sbi, ni);
				if (current_type==FLAG_WARP_READ) warp_clean_up_reading(sbi, ni);
				// hmfs_dbg("bt:%04X\n",le16_to_cpu(summary->bt));
				set_node_info_this_version(sbi, ni);
        	    reset_warp_normal(summary);break;
	    	case FLAG_WARP_READ:
				// hmfs_dbg("[WARP] : read update nid:%u\n",ni->nid);
				if (current_type==FLAG_WARP_WRITE) warp_clean_up_writing(sbi, ni);
				if (current_type==FLAG_WARP_WRITE) set_node_info_this_version(sbi, ni);
				// warp_prepare_for_reading(sbi, ni);
        	    reset_warp_read(summary);
				warp_prepare_node_info(sbi, ni);
				break;
                // if (get_warp_read_pure(summary)) hmfs_dbg("pure_read\n");
				// else hmfs_dbg("not_pure_read\n");
	    	case FLAG_WARP_WRITE:
				// hmfs_dbg("[WARP] : write update nid:%u\n",ni->nid);
				if (current_type==FLAG_WARP_READ) warp_clean_up_reading(sbi, ni);
				if (current_type==FLAG_WARP_READ) set_node_info_this_version(sbi, ni);
				// warp_prepare_for_writing(sbi, ni);
        	    reset_warp_write(summary);
				warp_prepare_node_info(sbi, ni);
				break;
	    	case FLAG_WARP_HYBRID:
				// hmfs_dbg("[WARP] : hybrid update nid:%u\n",ni->nid);
				if (current_type==FLAG_WARP_WRITE) warp_clean_up_writing(sbi, ni);
				if (current_type==FLAG_WARP_READ) warp_clean_up_reading(sbi, ni);
				ni->current_warp = FLAG_WARP_NORMAL;
				set_node_info_this_version(sbi, ni);
        	    reset_warp_normal(summary);break;
    	}
		ni->nread=0;
		ni->nwrite=0;
		ni->sread=0;
		ni->swrite=0;
        print_update(ni->nid,current_type,next_type);
        list_del(&le->list);
		// hmfs_dbg("nid:%u complete1.\n",ni->nid);
		destroy_warp_candidate(le);
		// hmfs_dbg("nid:%u complete2.\n",ni->nid);
	}
	// hmfs_dbg("hmfs_warp_update complete.\n");
    return 0;
}

struct node_info *find_next_warp_inter(struct hmfs_sb_info *sbi, struct node_info *ni) {
	struct hmfs_nm_info *nm_i = sbi->nm_info;
	struct inode *inode = NULL;
	// struct hmfs_inode_info *fi = HMFS_I(inode);
	//struct hmfs_proc_info *proc = radix_tree_lookup(&nm_i->p_ino_root,ni->ino);
	struct hmfs_proc_info *proc = NULL;
	struct node_info *ret = NULL;
	int i;
	uint64_t p_hash = getPpath(current);
	if (ni==NULL) return NULL;
	inode = hmfs_iget(sbi->sb, ni->ino);
	proc = radix_tree_lookup(&nm_i->p_ino_root, ni->ino);
	if (!proc) return NULL;

	// hmfs_dbg("search nid %lu ino %lu\n", (unsigned long) ni->nid, (unsigned long) ni->ino);
	// if(!proc)
	// if(!proc){
	// 	radix_tree_insert(&nm_i->p_ino_root,ni->ino,fi->i_proc_info);
	// 	proc = fi->i_proc_info;
	// }
	for(i=0;i<4;i++,proc++){
		if(proc->proc_id==p_hash){
			ret = get_node_info_by_nid(sbi, proc->next_nid);
		}
	}
	// if (ret!=NULL) hmfs_dbg("This is %lu, next is %lu\n", (unsigned long) ni->nid ,(unsigned long) ret->nid);
	return ret;
}

inline struct node_info *find_next_warp_inner(struct hmfs_sb_info *sbi, struct node_info *ni) {
	struct node_info *next = get_node_info_by_nid(sbi, ni->next_warp);
	return next;
}

// Current strategy:
// When called, prepare 'this' and the successor of 'this' with pre-read/pre-write.
// Check whether they have been prepared or not.
// If prepared, do nothing, prehaps report
// If not prepared, warp them
int warp_deal_with_pending(struct hmfs_sb_info *sbi, struct node_info *ni) {
	int ret=0;
	struct node_info *next;
	// display_warp(sbi);
	next = find_next_warp_inner(sbi, ni);
	if (next) ret = warp_prepare_node_info(sbi, next);
	next = find_next_warp_inter(sbi, ni);
	if (next) ret = warp_prepare_node_info(sbi, next);
	ret = warp_prepare_node_info(sbi, ni);
	//display_warp(sbi);
	return 0;
}


static int warp_thread_func(void *data) {
	struct hmfs_sb_info *sbi = data;
	struct node_info *this;
	int time_count = 0;  
	int ret = 0;
    do {
        // hmfs_dbg("warp_function: A %d times\n", ++time_count);  
		set_current_state(TASK_UNINTERRUPTIBLE);
		// schedule();
		schedule_timeout_interruptible(msecs_to_jiffies(WARP_THREAD_SLEEP_TIME));
		// hmfs_dbg("[warping] warp_thread_func\n");
        // hmfs_dbg("warp_function: B %d times\n", ++time_count);  
		while(!list_empty(&sbi->nm_info->warp_pending_list)) {
			// hmfs_dbg("[warping] In\n");
			this = pop_one_warp_pending_entry(sbi->nm_info);
			ret = warp_deal_with_pending(sbi, this);
		}
        // hmfs_dbg("warp_function: C %d times\n", ++time_count);  
    } while(!kthread_should_stop());  
    return time_count;
}

int start_warp_thread(struct hmfs_sb_info *sbi) {
	struct hmfs_kthread *warp_thread = NULL;
	int err = 0;

	sbi->warp_thread = NULL;
	/* Initialize WARP kthread */
	warp_thread = kmalloc(sizeof(struct hmfs_kthread), GFP_KERNEL);
	if (!warp_thread) {
		return -ENOMEM;
	}

	init_waitqueue_head(&(warp_thread->wait_queue_head));
	warp_thread->hmfs_task = kthread_run(warp_thread_func, sbi, "HMFS_warp");
	sbi->warp_thread = warp_thread;
	if (IS_ERR(warp_thread->hmfs_task)) {
		err = PTR_ERR(warp_thread->hmfs_task);
		goto free_warp;
	}

	return 0;

free_warp:
	kfree(warp_thread);
	return err;
}

void stop_warp_thread(struct hmfs_sb_info *sbi) {
	if (sbi->warp_thread) {
		kthread_stop(sbi->warp_thread->hmfs_task);
		hmfs_bug_on(sbi, !list_empty(&sbi->nm_info->warp_pending_list));
		kfree(sbi->warp_thread);
		sbi->warp_thread = NULL;
	}
}
