#include <linux/kthread.h>
#include <linux/delay.h>
#include "hmfs.h"
#include "hmfs_fs.h"
#include "node.h"
#include "segment.h"

int warp_test() {
    hmfs_dbg("this is shown.\n");
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
	unsigned long long idx;
    struct hmfs_nm_info *nm_i = sbi->nm_info;
	struct hmfs_summary *summary = NULL;
	loff_t pos_start = *ppos >> (HMFS_BLOCK_SIZE_BITS(HMFS_I(inode)->i_blk_type));
	loff_t pos_end = (*ppos+ len) >> (HMFS_BLOCK_SIZE_BITS(HMFS_I(inode)->i_blk_type));
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
        if (unlikely(!ne)) {
            hmfs_dbg("radix_tree_lookup misses.\n");
            continue;
        }
        ni = &ne->ni;

		summary = get_summary_by_addr(sbi, L_ADDR(sbi,dn));
		switch (type) {
			case FLAG_WARP_NORMAL:
                // this case won't exist for now.
				clear_warp_read_candidate_bit(summary);
				clear_warp_write_candidate_bit(summary);
				clear_warp_read_bit(summary);
				clear_warp_write_bit(summary);
				break;
			case FLAG_WARP_READ:
                if (get_warp_read_pure(summary)) break;
                if (!get_warp_is_candidate(summary)) {
					idx = i-(unsigned long long)di.ofs_in_node;
					hmfs_dbg("warp i:%llu idx:%llu\n",i,idx);
					ni->index = idx;
					wce = add_warp_candidate(sbi->nm_info, ni);
        			if (unlikely(!wce)) {
						hmfs_dbg("add_warp_candidate failed.\n");
            			continue;
        			}
					// Why add_warp_pending inside switch?
					// Because we rather having less pending entries than having too much
					wce = add_warp_pending(sbi->nm_info, ni);
        			if (unlikely(!wce)) {
						hmfs_dbg("add_warp_pending failed.\n");
            			continue;
        			}
				}
				set_warp_read_candidate_bit(summary);
				// set_warp_read_bit(summary);
				// clear_warp_write_bit(summary);
				break;
			case FLAG_WARP_WRITE:
                if (get_warp_write_pure(summary)) break;
                if (!get_warp_is_candidate(summary)) {
					idx = i-(unsigned long long)di.ofs_in_node;
					hmfs_dbg("warp i:%llu idx:%llu\n",i,idx);
					ni->index = idx;
					wce = add_warp_candidate(sbi->nm_info, ni);
        			if (unlikely(!wce)) {
						hmfs_dbg("add_warp_candidate failed.\n");
            			continue;
        			}
					wce = add_warp_pending(sbi->nm_info, ni);
        			if (unlikely(!wce)) {
						hmfs_dbg("add_warp_pending failed.\n");
            			continue;
        			}
				}
				set_warp_write_candidate_bit(summary);
				// clear_warp_read_bit(summary);
				// set_warp_write_bit(summary);
				break;
		}
		i+=ADDRS_PER_BLOCK;
	}
	// Call warp-preparation after a range request
	wake_up_warp(sbi);
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
    }
    switch(next_type){
    	case FLAG_WARP_NORMAL:
            nex = "normal";break;
	    case FLAG_WARP_READ:
            nex = "read";break;
	    case FLAG_WARP_WRITE:
            nex = "write";break;
    }
    hmfs_dbg("Dealing with nid:%d [%s]->[%s].\n",nid,cur,nex);
}

int hmfs_warp_update(struct hmfs_sb_info *sbi){
    struct hmfs_nm_info *nm_i = sbi->nm_info;
	struct warp_candidate_entry *le;
	struct warp_candidate_entry *tmp = (struct warp_candidate_entry *)kzalloc(sizeof(struct warp_candidate_entry),GFP_KERNEL);
	// struct hmfs_node *hn;
	struct hmfs_summary *summary = NULL;
    int current_type;
    int next_type;
    list_for_each_entry_safe(le, tmp, &nm_i->warp_candidate_list, list) {
        // hmfs_dbg("Dealing with nid:%d\n",le->nip->nid);
		summary = get_summary_by_addr(sbi, le->nip->blk_addr);
        current_type = get_warp_current_type(summary);
        next_type = get_warp_next_type(summary);
        print_update(le->nip->nid,current_type,next_type);
		switch(next_type){
    		case FLAG_WARP_NORMAL:
        	    reset_warp_normal(summary);break;
	    	case FLAG_WARP_READ:
        	    reset_warp_read(summary);break;
	    	case FLAG_WARP_WRITE:
        	    reset_warp_write(summary);break;
    	}
        list_del(&le->list);
		kfree(le);
	}
    return 0;
}

inline void wake_up_warp(struct hmfs_sb_info *sbi) {
	if (sbi->warp_thread) {
		smp_wmb();
		wake_up_process(sbi->warp_thread->hmfs_task);
	}
}



int warp_prepare_for_reading(struct node_info *ni) {
	hmfs_dbg("[WARP] prepare reading ino:%d nid:%d index:%llu\n",ni->ino,ni->nid,ni->index);
	return 0;
}

int warp_prepare_for_writing(struct node_info *ni) {
	return 0;	
}

int warp_clean_up_for_reading(struct node_info *ni) {
	return 0;
}

int warp_clean_up_for_writing(struct node_info *ni) {
	return 0;	
}

int warp_prepare_node_info(struct hmfs_sb_info *sbi, struct node_info *ni) {
	struct hmfs_summary *summary;
	int type;
	int cur = ni->current_warp;
	if (cur!=FLAG_WARP_NORMAL) return 0;
	summary = get_summary_by_ni(sbi, ni);
	type = get_warp_current_type(summary);
	hmfs_dbg("[WARP] prepare ino:%d nid:%d\n",ni->ino,ni->nid);
	switch (type) {
		case FLAG_WARP_NORMAL:
			return 0;
		case FLAG_WARP_READ:
			return warp_prepare_for_reading(ni);
	    case FLAG_WARP_WRITE:
			return warp_prepare_for_writing(ni);
	}
	return 0;
}

// Current strategy:
// When called, prepare 'this' and the successor of 'this' with pre-read/pre-write.
// Check whether they have been prepared or not.
// If prepared, do nothing, prehaps report
// If not prepared, warp them
int warp_deal_with_pending(struct hmfs_sb_info *sbi, struct node_info *ni) {
	int ret=0;
	struct node_info *next = get_node_info_by_nid(sbi, ni->next_warp);
	if (next) ret = warp_prepare_node_info(sbi, next);
	ret = warp_prepare_node_info(sbi, ni);
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
		schedule();
        // hmfs_dbg("warp_function: B %d times\n", ++time_count);  
		while(!list_empty(&sbi->nm_info->warp_pending_list)) {
			hmfs_dbg("[warping] In\n");
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
	warp_thread->hmfs_task = kthread_run(warp_thread_func, sbi, "HMFS warp");
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
		kfree(sbi->warp_thread);
		sbi->warp_thread = NULL;
	}
}