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
	struct direct_node *dn;
	int err;
	struct nat_entry *ne;
    struct warp_candidate_entry *wce;
	struct node_info *ni;
	long long i;
    struct hmfs_nm_info *nm_i = sbi->nm_info;
	struct hmfs_summary *summary = NULL;
	loff_t pos_start = *ppos >> (HMFS_BLOCK_SIZE_BITS(HMFS_I(inode)->i_blk_type));
	loff_t pos_end = (*ppos+ len) >> (HMFS_BLOCK_SIZE_BITS(HMFS_I(inode)->i_blk_type));
	di.inode = inode;
	for (i=pos_start;i<pos_end;) {
		err = get_data_block_info(&di, (int64_t)i, LOOKUP);
		hmfs_dbg("i:%d nid:%d\n",(int)i,(int)di.nid);
		if (err) return -1;
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
		dn = (struct direct_node *)di.node_block;
		ne = radix_tree_lookup(&nm_i->nat_root, di.nid);
        if (unlikely(!ne)) {
            hmfs_dbg("radix_tree_lookup misses.");
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
                if (!get_warp_is_candidate(summary)) wce = add_warp_candidate(sbi->nm_info, ni);
				set_warp_read_candidate_bit(summary);
				// set_warp_read_bit(summary);
				// clear_warp_write_bit(summary);
				break;
			case FLAG_WARP_WRITE:
                if (get_warp_write_pure(summary)) break;
                if (!get_warp_is_candidate(summary)) wce = add_warp_candidate(sbi->nm_info, ni);
				set_warp_write_candidate_bit(summary);
				// clear_warp_read_bit(summary);
				// set_warp_write_bit(summary);
				break;
		}
		i+=ADDRS_PER_BLOCK;
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
    list_for_each_entry_safe(le, tmp, &nm_i->warp_candidate, list) {
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