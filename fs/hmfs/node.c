#include <linux/fs.h>
#include <linux/types.h>
#include "hmfs.h"
#include "hmfs_fs.h"
#include "node.h"
#include "segment.h"

static struct kmem_cache *nat_entry_slab;

static struct kmem_cache *warp_candidate_entry_slab;

const struct address_space_operations hmfs_nat_aops;

static inline bool inc_valid_node_count(struct hmfs_sb_info *sbi, struct inode *inode,
				int count, bool force)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	pgc_t alloc_valid_block_count;
	pgc_t free_blocks = free_user_blocks(sbi);

	lock_cm(cm_i);

	alloc_valid_block_count = cm_i->alloc_block_count + count;

	if (unlikely(!free_blocks && !force)) {
		unlock_cm(cm_i);
		return false;
	}

	if (inode)
		inode->i_blocks += count;

	cm_i->valid_node_count += count;
	cm_i->valid_block_count += count;
	cm_i->alloc_block_count = alloc_valid_block_count;
	unlock_cm(cm_i);

	return true;
}

static inline void dec_valid_node_count(struct hmfs_sb_info *sbi, struct inode *inode,
				int count, bool dec_valid)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);

	lock_cm(cm_i);
	cm_i->valid_node_count -= count;
	if (likely(inode))
		inode->i_blocks -= count;
	if (dec_valid)
		cm_i->valid_block_count -= count;
	unlock_cm(cm_i);
}

static nid_t hmfs_max_nid(struct hmfs_sb_info *sbi)
{
	nid_t nid = 1;
	int height = 0;

	while (++height <= sbi->nat_height)
		nid *= NAT_ADDR_PER_NODE;
	nid *= NAT_ENTRY_PER_BLOCK;
	return nid;
}

static inline struct nat_entry *__lookup_nat_cache(struct hmfs_nm_info *nm_i, nid_t n)
{
	return radix_tree_lookup(&nm_i->nat_root, n);
}

void destroy_node_manager(struct hmfs_sb_info *sbi)
{
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct nat_entry *result[NATVEC_SIZE], *entry;
	nid_t nid = HMFS_ROOT_INO;
	int found, i;

	//hmfs_dbg("[WARP] : Deleting wp inode 0\n");
	// Skip delete for now
	delete_all_wp_inode_entry(sbi);
	//hmfs_dbg("[WARP] : Deleting wp inode 1\n");

	if (!nm_i)
		return;

	lock_write_nat(nm_i);
	while (1) {
		found = radix_tree_gang_lookup(&nm_i->nat_root, (void **)result, nid, NATVEC_SIZE);
		if (!found)
			break;
		for (i = 0; i < found; i++) {
			entry = result[i];
			nid = entry->ni.nid + 1;
			list_del(&entry->list);
			kmem_cache_free(nat_entry_slab, entry);
		}
	}
	unlock_write_nat(nm_i);

	if (nm_i->free_nids)
		kfree(nm_i->free_nids);
	
	kfree(nm_i);
}

static int init_node_manager(struct hmfs_sb_info *sbi)
{
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct checkpoint_info *cp_i = cm_i->last_cp_i;
	struct hmfs_checkpoint *cp = cp_i->cp;

	nm_i->max_nid = hmfs_max_nid(sbi);
	nm_i->nat_cnt = 0;
	nm_i->last_visited_nid = 0;
	nm_i->predicted_nid = 0;
	nm_i->last_visited_ninfo = NULL;
	nm_i->hitcount = 0;
	nm_i->miscount = 0;
	nm_i->free_nids = kzalloc(PAGE_SIZE * 2, GFP_KERNEL);
	nm_i->next_scan_nid = le32_to_cpu(cp->next_scan_nid);
	nm_i->journaling_threshold = HMFS_JOURNALING_THRESHOLD;
	nm_i->nid_wrapped = 0;
	nm_i->sbi = sbi;
	if (nm_i->free_nids == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&nm_i->nat_entries);
	INIT_LIST_HEAD(&nm_i->dirty_nat_entries);
	// INIT_LIST_HEAD(&nm_i->wp_inode_entries);
	INIT_LIST_HEAD(&nm_i->free_nid_list);
	INIT_RADIX_TREE(&nm_i->wp_inode_root, GFP_ATOMIC);
	INIT_LIST_HEAD(&nm_i->warp_candidate_list);
	INIT_LIST_HEAD(&nm_i->warp_pending_list);
        //INIT_LIST_HEAD(&nm_i->proc_list);   /*init process info list*/
	INIT_RADIX_TREE(&nm_i->p_ino_root,GFP_ATOMIC);
	INIT_RADIX_TREE(&nm_i->p_pid_root,GFP_ATOMIC);
	INIT_RADIX_TREE(&nm_i->nat_root, GFP_ATOMIC);
	rwlock_init(&nm_i->nat_tree_lock);
	spin_lock_init(&nm_i->free_nid_list_lock);
	mutex_init(&nm_i->build_lock);
	mutex_init(&nm_i->wpl_lock);
	return 0;
}

void alloc_nid_failed(struct hmfs_sb_info *sbi, nid_t nid)
{
	/* Treat as deleted nid, which will be collected in scan_delete_nid */
	update_nat_entry(NM_I(sbi), nid, nid, 0, true);
}

/*
 *	Add a new nat_entry(node info) to nm_i->nat_entries
 */
static struct nat_entry *grab_nat_entry(struct hmfs_nm_info *nm_i, nid_t nid)
{
	struct nat_entry *new;
	struct hmfs_sb_info *sbi = nm_i->sbi;

	new = kmem_cache_alloc(nat_entry_slab, GFP_ATOMIC);
	if (!new)
		return NULL;
	if (radix_tree_insert(&nm_i->nat_root, nid, new)) {
		kmem_cache_free(nat_entry_slab, new);
		return NULL;
	}
	memset(new, 0, sizeof(struct nat_entry));
	new->ni.nid = nid;
	set_node_info_this_version(sbi,&new->ni);
	// hmfs_dbg("nid:%d ver:%u\n",nid,new->ni.begin_version);
	list_add_tail(&new->list, &nm_i->nat_entries);
	nm_i->nat_cnt++;
	return new;
}

struct node_info *get_node_info_by_nid(struct hmfs_sb_info *sbi, nid_t nid){
	struct nat_entry *ne;
	struct node_info *nip;
	if (nid==0) return NULL;
	ne = radix_tree_lookup(&sbi->nm_info->nat_root, nid);
    if (unlikely(!ne)) {
        //hmfs_dbg("[HMFS] : radix_tree_lookup misses.\n");
		return NULL;
    }
    nip = &ne->ni;
	return nip;
}

void destroy_warp_candidate(struct warp_candidate_entry* we) {
	kmem_cache_free(warp_candidate_entry_slab, we);
}

// Add node to warp_candidate_list for read/write property adjustion
struct warp_candidate_entry *add_warp_candidate(struct hmfs_sb_info *sbi, struct node_info *ni) {
	struct warp_candidate_entry *new;
	new = kmem_cache_alloc(warp_candidate_entry_slab, GFP_ATOMIC);
	if (!new) return NULL;
	memset(new, 0, sizeof(struct warp_candidate_entry));
	new->nip = ni;
	list_add_tail(&new->list, &sbi->nm_info->warp_candidate_list);
	return new;
}

// Add node to warp_pending_list for back ground warp process to pre-read/pre-write
struct warp_candidate_entry *add_warp_pending(struct hmfs_sb_info *sbi, struct node_info *ni) {
	struct warp_candidate_entry *new;
	struct hmfs_summary *summary = get_summary_by_addr(sbi, ni->blk_addr);
	// Currently, WARP acceleration is only for direct node and inode.
	if (get_summary_type(summary) != SUM_TYPE_DN && get_summary_type(summary) != SUM_TYPE_INODE) return NULL;
	new = kmem_cache_alloc(warp_candidate_entry_slab, GFP_ATOMIC);
	if (!new) return NULL;
	memset(new, 0, sizeof(struct warp_candidate_entry));
	new->nip = ni;
	mutex_lock(&sbi->nm_info->wpl_lock);
	list_add_tail(&new->list, &sbi->nm_info->warp_pending_list);
	mutex_unlock(&sbi->nm_info->wpl_lock);
	return new;
}

struct node_info *pop_one_warp_pending_entry(struct hmfs_nm_info *nm_i) {
	struct warp_candidate_entry *this;
	struct node_info *that;
	if (unlikely(list_empty(&nm_i->warp_pending_list))) return NULL;
	this = list_entry(nm_i->warp_pending_list.next, struct warp_candidate_entry, list);
	that = this->nip;
	mutex_lock(&nm_i->wpl_lock);
	list_del(&this->list);
	mutex_unlock(&nm_i->wpl_lock);
	destroy_warp_candidate(this);
	return that;
}


/*  
 *  @nid: NID of node to be truncated
 *  @inode: inode structure which node(nid) belongs to
 */
void truncate_node(struct inode *inode, nid_t nid)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct node_info ni;
	struct allocator *allocator;
	int ret;	

	get_node_info(sbi, nid, &ni);
	if (inode->i_blocks == 0) {
		hmfs_bug_on(sbi, ni.blk_addr != 0);
		return;
	}

	hmfs_bug_on(sbi, ni.blk_addr == 0);

	dec_valid_node_count(sbi, inode, 1, is_new_block(sbi, ni.blk_addr));
	update_nat_entry(nm_i, nid, inode->i_ino, 0, true);

	if (nid == inode->i_ino) {
		remove_orphan_inode(sbi, nid);
		dec_valid_inode_count(sbi);
	} else {
		mark_inode_dirty(inode);
	}

	ret = invalidate_delete_block(sbi, ni.blk_addr, 1);
	if (ret) {
		allocator = ALLOCATOR(sbi, SEG_NODE_INDEX);	
		allocator->nr_cur_invalid += ret >> HMFS_BLOCK_SIZE_4K_BITS[SEG_NODE_INDEX];
	}
}

/* return address of node in historic checkpoint */
struct hmfs_node *__get_node(struct hmfs_sb_info *sbi,
				struct checkpoint_info *cp_i, nid_t nid)
{
	struct hmfs_nat_entry *nat_entry;
	struct hmfs_summary *sum;
	block_t node_addr;

	if (cp_i->version == CM_I(sbi)->new_version)
		return get_node(sbi, nid);

	nat_entry = get_nat_entry(sbi, cp_i->version, nid);
	if (!nat_entry)
		return NULL;

	sum = get_summary_by_addr(sbi, L_ADDR(sbi, nat_entry));
	if (get_summary_start_version(sum) == cp_i->version) { // MZX : why?
		node_addr = le64_to_cpu(nat_entry->block_addr);
	} else {
		/* Address might be stored in journals */
		int i;
		nid_t local_nid;
		struct hmfs_checkpoint *hmfs_cp = cp_i->cp;

		node_addr = 0;
		for (i = 0; i < NUM_NAT_JOURNALS_IN_CP; ++i) {
			local_nid = le32_to_cpu(hmfs_cp->nat_journals[i].nid);
			if (local_nid == nid) {
				node_addr = le64_to_cpu(hmfs_cp->nat_journals[i].entry.block_addr);
				break;
			}
		}
		if (node_addr == 0)
			return NULL;
	}

	return ADDR(sbi, node_addr);
}

/*
 * @index: start index of data block of current node
 * @from: index of blocks to be truncated
 * @height: height of current node
 * @nid: nid of current node
 */
static int truncate_nodes(struct inode *inode, nid_t nid, char height, int64_t index,
				int64_t from)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	uint64_t free = 0;
	struct db_info di;

	hmfs_bug_on(sbi, !nid);

	di.nid = nid;
	di.inode = inode;
	di.local = 0;

	if (height == 1) {
		if (likely(index >= from)) {
			di.node_block = get_node(sbi, nid);
			di.ofs_in_node = 0;
			free = truncate_data_blocks(&di);
		} else {
			di.node_block = alloc_new_node(sbi, nid, inode, SUM_TYPE_DN, false);
			di.ofs_in_node = from - index;
			hmfs_bug_on(sbi, di.ofs_in_node >= ADDRS_PER_BLOCK);
			free = truncate_data_blocks_range(&di, ADDRS_PER_BLOCK - di.ofs_in_node);
		}
	} else {
		bool set_null = false;
		if (likely(index >= from)) {
			di.node_block = get_node(sbi, nid);
			di.ofs_in_node = 0;
		} else {
			set_null = true;
			di.node_block = alloc_new_node(sbi, nid, inode, SUM_TYPE_IDN, false);
			di.ofs_in_node = (from - index) >> HEIGHT_TO_SHIFT(height);
			hmfs_bug_on(sbi, di.ofs_in_node >= NIDS_PER_BLOCK);
		}
	
		for (; di.ofs_in_node < NIDS_PER_BLOCK; di.ofs_in_node++) {
			nid_t next_nid = le32_to_cpu(di.node_block->in.nid[di.ofs_in_node]);
			int64_t next_index;
			if (!next_nid)
				continue;
			next_index = index + (di.ofs_in_node << HEIGHT_TO_SHIFT(height));
			free += truncate_nodes(inode, next_nid, height - 1, next_index, from);
			if (unlikely(set_null))
				di.node_block->in.nid[di.ofs_in_node] = 0;
		}
	}

	if (index >= from) {
		truncate_node(inode, nid);
		free++;
	}

	return free;
}

int truncate_inode_blocks(struct inode *inode, loff_t from)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	struct db_info di;
	uint8_t blk_type = HMFS_I(inode)->i_blk_type;
	int err = 0;
	uint8_t height = HMFS_I(inode)->i_height;
	int64_t start = (from + HMFS_BLOCK_SIZE[blk_type] - 1) >> HMFS_BLOCK_SIZE_BITS(blk_type);
	
	di.inode = inode;
	if (start < NORMAL_ADDRS_PER_INODE) {
		err = get_data_block_info(&di, start, ALLOC);
		if (err)
			return err;
		err = truncate_data_blocks_range(&di, NORMAL_ADDRS_PER_INODE - di.ofs_in_node);
		if (err < 0 && err != -ENODATA)
			goto fail;
		start = NORMAL_ADDRS_PER_INODE;
	}

	start -= NORMAL_ADDRS_PER_INODE;
	if (height) {
		struct hmfs_inode *hi = alloc_new_node(sbi, inode->i_ino, inode, SUM_TYPE_INODE, false);
		nid_t nid = le32_to_cpu(hi->i_nid);
		hmfs_bug_on(sbi, !nid);
		err = truncate_nodes(inode, nid, height, 0, start);
		hi->i_nid = NULL_NID;
		if (!start)
			HMFS_I(inode)->i_height = 0;
	}
	truncate_file_block_bitmap(inode, from);
fail:
	return err > 0 ? 0 : err;
}

void gc_update_nat_entry(struct hmfs_nm_info *nm_i, nid_t nid, block_t blk_addr)
{
	struct nat_entry *entry;

	lock_write_nat(nm_i);
	entry = __lookup_nat_cache(nm_i, nid);
	if (entry) {
		entry->ni.blk_addr = blk_addr;
	}

	unlock_write_nat(nm_i);
}

void update_nat_entry(struct hmfs_nm_info *nm_i, nid_t nid, nid_t ino,
		      block_t blk_addr, bool dirty)
{
	struct nat_entry *e, *le;

	lock_write_nat(nm_i);
retry:
	e = __lookup_nat_cache(nm_i, nid);

	if (!e) {
		e = grab_nat_entry(nm_i, nid);
		if (!e) {
			goto retry;
		}
	}
	e->ni.ino = ino;
	e->ni.nid = nid;
	e->ni.blk_addr = blk_addr;
	e->ni.flag = 0;

	if (dirty) {
		list_del(&e->list);
		INIT_LIST_HEAD(&e->list);
		if (nm_i->dirty_nat_entries.next == &nm_i->dirty_nat_entries) {
			list_add_tail(&e->list, &nm_i->dirty_nat_entries);
			goto unlock;
		}
		list_for_each_entry(le, &nm_i->dirty_nat_entries, list) {
			if (e->ni.nid < le->ni.nid) {
				list_add_tail(&e->list, &le->list);
				goto unlock;
			}
		}
		list_add_tail(&e->list, &nm_i->dirty_nat_entries);
	}
unlock:
	unlock_write_nat(nm_i);
}

// rb_tree operations
struct wp_data_page_entry *wp_data_page_search(struct rb_root *root, int key) {
	struct rb_node *node = root->rb_node;

  	while (node) {
  		struct wp_data_page_entry *data = container_of(node, struct wp_data_page_entry, node);
		int result;

		result = key-data->index;

		if (result < 0)
  			node = node->rb_left;
		else if (result > 0)
  			node = node->rb_right;
		else
  			return data;
	}
	return NULL;
}

int wp_data_page_insert(struct rb_root *root, struct wp_data_page_entry *data) {
  	struct rb_node **new = &(root->rb_node), *parent = NULL;

  	/* Figure out where to put new node */
  	while (*new) {
  		struct wp_data_page_entry *this = container_of(*new, struct wp_data_page_entry, node);
  		int result = data->index - this->index;

		parent = *new;
  		if (result < 0)
  			new = &((*new)->rb_left);
  		else if (result > 0)
  			new = &((*new)->rb_right);
  		else
  			return 1;
  	}

  	/* Add new node and rebalance tree. */
  	rb_link_node(&data->node, parent, new);
  	rb_insert_color(&data->node, root);

	return 0;
}

// caller should check if nid represents a valid inode number
// insert radix tree
// build red black tree
struct wp_nat_entry *init_wp_inode_entry(struct hmfs_nm_info *nm_i, struct inode *inode) {
	struct wp_nat_entry *wne;
	nid_t nid = inode->i_ino;
	wne = (struct wp_nat_entry *)kzalloc(sizeof(struct wp_nat_entry),GFP_KERNEL);
	wne->ino = nid;
	wne->rr = RB_ROOT;
	radix_tree_insert(&nm_i->wp_inode_root,nid,wne);
	return wne;
}

struct wp_nat_entry *search_wp_inode_entry_nid(struct hmfs_nm_info *nm_i, nid_t nid) {
	return radix_tree_lookup(&nm_i->wp_inode_root,nid);
}

struct wp_nat_entry *search_wp_inode_entry(struct hmfs_nm_info *nm_i, struct inode *inode) {
	nid_t nid = inode->i_ino;
	return search_wp_inode_entry_nid(nm_i,nid);
}

struct wp_data_page_entry *search_wp_data_block(struct hmfs_nm_info *nm_i, struct inode *inode, int index) {
	struct wp_nat_entry *wne = search_wp_inode_entry(nm_i, inode);
	if (!wne) return NULL;
	return wp_data_page_search(&wne->rr, index);
}

// insert red black tree
int add_wp_data_block(struct hmfs_nm_info *nm_i, struct inode *inode, int index, void *block) {
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	struct wp_nat_entry *wne;
	struct wp_data_page_entry *wdp;
	void *dp;
	int ret;
	nid_t nid = inode->i_ino;
	uint8_t blk_type = HMFS_I(inode)->i_blk_type;
	size_t page_size = 1 << HMFS_BLOCK_SIZE_BITS(blk_type);
	wne = radix_tree_lookup(&nm_i->wp_inode_root,nid);
	if (!wne) return 1;
	wdp = (struct wp_data_page_entry *)kzalloc(sizeof(struct wp_data_page_entry),GFP_KERNEL);
	if (!wdp) {
		return -ENOMEM;
	}
	dp = (void*)kzalloc(page_size,GFP_KERNEL);
	if (!dp) {
		kfree(wdp);
		return -ENOMEM;
	}
	if (block) {
		radix_tree_tag_set(&sbi->nm_info->wp_inode_root,wne->ino,1);
		memcpy(dp,block,page_size);
	}
				
	wdp->index = index;
	wdp->dp_addr = dp;
	ret = wp_data_page_insert(&wne->rr, wdp);
	if (ret) return 1;
	return 0;
}

//	Cleanup: clean dirty bits (write back)
//	Delete: delete the entry

int cleanup_wp_inode_entry(struct hmfs_sb_info *sbi, struct wp_nat_entry *wne) {
	struct wp_data_page_entry *wdp;
	struct rb_node *node;
	void* ret;
	//hmfs_dbg("[HMFS] : Entered data block entry cleanup.\n");
  	for (node = rb_first(&wne->rr); node; node = rb_next(node)) {
		wdp = rb_entry(node, struct wp_data_page_entry, node);
		// hmfs_dbg("Cleanup index: %d.\n",wdp->index);
		ret = hmfs_wp_wdp_write_back(hmfs_iget(sbi->sb, wne->ino), wdp );
		if (ret==NULL) return 1;
	}
	return 0;
}

int cleanup_one_wp_inode_entry(struct hmfs_sb_info *sbi, struct inode *inode) {
	struct wp_nat_entry *wne;
	nid_t nid = inode->i_ino;
	int ret;
	wne = radix_tree_lookup(&sbi->nm_info->wp_inode_root,nid);
	if (!wne) return 1;
	ret = cleanup_wp_inode_entry(sbi, wne);
	if (ret!=0) return ret;
	radix_tree_tag_clear(&sbi->nm_info->wp_inode_root,wne->ino,1);
	return 0;
}

int cleanup_all_wp_inode_entry(struct hmfs_sb_info *sbi) {
	int i;
	unsigned int count=1;
	int ret;
	struct wp_nat_entry *wne[10];
	//hmfs_dbg("[HMFS] : Entered inode entry cleanup.\n");
	while (count>0) {
		count = radix_tree_gang_lookup_tag(&sbi->nm_info->wp_inode_root,(void **)&wne[0],0,10,1);
		//hmfs_dbg("[HMFS] : There are %d dirty inode entries this round.\n",count);
		for (i=0;i<count;++i) {
			//hmfs_dbg("[HMFS] : Cleanup inode: %u.\n",wne[i]->ino);
			ret = cleanup_wp_inode_entry(sbi, wne[i]);
			if (ret!=0) return ret;
			radix_tree_tag_clear(&sbi->nm_info->wp_inode_root,wne[i]->ino,1);
		}
	}
	return 0;
}

int delete_one_wp_inode_wdp_entry(struct hmfs_nm_info *nm_i, struct inode *inode, int index) {
	struct wp_nat_entry *wne;
	nid_t nid = inode->i_ino;
	struct wp_data_page_entry *wdp;
	wne = radix_tree_lookup(&nm_i->wp_inode_root,nid);
	wdp = search_wp_data_block(nm_i, inode, index);
	rb_erase(&wdp->node, &wne->rr);
	return 0;	
}

int delete_all_wp_wdp_entry(struct wp_nat_entry *wne) {
	struct wp_data_page_entry *wdp = NULL;
	struct rb_node *node;
	//hmfs_dbg("Delete inode: %u.\n",wne->ino);
  	for (node = rb_first(&wne->rr); node; node = rb_next(node)) {
		if (wdp!=NULL) {
			//hmfs_dbg("[WARP] : Release wdp:%llx\n", (unsigned long long)wdp);
			kfree(wdp);
		}
		wdp = rb_entry(node, struct wp_data_page_entry, node);
		//hmfs_dbg("[HMFS] : Delete index: %d.\n",wdp->index);
		rb_erase(&wdp->node, &wne->rr);
		//hmfs_dbg("dbg1\n");
		//hmfs_dbg("Release dp_addr:%llx\n",(unsigned long long)wdp->dp_addr);
		kfree(wdp->dp_addr);
		//hmfs_dbg("dbg2\n");
		// Perhaps kfree(node) here
		// kfree(wdp);
	}
	//hmfs_dbg("[HMFS] : Last Release wdp:%llx\n",(unsigned long long)wdp);
	if (wdp!=NULL) 
		kfree(wdp);
	//hmfs_dbg("[WARP] : dbg3\n");
	return 0;
}

int delete_one_wp_inode_entry(struct hmfs_nm_info *nm_i, struct inode *inode) {
	nid_t nid = inode->i_ino;
	struct wp_nat_entry *wne;
	int ret;
	wne = radix_tree_lookup(&nm_i->wp_inode_root,nid);
	if (!wne) return 1;
	ret = delete_all_wp_wdp_entry(wne);
	if (ret!=0) return ret;
	radix_tree_delete(&nm_i->wp_inode_root, wne->ino);
	kfree(wne);
	return 0;
}

int delete_all_wp_inode_entry(struct hmfs_sb_info *sbi) {
	int i;
	unsigned int count=1;
	int ret;
	struct wp_nat_entry *wne[10];
	if (cleanup_all_wp_inode_entry(sbi)!=0) {
		//hmfs_dbg("[WARP] : here are dirty inode entries after cleanup.\n");
		return 1;
	} 
	//hmfs_dbg("[WARP] : Entered inode entry delete.\n");
	while (count>0) {
		count = radix_tree_gang_lookup(&sbi->nm_info->wp_inode_root,(void **)&wne[0],0,10);
		//hmfs_dbg("[WARP] : There are %d inode entries this round.\n",count);
		for (i=0;i<count;++i) {
			//hmfs_dbg("[WARP] : Deleting the %d th inode.\n",i);
			ret = delete_all_wp_wdp_entry(wne[i]);
			if (ret!=0) {
				//hmfs_dbg("[WARP] : Delete error with return %d.\n",ret);
				return ret;
			}
			radix_tree_delete(&sbi->nm_info->wp_inode_root, wne[i]->ino);
			//hmfs_dbg("[WARP] : Release wne:%llx\n",(unsigned long long)wne[i]);
			kfree(wne[i]);
		}
	}
	return 0;
}

/*
 * return node address in NVM by nid, would not allocate
 * new node
 */
void *get_node(struct hmfs_sb_info *sbi, nid_t nid)
{
	struct node_info ni;
	int err;

	if (nid == NULL_NID) {
		return ERR_PTR(-ENODATA);
	}

	err = get_node_info(sbi, nid, &ni);

	if (err) {
		return ERR_PTR(err);
	}
	if (ni.blk_addr == 0) {
		return ERR_PTR(-ENODATA);
	}
	/* 
	 * accelerate speed to grab nat entry, 
	 * we don't need to search nat entry block
	 */

	return ADDR(sbi, ni.blk_addr);
}

static struct hmfs_node *__alloc_new_node(struct hmfs_sb_info *sbi, nid_t nid,
				struct inode *inode, char sum_type, bool force)
{
	void *src;
	struct nat_entry *e;
	block_t blk_addr, src_addr;
	struct hmfs_node *dest;
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct checkpoint_info *cp_i = CURCP_I(sbi);
	struct hmfs_summary *summary = NULL;
	unsigned int ofs_in_node = NID_TO_BLOCK_OFS(nid);
	int warp=0;
	// struct node_info *old_ni,*new_ni;

	src = get_node(sbi, nid);

	// old_ni = get_node_info_by_nid(sbi, nid);

	if (!IS_ERR(src)) {
		src_addr = L_ADDR(sbi, src);
		summary = get_summary_by_addr(sbi, src_addr);
		warp = get_warp_all(summary);
		if (get_summary_start_version(summary) == cp_i->version &&
					!is_inode_flag_set(HMFS_I(inode), FI_CONVERT_INLINE))
			return src;
	} else
		src_addr = 0;

	if (is_inode_flag_set(HMFS_I(inode), FI_NO_ALLOC))
		return ERR_PTR(-EPERM);

	if (!inc_valid_node_count(sbi, get_stat_object(inode, !IS_ERR(src)), 1, force))
		return ERR_PTR(-ENOSPC);

	blk_addr = alloc_free_node_block(sbi, true);

	if (blk_addr == 0) {
		inc_valid_node_count(sbi, get_stat_object(inode, !IS_ERR(src)), -1, true);
		return ERR_PTR(-ENOSPC);
	}

	dest = ADDR(sbi, blk_addr);
	if (!IS_ERR(src)) {
		hmfs_memcpy(dest, src, HMFS_BLOCK_SIZE[SEG_NODE_INDEX]);
	} else {
		memset(dest, 0, HMFS_BLOCK_SIZE[SEG_NODE_INDEX]);
	}

	summary = get_summary_by_addr(sbi, blk_addr);
	if (sum_type>=SUM_TYPE_INODE && sum_type<=SUM_TYPE_IDN) {
		e = __lookup_nat_cache(nm_i, nid);
		if (!e) {
			make_summary_entry(summary, nid, CM_I(sbi)->new_version, ofs_in_node, sum_type, 0);
		} else {
			make_summary_entry(summary, nid, CM_I(sbi)->new_version, ofs_in_node, sum_type, e->ni.next_warp);	
			/*
			switch (nm_i->last_visited_type) {
			case FLAG_WARP_READ:
				set_warp_read_bit(summary);
				clear_warp_write_bit(summary);
				break;
			case FLAG_WARP_WRITE:
				set_warp_write_bit(summary);
				clear_warp_read_bit(summary);
				break;
			case FLAG_WARP_NORMAL:
				clear_warp_write_bit(summary);
				clear_warp_read_bit(summary);
				break;
			}
			*/
		}
	} else {
		make_summary_entry(summary, nid, CM_I(sbi)->new_version, ofs_in_node, sum_type, 0);
	}
	if(warp!=0) {
		//hmfs_dbg("warpnid:%d,%u\n",warp,nid);
		set_warp_all(summary, warp);
	}
	update_nat_entry(nm_i, nid, inode->i_ino, blk_addr,	true);

	return dest;
}

void *alloc_new_node(struct hmfs_sb_info *sbi, nid_t nid, struct inode *inode,
				char sum_type, bool force)
{
	block_t addr;

	if (likely(inode))
		return __alloc_new_node(sbi, nid, inode, sum_type, force);

	if (is_checkpoint_node(sum_type)) {
		if (!inc_valid_node_count(sbi, NULL, 1, true))
			return ERR_PTR(-ENOSPC);
		addr = alloc_free_node_block(sbi, false);
		if (sum_type == SUM_TYPE_CP)
			memset(ADDR(sbi, addr), 0, HMFS_BLOCK_SIZE[SEG_NODE_INDEX]);
		return ADDR(sbi, addr);
	}

	if (!inc_gc_block_count(sbi, SEG_NODE_INDEX))
		return ERR_PTR(-ENOSPC);
	addr = alloc_free_node_block(sbi, true);
	return ADDR(sbi, addr);
}

int get_node_info(struct hmfs_sb_info *sbi, nid_t nid, struct node_info *ni)
{
	struct hmfs_nat_entry *ne_local;
	struct nat_entry *e;
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct hmfs_summary *summary = NULL;

	// hmfs_dbg("get_node_info:%d\n",nid);
	/* search in nat cache */
	lock_read_nat(nm_i);
	e = __lookup_nat_cache(nm_i, nid);
	if (e) {
		// hmfs_dbg("[cache hit]\n");
		ni->ino = e->ni.ino;
		ni->blk_addr = e->ni.blk_addr;
		if (nid == nm_i->last_visited_nid) {
			unlock_read_nat(nm_i);
			return 0;
		}
		// hmfs_dbg("[s1]%p\n",e);
		// hmfs_dbg("[s0]%llu\n",e->ni.blk_addr);
		if (e->ni.blk_addr!=0) {
			summary = get_summary_by_addr(sbi, e->ni.blk_addr);
			// if (get_warp_read(summary)) hmfs_dbg("[ck] nid:%d Read is set.\n",nid);			
			// if (get_warp_write(summary)) hmfs_dbg("[ck] nid:%d Write is set.\n",nid);
			// hmfs_dbg("[s2]%p,%p,%d\n",e,summary,get_summary_valid_bit(summary));
			// if (get_summary_valid_bit(summary)) {
			// 	hmfs_dbg("[s3]%d\n",summary->next_warp);
			// 	// For OnDisk result, cat twice.
			// 	hmfs_dbg("Current:%d, Predicted:%d, PNext:%d, OnDisk:%d\n", nid, nm_i->predicted_nid, e->ni.next_warp, summary->next_warp);
			// }
			// else hmfs_dbg("Current:%d, Predicted:%d, PNext:%d\n", nid, nm_i->predicted_nid, e->ni.next_warp);
		}
		if (nid == nm_i->predicted_nid && nm_i->predicted_nid!=0) {
			// hmfs_dbg("[predict hit]\n");
			nm_i->hitcount++;
		}
		else {
			// hmfs_dbg("[predict miss]\n");
			nm_i->miscount++;
		} 
		// if((nm_i->hitcount)>0) hmfs_dbg("[predict] hit:%d, mis:%d\n", nm_i->hitcount, nm_i->miscount);
		if (nm_i->last_visited_ninfo!=NULL) nm_i->last_visited_ninfo->next_warp = nid;
		nm_i->last_visited_nid = nid;
		nm_i->last_visited_ninfo = &(e->ni);
		nm_i->predicted_nid = e->ni.next_warp;
		// hmfs_dbg("[predict]4\n");

		unlock_read_nat(nm_i);
		return 0;
	}
	unlock_read_nat(nm_i);
	/* Search free nid */

	/* search in main area */
	ne_local = get_nat_entry(sbi, CM_I(sbi)->last_cp_i->version, nid);
	// hmfs_dbg("[cache miss]\n");
	if (ne_local == NULL) {
		return -ENODATA;
	}
	node_info_from_raw_nat(sbi, ni, ne_local);

	update_nat_entry(nm_i, nid, ni->ino, ni->blk_addr, false);
	return 0;
}

static inline void add_free_nid(struct hmfs_nm_info *nm_i, nid_t nid, u64 free,
				int *pos)
{
	nm_i->free_nids[*pos].nid = make_free_nid(nid, free);
}

/* Get free nid from journals of loaded checkpoint */
static void init_free_nids(struct hmfs_sb_info *sbi)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct hmfs_checkpoint *hmfs_cp = cm_i->last_cp_i->cp;
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	int i, pos = 0;
	block_t blk_addr;
	nid_t nid;

	
	lock_free_nid(nm_i);
	for (i = 0; i < NUM_NAT_JOURNALS_IN_CP; ++i) {
		nid = le32_to_cpu(hmfs_cp->nat_journals[i].nid);
		blk_addr = le64_to_cpu(hmfs_cp->nat_journals[i].entry.block_addr);
		if (blk_addr == 0 && nid > HMFS_ROOT_INO) {
			add_free_nid(nm_i, nid, 1, &pos);
			pos++;
		}
		if (nid >= HMFS_ROOT_INO)
			cm_i->nr_nat_journals = i + 1;
	}
	
	nm_i->fcnt = pos;
	unlock_free_nid(nm_i);
}

/* Check whether block_addr of nid in journal is 0 */
static int is_valid_free_nid(struct hmfs_sb_info *sbi, nid_t nid)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct hmfs_checkpoint *hmfs_cp = cm_i->last_cp_i->cp;
	int i;
	nid_t local_nid;

	if (!nm_i->nid_wrapped)
		goto check_value;

	/* Check journal */
	for (i = 0; i < cm_i->nr_nat_journals; ++i) {
		local_nid = le32_to_cpu(hmfs_cp->nat_journals[i].nid);
		if (local_nid == nid)
			return 0;
	}

	/*
	 * If we scan nat block wrapped around, we might add a nid to free 
	 * nid list twice. Because a nid might always exist in journal and
	 * mark as NULL. In addition, the value of it in NAT block is also 
	 * 0
	 */
	for (i = nm_i->delete_nid_index; i < BUILD_FREE_NID_COUNT; ++i) {
		if (nid == get_free_nid(nm_i->free_nids[i].nid))
			return 0;
	}

	lock_read_nat(nm_i);
	if (__lookup_nat_cache(nm_i, nid)) {
		unlock_read_nat(nm_i);
		return 0;
	}
	unlock_read_nat(nm_i);
check_value:
	return nid > HMFS_ROOT_INO;
}

static nid_t scan_nat_block(struct hmfs_sb_info *sbi, struct hmfs_nat_block *nat_blk,
				nid_t start_nid, int *pos)
{
	int i = start_nid % NAT_ENTRY_PER_BLOCK;
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	block_t blk_addr;

	for (; i < NAT_ENTRY_PER_BLOCK && *pos >= 0; i++, start_nid++) {
		if (start_nid > nm_i->max_nid)
			break;

		if (nat_blk != NULL)
			blk_addr = le64_to_cpu(nat_blk->entries[i].block_addr);
		else
			goto found;

		if (blk_addr == 0) {
found:
			if (!is_valid_free_nid(sbi, start_nid))
				continue;
			add_free_nid(nm_i, start_nid, 0, pos);
			*pos = *pos - 1;
		}
	}
	return start_nid;
}

/* Scan free nid from dirty nat entries */
static int scan_delete_nid(struct hmfs_sb_info *sbi, int *pos)
{
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct nat_entry *ne;
	struct list_head *head, *this, *next;

	head = &nm_i->dirty_nat_entries;
	lock_write_nat(nm_i);

	list_for_each_safe(this, next, head) {
		ne = list_entry(this, struct nat_entry, list);
		if (ne->ni.blk_addr == 0) {
			/*
			 * The nid is from the dirty nat entries. Thus, we should mark the
			 * free bit of nid and we should always write the nid to NVM when 
			 * flushing it
			 */
			add_free_nid(nm_i, ne->ni.nid, 1, pos);	
			list_del(&ne->list);
			radix_tree_delete(&nm_i->nat_root, ne->ni.nid);
			kmem_cache_free(nat_entry_slab, ne);
			nm_i->nat_cnt--;

			*pos = *pos - 1;
			if (*pos < 0)
				break;
		}
	}

	nm_i->delete_nid_index = *pos;
	unlock_write_nat(nm_i);
	return *pos;
}

static int build_free_nids(struct hmfs_sb_info *sbi)
{
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct hmfs_nat_block *nat_block = NULL;
	nid_t nid = nm_i->next_scan_nid;
	int pos = BUILD_FREE_NID_COUNT - 1;
	int count;

	if (nm_i->fcnt > 0)
		return 0;

	pos = scan_delete_nid(sbi, &pos);
	
	if (pos < 0)
		return BUILD_FREE_NID_COUNT;

	while (pos >= 0 && nid < nm_i->max_nid) {
		nat_block = get_nat_entry_block(sbi, CM_I(sbi)->last_cp_i->version, nid);
		nid = scan_nat_block(sbi, nat_block, nid, &pos);
	}

	count = BUILD_FREE_NID_COUNT - 1 - pos;
	if (nid > nm_i->max_nid) {
		pos++;
		while (pos < BUILD_FREE_NID_COUNT) {
			nm_i->free_nids[nm_i->fcnt++] =	nm_i->free_nids[pos++];
		}	
		hmfs_bug_on(sbi, nm_i->fcnt != count);
		nid = 0;
		nm_i->nid_wrapped = 1;
	}

	nm_i->next_scan_nid = nid;
	return count;
}

bool alloc_nid(struct hmfs_sb_info *sbi, nid_t *nid)
{
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	int num;

retry:
	if (cm_i->valid_node_count + 1 >= nm_i->max_nid)
		return false;

	lock_free_nid(nm_i);
	if (nm_i->fcnt > 0) {
		nm_i->fcnt--;
		*nid = get_free_nid(nm_i->free_nids[nm_i->fcnt].nid);
		unlock_free_nid(nm_i);
		update_nat_entry(nm_i, *nid, *nid, 0, true);
		return true;
	}
	unlock_free_nid(nm_i);

	mutex_lock(&nm_i->build_lock);
	num = build_free_nids(sbi);
	if (num) {
		lock_free_nid(nm_i);
		nm_i->fcnt = num;
		unlock_free_nid(nm_i);
	}
	mutex_unlock(&nm_i->build_lock);

	goto retry;
}

int create_node_manager_caches(void)
{
	nat_entry_slab = hmfs_kmem_cache_create("hmfs_nat_entry",
							sizeof(struct nat_entry), NULL);
	if (!nat_entry_slab)
		return -ENOMEM;
		
	warp_candidate_entry_slab = hmfs_kmem_cache_create("warp_candidate_entry",
							sizeof(struct warp_candidate_entry), NULL);
	if (!warp_candidate_entry_slab)
		return -ENOMEM;
		
	return 0;
}

void destroy_node_manager_caches(void)
{
	kmem_cache_destroy(nat_entry_slab);
	kmem_cache_destroy(warp_candidate_entry_slab);
}

/* get a nat/nat page from nat/nat in-NVM tree */
static void *__get_nat_page(struct hmfs_sb_info *sbi, block_t cur_node_addr,
				unsigned int order, unsigned char height)
{
	block_t child_node_addr;
	struct hmfs_nat_node *cur_node;
	unsigned ofs;

	if (!cur_node_addr) {
		return NULL;
	}

	cur_node = ADDR(sbi, cur_node_addr);
	if (!height)
		return (void *)cur_node;

	ofs = (height - 1) * LOG2_NAT_ADDRS_PER_NODE;
	child_node_addr = le64_to_cpu(cur_node->addr[order >> ofs]);

	return __get_nat_page(sbi, child_node_addr, order & ((1 << ofs) - 1),
				height - 1);
}

struct hmfs_nat_block *get_nat_entry_block(struct hmfs_sb_info *sbi,
				ver_t version, nid_t nid)
{
	struct checkpoint_info *cp_i = get_checkpoint_info(sbi, version, false);
	unsigned int blk_id = nid / NAT_ENTRY_PER_BLOCK;
	struct hmfs_nat_node *nat_root = cp_i->nat_root;
	char nat_height = sbi->nat_height;
	
	hmfs_bug_on(sbi, !cp_i);
	return __get_nat_page(sbi, L_ADDR(sbi, nat_root), blk_id, nat_height);
}

struct hmfs_nat_entry *get_nat_entry(struct hmfs_sb_info *sbi,
				ver_t version, nid_t nid)
{
	struct hmfs_nat_block *nat_block;
	unsigned int rem = nid % NAT_ENTRY_PER_BLOCK;

	nat_block = get_nat_entry_block(sbi, version, nid);
	if (!nat_block)
		return NULL;
	return &nat_block->entries[rem];
}

struct hmfs_nat_node *get_nat_node(struct hmfs_sb_info *sbi,
				ver_t version, unsigned int index)
{
	struct checkpoint_info *cp_i = get_checkpoint_info(sbi, version, false);
	struct hmfs_nat_node *nat_root = cp_i->nat_root;
	unsigned int height = 0, block_id;

	height = GET_NAT_NODE_HEIGHT(index);
	block_id = GET_NAT_NODE_OFS(index);
	hmfs_bug_on(sbi, !cp_i);

	return __get_nat_page(sbi, L_ADDR(sbi, nat_root), block_id, height);
}

static block_t __flush_nat_entries(struct hmfs_sb_info *sbi,
				struct hmfs_nat_node *old_nat_node, 
				struct hmfs_nat_node *cur_nat_node,	unsigned int blk_order,
				char height, void *nat_entry_page, int ofs_in_par)
{
	//FIXME : cannot handle no NVM space for nat tree
	struct hmfs_nat_node *cur_stored_node, *old_child_node = NULL, 
			*cur_child_node = NULL;
	struct hmfs_summary *summary;
	unsigned char blk_type;
	block_t cur_stored_addr, child_stored_addr, child_node_addr;
	nid_t nid;
	unsigned int cur_version, _ofs, new_blk_order;

	nid = MAKE_NAT_NODE_NID(height, blk_order);
	/* preparation for summary update */
	cur_version = CM_I(sbi)->new_version;
	blk_type = ((height == 1) ? SUM_TYPE_NATD : SUM_TYPE_NATN);

	/* leaf, alloc & copy nat entry block  */
	if (!height) {
		cur_stored_node = alloc_new_node(sbi, nid, NULL, SUM_TYPE_NATD, true);
		cur_stored_addr = L_ADDR(sbi, cur_stored_node);

		hmfs_bug_on(sbi, IS_ERR(cur_stored_node) || !cur_stored_node);
		hmfs_bug_on(sbi, !nat_entry_page);

		hmfs_memcpy(cur_stored_node, nat_entry_page, HMFS_BLOCK_SIZE[SEG_NODE_INDEX]);
		summary = get_summary_by_addr(sbi, cur_stored_addr);
		make_summary_entry(summary, nid, cur_version, ofs_in_par, SUM_TYPE_NATD, 0);
		
		/*
		for(i=0; i < NAT_ENTRY_PER_BLOCK; i++){
			if(!nat_entry_blk->entries[i].ino){
				//nid not allocated yet
				continue;
			}
			_addr = le64_to_cpu(nat_entry_blk->entries[i].block_addr); 
			raw_summary = get_summary_by_addr(sbi, _addr);
			make_summary_entry(raw_summary, nid, cur_version, i, blk_type);
		}
		*/

		return cur_stored_addr;
	}

	cur_stored_node = cur_nat_node;
	cur_stored_addr = 0;

	if (cur_nat_node == NULL || cur_nat_node == old_nat_node) {
		cur_stored_node = alloc_new_node(sbi, nid, NULL, SUM_TYPE_NATN, true);
		cur_stored_addr = L_ADDR(sbi, cur_stored_node);
		hmfs_bug_on(sbi, IS_ERR(cur_stored_node) || !cur_stored_node);

		if (cur_nat_node) {
			hmfs_memcpy(cur_stored_node, old_nat_node, HMFS_BLOCK_SIZE[SEG_NODE_INDEX]);
		} else {
			memset(cur_stored_node, 0, HMFS_BLOCK_SIZE[SEG_NODE_INDEX]);
		}

		summary = get_summary_by_addr(sbi, cur_stored_addr);
		make_summary_entry(summary, nid, cur_version, ofs_in_par, SUM_TYPE_NATN, 0);
	}

	//go to child
	_ofs = blk_order >> ((height - 1) * LOG2_NAT_ADDRS_PER_NODE);
	new_blk_order = blk_order & ((1 << ((height - 1) * LOG2_NAT_ADDRS_PER_NODE)) - 1);

	if (old_nat_node != NULL) {
		child_node_addr = le64_to_cpu(old_nat_node->addr[_ofs]);
		if (child_node_addr)
			old_child_node = ADDR(sbi, child_node_addr);
		else
			old_child_node = NULL;
	}

	if (cur_stored_node != NULL) {
		child_node_addr = le64_to_cpu(cur_stored_node->addr[_ofs]);
		if (child_node_addr)
			cur_child_node = ADDR(sbi, child_node_addr);
		else
			cur_child_node = NULL;
	}

	child_stored_addr = __flush_nat_entries(sbi, old_child_node,
								cur_child_node, new_blk_order, height - 1,
								nat_entry_page, _ofs);

	if (child_stored_addr) {
		/* child COWed, change addr to new block */
		cur_stored_node->addr[_ofs] = cpu_to_le64(child_stored_addr);
	}
	return cur_stored_addr;
}

static void clean_free_nid(struct hmfs_sb_info *sbi, nid_t nid)
{
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	int i;
	
	nid = make_free_nid(nid, 1);
	for (i = 0; i < nm_i->fcnt; i++) {
		if (nid == nm_i->free_nids[i].nid) {
			nm_i->free_nids[i].nid = get_free_nid(nid);
			return;
		}
	}
	hmfs_bug_on(sbi, 1);
}

static inline void clean_dirty_nat_entries(struct hmfs_sb_info *sbi) 
{
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct nat_entry *ne;
	struct list_head *head, *this, *next;
	
	head = &nm_i->dirty_nat_entries;
	list_for_each_safe(this, next, head) {
		ne = list_entry(this, struct nat_entry, list);
		// If the node is to be freed, delete it
		// Else, move this node to the tail of nat_entries
		if (ne->ni.flag & NAT_FLAG_FREE_NID) {
			clean_free_nid(sbi, ne->ni.nid);
			list_del(&ne->list);
			kmem_cache_free(nat_entry_slab, ne);
		} else {
			list_del(&ne->list);
			INIT_LIST_HEAD(&ne->list);
			ne->ni.flag = 0;
			list_add_tail(&ne->list, &nm_i->nat_entries);
		}
	}

	/* 
	 * Move journaling nat into dirty list and they are in order
	 * in nat_entries list because we add them in order in flush_nat_entries
	 */
	list_for_each_safe(this, next, &nm_i->nat_entries) {
		ne = list_entry(this, struct nat_entry, list);
		if (ne->ni.flag & NAT_FLAG_JOURNAL) {
			list_del(&ne->list);
			ne->ni.flag = 0;
			INIT_LIST_HEAD(&ne->list);
			list_add_tail(&ne->list, &nm_i->dirty_nat_entries);
		}
	}
}

static void cache_nat_journals_entries(struct hmfs_sb_info *sbi)
{
	struct hmfs_checkpoint *hmfs_cp = CM_I(sbi)->last_cp_i->cp;
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct hmfs_nat_journal *ne;
	nid_t nid, ino;
	block_t blk_addr;
	int i;

	for (i = 0; i < cm_i->nr_nat_journals; ++i) {
		ne = &hmfs_cp->nat_journals[i];
		nid = le32_to_cpu(ne->nid);
		ino = le32_to_cpu(ne->entry.ino);
		blk_addr = le64_to_cpu(ne->entry.block_addr);
		if (nid >= HMFS_ROOT_INO && blk_addr != 0)
			update_nat_entry(nm_i, nid, ino, blk_addr, true);
	}
}

int build_node_manager(struct hmfs_sb_info *sbi)
{
	struct hmfs_nm_info *info;
	int err;

	info = kzalloc(sizeof(struct hmfs_nm_info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;
	sbi->nm_info = info;

	err = init_node_manager(sbi);
	if (err) 
		return err;

	init_free_nids(sbi);
	cache_nat_journals_entries(sbi);
	
	return 0;
}

static int __flush_nat_journals(struct hmfs_checkpoint *hmfs_cp, 
				struct nat_entry *entry, int nr_dirty_nat, int* journal_pos)
{
	struct hmfs_nat_journal *nat_journal;

	if (nr_dirty_nat > NUM_NAT_JOURNALS_IN_CP - *journal_pos)
		return 1;

	nat_journal = &hmfs_cp->nat_journals[*journal_pos];
	*journal_pos = *journal_pos + nr_dirty_nat;

	while (nr_dirty_nat > 0) {
		entry = list_entry(entry->list.prev, struct nat_entry, list);
		nat_journal->nid = cpu_to_le32(entry->ni.nid);
		nat_journal->entry.ino = cpu_to_le32(entry->ni.ino);
		nat_journal->entry.block_addr = cpu_to_le64(entry->ni.blk_addr);
		nr_dirty_nat--;
		nat_journal++;
		entry->ni.flag |= NAT_FLAG_JOURNAL;
	}
	return 0;
}


/*
 * Caller should obtain hmfs_nm_info.nat_tree_lock.
 * And the journaling nat entries should always in dirty_nat_entries
 * list in runtime of fs. When flushing nat journals, we just move some
 * of them to nat_entries temporary
 */
static void flush_nat_journals(struct hmfs_sb_info *sbi, 
				struct hmfs_checkpoint *hmfs_cp)
{
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	int i, full;
	nid_t nid;
	struct nat_entry *new, *entry;
	struct list_head *this, *next;
	long new_blk_order, old_blk_order = -1;
	int nr_dirty_nat = 0;

	/* We should also flush dirty free nids */
	for (i = 0; i < nm_i->fcnt; i++) {
		nid = nm_i->free_nids[i].nid;

		if (is_dirty_free_nid(nid)) {
retry:
			new = kmem_cache_alloc(nat_entry_slab, GFP_ATOMIC);

			if (!new) {
				cond_resched();
				goto retry;
			}
			new->ni.nid = get_free_nid(nid);
			new->ni.blk_addr = 0;
			new->ni.flag = NAT_FLAG_FREE_NID;
			INIT_LIST_HEAD(&new->list);

			list_for_each_entry(entry, &nm_i->dirty_nat_entries, list) {
				if (new->ni.nid < entry->ni.nid) {
					list_add_tail(&new->list, &entry->list);
					break;
				}
			}
		}
	}

	if (nm_i->nid_wrapped) {
		nm_i->nid_wrapped = 0;
		return;
	}

	cm_i->nr_nat_journals = 0;
	entry = list_entry(nm_i->dirty_nat_entries.next, struct nat_entry, list);
	old_blk_order = (entry->ni.nid) / NAT_ENTRY_PER_BLOCK;
	list_for_each_entry(entry, &nm_i->dirty_nat_entries, list) { // MZX : nm_i->ditry_nat_entries are sorted in ascendent order!
		new_blk_order = (entry->ni.nid) / NAT_ENTRY_PER_BLOCK;
		if (new_blk_order != old_blk_order) {
			update_nat_stat(sbi, nr_dirty_nat);
			if (nr_dirty_nat && nr_dirty_nat <= nm_i->journaling_threshold) { // MZX : always true??
				full = __flush_nat_journals(hmfs_cp, entry, nr_dirty_nat,
								&cm_i->nr_nat_journals);
				if (full) {
					if (nm_i->journaling_threshold > 1)
						nm_i->journaling_threshold--;
					if (cm_i->nr_nat_journals >= NUM_NAT_JOURNALS_IN_CP)
						goto del_journal;
				}
			}
			nr_dirty_nat = 0;
			old_blk_order = new_blk_order;
		}
		if (nr_dirty_nat > nm_i->journaling_threshold)
			nm_i->journaling_threshold++; // MZX : ??
		nr_dirty_nat++;
	}
	nm_i->journaling_threshold++;

del_journal:

	/* Delete journaled nat */
	list_for_each_safe(this, next, &nm_i->dirty_nat_entries) {
		entry = list_entry(this, struct nat_entry, list);
		if (entry->ni.flag & NAT_FLAG_JOURNAL) {
			list_del(&entry->list);
			if (entry->ni.flag & NAT_FLAG_FREE_NID) {
				kmem_cache_free(nat_entry_slab, entry);
			} else {
				INIT_LIST_HEAD(&entry->list);
				list_add_tail(&entry->list, &nm_i->nat_entries);
			}
		}
	}
}

struct hmfs_nat_node *flush_nat_entries(struct hmfs_sb_info *sbi,
				struct hmfs_checkpoint *hmfs_cp)
{
	struct hmfs_nat_node *old_root_node, *new_root_node;
	struct hmfs_nat_block *old_entry_block, *new_entry_block;
	struct hmfs_summary *summary;
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct nat_entry *ne;
	struct page *empty_page;
	unsigned char nat_height;
	block_t old_blk_order, new_blk_order = 0, _ofs;
	block_t new_nat_root_addr;

	if (list_empty(&nm_i->dirty_nat_entries)) {
		return cm_i->last_cp_i->nat_root;
	}
	empty_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!empty_page) {
		return ERR_PTR(-ENOMEM);
	}
	new_entry_block = kmap(empty_page);	

	/* FIXME : no space */

	/* do real NAT flush */
	nat_height = sbi->nat_height;
	new_root_node = old_root_node = CM_I(sbi)->last_cp_i->nat_root;

	lock_write_nat(nm_i);

	flush_nat_journals(sbi, hmfs_cp);

	/* All nat entries have been written in journals */
	if (list_empty(&nm_i->dirty_nat_entries)) {
		new_root_node = cm_i->last_cp_i->nat_root;
		goto out;
	}

	ne = list_entry(nm_i->dirty_nat_entries.next, struct nat_entry, list);
	old_blk_order = (ne->ni.nid) >> LOG2_NAT_ENTRY_PER_BLOCK;
	unlock_write_nat(nm_i);
	old_entry_block = get_nat_entry_block(sbi, CM_I(sbi)->last_cp_i->version, 
							ne->ni.nid);
	lock_write_nat(nm_i);

	if (old_entry_block)
		hmfs_memcpy(new_entry_block, old_entry_block, HMFS_BLOCK_SIZE[SEG_NODE_INDEX]);

	list_for_each_entry_from(ne, &nm_i->dirty_nat_entries, list) {
		new_blk_order = (ne->ni.nid) / NAT_ENTRY_PER_BLOCK;

		if (new_blk_order != old_blk_order) {
			/*
			 * It's safe to unlock write to nat. Because fs have
			 * obtained all mutex_lock_op. And there'is only read operation
			 * in fs. The structure of list would not be changed
			 */
			unlock_write_nat(nm_i);
			
			/* one page done, flush it */
			new_nat_root_addr = __flush_nat_entries(sbi, 
										old_root_node, new_root_node, 
										old_blk_order, nat_height, 
										new_entry_block, 0);
			if (new_nat_root_addr != 0) {
				/* root node not be COWed */
				new_root_node = ADDR(sbi, new_nat_root_addr);
			}
			old_blk_order = new_blk_order;
			
			old_entry_block = get_nat_entry_block(sbi, CM_I(sbi)->last_cp_i->version,
					     			old_blk_order * NAT_ENTRY_PER_BLOCK);

			if (old_entry_block) {
				memcpy(new_entry_block, old_entry_block, HMFS_BLOCK_SIZE[SEG_NODE_INDEX]);
			} else {
				memset(new_entry_block, 0, HMFS_BLOCK_SIZE[SEG_NODE_INDEX]);
			}
			lock_write_nat(nm_i);
		}

		/* add the entry to the page */
		_ofs = NID_TO_BLOCK_OFS(ne->ni.nid);
		node_info_to_raw_nat(&ne->ni, &new_entry_block->entries[_ofs]);
	}

	/* the last one page done, flush it */
	unlock_write_nat(nm_i);
	new_nat_root_addr = __flush_nat_entries(sbi, old_root_node,
				   new_root_node, new_blk_order, nat_height,
				   new_entry_block, 0);
	lock_write_nat(nm_i);
	if (new_nat_root_addr != 0) {
		// root node COWed
		new_root_node = ADDR(sbi, new_nat_root_addr);
	}

	hmfs_bug_on(sbi,new_root_node==NULL || new_root_node == old_root_node);
	new_nat_root_addr = L_ADDR(sbi, new_root_node);
	summary = get_summary_by_addr(sbi, new_nat_root_addr);
	make_summary_entry(summary, 0, cm_i->new_version, 0, SUM_TYPE_NATN,0);

out:
	clean_dirty_nat_entries(sbi);

	unlock_write_nat(nm_i);

	kunmap(empty_page);
	__free_page(empty_page);
	return new_root_node;
}

void mark_block_valid_type(struct hmfs_sb_info *sbi, block_t addr)
{
	struct hmfs_summary *summary;
	int type;
	int i;

	summary = get_summary_by_addr(sbi, addr);
	type = get_summary_type(summary);
	set_summary_valid_bit(summary);

	if (type == SUM_TYPE_DN) {
		struct direct_node *dn = ADDR(sbi, addr);

		for (i = 0; i < ADDRS_PER_BLOCK; i++) {
			addr = le64_to_cpu(dn->addr[i]);
			if (addr) {
				summary = get_summary_by_addr(sbi, addr);
				set_summary_valid_bit(summary);
			}
		}
	} else if (type == SUM_TYPE_INODE) {
		struct hmfs_inode *hi = ADDR(sbi, addr);
		unsigned long flag;

		flag = le32_to_cpu(hi->i_flags);
		if (test_bit(FI_INLINE_DATA, &flag))
			return;

		for (i = 0; i < NORMAL_ADDRS_PER_INODE; i++) {
			addr = le64_to_cpu(hi->i_addr[i]);
			if (addr) {
				summary = get_summary_by_addr(sbi, addr);
				set_summary_valid_bit(summary);
			}
		}
	}
}

static void __mark_block_valid(struct hmfs_sb_info *sbi,	 
				struct hmfs_nat_node *cur_nat_node, unsigned int blk_order,
				unsigned int version, u8 height)
{
	//FIXME : cannot handle no NVM space for nat tree
	struct hmfs_nat_node *cur_child_node = NULL;
	struct hmfs_nat_block *nat_entry_blk = NULL;
	struct hmfs_summary *raw_summary;
	block_t cur_node_addr, child_node_addr;
	unsigned int i, new_blk_order, _ofs;

	BUG_ON(!cur_nat_node);
	cur_node_addr = L_ADDR(sbi, cur_nat_node);
	raw_summary = get_summary_by_addr(sbi, cur_node_addr);
	if (get_summary_start_version(raw_summary) != version) {
		//not this version created
		return;
	}

	set_summary_valid_bit(raw_summary);
	//leaf, alloc & copy nat entry block 
	if (!height) {
		hmfs_bug_on(sbi, get_summary_type(raw_summary) != SUM_TYPE_NATD);
		nat_entry_blk = HMFS_NAT_BLOCK(cur_nat_node); 
		for (i = 0; i < NAT_ENTRY_PER_BLOCK; i++) {
			if (!nat_entry_blk->entries[i].ino)
				continue;
			child_node_addr = le64_to_cpu(nat_entry_blk->entries[i].block_addr);
			if (child_node_addr) {
				mark_block_valid_type(sbi, child_node_addr);
			}
		}
		return;
	} else
		set_summary_valid_bit(raw_summary);

	//go to child
	new_blk_order = blk_order & ((1 << ((height - 1) * LOG2_NAT_ADDRS_PER_NODE)) - 1);

	for (i = 0; i < NAT_ADDR_PER_NODE; i++) {
		child_node_addr = le64_to_cpu(cur_nat_node->addr[i]);
		if(child_node_addr) {
			_ofs = (i << ((height-1) * LOG2_NAT_ADDRS_PER_NODE)) + new_blk_order;
			cur_child_node = ADDR(sbi, child_node_addr);
			__mark_block_valid(sbi, cur_child_node, _ofs, version, height - 1); 
		}
	}
}

void mark_block_valid(struct hmfs_sb_info *sbi, struct hmfs_nat_node *nat_root,
				struct hmfs_checkpoint *hmfs_cp)
{
	struct hmfs_cm_info *cm_i = CM_I(sbi);
	struct hmfs_nat_journal *nat_journal;
	int i;
	nid_t nid;
	block_t blk_addr;
	int nr_nat_journals;
	ver_t sto_version;

	nat_journal = hmfs_cp->nat_journals;
	if (sbi->recovery_doing) {
		nr_nat_journals = NUM_NAT_JOURNALS_IN_CP;
		sto_version = le32_to_cpu(hmfs_cp->checkpoint_ver);
	} else {
		nr_nat_journals = cm_i->nr_nat_journals;
		sto_version = CM_I(sbi)->new_version;
	}

	for (i = 0; i < nr_nat_journals; ++i, nat_journal++) {
		nid = le32_to_cpu(nat_journal->nid);
		blk_addr = le64_to_cpu(nat_journal->entry.block_addr);
		if (nid >= HMFS_ROOT_INO && blk_addr != 0) {
			mark_block_valid_type(sbi, blk_addr);
		
			if (sbi->recovery_doing) {
				cm_i->nr_nat_journals = i + 1;
			}
		}
	}

	__mark_block_valid(sbi, nat_root, 0, sto_version, sbi->nat_height);
}
