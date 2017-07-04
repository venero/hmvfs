#include <linux/sched.h>
#include <linux/string.h>
#include <linux/radix-tree.h>
#include "hmfs.h"
#include "hmfs_fs.h"
#include "node.h"


//static struct kmem_cache *proc_info_slab;
static int update_proc_info(struct inode *inode, struct hmfs_proc_info *proc);
static uint32_t set_proc_nid(struct inode *inode, pgoff_t index);

/*
* make process excutive path tobe uint64 number
*/
static int64_t proc_hash( const void *key, int len)  
{  
            const uint64_t m = 0xc6a4a7935bd1e995;  
            const int r = 47;  
            unsigned int seed = 5;
            uint64_t h = seed ^ (len * m);  
      
            const uint64_t * data = (const uint64_t *)key;  
            const uint64_t * end = data + (len/8);  
     	    const unsigned char * data2;	
	     
            while(data != end)  
            {  
                    uint64_t k = *data++;  
      
                    k *= m;   
                    k ^= k >> r;   
                    k *= m;   
      
                    h ^= k;  
                    h *= m;   
            }  
      
           data2 = (const unsigned char*)data;  
      
            switch(len & 7)  
            {  
            case 7: h ^= (uint64_t)(data2[6]) << 48;  
            case 6: h ^= (uint64_t)(data2[5]) << 40;  
            case 5: h ^= (uint64_t)(data2[4]) << 32;  
            case 4: h ^= (uint64_t)(data2[3]) << 24;  
            case 3: h ^= (uint64_t)(data2[2]) << 16;  
            case 2: h ^= (uint64_t)(data2[1]) << 8;  
            case 1: h ^= (uint64_t)(data2[0]);  
                    h *= m;  
            };  
       
            h ^= h >> r;  
            h *= m;  
            h ^= h >> r;  
      
            return h;  
}
//static sturct kmem_cache *proc_info_slab;

/*
*get proceess executive directory when read or write in a file
*/
uint64_t getPpath(struct task_struct *cur_task){
	char *path = NULL,*ptr = NULL;
	char *read_buf = NULL;
	int len = 0;
	uint64_t p_hash=0;
	

	read_buf = kmalloc(PAGE_SIZE,GFP_KERNEL);
	if(!read_buf){
	 	printk("read_buf alloc error!\n");
		goto error1;
	}
	path = kmalloc(PAGE_SIZE,GFP_KERNEL);
	if(!path){
		printk("path alloc error!\n");
		goto error2;
	}

	if(cur_task && cur_task->mm && cur_task->mm->exe_file){
		ptr = d_path(&cur_task->mm->exe_file->f_path,path,PAGE_SIZE);        
	}
	else{
		printk("task is null!\n");
	}

	len = strlen(ptr);
     	p_hash = proc_hash(ptr, len);
    	printk("ProcName:%s PID: %d\n",cur_task->comm, cur_task->pid);
    	printk("ProcPath:%s", ptr);
error1:
    	kfree(read_buf);
error2:
    	kfree(path);
    	return p_hash;
}


/*
*init process information for a specific process
*/
/*int init_proc_info(){
	return 0;
}*/

/*
* set process infomation in dram from file operations
* first should set beginning proc
*/
int set_proc_info(uint64_t proc_id, struct inode *inode, loff_t *ppos){
   
	//struct list_head *this, *head;
	loff_t pos;
	pgoff_t index;
	int ret;
	uint32_t nid;
   	struct hmfs_proc_info *new_proc;// *proc = NULL;
   	//struct hmfs_inode_info *fi = HMFS_I(inode);
   	//struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
   	//struct hmfs_nm_info *nm_i = NM_I(sbi);    
	unsigned char seg_type = HMFS_I(inode)->i_blk_type;
	//const unsigned int block_size = HMFS_BLOCK_SIZE[seg_type];
	const unsigned long long block_size_bits = HMFS_BLOCK_SIZE_BITS(seg_type);
	pos= *ppos;
    	index = pos >> block_size_bits;
	/*
	*set new process information if read a file
	*/
   	//new_proc = kmem_cache_alloc(proc_info_slab,GFP_KERNEL);
	new_proc = (struct hmfs_proc_info *)kzalloc(sizeof(struct hmfs_proc_info), GFP_KERNEL);
	printk("get in setpproc function\n");
	
   	if(!new_proc){
		printk("kazalloc erro");
		return -ENOMEM;
   	}
	new_proc->proc_id = proc_id;
	new_proc->next_ino = inode->i_ino;
	if(is_inline_inode(inode)){
		nid = inode->i_ino;
	}
	else
		nid = set_proc_nid(inode, index);
  	new_proc->next_nid =nid;
	printk("proc_ino: %lu proc_nid: %lu\n", (unsigned long) new_proc->next_ino, (unsigned long) new_proc->next_nid);
	ret = update_proc_info(inode, new_proc);
	/*if(ret)
		kmem_cache_free(proc_info_slab, new_proc);*/
   //	head = &nm_i->proc_list;
    /*
    if(proc_id != fi->i_proc_info->proc_id){
       // can flush proc into nvm now?
       // flush_proc();  
       update_proc_info();
    }
    if(inode->i_ino!=fi->i_proc_info->proc_nid){
    	update_proc_info();
    }*/
	/*	
    list_for_each(this,head){
    	proc = list_entry(this, struct hmfs_proc_info, list);
 	if(proc->proc_id!=proc_id){
		continue;
	}
	else if()
    }*/
    /* 
    new_proc = kmem_cache_alloc(proc_info_slab,GFP_KERNEL);
    if(!new_proc){
    	return -ENOMEM;
    }
    new_proc->proc_id = proc_id;
    new_proc->next_nid =  fi->i_ino;
    new_proc->next_nt =set_proc_type();
    list_add_tail(&new_proc->list,head);
    */
    	return 0;
}

/*
*judge node type, and set nid in proc_info
*/
static uint32_t set_proc_nid(struct inode *inode, pgoff_t index){
	struct node_info *ni;
	//struct nat_entry *ne;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	//struct firct_node *dn;
	//struct hmfs_nm_info *nm_i = sbi->nm_info;
	struct hmfs_summary *summary;
	uint32_t ret = 0;

	ni = hmfs_get_node_info(inode,(int64_t)index);
	
	if(ni==NULL)
		return inode->i_ino;
   	summary = get_summary_by_addr(sbi,ni->blk_addr);
	
	if(get_summary_type(summary)==SUM_TYPE_DN)
		return ni->nid;
	else if(get_summary_type(summary)==SUM_TYPE_INODE)
		return inode->i_ino;
	return ret;
}


/*
*update proc_info if file changed or node changed or proc_id changed
*add list entry should be down in this function
//
static int update_proc_info(struct hmfs_nm_info *nm_i, struct hmfs_proc_info *c_proc){
	struct list_head *head, *this, *next;
	struct hmfs_proc_info *proc=NULL, *l_proc = NULL, *n_proc = NULL;
	int ret = 0;
	
	head = &nm_i->proc_list;
 	list_for_each_safe(this, next ,head){
		proc = list_entry(this, struct hmfs_proc_info, list);
		if(proc->proc_id==c_proc->proc_id && proc->proc_nid==c_proc->proc_nid){
			if(this->prev!=head)
				l_proc = list_entry(this->prev, struct hmfs_proc_info, list);
					if(l_proc->proc_id==c_proc->proc_id && 
						proc->proc_nid==nm_i->last_visited_ninfo->ino){
						if(proc->proc_nt==c_proc->proc_nt)
							ret=1;
						else{
							list_del_init(&proc->list);
							kmem_cache_free(proc_info_slab, proc);
						}		
						proc = NULL;
						break;
					}
					//
					else{
						list_add_tail(&c_proc->list, head);
						break;
					}
					//
		}
	}
	if(proc)
		list_add_tail(&c_proc->list, head);
	else if(!ret)
		list_add_tail(&c_proc->list, next);
	return ret;
}
*/

static int update_proc_info(struct inode *inode, struct hmfs_proc_info *proc){
	
	uint64_t proc_id = proc->proc_id;
	struct inode *last_visit_ino;
	//nid_t *i_ino = inode->i_ino;
	struct hmfs_inode_info *fi = HMFS_I(inode);
	struct hmfs_inode_info *lfi = NULL;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	struct hmfs_nm_info *nm_i = NM_I(sbi);
	struct hmfs_proc_info *cur_proc, *pproc;
	int ret = 0, i = 0;
	int ret_tag = 0;

	printk("get into update proc\n");	
	//get last_visited inode if proc exists
	last_visit_ino = radix_tree_lookup(&nm_i->p_pid_root, proc_id);
	if(!last_visit_ino){
		printk("get in tree insert");
		radix_tree_insert(&nm_i->p_pid_root, proc_id, inode);
		goto end;
	}
	else {
		radix_tree_delete(&nm_i->p_pid_root, proc_id);
		radix_tree_insert(&nm_i->p_pid_root, proc_id, inode);
	}	
	lfi = HMFS_I(last_visit_ino);
	hmfs_dbg("Insert proc id:%llu ino:%lu last:%lu\n",(unsigned long long)proc_id,inode->i_ino,last_visit_ino->i_ino);

	//generally it is impossible to find last_ino not in the tree 
	// zsa: It is actually possible, though. Otherwise, how to initialize?
	cur_proc= radix_tree_lookup(&nm_i->p_ino_root, last_visit_ino->i_ino);
	if(!cur_proc){
		printk("get into ino tree insert\n");
		radix_tree_insert(&nm_i->p_ino_root, last_visit_ino->i_ino,lfi->i_proc_info);
		cur_proc= lfi->i_proc_info;
		radix_tree_insert(&nm_i->p_ino_root, inode->i_ino,fi->i_proc_info);
		printk("the first proc info is: %llu\n", fi->i_proc_info[0].proc_id);
		// goto end;
	}
	pproc=cur_proc;
	for(i=0;i<4;i++,cur_proc++){
		if(cur_proc->proc_id==0){
			//cur_proc->proc_id=proc->proc_id;
			//cur_proc->next_ino=proc->next_ino;
			//cur_proc->next_nid=proc->next_nid;
			//break;
			printk("proc_id=0\n");
			continue;
		}
		if(cur_proc->proc_id==proc->proc_id&&cur_proc->next_ino==proc->next_ino&&
			cur_proc->next_nid==proc->next_nid){
			printk("Found the right proc_info\n");
			ret=1;
			goto end;
		}
	}
	for(i=0;i<4;i++,pproc++){
		if(pproc->proc_id==0){
			pproc->proc_id=proc->proc_id;
			pproc->next_ino=proc->next_ino;
			pproc->next_nid=proc->next_nid;
			//fi->i_proc_info[i]= pproc;
			printk("get dirty value\n");
			break;
		}
	}
	//make sure there is one empty
	if(i<3)
		pproc++;
	else{
		pproc-=3;
	}
	pproc->proc_id=0;
	pproc->next_ino=0;
	pproc->next_nid=0;
	//fi->i_proc_info[i]= pproc;
	//set dirty tags
	printk("set tag\n");
	radix_tree_tag_set(&nm_i->p_ino_root,last_visit_ino->i_ino,1);
	ret_tag= radix_tree_tag_get(&nm_i->p_ino_root, last_visit_ino->i_ino,1);
	printk("ret_tag in update is %d\n",ret_tag);
end:
	return ret;
	
}

/*
*fetch process information
*if inode doesn't exist, then insert it;
*we need to justify whether the proc_info is null,when use this function
*/
struct hmfs_proc_info *fetch_proc(struct inode *inode, uint64_t proc_id){
	
	int i;
	struct hmfs_inode_info *fi = HMFS_I(inode);
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	struct hmfs_nm_info *nm_i = sbi->nm_info;
	struct hmfs_proc_info *proc = NULL;
	nid_t ino = inode->i_ino;
	
	proc = radix_tree_lookup(&nm_i->p_ino_root,ino);
	if(!proc){
		radix_tree_insert(&nm_i->p_ino_root,ino,fi->i_proc_info);
		proc = fi->i_proc_info;
	}
	for(i=0;i<4;i++,proc++){
		if(proc->proc_id==proc_id){
			break;
		}
	}
	return proc;
}

/*
*flush proc to nvm
*/
//int flush_proc(){
//}
