#include <linux/sched.h>
#include <linux/string.h>

#include "hmfs.h"
#include "hmfs_fs.h"
#include "node.h"


static struct kmem_cache *proc_info_slab;

/*
* make process excutive path tobe uint64 number
*/
uint64_t proc_hash( const void *key, int len)  
{  
            const uint64_t m = 0xc6a4a7935bd1e995;  
            const int r = 47;  
            unsigned int seed = 5;
            uint64_t h = seed ^ (len * m);  
      
            const uint64_t * data = (const uint64_t *)key;  
            const uint64_t * end = data + (len/8);  
      
            while(data != end)  
            {  
                    uint64_t k = *data++;  
      
                    k *= m;   
                    k ^= k >> r;   
                    k *= m;   
      
                    h ^= k;  
                    h *= m;   
            }  
      
            const unsigned char * data2 = (const unsigned char*)data;  
      
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
uint64_t getPpath(struct task_truct *cur_task){
	char *path = NULL,*ptr = NULL;
	char *read_buf = NULL;
	int len = 0;
	uint64_t p_hash;
	

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
int init_proc_info(){
	return 0;
}

/*
* set process infomation in dram from file operations
* first should set beginning proc
*/
int set_proc_info(uint64_t proc_id, struct inode *inode, loff_t *ppos){
   
	struct list_head *this, *head;
	//loff_t pos;
	pgoff_t index;
	int ret;
	uint32_t nid;
   	struct hmfs_proc_info *new_proc = NULL, *proc = NULL;
   	struct hmfs_inode_info *fi = HMFS_I(inode);
   	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
   	struct hmfs_nm_info *nm_i = NM_I(sbi);    

    	// index = ppos >> block_size_bits;
	/*
	*set new process information if read a file
	*/
   	new_proc = kmem_cache_alloc(proc_info_slab,GFP_KERNEL);
   	if(!new_proc){
		return -ENOMEM;
   	}
	new_proc->proc_id = proc_id;
	new_proc->next_nid =  fi->i_ino;
	if(is_inline_inode(inode)){
		nid = inode->i_ino;
	}
	else
		nid = set_proc_nt(inode, index);
  	new_proc->next_nt =nid;
	ret = update_proc_info(nm_i);
	if(ret)
		kmem_cache_free(proc_info_slab,new_proc);
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
uint32_t set_proc_nt(struct inode *inode,int64_t index){
	struct node_info *ni;
	struct nat_entry *ne;
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	struct firct_node *dn;
	struct hmfs_nm_info *nm_i = sbi->nm_info;
	struct hmfs_summary *summary;

	ni = hmfs_get_node_info(inode,(int64_t)index);
	
	if(ni==NULL)
		return inode->i_ino;
   	summary = get_summary_by_addr(sbi,ni->blk_addr);
	
	if(get_summary_type(summary)==SUM_TYPE_DN)
		return summary->nid;
	else if(get_summary_type(summary)==SUM_TYPE_INODE)
		return inode->i_ino;
	
}

/*
*update proc_info if file changed or node changed or proc_id changed
*add list entry should be down in this function
*/
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
					/*
					else{
						list_add_tail(&c_proc->list, head);
						break;
					}
					*/
		}
	}
	if(proc)
		list_add_tail(&c_proc->list, head);
	else if(!ret)
		list_add_tail(&c_proc->list, next);
	return ret;
}

/*
*fetch process information
*/
int fetch_proc(){

}

/*
*flush proc to nvm
*/
int flush_proc(){

}
