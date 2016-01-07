#ifndef HMFS_UTIL_H
#define HMFS_UTIL_H

#include <linux/mm.h>
extern pte_t * (*hmfs_get_locked_pte) (struct mm_struct *, unsigned long, 
				spinlock_t **);

#endif
