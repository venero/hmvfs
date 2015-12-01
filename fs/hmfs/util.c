#include <linux/kallsyms.h>
#include "util.h"
#include "hmfs.h"

/* 
 * FIXME: Any good idea to call the function which is not exported
 * by macro EXPORT_SYMBOL
 */
int init_util_function(void)
{
	unsigned long sym_addr = 0;

	sym_addr = kallsyms_lookup_name("init_mm");
	if (!sym_addr)
		goto fail;
	hmfs_init_mm = (struct mm_struct *)sym_addr;

	sym_addr = kallsyms_lookup_name("pud_alloc");
	if (!sym_addr)
		goto fail;
	hmfs_pud_alloc = 
			(pud_t * (*) (struct mm_struct *, pgd_t *, unsigned long))sym_addr;

	sym_addr = kallsyms_lookup_name("pmd_alloc");
	if (!sym_addr)
		goto fail;
	hmfs_pmd_alloc = 
			(pmd_t * (*) (struct mm_struct *, pud_t *, unsigned long))sym_addr;

	sym_addr = kallsyms_lookup_name("__pte_alloc_kernel");
	if (!sym_addr)
		goto fail;

	__hmfs_pte_alloc_kernel = (int (*) (pmd_t *, unsigned long))sym_addr;

	sym_addr = kallsyms_lookup_name("remove_vm_area");
	if (!sym_addr)
		goto fail;
	hmfs_remove_vm_area = (struct vm_struct * (*) (const void *))sym_addr;

	sym_addr = kallsyms_lookup_name("find_vm_area");
	if (!sym_addr)
		goto fail;
	hmfs_find_vm_area = (struct vm_struct * (*) (const void *))sym_addr;

	sym_addr = kallsyms_lookup_name("get_vm_area");
	if (!sym_addr)
		goto fail;
	hmfs_get_vm_area = 
			(struct vm_struct * (*) (unsigned long, unsigned long))sym_addr;

	return 0;
fail:
	printk(KERN_INFO"[HMFS]: Fail to get all needed function\n");
	return -EPERM; 
}
