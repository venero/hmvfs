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

	sym_addr = kallsyms_lookup_name("__pud_alloc");
	if (!sym_addr)
		goto fail;
	__hmfs_pud_alloc = sym_addr;

	sym_addr = kallsyms_lookup_name("__pmd_alloc");
	if (!sym_addr)
		goto fail;
	__hmfs_pmd_alloc = sym_addr;

	sym_addr = kallsyms_lookup_name("__pte_alloc_kernel");
	if (!sym_addr)
		goto fail;
	__hmfs_pte_alloc_kernel = sym_addr;

	sym_addr = kallsyms_lookup_name("remove_vm_area");
	if (!sym_addr)
		goto fail;
	hmfs_remove_vm_area = sym_addr;

	sym_addr = kallsyms_lookup_name("find_vm_area");
	if (!sym_addr)
		goto fail;
	hmfs_find_vm_area = sym_addr;

	sym_addr = kallsyms_lookup_name("get_vm_area");
	if (!sym_addr)
		goto fail;
	hmfs_get_vm_area = sym_addr;
	return 0;
fail:
	printk(KERN_INFO"[HMFS]: Fail to get all needed function\n");
	return -EPERM; 
}
