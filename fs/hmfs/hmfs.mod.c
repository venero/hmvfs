#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xef025c67, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x61b7b126, __VMLINUX_SYMBOL_STR(simple_strtoull) },
	{        0, __VMLINUX_SYMBOL_STR(alloc_pages_current) },
	{ 0xf459fe8a, __VMLINUX_SYMBOL_STR(kmem_cache_destroy) },
	{ 0x9fc0f5d1, __VMLINUX_SYMBOL_STR(iget_failed) },
	{ 0x582bcf5, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x405c1144, __VMLINUX_SYMBOL_STR(get_seconds) },
	{ 0x22b1e21a, __VMLINUX_SYMBOL_STR(drop_nlink) },
	{ 0xf5893abf, __VMLINUX_SYMBOL_STR(up_read) },
	{ 0xda3e43d1, __VMLINUX_SYMBOL_STR(_raw_spin_unlock) },
	{ 0xf37b8bc9, __VMLINUX_SYMBOL_STR(generic_file_llseek) },
	{ 0x6164494f, __VMLINUX_SYMBOL_STR(__mark_inode_dirty) },
	{ 0xb1bda942, __VMLINUX_SYMBOL_STR(debugfs_create_dir) },
	{ 0x27864d57, __VMLINUX_SYMBOL_STR(memparse) },
	{ 0x13fcba85, __VMLINUX_SYMBOL_STR(filemap_fault) },
	{ 0x79d3898c, __VMLINUX_SYMBOL_STR(single_open) },
	{ 0xfcf090f7, __VMLINUX_SYMBOL_STR(kill_anon_super) },
	{ 0x34184afe, __VMLINUX_SYMBOL_STR(current_kernel_time) },
	{ 0xfc66bff8, __VMLINUX_SYMBOL_STR(single_release) },
	{ 0x8552999, __VMLINUX_SYMBOL_STR(generic_file_open) },
	{ 0x210b9dab, __VMLINUX_SYMBOL_STR(__lock_page) },
	{ 0xa8323a9, __VMLINUX_SYMBOL_STR(touch_atime) },
	{ 0xc0a3d105, __VMLINUX_SYMBOL_STR(find_next_bit) },
	{ 0xa05f372e, __VMLINUX_SYMBOL_STR(seq_printf) },
	{ 0x44e9a829, __VMLINUX_SYMBOL_STR(match_token) },
	{ 0x1eecf3fc, __VMLINUX_SYMBOL_STR(mutex_unlock) },
	{ 0x85df9b6c, __VMLINUX_SYMBOL_STR(strsep) },
	{ 0x83fb7638, __VMLINUX_SYMBOL_STR(generic_read_dir) },
	{ 0x7a56b0ef, __VMLINUX_SYMBOL_STR(debugfs_create_file) },
	{ 0x4629334c, __VMLINUX_SYMBOL_STR(__preempt_count) },
	{ 0x414d6b04, __VMLINUX_SYMBOL_STR(mount_nodev) },
	{ 0xd80df3ca, __VMLINUX_SYMBOL_STR(debugfs_remove_recursive) },
	{ 0x26948d96, __VMLINUX_SYMBOL_STR(copy_user_enhanced_fast_string) },
	{ 0xeeaaf2be, __VMLINUX_SYMBOL_STR(seq_read) },
	{ 0xaeb2b8a3, __VMLINUX_SYMBOL_STR(set_page_dirty) },
	{ 0x57a6ccd0, __VMLINUX_SYMBOL_STR(down_read) },
	{ 0x11089ac7, __VMLINUX_SYMBOL_STR(_ctype) },
	{ 0x8cb1ff45, __VMLINUX_SYMBOL_STR(current_task) },
	{ 0xac7f6dfd, __VMLINUX_SYMBOL_STR(__mutex_init) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x449ad0a7, __VMLINUX_SYMBOL_STR(memcmp) },
	{ 0xafb8c6ff, __VMLINUX_SYMBOL_STR(copy_user_generic_string) },
	{ 0x479c3c86, __VMLINUX_SYMBOL_STR(find_next_zero_bit) },
	{ 0xa1c76e0a, __VMLINUX_SYMBOL_STR(_cond_resched) },
	{ 0xa4511467, __VMLINUX_SYMBOL_STR(crc16) },
	{ 0xe136f7a2, __VMLINUX_SYMBOL_STR(kmem_cache_free) },
	{ 0x91e14f04, __VMLINUX_SYMBOL_STR(mutex_lock) },
	{ 0xd8fb49e1, __VMLINUX_SYMBOL_STR(unlock_page) },
	{ 0x3b4ceb4a, __VMLINUX_SYMBOL_STR(up_write) },
	{ 0xe6e3b875, __VMLINUX_SYMBOL_STR(down_write) },
	{ 0xaacb9773, __VMLINUX_SYMBOL_STR(inode_init_once) },
	{ 0x72a98fdb, __VMLINUX_SYMBOL_STR(copy_user_generic_unrolled) },
	{ 0xd00a74d2, __VMLINUX_SYMBOL_STR(kmem_cache_alloc) },
	{ 0xb2fd5ceb, __VMLINUX_SYMBOL_STR(__put_user_4) },
	{ 0x8dcecc03, __VMLINUX_SYMBOL_STR(unlock_new_inode) },
	{ 0xf0e9f05c, __VMLINUX_SYMBOL_STR(inode_newsize_ok) },
	{ 0x1c5e1c4e, __VMLINUX_SYMBOL_STR(page_cache_sync_readahead) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
	{ 0x635462ce, __VMLINUX_SYMBOL_STR(vfs_setpos) },
	{ 0x1a3d0587, __VMLINUX_SYMBOL_STR(clear_page_dirty_for_io) },
	{ 0x94745f80, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0xd52bf1ce, __VMLINUX_SYMBOL_STR(_raw_spin_lock) },
	{ 0xb243d003, __VMLINUX_SYMBOL_STR(kmem_cache_create) },
	{ 0x1208bc83, __VMLINUX_SYMBOL_STR(register_filesystem) },
	{ 0x2ea543e1, __VMLINUX_SYMBOL_STR(seq_lseek) },
	{ 0xf49fcb69, __VMLINUX_SYMBOL_STR(iput) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0x69acdf38, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0xa75312bc, __VMLINUX_SYMBOL_STR(call_rcu_sched) },
	{ 0xedc03953, __VMLINUX_SYMBOL_STR(iounmap) },
	{ 0x68c7263, __VMLINUX_SYMBOL_STR(ioremap_cache) },
	{ 0xea84ecc7, __VMLINUX_SYMBOL_STR(put_page) },
	{ 0xf4e620c3, __VMLINUX_SYMBOL_STR(d_make_root) },
	{ 0x870bf928, __VMLINUX_SYMBOL_STR(radix_tree_lookup) },
	{ 0xa96d8ecd, __VMLINUX_SYMBOL_STR(unregister_filesystem) },
	{ 0xeae58a83, __VMLINUX_SYMBOL_STR(init_special_inode) },
	{ 0x88d903f3, __VMLINUX_SYMBOL_STR(new_inode) },
	{ 0xac28be56, __VMLINUX_SYMBOL_STR(iget_locked) },
	{ 0x216d17f0, __VMLINUX_SYMBOL_STR(filemap_fdatawrite) },
	{ 0xc0f955cd, __VMLINUX_SYMBOL_STR(inode_init_owner) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "93AB79FE04835250431F59F");
