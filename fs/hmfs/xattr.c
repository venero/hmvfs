/*
 * fs/hmfs/xattr.c
 *
 * Copyright SJTU RADLAB.
 *             http://radlab.sjtu.edu.cn/
 *
 * Portions of this code from fs/ext2/xattr.c
 * 							  fs/f2fs/xattr.c
 *
 * Copyright (C) 2001-2003 Andreas Gruenbacher <agruen@suse.de>
 *
 * Fix by Harrison Xing <harrison@mountainviewdata.com>.
 * Extended attributes for symlinks and special files added per
 *  suggestion of Luka Renko <luka.renko@hermes.si>.
 * xattr consolidation Copyright (c) 2004 James Morris <jmorris@redhat.com>,
 *  Red Hat Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/dcache.h>
#include <linux/security.h>
#include "xattr.h"
#include "hmfs.h"
#include "hmfs_fs.h"

static const struct xattr_handler *hmfs_xattr_handler_map[];

static struct hmfs_xattr_entry *__find_xattr(void *base_addr, int index,
				size_t name_len, const char *name)
{
	struct hmfs_xattr_entry *entry;
	
	list_for_each_xattr(entry, base_addr) {
		if (entry->e_name_index != index)
			continue;
		if (entry->e_name_len != name_len)
			continue;
		if (!memcmp(entry->e_name, name, name_len))
			break;
	}

	return entry;
}

static void *get_xattr_block(struct inode *inode)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	block_t xattr_addr;
	struct hmfs_inode *inode_block;

	inode_block = get_node(sbi, inode->i_ino);
	if (IS_ERR(inode_block))
		return NULL;

	xattr_addr = le64_to_cpu(inode_block->i_xattr_addr);
	if (xattr_addr)
		return ADDR(sbi, xattr_addr);
	return NULL;
}

static size_t hmfs_xattr_generic_list(struct dentry *dentry, char *list,
				size_t list_size, const char *name, size_t len, int flags)
{
	struct hmfs_sb_info *sbi = HMFS_SB(dentry->d_sb);
	int total_len, prefix_len;
	const struct xattr_handler *handler;

	switch (flags) {
	case HMFS_XATTR_INDEX_USER:
		if (!test_opt(sbi, XATTR_USER))
			return -EOPNOTSUPP;
		break;
	case HMFS_XATTR_INDEX_TRUSTED:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		break;
	case HMFS_XATTR_INDEX_SECURITY:
		break;
	default:
		return -EINVAL;
	}

	handler = hmfs_xattr_handler_map[flags];
	prefix_len = strlen(handler->prefix);
	total_len = prefix_len + len + 1;
	if (list && total_len <= list_size) {
		memcpy(list, handler->prefix, prefix_len);
		memcpy(list + prefix_len, name, len);
		list[prefix_len + len] = '\0';
	}
	return total_len;
}

static int __hmfs_getxattr(struct inode *inode, int index, const char *name,
				void *buffer, size_t buffer_size) 
{
	struct hmfs_xattr_entry *entry;
	void *xattr_block;
	int error = 0;
	size_t value_len, name_len;

	if (name == NULL)
		return -EINVAL;

	name_len = strlen(name);
	if (name_len > HMFS_NAME_LEN)
		return -ERANGE;
	
	xattr_block = get_xattr_block(inode);
	if (!xattr_block) {
		return -ENODATA;
	}

	entry = __find_xattr(xattr_block, index, name_len, name);
	if (IS_XATTR_LAST_ENTRY(entry)) {
		error = -ENODATA;
		goto out;
	}

	value_len = entry->e_value_len;

	if (buffer && value_len > buffer_size) {
		error = -ERANGE;
		goto out;
	}

	if (buffer) {
		memcpy(buffer, entry->e_name + name_len, value_len);
	}

	error = value_len;
out:
	return error;
} 

int hmfs_getxattr(struct inode *inode, int index, const char *name,
				void *buffer, size_t buffer_size) 
{
	int ret;

	inode_read_lock(inode);
	ret = __hmfs_getxattr(inode, index, name, buffer, buffer_size);
	inode_read_unlock(inode);
	return ret;
}

static int hmfs_xattr_generic_get(struct dentry *dentry, const char *name,
				void *buffer, size_t size, int flags)
{
	struct hmfs_sb_info *sbi = HMFS_SB(dentry->d_sb);

	switch (flags) {
	case HMFS_XATTR_INDEX_USER:
		if (!test_opt(sbi, XATTR_USER))
			return -EOPNOTSUPP;
		break;
	case HMFS_XATTR_INDEX_TRUSTED:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		break;
	case HMFS_XATTR_INDEX_SECURITY:
		break;
	default:
		return -EINVAL;
	}
	if (strcmp(name, "") == 0)
		return -EINVAL;
	return hmfs_getxattr(dentry->d_inode, flags, name,
					buffer, size);
}

static void init_xattr_block(void *base_addr)
{
	XATTR_HDR(base_addr)->h_magic = cpu_to_le16(HMFS_X_BLOCK_TAG_XATTR);
}

static int __hmfs_setxattr(struct inode *inode, int index,
				const char *name, const void *value, size_t size,
				int flags)
{
	struct hmfs_xattr_entry *this, *last, *next;
	void *base_addr, *new_xattr_blk;
	int newsize, cpy_size;
	size_t name_len;
	int error = -ENOMEM;

	if (name == NULL)
		return -EINVAL;

	if (value == NULL)
		size = 0;

	name_len = strlen(name);

	if (name_len > HMFS_NAME_LEN)
		return -ERANGE;

	if (name_len + size > HMFS_XATTR_VALUE_LEN)
		return -E2BIG;

	base_addr = get_xattr_block(inode);
	if (!base_addr) {
		error = -ENODATA;
		goto out;
	}

	if (!base_addr) {
		if (flags & XATTR_CREATE)
			goto create;
		error = -ENODATA;
		goto out;
	}
	this = __find_xattr(base_addr, index, name_len, name);

	if (this->e_name_index == HMFS_XATTR_INDEX_END &&
				(flags & XATTR_REPLACE)) {
		error = -ENODATA;
		goto out;
	} else if ((flags & XATTR_CREATE) && this->e_name_index !=
						HMFS_XATTR_INDEX_END) {
		error = -EEXIST;
		goto out;
	}
	
	newsize = XATTR_RAW_SIZE + name_len + size;

	/* Check Space */
	if (value) {
		/* If value is NULL, it's a remove operation */
		/* Add another hmfs_xattr_entry for end entry */
		last = XATTR_ENTRY(JUMP(this, newsize + XATTR_RAW_SIZE));

		if (DISTANCE(base_addr, last) > HMFS_XATTR_BLOCK_SIZE) {
			error = -ENOSPC;
			goto out;
		}
	}

create:	
	/* Allocate new xattr block */
	new_xattr_blk = alloc_new_x_block(inode, HMFS_X_BLOCK_TAG_XATTR, false);
	init_xattr_block(new_xattr_blk);	

	/* Remove old entry in old xattr block */
	if (base_addr) {
		/* Copy first part */
		next = XATTR_FIRST_ENTRY(base_addr);
		cpy_size = DISTANCE(next, this);
		hmfs_memcpy(XATTR_FIRST_ENTRY(new_xattr_blk), next, cpy_size);

		/* Get last xattr in source xattr block */
		last = this;
		while (!IS_XATTR_LAST_ENTRY(last))
			last = XATTR_NEXT_ENTRY(last);

		/* Copy second part */
		next = XATTR_NEXT_ENTRY(this);
		cpy_size = DISTANCE(next, last);
		next = XATTR_ENTRY(JUMP(new_xattr_blk, DISTANCE(base_addr, this)));
		hmfs_memcpy(next, XATTR_NEXT_ENTRY(this), cpy_size);
		next = XATTR_ENTRY(JUMP(next, cpy_size));
	} else {
		next = XATTR_FIRST_ENTRY(new_xattr_blk);
	}

	/* Write new entry */
	if (value) {
		next->e_name_index = index;
		next->e_name_len = name_len;
		next->e_value_len = size;
		memcpy(next->e_name, name, name_len);
		memcpy(next->e_name + name_len, value, size);
		next = XATTR_ENTRY(next->e_name + name_len + size);
	}

	/* Write End entry */
	next->e_name_index = HMFS_XATTR_INDEX_END;
	hmfs_bug_on(HMFS_I_SB(inode), DISTANCE(new_xattr_blk, 
			JUMP(next, XATTR_RAW_SIZE)) > HMFS_XATTR_BLOCK_SIZE);

	inode->i_ctime = CURRENT_TIME;
	mark_inode_dirty(inode);
out:
	return error;
}

static int hmfs_setxattr(struct inode *inode, int index, const char *name,
				const void *value, size_t size, int flags)
{
	struct hmfs_sb_info *sbi = HMFS_I_SB(inode);
	int err, ilock;

	ilock = mutex_lock_op(sbi);
	inode_write_lock(inode);
	err = __hmfs_setxattr(inode, index, name, value, size, flags);
	inode_write_unlock(inode);
	mutex_unlock_op(sbi, ilock);

	return err;
}

static int hmfs_xattr_generic_set(struct dentry *dentry, const char *name,
				const void *value, size_t size, int flags, int handler_flags)
{
	struct hmfs_sb_info *sbi = HMFS_SB(dentry->d_sb);

	switch (handler_flags) {
	case HMFS_XATTR_INDEX_USER:
		if (!test_opt(sbi, XATTR_USER))
			return -EOPNOTSUPP;
		break;
	case HMFS_XATTR_INDEX_TRUSTED:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		break;
	case HMFS_XATTR_INDEX_SECURITY:
		break;
	default:
		return -EINVAL;
	}
	if (strcmp(name, "") == 0)
		return -EINVAL;
	return hmfs_setxattr(dentry->d_inode, handler_flags, name,
					value, size, flags);
}

static size_t hmfs_xattr_advise_list(struct dentry *dentry, char *list,
				size_t list_size, const char *name, size_t len, int flags)
{
	const char *xname = HMFS_SYSTEM_ADVISE_PREFIX;
	size_t size;

	size = strlen(xname) + 1;
	if (list && size <= list_size)
		memcpy(list, xname, size);
	return size;
}

static int hmfs_xattr_advise_get(struct dentry *dentry, const char *name,
				void *buffer, size_t size, int flags)
{
	struct inode *inode = dentry->d_inode;

	if (strcmp(name ,"") != 0)
		return -EINVAL;

	inode_read_lock(inode);
	if (buffer)
		*((char *)buffer) = HMFS_I(inode)->i_advise;
	inode_read_unlock(inode);
	return sizeof(char);
}

static int hmfs_xattr_advise_set(struct dentry *dentry, const char *name,
				const void *value, size_t size, int flags, int handler_flag)
{
	struct inode *inode = dentry->d_inode;

	if (strcmp(name, "") != 0)
		return -EINVAL;
	if (!inode_owner_or_capable(inode))
		return -EPERM;
	if (value == NULL)
		return -EINVAL;

	inode_write_lock(inode);
	HMFS_I(inode)->i_advise = *(char *)value;
	inode_write_unlock(inode);
	mark_inode_dirty(inode);
	return 0;
}

static int hmfs_initxattrs(struct inode *inode, const struct xattr *xattr_array,
				void *page)
{
	const struct xattr *xattr;
	int err = 0;

	for (xattr = xattr_array; xattr->name != NULL; xattr++) {
		err = hmfs_setxattr(inode, HMFS_XATTR_INDEX_SECURITY,
					xattr->name, xattr->value, xattr->value_len, 0);
		if (err < 0)
			break;
	}
	return err;
}

int hmfs_init_security(struct inode *inode ,struct inode *dir,
				const struct qstr *qstr, struct page *ipage)
{
	return security_inode_init_security(inode, dir, qstr,
				&hmfs_initxattrs, ipage);
}

const struct xattr_handler hmfs_xattr_trusted_handler = {
	.prefix = XATTR_TRUSTED_PREFIX,
	.flags = HMFS_XATTR_INDEX_TRUSTED,
	.list = hmfs_xattr_generic_list,
	.get = hmfs_xattr_generic_get,
	.set = hmfs_xattr_generic_set,
};

const struct xattr_handler hmfs_xattr_advise_handler = {
	.prefix = HMFS_SYSTEM_ADVISE_PREFIX,
	.flags = HMFS_XATTR_INDEX_ADVISE,
	.list = hmfs_xattr_advise_list,
	.get = hmfs_xattr_advise_get,
	.set = hmfs_xattr_advise_set,
};

const struct xattr_handler hmfs_xattr_security_handler = {
	.prefix = XATTR_SECURITY_PREFIX,
	.flags = HMFS_XATTR_INDEX_SECURITY,
	.list = hmfs_xattr_generic_list,
	.get = hmfs_xattr_generic_get,
	.set = hmfs_xattr_generic_set,
};

const struct xattr_handler hmfs_xattr_user_handler = {
	.prefix = XATTR_USER_PREFIX,
	.flags = HMFS_XATTR_INDEX_USER,
	.list = hmfs_xattr_generic_list,
	.get = hmfs_xattr_generic_get,
	.set = hmfs_xattr_generic_set,
};

static const struct xattr_handler *hmfs_xattr_handler_map[] = {
	[HMFS_XATTR_INDEX_USER] = &hmfs_xattr_user_handler,
#ifdef CONFIG_HMFS_ACL
	[HMFS_XATTR_INDEX_POSIX_ACL_ACCESS] = &hmfs_acl_access_handler,
	[HMFS_XATTR_INDEX_POSIX_ACL_DEFAULT] = &hmfs_acl_default_handler,
#endif
	[HMFS_XATTR_INDEX_TRUSTED] = &hmfs_xattr_trusted_handler,
	[HMFS_XATTR_INDEX_SECURITY] = &hmfs_xattr_security_handler,
	[HMFS_XATTR_INDEX_ADVISE] = &hmfs_xattr_advise_handler,
};

const struct xattr_handler *hmfs_xattr_handlers[] = {
	&hmfs_xattr_user_handler,
	&hmfs_xattr_trusted_handler,
	&hmfs_xattr_advise_handler,
	&hmfs_xattr_security_handler,
	&hmfs_acl_access_handler,
	&hmfs_acl_default_handler,
	NULL,
};

static inline const struct xattr_handler *hmfs_xattr_handler(int index)
{
	const struct xattr_handler *handler = NULL;
	if (index > 0 && index < ARRAY_SIZE(hmfs_xattr_handler_map))
		handler = hmfs_xattr_handler_map[index];
	return handler;
}

ssize_t hmfs_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	struct inode *inode =dentry->d_inode;
	struct hmfs_xattr_entry *entry;
	void *xattr_block;
	int error = 0;
	size_t size, rest = buffer_size;

	xattr_block  = get_xattr_block(inode);
	if (!xattr_block)
		return -ENODATA;

	list_for_each_xattr(entry, xattr_block) {
		const struct xattr_handler *handler = 
				hmfs_xattr_handler(entry->e_name_index);

		if (!handler)
			continue;

		size = handler->list(dentry, buffer, rest,entry->e_name,
					entry->e_name_len, handler->flags);
		if (buffer && size > rest) {
			error = -ERANGE;
			goto out;
		}

		if (buffer)
			buffer += size;
		rest -= size;
	}
	error = buffer_size - rest;
out:
	return error;
}
