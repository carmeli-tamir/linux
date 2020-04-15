// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "ipe.h"
#include "ipe-parse.h"
#include "ipe-secfs.h"
#include "ipe-policy.h"
#include "ipe-audit.h"

#include <linux/types.h>
#include <linux/security.h>
#include <linux/fs.h>
#include <linux/rcupdate.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/verification.h>
#include <linux/capability.h>

#define IPE_ROOT "ipe"
#define IPE_FULL_CONTENT "raw"
#define IPE_INNER_CONTENT "content"
#define IPE_POLICIES "policies"
#define IPE_NEW_POLICY "new_policy"
#define IPE_DELETE_POLICY "del_policy"

struct ipe_policy_node {
	u8		*data;
	size_t		data_len;
	const u8	*content;
	size_t		content_size;

	struct ipe_policy *parsed;
};

/* root directory */
static struct dentry *ipe_secfs_root __ro_after_init;

/* subdirectory containing policies */
static struct dentry *ipe_policies_root __ro_after_init;

/* boot policy */
static struct dentry *boot_policy_node __ro_after_init;

/* top-level policy commands */
static struct dentry *ipe_new_policy __ro_after_init;
static struct dentry *ipe_del_policy __ro_after_init;

/* lock for synchronizing writers across ipe policy */
DEFINE_MUTEX(ipe_policy_lock);

static ssize_t ipe_secfs_new_policy(struct file *f, const char __user *data,
				    size_t len, loff_t *offset);

static ssize_t ipe_secfs_del_policy(struct file *f, const char __user *data,
				    size_t len, loff_t *offset);

static ssize_t ipe_secfs_rd_policy(struct file *f, char __user *data,
				   size_t len, loff_t *offset);

static ssize_t ipe_secfs_ud_policy(struct file *f, const char __user *data,
				   size_t len, loff_t *offset);

static ssize_t ipe_secfs_rd_content(struct file *f, char __user *data,
				    size_t len, loff_t *offset);

static const struct file_operations new_policy_ops = {
	.write = ipe_secfs_new_policy
};

static const struct file_operations del_policy_ops = {
	.write = ipe_secfs_del_policy
};

static const struct file_operations policy_raw_ops = {
	.read = ipe_secfs_rd_policy,
	.write = ipe_secfs_ud_policy
};

static const struct file_operations policy_content_ops = {
	.read = ipe_secfs_rd_content
};

/**
 * ipe_free_policy_node: Free an ipe_policy_node structure allocated by
 *			 ipe_alloc_policy_node.
 * @n: ipe_policy_node to free
 */
static void ipe_free_policy_node(struct ipe_policy_node *n)
{
	if (IS_ERR_OR_NULL(n))
		return;

	ipe_free_policy(n->parsed);
	kfree(n->data);

	kfree(n);
}

/**
 * alloc_callback: Callback given to verify_pkcs7_signature function to set
 *		   the inner content reference and parse the policy.
 * @ctx: "ipe_policy_node" to set inner content, size and parsed policy of.
 * @data: Start of PKCS#7 inner content.
 * @len: Length of @data.
 * @asn1hdrlen: Unused.
 *
 * Return:
 * 0 - OK
 * ERR_PTR(-EBADMSG) - Invalid policy syntax
 * ERR_PTR(-ENOMEM) - Out of memory
 */
static int alloc_callback(void *ctx, const void *data, size_t len,
			  size_t asn1hdrlen)
{
	char *cpy = NULL;
	struct ipe_policy *pol = NULL;
	struct ipe_policy_node *n = (struct ipe_policy_node *)ctx;

	n->content = (const u8 *)data;
	n->content_size = len;

	if (len == 0)
		return -EBADMSG;

	cpy = kzalloc(len + 1, GFP_KERNEL);
	if (!cpy)
		return -ENOMEM;

	(void)memcpy(cpy, data, len);

	pol = ipe_parse_policy(cpy);
	if (IS_ERR(pol)) {
		kfree(cpy);
		return PTR_ERR(pol);
	}

	n->parsed = pol;
	kfree(cpy);
	return 0;
}

/**
 * ipe_alloc_policy_node: Allocate a new ipe_policy_node structure.
 * @data: Raw enveloped PKCS#7 data that represents the policy.
 * @len: Length of @data.
 *
 * Return:
 * valid ipe_policy_node - OK
 * ERR_PTR(-EBADMSG) - Invalid policy syntax
 * ERR_PTR(-ENOMEM) - Out of memory
 */
static struct ipe_policy_node *ipe_alloc_policy_node(const u8 *data,
						     size_t len)
{
	int rc = 0;
	struct ipe_policy_node *node = NULL;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node) {
		rc = -ENOMEM;
		goto out;
	}

	node->data_len = len;
	node->data = kmemdup(data, len, GFP_KERNEL);
	if (!node->data) {
		rc = -ENOMEM;
		goto out2;
	}

	rc = verify_pkcs7_signature(node->content, node->content_size,
				    node->data, node->data_len, NULL,
				    VERIFYING_UNSPECIFIED_SIGNATURE,
				    alloc_callback, node);
	if (rc != 0)
		goto out2;

	return node;
out2:
	ipe_free_policy_node(node);
out:
	return ERR_PTR(rc);
}

/**
 * ipe_build_policy_secfs_node: Build a new securityfs node for IPE policies.
 * @data: Raw enveloped PKCS#7 data that represents the policy.
 * @len: Length of @data.
 *
 * Return:
 * 0 - OK
 * -EEXIST - Policy already exists
 * -EBADMSG - Invalid policy syntax
 * -ENOMEM - Out of memory
 */
int ipe_build_policy_secfs_node(const u8 *data, size_t len)
{
	int rc = 0;
	struct dentry *raw = NULL;
	struct dentry *root = NULL;
	struct inode *root_i = NULL;
	struct dentry *content = NULL;
	struct crypto_shash *tfm = NULL;
	struct ipe_policy_node *node = NULL;

	tfm = crypto_alloc_shash("sha1", 0, 0);
	if (IS_ERR(tfm))
		goto out;

	node = ipe_alloc_policy_node(data, len);
	if (IS_ERR(node)) {
		rc = PTR_ERR(node);
		goto out2;
	}

	root = securityfs_create_dir(node->parsed->policy_name,
				     ipe_policies_root);
	if (IS_ERR(root)) {
		rc = PTR_ERR(root);
		goto out3;
	}

	root_i = d_inode(root);

	inode_lock(root_i);
	root_i->i_private = node;
	ipe_audit_policy_load(node->parsed, node->data, node->data_len, tfm);
	inode_unlock(root_i);

	raw = securityfs_create_file(IPE_FULL_CONTENT, 0644, root, NULL,
				     &policy_raw_ops);
	if (IS_ERR(raw)) {
		rc = PTR_ERR(raw);
		goto out4;
	}

	content = securityfs_create_file(IPE_INNER_CONTENT, 0444, root,
					 NULL, &policy_content_ops);
	if (IS_ERR(raw)) {
		rc = PTR_ERR(raw);
		goto out5;
	}

	crypto_free_shash(tfm);
	return rc;
out5:
	securityfs_remove(raw);
out4:
	securityfs_remove(root);
out3:
	ipe_free_policy_node(node);
out2:
	crypto_free_shash(tfm);
out:
	return rc;
}

/**
 * ipe_secfs_new_policy: Entry point of the securityfs node, "ipe/new_policy".
 * @f: File representing the securityfs entry.
 * @data: Raw enveloped PKCS#7 data that represents the policy.
 * @len: Length of @data.
 * @offset: Offset for @data.
 *
 * Return:
 * > 0 - OK
 * -EEXIST - Policy already exists
 * -EBADMSG - Invalid policy syntax
 * -ENOMEM - Out of memory
 * -EPERM - if a MAC subsystem is enabled, missing CAP_MAC_ADMIN
 */
static ssize_t ipe_secfs_new_policy(struct file *f, const char __user *data,
				    size_t len, loff_t *offset)
{
	ssize_t rc = 0;
	u8 *cpy = NULL;

	if (!file_ns_capable(f, &init_user_ns, CAP_MAC_ADMIN))
		return -EPERM;

	cpy = memdup_user(data, len);
	if (IS_ERR(cpy))
		return PTR_ERR(cpy);

	rc = ipe_build_policy_secfs_node(cpy, len);
	kfree(cpy);
	return rc < 0 ? rc : len;
}

/**
 * retrieve_backed_dentry: Retrieve a dentry with a backing inode, identified
 *			   by @name, under @parent.
 * @name: Name of the dentry under @parent.
 * @parent: The parent dentry to search under for @name.
 * @size: Length of @name.
 *
 * This takes a reference to the returned dentry. Caller needs to call dput
 * to drop the reference.
 *
 * Return:
 * valid dentry - OK
 * ERR_PTR - Error, see lookup_one_len_unlocked
 * NULL - No backing inode was found
 */
static struct dentry *retrieve_backed_dentry(const char *name,
					     struct dentry *parent,
					     size_t size)
{
	struct dentry *tmp = NULL;

	tmp = lookup_one_len_unlocked(name, parent, size);
	if (IS_ERR(tmp))
		return tmp;

	if (!d_really_is_positive(tmp))
		return NULL;

	return tmp;
}

/**
 * ipe_secfs_del_policy: Delete a policy indicated by the name provided by
 *			 @data
 * @f: File representing the securityfs entry.
 * @data: Buffer containing the policy id to delete.
 * @len: Length of @data.
 * @offset: Offset into @data.
 *
 * NOTE: Newlines are treated as part of the name, if using echo to test,
 * use -n to prohibit the silent addition of a newline.
 *
 * Return:
 * > 0 - OK
 * -ENOMEM - Out of memory
 * -EPERM - Policy is active
 * -ENOENT - Policy does not exist
 * -EPERM - if a MAC subsystem is enabled, missing CAP_MAC_ADMIN
 * Other - See retrieve_backed_dentry
 */
static ssize_t ipe_secfs_del_policy(struct file *f, const char __user *data,
				    size_t len, loff_t *offset)
{
	ssize_t rc = 0;
	char *id = NULL;
	ssize_t written = 0;
	struct dentry *raw = NULL;
	struct dentry *content = NULL;
	struct inode *policy_i = NULL;
	struct dentry *policy_root = NULL;
	struct inode *policies_root = NULL;
	const struct ipe_policy *target = NULL;

	if (!file_ns_capable(f, &init_user_ns, CAP_MAC_ADMIN))
		return -EPERM;

	id = kzalloc(len, GFP_KERNEL);
	if (!id) {
		rc = -ENOMEM;
		goto out;
	}

	written = simple_write_to_buffer(id, len, offset, data, len);
	if (written < 0) {
		rc = written;
		goto out;
	}

	policies_root = d_inode(ipe_policies_root);

	policy_root = retrieve_backed_dentry(id, ipe_policies_root, written);
	if (IS_ERR_OR_NULL(policy_root)) {
		rc = IS_ERR(policy_root) ? PTR_ERR(policy_root) : -ENOENT;
		goto out;
	}

	policy_i = d_inode(policy_root);

	/* if the found dentry matches boot policy, fail */
	if (boot_policy_node == policy_root) {
		rc = -EACCES;
		goto out1;
	}

	target = ((struct ipe_policy_node *)policy_i->i_private)->parsed;

	/* guarantee active policy cannot change */
	mutex_lock(&ipe_policy_lock);

	/* fail if it's the active policy */
	if (ipe_is_active_policy(target)) {
		rc = -EPERM;
		goto out2;
	}

	raw = retrieve_backed_dentry(IPE_FULL_CONTENT, policy_root,
				     strlen(IPE_FULL_CONTENT));
	if (IS_ERR_OR_NULL(raw)) {
		rc = IS_ERR(raw) ? PTR_ERR(raw) : -ENOENT;
		goto out2;
	}

	content = retrieve_backed_dentry(IPE_INNER_CONTENT, policy_root,
					 strlen(IPE_INNER_CONTENT));
	if (IS_ERR_OR_NULL(content)) {
		rc = IS_ERR(content) ? PTR_ERR(content) : -ENOENT;
		goto out3;
	}

	inode_lock(policies_root);
	ipe_free_policy_node(policy_i->i_private);
	policy_i->i_private = NULL;
	inode_unlock(policies_root);

	dput(raw);
	dput(content);
	dput(policy_root);
	securityfs_remove(raw);
	securityfs_remove(content);
	securityfs_remove(policy_root);

	mutex_unlock(&ipe_policy_lock);
	synchronize_rcu();

	kfree(id);
	return written;
out3:
	dput(raw);
out2:
	mutex_unlock(&ipe_policy_lock);
out1:
	dput(policy_root);
out:
	kfree(id);
	return rc;
}

/**
 * ipe_secfs_rd_policy: Read the raw content (full enveloped PKCS7) data of
 *			the policy stored within the file's parent inode.
 * @f: File representing the securityfs entry.
 * @data: User mode buffer to place the raw pkcs7.
 * @len: Length of @data.
 * @offset: Offset into @data.
 *
 * Return:
 * > 0 - OK
 * -ENOMEM - Out of memory
 */
static ssize_t ipe_secfs_rd_policy(struct file *f, char __user *data,
				   size_t size, loff_t *offset)
{
	ssize_t rc = 0;
	size_t avail = 0;
	struct inode *root = NULL;
	const struct ipe_policy_node *node = NULL;

	root = d_inode(f->f_path.dentry->d_parent);

	inode_lock_shared(root);
	node = (const struct ipe_policy_node *)root->i_private;

	avail = node->data_len;
	rc = simple_read_from_buffer(data, size, offset, node->data, avail);

	inode_unlock_shared(root);
	return rc;
}

/**
 * ipe_secfs_ud_policy: Update a policy in place with a new PKCS7 policy.
 * @f: File representing the securityfs entry.
 * @data: Buffer user mode to place the raw pkcs7.
 * @len: Length of @data.
 * @offset: Offset into @data.
 *
 * Return:
 * 0 - OK
 * -EBADMSG - Invalid policy format
 * -ENOMEM - Out of memory
 * -EPERM - if a MAC subsystem is enabled, missing CAP_MAC_ADMIN
 * -EINVAL - Incorrect policy name for this node, or version is < current
 */
static ssize_t ipe_secfs_ud_policy(struct file *f, const char __user *data,
				   size_t len, loff_t *offset)
{
	ssize_t rc = 0;
	u8 *cpy = NULL;
	struct inode *root = NULL;
	struct crypto_shash *tfm = NULL;
	struct ipe_policy_node *new = NULL;
	struct ipe_policy_node *old = NULL;

	if (!file_ns_capable(f, &init_user_ns, CAP_MAC_ADMIN))
		return -EPERM;

	cpy = memdup_user(data, len);
	if (IS_ERR(cpy))
		return PTR_ERR(cpy);

	new = ipe_alloc_policy_node(cpy, len);
	if (IS_ERR(new)) {
		rc = PTR_ERR(new);
		goto out_free_cpy;
	}

	tfm = crypto_alloc_shash("sha1", 0, 0);
	if (IS_ERR(tfm))
		goto out_free_cpy;

	root = d_inode(f->f_path.dentry->d_parent);
	inode_lock(root);
	mutex_lock(&ipe_policy_lock);

	old = (struct ipe_policy_node *)root->i_private;

	if (strcmp(old->parsed->policy_name, new->parsed->policy_name)) {
		rc = -EINVAL;
		goto out_unlock_inode;
	}

	if (!ipe_is_valid_policy(old->parsed, new->parsed)) {
		rc = -EINVAL;
		goto out_unlock_inode;
	}

	rc = ipe_update_active_policy(old->parsed, new->parsed);
	if (rc != 0)
		goto out_unlock_inode;

	ipe_audit_policy_load(new->parsed, new->data, new->data_len, tfm);
	swap(root->i_private, new);

	mutex_unlock(&ipe_policy_lock);
	synchronize_rcu();

	inode_unlock(root);
	kfree(cpy);
	ipe_free_policy_node(new);
	crypto_free_shash(tfm);

	return len;

out_unlock_inode:
	mutex_unlock(&ipe_policy_lock);
	inode_unlock(root);
	ipe_free_policy_node(new);
	crypto_free_shash(tfm);
out_free_cpy:
	kfree(cpy);
	return rc;
}

/**
 * ipe_secfs_rd_content: Read the inner content of the enveloped PKCS7 data,
 *			 representing the IPE policy.
 * @f: File representing the securityfs entry.
 * @data: User mode buffer to place the inner content of the pkcs7 data.
 * @len: Length of @data.
 * @offset: Offset into @data.
 *
 * Return:
 * > 0 - OK
 * -ENOMEM - Out of memory
 */
static ssize_t ipe_secfs_rd_content(struct file *f, char __user *data,
				    size_t size, loff_t *offset)
{
	ssize_t rc = 0;
	size_t avail = 0;
	struct inode *root = NULL;
	const struct ipe_policy_node *node = NULL;

	root = d_inode(f->f_path.dentry->d_parent);

	inode_lock_shared(root);
	node = (const struct ipe_policy_node *)root->i_private;

	avail = node->content_size;
	rc = simple_read_from_buffer(data, size, offset, node->content, avail);

	inode_unlock_shared(root);
	return rc;
}

/**
 * ipe_build_secfs_root: Build the root of securityfs for IPE.
 *
 * Return:
 * 0 - OK
 * !0 - See securityfs_create_dir and securityfs_create_file
 */
int __init ipe_build_secfs_root(void)
{
	int rc = 0;
	struct dentry *new = NULL;
	struct dentry *del = NULL;
	struct dentry *root = NULL;
	struct dentry *policies = NULL;

	root = securityfs_create_dir(IPE_ROOT, NULL);
	if (IS_ERR(root)) {
		rc = PTR_ERR(root);
		goto out;
	}

	new = securityfs_create_file(IPE_NEW_POLICY, 0644, root, NULL,
				     &new_policy_ops);
	if (IS_ERR(new)) {
		rc = PTR_ERR(new);
		goto out1;
	}

	del = securityfs_create_file(IPE_DELETE_POLICY, 0644, root, NULL,
				     &del_policy_ops);
	if (IS_ERR(del)) {
		rc = PTR_ERR(del);
		goto out2;
	}

	policies = securityfs_create_dir(IPE_POLICIES, root);
	if (IS_ERR(policies)) {
		rc = PTR_ERR(policies);
		goto out3;
	}

	ipe_secfs_root = root;
	ipe_new_policy = new;
	ipe_del_policy = del;
	ipe_policies_root = policies;

	return rc;

out3:
	securityfs_remove(del);
out2:
	securityfs_remove(new);
out1:
	securityfs_remove(root);
out:
	return rc;
}

/**
 * ipe_build_secfs_boot_node: Build a policy node for IPE's boot policy.
 *
 * This differs from the normal policy nodes, as the IPE boot policy is
 * read only.
 *
 * Return:
 * 0 - OK
 * !0 - See securityfs_create_dir and securityfs_create_file
 */
static int __init ipe_build_secfs_boot_node(void)
{
	int rc = 0;
	char *cpy = NULL;
	struct dentry *raw = NULL;
	struct inode *raw_i = NULL;
	struct dentry *root = NULL;
	struct dentry *content = NULL;
	struct ipe_policy *parsed = NULL;
	struct ipe_policy_node *node = NULL;

	if (!ipe_boot_policy)
		return 0;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node) {
		rc = -ENOMEM;
		goto out;
	}

	cpy = kstrdup(ipe_boot_policy, GFP_KERNEL);
	if (!cpy) {
		rc = -ENOMEM;
		goto out;
	}

	parsed = ipe_parse_policy(cpy);
	if (IS_ERR(parsed)) {
		rc = PTR_ERR(parsed);
		goto out2;
	}

	node->content = ipe_boot_policy;
	node->content_size = strlen(cpy);
	node->parsed = parsed;

	root = securityfs_create_dir(node->parsed->policy_name,
				     ipe_policies_root);
	if (IS_ERR(root)) {
		rc = PTR_ERR(root);
		goto out2;
	}

	raw_i = d_inode(root);

	inode_lock(raw_i);
	raw_i->i_private = node;
	inode_unlock(raw_i);

	content = securityfs_create_file(IPE_INNER_CONTENT, 0444, root, NULL,
					 &policy_content_ops);
	if (IS_ERR(raw)) {
		rc = PTR_ERR(raw);
		goto out3;
	}

	boot_policy_node = root;
	mutex_lock(&ipe_policy_lock);
	rc = ipe_activate_policy(node->parsed);
	mutex_unlock(&ipe_policy_lock);
	synchronize_rcu();

	return rc;

out3:
	securityfs_remove(root);
out2:
	ipe_free_policy(parsed);
out:
	kfree(cpy);
	kfree(node);
	return rc;
}

/**
 * ipe_set_active_policy: Set the policy identified by @id as the active
 *			  policy.
 * @id: Policy id represnting the policy to activate.
 * @id_len: Length of @id.
 *
 * Return:
 * 0 - OK
 * -ENOENT - Policy identified by @id does not exist
 * -EINVAL - Policy that is being activated is lower in version than
 *	     currently running policy.
 * Other - See retrieve_backed_dentry
 */
int ipe_set_active_policy(const char *id, size_t id_len)
{
	int rc = 0;
	struct dentry *policy_root = NULL;
	const struct ipe_policy_node *ref = NULL;

	mutex_lock(&ipe_policy_lock);

	policy_root = retrieve_backed_dentry(id, ipe_policies_root, id_len);
	if (IS_ERR_OR_NULL(policy_root)) {
		rc = IS_ERR(policy_root) ? PTR_ERR(policy_root) : -ENOENT;
		goto out;
	}

	inode_lock_shared(d_inode(policy_root));

	ref = (const struct ipe_policy_node *)d_inode(policy_root)->i_private;
	rc = ipe_activate_policy(ref->parsed);

	inode_unlock_shared(d_inode(policy_root));
	dput(policy_root);

out:
	mutex_unlock(&ipe_policy_lock);
	synchronize_rcu();
	return rc;
}

/**
 * ipe_securityfs_init: Initialize IPE's securityfs entries.
 *
 * This is called after the lsm initialization.
 *
 * Return:
 * 0 - OK
 * !0 - Error
 */
int __init ipe_securityfs_init(void)
{
	int rc = 0;

	rc = ipe_build_secfs_root();
	if (rc != 0)
		goto err;

	rc = ipe_build_secfs_boot_node();
	if (rc != 0)
		panic("IPE failed to initialize the boot policy: %d", rc);

	return rc;
err:
	pr_err("failed to initialize secfs: %d", -rc);
	return rc;
}

core_initcall(ipe_securityfs_init);
