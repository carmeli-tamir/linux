// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "ipe.h"
#include "ipe-property.h"
#include "ipe-prop-internal.h"
#include "ipe-policy.h"
#include "ipe-engine.h"
#include "ipe-audit.h"
#include "ipe-pin.h"
#include "utility.h"

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/security.h>

const struct ipe_policy *ipe_active_policy;

/**
 * get_audit_pathname: Return the absolute path of the file struct passed in
 * @file: file to derive an absolute path from.
 *
 * This function walks past chroots and mount points.
 *
 * Return:
 * !NULL - OK
 * ERR_PTR(-ENOENT) - No File
 * ERR_PTR(-ENOMEM) - No Memory
 * ERR_PTR(-ENAMETOOLONG) - Path Exceeds PATH_MAX
 */
static char *get_audit_pathname(const struct file *file)
{
	int rc = 0;
	char *pos = NULL;
	char *pathbuf = NULL;
	struct super_block *sb;
	char *temp_path = NULL;

	/* No File to get Path From */
	if (!file)
		return ERR_PTR(-ENOENT);

	sb = file->f_path.dentry->d_sb;

	pathbuf = __getname();
	if (!pathbuf)
		return ERR_PTR(-ENOMEM);

	pos = d_absolute_path(&file->f_path, pathbuf, PATH_MAX);
	if (IS_ERR(pos)) {
		rc = PTR_ERR(pos);
		goto err;
	}

	temp_path = __getname();
	if (!temp_path) {
		rc = -ENOMEM;
		goto err;
	}

	strlcpy(temp_path, pos, PATH_MAX);

	__putname(pathbuf);

	return temp_path;

err:
	__putname(pathbuf);
	return ERR_PTR(rc);
}

/**
 * free_ctx: free a previously allocated ipe_engine_ctx struct
 * @ctx: structure to allocate.
 *
 * The caller is required to free @ctx, if previously allocated.
 */
static void free_ctx(struct ipe_engine_ctx *ctx)
{
	if (IS_ERR_OR_NULL(ctx))
		return;

	if (!IS_ERR_OR_NULL(ctx->audit_pathname))
		__putname(ctx->audit_pathname);

	kfree(ctx);
}

/**
 * build_ctx: allocate a new ipe_engine_ctx structure
 * @file: File that is being evaluated against IPE policy.
 * @op: Operation that the file is being evaluated against.
 * @hook: Specific hook that the file is being evaluated through.
 *
 * Return:
 * !NULL - OK
 * ERR_PTR(-ENOMEM) - no memory
 */
static struct ipe_engine_ctx *build_ctx(const struct file *file,
					enum ipe_op op, enum ipe_hook hook)
{
	struct ipe_engine_ctx *local;

	local = kzalloc(sizeof(*local), GFP_KERNEL);
	if (!local)
		return ERR_PTR(-ENOMEM);

	/* if there's an error here, it's O.K. */
	local->audit_pathname = get_audit_pathname(file);
	local->file = file;
	local->op = op;
	local->hook = hook;

	return local;
}

/**
 * evaluate: Process an @ctx against IPE's current active policy.
 * @ctx: the engine ctx to perform an evaluation on.
 * @cache: the red-black tree root that is used for cache storage.
 *
 * This uses a preallocated @cache as storage for the properties to avoid
 * re-evaulation.
 *
 * Return:
 * -EACCES - A match occurred against a "action=DENY" rule
 * -ENOMEM - Out of memory
 */
static int evaluate(struct ipe_engine_ctx *ctx)
{
	int rc = 0;
	bool match = false;
	enum ipe_action action;
	enum ipe_match match_type;
	const struct ipe_rule *rule;
	const struct ipe_policy *pol;
	const struct ipe_rule_table *rules;
	const struct ipe_prop_container *prop;

	if (!rcu_access_pointer(ipe_active_policy))
		return rc;

	rcu_read_lock();

	pol = rcu_dereference(ipe_active_policy);

	rules = &pol->ops[ctx->op];

	list_for_each_entry(rule, &rules->rules, next) {
		match = true;

		list_for_each_entry(prop, &rule->props, next)
			match = match && prop->prop->eval(ctx, prop->value);

		if (match)
			break;
	}

	if (match) {
		match_type = ipe_match_rule;
		action = rule->action;
	} else if (rules->def != ipe_action_unset) {
		match_type = ipe_match_table;
		action = rules->def;
		rule = NULL;
	} else {
		match_type = ipe_match_global;
		action = pol->def;
		rule = NULL;
	}

	ipe_audit_match(ctx, match_type, action, rule);

	if (action == ipe_action_deny)
		rc = -EACCES;

	if (ipe_enforce == 0)
		rc = 0;

	rcu_read_unlock();
	return rc;
}

/**
 * ipe_process_event: Perform an evaluation of @file, @op, and @hook against
 *		      IPE's current active policy.
 * @file: File that is being evaluated against IPE policy.
 * @op: Operation that the file is being evaluated against.
 * @hook: Specific hook that the file is being evaluated through.
 *
 * Return:
 * -ENOMEM: (No Memory)
 * -EACCES: (A match occurred against a "action=DENY" rule)
 */
int ipe_process_event(const struct file *file, enum ipe_op op,
		      enum ipe_hook hook)
{
	int rc = 0;
	struct ipe_engine_ctx *ctx;

	ctx = build_ctx(file, op, hook);
	if (IS_ERR(ctx))
		goto cleanup;

	ipe_pin_superblock(ctx->file);

	rc = evaluate(ctx);

cleanup:
	free_ctx(ctx);
	return rc;
}
