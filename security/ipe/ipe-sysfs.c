// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "ipe.h"
#include "ipe-audit.h"
#include "ipe-secfs.h"

#include <linux/sysctl.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/slab.h>

#ifdef CONFIG_SYSCTL

#ifdef CONFIG_SECURITY_IPE_PERMISSIVE_SWITCH

/**
 * ipe_switch_mode: Handler to switch IPE's modes between permissive
 *		    and enforce.
 * @table: Sysctl table entry from the variable, sysctl_table.
 * @write: Integer indicating whether this is a write or a read.
 * @buffer: Data passed to sysctl, this should be 1 or 0 for this function.
 * @lenp: Pointer to the size of @buffer.
 * @ppos: Offset into @buffer.
 *
 * This wraps proc_dointvec_minmax, and if there's a change, emits an
 * audit event.
 *
 * Return:
 * 0 - OK
 * Other - See proc_dointvec_minmax
 */
static int ipe_switch_mode(struct ctl_table *table, int write,
			   void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int old = ipe_enforce;
	int ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (ret == 0 && old != ipe_enforce)
		ipe_audit_mode();

	return ret;
}

#endif /* CONFIG_SECURITY_IPE_PERMISSIVE_SWITCH */

#ifdef CONFIG_SECURITYFS

/**
 * ipe_switch_active_policy: Handler to switch the policy IPE is enforcing.
 * @table: Sysctl table entry from the variable, sysctl_table.
 * @write: Integer indicating whether this is a write or a read.
 * @buffer: Data passed to sysctl. This is the policy id to activate,
 *	    for this function.
 * @lenp: Pointer to the size of @buffer.
 * @ppos: Offset into @buffer.
 *
 * This wraps proc_dointvec_minmax, and if there's a change, emits an
 * audit event.
 *
 * Return:
 * 0 - OK
 * -ENOMEM - Out of memory
 * -ENOENT - Policy identified by @id does not exist
 * Other - See proc_dostring and retrieve_backed_dentry
 */
static int ipe_switch_active_policy(struct ctl_table *table, int write,
				    void __user *buffer, size_t *lenp,
				    loff_t *ppos)
{
	int rc = 0;
	char *id = NULL;
	size_t size = 0;

	if (write) {
		id = kzalloc((*lenp) + 1, GFP_KERNEL);
		if (!id)
			return -ENOMEM;

		table->data = id;
		table->maxlen = (*lenp) + 1;

		rc = proc_dostring(table, write, buffer, lenp, ppos);
		if (rc != 0)
			goto out;

		rc = ipe_set_active_policy(id, strlen(id));
	} else {
		if (!rcu_access_pointer(ipe_active_policy)) {
			table->data = "";
			table->maxlen = 1;
			return proc_dostring(table, write, buffer, lenp, ppos);
		}

		rcu_read_lock();
		size = strlen(rcu_dereference(ipe_active_policy)->policy_name);
		rcu_read_unlock();

		id = kzalloc(size + 1, GFP_KERNEL);
		if (!id)
			return -ENOMEM;

		rcu_read_lock();
		strncpy(id, rcu_dereference(ipe_active_policy)->policy_name,
			size);
		rcu_read_unlock();

		table->data = id;
		table->maxlen = size;

		rc = proc_dostring(table, write, buffer, lenp, ppos);
	}
out:
	kfree(id);
	return rc;
}

#endif /* CONFIG_SECURITYFS */

static struct ctl_table_header *sysctl_header;

static const struct ctl_path sysctl_path[] = {
	{
		.procname = "ipe",
	},
	{}
};

static struct ctl_table sysctl_table[] = {
#ifdef CONFIG_SECURITY_IPE_PERMISSIVE_SWITCH
	{
		.procname = "enforce",
		.data = &ipe_enforce,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = ipe_switch_mode,
		.extra1 = SYSCTL_ZERO,
		.extra2 = SYSCTL_ONE,
	},
#endif /* CONFIG_SECURITY_IPE_PERMISSIVE_SWITCH */
	{
		.procname = "success_audit",
		.data = &ipe_success_audit,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = proc_dointvec_minmax,
		.extra1 = SYSCTL_ZERO,
		.extra2 = SYSCTL_ONE,
	},
#ifdef CONFIG_SECURITYFS
	{
		.procname = "strict_parse",
		.data = &ipe_strict_parse,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = proc_dointvec_minmax,
		.extra1 = SYSCTL_ZERO,
		.extra2 = SYSCTL_ONE,
	},
	{
		.procname = "active_policy",
		.data = NULL,
		.maxlen = 0,
		.mode = 0644,
		.proc_handler = ipe_switch_active_policy,
	},
#endif /* CONFIG_SECURITYFS */
	{}
};

/**
 * ipe_sysctl_init: Initialize IPE's sysfs entries.
 *
 * Return:
 * 0 - OK
 * -ENOMEM - Sysctl registration failed
 */
int __init ipe_sysctl_init(void)
{
	sysctl_header = register_sysctl_paths(sysctl_path, sysctl_table);

	if (!sysctl_header) {
		pr_err("sysctl registration failed");
		return -ENOMEM;
	}

	return 0;
}

#else /* !CONFIG_SYSCTL */

/**
 * ipe_sysctl_init: Initialize IPE's sysfs entries.
 *
 * Return:
 * 0 - OK
 * -ENOMEM - Sysctl registration failed
 */
int __init ipe_sysctl_init(void)
{
	return 0;
}

#endif /* !CONFIG_SYSCTL */
