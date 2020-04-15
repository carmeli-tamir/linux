/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "ipe-hooks.h"
#include "ipe-property.h"

#include <linux/types.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>

#ifndef IPE_POLICY_H
#define IPE_POLICY_H

#define IPE_HEADER_POLICY_NAME		"policy_name"
#define IPE_HEADER_POLICY_VERSION	"policy_version"

extern const char *const ipe_boot_policy;
extern const struct ipe_policy *ipe_active_policy;

enum ipe_action {
	ipe_action_unset = 0,
	ipe_action_allow,
	ipe_action_deny
};

struct ipe_prop_container {
	struct list_head next;
	void *value;
	const struct ipe_property *prop;
};

struct ipe_rule {
	struct list_head props;
	struct list_head next;
	enum ipe_action action;
	enum ipe_op op;
};

struct ipe_rule_table {
	struct list_head rules;
	enum ipe_action def;
};

struct ipe_pol_ver {
	u16 major;
	u16 minor;
	u16 rev;
};

struct ipe_policy {
	char *policy_name;
	struct ipe_pol_ver policy_version;
	enum ipe_action def;

	/* KERNEL_READ stores no data itself */
	struct ipe_rule_table ops[ipe_op_max - 1];
};

#endif /* IPE_POLICY_H */
