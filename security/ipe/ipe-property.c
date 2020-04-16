// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "ipe.h"
#include "ipe-prop-internal.h"
#include "ipe-property.h"

#include <linux/types.h>
#include <linux/rbtree.h>
#include <linux/slab.h>

/* global root containing all registered properties */
struct rb_root ipe_registry_root = RB_ROOT;

/**
 * reg_lookup: Attempt to find a `prop_reg` structure with property_name @key.
 * @key: The property_name to look for in the tree.
 *
 * Return:
 * ipe_prop_reg structure - OK
 * NULL - No such property exists
 */
static struct ipe_prop_reg *reg_lookup(const char *key)
{
	struct rb_node *n = ipe_registry_root.rb_node;

	while (n) {
		int r;
		struct ipe_prop_reg *reg =
			container_of(n, struct ipe_prop_reg, node);

		r = strcmp(reg->prop->property_name, key);
		if (r == 0)
			return reg;
		else if (r > 0)
			n = n->rb_right;
		else
			n = n->rb_left;
	}

	return NULL;
}

/**
 * ipe_lookup_prop: Attempt to find a ipe_property structure by name @key.
 * @key: The property_name to look for in the tree.
 *
 * Return:
 * ipe_property structure - OK
 * NULL - No property exists under @key
 */
const struct ipe_property *ipe_lookup_prop(const char *key)
{
	struct ipe_prop_reg *reg = reg_lookup(key);

	if (!reg)
		return NULL;

	return reg->prop;
}

/**
 * ipe_register_property: Insert a property into the registration system.
 * @prop: Read-only property structure containing the property_name, as well
 *	  as the necessary function pointers for a property.
 *
 * The caller needs to maintain the lifetime of @prop throughout the life of
 * the system, after calling ipe_register_property.
 *
 * All necessary properties need to be loaded via this method before
 * loading a policy, otherwise the properties will be ignored as unknown.
 *
 * Return:
 * 0 - OK
 * -EEXIST - A key exists with the name @prop->property_name
 * -ENOMEM - Out of Memory
 */
int ipe_register_property(const struct ipe_property *prop)
{
	struct rb_node *parent = NULL;
	struct ipe_prop_reg *new_data = NULL;
	struct rb_node **new = &ipe_registry_root.rb_node;

	while (*new) {
		int r;
		struct ipe_prop_reg *reg =
			container_of(*new, struct ipe_prop_reg, node);

		parent = *new;

		r = strcmp(reg->prop->property_name, prop->property_name);
		if (r == 0)
			return -EEXIST;
		else if (r > 0)
			new = &((*new)->rb_right);
		else
			new = &((*new)->rb_left);
	}

	new_data = kzalloc(sizeof(*new_data), GFP_KERNEL);
	if (!new_data)
		return -ENOMEM;

	new_data->prop = prop;

	rb_link_node(&new_data->node, parent, new);
	rb_insert_color(&new_data->node, &ipe_registry_root);

	return 0;
}
