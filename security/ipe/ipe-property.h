/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "ipe-engine.h"

#include <linux/types.h>
#include <linux/lsm_audit.h>

#ifndef IPE_PROPERTY_H
#define IPE_PROPERTY_H

/**
 * ipe_property_evaluator: Determines whether a file subject matches the
 *			   property.
 * @value: Value to compare against for a match
 *
 * NOTE: This is done in an rcu read critical section - sleeping
 *	 allocations are prohibited.
 *
 * Return:
 * true - The property matches evaluation
 * false - The property does not match evaluation
 */
typedef bool (*ipe_property_evaluator)(const struct ipe_engine_ctx *ctx,
				       const void *value);

/**
 * ipe_property_audit: Transform a rule value into a string representation.
 * @ab: Audit buffer to add the string representation of @value to.
 * @value: Value to transform into a string representation.
 *
 * NOTE: This is done in an rcu read critical section - sleeping
 *	 allocations are prohibited.
 */
typedef void (*ipe_property_audit)(struct audit_buffer *ab, const void *value);

/**
 * ipe_ctx_audit: Called by the auditing to provide the values
 *	that were evaluated about the subject, @ctx->file, to determine how
 *	a value was evaluated.
 *
 * NOTE: This is done in an rcu read critical section - sleeping
 *	 allocations are prohibited.
 *
 * @ab: Audit buffer to add the string representation of @value to.
 * @value: Value to transform into a string representation.
 *
 */
typedef void (*ipe_ctx_audit)(struct audit_buffer *ab,
			     const struct ipe_engine_ctx *ctx);

/**
 * ipe_parse_value: Transform a string representation of a rule into an
 *		    internal ipe data-structure, opaque to the engine.
 * @val_str: String-value parsed by the policy parser.
 * @value: Valid-pointer indicating address to store parsed value.
 *
 * Return:
 * 0 - OK
 * !0 - ERR, use Standard Return Codes
 */
typedef int(*ipe_parse_value)(const char *val_str, void **value);

/**
 * ipe_dup_val: Called by the policy parser to make duplicate properties for
 *		pseudo-properties like "KERNEL_READ".
 * @src:  Value to copy.
 * @dest: Pointer to the destination where the value should be copied.
 *
 * Return:
 * 0 - OK
 * !0 - ERR, use Standard Return Codes
 */
typedef int (*ipe_dup_val)(const void *src, void **dest);

/**
 * ipe_free_value: Free a policy value, created by ipe_parse_value.
 * @value: Valid-pointer to the value to be interpreted and
 *	   freed by the property.
 *
 * Optional, can be NULL - in which case, this will not be called.
 */
typedef void (*ipe_free_value)(void **value);

struct ipe_property {
	const char			*const property_name;
	ipe_property_evaluator		eval;
	ipe_property_audit		rule_audit;
	ipe_ctx_audit			ctx_audit;
	ipe_parse_value			parse;
	ipe_dup_val			dup;
	ipe_free_value			free_val;
};

int ipe_register_property(const struct ipe_property *prop);

#endif /* IPE_PROPERTY_H */
