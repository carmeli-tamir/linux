// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "../ipe.h"
#include "../ipe-pin.h"
#include "../ipe-property.h"
#include "../utility.h"

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/audit.h>
#include <linux/kernel.h>

#define PROPERTY_NAME "dmverity_roothash"

struct counted_array {
	u8 *arr;
	size_t len;
};

static void audit(struct audit_buffer *ab, const void *value)
{
	const struct counted_array *a = (const struct counted_array *)value;

	if (!a || a->len == 0)
		audit_log_format(ab, "NULL");
	else
		audit_log_n_hex(ab, a->arr, a->len);
}

static inline void audit_rule_value(struct audit_buffer *ab,
				    const void *value)
{
	audit(ab, value);
}

static inline void audit_ctx(struct audit_buffer *ab,
			     const struct ipe_engine_ctx *ctx)
{
	struct counted_array a;

	if (!has_bdev(ctx->file))
		return audit(ab, NULL);

	a.arr = ctx->sec_bdev->dmverity_rh;
	a.len = ctx->sec_bdev->rh_size;

	return audit(ab, &a);
}

static bool evaluate(const struct ipe_engine_ctx *ctx,
		     const void *value)
{
	const struct counted_array *a = (const struct counted_array *)value;

	if (!has_bdev(ctx->file))
		return false;

	if (a->len != ctx->sec_bdev->rh_size)
		return false;

	return memcmp(a->arr, ctx->sec_bdev->dmverity_rh, a->len) == 0;
}

static int parse(const char *val_str, void **value)
{
	struct counted_array *arr = NULL;
	int rv = 0;

	arr = kzalloc(sizeof(*arr), GFP_KERNEL);
	if (!arr) {
		rv = -ENOMEM;
		goto err;
	}

	arr->len = strlen(val_str) / 2;

	arr->arr = kzalloc(arr->len, GFP_KERNEL);
	if (!arr->arr) {
		rv = -ENOMEM;
		goto err;
	}

	rv = hex2bin(arr->arr, val_str, arr->len);
	if (rv != 0)
		goto err;

	*value = arr;
	return rv;
err:
	if (arr)
		kfree(arr->arr);
	kfree(arr);
	return rv;
}

static int duplicate(const void *src, void **dest)
{
	struct counted_array *arr = NULL;
	const struct counted_array *src_arr = src;
	int rv = 0;

	arr = kmemdup(src_arr, sizeof(*arr), GFP_KERNEL);
	if (!arr) {
		rv = -ENOMEM;
		goto err;
	}

	arr->arr = kmemdup(src_arr->arr, src_arr->len, GFP_KERNEL);
	if (!arr->arr) {
		rv = -ENOMEM;
		goto err;
	}

	*dest = arr;
	return rv;
err:
	if (arr)
		kfree(arr->arr);
	kfree(arr);

	return rv;
}

static void free_val(void **value)
{
	struct counted_array *a = (struct counted_array *)*value;

	if (a)
		kfree(a->arr);
	kfree(a);
	*value = NULL;
}

static const struct ipe_property dmv_roothash = {
	.property_name = PROPERTY_NAME,
	.eval = evaluate,
	.parse = parse,
	.rule_audit = audit_rule_value,
	.ctx_audit = audit_ctx,
	.dup = duplicate,
	.free_val = free_val,
};

int ipe_init_dm_verity_rh(void)
{
	return ipe_register_property(&dmv_roothash);
}
