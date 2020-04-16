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
#include <linux/audit.h>
#include <linux/mount.h>

#define PROPERTY_NAME "dmverity_signature"

static void audit(struct audit_buffer *ab, bool value)
{
	audit_log_format(ab, "%s", (value) ? "TRUE" : "FALSE");
}

static inline void audit_rule_value(struct audit_buffer *ab,
				    const void *value)
{
	audit(ab, (bool)value);
}

static inline void audit_ctx(struct audit_buffer *ab,
			     const struct ipe_engine_ctx *ctx)
{
	bool b = has_bdev(ctx->file) && ctx->sec_bdev->dmverity_rh_sig;

	audit(ab, b);
}

static bool evaluate(const struct ipe_engine_ctx *ctx,
		     const void *value)
{
	bool expect = (bool)value;

	if (!has_bdev(ctx->file))
		return false;

	return ((bool)ctx->sec_bdev->dmverity_rh_sig) == expect;
}

static int parse(const char *val_str, void **value)
{
	if (strcmp("TRUE", val_str) == 0)
		*value = (void *)true;
	else if (strcmp("FALSE", val_str) == 0)
		*value = (void *)false;
	else
		return -EBADMSG;

	return 0;
}

static inline int duplicate(const void *src, void **dest)
{
	*dest = (void *)(bool)src;

	return 0;
}

static const struct ipe_property dmv_signature = {
	.property_name = PROPERTY_NAME,
	.eval = evaluate,
	.parse = parse,
	.rule_audit = audit_rule_value,
	.ctx_audit = audit_ctx,
	.dup = duplicate,
	.free_val = NULL,
};

int ipe_init_dm_verity_signature(void)
{
	return ipe_register_property(&dmv_signature);
}
