/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "ipe.h"
#include "ipe-hooks.h"

#include <linux/types.h>
#include <linux/rbtree.h>
#include <linux/fs.h>

#include <crypto/pkcs7.h>

#ifndef IPE_ENGINE_H
#define IPE_ENGINE_H

struct ipe_bdev_blob {
	u8	*dmverity_rh_sig;
	size_t	dmv_rh_sig_len;

	u8 *dmverity_rh;
	size_t rh_size;
};

struct ipe_engine_ctx {
	enum ipe_op op;
	enum ipe_hook hook;
	const struct file *file;
	const char *audit_pathname;
	const struct ipe_bdev_blob *sec_bdev;
};

struct ipe_prop_cache {
	struct rb_node node;
	void *storage;
	const struct ipe_property *prop;
};

enum ipe_match {
	ipe_match_rule = 0,
	ipe_match_table,
	ipe_match_global
};

int ipe_process_event(const struct file *file, enum ipe_op op,
		      enum ipe_hook hook);

#endif /* IPE_ENGINE_H */
