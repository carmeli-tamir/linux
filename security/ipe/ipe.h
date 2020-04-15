/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#ifndef IPE_H
#define IPE_H

#define pr_fmt(fmt) "IPE " fmt "\n"

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/lsm_hooks.h>

#define IPE_MODE_ENFORCE	"enforce"
#define IPE_MODE_PERMISSIVE	"permissive"

extern struct lsm_blob_sizes ipe_blobs;
extern int ipe_enforce;
extern int ipe_success_audit;
extern int ipe_strict_parse;

#endif /* IPE_H */
