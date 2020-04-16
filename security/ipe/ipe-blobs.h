/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#include <linux/types.h>
#include <linux/fs.h>

#include "ipe.h"

#ifndef IPE_BLOB_H
#define IPE_BLOB_H

static inline struct ipe_bdev_blob *ipe_bdev(struct block_device *bdev)
{
	return bdev->security + ipe_blobs.lbs_bdev;
}

#endif /* IPE_BLOB_H */
