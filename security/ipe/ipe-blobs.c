// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "ipe.h"
#include "ipe-engine.h"
#include "ipe-blobs.h"

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/device-mapper.h>

/**
 * ipe_bdev_alloc_security: Performs the initialization of IPE's security blob.
 * @bdev: The block device to source the security blob from.
 *
 * The allocation is performed earlier by the LSM infrastructure,
 * (on behalf of all LSMs) in lsm_alloc_bdev. At the moment, IPE uses
 * this time to zero out the region of memory reserved for IPE.
 *
 * Return:
 * 0 - OK
 */
int ipe_bdev_alloc_security(struct block_device *bdev)
{
	struct ipe_bdev_blob *bdev_sec = ipe_bdev(bdev);

	memset(bdev_sec, 0x0, sizeof(*bdev_sec));

	return 0;
}

/**
 * ipe_bdev_free_security: Frees all fields of IPE's block dev security blob.
 * @bdev: The block device to source the security blob from.
 *
 * The deallocation of the blob itself is performed later by the LSM
 * infrastructure, (on behalf of all LSMs) in lsm_free_bdev.
 *
 * Pointers allocated by the bdev_setsecurity hook and alloc_security
 * hook need to be deallocated here.
 */
void ipe_bdev_free_security(struct block_device *bdev)
{
	struct ipe_bdev_blob *bdev_sec = ipe_bdev(bdev);

	memset(bdev_sec, 0x0, sizeof(*bdev_sec));
}

/**
 * ipe_bdev_setsecurity: Sets the a certain field of a block device security
 *			 blob, based on @key.
 * @bdev: The block device to source the security blob from.
 * @key: The key representing the information to be stored.
 * @value: The value to be stored.
 * @len: The length of @value.
 *
 * As block-devices are a generic implementation across specific stacks,
 * this allows information to be stored from various stacks.
 *
 * Return:
 * 0 - OK
 * !0 - Error
 */
int ipe_bdev_setsecurity(struct block_device *bdev, const char *key,
			 const void *value, size_t len)
{
	struct ipe_bdev_blob *bdev_sec = ipe_bdev(bdev);

	if (!strcmp(key, DM_VERITY_SIGNATURE_SEC_NAME)) {
		bdev_sec->dmverity_rh_sig = kmemdup(value, len, GFP_KERNEL);
		if (!bdev_sec->dmverity_rh_sig)
			return -ENOMEM;

		bdev_sec->dmv_rh_sig_len = len;
	}

	return 0;
}
