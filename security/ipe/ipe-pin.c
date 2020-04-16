// SPDX-License-Identifier: GPL-2.0
/*
 * This file has been heavily adapted from the source code of the
 * loadpin LSM. The source code for loadpin is co-located in the linux
 * tree under security/loadpin/loadpin.c.
 *
 * Please see loadpin.c for up-to-date information about
 * loadpin.
 */

#include "ipe.h"

#include <linux/types.h>
#include <linux/spinlock_types.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/magic.h>
#include <linux/mm.h>
#include <linux/mman.h>

static DEFINE_SPINLOCK(pinned_sb_spinlock);

static struct super_block *pinned_sb;

/**
 * ipe_is_from_pinned_sb: Determine if @file originates from the initial
 *			  super block that a file was executed from.
 * @file: File to check if it originates from the super block.
 *
 * Return:
 * true - File originates from the initial super block
 * false - File does not originate from the initial super block
 */
bool ipe_is_from_pinned_sb(const struct file *file)
{
	bool rv = false;

	spin_lock(&pinned_sb_spinlock);

	/*
	 * Check if pinned_sb is set:
	 *  NULL == not set -> exit
	 *  ERR == was once set (and has been unmounted) -> exit
	 * AND check that the pinned sb is the same as the file's.
	 */
	if (!IS_ERR_OR_NULL(pinned_sb) &&
	    file->f_path.mnt->mnt_sb == pinned_sb) {
		rv = true;
		goto cleanup;
	}

cleanup:
	spin_unlock(&pinned_sb_spinlock);
	return rv;
}

/**
 * ipe_pin_superblock: Attempt to save a file's super block address to later
 *		       determine if a file originates from a super block.
 * @file: File to source the super block from.
 */
void ipe_pin_superblock(const struct file *file)
{
	spin_lock(&pinned_sb_spinlock);

	/* if set, return */
	if (pinned_sb || !file)
		goto cleanup;

	pinned_sb = file->f_path.mnt->mnt_sb;
cleanup:
	spin_unlock(&pinned_sb_spinlock);
}

/**
 * ipe_invalidate_pinned_sb: Invalidate the saved super block.
 * @mnt_sb: Super block to compare against the saved super block.
 *
 * This avoids authorizing a file when the super block does not exist anymore.
 */
void ipe_invalidate_pinned_sb(const struct super_block *mnt_sb)
{
	spin_lock(&pinned_sb_spinlock);

	/*
	 * On pinned sb unload - invalidate the pinned address
	 * by setting the pinned_sb to ERR_PTR(-EIO)
	 */
	if (!IS_ERR_OR_NULL(pinned_sb) && mnt_sb == pinned_sb)
		pinned_sb = ERR_PTR(-EIO);

	spin_unlock(&pinned_sb_spinlock);
}
