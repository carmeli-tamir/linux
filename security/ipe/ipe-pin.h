/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#ifndef IPE_PIN_H
#define IPE_PIN_H

#include <linux/types.h>
#include <linux/fs.h>

#ifdef CONFIG_IPE_BOOT_PROP

/**
 * ipe_is_from_pinned_sb: Determine if @file originates from the initial
 *			  super block that a file was executed from.
 * @file: File to check if it originates from the super block.
 *
 * Return:
 * true - File originates from the initial super block
 * false - File does not originate from the initial super block
 */
bool ipe_is_from_pinned_sb(const struct file *file);

/**
 * ipe_pin_superblock: Attempt to save a file's super block address to later
 *		       determine if a file originates from a super block.
 * @file: File to source the super block from.
 */
void ipe_pin_superblock(const struct file *file);

/**
 * ipe_invalidate_pinned_sb: Invalidate the saved super block.
 * @mnt_sb: Super block to compare against the saved super block.
 *
 * This avoids authorizing a file when the super block does not exist anymore.
 */
void ipe_invalidate_pinned_sb(const struct super_block *mnt_sb);

#else /* CONFIG_IPE_BOOT_PROP */

static inline bool ipe_is_from_pinned_sb(const struct file *file)
{
	return false;
}

static inline void ipe_pin_superblock(const struct file *file)
{
}

static inline void ipe_invalidate_pinned_sb(const struct super_block *mnt_sb)
{
}

#endif /* !CONFIG_IPE_BOOT_PROP */

#endif /* IPE_PIN_H */
