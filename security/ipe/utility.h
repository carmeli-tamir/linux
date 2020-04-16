/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#ifndef IPE_UTILITY_H
#define IPE_UTILITY_H

#include <linux/types.h>
#include <linux/fs.h>

static inline bool has_mount(const struct file *file)
{
	return file && file->f_path.mnt;
}

static inline bool has_sb(const struct file *file)
{
	return has_mount(file) && file->f_path.mnt->mnt_sb;
}

static inline bool has_bdev(const struct file *file)
{
	return has_sb(file) && file->f_path.mnt->mnt_sb->s_bdev;
}

static inline struct block_device *bdev(const struct file *file)
{
	return file->f_path.mnt->mnt_sb->s_bdev;
}

#endif /* IPE_UTILITY_H */
