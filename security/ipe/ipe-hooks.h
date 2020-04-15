/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/binfmts.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/security.h>

#ifndef IPE_HOOK_H
#define IPE_HOOK_H

#define IPE_HOOK_EXEC		"EXEC"
#define IPE_HOOK_MMAP		"MMAP"
#define IPE_HOOK_MPROTECT	"MPROTECT"
#define IPE_HOOK_KERNEL_READ	"KERNEL_READ"
#define IPE_HOOK_KERNEL_LOAD	"KERNEL_LOAD"

enum ipe_hook {
	ipe_hook_exec = 0,
	ipe_hook_mmap,
	ipe_hook_mprotect,
	ipe_hook_kernel_read,
	ipe_hook_kernel_load,
	ipe_hook_max
};

/*
 * The sequence between ipe_op_firmware and ipe_op_kmodule
 * must remain the same for ipe_op_kernel read to function
 * appropriately.
 */
enum ipe_op {
	ipe_op_execute = 0,
	ipe_op_firmware,
	ipe_op_kexec_image,
	ipe_op_kexec_initramfs,
	ipe_op_x509,
	ipe_op_policy,
	ipe_op_kmodule,
	ipe_op_kernel_read,
	ipe_op_max
};

int ipe_on_exec(struct linux_binprm *bprm);

int ipe_on_mmap(struct file *file, unsigned long reqprot, unsigned long prot,
		unsigned long flags);

int ipe_on_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
		    unsigned long prot);

int ipe_on_kernel_read(struct file *file, enum kernel_read_file_id id);

int ipe_on_kernel_load_data(enum kernel_load_data_id id);

void ipe_sb_free_security(struct super_block *mnt_sb);

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
int ipe_bdev_alloc_security(struct block_device *bdev);

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
void ipe_bdev_free_security(struct block_device *bdev);

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
			 const void *value, size_t len);

#endif /* IPE_HOOK_H */
