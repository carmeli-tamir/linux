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

#endif /* IPE_HOOK_H */
