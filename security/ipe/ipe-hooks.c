// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "ipe.h"
#include "ipe-hooks.h"
#include "ipe-engine.h"
#include "ipe-pin.h"

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/binfmts.h>
#include <linux/mount.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/security.h>

/**
 * ipe_on_exec: LSM hook called on the exec family of system calls.
 * @bprm: A structure to hold arguments that are used when loading binaries,
 *	  used to extract the file being executed.
 *
 * Return:
 * 0 - OK
 * !0 - see ipe_process_event
 */
int ipe_on_exec(struct linux_binprm *bprm)
{
	return ipe_process_event(bprm->file, ipe_op_execute, ipe_hook_exec);
}

/**
 * ipe_on_mmap: LSM hook called on the mmap system call.
 * @file: File being mapped into memory.
 * @reqprot: Unused.
 * @prot: A protection mapping of the memory region, calculated based on
 *	  @reqprot, and the system configuration.
 * @flags: Unused.
 *
 * Return:
 * 0 - OK
 * !0 - see ipe_process_event
 */
int ipe_on_mmap(struct file *file, unsigned long reqprot, unsigned long prot,
		unsigned long flags)
{
	if (prot & PROT_EXEC)
		return ipe_process_event(file, ipe_op_execute, ipe_hook_mmap);

	return 0;
}

/**
 * ipe_on_mprotect: LSM hook called on the mprotect system call
 * @vma: A structure representing the existing memory region.
 * @reqprot: Unused.
 * @prot: A protection mapping of the memory region, calculated based on
 *	  @reqprot, and the system configuration.
 *
 * Return:
 * 0 - OK
 * !0 - see ipe_process_event
 */
int ipe_on_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
		    unsigned long prot)
{
	if ((prot & PROT_EXEC) && !(vma->vm_flags & VM_EXEC))
		return ipe_process_event(vma->vm_file, ipe_op_execute,
					 ipe_hook_mprotect);

	return 0;
}

/**
 * ipe_on_kernel_read: LSM hook called on kernel_read_file.
 * @file: File being read by the hook kernel_read_file.
 * @id: Enumeration indicating the type of file being read.
 *
 * For more information, see the LSM hook, kernel_read_file.
 *
 * Return:
 * 0 - OK
 * !0 - see ipe_process_event
 */
int ipe_on_kernel_read(struct file *file, enum kernel_read_file_id id)
{
	switch (id) {
	case READING_FIRMWARE:
	case READING_FIRMWARE_PREALLOC_BUFFER:
		return ipe_process_event(file, ipe_op_firmware,
					 ipe_hook_kernel_read);
	case READING_MODULE:
		return ipe_process_event(file, ipe_op_kmodule,
					 ipe_hook_kernel_read);
	case READING_KEXEC_INITRAMFS:
		return ipe_process_event(file, ipe_op_kexec_initramfs,
					 ipe_hook_kernel_read);
	case READING_KEXEC_IMAGE:
		return ipe_process_event(file, ipe_op_kexec_image,
					 ipe_hook_kernel_read);
	case READING_POLICY:
		return ipe_process_event(file, ipe_op_policy,
					 ipe_hook_kernel_read);
	case READING_X509_CERTIFICATE:
		return ipe_process_event(file, ipe_op_x509,
					 ipe_hook_kernel_read);
	default:
		return ipe_process_event(file, ipe_op_kernel_read,
					 ipe_hook_kernel_read);
	}
}

/**
 * ipe_on_kernel_load_data: LSM hook called on kernel_load_data.
 * @id: Enumeration indicating what type of data is being loaded.
 *
 * For more information, see the LSM hook, kernel_load_data.
 *
 * Return:
 * 0 - OK
 * !0 - see ipe_process_event
 */
int ipe_on_kernel_load_data(enum kernel_load_data_id id)
{
	switch (id) {
	case LOADING_FIRMWARE:
	case LOADING_FIRMWARE_PREALLOC_BUFFER:
		return ipe_process_event(NULL, ipe_op_firmware,
					 ipe_hook_kernel_load);
	case LOADING_MODULE:
		return ipe_process_event(NULL, ipe_op_kmodule,
					 ipe_hook_kernel_load);
	case LOADING_KEXEC_INITRAMFS:
		return ipe_process_event(NULL, ipe_op_kexec_initramfs,
					 ipe_hook_kernel_load);
	case LOADING_KEXEC_IMAGE:
		return ipe_process_event(NULL, ipe_op_kexec_image,
					 ipe_hook_kernel_load);
	case LOADING_POLICY:
		return ipe_process_event(NULL, ipe_op_policy,
					 ipe_hook_kernel_load);
	case LOADING_X509_CERTIFICATE:
		return ipe_process_event(NULL, ipe_op_x509,
					 ipe_hook_kernel_load);
	default:
		return ipe_process_event(NULL, ipe_op_kernel_read,
					 ipe_hook_kernel_load);
	}
}

/**
 * ipe_sb_free_security: LSM hook called on sb_free_security.
 * @mnt_sb: Super block that is being freed.
 *
 * IPE does not currently utilize the super block security hook,
 * it utilizes this hook to invalidate the saved super block for
 * the boot_verified property.
 *
 * For more information, see the LSM hook, sb_free_security.
 *
 * Return:
 * 0 - OK
 */
void ipe_sb_free_security(struct super_block *mnt_sb)
{
	ipe_invalidate_pinned_sb(mnt_sb);
}
