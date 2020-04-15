// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "ipe.h"
#include "ipe-policy.h"
#include "ipe-hooks.h"
#include "ipe-secfs.h"
#include "ipe-sysfs.h"

#include <linux/module.h>
#include <linux/lsm_hooks.h>
#include <linux/sysctl.h>
#include <linux/rcupdate.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/security.h>

static struct security_hook_list ipe_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(bprm_check_security, ipe_on_exec),
	LSM_HOOK_INIT(mmap_file, ipe_on_mmap),
	LSM_HOOK_INIT(kernel_read_file, ipe_on_kernel_read),
	LSM_HOOK_INIT(kernel_load_data, ipe_on_kernel_load_data),
	LSM_HOOK_INIT(file_mprotect, ipe_on_mprotect),
};

/**
 * ipe_init: Entry point of IPE.
 *
 * This is called at LSM init, which happens occurs early during kernel
 * start up. During this phase, IPE initializes the sysctls, loads the
 * properties compiled into the kernel, and register's IPE's hooks.
 * The boot policy is loaded later, during securityfs init, at which point
 * IPE will start enforcing its policy.
 *
 * Return:
 * 0 - OK
 * -ENOMEM - sysctl registration failed.
 */
static int __init ipe_init(void)
{
	int rc;

	rc = ipe_sysctl_init();
	if (rc != 0)
		pr_err("failed to configure sysctl: %d", -rc);

	pr_info("mode=%s", (ipe_enforce == 1) ? IPE_MODE_ENFORCE :
						IPE_MODE_PERMISSIVE);

	security_add_hooks(ipe_hooks, ARRAY_SIZE(ipe_hooks), "IPE");

	return rc;
}

DEFINE_LSM(ipe) = {
	.name = "ipe",
	.init = ipe_init,
};

int ipe_enforce = 1;
int ipe_success_audit;
int ipe_strict_parse;
