// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "ipe.h"
#include "ipe-secfs.h"
#include "ipe-policy.h"
#include "ipe-parse.h"
#include "ipe-audit.h"

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/lockdep.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/rcupdate.h>

#define VER_TO_UINT64(_major, _minor, _rev) \
	((((((u64)(_major)) << 16) | ((u64)(_minor))) << 16) | ((u64)(_rev)))

/**
 * ipe_is_version_allowed: Determine if @new has a greater or equal
 *			   policy version than @old.
 * @old: The policy to compare against.
 * @new: The policy staged to replace @old.
 *
 * Return:
 * true - @new has a policy version >= than @old
 * false - @new does not have a policy version >= than @old
 */
static bool ipe_is_version_allowed(const struct ipe_pol_ver *old,
				   const struct ipe_pol_ver *new)
{
	u64 old_ver = VER_TO_UINT64(old->major, old->minor, old->rev);
	u64 new_ver = VER_TO_UINT64(new->major, new->minor, new->rev);

	return new_ver >= old_ver;
}

/**
 * ipe_is_valid_policy: determine if @old is allowed to replace @new.
 * @old: policy that the @new is supposed to replace. Can be NULL.
 * @new: the policy that is supposed to replace @new.
 *
 * Return:
 * true - @new can replace @old
 * false - @new cannot replace @old
 */
bool ipe_is_valid_policy(const struct ipe_policy *old,
			 const struct ipe_policy *new)
{
	if (old)
		return ipe_is_version_allowed(&old->policy_version,
					      &new->policy_version);
	return true;
}

/**
 * ipe_is_active_policy: Determine if @policy is the currently active policy.
 * @policy: Policy to check if it's the active policy.
 *
 * Return:
 * true - @policy is the active policy
 * false - @policy is not the active policy
 */
bool ipe_is_active_policy(const struct ipe_policy *policy)
{
	return rcu_access_pointer(ipe_active_policy) == policy;
}

/**
 * ipe_update_active_policy: Determine if @old is the active policy, and update
 *			     the active policy if necessary.
 * @old: The previous policy that the update is trying to replace.
 * @new: The new policy attempting to replace @old.
 *
 * If @old is not the active policy, nothing will be done.
 *
 * Return:
 * 0 - OK
 * -EBADMSG - Invalid Policy
 */
int ipe_update_active_policy(const struct ipe_policy *old,
			     const struct ipe_policy *new)
{
	const struct ipe_policy *curr = NULL;

	lockdep_assert_held(&ipe_policy_lock);

	/* no active policy, safe to update */
	if (!rcu_access_pointer(ipe_active_policy))
		return 0;

	curr = rcu_dereference_protected(ipe_active_policy,
					 lockdep_is_held(&ipe_policy_lock));

	if (curr == old) {
		if (!ipe_is_valid_policy(curr, new))
			return -EINVAL;

		ipe_audit_policy_activation(new);

		(void)rcu_replace_pointer(ipe_active_policy, new,
					  lockdep_is_held(&ipe_policy_lock));
	}

	return 0;
}

/**
 * ipe_activate_policy: Set a specific policy as the active policy.
 * @pol: The policy to set as the active policy.
 *
 * This is only called by the sysctl "ipe.active_policy".
 *
 * Return:
 * 0 - OK
 * -EINVAL - Policy that is being activated is lower in version than
 *	     currently running policy.
 */
int ipe_activate_policy(const struct ipe_policy *pol)
{
	const struct ipe_policy *curr = NULL;

	lockdep_assert_held(&ipe_policy_lock);

	curr = rcu_dereference_protected(ipe_active_policy,
					 lockdep_is_held(&ipe_policy_lock));

	/*
	 * User-set policies must be >= to current running policy.
	 */
	if (!ipe_is_valid_policy(curr, pol))
		return -EINVAL;

	ipe_audit_policy_activation(pol);

	/* cleanup of this pointer is handled by the secfs removal */
	(void)rcu_replace_pointer(ipe_active_policy, pol,
				  lockdep_is_held(&ipe_policy_lock));

	return 0;
}
