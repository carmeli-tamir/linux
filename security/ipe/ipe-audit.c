// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "ipe.h"
#include "ipe-audit.h"
#include "ipe-engine.h"
#include "ipe-prop-internal.h"

#include <linux/types.h>
#include <linux/audit.h>
#include <linux/rcupdate.h>
#include <linux/lsm_audit.h>
#include <linux/rbtree.h>
#include <crypto/hash.h>
#include <crypto/sha1_base.h>

#define ACTION_STR(a) ((a) == ipe_action_allow ? "ALLOW" : "DENY")
#define POLICY_LOAD_FSTR	"IPE policy_name=\"%s\" policy_version=%hu.%hu.%hu sha1="
#define POLICY_ACTIVATE_STR	"IPE policy_name=\"%s\" policy_version=%hu.%hu.%hu"
#define IPE_UNKNOWN		"UNKNOWN"

/* Keep in sync with ipe_op in ipe-hooks.h */
const char *audit_op_names[] = {
	IPE_OP_EXECUTE,
	IPE_OP_FIRMWARE,
	IPE_OP_KEXEC_IMAGE,
	IPE_OP_KEXEC_INITRAMFS,
	IPE_OP_X509_CERTIFICATE,
	IPE_OP_POLICY,
	IPE_OP_KMODULE,
	IPE_OP_KERNEL_READ,
	IPE_UNKNOWN,
};

/* Keep in sync with ipe_hook in ipe-hooks.h */
const char *audit_hook_names[] = {
	IPE_HOOK_EXEC,
	IPE_HOOK_MMAP,
	IPE_HOOK_MPROTECT,
	IPE_HOOK_KERNEL_READ,
	IPE_HOOK_KERNEL_LOAD,
	IPE_UNKNOWN,
};

/**
 * ipe_audit_mode: Emit an audit event indicating what mode IPE is currently
 *		   in.
 *
 * This event is of form "IPE mode=(enforce|audit)"
 */
void ipe_audit_mode(void)
{
	struct audit_buffer *ab;
	const char *mode_str = (ipe_enforce) ? IPE_MODE_ENFORCE :
					       IPE_MODE_PERMISSIVE;

	ab = audit_log_start(audit_context(), GFP_KERNEL,
			     AUDIT_INTEGRITY_MODE);
	if (!ab)
		return;

	audit_log_format(ab, "IPE mode=%s", mode_str);

	audit_log_end(ab);
}

/**
 * audit_engine_ctx: Add the string representation of ipe_engine_ctx to the
 *		     end of an audit buffer.
 * @ab: the audit buffer to append the string representation of @ctx
 * @ctx: the ipe_engine_ctx structure to transform into a string
 *	 representation
 *
 * This string representation is of form:
 * "ctx_pid=%d ctx_op=%s ctx_hook=%s ctx_comm=%s ctx_audit_pathname=%s ctx_ino=%ld ctx_dev=%s"
 *
 * Certain fields may be omitted or replaced with ERR(%d).
 *
 */
static void audit_engine_ctx(struct audit_buffer *ab,
			     const struct ipe_engine_ctx *ctx)
{
	audit_log_format(ab, "ctx_pid=%d ctx_op=%s ctx_hook=%s ctx_comm=",
			 task_tgid_nr(current),
			 audit_op_names[ctx->op],
			 audit_hook_names[ctx->hook]);

	audit_log_untrustedstring(ab, current->comm);

	if (ctx->file) {
		if (IS_ERR(ctx->audit_pathname)) {
			audit_log_format(ab, " ctx_audit_pathname=ERR(%ld) ",
					 PTR_ERR(ctx->audit_pathname));
		} else {
			audit_log_format(ab, " ctx_audit_pathname=\"%s\" ",
					 ctx->audit_pathname);
		}

		audit_log_format(ab, "ctx_ino=%ld ctx_dev=%s",
				 ctx->file->f_inode->i_ino,
				 ctx->file->f_inode->i_sb->s_id);
	}
}

/**
 * audit_eval_properties: Append the string representation of evaluated
 *			  properties to an audit buffer.
 * @ab: the audit buffer to append the string representation of the evaluated
 *	properties.
 * @ctx: the ipe_engine_ctx structure to pass to property audit function.
 *
 * This string representation is of form:
 * "prop_key1=value1 prop_key2=value2 ... "
 *
 * Certain values may be replaced with ERR(%d). Prop may also be empty,
 * and thus omitted entirely.
 *
 */
static void audit_eval_properties(struct audit_buffer *ab,
				  const struct ipe_engine_ctx *ctx)
{
	struct rb_node *node;
	struct ipe_prop_reg *val;

	for (node = rb_first(&ipe_registry_root); node; node = rb_next(node)) {
		val = container_of(node, struct ipe_prop_reg, node);

		audit_log_format(ab, "prop_%s=", val->prop->property_name);

		val->prop->ctx_audit(ab, ctx);

		audit_log_format(ab, " ");
	}
}

/**
 * audit_rule: Add the string representation of a non-default IPE rule to the
 *	       end of an audit buffer.
 * @ab: the audit buffer to append the string representation of a rule.
 * @rule: the ipe_rule structure to transform into a string representation.
 *
 * This string representation is of form:
 * "rule={op=%s key1=value1 key2=value2 ... action=%s}"
 *
 * Certain values may be replaced with ERR(%d).
 *
 */
static void audit_rule(struct audit_buffer *ab,
		       const struct ipe_rule *rule)
{
	struct ipe_prop_container *ptr;

	audit_log_format(ab, "rule=\"op=%s ", audit_op_names[rule->op]);

	list_for_each_entry(ptr, &rule->props, next) {
		audit_log_format(ab, "%s=", ptr->prop->property_name);

		ptr->prop->rule_audit(ab, ptr->value);

		audit_log_format(ab, " ");
	}

	audit_log_format(ab, "action=%s\"", ACTION_STR(rule->action));
}

/**
 * ipe_audit_match: Emit an audit event indicating that the IPE engine has
 *		    determined a match to a rule in IPE policy.
 * @ctx: the engine context structure to audit
 * @rule: The rule that was matched. If NULL, then assumed to be a default
 *	  either operation specific, indicated by table, or global.
 * @table: the operation-specific rule table. If NULL, then it assumed
 *	   that the global default is matched.
 * @match_type: The type of match that the engine used during evaluation
 * @action: The action that the engine decided to take
 * @rule: The rule that was matched. Must be set if @match_type is
 *	  ipe_match_rule and NULL otherwise.
 */
void ipe_audit_match(const struct ipe_engine_ctx *ctx,
		     enum ipe_match match_type, enum ipe_action action,
		     const struct ipe_rule *rule)
{
	struct audit_buffer *ab;

	if (!ipe_success_audit && action == ipe_action_allow)
		return;

	ab = audit_log_start(audit_context(), GFP_ATOMIC | __GFP_NOWARN,
			     AUDIT_INTEGRITY_EVENT);
	if (!ab)
		return;

	audit_log_format(ab, "IPE ");

	audit_engine_ctx(ab, ctx);

	audit_log_format(ab, " ");

	audit_eval_properties(ab, ctx);

	if (match_type == ipe_match_rule)
		audit_rule(ab, rule);
	else if (match_type == ipe_match_table)
		audit_log_format(ab, "rule=\"DEFAULT op=%s action=%s\"",
				 audit_op_names[ctx->op], ACTION_STR(action));
	else if (match_type == ipe_match_global)
		audit_log_format(ab, "rule=\"DEFAULT action=%s\"",
				 ACTION_STR(action));

	audit_log_end(ab);
}

/**
 * ipe_audit_policy_load: Emit an audit event that an IPE policy has been
 *			  loaded, with the name of the policy, the policy
 *			  version triple, and a flat hash of the content.
 * @pol: The parsed policy to derive the policy_name and policy_version
 *	 triple.
 * @raw: The raw content that was passed to the ipe.policy sysctl to derive
 *	 the sha1 hash.
 * @raw_size: the length of @raw.
 * @tfm: shash structure allocated by the caller, used to fingerprint the
 *	 policy being deployed
 */
void ipe_audit_policy_load(const struct ipe_policy *pol, const uint8_t *raw,
			   size_t raw_size, struct crypto_shash *tfm)
{
	int rc = 0;
	struct audit_buffer *ab;
	u8 digest[SHA1_DIGEST_SIZE];
	SHASH_DESC_ON_STACK(desc, tfm);

	ab = audit_log_start(audit_context(), GFP_KERNEL,
			     AUDIT_INTEGRITY_POLICY_LOAD);
	if (!ab)
		return;

	audit_log_format(ab, POLICY_LOAD_FSTR, pol->policy_name,
			 pol->policy_version.major, pol->policy_version.minor,
			 pol->policy_version.rev);

	desc->tfm = tfm;

	if (crypto_shash_init(desc) != 0)
		goto err;

	if (crypto_shash_update(desc, raw, raw_size) != 0)
		goto err;

	if (crypto_shash_final(desc, digest) != 0)
		goto err;

	audit_log_n_hex(ab, digest, crypto_shash_digestsize(tfm));

err:
	if (rc != 0)
		audit_log_format(ab, "ERR(%d)", rc);

	audit_log_end(ab);
}

/**
 * ipe_audit_policy_activation: Emit an audit event that a specific policy
 *				was activated as the active policy.
 * @pol: policy that is being activated
 */
void ipe_audit_policy_activation(const struct ipe_policy *pol)
{
	struct audit_buffer *ab;

	ab = audit_log_start(audit_context(), GFP_KERNEL,
			     AUDIT_INTEGRITY_POLICY_ACTIVATE);

	if (!ab)
		return;

	audit_log_format(ab, POLICY_ACTIVATE_STR, pol->policy_name,
			 pol->policy_version.major, pol->policy_version.minor,
			 pol->policy_version.rev);

	audit_log_end(ab);
}

/**
 * ipe_audit_unset_remap: Emit an warning indicating that the operation
 *			  represented by @op is unset and will implicitly
 *			  allow everything under that op.
 * @op: the operation to emit an audit message for.
 */
void ipe_audit_unset_remap(enum ipe_op op)
{
	pr_warn("op=%s default was unset, remapping to \"DEFAULT op=%s action=ALLOW\" for compatibility",
		audit_op_names[op],
		audit_op_names[op]);
}
