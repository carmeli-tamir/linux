// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Microsoft Corporation.
 *
 * Author:  Jaskaran Singh Khurana <jaskarankhurana@linux.microsoft.com>
 *
 */
#include <linux/device-mapper.h>
#include <linux/verification.h>
#include <keys/user-type.h>
#include <linux/module.h>
#include "dm-verity.h"
#include "dm-verity-verify-sig.h"

#define DM_VERITY_VERIFY_ERR(s) DM_VERITY_ROOT_HASH_VERIFICATION " " s

static bool require_signatures;
module_param(require_signatures, bool, false);
MODULE_PARM_DESC(require_signatures,
		"Verify the roothash of dm-verity hash tree");

#define DM_VERITY_IS_SIG_FORCE_ENABLED() \
	(require_signatures != false)

static void destroy_verity_sig(struct dm_verity_sig *sig_info)
{
	if (!sig_info)
		return;

	kfree(sig_info->sig);
	kfree(sig_info->signature_key_desc);
	kfree(sig_info);
}

bool verity_verify_is_sig_opt_arg(const char *arg_name)
{
	return (!strcasecmp(arg_name,
			    DM_VERITY_ROOT_HASH_VERIFICATION_OPT_SIG_KEY));
}

static int verity_verify_get_sig_from_key(const char *key_desc,
					  struct dm_verity_sig  *sig_info)
{
	struct key *key;
	const struct user_key_payload *ukp;
	int ret = 0;

	key = request_key(&key_type_user,
			key_desc, NULL);
	if (IS_ERR(key))
		return PTR_ERR(key);

	down_read(&key->sem);

	ukp = user_key_payload_locked(key);
	if (!ukp) {
		ret = -EKEYREVOKED;
		goto end;
	}

	sig_info->sig = kmalloc(ukp->datalen, GFP_KERNEL);
	if (!sig_info->sig) {
		ret = -ENOMEM;
		goto end;
	}
	sig_info->sig_size = ukp->datalen;

	memcpy(sig_info->sig, ukp->data, sig_info->sig_size);

end:
	up_read(&key->sem);
	key_put(key);

	return ret;
}

/**
 * Parse any signature verification arguments.
 *	This function will populate v->sig, it is the caller's
 *	responsibility to free this structure via verity_verify_dtr
 *
 * @as: argument set passed in to parse
 * @v: verity context structure. Should have a NULL v->sig member.
 * @argc: current argument number
 */
int verity_verify_sig_parse_opt_args(struct dm_arg_set *as,
				     struct dm_verity *v,
				     unsigned int *argc)
{
	struct dm_target *ti = v->ti;
	struct dm_verity_sig *sig_info = NULL;
	int ret = 0;
	const char *sig_key = NULL;

	if (!*argc) {
		ti->error = DM_VERITY_VERIFY_ERR("Signature key not specified");
		ret = -EINVAL;
		goto cleanup;
	}

	sig_info = kzalloc(sizeof(*sig_info), GFP_KERNEL);
	if (!sig_info) {
		ret = -ENOMEM;
		goto cleanup;
	}

	sig_key = dm_shift_arg(as);
	(*argc)--;

	ret = verity_verify_get_sig_from_key(sig_key, sig_info);
	if (ret < 0) {
		ti->error = DM_VERITY_VERIFY_ERR("Invalid key specified");
		goto cleanup;
	}

	sig_info->signature_key_desc = kstrdup(sig_key, GFP_KERNEL);
	if (!sig_info->signature_key_desc) {
		ret = -ENOMEM;
		goto cleanup;
	}

	v->sig = sig_info;
	sig_info = NULL;
cleanup:
	if (sig_info)
		destroy_verity_sig(sig_info);
	return ret;
}

/**
 * verify_verify_roothash - Verify the root hash of the verity hash device
 *			     using builtin trusted keys.
 *
 * @v: dm_verity structure containing all context for the dm_verity
 *	operation.
 *
 */
int verity_verify_root_hash(const struct dm_verity *v)
{
	int ret = 0;
	char *root_hash = NULL;
	size_t root_hash_size = 0;
	struct dm_verity_sig *sig_target = NULL;

	if (!v || !v->ti || !v->root_digest || v->digest_size == 0) {
		ret = -EINVAL;
		goto cleanup;
	}

	sig_target = v->sig;

	if (!sig_target || !sig_target->sig || sig_target->sig_size == 0) {
		if (DM_VERITY_IS_SIG_FORCE_ENABLED()) {
			ret = -ENOKEY;
			goto cleanup;
		} else {
			goto cleanup;
		}
	}

	/*
	 * If signature has passed validation once, assume
	 * that future signatures will pass.
	 */
	if (sig_target->passed)
		goto cleanup;

	root_hash_size = v->digest_size * 2;
	root_hash = kzalloc(root_hash_size, GFP_KERNEL);
	if (!root_hash) {
		ret = -ENOMEM;
		goto cleanup;
	}

	bin2hex(root_hash, v->root_digest, v->digest_size);

	ret = verify_pkcs7_signature(root_hash, root_hash_size, v->sig->sig,
				     v->sig->sig_size, NULL,
				     VERIFYING_UNSPECIFIED_SIGNATURE, NULL,
				     NULL);
	if (ret != 0)
		goto cleanup;

	sig_target->passed = true;
cleanup:
	kfree(root_hash);
	return ret;
}

/**
 * Performs destruction / cleanup of a valid dm_verity_sig struct
 *
 * @v: dm_verity structure containing the dm_verity_sig struct to
 *	be freed.
 */

void verity_verify_dtr(struct dm_verity *v)
{
	destroy_verity_sig(v->sig);
	v->sig = NULL;
}
