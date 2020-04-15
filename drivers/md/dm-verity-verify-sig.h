// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Microsoft Corporation.
 *
 * Author:  Jaskaran Singh Khurana <jaskarankhurana@linux.microsoft.com>
 *
 */
#ifndef DM_VERITY_SIG_VERIFICATION_H
#define DM_VERITY_SIG_VERIFICATION_H

#define DM_VERITY_ROOT_HASH_VERIFICATION "DM Verity Sig Verification"
#define DM_VERITY_ROOT_HASH_VERIFICATION_OPT_SIG_KEY "root_hash_sig_key_desc"

struct dm_verity_sig {
	char *signature_key_desc;
	unsigned int sig_size;
	u8 *sig;
	bool passed;
};

#ifdef CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG

#define DM_VERITY_ROOT_HASH_VERIFICATION_OPTS 2

int verity_verify_root_hash(const struct dm_verity *v);
bool verity_verify_is_sig_opt_arg(const char *arg_name);

int verity_verify_sig_parse_opt_args(struct dm_arg_set *as, struct dm_verity *v,
				    unsigned int *argc);

void verity_verify_dtr(struct dm_verity *v);

#else

#define DM_VERITY_ROOT_HASH_VERIFICATION_OPTS 0

int verity_verify_root_hash(const struct dm_verity *v)
{
	return 0;
}

bool verity_verify_is_sig_opt_arg(const char *arg_name)
{
	return false;
}

int verity_verify_sig_parse_opt_args(struct dm_arg_set *as, struct dm_verity *v,
				    unsigned int *argc)
{
	return -EINVAL;
}

void verity_verify_dtr(struct dm_verity *v)
{
}

#endif /* CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG */
#endif /* DM_VERITY_SIG_VERIFICATION_H */
