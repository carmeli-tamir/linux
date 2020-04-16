/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "ipe-prop-internal.h"
#include "ipe-engine.h"
#include "ipe-policy.h"

#ifndef IPE_AUDIT_H
#define IPE_AUDIT_H

void ipe_audit_mode(void);

void ipe_audit_match(const struct ipe_engine_ctx *ctx,
		     enum ipe_match match_type, enum ipe_action action,
		     const struct ipe_rule *rule);

void ipe_audit_policy_load(const struct ipe_policy *pol, const uint8_t *raw,
			   size_t raw_size, struct crypto_shash *tfm);

void ipe_audit_policy_activation(const struct ipe_policy *pol);

void ipe_audit_unset_remap(enum ipe_op op);

#endif /* IPE_AUDIT_H */
