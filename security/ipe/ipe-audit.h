/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "ipe-engine.h"
#include "ipe-policy.h"

#ifndef IPE_AUDIT_H
#define IPE_AUDIT_H

void ipe_audit_mode(void);

void ipe_audit_match(const struct ipe_engine_ctx *ctx,
		     enum ipe_match match_type, enum ipe_action action,
		     const struct ipe_rule *rule);

#endif /* IPE_AUDIT_H */
