/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "ipe-policy.h"

#include <linux/types.h>

#ifndef IPE_PARSE_H
#define IPE_PARSE_H

struct ipe_policy *ipe_parse_policy(char *policy);

void ipe_free_policy(struct ipe_policy *pol);

#endif /* IPE_AUDIT_H */
