/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */
#include <linux/types.h>

#include "ipe-policy.h"

#ifndef IPE_SECFS_H
#define IPE_SECFS_H

extern struct mutex ipe_policy_lock;

int ipe_set_active_policy(const char *id, size_t id_len);

#endif /* IPE_SECFS_H */
