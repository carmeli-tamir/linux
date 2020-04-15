/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include <linux/types.h>

#ifndef IPE_PROP_ENTRY_H
#define IPE_PROP_ENTRY_H

#ifndef CONFIG_IPE_BOOT_PROP
static inline int __init ipe_init_bootv(void)
{
	return 0;
}
#else
int __init ipe_init_bootv(void);
#endif /* CONFIG_IPE_BOOT_PROP */

#endif /* IPE_PROP_ENTRY_H */
