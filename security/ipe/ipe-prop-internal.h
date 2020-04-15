/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Microsoft Corporation. All rights reserved.
 */

#include "ipe-property.h"

#include <linux/types.h>

#ifndef IPE_PROPERTY_INTERNAL_H
#define IPE_PROPERTY_INTERNAL_H

#define IPE_PROPERTY_OPERATION	"op"
#define IPE_PROPERTY_DEFAULT	"DEFAULT"
#define IPE_PROPERTY_ACTION	"action"

#define IPE_OP_EXECUTE		"EXECUTE"
#define IPE_OP_FIRMWARE		"FIRMWARE"
#define IPE_OP_KEXEC_IMAGE	"KEXEC_IMAGE"
#define IPE_OP_KEXEC_INITRAMFS	"KEXEC_INITRAMFS"
#define IPE_OP_X509_CERTIFICATE	"X509_CERT"
#define IPE_OP_POLICY		"POLICY"
#define IPE_OP_KMODULE		"KMODULE"
#define IPE_OP_KERNEL_READ	"KERNEL_READ"

#define IPE_UNKNOWN		"UNKNOWN"

struct ipe_prop_reg {
	struct rb_node node;
	const struct ipe_property *prop;
};

extern struct rb_root ipe_registry_root;

const struct ipe_property *ipe_lookup_prop(const char *key);

#endif /* IPE_PROPERTY_INTERNAL_H */
