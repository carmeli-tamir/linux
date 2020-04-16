# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) Microsoft Corporation. All rights reserved.
#
# Makefile for building the IPE module as part of the kernel tree.
#

quiet_cmd_polgen  = IPE_POL $(patsubst "%",%,$(2))
      cmd_polgen  = scripts/ipe/polgen/polgen security/ipe/ipe-bp.c $(2)

$(eval $(call config_filename,SECURITY_IPE_BOOT_POLICY))

targets += ipe-bp.c
$(obj)/ipe-bp.c: scripts/ipe/polgen/polgen $(SECURITY_IPE_BOOT_POLICY_FILENAME) FORCE
	$(call if_changed,polgen,$(SECURITY_IPE_BOOT_POLICY_FILENAME))

obj-$(CONFIG_SECURITY_IPE) += \
	ipe.o \
	ipe-audit.o \
	ipe-bp.o \
	ipe-engine.o \
	ipe-parse.o \
	ipe-policy.o \
	ipe-property.o \
	ipe-hooks.o \
	ipe-secfs.o \
	ipe-sysfs.o \
	ipe-blobs.o \

clean-files := ipe-bp.c

obj-$(CONFIG_IPE_BOOT_PROP) += ipe-pin.o

obj-$(CONFIG_SECURITY_IPE) += properties/
