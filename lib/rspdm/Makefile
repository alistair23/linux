# SPDX-License-Identifier: GPL-2.0
#
# Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
# https://www.dmtf.org/dsp/DSP0274
#
# Copyright (C) 2024 Western Digital

obj-$(CONFIG_RSPDM) += spdm.o

spdm-y := lib.o
spdm-$(CONFIG_NET) += req-netlink.o netlink-autogen.o
