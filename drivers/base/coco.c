// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2026 Intel Corporation */
#include <linux/device.h>
#include <linux/lockdep.h>
#include "base.h"

/*
 * Confidential devices implement encrypted + integrity protected MMIO and have
 * the ability to issue DMA to encrypted + integrity protected System RAM
 * (private memory). The device_cc_*() helpers aid buses in setting the
 * acceptance state and the DMA mapping subsystem augmenting behavior in the
 * presence of accepted devices.
 */

/**
 * device_cc_accept(): Mark a device as able to access private memory
 * @dev: device to accept
 *
 * Confidential bus drivers use this helper to accept devices. For example, PCI
 * has a sysfs ABI to accept devices after relying party attestation.
 *
 * Given that moving a device into confidential / private operation implicates
 * changes to MMIO mapping attributes and DMA mappings, the transition must be
 * done while the device is idle (driver detached).
 */
int device_cc_accept(struct device *dev)
{
	lockdep_assert_held(&dev->mutex);

	if (dev->driver)
		return -EBUSY;
	dev->p->cc_accepted = 1;

	return 0;
}

int device_cc_reject(struct device *dev)
{
	lockdep_assert_held(&dev->mutex);

	if (dev->driver)
		return -EBUSY;
	dev->p->cc_accepted = 0;

	return 0;
}

/**
 * device_cc_accepted(): Fetch the device's ability to access private memory
 * @dev: device to check
 *
 * Mechanisms like swiotlb and dma_alloc() need to augment their behavior in the
 * presence of accepted devices.
 */
bool device_cc_accepted(struct device *dev)
{
	return dev->p->cc_accepted;
}
