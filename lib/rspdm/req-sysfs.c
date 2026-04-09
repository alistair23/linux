// SPDX-License-Identifier: GPL-2.0

/*
 * Rust implementation of the DMTF Security Protocol and Data Model (SPDM)
 * https://www.dmtf.org/dsp/DSP0274
 *
 * Requester role: sysfs interface
 *
 * Copyright (C) 2023-24 Intel Corporation
 * Copyright (C) 2024 Western Digital
 */

#include <linux/pci.h>
#include "spdm.h"

int rust_authenticated_show(void *spdm_state, char *buf);
ssize_t rust_nonce_store(void *spdm_state, const char *buf, loff_t off, size_t count);
ssize_t rust_nonce_show(void *spdm_state, char *buf, loff_t off, size_t count);

/**
 * dev_to_spdm_state() - Retrieve SPDM session state for given device
 *
 * @dev: Responder device
 *
 * Returns a pointer to the device's SPDM session state,
 *	   %NULL if the device doesn't have one or
 *	   %ERR_PTR if it couldn't be determined whether SPDM is supported.
 *
 * In the %ERR_PTR case, attributes are visible but return an error on access.
 * This prevents downgrade attacks where an attacker disturbs memory allocation
 * or communication with the device in order to create the appearance that SPDM
 * is unsupported.  E.g. with PCI devices, the attacker may foil CMA or DOE
 * initialization by simply hogging memory.
 */
static void *dev_to_spdm_state(struct device *dev)
{
	if (dev_is_pci(dev))
		return pci_dev_to_spdm_state(to_pci_dev(dev));

	/* Insert mappers for further bus types here. */

	return NULL;
}

static umode_t spdm_attrs_are_visible(struct kobject *kobj,
				      struct attribute *a, int n)
{
	struct device *dev = kobj_to_dev(kobj);
	void *spdm_state = dev_to_spdm_state(dev);

	if (IS_ERR_OR_NULL(spdm_state))
		return SYSFS_GROUP_INVISIBLE;

	return a->mode;
}

static umode_t spdm_bin_attrs_are_visible(struct kobject *kobj,
					  const struct bin_attribute *a, int n)
{
	struct device *dev = kobj_to_dev(kobj);
	struct spdm_state *spdm_state = dev_to_spdm_state(dev);

	if (IS_ERR_OR_NULL(spdm_state))
		return SYSFS_GROUP_INVISIBLE;

	return a->attr.mode;
}

/* authenticated attribute */

static ssize_t authenticated_store(struct device *dev,
				   struct device_attribute *attr,
				   const char *buf, size_t count)
{
	void *spdm_state = dev_to_spdm_state(dev);
	int rc;

	if (IS_ERR_OR_NULL(spdm_state))
		return PTR_ERR(spdm_state);

	if (sysfs_streq(buf, "re")) {
		rc = spdm_chall(spdm_state);
		if (rc)
			return rc;
	} else {
		return -EINVAL;
	}

	return count;
}

static ssize_t authenticated_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	void *spdm_state = dev_to_spdm_state(dev);

	if (IS_ERR_OR_NULL(spdm_state))
		return PTR_ERR(spdm_state);

	return rust_authenticated_show(spdm_state, buf);
}
static DEVICE_ATTR_RW(authenticated);

/* nonce attribute */

static ssize_t nonce_write(struct file *filp, struct kobject *kobj,
			   const struct bin_attribute *attr,
			   char *buf, loff_t off, size_t count)
{
	struct device *dev = kobj_to_dev(kobj);
	void *spdm_state = dev_to_spdm_state(dev);

	if (IS_ERR_OR_NULL(spdm_state))
		return PTR_ERR(spdm_state);

	return rust_nonce_store(spdm_state, buf, off, count);
}

static ssize_t nonce_read(struct file *filp, struct kobject *kobj,
			  const struct bin_attribute *attr,
			  char *buf, loff_t off, size_t count)
{
	struct device *dev = kobj_to_dev(kobj);
	void *spdm_state = dev_to_spdm_state(dev);

	if (IS_ERR_OR_NULL(spdm_state))
		return PTR_ERR(spdm_state);

	return rust_nonce_show(spdm_state, buf, off, count);
}
static BIN_ATTR_RW(nonce, 32);

static struct attribute *spdm_attrs[] = {
	&dev_attr_authenticated.attr,
	NULL
};

static const struct bin_attribute *spdm_bin_attrs[] = {
	&bin_attr_nonce,
	NULL
};

const struct attribute_group spdm_attr_group = {
	.attrs = spdm_attrs,
	.bin_attrs = spdm_bin_attrs,
	.is_visible = spdm_attrs_are_visible,
	.is_bin_visible = spdm_bin_attrs_are_visible,
};
