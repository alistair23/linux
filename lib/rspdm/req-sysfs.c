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

#define SPDM_NONCE_SZ 32 /* SPDM 1.0.0 table 20 */

int rust_authenticated_show(void *spdm_state, char *buf);

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

/* authenticated attribute */

static umode_t spdm_attrs_are_visible(struct kobject *kobj,
				      struct attribute *a, int n)
{
	struct device *dev = kobj_to_dev(kobj);
	void *spdm_state = dev_to_spdm_state(dev);

	if (IS_ERR_OR_NULL(spdm_state))
		return SYSFS_GROUP_INVISIBLE;

	return a->mode;
}

static ssize_t authenticated_store(struct device *dev,
				   struct device_attribute *attr,
				   const char *buf, size_t count)
{
	void *spdm_state = dev_to_spdm_state(dev);
	int rc;

	if (IS_ERR_OR_NULL(spdm_state))
		return PTR_ERR(spdm_state);

	if (sysfs_streq(buf, "re")) {
		rc = spdm_authenticate(spdm_state);
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

static struct attribute *spdm_attrs[] = {
	&dev_attr_authenticated.attr,
	NULL
};

const struct attribute_group spdm_attr_group = {
	.attrs = spdm_attrs,
	.is_visible = spdm_attrs_are_visible,
};

/* certificates attributes */

static umode_t spdm_certificates_are_visible(struct kobject *kobj,
					     const struct bin_attribute *a, int n)
{
	return SYSFS_GROUP_INVISIBLE;
}

static ssize_t spdm_cert_read(struct file *file, struct kobject *kobj,
			      struct bin_attribute *a, char *buf, loff_t off,
			      size_t count)
{
	return 0;
}

static BIN_ATTR(slot0, 0444, spdm_cert_read, NULL, 0xffff);
static BIN_ATTR(slot1, 0444, spdm_cert_read, NULL, 0xffff);
static BIN_ATTR(slot2, 0444, spdm_cert_read, NULL, 0xffff);
static BIN_ATTR(slot3, 0444, spdm_cert_read, NULL, 0xffff);
static BIN_ATTR(slot4, 0444, spdm_cert_read, NULL, 0xffff);
static BIN_ATTR(slot5, 0444, spdm_cert_read, NULL, 0xffff);
static BIN_ATTR(slot6, 0444, spdm_cert_read, NULL, 0xffff);
static BIN_ATTR(slot7, 0444, spdm_cert_read, NULL, 0xffff);

static struct bin_attribute *spdm_certificates_bin_attrs[] = {
	&bin_attr_slot0,
	&bin_attr_slot1,
	&bin_attr_slot2,
	&bin_attr_slot3,
	&bin_attr_slot4,
	&bin_attr_slot5,
	&bin_attr_slot6,
	&bin_attr_slot7,
	NULL
};

const struct attribute_group spdm_certificates_group = {
	.name = "certificates",
	.bin_attrs = spdm_certificates_bin_attrs,
	.is_bin_visible = spdm_certificates_are_visible,
};

/* signatures attributes */

static umode_t spdm_signatures_are_visible(struct kobject *kobj,
					   const struct bin_attribute *a, int n)
{
	struct device *dev = kobj_to_dev(kobj);
	void *spdm_state = dev_to_spdm_state(dev);

	if (IS_ERR_OR_NULL(spdm_state))
		return SYSFS_GROUP_INVISIBLE;

	return a->attr.mode;
}

static ssize_t next_requester_nonce_write(struct file *file,
					  struct kobject *kobj,
					  struct bin_attribute *attr,
					  char *buf, loff_t off, size_t count)
{
	return 0;
}
static BIN_ATTR_WO(next_requester_nonce, SPDM_NONCE_SZ);

static struct bin_attribute *spdm_signatures_bin_attrs[] = {
	&bin_attr_next_requester_nonce,
	NULL
};

const struct attribute_group spdm_signatures_group = {
	.name = "signatures",
	.bin_attrs = spdm_signatures_bin_attrs,
	.is_bin_visible = spdm_signatures_are_visible,
};
