// SPDX-License-Identifier: GPL-2.0
/*
 * Component Measurement and Authentication (CMA-SPDM, PCIe r6.2 sec 6.31)
 *
 * Copyright (C) 2021 Huawei
 *     Jonathan Cameron <Jonathan.Cameron@huawei.com>
 *
 * Copyright (C) 2022-24 Intel Corporation
 */

#define dev_fmt(fmt) "CMA: " fmt

#include <linux/pci.h>
#include <linux/pci-doe.h>
#include <linux/spdm.h>

#include "pci.h"

static ssize_t pci_doe_transport(void *priv, struct device *dev,
				 const void *request, size_t request_sz,
				 void *response, size_t response_sz)
{
	struct pci_doe_mb *doe = priv;
	ssize_t rc;

	rc = pci_doe(doe, PCI_VENDOR_ID_PCI_SIG, PCI_DOE_FEATURE_CMA,
		     request, request_sz, response, response_sz);

	return rc;
}

void pci_cma_init(struct pci_dev *pdev)
{
	struct pci_doe_mb *doe;

	if (!pci_is_pcie(pdev))
		return;

	doe = pci_find_doe_mailbox(pdev, PCI_VENDOR_ID_PCI_SIG,
				   PCI_DOE_FEATURE_CMA);
	if (!doe)
		return;

	pdev->spdm_state = spdm_create(&pdev->dev, pci_doe_transport, doe,
				       PCI_DOE_MAX_PAYLOAD,
				       NULL);
	if (!pdev->spdm_state)
		return;

	/*
	 * Keep spdm_state allocated even if initial authentication fails
	 * to allow for provisioning of certificates and reauthentication.
	 */
	spdm_authenticate(pdev->spdm_state);
}

void pci_cma_destroy(struct pci_dev *pdev)
{
	if (!pdev->spdm_state)
		return;

	spdm_destroy(pdev->spdm_state);
}
