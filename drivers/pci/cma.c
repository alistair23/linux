// SPDX-License-Identifier: GPL-2.0
/*
 * Component Measurement and Authentication (CMA-SPDM, PCIe r6.2 sec 6.31)
 *
 * Copyright (C) 2021 Huawei
 *     Jonathan Cameron <Jonathan.Cameron@huawei.com>
 * Copyright (C) 2022-24 Intel Corporation
 * Copyright (C) 2026 Western Digital
 * 	Alistair Francis <alistair.francis@wdc.com>
 */

#define dev_fmt(fmt) "CMA: " fmt

#include <linux/err.h>
#include <linux/pci.h>
#include <linux/pci-doe.h>
#include <linux/pci-tsm.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>
#include <linux/spdm.h>
#include <linux/tsm.h>

#include "pci.h"

static int pci_doe_transport(void *priv, struct device *dev,
			     const void *request, size_t request_sz,
			     void *response, size_t response_sz)
{
	struct pci_doe_mb *doe = priv;

	return pci_doe(doe, PCI_VENDOR_ID_PCI_SIG, PCI_DOE_FEATURE_CMA,
		       request, request_sz, response, response_sz);
}

struct pci_cma_tsm {
	struct pci_tsm_host host;
	struct spdm_state *spdm;
};

static struct pci_cma_tsm *cma_tsm_from_tsm(struct pci_tsm *tsm)
{
	struct pci_tsm_host *host = container_of(tsm, struct pci_tsm_host, base_tsm);

	return container_of(host, struct pci_cma_tsm, host);
}

static struct pci_tsm *pci_cma_tsm_probe(struct tsm_dev *tsm_dev,
					 struct pci_dev *pdev)
{
	struct pci_cma_tsm *cma;
	int rc;

	cma = kzalloc(sizeof(*cma), GFP_KERNEL);
	if (!cma)
		return NULL;

	rc = pci_tsm_host_constructor(pdev, &cma->host, tsm_dev);
	if (rc) {
		kfree(cma);
		return NULL;
	}

	cma->spdm = spdm_create(&pdev->dev, pci_doe_transport, cma->host.doe_mb,
				PCI_DOE_MAX_PAYLOAD, NULL);
	if (!cma->spdm) {
		pci_tsm_host_destructor(&cma->host);
		kfree(cma);
		return NULL;
	}

	return &cma->host.base_tsm;
}

static void pci_cma_tsm_remove(struct pci_tsm *tsm)
{
	struct pci_cma_tsm *cma = cma_tsm_from_tsm(tsm);

	spdm_destroy(cma->spdm);
	pci_tsm_host_destructor(&cma->host);
	kfree(cma);
}

static int pci_cma_tsm_connect(struct pci_dev *pdev)
{
	struct pci_cma_tsm *cma = cma_tsm_from_tsm(pdev->tsm);
	int rc;

	/*
	 * The DOE mailbox lives in the device's config space, so the
	 * device must be runtime-resumed for the duration of the SPDM
	 * exchange.
	 */
	rc = pm_runtime_get_sync(&pdev->dev);
	if (rc < 0) {
		pm_runtime_put_noidle(&pdev->dev);
		return rc;
	}

	rc = spdm_authenticate(cma->spdm);

	pm_runtime_put_sync(&pdev->dev);
	return rc;
}

static void pci_cma_tsm_disconnect(struct pci_dev *pdev)
{
	/* SPDM state is freed in pci_cma_tsm_remove() */
}

static struct pci_tdi *pci_cma_tsm_bind(struct pci_dev *pdev,
					struct kvm *kvm, u32 tdi_id)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static void pci_cma_tsm_unbind(struct pci_tdi *tdi)
{
}

static ssize_t pci_cma_tsm_guest_req(struct pci_tdi *tdi,
				     enum pci_tsm_req_scope scope,
				     sockptr_t req_in, size_t in_len,
				     sockptr_t req_out, size_t out_len,
				     u64 *tsm_code)
{
	return -EOPNOTSUPP;
}

static const struct pci_tsm_ops pci_cma_tsm_ops = {
	.link_ops = {
		.probe		= pci_cma_tsm_probe,
		.remove		= pci_cma_tsm_remove,
		.connect	= pci_cma_tsm_connect,
		.disconnect	= pci_cma_tsm_disconnect,
		.bind		= pci_cma_tsm_bind,
		.unbind		= pci_cma_tsm_unbind,
		.guest_req	= pci_cma_tsm_guest_req,
	},
};

static struct tsm_dev *pci_cma_tsm_dev;

static int __init pci_cma_tsm_init(void)
{
	struct tsm_dev *tsm_dev;

	tsm_dev = tsm_register(NULL, (struct pci_tsm_ops *)&pci_cma_tsm_ops);
	if (IS_ERR(tsm_dev))
		return PTR_ERR(tsm_dev);

	pci_cma_tsm_dev = tsm_dev;
	return 0;
}
late_initcall(pci_cma_tsm_init);
