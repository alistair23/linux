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
#include <keys/x509-parser.h>
#include <linux/asn1_decoder.h>
#include <linux/oid_registry.h>
#include <linux/pci.h>
#include <linux/pci-doe.h>
#include <linux/pci-tsm.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>
#include <linux/spdm.h>
#include <linux/tsm.h>

#include "cma.asn1.h"
#include "pci.h"

/*
 * The spdm_requester.c library calls pci_cma_validate() to check requirements
 * for Leaf Certificates per PCIe r6.1 sec 6.31.3.
 *
 * pci_cma_validate() parses the Subject Alternative Name using the ASN.1
 * module cma.asn1, which calls pci_cma_note_oid() and pci_cma_note_san()
 * to compare an OtherName against the expected name.
 *
 * The expected name is constructed beforehand by pci_cma_construct_san().
 *
 * PCIe r6.2 drops the Subject Alternative Name spec language, even though
 * it continues to require "the leaf certificate to include the information
 * typically used by system software for device driver binding".  Use the
 * Subject Alternative Name per PCIe r6.1 for lack of a replacement and
 * because it is the de facto standard among existing products.
 */
#define CMA_NAME_MAX sizeof("Vendor=1234:Device=1234:CC=123456:"	  \
			    "REV=12:SSVID=1234:SSID=1234:1234567890123456")

struct pci_cma_x509_context {
	struct pci_dev *pdev;
	u8 slot;
	enum OID last_oid;
	char expected_name[CMA_NAME_MAX];
	unsigned int expected_len;
	unsigned int found:1;
};

int pci_cma_note_oid(void *context, size_t hdrlen, unsigned char tag,
		     const void *value, size_t vlen)
{
	struct pci_cma_x509_context *ctx = context;

	ctx->last_oid = look_up_OID(value, vlen);

	return 0;
}

int pci_cma_note_san(void *context, size_t hdrlen, unsigned char tag,
		     const void *value, size_t vlen)
{
	struct pci_cma_x509_context *ctx = context;

	/* These aren't the drOIDs we're looking for. */
	if (ctx->last_oid != OID_CMA)
		return 0;

	if (tag != ASN1_UTF8STR ||
	    vlen != ctx->expected_len ||
	    memcmp(value, ctx->expected_name, vlen) != 0) {
		pci_err(ctx->pdev, "Leaf certificate of slot %u "
			"has invalid Subject Alternative Name\n", ctx->slot);
		return -EINVAL;
	}

	ctx->found = true;

	return 0;
}

static unsigned int pci_cma_construct_san(struct pci_dev *pdev, char *name)
{
	unsigned int len;
	u64 serial;

	len = scnprintf(name, CMA_NAME_MAX,
			"Vendor=%04hx:Device=%04hx:CC=%06x:REV=%02hhx",
			pdev->vendor, pdev->device, pdev->class, pdev->revision);

	if (pdev->hdr_type == PCI_HEADER_TYPE_NORMAL)
		len += scnprintf(name + len, CMA_NAME_MAX - len,
				 ":SSVID=%04hx:SSID=%04hx",
				 pdev->subsystem_vendor, pdev->subsystem_device);

	serial = pci_get_dsn(pdev);
	if (serial)
		len += scnprintf(name + len, CMA_NAME_MAX - len,
				 ":%016llx", serial);

	return len;
}

static int pci_cma_validate(struct device *dev, u8 slot,
			    struct x509_certificate *leaf_cert)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct pci_cma_x509_context ctx;
	int ret;

	if (!leaf_cert->raw_san) {
		pci_err(pdev, "Leaf certificate of slot %u "
			"has no Subject Alternative Name\n", slot);
		return -EINVAL;
	}

	ctx.pdev = pdev;
	ctx.slot = slot;
	ctx.found = false;
	ctx.expected_len = pci_cma_construct_san(pdev, ctx.expected_name);

	ret = asn1_ber_decoder(&cma_decoder, &ctx, leaf_cert->raw_san,
			       leaf_cert->raw_san_size);
	if (ret == -EBADMSG || ret == -EMSGSIZE)
		pci_err(pdev, "Leaf certificate of slot %u "
			"has malformed Subject Alternative Name\n", slot);
	if (ret < 0)
		return ret;

	if (!ctx.found) {
		pci_err(pdev, "Leaf certificate of slot %u "
			"has no OtherName with CMA OID\n", slot);
		return -EINVAL;
	}

	return 0;
}

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
				PCI_DOE_MAX_PAYLOAD, pci_cma_validate);
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
