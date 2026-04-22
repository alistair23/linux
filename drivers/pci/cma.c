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

#include <crypto/hash_info.h>
#include <keys/x509-parser.h>
#include <linux/asn1_decoder.h>
#include <linux/oid_registry.h>
#include <linux/pci.h>
#include <linux/pci-doe.h>
#include <linux/pci-tsm.h>
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

	len = snprintf(name, CMA_NAME_MAX,
		       "Vendor=%04hx:Device=%04hx:CC=%06x:REV=%02hhx",
		       pdev->vendor, pdev->device, pdev->class, pdev->revision);

	if (pdev->hdr_type == PCI_HEADER_TYPE_NORMAL)
		len += snprintf(name + len, CMA_NAME_MAX - len,
				":SSVID=%04hx:SSID=%04hx",
				pdev->subsystem_vendor, pdev->subsystem_device);

	serial = pci_get_dsn(pdev);
	if (serial)
		len += snprintf(name + len, CMA_NAME_MAX - len,
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

/**
 * struct pci_cma_tsm - CMA SPDM TSM driver context
 * @pf0: base pci_tsm_pf0 context (must be first)
 * @spdm: SPDM session for this device
 */
struct pci_cma_tsm {
	struct pci_tsm_pf0 pf0;
	struct spdm_state *spdm;
};

static struct pci_cma_tsm *cma_tsm_from_tsm(struct pci_tsm *tsm)
{
	struct pci_tsm_pf0 *pf0 = container_of(tsm, struct pci_tsm_pf0, base_tsm);

	return container_of(pf0, struct pci_cma_tsm, pf0);
}

/**
 * struct pci_cma_devsec - CMA SPDM devsec TSM context
 * @devsec: base pci_tsm_devsec context (must be first)
 * @spdm: SPDM session for this device
 */
struct pci_cma_devsec {
	struct pci_tsm_devsec devsec;
	struct spdm_state *spdm;
};

static struct pci_cma_devsec *cma_devsec_from_tsm(struct pci_tsm *tsm)
{
	struct pci_tsm_devsec *devsec =
		container_of(tsm, struct pci_tsm_devsec, base_tsm);

	return container_of(devsec, struct pci_cma_devsec, devsec);
}

static void cma_tsm_free_evidence_objects(struct pci_tsm_evidence *evidence)
{
	int i;

	for (i = 0; i <= PCI_TSM_EVIDENCE_TYPE_MAX; i++) {
		kfree(evidence->obj[i].data);
		evidence->obj[i].data = NULL;
		evidence->obj[i].len = 0;
	}
}

static int cma_tsm_populate_evidence(struct spdm_state *spdm,
				      struct pci_tsm_evidence *evidence)
{
	const u8 *data;
	size_t len;
	int slot, rc = 0;

	down_write(&evidence->lock);
	cma_tsm_free_evidence_objects(evidence);

	for (slot = 0; slot < 8; slot++) {
		spdm_get_cert(spdm, slot, &data, &len);
		if (!data || !len)
			continue;
		evidence->obj[PCI_TSM_EVIDENCE_TYPE_CERT0 + slot].data =
			kmemdup(data, len, GFP_KERNEL);
		if (!evidence->obj[PCI_TSM_EVIDENCE_TYPE_CERT0 + slot].data) {
			rc = -ENOMEM;
			goto out_free;
		}
		evidence->obj[PCI_TSM_EVIDENCE_TYPE_CERT0 + slot].len = len;
	}

	spdm_get_transcript(spdm, &data, &len);
	if (data && len) {
		evidence->obj[PCI_TSM_EVIDENCE_TYPE_VCA].data =
			kmemdup(data, len, GFP_KERNEL);
		if (!evidence->obj[PCI_TSM_EVIDENCE_TYPE_VCA].data) {
			rc = -ENOMEM;
			goto out_free;
		}
		evidence->obj[PCI_TSM_EVIDENCE_TYPE_VCA].len = len;
	}

	evidence->generation++;
	goto out_unlock;

out_free:
	cma_tsm_free_evidence_objects(evidence);
out_unlock:
	up_write(&evidence->lock);
	return rc;
}

static struct pci_tsm *pci_cma_tsm_probe(struct tsm_dev *tsm_dev,
				      struct pci_dev *pdev)
{
	struct pci_doe_mb *doe;
	struct pci_cma_tsm *cma;

	doe = pci_find_doe_mailbox(pdev, PCI_VENDOR_ID_PCI_SIG,
				   PCI_DOE_FEATURE_CMA);
	if (!doe)
		return NULL;

	cma = kzalloc(sizeof(*cma), GFP_KERNEL);
	if (!cma)
		return NULL;

	mutex_init(&cma->pf0.lock);
	cma->pf0.doe_mb = doe;
	cma->pf0.base_tsm.pdev = pdev;
	cma->pf0.base_tsm.dsm_dev = pdev;
	cma->pf0.base_tsm.tsm_dev = tsm_dev;

	cma->spdm = spdm_create(&pdev->dev, pci_doe_transport, doe,
				PCI_DOE_MAX_PAYLOAD, pci_cma_validate);
	if (!cma->spdm) {
		mutex_destroy(&cma->pf0.lock);
		kfree(cma);
		return NULL;
	}

	pci_tsm_init_evidence(&cma->pf0.base_tsm.evidence, 0, HASH_ALGO_SHA256);

	return &cma->pf0.base_tsm;
}

static void pci_cma_tsm_remove(struct pci_tsm *tsm)
{
	struct pci_cma_tsm *cma = cma_tsm_from_tsm(tsm);

	down_write(&tsm->evidence.lock);
	cma_tsm_free_evidence_objects(&tsm->evidence);
	up_write(&tsm->evidence.lock);

	spdm_destroy(cma->spdm);
	mutex_destroy(&cma->pf0.lock);
	kfree(cma);
}

static int pci_cma_tsm_connect(struct pci_dev *pdev)
{
	struct pci_cma_tsm *cma = cma_tsm_from_tsm(pdev->tsm);
	int rc;

	rc = spdm_authenticate(cma->spdm);
	if (rc)
		return rc;

	return cma_tsm_populate_evidence(cma->spdm, &pdev->tsm->evidence);
}

static void pci_cma_tsm_disconnect(struct pci_dev *pdev)
{
	/* Evidence and SPDM state are freed in pci_cma_tsm_remove() */
}

static int pci_cma_tsm_refresh(struct pci_tsm *tsm,
				enum pci_tsm_evidence_type type,
				unsigned long flags, void *nonce,
				size_t nonce_len)
{
	/*
	 * Distinguish link (dsm_dev == pdev, self-DSM) from devsec
	 * (dsm_dev == NULL) contexts to retrieve the right spdm pointer.
	 */
	struct spdm_state *spdm = tsm->dsm_dev
		? cma_tsm_from_tsm(tsm)->spdm
		: cma_devsec_from_tsm(tsm)->spdm;
	int rc;

	if (nonce) {
		rc = spdm_nonce_store(spdm, nonce, 0, nonce_len);
		if (rc)
			return rc;
	}

	rc = spdm_authenticate(spdm);
	if (rc)
		return rc;

	return cma_tsm_populate_evidence(spdm, &tsm->evidence);
}

static const struct pci_tsm_ops pci_cma_tsm_ops = {
	.link_ops = {
		.probe		= pci_cma_tsm_probe,
		.remove		= pci_cma_tsm_remove,
		.connect	= pci_cma_tsm_connect,
		.disconnect	= pci_cma_tsm_disconnect,
	},
	.refresh_evidence	= pci_cma_tsm_refresh,
};

static struct tsm_dev *pci_cma_tsm_dev;

static int __init pci_cma_tsm_init(void)
{
	struct tsm_dev *tsm_dev;

	/* tsm_register() registers with pci_tsm_register() internally */
	tsm_dev = tsm_register(NULL, (struct pci_tsm_ops *)&pci_cma_tsm_ops);
	if (IS_ERR(tsm_dev))
		return PTR_ERR(tsm_dev);

	pci_cma_tsm_dev = tsm_dev;
	return 0;
}
late_initcall(pci_cma_tsm_init);
