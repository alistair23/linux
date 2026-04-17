/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/pci-tsm.yaml */
/* YNL-GEN uapi header */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#ifndef _UAPI_LINUX_PCI_TSM_NETLINK_H
#define _UAPI_LINUX_PCI_TSM_NETLINK_H

#define PCI_TSM_FAMILY_NAME	"pci-tsm"
#define PCI_TSM_FAMILY_VERSION	1

#define PCI_TSM_MAX_OBJECT_SIZE	16777216
#define PCI_TSM_MAX_NONCE_SIZE	256
#define PCI_TSM_MAX_OBJ_TYPE	4

/**
 * enum pci_tsm_evidence_type - PCI device security evidence objects
 * @PCI_TSM_EVIDENCE_TYPE_CERT0: SPDM certificate chain from device slot0
 * @PCI_TSM_EVIDENCE_TYPE_CERT1: SPDM certificate chain from device slot1
 * @PCI_TSM_EVIDENCE_TYPE_CERT2: SPDM certificate chain from device slot2
 * @PCI_TSM_EVIDENCE_TYPE_CERT3: SPDM certificate chain from device slot3
 * @PCI_TSM_EVIDENCE_TYPE_CERT4: SPDM certificate chain from device slot4
 * @PCI_TSM_EVIDENCE_TYPE_CERT5: SPDM certificate chain from device slot5
 * @PCI_TSM_EVIDENCE_TYPE_CERT6: SPDM certificate chain from device slot6
 * @PCI_TSM_EVIDENCE_TYPE_CERT7: SPDM certificate chain from device slot7
 * @PCI_TSM_EVIDENCE_TYPE_VCA: SPDM transcript of version, capabilities, and
 *   algorithms negotiation
 * @PCI_TSM_EVIDENCE_TYPE_MEASUREMENTS: SPDM GET_MEASUREMENTS response
 * @PCI_TSM_EVIDENCE_TYPE_REPORT: TDISP GET_DEVICE_INTERFACE_REPORT response
 */
enum pci_tsm_evidence_type {
	PCI_TSM_EVIDENCE_TYPE_CERT0,
	PCI_TSM_EVIDENCE_TYPE_CERT1,
	PCI_TSM_EVIDENCE_TYPE_CERT2,
	PCI_TSM_EVIDENCE_TYPE_CERT3,
	PCI_TSM_EVIDENCE_TYPE_CERT4,
	PCI_TSM_EVIDENCE_TYPE_CERT5,
	PCI_TSM_EVIDENCE_TYPE_CERT6,
	PCI_TSM_EVIDENCE_TYPE_CERT7,
	PCI_TSM_EVIDENCE_TYPE_VCA,
	PCI_TSM_EVIDENCE_TYPE_MEASUREMENTS,
	PCI_TSM_EVIDENCE_TYPE_REPORT,

	/* private: */
	__PCI_TSM_EVIDENCE_TYPE_MAX,
	PCI_TSM_EVIDENCE_TYPE_MAX = (__PCI_TSM_EVIDENCE_TYPE_MAX - 1)
};

/*
 * PCI device security evidence request flags
 */
enum pci_tsm_evidence_type_flag {
	PCI_TSM_EVIDENCE_TYPE_FLAG_CERT0 = 1,
	PCI_TSM_EVIDENCE_TYPE_FLAG_CERT1 = 2,
	PCI_TSM_EVIDENCE_TYPE_FLAG_CERT2 = 4,
	PCI_TSM_EVIDENCE_TYPE_FLAG_CERT3 = 8,
	PCI_TSM_EVIDENCE_TYPE_FLAG_CERT4 = 16,
	PCI_TSM_EVIDENCE_TYPE_FLAG_CERT5 = 32,
	PCI_TSM_EVIDENCE_TYPE_FLAG_CERT6 = 64,
	PCI_TSM_EVIDENCE_TYPE_FLAG_CERT7 = 128,
	PCI_TSM_EVIDENCE_TYPE_FLAG_VCA = 256,
	PCI_TSM_EVIDENCE_TYPE_FLAG_MEASUREMENTS = 512,
	PCI_TSM_EVIDENCE_TYPE_FLAG_REPORT = 1024,

	/* private: */
	PCI_TSM_EVIDENCE_TYPE_FLAG_MASK = 2047,
};

/**
 * enum pci_tsm_evidence_flag - Flags to control evidence retrieval
 * @PCI_TSM_EVIDENCE_FLAG_DIGEST: Request the TSM's private digest of an
 *   evidence object
 */
enum pci_tsm_evidence_flag {
	PCI_TSM_EVIDENCE_FLAG_DIGEST = 1,

	/* private: */
	PCI_TSM_EVIDENCE_FLAG_MASK = 1,
};

enum {
	PCI_TSM_A_EVIDENCE_OBJECT_TYPE = 1,
	PCI_TSM_A_EVIDENCE_OBJECT_TYPE_MASK,
	PCI_TSM_A_EVIDENCE_OBJECT_FLAGS,
	PCI_TSM_A_EVIDENCE_OBJECT_DEV_NAME,
	PCI_TSM_A_EVIDENCE_OBJECT_NONCE,
	PCI_TSM_A_EVIDENCE_OBJECT_VAL,

	__PCI_TSM_A_EVIDENCE_OBJECT_MAX,
	PCI_TSM_A_EVIDENCE_OBJECT_MAX = (__PCI_TSM_A_EVIDENCE_OBJECT_MAX - 1)
};

enum {
	PCI_TSM_CMD_EVIDENCE_READ = 1,

	__PCI_TSM_CMD_MAX,
	PCI_TSM_CMD_MAX = (__PCI_TSM_CMD_MAX - 1)
};

#endif /* _UAPI_LINUX_PCI_TSM_NETLINK_H */
