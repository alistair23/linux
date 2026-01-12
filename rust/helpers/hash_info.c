// SPDX-License-Identifier: GPL-2.0

#include <crypto/hash_info.h>

__rust_helper int rust_helper_get_hash_digest_size(uint32_t offset)
{
	return hash_digest_size[offset];
}
