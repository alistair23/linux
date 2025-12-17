// SPDX-License-Identifier: GPL-2.0

#include <crypto/hash.h>

unsigned int rust_helper_crypto_shash_descsize(struct crypto_shash *tfm)
{
	return crypto_shash_descsize(tfm);
}

unsigned int rust_helper_crypto_shash_digestsize(struct crypto_shash *tfm)
{
	return crypto_shash_digestsize(tfm);
}

void rust_helper_crypto_free_shash(struct crypto_shash *tfm)
{
	crypto_free_shash(tfm);
}
