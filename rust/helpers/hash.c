// SPDX-License-Identifier: GPL-2.0

#include <crypto/hash.h>

__rust_helper unsigned int rust_helper_crypto_shash_descsize(struct crypto_shash *tfm)
{
	return crypto_shash_descsize(tfm);
}

__rust_helper unsigned int rust_helper_crypto_shash_digestsize(struct crypto_shash *tfm)
{
	return crypto_shash_digestsize(tfm);
}

__rust_helper void rust_helper_crypto_free_shash(struct crypto_shash *tfm)
{
	crypto_free_shash(tfm);
}
