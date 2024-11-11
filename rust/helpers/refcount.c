// SPDX-License-Identifier: GPL-2.0

#include <linux/refcount.h>

refcount_t rust_helper_REFCOUNT_INIT(int n)
{
	return (refcount_t)REFCOUNT_INIT(n);
}
