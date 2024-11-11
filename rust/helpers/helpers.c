// SPDX-License-Identifier: GPL-2.0
/*
 * Non-trivial C macros cannot be used in Rust. This file explicitly creates
 * functions ("helpers") that wrap those so that they can be called from Rust.
 *
 * Sorted alphabetically.
 */

#include "bug.c"
#include "build_assert.c"
#include "build_bug.c"
#include "cred.c"
#include "fs.c"
#include "jump_label.c"
#include "mutex.c"
#include "page.c"
#include "pid_namespace.c"
#include "refcount.c"
#include "security.c"
#include "slab.c"
#include "spinlock.c"
#include "task.c"
#include "vmalloc.c"
#include "wait.c"
#include "workqueue.c"
