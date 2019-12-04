/* Copyright 2019 Tad Lebeck
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once
#include "nuvo_lock.h"
#include "nuvo_list.h"

#define MAX_SIMULT_IOS    256

struct nuvo_range_lock_entry {
    int                deny;
    off_t              start, end;
    struct nuvo_dlnode node;
    int                waiters;
    nuvo_cond_t        waiters_cv;
};

struct nuvo_range_lock {
    int               initialized;
    struct nuvo_dlist lock_list;
    nuvo_mutex_t      lock_mutex;
};

/**
 * Initialize the range lock free list
 * once per system.
 */
int nuvo_range_lock_freelist_init();

/**
 * Destroy the range_lock_freelist
 * once per system.
 */
void nuvo_range_lock_freelist_destroy();

/**
 * Initialize a range lock
 *
 * Once per range lock (per lun)
 */
int nuvo_range_lock_init(struct nuvo_range_lock *rl);

/*
 * Destroy a range lock
 *
 * Don't call this if still active.
 */
void nuvo_range_lock_destroy(struct nuvo_range_lock *rl);

/**
 * Acquires a lock on a range. Will block until locked.
 *
 * Returns a handle to the lock so it can be released
 * later.
 */
void *nuvo_lock_range_wait(struct nuvo_range_lock *rl, off_t start, off_t len);

/**
 * Release the range lock associated with this handle.
 *
 * Will panic if bad values are given.
 */
void nuvo_unlock_range(struct nuvo_range_lock *rl, void *handle);
