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
#include "nuvo_range_lock.h"

//
// This code implements a range lock mechanism to protect
// volumes from simultaneous reads/writes from the same
// offset and length.
//

static struct nuvo_range_lock_entry range_lock_entries[MAX_SIMULT_IOS];
static struct nuvo_dlist            range_lock_freelist;
static struct nuvo_mutex            range_lock_freelist_mutex;

/**
 * Initialize Range Lock Free List
 * Once per system.
 */
int
nuvo_range_lock_freelist_init()
{
    int ret;

    ret = nuvo_mutex_init(&range_lock_freelist_mutex);
    if (ret != 0)
    {
        return (ret);
    }

    nuvo_dlist_init(&range_lock_freelist);

    for (int i = 0; i < MAX_SIMULT_IOS; i++)
    {
        nuvo_dlnode_init(&range_lock_entries[i].node);
        nuvo_dlist_insert_tail(&range_lock_freelist, &range_lock_entries[i].node);
    }
    return (0);
}

void
nuvo_range_lock_freelist_destroy()
{
    // Assert the freelist has all entries
    nuvo_mutex_destroy(&range_lock_freelist_mutex);
}

/**
 * Initialize a range lock
 * Once per range lock (lun)
 */
int
nuvo_range_lock_init(struct nuvo_range_lock *rl)
{
    rl->initialized = 1;
    nuvo_dlist_init(&rl->lock_list);
    return (nuvo_mutex_init(&rl->lock_mutex));
}

/*
 * Destroy a range lock
 *
 * Don't call this if still active.
 */
void
nuvo_range_lock_destroy(struct nuvo_range_lock *rl)
{
    // Not outstanding I/O
    NUVO_ASSERT(nuvo_dlist_get_head(&rl->lock_list) == NULL);

    nuvo_mutex_destroy(&rl->lock_mutex);
}

/**
 * Get a new range lock entry internal use only
 */
static struct nuvo_range_lock_entry *
range_lock_entry_alloc()
{
    struct nuvo_range_lock_entry *new;

    nuvo_mutex_lock(&range_lock_freelist_mutex);
    new = nuvo_dlist_remove_head_object(&range_lock_freelist, struct nuvo_range_lock_entry, node);
    nuvo_mutex_unlock(&range_lock_freelist_mutex);

    return (new);
}

/**
 * Free a range lock entry
 * Internal use only
 */
static void
range_lock_entry_free(struct nuvo_range_lock_entry *entry)
{
    NUVO_ASSERT(entry->waiters == 0);
    nuvo_mutex_lock(&range_lock_freelist_mutex);
    nuvo_dlist_insert_head(&range_lock_freelist, &entry->node);
    nuvo_mutex_unlock(&range_lock_freelist_mutex);
}

/**
 * Acquires a lock on a range. Will block until locked.
 *
 * Returns a handle to the lock so it can be released
 * later.
 */
void *
nuvo_lock_range_wait(struct nuvo_range_lock *rl, off_t start, off_t len)
{
    struct nuvo_range_lock_entry *this, *new;
    int cleared = 0;

    NUVO_ASSERT(rl->initialized == 1);

    new = range_lock_entry_alloc(rl);
    NUVO_ASSERT(new);
    NUVO_ASSERT(len > 0);
    new->start = start;
    new->end = start + len - 1;

    nuvo_mutex_lock(&rl->lock_mutex);

    while (!cleared)
    {
        this = nuvo_dlist_get_head_object(&rl->lock_list, struct nuvo_range_lock_entry, node);
        while (this && (new->start > this->end))
        {
            this = nuvo_dlist_get_next_object(&rl->lock_list, this, struct nuvo_range_lock_entry, node);
        }

        if (this == NULL)
        {
            nuvo_dlist_insert_tail(&rl->lock_list, &new->node);
            cleared = 1;
        }
        else if (new->end < this->start)
        {
            nuvo_dlist_insert_before(&this->node, &new->node);
            cleared = 1;
        }
        else
        {
            // conflicting lock
            this->waiters++;
            nuvo_cond_wait(&this->waiters_cv, &rl->lock_mutex);
            if (--this->waiters == 0)   // I'm the last waiter
            {
                range_lock_entry_free(this);
            }
        }
    }
    nuvo_mutex_unlock(&rl->lock_mutex);

    return ((void *)new);
}

/**
 * Release the range lock associated with this handle.
 *
 * Will panic if bad values are given.
 */

void
nuvo_unlock_range(struct nuvo_range_lock *rl, void *handle)
{
    struct nuvo_range_lock_entry *stale;

    stale = (struct nuvo_range_lock_entry *)handle;

    nuvo_mutex_lock(&rl->lock_mutex);
    nuvo_dlist_remove(&stale->node);

    if (stale->waiters == 0)
    {
        nuvo_mutex_unlock(&rl->lock_mutex);
        range_lock_entry_free(stale);
    }
    else
    {
        // Waiters are still hanging on this entry
        // It will be freed when the last waiter
        // is awakened.
        nuvo_cond_broadcast(&stale->waiters_cv);
        nuvo_mutex_unlock(&rl->lock_mutex);
    }
}
