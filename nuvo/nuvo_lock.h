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
#include <stdint.h>
#include <pthread.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <stdlib.h>

#include "nuvo.h"

#define NUVO_MUTEX_LEAK_DETECTION    0

struct nuvo_mutex {
    pthread_mutex_t mutex;

#ifndef NDEBUG
    pthread_t       owner;
    int             line_no;
    const char     *file_name;
#endif
#if NUVO_MUTEX_LEAK_DETECTION
    void           *leak;
#endif
};

struct nuvo_rw_lock {
    pthread_rwlock_t rw_lock;

#if NUVO_MUTEX_LEAK_DETECTION
    void            *leak;
#endif
};

typedef struct nuvo_mutex     nuvo_mutex_t;
typedef pthread_cond_t        nuvo_cond_t;
typedef struct nuvo_rw_lock   nuvo_rwlock_t;

/**
 * \brief Initializes a nuvo_mutex_t.
 *
 * This function initializes a nuvo_mutex_t.  All nuvo_mutex_t objects must
 * have this function invoked on them before use.
 *
 * \param m A pointer to the nuvo_mutex_t object.
 * \returns Zero or a positive integer on success.  On failure, returns a
 * negative integer.
 */
inline nuvo_return_t nuvo_mutex_init(nuvo_mutex_t *m)
{
    int ret = pthread_mutex_init(&m->mutex, NULL);

    if (ret != 0)
    {
        return (-1);
    }
#if NUVO_MUTEX_LEAK_DETECTION
    m->leak = malloc(1);
    if (m->leak == NULL)
    {
        pthread_mutex_destroy(&m->mutex);
        return (-1);
    }
#endif
#ifndef NDEBUG
    m->owner = (pthread_t) ~0ull;
#endif
    return (0);
}

/**
 * \brief Performs clean-up on a nuvo_mutex_t object.
 *
 * This function performs any necessary clean-up on a nuvo_mutex_t object.
 *
 * \param m A pointer to the nuvo_mutex_t object.
 */
inline void nuvo_mutex_destroy(nuvo_mutex_t *m)
{
#if NUVO_MUTEX_LEAK_DETECTION
    free(m->leak);
#endif
    pthread_mutex_destroy(&m->mutex);
}

inline void __nuvo_mutex_lock(nuvo_mutex_t *m, const char *file, int line_no)
{
    int ret = pthread_mutex_lock(&m->mutex);

    if (ret)
    {
        NUVO_PANIC_ERRNO(ret, "Lock failed.");
    }
#ifndef NDEBUG
    NUVO_ASSERT(m->owner == (pthread_t) ~0ull);
    m->owner = pthread_self();
    m->line_no = line_no;
    m->file_name = file;
#endif
}

/**
 * \brief Lock a nuvo_mutex_t, blocking if necessary.
 *
 * This function attempts to lock a nuvo_mutex_t object.  If the object is
 * already locked, this function will block until the lock can be obtained.
 * This function does not support recursive locks, and will block if called
 * on a lock that is already held by the current thread.
 *
 * \param m A pointer to the nuvo_mutex_t object.
 */

#define  nuvo_mutex_lock(m)    __nuvo_mutex_lock(m, __FILE__, __LINE__)

inline nuvo_return_t  __nuvo_mutex_trylock(nuvo_mutex_t *m, const char *file, int line_no)
{
    int ret = pthread_mutex_trylock(&m->mutex);

    if (ret != 0 && ret != EBUSY)
    {
        NUVO_PANIC_ERRNO(ret, "Lock failed.");
    }

#ifndef NDEBUG
    if (ret == 0)
    {
        NUVO_ASSERT(m->owner == (pthread_t) ~0ull);
        m->owner = pthread_self();
    }

    if (ret == 0)
    {
        m->line_no = line_no;
        m->file_name = file;
    }
#endif

    return (ret == 0);
}

/**
 * \brief Attempts to lock a nuvo_mutex_t, immediately returning if lock is
 * held.
 *
 * This function attempts to lock a nuvo_mutex_t object.  If the lock is
 * acquired, the function returns 1.  If the object is already locked, this
 * function will return 0.  This function will always immediately return
 * regardless of whether the nuvo_mutex_t object is locked or not.
 *
 * \param m A pointer to the nuvo_mutex_t object.
 * \returns One if the lock was acquired.  Zero if the lock was not acquired.
 */

#define nuvo_mutex_trylock(m)    __nuvo_mutex_trylock(m, __FILE__, __LINE__)

inline void __nuvo_mutex_unlock(nuvo_mutex_t *m, const char *file, int line_no)
{
#ifndef NDEBUG
    NUVO_ASSERT(m->owner != (pthread_t) ~0ull);
    m->owner = (pthread_t) ~0ull;
    NUVO_ASSERT(m->line_no);

    // if owner is null, line_no is the last line unlocked.
    m->line_no = line_no;
    m->file_name = file;
#endif
    int ret = pthread_mutex_unlock(&m->mutex);
    if (ret)
    {
        NUVO_PANIC_ERRNO(ret, "Unlock failed.");
    }
}

/**
 * \brief Unlocks a previously locked nuvo_mutex_t object.
 *
 * This function unlocks a previously locked nuvo_mutex_t object.  The object
 * must have previously been locked, and behaviour is undefined if the object
 * is in an unlocked state.
 *
 * \param m A pointer to the nuvo_mutex_t object.
 */

#define  nuvo_mutex_unlock(m)                 __nuvo_mutex_unlock(m, __FILE__, __LINE__)

#define NUVO_ASSERT_MUTEX_HELD(m)             NUVO_ASSERT((m)->owner == pthread_self())
#define NUVO_ASSERT_MUTEX_NOT_HELD_BYME(m)    NUVO_ASSERT((m)->owner != pthread_self())

inline nuvo_return_t nuvo_cond_init(nuvo_cond_t *cond)
{
    return (-pthread_cond_init((pthread_cond_t *)cond, NULL));
}

inline void nuvo_cond_destroy(nuvo_cond_t *cond)
{
    pthread_cond_destroy((pthread_cond_t *)cond);
}

inline nuvo_return_t nuvo_cond_wait(nuvo_cond_t *cond, nuvo_mutex_t *mutex)
{
#ifndef NDEBUG
    NUVO_ASSERT(mutex->owner != (pthread_t) ~0ull);
    mutex->owner = (pthread_t) ~0ull;
#endif
    nuvo_return_t rc = -pthread_cond_wait((pthread_cond_t *)cond, &mutex->mutex);
#ifndef NDEBUG
    if (rc == 0)
    {
        NUVO_ASSERT(mutex->owner == (pthread_t) ~0ull);
        mutex->owner = pthread_self();
        mutex->line_no = __LINE__;
        mutex->file_name = __FILE__;
    }
#endif
    return (rc);
}

inline nuvo_return_t nuvo_cond_signal(nuvo_cond_t *cond)
{
    return (-pthread_cond_signal((pthread_cond_t *)cond));
}

inline nuvo_return_t nuvo_cond_broadcast(nuvo_cond_t *cond)
{
    return (-pthread_cond_broadcast((pthread_cond_t *)cond));
}

/**
 *
 */
inline nuvo_return_t nuvo_rwlock_init(nuvo_rwlock_t *rw)
{
    int ret;
    pthread_rwlockattr_t attr;

    if ((ret = pthread_rwlockattr_init(&attr)) != 0)
    {
        return (-1);
    }
    // this avoids writer starvation
    pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);

    ret = pthread_rwlock_init(&rw->rw_lock, &attr);
    pthread_rwlockattr_destroy(&attr);
    if (ret != 0)
    {
        return (-1);
    }
#if NUVO_MUTEX_LEAK_DETECTION
    rw->leak = malloc(1);
    if (rw->leak == NULL)
    {
        pthread_rwlock_destroy(&rw->mutex);
        return (-1);
    }
#endif
    return (0);
}

/**
 * \brief Performs clean-up on a nuvo_rwlock_t object.
 *
 * This function performs any necessary clean-up on a nuvo_rwlock_t object.
 *
 * \param rw A pointer to the nuvo_rwlock_t object.
 */
inline void nuvo_rwlock_destroy(nuvo_rwlock_t *rw)
{
#if NUVO_MUTEX_LEAK_DETECTION
    free(rw->leak);
#endif
    pthread_rwlock_destroy(&rw->rw_lock);
}

/**
 * \brief Lock a nuvo_rwlock_t for read, blocking if necessary.
 *
 * This function attempts to lock a nuvo_rwlock_t object for read in parallel with
 * other readers.  If the object is write locked, this function will block until the
 * lock can be obtained (any writer drains).
 *
 * \param rw A pointer to the nuvo_rwlock_t object.
 */
inline void nuvo_rwlock_rdlock(nuvo_rwlock_t *rw)
{
    int ret = pthread_rwlock_rdlock(&rw->rw_lock);

    if (ret)
    {
        NUVO_PANIC_ERRNO(ret, "Lock failed.");
    }
}

/**
 * \brief Lock a nuvo_rwlock_t for write, blocking if necessary.
 *
 * This function attempts to lock a nuvo_rwlock_t object for write (exclusive access).
 * If the object is write locked, this function will block until the
 * lock can be obtained (all readers and writers drain).
 *
 * \param rw A pointer to the nuvo_rwlock_t object.
 */
inline void nuvo_rwlock_wrlock(nuvo_rwlock_t *rw)
{
    int ret = pthread_rwlock_wrlock(&rw->rw_lock);

    if (ret)
    {
        NUVO_PANIC_ERRNO(ret, "Lock failed.");
    }
}

/**
 * \brief Unlocks a previously locked nuvo_rwlock_t object.
 *
 * This function unlocks a previously locked nuvo_rwlock_t object.  The object
 * must have previously been locked, and behaviour is undefined if the object
 * is in an unlocked state.
 *
 * \param rw A pointer to the nuvo_rwlock_t object.
 */
inline void nuvo_rwlock_unlock(nuvo_rwlock_t *rw)
{
    int ret = pthread_rwlock_unlock(&rw->rw_lock);

    if (ret)
    {
        NUVO_PANIC_ERRNO(ret, "Unlock failed.");
    }
}
