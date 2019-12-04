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
#include "nuvo_lock.h"

extern inline nuvo_return_t nuvo_mutex_init(nuvo_mutex_t *m);
extern inline void nuvo_mutex_destroy(nuvo_mutex_t *m);
extern inline void __nuvo_mutex_lock(nuvo_mutex_t *m, const char *file, int line_no);
extern nuvo_return_t  __nuvo_mutex_trylock(nuvo_mutex_t *m, const char *file, int line_no);
extern inline void __nuvo_mutex_unlock(nuvo_mutex_t *m, const char *file, int line_no);

extern inline nuvo_return_t nuvo_cond_init(nuvo_cond_t *cond);
extern inline void nuvo_cond_destroy(nuvo_cond_t *cond);

extern inline nuvo_return_t nuvo_cond_wait(nuvo_cond_t *cond, nuvo_mutex_t *mutex);
extern inline nuvo_return_t nuvo_cond_signal(nuvo_cond_t *cond);
extern inline nuvo_return_t nuvo_cond_broadcast(nuvo_cond_t *cond);

extern inline nuvo_return_t nuvo_rwlock_init(nuvo_rwlock_t *rw);
extern inline void nuvo_rwlock_destroy(nuvo_rwlock_t *rw);
extern inline void nuvo_rwlock_rdlock(nuvo_rwlock_t *rw);
extern inline void nuvo_rwlock_wrlock(nuvo_rwlock_t *rw);
extern inline void nuvo_rwlock_unlock(nuvo_rwlock_t *rw);
