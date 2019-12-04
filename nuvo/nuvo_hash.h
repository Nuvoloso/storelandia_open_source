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

#define XXH_STATIC_LINKING_ONLY
#include "xxhash/xxhash.h"

typedef XXH64_hash_t nuvo_hash_t;
#define NUVO_HASH_BYTES    (sizeof(nuvo_hash_t))
#define NUVO_HASH_BITS     (NUVO_HASH_BYTES * CHAR_BIT)
#define NUVO_HASH_SEED     (0xFFFFFFFFFFFFFFC5ull)          //largest 64b prime

#define nuvo_hash(input, length)                  XXH64(input, length, NUVO_HASH_SEED)
#define nuvo_hash_cv(input, length, cv, is_cv)    XXH64_4096_CV(input, length, NUVO_HASH_SEED, cv, is_cv)

/*
 * If you have multiple pieces of data in non-contiguous locations,
 * use nuvo_hash_reset, then multiple nuvo_hash_update, then nuvo_hash_digest
 */
typedef XXH64_state_t nuvo_hash_state_t;
#define nuvo_hash_reset(statePtr)                    XXH64_reset(statePtr, NUVO_HASH_SEED)
#define nuvo_hash_update(statePtr, input, length)    XXH64_update(statePtr, input, length)
#define nuvo_hash_digest(statePtr)                   XXH64_digest(statePtr)
