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

#define NUVO_ARRAY_LENGTH(x)                          (sizeof(x) / sizeof(x[0]))

#define nuvo_containing_object(node, type, member)    ({                             \
        type *nuvo_co_item = ((type *)((uintptr_t)(node) - offsetof(type, member))); \
        if (node == NULL) {                                                          \
            nuvo_co_item = NULL; }                                                   \
        nuvo_co_item; })

#define   NUVO_MAX(a, b)      \
    ({ __typeof__(a)_a = (a); \
       __typeof__(b)_b = (b); \
       _a > _b ? _a : _b; })

#define   NUVO_MIN(a, b)      \
    ({ __typeof__(a)_a = (a); \
       __typeof__(b)_b = (b); \
       _a < _b ? _a : _b; })
