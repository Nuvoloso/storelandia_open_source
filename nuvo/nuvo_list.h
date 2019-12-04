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

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "nuvo.h"
#include "nuvo_util.h"

struct nuvo_dlnode {
    struct nuvo_dlnode *prev;
    struct nuvo_dlnode *next;
};

struct nuvo_dlist {
    struct nuvo_dlnode node;
};

inline void nuvo_dlist_init(struct nuvo_dlist *list)
{
    list->node.prev = &list->node;
    list->node.next = &list->node;
}

#define nuvo_dlist_empty(_dlist)    (((_dlist)->node.prev == &(_dlist)->node))

inline void nuvo_dlnode_init(struct nuvo_dlnode *node)
{
    node->prev = NULL;
    node->next = NULL;
}

inline bool nuvo_dlnode_on_list(struct nuvo_dlnode *node)
{
    return (node->next != NULL);
}

inline void nuvo_dlist_insert_after(struct nuvo_dlnode *ref, struct nuvo_dlnode *node)
{
    NUVO_ASSERT(ref->next != NULL);
    NUVO_ASSERT(ref->prev != NULL);
    NUVO_ASSERT(node->next == NULL);
    NUVO_ASSERT(node->prev == NULL);

    node->next = ref->next;
    node->prev = ref;
    ref->next->prev = node;
    ref->next = node;
}

inline void nuvo_dlist_insert_list_after(struct nuvo_dlnode *ref, struct nuvo_dlist *list)
{
    NUVO_ASSERT(ref->next != NULL);
    NUVO_ASSERT(ref->prev != NULL);

    // if list is empty, just return
    if (nuvo_dlist_empty(list))
    {
        return;
    }

    struct nuvo_dlnode *list_first = list->node.next;
    struct nuvo_dlnode *list_last = list->node.prev;

    list->node.next = &list->node;
    list->node.prev = &list->node;

    list_first->prev = ref;
    list_last->next = ref->next;
    ref->next->prev = list_last;
    ref->next = list_first;
}

inline void nuvo_dlist_insert_list_before(struct nuvo_dlnode *ref, struct nuvo_dlist *list)
{
    NUVO_ASSERT(ref->next != NULL);
    NUVO_ASSERT(ref->prev != NULL);

    // if list is empty, just return
    if (nuvo_dlist_empty(list))
    {
        return;
    }

    struct nuvo_dlnode *list_first = list->node.next;
    struct nuvo_dlnode *list_last = list->node.prev;

    list->node.next = &list->node;
    list->node.prev = &list->node;

    list_first->prev = ref->prev;
    list_last->next = ref;
    ref->prev->next = list_first;
    ref->prev = list_last;
}

inline void nuvo_dlist_insert_before(struct nuvo_dlnode *ref, struct nuvo_dlnode *node)
{
    NUVO_ASSERT(ref->next != NULL);
    NUVO_ASSERT(ref->prev != NULL);
    NUVO_ASSERT(node->next == NULL);
    NUVO_ASSERT(node->prev == NULL);

    node->next = ref;
    node->prev = ref->prev;
    ref->prev->next = node;
    ref->prev = node;
}

inline void nuvo_dlist_insert_list_head(struct nuvo_dlist *list, struct nuvo_dlist *insert_list)
{
    NUVO_ASSERT(list->node.next != NULL);
    NUVO_ASSERT(list->node.prev != NULL);
    nuvo_dlist_insert_list_after(&list->node, insert_list);
}

inline void nuvo_dlist_insert_head(struct nuvo_dlist *list, struct nuvo_dlnode *node)
{
    NUVO_ASSERT(list->node.next != NULL);
    NUVO_ASSERT(list->node.prev != NULL);
    nuvo_dlist_insert_after(&list->node, node);
}

inline void nuvo_dlist_insert_list_tail(struct nuvo_dlist *list, struct nuvo_dlist *insert_list)
{
    NUVO_ASSERT(list->node.next != NULL);
    NUVO_ASSERT(list->node.prev != NULL);
    nuvo_dlist_insert_list_before(&list->node, insert_list);
}

inline void nuvo_dlist_insert_tail(struct nuvo_dlist *list, struct nuvo_dlnode *node)
{
    NUVO_ASSERT(list->node.next != NULL);
    NUVO_ASSERT(list->node.prev != NULL);
    nuvo_dlist_insert_before(&list->node, node);
}

inline struct nuvo_dlnode *nuvo_dlist_get_next(struct nuvo_dlist *list, struct nuvo_dlnode *node)
{
    struct nuvo_dlnode *next_node = node->next;

    NUVO_ASSERT(list->node.next != NULL);
    NUVO_ASSERT(list->node.prev != NULL);
    NUVO_ASSERT(node->next != NULL);
    NUVO_ASSERT(node->prev != NULL);

    if (next_node == &list->node)
    {
        next_node = NULL;
    }

    return (next_node);
}

#define nuvo_dlist_get_object(list, node_ptr, type, member)    ({                         \
        NUVO_ASSERT((list)->node.next != NULL);                                           \
        NUVO_ASSERT((list)->node.prev != NULL);                                           \
        type *nuvo_dlgo_obj = ((type *)((uintptr_t)(node_ptr) - offsetof(type, member))); \
        if (node_ptr == &(list)->node) {                                                  \
            nuvo_dlgo_obj = NULL;                                                         \
        }                                                                                 \
        nuvo_dlgo_obj; })

#define nuvo_dlist_get_next_object(list, obj, type, member)    ({ \
        NUVO_ASSERT((obj)->member.next != NULL);                  \
        NUVO_ASSERT((obj)->member.prev != NULL);                  \
        nuvo_dlist_get_object(list, (obj)->member.next, type, member); })

inline struct nuvo_dlnode *nuvo_dlist_get_prev(struct nuvo_dlist *list, struct nuvo_dlnode *node)
{
    struct nuvo_dlnode *prev_node = node->prev;

    NUVO_ASSERT(list->node.next != NULL);
    NUVO_ASSERT(list->node.prev != NULL);
    NUVO_ASSERT(node->next != NULL);
    NUVO_ASSERT(node->prev != NULL);

    if (prev_node == &list->node)
    {
        prev_node = NULL;
    }

    return (prev_node);
}

#define nuvo_dlist_get_prev_object(list, obj, type, member)    ({ \
        NUVO_ASSERT((obj)->member.next != NULL);                  \
        NUVO_ASSERT((obj)->member.prev != NULL);                  \
        nuvo_dlist_get_object(list, (obj)->member.prev, type, member); })

inline struct nuvo_dlnode *nuvo_dlist_get_head(struct nuvo_dlist *list)
{
    NUVO_ASSERT(list->node.next != NULL);
    NUVO_ASSERT(list->node.prev != NULL);

    if (nuvo_dlist_empty(list))
    {
        return (NULL);
    }

    return (list->node.next);
}

#define nuvo_dlist_get_head_object(list, type, member)    ({ \
        NUVO_ASSERT((list)->node.next != NULL);              \
        NUVO_ASSERT((list)->node.prev != NULL);              \
        nuvo_dlist_get_object(list, (list)->node.next, type, member); })

inline struct nuvo_dlnode *nuvo_dlist_get_tail(struct nuvo_dlist *list)
{
    if (nuvo_dlist_empty(list))
    {
        return (NULL);
    }
    return (list->node.prev);
}

#define nuvo_dlist_get_tail_object(list, type, member)    ({ \
        NUVO_ASSERT((list)->node.next != NULL);              \
        NUVO_ASSERT((list)->node.prev != NULL);              \
        nuvo_dlist_get_object(list, (list)->node.prev, type, member); })

inline void nuvo_dlist_remove(struct nuvo_dlnode *node)
{
    NUVO_ASSERT(node->next != NULL);
    NUVO_ASSERT(node->prev != NULL);

    node->prev->next = node->next;
    node->next->prev = node->prev;

    node->prev = NULL;
    node->next = NULL;
}

inline struct nuvo_dlnode *nuvo_dlist_remove_head(struct nuvo_dlist *list)
{
    if (nuvo_dlist_empty(list))
    {
        return (NULL);
    }
    struct nuvo_dlnode *node = list->node.next;

    list->node.next = node->next;
    node->next->prev = &list->node;

    node->next = NULL;
    node->prev = NULL;

    return (node);
}

#define nuvo_dlist_remove_head_object(list, type, member)    ({                                    \
        NUVO_ASSERT((list)->node.next != NULL);                                                    \
        NUVO_ASSERT((list)->node.prev != NULL);                                                    \
        struct nuvo_dlnode *nuvo_dlrho_node = (list)->node.next;                                   \
        type *nuvo_dlrho_item = ((type *)((uintptr_t)(nuvo_dlrho_node) - offsetof(type, member))); \
        (list)->node.next = nuvo_dlrho_node->next;                                                 \
        nuvo_dlrho_node->next->prev = &(list)->node;                                               \
        if (nuvo_dlrho_node == (&(list)->node)) {                                                  \
            nuvo_dlrho_item = NULL;                                                                \
        } else {                                                                                   \
            nuvo_dlrho_node->next = NULL;                                                          \
            nuvo_dlrho_node->prev = NULL;                                                          \
        }                                                                                          \
        nuvo_dlrho_item; })

inline struct nuvo_dlnode *nuvo_dlist_remove_tail(struct nuvo_dlist *list)
{
    if (nuvo_dlist_empty(list))
    {
        return (NULL);
    }
    struct nuvo_dlnode *node = list->node.prev;

    node->prev->next = &list->node;
    list->node.prev = node->prev;

    node->next = NULL;
    node->prev = NULL;

    return (node);
}

#define nuvo_dlist_remove_tail_object(list, type, member)    ({                                    \
        NUVO_ASSERT((list)->node.next != NULL);                                                    \
        NUVO_ASSERT((list)->node.prev != NULL);                                                    \
        struct nuvo_dlnode *nuvo_dlrto_node = (list)->node.prev;                                   \
        type *nuvo_dlrto_item = ((type *)((uintptr_t)(nuvo_dlrto_node) - offsetof(type, member))); \
        nuvo_dlrto_node->prev->next = &(list)->node;                                               \
        (list)->node.prev = nuvo_dlrto_node->prev;                                                 \
        if (nuvo_dlrto_node == (&(list)->node)) {                                                  \
            nuvo_dlrto_item = NULL;                                                                \
        } else {                                                                                   \
            nuvo_dlrto_node->next = NULL;                                                          \
            nuvo_dlrto_node->prev = NULL;                                                          \
        }                                                                                          \
        nuvo_dlrto_item; })

struct nuvo_lnode {
    struct nuvo_lnode *next;
};

struct nuvo_list {
    struct nuvo_lnode node;
};

inline void nuvo_list_init(struct nuvo_list *list)
{
    list->node.next = NULL;
}

inline void nuvo_lnode_init(struct nuvo_lnode *node)
{
    node->next = NULL;
}

inline void nuvo_list_insert_head(struct nuvo_list *list, struct nuvo_lnode *node)
{
    node->next = list->node.next;
    list->node.next = node;
}

inline struct nuvo_lnode *nuvo_list_get_head(struct nuvo_list *list)
{
    return (list->node.next);
}

#define nuvo_list_get_head_object(list, type, member)    ({         \
        nuvo_containing_object((list)->node.next, type, member); }) \

inline struct nuvo_lnode *nuvo_list_remove_head(struct nuvo_list *list)
{
    struct nuvo_lnode *node = list->node.next;

    if (node != NULL)
    {
        list->node.next = node->next;
    }

    return (node);
}

#define nuvo_list_remove_head_object(list, type, member)    ({                                   \
        struct nuvo_lnode *nuvo_lrho_node = (list)->node.next;                                   \
        type *nuvo_lrho_item = ((type *)((uintptr_t)(nuvo_lrho_node) - offsetof(type, member))); \
        if (nuvo_lrho_node == NULL) {                                                            \
            nuvo_lrho_item = NULL;                                                               \
        } else {                                                                                 \
            (list)->node.next = nuvo_lrho_node->next;                                            \
        }                                                                                        \
        nuvo_lrho_item; })
