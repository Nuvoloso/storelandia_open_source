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

#include "nuvo_list.h"


extern inline void nuvo_dlist_init(struct nuvo_dlist *list);
extern inline void nuvo_dlnode_init(struct nuvo_dlnode *node);
extern inline bool nuvo_dlnode_on_list(struct nuvo_dlnode *node);
extern inline void nuvo_dlist_insert_after(struct nuvo_dlnode *ref, struct nuvo_dlnode *node);
extern inline void nuvo_dlist_insert_list_after(struct nuvo_dlnode *ref, struct nuvo_dlist *list);
extern inline void nuvo_dlist_insert_before(struct nuvo_dlnode *ref, struct nuvo_dlnode *node);
extern inline void nuvo_dlist_insert_list_before(struct nuvo_dlnode *ref, struct nuvo_dlist *list);
extern inline void nuvo_dlist_insert_head(struct nuvo_dlist *list, struct nuvo_dlnode *node);
extern inline void nuvo_dlist_insert_list_head(struct nuvo_dlist *list, struct nuvo_dlist *insert_list);
extern inline void nuvo_dlist_insert_tail(struct nuvo_dlist *list, struct nuvo_dlnode *node);
extern inline void nuvo_dlist_insert_list_tail(struct nuvo_dlist *list, struct nuvo_dlist *insert_list);
extern inline struct nuvo_dlnode *nuvo_dlist_get_next(struct nuvo_dlist *list, struct nuvo_dlnode *node);
extern inline struct nuvo_dlnode *nuvo_dlist_get_prev(struct nuvo_dlist *list, struct nuvo_dlnode *node);
extern inline struct nuvo_dlnode *nuvo_dlist_get_head(struct nuvo_dlist *list);
extern inline struct nuvo_dlnode *nuvo_dlist_get_tail(struct nuvo_dlist *list);
extern inline void nuvo_dlist_remove(struct nuvo_dlnode *node);
extern inline struct nuvo_dlnode *nuvo_dlist_remove_head(struct nuvo_dlist *list);
extern inline struct nuvo_dlnode *nuvo_dlist_remove_tail(struct nuvo_dlist *list);
extern inline void nuvo_list_init(struct nuvo_list *list);
extern inline void nuvo_lnode_init(struct nuvo_lnode *node);
extern inline void nuvo_list_insert_head(struct nuvo_list *list, struct nuvo_lnode *node);
extern inline struct nuvo_lnode *nuvo_list_get_head(struct nuvo_list *list);
extern inline struct nuvo_lnode *nuvo_list_remove_head(struct nuvo_list *list);
