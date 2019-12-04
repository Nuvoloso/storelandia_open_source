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

/**
 * \brief wrapper to ck_assert to allow setting breakpoint.
 *
 * This contains a test and a line inside where a breakpoint can be set to
 * stop a test in gdb on a failure.
 *
 * The expectation is that developer is hitting a hard to find problem, changes
 * their sk_assert to nuvo_ck_assert, finds and fixes their problem, changes
 * their nuvo_ck_asserts to
 * \param worked The expression to test.
 */
void nuvo_ck_assert(int worked);

void nuvo_ck_assert_uint_eq(uint64_t a, uint64_t b);
void nuvo_ck_assert_uint_ge(uint64_t a, uint64_t b);
void nuvo_ck_assert_uint_le(uint64_t a, uint64_t b);
void nuvo_ck_assert_uint_gt(uint64_t a, uint64_t b);
void nuvo_ck_assert_uint_lt(uint64_t a, uint64_t b);

void nuvo_ck_assert_int_eq(int64_t a, int64_t b);
void nuvo_ck_assert_int_ge(int64_t a, int64_t b);
void nuvo_ck_assert_int_le(int64_t a, int64_t b);
void nuvo_ck_assert_int_gt(int64_t a, int64_t b);
void nuvo_ck_assert_int_lt(int64_t a, int64_t b);

void nuvo_ck_assert_ptr_ne(void *p1, void *p2);
void nuvo_ck_assert_ptr_eq(void *p1, void *p2);