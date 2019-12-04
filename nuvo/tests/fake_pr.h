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
 * @file fake_pr.h
 * @brief fake parcel router
 *
 * This provides a simple parcel router interface
 * so we can use it in testing.  At present it
 * assumes a single caller.
 */


/**
 * \brief Setup the fake pr
 */
void fake_pr_init();

/**
 * \brief Tear down the fake pr
 */
void fake_pr_teardown();

/**
 * \brief How many ops have been replied to.
 */
uint64_t fake_pr_ops_completed();

/**
 * \brief suspend replies from the fake pr.
 *
 * Useful if you want to send a bunch of requests in and NOT
 * have callbacks called immediately.
 */
void fake_pr_suspend_replies();

/**
 * \brief unsuspends replies from the fake pr.
 *
 * Does callbacks for all ios that were queued.
 */
void fake_pr_unsuspend_replies();

/**
 * \brief Add a fake device.
 */
void fake_pr_add_device(uuid_t device_uuid, uint64_t parcel_size, uint8_t device_class);

/**
 * \brief Is the parcel descriptor valid?
 */
bool fake_pr_parcel_descriptor_valid(uint_fast32_t pd);

/**
 * \brief Get the last descriptor created.
 */
uint_fast32_t fake_pr_get_last_descriptor();

/**
 * \brief Allow direct access to the data of the parcel.
 *
 * Accesses are not mutex protected.   You are on your own.
 */
uint8_t *fake_pr_parcel_data(uint_fast32_t pd);

/**
 * \brief Fail an IO.
 *
 * Let the next \p after succeed, then fail with \c status
 * \param status The status to return on the failure.
 * \param after How man IOs to allow to succceed until failing.
 */
void fake_pr_fail_next_io(nuvo_return_t status, unsigned after);
