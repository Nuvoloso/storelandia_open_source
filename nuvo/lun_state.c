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

/**
 * @file lun_state.c
 * @brief Routines for lun states and pinning.
 *
 * Consider which of these routines should be here vs. lun.h
 */
#include "lun.h"

nuvo_return_t nuvo_lun_state_transition(struct nuvo_lun             *lun,
                                        enum nuvo_lun_state_e        lun_state,
                                        enum nuvo_lun_export_state_e export_state)
{
    NUVO_ASSERT_MUTEX_HELD(&lun->mutex);
    switch (lun->lun_state)
    {
    case NUVO_LUN_STATE_FREE:
        if (lun_state != NUVO_LUN_STATE_VALID ||
            export_state != NUVO_LUN_EXPORT_UNEXPORTED)
        {
            return (-NUVO_E_BAD_STATE_TRANSITION);
        }
        break;

    case NUVO_LUN_STATE_VALID:
        if (lun_state != NUVO_LUN_STATE_VALID)
        {
            if (lun_state != NUVO_LUN_STATE_DELETING ||
                export_state != NUVO_LUN_EXPORT_UNEXPORTED)
            {
                return (-NUVO_E_BAD_STATE_TRANSITION);
            }
        }
        break;

    case NUVO_LUN_STATE_DELETING:
        if (export_state != NUVO_LUN_EXPORT_UNEXPORTED)
        {
            return (-NUVO_E_BAD_STATE_TRANSITION);
        }
        if (lun->pin_count > 0 && lun_state != NUVO_LUN_STATE_DELETING_DRAIN)
        {
            return (-NUVO_E_BAD_STATE_TRANSITION);
        }
        break;

    case NUVO_LUN_STATE_DELETING_DRAIN:
        if (export_state != NUVO_LUN_EXPORT_UNEXPORTED ||
            lun->pin_count != 0 ||
            lun_state != NUVO_LUN_STATE_DELETED)
        {
            return (-NUVO_E_BAD_STATE_TRANSITION);
        }
        break;

    case NUVO_LUN_STATE_DELETED:
        NUVO_ASSERT(lun->pin_count == 0);
        if (export_state != NUVO_LUN_EXPORT_UNEXPORTED ||
            lun_state != NUVO_LUN_STATE_FREE_PENDING)
        {
            return (-NUVO_E_BAD_STATE_TRANSITION);
        }
        break;

    case NUVO_LUN_STATE_FREE_PENDING:
        if (export_state != NUVO_LUN_EXPORT_UNEXPORTED ||
            lun_state != NUVO_LUN_STATE_FREE)
        {
            return (-NUVO_E_BAD_STATE_TRANSITION);
        }
    }

    lun->lun_state = lun_state;
    lun->export_state = export_state;
    return (0);
}

void nuvo_lun_state_init(struct nuvo_lun *lun, struct nuvo_vol *vol, enum nuvo_lun_state_e lun_state, enum nuvo_lun_export_state_e export_state)
{
    lun->vol = vol;
    lun->lun_state = lun_state;
    lun->export_state = export_state;
}

void nuvo_lun_pin(struct nuvo_lun *lun)
{
    NUVO_ASSERT_MUTEX_HELD(&lun->mutex);
    NUVO_ASSERT(lun->lun_state <= NUVO_LUN_STATE_DELETING && lun->lun_state != NUVO_LUN_STATE_FREE)
    lun->pin_count++;
}

void nuvo_lun_unpin(struct nuvo_lun *lun)
{
    NUVO_ASSERT_MUTEX_HELD(&lun->mutex);
    lun->pin_count--;
}
