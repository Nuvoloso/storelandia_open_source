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

#include "parcel_manager_priv.h"
#include "logger.h"
#include "nuvo_vol_series.h"
#include "nuvo.h"
#include "segment.h"
#include "cache.h"
#include "fault_inject.h"

#include <errno.h>
#include <fcntl.h>
#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>
#include <semaphore.h>

UUID_DEFINE(bad_uuid, 186, 219, 173, 186, 219, 173, 186, 219, 173, 186, 219, 173, 186, 219, 173, 186);
UUID_DEFINE(node_uuid, 52, 48, 81, 19, 185, 24, 20, 141, 72, 211, 221, 54, 20, 191, 82, 84);

#define TEST_DEBUG_LOG_LEVEL (100)

/*
 * used for creating a pool of test devices
 * each device has enough nuvo_io_requests pre-allocated to fully utilize the device.
 * devices in the test pool may not be suitable for limit tests.
 */
#define TEST_DEVICE_NAME_TEMPLATE ("/tmp/nuvo_test_device.XXXXXX")
/* number of devices in the test pool */
#define MAX_TEST_DEVICES (8)
#define MAX_TEST_CACHE_DEVICES (3)
/* maximum number of test devices per volume */
#define MAX_TEST_VOLUME_DEVICES (MAX_TEST_DEVICES)

/* the segment size */
#define TEST_DEVICE_SEGMENT_BLOCKS (1024)
//#define TEST_DEVICE_SEGMENT_BLOCKS (16384)
#define TEST_DEVICE_SEGMENT_SIZE (TEST_DEVICE_SEGMENT_BLOCKS * NUVO_BLOCK_SIZE)
/* the number of segments per parcel */
#define TEST_DEVICE_MAX_PARCEL_SEGMENTS (2)
/* the default parcel size used for test devices */
#define TEST_DEVICE_PARCEL_BLOCKS (TEST_DEVICE_SEGMENT_BLOCKS * TEST_DEVICE_MAX_PARCEL_SEGMENTS)
#define TEST_DEVICE_PARCEL_SIZE (TEST_DEVICE_PARCEL_BLOCKS * NUVO_BLOCK_SIZE)
#define TEST_DEVICE_MAX_PARCELS (3)
/* the addressable size of the test devices */
#define TEST_DEVICE_USABLE_SIZE (TEST_DEVICE_PARCEL_SIZE * TEST_DEVICE_MAX_PARCELS)
/* the total size of the test device */
#define TEST_DEVICE_SIZE (TEST_DEVICE_USABLE_SIZE + (NUVO_PM_DEVICE_PRIVATEREGION_SIZE * 2))
//#define TEST_CACHE_DEVICE_SIZE (TEST_DEVICE_SIZE * MAX_TEST_DEVICES)
#define TEST_CACHE_DEVICE_SIZE (TEST_DEVICE_SIZE * 2)
/* used for sizing a pre-allocated array of io requests */
#define TEST_DEVICE_MAX_IOREQS (TEST_DEVICE_USABLE_SIZE / NUVO_MAX_IO_SIZE)

#define MAX_LOG_REQ_BLOCKS (NUVO_MAX_IO_BLOCKS - NUVO_MAX_LOG_DESCRIPTOR_BLOCKS)
/* used for sizing the number pre-allocated log requests */
#define MIN_LOG_REQ_BLOCKS (128)
#define TEST_DEVICE_SEGMENT_MAX_LOGREQS (TEST_DEVICE_SEGMENT_BLOCKS / MIN_LOG_REQ_BLOCKS)
/* the maximum pre-allocated log requests available for the volume series */
#define TEST_VOL_MAX_LOGREQS (TEST_DEVICE_SEGMENT_MAX_LOGREQS * TEST_DEVICE_MAX_PARCEL_SEGMENTS * TEST_DEVICE_MAX_PARCELS * MAX_TEST_VOLUME_DEVICES)
#define TEST_VOL_STARTING_SEQUENCE_NO (101)
#define TEST_VOL_STARTING_SEG_CNT_SEQUENCE_NO (102)

#define MAX_TEST_THREADS    (4)

#define TEST_DEVICE_INDEX(d) (d - &test_devs[0])

extern struct device_records g_devices;

/* for comparing logger state after replay */
struct nuvo_logger old_logger;

sem_t sem;
sem_t replay_sem;

/* used to set nuvo's notion of what type of device it's working with during the test */
enum test_device_type
{
    TEST_DEVICE_SSD = 0,   /* use ssd for the test */
    TEST_DEVICE_HDD = 1,   /* use hdd for the test */
    TEST_DEVICE_ALL = 2,   /* use both types for the test */
};

struct test_cache_device
{
    char   name[128];
    uuid_t uuid;
    uint64_t size_bytes;
    int    fd;
};
struct test_cache_device cache_dev[MAX_TEST_CACHE_DEVICES];

struct io_completion
{
    union
    {
        struct nuvo_io_request io_req;
        struct nuvo_log_request log_req;
    };
    int io_complete;
    sem_t log_io_sem;
};

struct test_device
{
    char name[128];
    int fd;
    uuid_t uuid;
    uint64_t device_size;
    uint32_t parcel_size;
    enum nuvo_dev_type device_type;
    uuid_t volume_uuid;

    struct nuvo_dlist segment_list;
    struct device_info device_info;
    struct io_completion op_info;
    struct io_completion op_alloc[TEST_DEVICE_MAX_PARCELS];
    struct io_completion op_free[TEST_DEVICE_MAX_PARCELS];
    struct io_completion op_open[TEST_DEVICE_MAX_PARCELS];
    struct io_completion op_close[TEST_DEVICE_MAX_PARCELS];
    struct io_completion op_read[TEST_DEVICE_MAX_IOREQS];
    struct io_completion op_write[TEST_DEVICE_MAX_IOREQS];

    struct nuvo_io_stats_snap write_io_stats;
    uint_fast64_t write_size_hist[NUVO_STATS_SIZE_BINS];
    uint_fast64_t write_latency_hist[NUVO_STATS_LAT_BINS];

    struct nuvo_io_stats_snap read_io_stats;
    uint_fast64_t read_size_hist[NUVO_STATS_SIZE_BINS];
    uint_fast64_t read_latency_hist[NUVO_STATS_LAT_BINS];
};
struct test_device test_devs[MAX_TEST_DEVICES];

struct test_vol
{
    struct nuvo_vol nuvo_vol;
    struct io_completion op_log[TEST_VOL_MAX_LOGREQS];
    struct test_device *devices[MAX_TEST_VOLUME_DEVICES];
    uint32_t allocated_device_count;
    bool cp_requested;
    nuvo_mutex_t cp_mutex;
    nuvo_cond_t cp_cond;
    struct
    {
        uint64_t sequence_no;
        struct nuvo_segment replay_segments[NUVO_MAX_DATA_CLASSES * NUVO_MAX_OPEN_SEGMENTS * 2];
        uint32_t segment_count;
    } cp;
    nuvo_mutex_t count_mutex;    // mutex to protect updating the counters and segment snap.
};
struct test_vol test_vol;
struct nuvo_vol fake_vol[3];    // additional fake volumes

struct test_segment
{
    struct nuvo_dlnode  list_node;
    struct nuvo_segment nuvo_segment;
};

struct log_write_sequential_params
{
    struct test_vol *vol;
    uint32_t submit_cnt;
    uint32_t block_cnt;
    uint64_t device_offset;
    int log_op_type;
    int data_class;
    enum nuvo_dev_type device_type;
    int cv_mix;
    int op_idx;
    bool cleanup;
};

struct test_thread
{
    struct log_write_sequential_params  param;
    pthread_t th;
};
struct test_thread test_th[MAX_TEST_THREADS];

enum
{
    TEST_FREELIST_LAYOUT_CONCAT,
    TEST_FREELIST_LAYOUT_STRIPED,
    TEST_FREELIST_LAYOUT_RANDOM
};

void get_current_log_state(struct nuvo_logger *logger, struct logger_class *open_data_segments, uint64_t *sequence_no)
{
    nuvo_mutex_lock(&logger->sequence_no_mutex);

    *sequence_no = logger->sequence_no - 1;
    memcpy(open_data_segments, logger->open_data_segments, sizeof(logger->open_data_segments));

    nuvo_mutex_unlock(&logger->sequence_no_mutex);
}

struct {
    nuvo_mutex_t        mutex;
    struct nuvo_dlist   segments_list[NUVO_MAX_DATA_CLASSES];
} fake_space;

static void fake_space_init()
{
    nuvo_mutex_init(&fake_space.mutex);
    for (unsigned i = 0; i < NUVO_MAX_DATA_CLASSES; i++)
    {
        nuvo_dlist_init(&fake_space.segments_list[i]);
    }
}

static void fake_space_destroy()
{
    nuvo_mutex_destroy(&fake_space.mutex);
}
void nuvo_map_replay_vol_done(struct nuvo_vol *vol)
{
    (void)vol;
}

/* fake volume index lookup */
unsigned int nuvo_vol_index_lookup(const struct nuvo_vol *vol)
{
    (void) vol;
    return 0;
}

nuvo_mutex_t ack_queue_mutex;
nuvo_cond_t ack_queue_cond;
struct nuvo_dlist ack_queue;
pthread_t ack_tid;
bool ack_test_running;

#define UNUSED(x) (void)x

nuvo_return_t nuvo_log_vol_delete_lun_int(struct nuvo_lun *lun)
{
    UNUSED(lun);
    return 0;
}

struct nuvo_lun rlun;

struct nuvo_lun * nuvo_map_create_snap(struct nuvo_vol *vol, const uuid_t lun_uuid)
{
    UNUSED(vol);
    UNUSED(lun_uuid);
    rlun.snap_id = 1; //fake the snap id to keep the replay happy
    return &rlun;
}
struct nuvo_lun *
nuvo_get_lun_by_snapid_locked(struct nuvo_vol *vol, uint64_t snap_id, bool pin)
{
    UNUSED(vol);
    UNUSED(snap_id);
    UNUSED(pin);
    return NULL;
}


/* mock fn that pretend updates the map and then calls ack */
void nuvo_map_replay(struct nuvo_log_request *log_req)
{
    nuvo_log_ack_sno(log_req);
}

/* mock fn to freeze the manifest when requested. */
void nuvo_mfst_freeze_at_seqno(struct nuvo_mfst *mfst, uint64_t next_seq_no)
{
    UNUSED(mfst);
    UNUSED(next_seq_no);
}

/* mock_fn that tells the manifest to start updating segment counts. */
void nuvo_mfst_seg_counts_start(struct nuvo_mfst *mfst)
{
    UNUSED(mfst);
}

void nuvo_mfst_log_starts_set(struct nuvo_mfst          *mfst,
                              uint64_t                  log_start_seq_no,
                              struct nuvo_segment       *segments,
                              unsigned                  num)
{
    UNUSED(mfst);
    UNUSED(log_start_seq_no);
    UNUSED(num);
    UNUSED(segments);
}

/*
 * mock routine to trigger a fake checkpoint when the io threshold is reached
 */
void nuvo_space_trigger_cp(struct nuvo_space_vol *space)
{
    UNUSED(space);
    nuvo_mutex_lock(&test_vol.cp_mutex);
    test_vol.cp_requested = true;
    nuvo_cond_signal(&test_vol.cp_cond);
    nuvo_mutex_unlock(&test_vol.cp_mutex);
}


/*
 * mock routine to notify that the logger is done with the segment
 */
void nuvo_space_vol_segment_done(struct nuvo_space_vol *space, struct nuvo_segment *seg, enum nuvo_mfst_segment_reason_t reason)
{
    UNUSED(space);
    UNUSED(seg);
    UNUSED(reason);

    nuvo_mutex_lock(&fake_space.mutex);
    nuvo_dlist_insert_tail(&fake_space.segments_list[seg->data_class], &seg->list_node);
    nuvo_mutex_unlock(&fake_space.mutex);
}

struct nuvo_segment *nuvo_space_vol_segment_get(struct  nuvo_space_vol  *space,
                                                uint8_t                 data_class,
                                                uint8_t                 data_subclass,
                                                unsigned                num_avoid,
                                                uint_fast32_t           *avoid_dev,
                                                enum nuvo_space_urgency urgency)
{
    UNUSED(space);
    UNUSED(data_subclass);

    nuvo_mutex_lock(&fake_space.mutex);
    struct nuvo_segment *segment = nuvo_dlist_get_head_object(&fake_space.segments_list[data_class], struct nuvo_segment, list_node);
    while (segment != NULL)
    {
        bool collision = false;
        for (unsigned i = 0; i < num_avoid; i++)
        {
            if (segment->device_index == avoid_dev[i])
            {
                collision = true;
            }
        }
        if (collision == false)
        {
            break;
        }
        segment = nuvo_dlist_get_next_object(&fake_space.segments_list[data_class], segment, struct nuvo_segment, list_node);
    }
    if (segment == NULL && urgency != NUVO_SPACE_SEGMENT_DEFINITELY_AVOID)
    {
        segment = nuvo_dlist_get_head_object(&fake_space.segments_list[data_class], struct nuvo_segment, list_node);
    }
    if (segment != NULL)
    {
        nuvo_dlist_remove(&segment->list_node);
    }
    nuvo_mutex_unlock(&fake_space.mutex);

    return segment;
}

/* mock routine to getting segment information for segments that need to be open for replay */
nuvo_return_t nuvo_space_vol_segment_log_replay_get(struct nuvo_space_vol *space, uint32_t parcel_index, uint32_t block_offset, struct nuvo_segment **replay_segment)
{
    UNUSED(space);

    nuvo_mutex_lock(&fake_space.mutex);
    for (uint8_t data_class = 0; data_class < NUVO_MAX_DATA_CLASSES; data_class++)
    {
        struct nuvo_segment *segment = nuvo_dlist_get_head_object(&fake_space.segments_list[data_class], struct nuvo_segment, list_node);
        while (segment != NULL)
        {
            if ((segment->parcel_index == parcel_index) && (segment->block_offset == block_offset))
            {
                nuvo_dlist_remove(&segment->list_node);
                *replay_segment = segment;
                nuvo_mutex_unlock(&fake_space.mutex);
                return 0;
            }
            segment = nuvo_dlist_get_next_object(&fake_space.segments_list[data_class], segment, struct nuvo_segment, list_node);
        }
    }
    nuvo_mutex_unlock(&fake_space.mutex);
    return -NUVO_E_OUT_OF_SEGMENT_STRUCTS;
}

bool in_cp(struct nuvo_segment *segment)
{
    for (uint32_t idx = 0; idx < test_vol.cp.segment_count; idx++)
    {
        if ((segment->parcel_index == test_vol.cp.replay_segments[idx].parcel_index) &&
            (segment->block_offset == test_vol.cp.replay_segments[idx].block_offset))
        {
            return true;
        }
    }
    return false;
}

/*
 * fakes gc by inverting the free segment lru.
 * this causes segments already written during the test to be recycled as if they had been gc'd.
 *
 */
void fake_gc()
{
    nuvo_mutex_lock(&fake_space.mutex);
    for (uint8_t data_class = 0; data_class < NUVO_MAX_DATA_CLASSES; data_class++)
    {
        struct nuvo_segment *end = nuvo_dlist_get_tail_object(&fake_space.segments_list[data_class], struct nuvo_segment, list_node);
        struct nuvo_segment *prev = NULL;
        struct nuvo_segment *current = NULL;
        do
        {
            current = nuvo_dlist_remove_head_object(&fake_space.segments_list[data_class], struct nuvo_segment, list_node);
            if (!current)
            {
                break;
            }
            else if (in_cp(current) || !prev)
            {
                nuvo_dlist_insert_tail(&fake_space.segments_list[data_class], &current->list_node);
            }
            else
            {
                nuvo_dlist_insert_before(&prev->list_node, &current->list_node);
            }
            prev = current;
        } while (current != end);
    }
    nuvo_mutex_unlock(&fake_space.mutex);
}

/*
 * finds the best block count to use to pack a segment with the fewest wasted blocks and fewest log requests
 */
int best_fit(int x)
{
    int max = (NUVO_MAX_LOG_DESCRIPTOR_BLOCK_ENTRIES * NUVO_MAX_LOG_DESCRIPTOR_BLOCKS) - (NUVO_SEGMENT_HEADER_BLOCKS + NUVO_MAX_LOG_DESCRIPTOR_BLOCKS);
    int min = NUVO_MAX_LOG_DESCRIPTOR_BLOCK_ENTRIES + NUVO_MAX_LOG_DESCRIPTOR_BLOCKS;
    int res = (((x * NUVO_SEGMENT_SUMMARY_ENTRY_SIZE) + (NUVO_BLOCK_SIZE - 1)) / NUVO_BLOCK_SIZE) + NUVO_SEGMENT_FOOTER_BLOCKS + NUVO_SEGMENT_HEADER_BLOCKS + (NUVO_SEGMENT_FORK_BLOCKS * 2);
    int n = x - res;
    int best = 0;

    do
    {
        best = 0;
        int i = 2;
        while (i <= sqrt(n))
        {
            if ((n % i) == 0)
            {
                if (((n / i) >= min) && ((n / i) <= max))
                {
                    best = (n / i);
                }
            }
            i++;
        }
        if (best != 0)
        {
            break;
        }
        n--;
    } while (best == 0);

    return best;
}

void init_test_vol()
{
    memset(&test_vol, 0, sizeof(struct test_vol));
    for (int j = 0;  j < TEST_VOL_MAX_LOGREQS; j++)
    {
        memset(&test_vol.op_log[j], 0, sizeof(struct io_completion));
    }
    for (int j = 0;  j < MAX_TEST_VOLUME_DEVICES; j++)
    {
        test_vol.devices[j] = &test_devs[j];
    }
    nuvo_mutex_init(&test_vol.cp_mutex);
    nuvo_cond_init(&test_vol.cp_cond);
}

void init_test_device_array()
{
    for (int i = 0; i < MAX_TEST_DEVICES; i++)
    {
        memset(test_devs[i].name, 0, sizeof(test_devs[i].name));
        uuid_generate(test_devs[i].uuid);
        test_devs[i].device_size = TEST_DEVICE_SIZE;
        test_devs[i].parcel_size = TEST_DEVICE_PARCEL_SIZE;
        memset(&test_devs[i].device_info, 0, sizeof(test_devs[i].device_info));
        memset(&test_devs[i].op_info, 0, sizeof(struct io_completion));
        for (int j = 0;  j < TEST_DEVICE_MAX_IOREQS; j++)
        {
            memset(&test_devs[i].op_read[j], 0, sizeof(struct io_completion));
            memset(&test_devs[i].op_write[j], 0, sizeof(struct io_completion));
        }
        for (int j = 0;  j < TEST_DEVICE_MAX_PARCELS; j++)
        {
            memset(&test_devs[i].op_alloc[j], 0, sizeof(struct io_completion));
            memset(&test_devs[i].op_free[j], 0, sizeof(struct io_completion));
            memset(&test_devs[i].op_open[j], 0, sizeof(struct io_completion));
            memset(&test_devs[i].op_close[j], 0, sizeof(struct io_completion));
        }
        test_devs[i].write_io_stats.size_hist = test_devs[i].write_size_hist;
        test_devs[i].write_io_stats.latency_hist = test_devs[i].write_latency_hist;
        test_devs[i].read_io_stats.size_hist = test_devs[i].read_size_hist;
        test_devs[i].read_io_stats.latency_hist = test_devs[i].read_latency_hist;
    }
}

/*
 * a callback needed for the pm setup routines
 */
void pm_test_callback(struct nuvo_io_request *iorp)
{
    struct io_completion *op;

    switch(iorp->operation)
    {
    case NUVO_OP_READ:
    case NUVO_OP_WRITE:
    case NUVO_OP_OPEN:
    case NUVO_OP_CLOSE:
    case NUVO_OP_ALLOC:
    case NUVO_OP_FREE:
    case NUVO_OP_DEV_INFO:
        op = (struct io_completion *)iorp->tag.ptr;
        if (op != NULL)
        {
            op->io_complete = 1;
        }
        ck_assert_int_eq(iorp->status, 0);
        break;
    default:
        break;
    }
    sem_post(&sem);
}

/*
 * used by test program to get the segment information give an block offset within the segment
 */
struct nuvo_segment *get_segment_info(uint32_t parcel_index, uint32_t block_offset)
{
    for (uint32_t i = 0; i < MAX_TEST_DEVICES; i++)
    {
        struct test_device *device = &test_devs[i];
        struct test_segment *test_segment = nuvo_dlist_get_head_object(&device->segment_list, struct test_segment, list_node);
        while (test_segment != NULL)
        {
            if ((test_segment->nuvo_segment.parcel_index == parcel_index) &&
                ((block_offset >= test_segment->nuvo_segment.block_offset) && (block_offset <= test_segment->nuvo_segment.block_offset)))
            {
                return &test_segment->nuvo_segment;
            }
            test_segment = nuvo_dlist_get_next_object(&device->segment_list, test_segment, struct test_segment, list_node);
        }
    }
    return NULL;
}

/*
 * this callback needs to be called by nuvo_log_io_complete when all io is completed.
 */
void log_io_test_callback(struct nuvo_log_request *log_req)
{
    struct io_completion *op;
    sem_t *snap_sem;

    switch (log_req->operation)
    {
        case NUVO_LOG_OP_DATA:
        case NUVO_LOG_OP_GC:
        case NUVO_LOG_OP_MAP:
            op = (struct io_completion *)log_req->tag.ptr;
            op->io_complete = 1;

            if (log_req->status != 0)
            {
                ck_assert(log_req->status == NUVO_ECANCELED);
            }
            else
            {
                nuvo_log_ack_sno(log_req);
            }

            sem_post(&op->log_io_sem);

            break;
        case NUVO_LOG_OP_CREATE_SNAP:
        case NUVO_LOG_OP_DELETE_SNAP:
            snap_sem = (sem_t *)log_req->tag.ptr;
            nuvo_log_ack_sno(log_req);
            sem_post(snap_sem);
            break;
        default:
            ck_abort_msg("%s: invalid operation %d in the nuvo_log_request.", __func__, log_req->operation);
        break;
    }
}

/*
 * this is the callback function to be called at the end of replay
 */
void replay_test_callback(struct nuvo_log_replay_request *replay_req)
{
    struct nuvo_logger *logger = &replay_req->vol->log_volume.logger;
    uint32_t txn_count = logger->sequence_no - replay_req->sequence_no;

    printf("replay completed: replayed %u transactions sequence no: %lu - %lu \n", txn_count, replay_req->sequence_no, logger->sequence_no);
    sem_post(&replay_sem);
}

/*
 * allocates a bunch of parcels on a device
 */
int allocate_parcels(struct test_device *device, uint32_t parcel_cnt)
{
    uuid_t device_uuid;
    uuid_t volume_uuid;
    struct nuvo_dlist submit_list;
    nuvo_dlist_init(&submit_list);

    uuid_copy(device_uuid, device->uuid);
    uuid_copy(volume_uuid, device->volume_uuid);

    /* allocate all parcels */
    uint32_t submit_cnt = 0;
    while (submit_cnt < parcel_cnt)
    {
        struct nuvo_io_request *io_req = &device->op_alloc[submit_cnt].io_req;
        device->op_alloc[submit_cnt].io_complete = 0;
        nuvo_dlnode_init(&io_req->list_node);

        uuid_copy(io_req->alloc.device_uuid, device_uuid);
        uuid_copy(io_req->alloc.volume_uuid, volume_uuid);
        io_req->operation = NUVO_OP_ALLOC;
        io_req->tag.ptr = &device->op_alloc[submit_cnt];
        io_req->callback=(void *)&pm_test_callback;

        nuvo_dlist_insert_tail(&submit_list, &io_req->list_node);
        submit_cnt++;
    }

    (void)nuvo_pr_submit(&submit_list);

    uint32_t done = 0;
    uint32_t failed = 0;

    for (uint32_t i = 0; i < submit_cnt; i++)
    {
        sem_wait(&sem);
    }

    for (uint32_t i = 0; i < submit_cnt; i++)
    {
        if (device->op_alloc[i].io_complete != 0)
        {
            if (device->op_alloc[i].io_req.status != 0)
            {
                failed++;
            }
            done++;
        }
    }

    ck_assert_int_eq(done, submit_cnt);

    return (done - failed);
}

/*
 * opens or closes a bunch of parcels on a device
 */
int open_close_parcels(struct test_device *device, uint32_t parcel_cnt, int op)
{
    uint32_t submit_cnt = 0;
    struct nuvo_dlist submit_list;

    nuvo_dlist_init(&submit_list);

    while (submit_cnt < parcel_cnt)
    {
        /* uses results of the previous parcel alloc stored in op_alloc[] */
        device->op_open[submit_cnt].io_complete = 0;
        struct nuvo_io_request *io_req = &device->op_open[submit_cnt].io_req;
        nuvo_dlnode_init(&io_req->list_node);

        if (op == NUVO_OP_OPEN)
        {
            uuid_copy(io_req->open.parcel_uuid, device->op_alloc[submit_cnt].io_req.alloc.parcel_uuid);
            uuid_copy(io_req->open.volume_uuid, device->op_alloc[submit_cnt].io_req.alloc.volume_uuid);
            uuid_copy(io_req->open.device_uuid, device->op_alloc[submit_cnt].io_req.alloc.device_uuid);
            io_req->open.reopen_flag = 0;
            io_req->operation = NUVO_OP_OPEN;
            io_req->tag.ptr = &device->op_open[submit_cnt];
        }
        else
        {
            io_req->close.parcel_desc = device->op_open[submit_cnt].io_req.open.parcel_desc;
            io_req->operation = NUVO_OP_CLOSE;
            io_req->tag.ptr = &device->op_close[submit_cnt];
        }
        io_req->callback=(void *)pm_test_callback;

        nuvo_dlist_insert_tail(&submit_list, &io_req->list_node);
        submit_cnt++;
    }

    (void)nuvo_pr_submit(&submit_list);

    uint32_t done = 0;
    uint32_t failed = 0;

    for (uint32_t i = 0; i < submit_cnt; i++)
    {
        sem_wait(&sem);
    }

    for (uint32_t i = 0; i < submit_cnt; i++)
    {
        if (op == NUVO_OP_OPEN)
        {
            if (device->op_open[i].io_complete != 0)
            {
                if (device->op_open[i].io_req.status != 0)
                {
                    failed++;
                }
                done++;
            }
        }
        else
        {
            if (device->op_close[i].io_complete != 0)
            {
                if (device->op_close[i].io_req.status != 0)
                {
                    failed++;
                }
                done++;
            }
        }
    }

    ck_assert_int_eq(done, submit_cnt);

    return (done - failed);
}

/* wrapper */
int open_parcels(struct test_device *device, uint32_t parcel_cnt)
{
    return (open_close_parcels(device, parcel_cnt, NUVO_OP_OPEN));
}

/* wrapper */
int close_parcels(struct test_device *device, uint32_t parcel_cnt)
{
    return (open_close_parcels(device, parcel_cnt, NUVO_OP_CLOSE));
}

/*
 * tests the segment_logger async io interface by writing blocks of random data to the device
 * can be used to send 1 or more data logging operations.
 *
 * assigns lun_id and block offsets for the data blocks sequentially.
 *
 * vol - the volume.
 * submit_cnt = the number of log requests to be submitted the to volume.
 * block_cnt = the number of data blocks in each log request
 * device_offset - the starting address to be recorded in the bno.
 * log_op_type - the type of log operation.
 * data_class - the data class (i.e. the free list the test should use).
 * use_constant - if false, blocks will contain random data.
 * op_idx - an index into the pre-allocated log_reqs available for this test.
 * cleanup - if true, free all data buffers.
 *
 */
void *log_write_sequential(void *args)
{
    struct log_write_sequential_params *p = args;
    struct test_vol *vol = p->vol;
    uint32_t submit_cnt = p->submit_cnt;
    uint32_t block_cnt = p->block_cnt;
    uint64_t device_offset = p->device_offset;
    int log_op_type = p->log_op_type;
    int data_class = p->data_class;
    int cv_mix = p->cv_mix;
    int op_idx = p->op_idx;
    bool cleanup = p->cleanup;

    uint64_t constant_value = (0xAFFFBFFFCFFFDFFF);

    assert(block_cnt <= NUVO_MAX_IO_SIZE);

    for (uint32_t idx = op_idx; idx < op_idx + submit_cnt; idx++)
    {
        uint32_t cv_count = (uint32_t)(block_cnt * ((double)cv_mix / 100));
        uint32_t rnd_count = block_cnt - cv_count;
        struct nuvo_log_request *log_req = &vol->op_log[idx].log_req;
        memset(log_req, 0, sizeof(struct nuvo_log_request));

        /* create a log io request */
        nuvo_dlnode_init(&log_req->list_node);
        log_req->operation = log_op_type;
        log_req->atomic = true;
        log_req->data_class = data_class;
        log_req->block_count = block_cnt;
        log_req->callback = (void *)&log_io_test_callback;
        log_req->tag.ptr = &vol->op_log[idx];
        log_req->vs_ptr = &vol->nuvo_vol;

        /* allocates block_cnt aligned 4K buffers */
        /* fills in the required metadata for each block */
        for (uint32_t i = 0; i < block_cnt; i++)
        {
            bool use_constant;
            memset(&log_req->log_io_blocks[i], 0, sizeof(struct nuvo_log_io_block));

            /* round robin cv and rand data blocks */
            if (((i % 2) && cv_count) || rnd_count == 0)
            {
                use_constant = true;
                cv_count--;
            }
            else
            {
                use_constant = false;
                rnd_count--;
            }

            if ((log_op_type == NUVO_LOG_OP_MAP) && use_constant)
            {
                log_req->log_io_blocks[i].log_entry_type = NUVO_LE_MAP_L0;
                log_req->log_io_blocks[i].map_is_zero = true;
                log_req->log_io_blocks[i].data = NULL;
                log_req->log_io_blocks[i].bno = device_offset;
                LOG_PIT_INFO_SET_DATA(log_req->log_io_blocks[i].pit_info, 1, 2);  // 2 is fake pit id.
                log_req->log_io_blocks[i].gc_block_hash = 0;
                log_req->log_io_blocks[i].gc_media_addr.parcel_index = 0;
                log_req->log_io_blocks[i].gc_media_addr.block_offset = 0;
            }
            else
            {
                posix_memalign(&log_req->log_io_blocks[i].data, NUVO_BLOCK_SIZE, NUVO_BLOCK_SIZE);

                uint64_t *ptr = log_req->log_io_blocks[i].data;
                for (uint32_t j = 0; j < NUVO_BLOCK_SIZE / sizeof(uint64_t); j++)
                {
                    if (use_constant)
                    {
                        ptr[j] = constant_value;
                    }
                    else
                    {
                        ptr[j] = rand();
                    }
                }

                /* meta data to be logged that will be logged in the descriptor */
                log_req->log_io_blocks[i].log_entry_type = (log_op_type == NUVO_LOG_OP_MAP) ? NUVO_LE_MAP_L1 : NUVO_LE_DATA;
                LOG_PIT_INFO_SET_DATA(log_req->log_io_blocks[i].pit_info, 1, 2);  // 2 is fake pit id.
                log_req->log_io_blocks[i].bno = device_offset; /* the device relative lba for this block */
                if (log_op_type == NUVO_LOG_OP_GC)
                {
                    log_req->log_io_blocks[i].gc_block_hash = nuvo_hash(ptr, NUVO_BLOCK_SIZE);
                    log_req->log_io_blocks[i].gc_media_addr.parcel_index = 0;
                    log_req->log_io_blocks[i].gc_media_addr.block_offset = 0;
                }
                else
                {
                    log_req->log_io_blocks[i].gc_block_hash = 0; /* not used except for GC, just set to 0 */
                    log_req->log_io_blocks[i].gc_media_addr.parcel_index = 0; /* not not used except for GC, just set to 0 */
                    log_req->log_io_blocks[i].gc_media_addr.block_offset = 0; /* not used except for GC, just set to 0 */
                }
            }

            device_offset += NUVO_BLOCK_SIZE;
        }

        /* the log io has been prepared, send it for write */
        (void)nuvo_log_submit(log_req);
    }

    for (uint32_t idx = op_idx; idx < op_idx + submit_cnt; idx++)
    {
        sem_wait(&vol->op_log[idx].log_io_sem);
    }

    for (uint32_t idx = op_idx; idx < op_idx + submit_cnt; idx++)
    {
        ck_assert_int_eq(vol->op_log[idx].io_complete, 1);
        ck_assert_int_eq(vol->op_log[idx].log_req.status, 0);
    }

    /* write a create snapshot entry in the log */
    sem_t snap_sem;
    struct nuvo_log_request log_req;

    sem_init(&snap_sem, 0, 0);
    memset(&log_req, 0, sizeof(struct nuvo_log_request));
    log_req.operation = NUVO_LOG_OP_CREATE_SNAP;
    log_req.atomic = true;
    log_req.data_class = data_class;
    log_req.pit_id = 1;
    uuid_generate(log_req.pit_uuid);
    log_req.callback = (void *)&log_io_test_callback;
    log_req.tag.ptr = &snap_sem;
    log_req.vs_ptr = &vol->nuvo_vol;

    (void)nuvo_log_submit(&log_req);
    sem_wait(&snap_sem);

    if (cleanup)
    {
        for (uint32_t idx = op_idx; idx < op_idx + submit_cnt; idx++)
        {
            for (uint32_t i = 0; i < block_cnt; i++)
            {
                if (vol->op_log[idx].log_req.log_io_blocks[i].data != NULL)
                {
                    free(vol->op_log[idx].log_req.log_io_blocks[i].data);
                    vol->op_log[idx].log_req.log_io_blocks[i].data = NULL;
                }
            }
        }
    }

    return NULL;
}

/*
 * formats, opens and creates parcels on test device
 * optionally opens all the parcels
 * returns the number of parcels allocated.
 */
int create_open_alloc_test_device(int idx, enum nuvo_dev_type device_type, bool open_flag)
{
    int ret;
    int allocated = 0;

    ret = nuvo_pm_device_format(test_devs[idx].name, test_devs[idx].uuid, test_devs[idx].parcel_size);
    ck_assert_int_eq(ret, 0);

    test_devs[idx].device_type = device_type;
    ret = nuvo_pm_device_open(test_devs[idx].name, test_devs[idx].uuid, test_devs[idx].device_type);
    ck_assert_int_eq(ret, 0);

    ret = nuvo_pm_device_info(test_devs[idx].uuid, &test_devs[idx].device_info);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(test_devs[idx].device_info.parcels_allocated, 0);
    ck_assert_int_eq(test_devs[idx].device_info.parceltable_full, 0);
    ck_assert_int_eq(test_devs[idx].device_info.device_type, test_devs[idx].device_type);

    allocated = allocate_parcels(&test_devs[idx], test_devs[idx].device_info.max_parcels);

    memset(&test_devs[idx].device_info, 0, sizeof(struct device_info));
    ret = nuvo_pm_device_info(test_devs[idx].uuid, &test_devs[idx].device_info);
    ck_assert_int_eq(ret, 0);
    ck_assert_int_eq(allocated, test_devs[idx].device_info.parcels_allocated);
    ck_assert_int_eq(test_devs[idx].device_info.parcels_allocated, test_devs[idx].device_info.max_parcels);
    ck_assert_int_eq(test_devs[idx].device_info.parceltable_full, 1);

    if (open_flag)
    {
        ret = open_parcels(&test_devs[idx], allocated);
        ck_assert_int_eq(ret, allocated);
    }

    return allocated;
}

// assign segments from the given device to the specified data_class
int alloc_volume_segments(struct test_device *device, uint32_t data_class)
{
    int segment_cnt = 0;
    struct test_segment *test_segment;
    test_segment = nuvo_dlist_get_head_object(&device->segment_list, struct test_segment, list_node);
    while (test_segment)
    {
        test_segment->nuvo_segment.data_class = data_class;
        nuvo_dlist_insert_tail(&fake_space.segments_list[data_class], &test_segment->nuvo_segment.list_node);
        segment_cnt++;
        test_segment = nuvo_dlist_get_next_object(&device->segment_list, test_segment, struct test_segment, list_node);
    }

   return segment_cnt;
}

/*
 * creates a list of segments on this device.
 * these segments can be subsequently allocated to the volume series.
 */
void init_device_segment_list(struct test_device *device, uint32_t parcel_cnt)
{
    uint32_t parcel_segment_cnt = device->parcel_size / TEST_DEVICE_SEGMENT_SIZE;

    nuvo_dlist_init(&device->segment_list);

    printf("using test device: %s\n", device->name);
    for (uint32_t i = 0; i < parcel_cnt; i++)
    {
        uint32_t block_offset = 0;
        for (uint32_t j = 0; j < parcel_segment_cnt; j++)
        {
            struct test_segment *test_segment = malloc(sizeof(struct test_segment));
            memset(test_segment, 0, sizeof(struct test_segment));

            test_segment->nuvo_segment.parcel_desc = device->op_open[i].io_req.open.parcel_desc;
            test_segment->nuvo_segment.parcel_index = device->op_open[i].io_req.open.parcel_desc;  /* abuse of the parcel index for testing */
            test_segment->nuvo_segment.block_offset = block_offset;
            test_segment->nuvo_segment.block_count = TEST_DEVICE_SEGMENT_BLOCKS;
            test_segment->nuvo_segment.device_index = TEST_DEVICE_INDEX(device);
            test_segment->nuvo_segment.device_type = device->device_type;

            nuvo_dlist_insert_tail(&device->segment_list, &test_segment->list_node);

            block_offset = block_offset + TEST_DEVICE_SEGMENT_BLOCKS;
        }
    }
}

/*
 * frees the list of segments on this device.
 */
void free_device_segment_list(struct test_device *device)
{

    struct test_segment *test_segment = nuvo_dlist_remove_head_object(&device->segment_list, struct test_segment, list_node);
    while (test_segment != NULL)
    {
        free(test_segment);
        test_segment = nuvo_dlist_remove_head_object(&device->segment_list, struct test_segment, list_node);
    }
}

/*
 * this test creates a device and parcels, then performs various segment logging operations into segments on those parcels
 *
 * device_cnt - the number of devices allocated to the volume.
 * thread_cnt - the number of threads that will submit log requests.
 * cv_mix - percentage constant value blocks.
 * submit_cnt - the number of submits per thread, if 0 a value is calculated.
 */
int test_log_write(uint32_t device_cnt, uint32_t thread_cnt, uint32_t cv_mix, uint32_t submit_cnt, uint8_t multi_class, uint8_t test_gc, enum test_device_type test_device_type, uint8_t cp_trigger_type)
{
    nuvo_return_t ret;
    int op_idx = 0;
    uint32_t allocated_cnt;
    struct nuvo_logger *logger = &test_vol.nuvo_vol.log_volume.logger;
    uint32_t segment_cnt = 0;

    uuid_generate(test_vol.nuvo_vol.vs_uuid);

    for (uint32_t i = 0; i < device_cnt; i++)
    {
        enum nuvo_dev_type device_type;
        switch (test_device_type)
        {
        case TEST_DEVICE_ALL:
            if (i % 2)
            {
                device_type = NUVO_DEV_TYPE_HDD;
            }
            else
            {
                device_type = NUVO_DEV_TYPE_SSD;
            }
            break;
        case TEST_DEVICE_HDD:
            device_type = NUVO_DEV_TYPE_HDD;
            break;
        case TEST_DEVICE_SSD:
            device_type = NUVO_DEV_TYPE_SSD;
            break;
        default:
            printf("invalid test device type!\n");
            ck_assert(true);
            break;
        }
        allocated_cnt = create_open_alloc_test_device(i, device_type, true);
        init_device_segment_list(&test_devs[i], allocated_cnt);
        test_vol.allocated_device_count++;
        if (multi_class)
        {
            segment_cnt += alloc_volume_segments(&test_devs[i], i % 2);
        }
        else
        {
            segment_cnt += alloc_volume_segments(&test_devs[i], NUVO_DATA_CLASS_A);
        }
    }

    uint32_t block_cnt = best_fit(TEST_DEVICE_SEGMENT_BLOCKS);
    uint32_t free_cnt = TEST_DEVICE_SEGMENT_BLOCKS - ((((TEST_DEVICE_SEGMENT_BLOCKS * NUVO_SEGMENT_SUMMARY_ENTRY_SIZE) + (NUVO_BLOCK_SIZE - 1)) / NUVO_BLOCK_SIZE) + NUVO_SEGMENT_FOOTER_BLOCKS + NUVO_SEGMENT_HEADER_BLOCKS + NUVO_SEGMENT_FORK_BLOCKS);

    /* calculate the submits per thread, if value not provided */
    if (submit_cnt == 0)
    {
        /* cv detection is disabled for HDDs */
        if ((cv_mix == 100) && (test_device_type == TEST_DEVICE_SSD))
        {
            submit_cnt = TEST_VOL_MAX_LOGREQS / thread_cnt;
        }
        else
        {
            submit_cnt = ((segment_cnt * ((free_cnt / block_cnt) - 1)) / thread_cnt) * .6;
        }
    }

    /* sets the test to get a checkpoint after half the io has completed */
    ck_assert(test_vol.nuvo_vol.log_volume.logger.cp_trigger_log_io_count_limit == NUVO_CP_TRIGGER_LOG_IO_COUNT_LIMIT);
    ck_assert(test_vol.nuvo_vol.log_volume.logger.cp_trigger_segments_used_count_limit == NUVO_CP_TRIGGER_SEGMENTS_USED_COUNT_LIMIT);
    test_vol.nuvo_vol.log_volume.logger.cp_trigger_log_io_count_limit = (submit_cnt * thread_cnt) / 2;
    test_vol.nuvo_vol.log_volume.logger.cp_trigger_segments_used_count_limit = ((((submit_cnt * thread_cnt) * block_cnt) / TEST_DEVICE_SEGMENT_BLOCKS) / 2);
    test_vol.nuvo_vol.log_volume.logger.cp_trigger_type = cp_trigger_type;

    printf("  total parcels allocated : %u or %u blocks\n", allocated_cnt * device_cnt, allocated_cnt * device_cnt * TEST_DEVICE_PARCEL_BLOCKS);
    printf(" total segments allocated : %u x %u blocks\n", segment_cnt, TEST_DEVICE_SEGMENT_BLOCKS);
    printf("                  threads : %d\n", thread_cnt);
    printf("       submits per thread : %u\n", submit_cnt);
    printf("            total submits : %u\n", thread_cnt * submit_cnt);
    printf("            cv percentage : %u %%\n", cv_mix);
    printf("              device type : %s\n", (test_device_type == TEST_DEVICE_ALL) ? "HDD & SSD" : ((test_device_type == TEST_DEVICE_HDD) ? "HDD" : "SSD"));
    printf("   data blocks per submit : %u\n", (uint32_t)((block_cnt - NUVO_MAX_LOG_DESCRIPTOR_BLOCKS) - ((block_cnt - NUVO_MAX_LOG_DESCRIPTOR_BLOCKS) * ((double)cv_mix / 100))));
    printf("          cp trigger type : %u\n", cp_trigger_type);
    if (cp_trigger_type != NUVO_CP_TRIGGER_DISABLED)
    {
        printf("            checkpoint at : %lu\n", (cp_trigger_type == NUVO_CP_TRIGGER_LOG_IO_COUNT) ? test_vol.nuvo_vol.log_volume.logger.cp_trigger_log_io_count_limit : test_vol.nuvo_vol.log_volume.logger.cp_trigger_segments_used_count_limit);
    }

    struct nuvo_log_replay_request replay_req;
    replay_req.sequence_no = TEST_VOL_STARTING_SEQUENCE_NO;
    replay_req.segment_cnt_sequence_no = TEST_VOL_STARTING_SEG_CNT_SEQUENCE_NO;
    replay_req.vol = &test_vol.nuvo_vol;
    replay_req.replay_segments[0].parcel_index = 0; // the root segment is always 0:0 in the ut
    replay_req.replay_segments[0].block_offset = 0;
    replay_req.replay_segments[0].subclass = NUVO_SEGMENT_TYPE_DATA;
    replay_req.segment_count = 1;

    // since the logger is layered on the rl, enable the cache for cache io code coverage
    ret = nuvo_cache_vol_init(&test_vol.nuvo_vol);
    ck_assert_int_eq(ret, 0);

    uint64_t cache_size = 0;
    uint64_t alloc_unit_size = 0;
    for (int i = 0; i < MAX_TEST_CACHE_DEVICES; i++)
    {
        ret = nuvo_cache_device_open(cache_dev[i].name, cache_dev[i].uuid, &cache_dev[i].size_bytes, &alloc_unit_size);
        cache_size += cache_dev[i].size_bytes;
        ck_assert_int_eq(ret, 0);
    }
    printf("cache is %lu bytes with allocation unit size of: %lu\n", cache_size, alloc_unit_size);
    uint32_t total_units = cache_size / alloc_unit_size;
    uint32_t remaining_units = total_units;

    // force the cache allocation for the test volume to use 2 cache fragments
    // to do this 3 fake volumes are allocated the minimal amount cache.
    // then the second volumes cache is deleted which creates a fragment.
    // when the cache is allocated for the test volume it will be allocated that fragment
    // and another fragment with the remainder of the requested cache space.
    for (int i = 0; i < 3; i++)
    {
        ret = nuvo_cache_vol_init(&fake_vol[i]);
        ck_assert_int_eq(ret, 0);
    }

    uint32_t alloc_units;
    for (int i = 0; i < 3; i++)
    {
        uuid_generate(fake_vol[i].vs_uuid);
        alloc_units = 1;
        remaining_units -= alloc_units;
        ret = nuvo_cache_vol_allocate(&fake_vol[i], alloc_units * alloc_unit_size);
        ck_assert_int_eq(ret, 0);
    }
    ret = nuvo_cache_vol_allocate(&fake_vol[1], 0);
    remaining_units++;
    ck_assert_int_eq(ret, 0);

    // now allocate half the remainder of the cache to the test volume.
    alloc_units = remaining_units / 2;
    remaining_units -= alloc_units;
    ret = nuvo_cache_vol_allocate(&test_vol.nuvo_vol, alloc_units * alloc_unit_size);
    ck_assert_int_eq(ret, 0);

    nuvo_log_sync_replay(&replay_req);
    printf("%s: new volume replay completed.\n", __func__);

    for (uint32_t i = 0; i <thread_cnt; i++)
    {
        test_th[i].param.vol = &test_vol;
        test_th[i].param.submit_cnt = submit_cnt;
        test_th[i].param.block_cnt = block_cnt - NUVO_MAX_LOG_DESCRIPTOR_BLOCKS;
        test_th[i].param.device_offset = 0;
        if (test_gc && !(i % 2))
        {
            test_th[i].param.log_op_type = NUVO_LOG_OP_GC;
        }
        else if (!(i % 2))
        {
            test_th[i].param.log_op_type = NUVO_LOG_OP_DATA;
        }
        else
        {
            test_th[i].param.log_op_type = NUVO_LOG_OP_MAP;
        }
        test_th[i].param.cv_mix = cv_mix;
        test_th[i].param.op_idx = op_idx + (submit_cnt * i);
        test_th[i].param.cleanup = true;
        if (multi_class)
        {
            test_th[i].param.data_class = i % 2;
        }
        else
        {
            test_th[i].param.data_class = NUVO_DATA_CLASS_A;
        }

        (void) pthread_create(&test_th[i].th, NULL, log_write_sequential, &test_th[i].param);
    }

    /* resize the cache */
    alloc_units = remaining_units;
    remaining_units -= alloc_units;
    ret = nuvo_cache_vol_allocate(&test_vol.nuvo_vol, alloc_units * alloc_unit_size);
    ck_assert_int_eq(ret, 0);

    if (cp_trigger_type != NUVO_CP_TRIGGER_DISABLED)
    {
        nuvo_mutex_lock(&test_vol.cp_mutex);
        while (!test_vol.cp_requested)
        {
            nuvo_cond_wait(&test_vol.cp_cond, &test_vol.cp_mutex);
        }
        test_vol.cp_requested = false;
        nuvo_mutex_unlock(&test_vol.cp_mutex);
        test_vol.cp.sequence_no = nuvo_log_freeze_map_updates(&test_vol.nuvo_vol);
        ck_assert(test_vol.cp.sequence_no >= test_vol.nuvo_vol.log_volume.logger.cp_trigger_log_io_count_limit);
        nuvo_log_get_open_segments(&test_vol.nuvo_vol, test_vol.cp.sequence_no, test_vol.cp.replay_segments, &test_vol.cp.segment_count);

        fake_gc();

        nuvo_log_unfreeze_map_updates(&test_vol.nuvo_vol);
    }
    else
    {
        /* fake CPs were disabled during test, replay everything */
        test_vol.cp.sequence_no = TEST_VOL_STARTING_SEQUENCE_NO;
        test_vol.cp.replay_segments[0].parcel_index = 0;
        test_vol.cp.replay_segments[0].block_offset = 0;
        test_vol.cp.replay_segments[0].subclass = NUVO_SEGMENT_TYPE_DATA;
        test_vol.cp.segment_count = 1;
    }

    for (uint32_t i = 0; i < thread_cnt; i++)
    {
        pthread_join(test_th[i].th, NULL);
    }

    /* Wait for in flight io requests to complete */
    nuvo_mutex_lock(&logger->pr_io_count_mutex);
    while (logger->pr_io_count != 0)
    {
        nuvo_cond_wait(&logger->pr_io_count_zero_cond, &logger->pr_io_count_mutex);
    }
    nuvo_mutex_unlock(&logger->pr_io_count_mutex);

    /* Wait for completed io requests to be acknowledged */
    nuvo_mutex_lock(&logger->log_io_count_mutex);
    while (logger->log_io_count != 0)
    {
        nuvo_cond_wait(&logger->log_io_count_zero_cond, &logger->log_io_count_mutex);
    }
    nuvo_mutex_unlock(&logger->log_io_count_mutex);

    uint64_t final_sequence_no = logger->sequence_no;
    uint64_t final_lowest_sequence_no = logger->lowest_sequence_no;
    struct logger_segment *active_segment = logger->active_segment;
    printf("%s: final logger sequence number : %lu\n", __func__, final_sequence_no);
    printf("%s: final lowest sequence number : %lu\n", __func__, final_lowest_sequence_no);
    printf("%s:         final active segment : SEG [%04u:%05u]\n", __func__, active_segment->segment->parcel_index, active_segment->segment->block_offset);

    /* copy the complete logger state at the end of write test for comparison after replay */
    memcpy(&old_logger, &test_vol.nuvo_vol.log_volume.logger, sizeof(struct nuvo_logger));

    printf("%s: shutting down log.\n", __func__);
    ret = nuvo_log_shutdown(&test_vol.nuvo_vol);
    ck_assert(ret == 0);

    printf("%s: re-initializing log.\n", __func__);
    ret = nuvo_log_init(&test_vol.nuvo_vol);
    ck_assert(ret == 0);
    ck_assert(test_vol.nuvo_vol.log_volume.logger.sequence_no == 0);

    /* resize the cache down */
    alloc_units = total_units / 2;
    ret = nuvo_cache_vol_allocate(&test_vol.nuvo_vol, alloc_units * alloc_unit_size);
    ck_assert_int_eq(ret, 0);


    printf("%s: starting replay at sequence number: %lu\n", __func__, test_vol.cp.sequence_no);

    replay_req.sequence_no = test_vol.cp.sequence_no;
    replay_req.vol = &test_vol.nuvo_vol;
    replay_req.callback = replay_test_callback;
    replay_req.segment_count = 0;

    for (uint32_t idx = 0; idx < test_vol.cp.segment_count; idx++)
    {
        replay_req.replay_segments[idx].parcel_index = test_vol.cp.replay_segments[idx].parcel_index;
        replay_req.replay_segments[idx].block_offset = test_vol.cp.replay_segments[idx].block_offset;
        replay_req.replay_segments[idx].subclass = test_vol.cp.replay_segments[idx].subclass;
        replay_req.segment_count++;
    }

    sem_init(&replay_sem, 0, 0);
    nuvo_log_replay(&replay_req);
    sem_wait(&replay_sem);
    sem_destroy(&replay_sem);

    printf("%s: replay completed\n", __func__);
    printf("       sequence number check : %lu vs %lu\n", final_sequence_no, test_vol.nuvo_vol.log_volume.logger.sequence_no);
    printf("lowest sequence number check : %lu vs %lu\n", final_lowest_sequence_no, test_vol.nuvo_vol.log_volume.logger.lowest_sequence_no);

    ck_assert(final_sequence_no == test_vol.nuvo_vol.log_volume.logger.sequence_no);
    ck_assert(final_lowest_sequence_no == test_vol.nuvo_vol.log_volume.logger.lowest_sequence_no);

    printf("%s: starting shutdown.\n", __func__);
    ret = nuvo_log_shutdown(&test_vol.nuvo_vol);
    ck_assert(ret == 0);

    nuvo_cache_vol_destroy(&test_vol.nuvo_vol);

    printf("%s: re-initializing log.\n", __func__);
    ret = nuvo_log_init(&test_vol.nuvo_vol);
    ck_assert(ret == 0);
    ck_assert(test_vol.nuvo_vol.log_volume.logger.sequence_no == 0);

    /* change the volume uuid and try to replay */
    uuid_generate(test_vol.nuvo_vol.vs_uuid);
    replay_req.sequence_no = TEST_VOL_STARTING_SEQUENCE_NO;
    replay_req.segment_cnt_sequence_no = TEST_VOL_STARTING_SEG_CNT_SEQUENCE_NO;
    replay_req.vol = &test_vol.nuvo_vol;
    replay_req.replay_segments[0].parcel_index = test_vol.cp.replay_segments[0].parcel_index;
    replay_req.replay_segments[0].block_offset = test_vol.cp.replay_segments[0].block_offset;
    replay_req.replay_segments[0].subclass = NUVO_SEGMENT_TYPE_DATA;
    replay_req.segment_count = 1;

    nuvo_log_sync_replay(&replay_req);
    ck_assert(TEST_VOL_STARTING_SEQUENCE_NO == test_vol.nuvo_vol.log_volume.logger.sequence_no);
    ck_assert(TEST_VOL_STARTING_SEQUENCE_NO == test_vol.nuvo_vol.log_volume.logger.lowest_sequence_no);

    printf("%s: starting shutdown.\n", __func__);
    ret = nuvo_log_shutdown(&test_vol.nuvo_vol);
    ck_assert(ret == 0);

    /* close the parcels and the device */
    for (uint32_t i = 0; i < device_cnt; i++)
    {
        ret = close_parcels(&test_devs[i], allocated_cnt);
        ck_assert_int_eq(ret, allocated_cnt);

        ret = nuvo_pm_device_close(test_devs[i].uuid);
        ck_assert_int_eq(ret, 0);

        free_device_segment_list(&test_devs[i]);
    }

    for (int i = 0; i < 3; i++)
    {
        nuvo_cache_vol_destroy(&fake_vol[i]);
    }

    return 0;
}

START_TEST(nuvo_sl_test_log_write_4d_2t_25cv_gc)
{
    printf("\n%s\n", __func__);
    ck_assert(test_log_write(4, 2, 25, 0, 0, 1, TEST_DEVICE_SSD, NUVO_CP_TRIGGER_LOG_IO_COUNT) == 0);
}
END_TEST

START_TEST(nuvo_sl_test_log_write_2d_2t_0cv_gc)
{
    printf("\n%s\n", __func__);
    ck_assert(test_log_write(2, 2, 0, 0, 0, 1, TEST_DEVICE_SSD, NUVO_CP_TRIGGER_SEGMENTS_USED_COUNT) == 0);
}
END_TEST

START_TEST(nuvo_sl_test_log_write_2d_1t_0cv)
{
    printf("\n%s\n", __func__);
    ck_assert(test_log_write(2, 1, 0, 0, 0, 0, TEST_DEVICE_SSD, NUVO_CP_TRIGGER_SEGMENTS_USED_COUNT) == 0);
}
END_TEST

START_TEST(nuvo_sl_test_log_write_2d_1t_0cv_1s)
{
    printf("\n%s\n", __func__);
    ck_assert(test_log_write(2, 1, 0, 1, 0, 0, TEST_DEVICE_SSD, NUVO_CP_TRIGGER_DISABLED) == 0);
}
END_TEST

START_TEST(nuvo_sl_test_log_write_2d_1t_100cv_1s)
{
    printf("\n%s\n", __func__);
    ck_assert(test_log_write(2, 1, 100, 1, 0, 0, TEST_DEVICE_SSD, NUVO_CP_TRIGGER_DISABLED) == 0);
}
END_TEST

START_TEST(nuvo_sl_test_log_write_1d_1t_100cv)
{
    printf("\n%s\n", __func__);
    ck_assert(test_log_write(1, 1, 100, 0, 0, 0, TEST_DEVICE_SSD, NUVO_CP_TRIGGER_LOG_IO_COUNT) == 0);
}
END_TEST


START_TEST(nuvo_sl_test_log_write_1d_2t_50cv)
{
    printf("\n%s\n", __func__);
    ck_assert(test_log_write(1, 2, 50, 0, 0, 0, TEST_DEVICE_SSD, NUVO_CP_TRIGGER_LOG_IO_COUNT) == 0);
}
END_TEST

START_TEST(nuvo_sl_test_log_write_1d_1t_0cv)
{
    printf("\n%s\n", __func__);
    ck_assert(test_log_write(1, 1, 0, 0, 0, 0, TEST_DEVICE_SSD, NUVO_CP_TRIGGER_SEGMENTS_USED_COUNT) == 0);
}
END_TEST

START_TEST(nuvo_sl_test_log_write_1d_4t_0cv)
{
    printf("\n%s\n", __func__);
    ck_assert(test_log_write(1, 4, 0, 0, 0, 0, TEST_DEVICE_SSD, NUVO_CP_TRIGGER_SEGMENTS_USED_COUNT) == 0);
}
END_TEST

START_TEST(nuvo_sl_test_log_write_8d_4t_0cv_mc)
{
    printf("\n%s\n", __func__);
    ck_assert(test_log_write(8, 4, 0, 0, 1, 0, TEST_DEVICE_SSD, NUVO_CP_TRIGGER_SEGMENTS_USED_COUNT) == 0);
}
END_TEST

START_TEST(nuvo_sl_test_log_write_2d_2t_0cv_mc)
{
    printf("\n%s\n", __func__);
    ck_assert(test_log_write(2, 2, 0, 0, 1, 0, TEST_DEVICE_SSD, NUVO_CP_TRIGGER_SEGMENTS_USED_COUNT) == 0);
}
END_TEST

START_TEST(nuvo_sl_test_log_write_1d_1t_100cv_hdd)
{
    printf("\n%s\n", __func__);
    ck_assert(test_log_write(1, 1, 100, 0, 0, 0, TEST_DEVICE_HDD, NUVO_CP_TRIGGER_LOG_IO_COUNT) == 0);
}
END_TEST

START_TEST(nuvo_sl_test_log_write_1d_2t_50cv_hdd)
{
    printf("\n%s\n", __func__);
    ck_assert(test_log_write(1, 2, 50, 0, 0, 0, TEST_DEVICE_HDD, NUVO_CP_TRIGGER_LOG_IO_COUNT) == 0);
}
END_TEST

START_TEST(nuvo_sl_test_log_write_2d_2t_100cv_all)
{
    printf("\n%s\n", __func__);
    ck_assert(test_log_write(2, 2, 100, 0, 0, 0, TEST_DEVICE_ALL, NUVO_CP_TRIGGER_LOG_IO_COUNT) == 0);
}
END_TEST

/* wrapper to initialized PR for test */
int64_t pr_test_setup(const uuid_t uuid, uint64_t port)
{
    int64_t ret = nuvo_pr_init(port);
    if (ret == 0)
    {
        nuvo_pr_set_node_uuid(uuid);
        nuvo_pr_enable(true);
    }
    return ret;
}

void nuvo_sl_test_setup(void)
{
    int ret;

    ck_assert_int_eq(sem_init(&sem, 0, 0), 0);

    /* initialize the parcel manager */
    ret = nuvo_pm_init();
    ck_assert_int_ge(ret, 0);

    /* initialize the parcel router */
    ret = pr_test_setup(node_uuid, 0);
    ck_assert_int_ge(ret, 0);

    ret = nuvo_io_concat_pool_init(100);
    ck_assert_int_ge(ret, 0);

    /* initial the cache */
    ret = nuvo_cache_init();
    ck_assert_int_eq(ret, 0);

    init_test_device_array();
    init_test_vol();

    for (int i = 0; i < MAX_TEST_DEVICES; i++ )
    {
        int fd;
        char *name = &test_devs[i].name[0];
        strcpy(name, TEST_DEVICE_NAME_TEMPLATE);
        fd = mkstemp(name);
        ck_assert_int_ge(fd, 0);

        ret = ftruncate(fd, test_devs[i].device_size);
        test_devs[i].fd = fd;
        ck_assert_int_eq(ret, 0);

        uuid_generate(test_devs[i].uuid);
        uuid_generate(test_devs[i].volume_uuid);

        ret = nuvo_pr_device_insert(test_devs[i].uuid, node_uuid);
        ck_assert_int_ge(ret, 0);
    }

    /* create a fake cache device */
    for (int i = 0; i < MAX_TEST_CACHE_DEVICES; i++)
    {
        uuid_generate(cache_dev[i].uuid);
        strcpy(cache_dev[i].name, TEST_DEVICE_NAME_TEMPLATE);
        cache_dev[i].fd = mkstemp(cache_dev[i].name);
        cache_dev[i].size_bytes = 0;
        ret = ftruncate(cache_dev[i].fd, TEST_CACHE_DEVICE_SIZE);
        ck_assert_int_eq(ret, 0);
    }

    fake_space_init();
    ret = nuvo_log_init(&test_vol.nuvo_vol);
    ck_assert_int_ge(ret, 0);
    for (int j = 0; j < TEST_VOL_MAX_LOGREQS; j++)
    {
        ck_assert_int_eq(sem_init(&test_vol.op_log[j].log_io_sem, 0, 0), 0);
    }

    nuvo_log_set_level("logger", TEST_DEBUG_LOG_LEVEL);
}

void nuvo_sl_test_teardown(void)
{
    int ret;

    nuvo_cache_destroy();
    nuvo_pr_shutdown();
    nuvo_io_concat_pool_destroy();

    ret = nuvo_pm_destroy();
    ck_assert_int_ge(ret, 0);

    for (int i = 0; i < MAX_TEST_DEVICES; i++ )
    {
        for (int j = 0;  j < TEST_DEVICE_MAX_IOREQS; j++)
        {
            for (int k = 0; k < NUVO_MAX_IO_BLOCKS; k++)
            {
                if (test_devs[i].op_read[j].io_req.rw.iovecs[k].iov_base)
                {
                    free(test_devs[i].op_read[j].io_req.rw.iovecs[k].iov_base);
                }
                if (test_devs[i].op_write[j].io_req.rw.iovecs[k].iov_base)
                {
                    free(test_devs[i].op_write[j].io_req.rw.iovecs[k].iov_base);
                }
            }
        }
        close(test_devs[i].fd);
        unlink(test_devs[i].name);
    }

    for (int i = 0; i < MAX_TEST_CACHE_DEVICES; i++)
    {
        unlink(cache_dev[i].name);
    }

    nuvo_mutex_destroy(&test_vol.cp_mutex);
    nuvo_cond_destroy(&test_vol.cp_cond);

    for (int j = 0; j < TEST_VOL_MAX_LOGREQS; j++)
    {
        sem_destroy(&test_vol.op_log[j].log_io_sem);
    }
    fake_space_destroy();
    sem_destroy(&sem);

    nuvo_test_fi_free();

    printf("done teardown\n");

}

Suite * nuvo_sl_suite(void)
{
    Suite *s;
    TCase *tc_pm;

    s = suite_create("NuvoSL");

    tc_pm = tcase_create("NuvoSL");
    tcase_add_checked_fixture(tc_pm, nuvo_sl_test_setup, nuvo_sl_test_teardown);

    tcase_add_test(tc_pm, nuvo_sl_test_log_write_2d_2t_100cv_all);
    tcase_add_test(tc_pm, nuvo_sl_test_log_write_1d_2t_50cv_hdd);
    tcase_add_test(tc_pm, nuvo_sl_test_log_write_1d_1t_100cv_hdd);
    tcase_add_test(tc_pm, nuvo_sl_test_log_write_1d_1t_0cv);
    tcase_add_test(tc_pm, nuvo_sl_test_log_write_1d_1t_100cv);
    tcase_add_test(tc_pm, nuvo_sl_test_log_write_1d_2t_50cv);
    tcase_add_test(tc_pm, nuvo_sl_test_log_write_2d_1t_0cv);
    tcase_add_test(tc_pm, nuvo_sl_test_log_write_2d_1t_0cv_1s);
    tcase_add_test(tc_pm, nuvo_sl_test_log_write_2d_1t_100cv_1s);
    tcase_add_test(tc_pm, nuvo_sl_test_log_write_1d_4t_0cv);
    tcase_add_test(tc_pm, nuvo_sl_test_log_write_2d_2t_0cv_mc);
    tcase_add_test(tc_pm, nuvo_sl_test_log_write_8d_4t_0cv_mc);
    tcase_add_test(tc_pm, nuvo_sl_test_log_write_2d_2t_0cv_gc);
    tcase_add_test(tc_pm, nuvo_sl_test_log_write_4d_2t_25cv_gc);

    suite_add_tcase(s, tc_pm);

    return s;
}

