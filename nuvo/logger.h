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
 * @file logger.h
 * @brief data structures for logging into segments.
 *
 */
#pragma once

#include <stdint.h>

#include <nuvo.pb-c.h>

#include "io_concatenator.h"
#include "status.h"
#include "nuvo_hash.h"
#include "nuvo_pr.h"
#include "map_entry.h"
#include "map_request.h"
#include "manifest.h"
#include "segment.h"

#define NUVO_MAX_SEGMENT_BLOCKS    (16384)
#define NUVO_MIN_SEGMENT_BLOCKS    (1024)


/**
 * @brief Defines type of data contained in each block in the log.
 *
 * These types are used in the log descriptors and the summary table entries
 * to identify the type of data that was written to the log, or not written in the case of constant values.
 * <br> \b NUVO_LE_DATA is used in log descriptors and summary table to identify blocks containing data.
 * <br> \b NUVO_LE_MAP_L0-L4 is used in log descriptors and summary table to identify blocks containing map entries.
 *
 * log entry types \b NUVO_LE_FORK, \b NUVO_LE_HEADER, and \b NUVO_LE_DESCRIPTOR
 * are used internally by the segment logger. They are only used in the summary table.
 * These are used to identify blocks containing the respective types of data in the log.
 */
enum nuvo_log_entry_type
{
    NUVO_LE_EMPTY      = 0x0,   /**< Entry is empty */
    NUVO_LE_DATA       = 0x2,   /**< Block contains opaque data */
    NUVO_LE_MAP_L0     = 0x3,   /**< Block contains L0  map entries */
    NUVO_LE_MAP_L1     = 0x4,   /**< Block contains L1  map entries */
    NUVO_LE_MAP_L2     = 0x5,   /**< Block contains L2  map entries */
    NUVO_LE_MAP_L3     = 0x6,   /**< Block contains L3  map entries */
    NUVO_LE_MAP_L4     = 0x7,   /**< Block contains L4  map entries */
    NUVO_LE_FORK       = 0x8,   /**< Block contains the address of another segment */
    NUVO_LE_HEADER     = 0x9,   /**< Block is a segment header */
    NUVO_LE_DESCRIPTOR = 0xA,   /**< Block is a log descriptor */
    NUVO_LE_SNAP       = 0xB,   /**< Block is a create/delete pit marker */
};
static_assert(NUVO_LE_MAP_L4 == NUVO_LE_MAP_L3 + 1 &&
              NUVO_LE_MAP_L3 == NUVO_LE_MAP_L2 + 1 &&
              NUVO_LE_MAP_L2 == NUVO_LE_MAP_L1 + 1 &&
              NUVO_LE_MAP_L1 == NUVO_LE_MAP_L0 + 1 &&
              NUVO_LE_MAP_L0 == NUVO_LE_DATA + 1,
              "We do arithmetic with these values!");
#define NUVO_LE_MAP(e)    ((e) >= NUVO_LE_MAP_L0 && (e) <= NUVO_LE_MAP_L4)

/**
 * @brief Defines the type data logging operation to be performed by the logger
 * Specifies the operation types supported by a nuvo_log_request.
 */
enum nuvo_log_op_type
{
    NUVO_LOG_OP_NOOP        = 0,    /**< Noop, don't use this */
    NUVO_LOG_OP_DATA        = 1,    /**< Data write operation */
    NUVO_LOG_OP_MAP         = 2,    /**< Map write operation */
    NUVO_LOG_OP_GC          = 3,    /**< Segment cleaner write operation */
    NUVO_LOG_OP_CREATE_SNAP = 4,    /**< Create snapshot operation */
    NUVO_LOG_OP_DELETE_SNAP = 5,    /**< Delete snapshot operation */
    NUVO_LOG_OP_FORK        = 6,    /**< Fork operation (for replay only)*/
    NUVO_LOG_OP_INVALID     = 7
};

extern const char *const nuvo_log_op_str[];
inline const char *logger_op_to_str(uint8_t op)
{
    if (op < NUVO_LOG_OP_INVALID)
    {
        return (nuvo_log_op_str[op]);
    }
    else
    {
        return (nuvo_log_op_str[NUVO_LOG_OP_INVALID]);
    }
}

/**
 * \brief Formalize the pit/lun_id in the log.
 *
 * For each block (data or map) written, record whether it is for the active or for a pit.
 * For data blocks written for active, record the pit_id that is next allocated. It is ok
 * if this is too low, but not if it is too high - it is used for gc optimization.
 */
struct log_pit_info {
    uint32_t active : 1;    /** Is the block written for the active lun/map. */
    uint32_t pit_id : 31;   /** If written for active, the next pit to be created at that time (if data block)
                             *  If written not written for active, which pit this was written for. */
};

#define LOG_PIT_INFO_SET_DATA(pit_info, write_for_active, map_pit_id)    do { \
        (pit_info).active = (write_for_active) ? 1 : 0;                       \
        (pit_info).pit_id = (map_pit_id);                                     \
} while (0)

#define LOG_PIT_INFO_SET_MAP(pit_info, map_pit_id)                       do {               \
        (pit_info).active = (map_pit_id) == NUVO_MFST_ACTIVE_LUN_SNAPID ? 1 : 0;            \
        (pit_info).pit_id = (map_pit_id) == NUVO_MFST_ACTIVE_LUN_SNAPID ? 0 : (map_pit_id); \
} while (0)

#define NUVO_LOG_PIT_WRITTEN_FOR_PIT(id_of_pit, pit_info)                ((pit_info).active == 0 && (pit_info).pit_id == id_of_pit)
#define NUVO_LOG_PIT_COULD_MOVED_TO_PIT(id_of_pit, pit_info)             ((pit_info).active == 1 && (pit_info).pit_id <= id_of_pit)
#define NUVO_LOG_PIT_COULD_BE_IN_PIT(id_of_pit, pit_info)                (NUVO_LOG_PIT_WRITTEN_FOR_PIT(id_of_pit, pit_info) || (NUVO_LOG_PIT_COULD_MOVED_TO_PIT(id_of_pit, pit_info)))

/**
 * @brief Defines the type of segment operation
 * Used to specify segment_io_req i/o operation types.
 */
enum segment_op_type
{
    NUVO_SEGMENT_OP_WRITE           = 1, /**< Write data, log descriptors, header, footer, digest to segment */
    NUVO_SEGMENT_OP_FORK            = 2, /**< Write fork block to segment */
    NUVO_SEGMENT_OP_OPEN            = 3, /**< Open a new segment */
    NUVO_SEGMENT_OP_CLOSE           = 4, /**< Close an open segment and writes the summary table */
    NUVO_SEGMENT_OP_FAST_CLOSE      = 5, /**< Close an open segment but doesn't write a summary table */
    NUVO_SEGMENT_OP_READ_DIGEST     = 6, /**< Read and verify the segment digest */
    NUVO_SEGMENT_OP_READ_DESCRIPTOR = 7, /**< Read segment data then rebuild log descriptor */
    NUVO_SEGMENT_OP_READ_DATA       = 8, /**< Read segment data then rebuild the digest */
    NUVO_SEGMENT_OP_READ_SNAP       = 9, /**< Read segment snap block */
    NUVO_SEGMENT_OP_SNAP            = 10 /**< Create or Delete a pit */
};

/** @brief Defines the segment states  */
enum segment_states
{
    NUVO_SEGMENT_CLOSED         = 0, /**< The segment is closed */
    NUVO_SEGMENT_OPEN           = 1, /**< The segment is open for new writes */
    NUVO_SEGMENT_CLOSING        = 2, /**< The segment is closing, pending completion of writes */
    NUVO_SEGMENT_REPLAYING      = 3, /**< The segment digest is ready and transactions are being replayed */
    NUVO_SEGMENT_REPLAY_PENDING = 4, /**< The segment is pending either a summary table read or rebuild */
    NUVO_SEGMENT_REPLAY_ERROR   = 5  /**< Replay of a transaction in this segment failed. */
};

/** @brief Defines the sub-class types of segments */
enum segment_subclasses
{
    NUVO_SEGMENT_TYPE_DATA      = 0, /**< the segment is to be used for new write data */
    NUVO_SEGMENT_TYPE_GC        = 1, /**< the segment is to be used for GC data */
    NUVO_MAX_SEGMENT_SUBCLASSES = 2
};

#define NUVO_MAX_OPEN_SUBCLASS_SEGMENTS    (8)
#define NUVO_MAX_OPEN_SEGMENTS             (NUVO_MAX_OPEN_SUBCLASS_SEGMENTS * NUVO_MAX_SEGMENT_SUBCLASSES)

#define NUVO_SEGMENT_HEADER_MAGIC          (0x48474553)
#define NUVO_SEGMENT_HEADER_BLOCKS         (1)
#define NUVO_SEGMENT_HEADER_SIZE           (NUVO_SEGMENT_HEADER_BLOCKS * NUVO_BLOCK_SIZE)

/**
 * @brief data structure for a segment header.
 *
 * The segment header identifies the beginning of a segment.
 * The segment header stores the opening sequence number for the segment, such that
 * the opening sequence number will be <= the sequence numbers assigned to the
 * the volume_uuid is used to verify the segment belongs to the volume. This avoids replay
 * of old segment data when reusing parcels for new volumes.
 * log descriptors stored within the segment. A corresponding closing sequence number is
 * recorded in the segment footer, such that the
 * opening sequence number <= log descriptor sequence numbers <= closing sequence number.
 *
 * The segment header is written when the segment is opened, and is NUVO_BLOCK_SIZE bytes in size.
 *
 */
struct __attribute__((packed)) nuvo_segment_header {
    union
    {
        struct __attribute__((packed)) {
            uint32_t    magic;                  /**< Identifies the block as a segment header. */
            uint64_t    sequence_no;            /**< The opening sequence number of this segment. */
            nuvo_hash_t block_hash;
            uint8_t     subclass;               /**< The segment subclass type */
            uuid_t      vs_uuid;                /**< The uuid of the volume associated with this segment */
        };
        uint8_t reserved[NUVO_BLOCK_SIZE];
    };
};
static_assert(sizeof(struct nuvo_segment_header) == NUVO_BLOCK_SIZE, "invalid size");

#define NUVO_SNAP_DESCRIPTOR_MAGIC    (0x50414e53)
#define NUVO_SEGMENT_SNAP_BLOCKS      (1)

/**
 * @brief Data structure for a pit descriptor block
 *
 * A pit descriptor block records either a create or delete pit operation in the log
 * the block records the pit_id and pit_uuid of the pit and a sequence number.
 *
 */
struct __attribute__((packed)) nuvo_segment_snap {
    union
    {
        struct __attribute__((packed)) {
            uint32_t    magic;              /**< Identifies this as a pit descriptor. */
            uint64_t    sequence_no;        /**< The sequence number of this log entry. */
            nuvo_hash_t block_hash;         /**< An internal hash of the snapshot block. */
            uint32_t    pit_id;             /**< The PiT ID of the pit */
            uuid_t      pit_uuid;           /**< The PiT UUID of the pit */
            uint8_t     operation;          /**< The type of pit operation */
            uuid_t      vs_uuid;            /**< The uuid of the volume associated with this segment */
        };
        uint8_t reserved[NUVO_BLOCK_SIZE];
    };
};
static_assert(sizeof(struct nuvo_segment_snap) == NUVO_BLOCK_SIZE, "invalid size");


#define NUVO_FORK_DESCRIPTOR_MAGIC    (0x4B524F46)
#define NUVO_SEGMENT_FORK_BLOCKS      (1)

/**
 * @brief Data structure for a fork descriptor block
 *
 * A fork descriptor block records the sequence number and the parcel and offset address of a new segment.
 * The fork block must be written to an open segment before writes to the new segment may be acknowledged.
 * The information in the fork block is used identify the location of the next segment which contains higher sequence numbers.
 *
 */
struct __attribute__((packed)) nuvo_segment_fork {
    union
    {
        struct __attribute__((packed)) {
            uint32_t    magic;              /**< Identifies this as a fork descriptor. */
            uint64_t    sequence_no;        /**< The sequence number of this log entry. */
            nuvo_hash_t block_hash;         /**< An internal hash of the fork block. */
            uint32_t    parcel_index;       /**< The parcel index of the new segment. */
            uint32_t    block_offset;       /**< The block offset of the new segment.*/
            uint8_t     subclass;           /**< The segment subclass type */
            uuid_t      vs_uuid;            /**< The uuid of the volume associated with this segment */
        };
        uint8_t reserved[NUVO_BLOCK_SIZE];
    };
};
static_assert(sizeof(struct nuvo_segment_fork) == NUVO_BLOCK_SIZE, "invalid size");

#define NUVO_LOG_DESCRIPTOR_MAGIC          (0x44474F4C)
#define NUVO_LOG_DESCRIPTOR_HEADER_SIZE    (128)

/**
 * @brief Data structure for a log descriptor header.
 *
 * The log descriptor header records the sequence number and number of entries in the record associated with this
 * sequence number.
 * The log descriptor header structure must be 128 bytes.
 */
struct __attribute__((packed)) nuvo_log_descriptor_header {
    union
    {
        struct __attribute__((packed)) {
            uint32_t    magic;            /**< Identifies this as a log descriptor. */
            uint64_t    sequence_no;      /**< The sequence number of this log entry. */
            nuvo_hash_t block_hash;       /**< An internal hash of the log descriptor block. */
            uint16_t    entry_count;      /**< The total number of entries in the log descriptor including both data and constant values. */
            uint16_t    data_block_count; /**< The total number of data blocks that were logged with this descriptor */
            uuid_t      vs_uuid;          /**< The uuid of the volume associated with this segment */
            uint8_t     operation;        /**< The type of operation that wrote this descriptor */
        };
        uint8_t reserved[NUVO_LOG_DESCRIPTOR_HEADER_SIZE];
    };
};
static_assert(sizeof(struct nuvo_log_descriptor_header) == NUVO_LOG_DESCRIPTOR_HEADER_SIZE, "invalid size");

#define NUVO_LOG_DESCRIPTOR_ENTRY_SIZE    (31)

/**
 * @brief Data structure for a log descriptor entry.
 *
 *  Each entry represents the identity of one NUVO_BLOCK_SIZE byte block of data.
 *  A log descriptor entry must be 31 bytes.
 */
struct __attribute__((packed)) nuvo_log_descriptor_entry {
    union
    {
        struct __attribute__((packed)) {
            uint8_t             log_entry_type;         /**< The type of record, defined in nuvo_log_entry_type. */
            uint8_t             is_cv;                  /**< Set if the data block was constant values (and not written) */
            struct log_pit_info pit_info;               /**< Which PiTs this is/can be used by. */
            uint64_t            bno : 40;               /**< The LUN relative device offset of this block. */
            union
            {
                nuvo_hash_t block_hash;                 /**< If type is NUVO_LE_DATA or NUVO_LE_MAP_L[0..4], The hash of the data block */
                uint64_t    pattern;                    /**< Or if is_cv is set, the pattern */
            };
            struct nuvo_media_addr gc_media_addr;       /**< The old media address before GC, zero if not GD'd. */
        };
        uint8_t reserved[NUVO_LOG_DESCRIPTOR_ENTRY_SIZE];
    };
};
static_assert(sizeof(struct nuvo_log_descriptor_entry) == NUVO_LOG_DESCRIPTOR_ENTRY_SIZE, "invalid size");

#define NUVO_MAX_LOG_DESCRIPTOR_BLOCKS           (2)
#define NUVO_MAX_LOG_DESCRIPTOR_BLOCK_ENTRIES    (NUVO_MAX_IO_BLOCKS / NUVO_MAX_LOG_DESCRIPTOR_BLOCKS)
#define NUVO_LOG_DESCRIPTOR_SIZE                 (NUVO_BLOCK_SIZE)

/**
 * @brief Data structure for a log descriptor.
 *
 * A log descriptor is one or two NUVO_BLOCK_SIZE records which records a sequence number and up to 256
 * log descriptor entries, each representing a NUVO_BLOCK_SIZE data buffer associated with the sequence number.
 *
 * There are 128 log descriptor entries in each NUVO_BLOCK_SIZE log descriptor block. An entry_count > 128
 * means the log descriptor data is recorded in 2 blocks.
 */
struct __attribute__((packed)) nuvo_log_descriptor_block {
    //union nuvo_log_descriptor_header_data  header; /**< the log descriptor block header */
    struct nuvo_log_descriptor_header header;                                         /**< the log descriptor block header */
    struct nuvo_log_descriptor_entry  entries[NUVO_MAX_LOG_DESCRIPTOR_BLOCK_ENTRIES]; /**< log descriptor entry table */
};
static_assert(sizeof(struct nuvo_log_descriptor_block) == NUVO_LOG_DESCRIPTOR_SIZE, "invalid size");
static_assert((NUVO_LOG_DESCRIPTOR_ENTRY_SIZE * NUVO_MAX_LOG_DESCRIPTOR_BLOCK_ENTRIES) + NUVO_LOG_DESCRIPTOR_HEADER_SIZE == NUVO_LOG_DESCRIPTOR_SIZE, "invalid size");

#define NUVO_SEGMENT_FOOTER_MAGIC                (0x46474553)
#define NUVO_SEGMENT_FOOTER_BLOCKS               (1)
#define NUVO_SEGMENT_SUMMARY_ENTRY_SIZE          (24)
#define NUVO_MAX_SEGMENT_SUMMARY_TABLE_BLOCKS    ((NUVO_MAX_SEGMENT_BLOCKS * NUVO_SEGMENT_SUMMARY_ENTRY_SIZE) / NUVO_BLOCK_SIZE)

/**
 * @brief data structure for a segment footer.
 *
 * The segment footer identifies the end of a segment and also serves as the digest header.
 * The segment footer is written when the segment is closed, and is NUVO_BLOCK_SIZE bytes in size.
 * The footer is written along with the summary table as part of the segment digest.
 *
 * Note on footer sequence numbers
 * The footer does not get it's own sequence number because other writes don't depend on its completion.
 * sequence_no records the highest sequence number in the segment.
 *
 */
struct __attribute__((packed)) nuvo_segment_footer {
    union
    {
        struct __attribute__((packed)) {
            uint32_t    magic;                                               /**< Identifies this as a fork descriptor. */
            uint64_t    sequence_no;                                         /**< The sequence number of the last log write */
            nuvo_hash_t block_hash;                                          /**< An internal hash of the fork block */
            uint32_t    used_block_count;                                    /**< the last block used in the segment before the footer block */
            uint64_t    closing_sequence_no;                                 /**< the sequence number at the time of close */
            uuid_t      vs_uuid;                                             /**< The uuid of the volume associated with this segment */
            nuvo_hash_t block_hashes[NUVO_MAX_SEGMENT_SUMMARY_TABLE_BLOCKS]; /**< hashes for each block of the summary table */
        };
        uint8_t reserved[NUVO_BLOCK_SIZE];
    };
};
static_assert(sizeof(struct nuvo_segment_footer) == NUVO_BLOCK_SIZE, "invalid size");

/** @brief data structure for summary table entry
 *
 * A summary table entry records summary information about each block in the segment.
 *
 * Each entry records the type of data that was written to a segment block and the blocks on device checksum.
 * Additional information is recorded depending on the log entry type.
 *
 * - If type is NUVO_LE_DATA or NUVO_LE_MAP_L0 - L4, the data union is used to record the respective pit_info and bno.
 * - If type is NUVO_LE_HEADER the descriptor union is used to record the opening sequence number of the segment.
 * - If type is NUVO_LE_FORK the fork union is used to record the address of a new segment and the sequence number.
 * - If type is NUVO_LE_DESCRIPTOR the sequence number and indicate if constant value block info is in the descriptor.
 * - If type is NUVO_LE_SNAP create/delete op type and the sequence number is stored. Note there is insufficient space to store the pit_id and pit_uuid.
 * - If type is NUVO_LE_EMPTY the block was never written.
 *
 */
struct __attribute__((packed)) nuvo_segment_summary_entry {
    uint8_t     log_entry_type;                     /**< The type of record, defined in nuvo_log_entry_type. */
    nuvo_hash_t block_hash;                         /**< A hash of the data block in this segment associated with this entry */
    union
    {
        struct __attribute__((packed)) {
            uint64_t sequence_no;                   /**< The opening sequence number */
            uint8_t  subclass;                      /**< The segment subclass type */
        } header;
        struct __attribute__((packed)) {
            struct log_pit_info    pit_info;        /**< Which active/pit this is/can be used by. */
            uint64_t               bno : 40;        /**< The LUN relative device offset of this block. */
            struct nuvo_media_addr gc_media_addr;   /**< The old media addr, 0 if the block hasn't been GD'd */
        } data;
        struct __attribute__((packed)) {
            uint8_t  cv_flag;                       /**< True if the log descriptor has constant values */
            uint16_t entry_count;                   /**< The number of entries that were logged in this descriptor */
            uint16_t data_block_count;              /**< The number of data blocks that were logged with this descriptor */
            uint64_t sequence_no;                   /**< The sequence number of the log descriptor */
            uint8_t  operation;                     /**< The type of operation that wrote this descriptor */
        } descriptor;
        struct __attribute__((packed)) {
            struct nuvo_media_addr segment_addr;    /**< The media address of the new segment */
            uint64_t sequence_no;                   /**< The sequence number of the fork */
            uint8_t  subclass;                      /**< The subclass type of the new segment */
        } fork;
        struct __attribute__((packed)) {
            uint8_t  operation;                     /**< Either create or delete pit */
            uint64_t sequence_no;                   /**< The sequence number of the pit op */
        } snap;
    };
};
static_assert(sizeof(struct nuvo_segment_summary_entry) == NUVO_SEGMENT_SUMMARY_ENTRY_SIZE, "invalid size");

/**
 * @brief Structure for tracking memory for the summary table
 *
 * A segment digest is the collective name for the segment footer and digest table representing a block map
 * of the segment.
 */
struct __attribute__((aligned(NUVO_BLOCK_SIZE))) nuvo_segment_digest {
    struct nuvo_segment_footer        footer;                           /**< The segment footer block */
    struct nuvo_segment_summary_entry table[NUVO_MAX_SEGMENT_BLOCKS];   /**< The segment summary table */
};
static_assert(sizeof(struct nuvo_segment_digest) == ((NUVO_MAX_SEGMENT_BLOCKS * NUVO_SEGMENT_SUMMARY_ENTRY_SIZE) + NUVO_BLOCK_SIZE), "invalid size");

/*
 * @brief Tracking structure for the segment summary table
 *
 * Memory used for run time tracking of a segment summary table is allocated off
 * a list of free summary tables and returned to the list when not in
 * use.
 *
 */
union __attribute__((aligned(NUVO_BLOCK_SIZE))) digest_tracking_structs
{
    struct nuvo_dlnode         list_node;
    struct nuvo_segment_digest digest;
};

/** @brief Free tracking structures for the segment digest (footer and summary table)
 * These structures are a statically allocated for now.
 * The free_tracking_structs list is linked list of the statically allocated tracking structs.
 * The tracking structures are allocated from the list when needed and returned to the list when complete.
 */
struct logger_tracking_structs {
    union digest_tracking_structs tracking_digests[NUVO_MAX_OPEN_SEGMENTS]; /**< Pre-allocated memory for the segment digest */
    struct nuvo_dlist             free_tracking_structs;                    /**< Free list of tracking structures. */
};

/**
 * @brief A structure for enqueueing a segment io operation.
 *
 * A segment io req is used for write, fork and close operations.
 */
struct segment_io_req {
    struct nuvo_dlnode       list_node;              /**< used for adding to the completion list */
    int32_t                  status;
    uint8_t                  op;                     /**< type io operation being performed */
    uint64_t                 sequence_no;            /**< sequence number of this sub-request */
    uint32_t                 parcel_index;           /**< parcel index of the destination segment */
    uint32_t                 parcel_desc;            /**< parcel descriptor of the destination segment */
    uint32_t                 block_count;            /**< total size of the io, both data and meta data, in blocks */
    uint32_t                 block_offset;           /**< parcel relative io offset */
    uint32_t                 meta_block_count;       /**< total number of non-data blocks being written */
    struct nuvo_log_request *log_req;                /**< pointer to the log request originating this write */
    struct nuvo_logger      *logger;                 /**< pointer to the logger state */
    struct logger_segment   *log_segment;            /**< pointer to the tracking structure for destination segment */
    struct nuvo_pr_req_alloc req_alloc;              /**< struct for allocating io reqs from the parcel router */
    struct nuvo_pr_buf_alloc buf_alloc;              /**< struct for allocating buffers from the parcel router */

    union
    {
        struct {
            bool                 write_header_flag; /**< set to true if the segment needs a header block */
            struct nuvo_segment *segment;           /**< the new segment */
        } fork;
        struct {
            uint64_t closing_sequence_no;             /**< the logger sequence number at time of close  */
        } close;
        struct {
            nuvo_hash_t block_hashes[NUVO_MAX_LOG_DESCRIPTOR_BLOCKS];           /**< for verifying snap, fork, descriptor blocks reads */
        } read;
    };
};

/**
 * @brief a tracking structure for segment info used by the logger
 */
struct logger_segment {
    //struct nuvo_dlnode           list_node;         /**< May be used for adding to lists */
    struct nuvo_segment        *segment;            /**< A pointer to the raw segment offset and size information */
    struct nuvo_segment_digest *digest;             /**< Staging area for the footer and summary table */
    uint32_t                    current_offset;     /**< The current block offset in the segment */
    int32_t                     free_block_count;   /**< The current number of free blocks in the segment, can be -1 if reserved block is used */
    uint64_t                    last_sequence_no;   /**< The sequence number of the last write operation */
    uint32_t                    state;              /**< One of segment states */
    struct segment_io_req       segment_req;        /**< Request structure used for write on close or reading from this segment during replay */
    struct {
        uint64_t sequence_no;                       /**< The lowest known sequence number in this segment that hasn't been replayed */
        uint64_t highest_sequence_no;               /**< The highest known sequence number in this segment */
        uint8_t  has_digest;                        /**< True if the segment had a valid digest when it was read from media */
        bool     is_processed;                      /**< True if the segment has been processed by replay after the digest was read */
    }                           replay;
    struct nuvo_io_concatenator concatenator;
};

/**
 * @brief a structure for tracking the last segment written in a data class and type.
 * keeps track of how many are opened, or are in queue to be opened
 */
struct segment_subclass {
    struct logger_segment *active_segment;  /**< The last segment that was written to. */
    uint32_t               max_open_count;  /**< The maximum number of open  segments.  */
    uint32_t               open_count;      /**< The current number of open segments. */
    uint32_t               open_queue_len;  /**< How many open segment requests are outstanding. */
};

/** @brief for tracking info about the data class and it's tracking structures for open segments
 *
 * This structure has the array of currently open segments for a data class. It also tracks
 * the last segment written and how many segments are currently open.
 *
 * The max open count defines how many unique devices the logger should try to use.
 * This value will only be reached if there are at least that many devices with segments in this data class.
 *
 */
struct logger_class {
    struct logger_segment   segments[NUVO_MAX_OPEN_SEGMENTS]; /**< An array of pointers to currently open segments. */
    struct segment_subclass subclass[NUVO_MAX_SEGMENT_SUBCLASSES];
    uint32_t                max_open_count;                   /**< The maximum number of open segments in this data class */
};


/** @brief List of segment_io_reqs for writing fork blocks.
 *
 * This is used for writing fork blocks when opening a new segment.
 */
struct logger_segment_reqs {
    struct segment_io_req seg_reqs[NUVO_MAX_OPEN_SEGMENTS];   /**< Pre-allocated segment_io_req's */
    struct nuvo_dlist     free_segment_io_reqs;               /**< Free list of segment io reqs */
};

/**
 * @brief A structure for passing information be recorded in log descriptors
 *
 * All operation types must provide values for the data, data_type, log_pit_info, and bno fields.
 * Values for gc_block_hash and gc_media_addr are only required for NUVO_LOG_OP_GC operations, and are otherwise not used.
 * map_is_zero may be set for NUVO_LOG_OP_MAP operations to indicate the map block is known to be empty.
 *
 */
struct nuvo_log_io_block {
    void                  *data;           /**< A pointer a NUVO_BLOCK_SIZE buffer, required for all operation types */
    uint8_t                log_entry_type; /**< The type of data being logged, NUVO_LE_DATA or NUVO_LE_MAP_L0 - L4 */
    struct log_pit_info    pit_info;       /**< The pit info for the block, required for all log operation types */
    uint64_t               bno;            /**< An LUN relative offset value, required for all log operation types */
    nuvo_hash_t            gc_block_hash;  /**< A data block hash, required only for GC operations */
    struct nuvo_media_addr gc_media_addr;  /**< A media address, required only for GC operations */
    bool                   map_is_zero;    /**< If set, indicates an empty map block flush */
};

/**
 * @brief A structure for storing provisional map entries
 *
 * This structure stores the hashes and/or constant values which will be used for populating the
 * nuvo_map_entry map_entires array on completion of the log request.
 *
 * It holds both the hash and a constant value if detected.
 * This is required because when a log request is submitted, it's not known which device the request
 * will be written to. The device that's selected for write depends on the number of blocks available
 * in the segment. However, if constant value detection is disabled, the blocks written to SSD and HDD
 * will not be the same if there are constant values.
 *
 */
struct nuvo_log_io_block_hashes {
    enum nuvo_map_entry_type type;
    nuvo_hash_t              hash;
    uint64_t                 pattern;
};

/**
 * @brief A request to start log replay for a volume
 *
 * This structure is provided on the call to nuvo_log_replay() to start log replay.
 * The log replay request will start replaying the log starting at the specified sequence number
 * by reading transactions from each of the given segments and replaying them with the map.
 *
 * The log transaction with the starting sequence number must be contained in one of the
 * starting segments given for replay. The starting list of segments must collectively have,
 * or fork to segments that have, all the sequence numbers greater than then starting sequence
 * number.
 *
 * A callback must be provided on the nuvo_log_replay_request. The callback is run when log replay has completed.
 *
 * When a new volume is created, nuvo_log_replay() must be called with a single unused segment
 * and sequence number. Even though there will be no operations requiring replay, when the
 * replay process completes, the logger will be ready for new writes which will be assigned
 * sequence numbers starting at value provided with the nuvo_log_replay_request.
 *
 */
struct nuvo_log_replay_request {
    struct nuvo_dlnode  list_node;                                               /**< For adding the request to lists */
    uint64_t            sequence_no;                                             /**< The starting sequence number in the log where replay should start */
    uint64_t            segment_cnt_sequence_no;                                 /**< The starting sequence number that should modify the sequence count. */
    struct nuvo_vol    *vol;                                                     /**< The volume being replayed */
    nuvo_return_t       status;                                                  /**< Non zero if an error occurs */
    union nuvo_tag      tag;                                                     /**< A tag used by the caller to identify the request. */
    uint32_t            segment_count;                                           /**< The number for segments provided to start replay */
    struct nuvo_segment replay_segments[NUVO_MFST_NUM_LOG_STARTS];
    void                (*callback)(struct nuvo_log_replay_request *replay_req); /**< Completion callback */
};

/**
 * @brief A structure for passing and returning information for a log request
 *
 * A log operation request specifies data for writing to the log, along with accounting information for each block
 * '* which will be recorded in a corresponding log descriptor. Depending on the type of operation the caller is required
 * to supply different input data on the request.
 *
 * There are three operation types supported.
 *  - NUVO_LOG_OP_DATA : Request contains regular (FUSE) io data.
 *  - NUVO_LOG_OP_MAP  : Request contains map entry data.
 *  - NUVO_LOG_OP_GC   : Request contains data from garbage collection.
 *  - NUVO_LOG_OP_CREATE_SNAP : Request contains the pit_id and pit_uuid of a new pit.
 *  - NUVO_LOG_OP_DELETE_SNAP : Request contains the pit_id and pit_uuid of a pit to be deleted.
 *
 * Each operation type requires the following information.
 * atomic_flag - This flag indicates whether the logger is required to log the operation in a single log descriptor.
 * data_class - Type media the data should be logged to. All data included in a log request must intend to be written
 * to the same class.
 * block_count - The number of data blocks in the request, corresponding to the length of the log_io array.
 * tag - A tag to be used by the caller to identify the request on a callback.
 * log_io array - An array of nuvo_log_io entries passing information to be recorded in the log descriptor.
 *
 * On success, A callback is executed which informs the caller that the log descriptor and associated data has be
 * persistently logged.
 * When the user specified callback is invoked the log_io_request struct will be populated with
 * The completion status of the log io operation in the status field.
 * The map entries associated with blocks logged.
 * A sequence number that must be used on a subsequent request to the logger to inform the logger the map has been
 * updated, or otherwise done with the request.
 * The sequence number is used to enforce ordering of updates, the logger will not executed callbacks.
 *
 * On success, the nuvo_map_entries array contains the follow information for each data block.
 *  - the type of entry made, either constant value or media.
 *  - if the type is NUVO_ME_MEDIA:
 *    - A media address, The index of the parcel in the manifest and block offset where the data was written.
 *    - A hash of the data block written.
 *  - if the type is NUVO_ME_CONST:
 *    - The constant value pattern.
 *
 * Operation specific information, and behaviour.
 *
 * \b NUVO_LOG_OP_DATA
 * The hash value of the data block is calculated by the logger, and returned in associated the map entry.
 * If a constant value is detected in the data buffer the data won't be logged.
 * The pattern detected is returned in the map entry for the block, and the entry type is set to NUVO_ME_CONST.
 * The media_addr recorded in the log descriptor is set to 0.
 *
 * \b NUVO_LOG_OP_MAP
 * If atomic is set, the log descriptor entry, including the data blocks, must be logged as part of a single
 * log descriptor. If the logger is not able to log in single descriptor an error is returned. This operation is
 * otherwise handled the same as NUVO_LOG_OP_DATA.
 *
 * \b NUVO_LOG_OP_GC
 * A GC log operation is required to provide the hash value of the data block to be logged. That hash value is still
 * returned in the associated map entry.
 * Constant value detection does not apply to blocks written during GC operations.
 * If atomic is set, the log descriptor entry, including the data blocks, must be logged as part of a single log
 * descriptor. If the logger is not able to log in single descriptor an error is returned.
 *
 */
struct nuvo_log_request {
    struct nuvo_dlnode    list_node;            /**< List pointer to prev and next request. */
    enum nuvo_log_op_type operation;            /**< Data logging operation type, defined in nuvo_log_op_type. */
    bool                  atomic;               /**< If set, the logger must log into a single log descriptor */
    union nuvo_tag        tag;                  /**< A tag used by the caller to identify the request. */
    struct nuvo_vol      *vs_ptr;               /**< A pointer to the volume series for this request. */
    enum nuvo_data_class  data_class;           /**< The class of data indicating which media type to use. */
    enum nuvo_cache_hint  cache_hint;           /**< Advisory to cache layer on whether to cache. */
    union
    {
        struct {
            uint32_t pit_id;                      /**< ID of the PiT */
            uuid_t   pit_uuid;                    /**< UUID of the PiT */
        };
        struct {
            uint32_t                        block_count;                             /**< Number of data blocks on the request */
            struct nuvo_log_io_block        log_io_blocks[NUVO_MAX_IO_BLOCKS];       /**< data and metadata for the log descriptor */
            struct nuvo_log_io_block_hashes log_io_block_hashes[NUVO_MAX_IO_BLOCKS]; /**< Map entry information, calculated for both SSD or HDD */
        };
    };
    void                  (*callback)(struct nuvo_log_request *log_req);     /**< Completion callback */

    union
    {
        struct segment_io_req segment_req;          /**< Internally used for preparing and tracking io operations for the request */
        struct {
            struct nuvo_map_request map_req;
            struct nuvo_map_request map_req_snap;
            uint_fast32_t           replay_count;
        };
    };

    /* Cooked values */
    uint32_t              nocv_io_block_count; /**< The total number of blocks that will be written if CV detection is disabled */
    uint32_t              io_block_count;      /**< The total number of all blocks to be written on this request */
    uint32_t              data_block_count;    /**< The number of data blocks to be written */
    uint32_t              meta_block_count;    /**< The number of header and log descriptor blocks to be written */
    bool                  write_header_flag;   /**< Flag to indicate a segment header block is required */
    bool                  replay_ready;        /**< Set to true when map entries are prepared */
    uint_fast64_t         ack_submit_time;     /**< Set to the time when this log request was sent to map for acknowledgment */

    /* Populated by the logger and returned on completion. */
    int64_t               status;                               /**< The request completion status. */
    union nuvo_tag        sequence_tag;                         /**< A tag that associates this request with a sequence number. */
    struct nuvo_map_entry nuvo_map_entries[NUVO_MAX_IO_BLOCKS]; /**< A map entry struct returned on completion. */
};

/**
 * @brief Defines the different logger checkpoint triggers
 */
enum logger_cp_trigger_type
{
    NUVO_CP_TRIGGER_DISABLED            = 0,     /**< Disable triggering CP from logger */
    NUVO_CP_TRIGGER_LOG_IO_COUNT        = 1,     /**< Trigger based onthe number io's performed */
    NUVO_CP_TRIGGER_SEGMENTS_USED_COUNT = 2      /**< Trigger based on the number of segments used */
};

/* Defines the default trigger to use */
#define NUVO_CP_TRIGGER_DEFAULT                      (NUVO_CP_TRIGGER_SEGMENTS_USED_COUNT)

/* Defines the number of io's before triggering a checkpoint. */
#define NUVO_CP_TRIGGER_LOG_IO_COUNT_LIMIT           (8192)

/* Defines the number of segments used before triggering a checkpoint. */
#define NUVO_CP_TRIGGER_SEGMENTS_USED_COUNT_LIMIT    (16)

/*
 * Defines the maximum number of transactions that may be enqueued for replay at a time.
 * As replay processes segments it enqueues transactions in sequential order.
 * This limits the number of transactions that may be enqueued before they must be replayed with the map.
 * This also limits the depth of recursion that's able to occur if the map completes an ack
 * on the same thread that called in with the replay.
 * minimum value is 1
 */
#define NUVO_MAX_REPLAY_TRANSACTIONS                 (16)

/** @brief Free log request structures used for replaying a log request transaction.
 * These structures are statically allocated for now.
 * The free_log_reqs list is linked list of the statically allocated nuvo_log_request structs.
 * The free structures are allocated from the list when needed and returned to the list when complete.
 */
struct replay_log_reqs {
    struct nuvo_log_request log_reqs[NUVO_MAX_REPLAY_TRANSACTIONS];
    struct nuvo_dlist       free_log_reqs;
};

/**
 * @brief Defines the states of the logger
 *
 */
enum nuvo_logger_state
{
    NUVO_LOG_STATE_SHUTDOWN = 0,     /**< Logger is shutdown. */
    NUVO_LOG_STATE_RUNNING  = 1,     /**< Logger is ready for new log write requests. */
    NUVO_LOG_STATE_REPLAY   = 2      /**< Logger is replaying log write requests. Not ready for new write requests. */
};

/** @brief The logger state variables.
 *
 * The logger state is initialized as part of volume series.
 */
struct nuvo_logger {
    uint32_t                        state;                  /**< current logger state. */
    uint64_t                        log_io_count;           /**< the number of log requests with assigned sequence numbers pending */
    nuvo_cond_t                     log_io_count_zero_cond; /**< signaled when all log requests are acknowledged */
    nuvo_mutex_t                    log_io_count_mutex;

    enum logger_cp_trigger_type     cp_trigger_type;                      /**< The type of CP trigger to use */
    uint64_t                        cp_trigger_log_io_count_limit;        /**< The number of log requests before triggering a CP */
    uint64_t                        cp_trigger_segments_used_count_limit; /**< The number of segments to use before triggering a CP */
    uint64_t                        cp_trigger_log_io_count;              /**< The number of log requests completed since the last CP was requested */
    uint64_t                        cp_trigger_segments_used_count;       /**< The number of segments used since the last CP was requested */
    nuvo_mutex_t                    cp_trigger_mutex;                     /**< Mutex protecting cp_trigger counters */

    uint64_t                        pr_io_count;                          /**< the number of pr requests outstanding waiting for io completion */
    nuvo_cond_t                     pr_io_count_zero_cond;                /**< signaled when no pr requests are in flight */
    nuvo_mutex_t                    pr_io_count_mutex;

    uint64_t                        sequence_no;                                   /**< The next sequence no. that will be assigned to a request */
    nuvo_mutex_t                    sequence_no_mutex;                             /**< A mutex */

    uint64_t                        lowest_sequence_no;                            /**< The lowest sequence no. which has not been acknowledged */
    uint64_t                        lowest_sequence_no_seg_cnts;                   /**< The sequence no to start recording segment count changes. */
    nuvo_mutex_t                    lowest_sequence_no_mutex;                      /**< A mutex */

    struct nuvo_dlist               completion_list;                               /**< All io_reqs that have completed i/o and pending callbacks */
    bool                            completions_frozen;                            /**< true if io completion callbacks are frozen */
    nuvo_mutex_t                    completion_list_mutex;                         /**< A mutex protecting the queue and frozen state */

    struct nuvo_dlist               segment_close_queue;                           /**< A list of segments which are queued for closure */
    nuvo_mutex_t                    segment_close_queue_mutex;                     /**< A mutex protecting the queue */
    nuvo_cond_t                     close_queue_len_zero_cond;                     /**< signaled when their are no segment close ops in queue */
    uint32_t                        close_queue_len;                               /**< The number of close requests waiting for i/o completion */

    struct nuvo_dlist               segment_open_queue;                            /**< A list of segments which are queued to be open */
    nuvo_mutex_t                    segment_open_queue_mutex;                      /**< A mutex protecting the queue */

    struct nuvo_dlist               segment_io_queue;                              /**< A list of log requests submitted to the logger for writes */
    nuvo_mutex_t                    segment_io_queue_mutex;                        /**< A mutex protecting the queue */
    nuvo_cond_t                     segment_io_queue_len_zero_cond;                /**< signaled when their are no log write requests in queue */
    uint32_t                        segment_io_queue_len;                          /**< The number of log requests waiting for segments */

    struct logger_class             open_data_segments[NUVO_MAX_DATA_CLASSES];     /**< Open segments in each data class */
    struct logger_segment          *active_segment;                                /**< The last segment that the logger wrote to. Protected by the open_data_segments mutex */
    nuvo_mutex_t                    open_data_segments_mutex;                      /**< A mutex protecting the list of open segments */

    struct logger_tracking_structs  tracking_structs[NUVO_MAX_DATA_CLASSES];       /**< A list of free tracking structures for digests */
    nuvo_mutex_t                    tracking_structs_mutex;                        /**< A mutex protecting the tracking structures */

    struct logger_segment_reqs      segment_io_req_structs[NUVO_MAX_DATA_CLASSES]; /**< A list of segment_io_reqs for writing fork blocks */
    nuvo_mutex_t                    segment_io_req_structs_mutex;                  /**< A mutex protecting the list of segment_io_reqs */

    struct nuvo_dlist               replay_queue;                                  /**< An ordered list of transaction replay requests to be replayed */
    nuvo_mutex_t                    replay_queue_mutex;                            /**< A mutex protecting the replay queue */
    nuvo_cond_t                     replay_queue_len_zero_cond;                    /**< signaled when there are no replay requests in queue */
    nuvo_cond_t                     replay_queue_cond;                             /**< signaled when the replay thread should try and do more work */
    uint32_t                        replay_queue_len;                              /**< The number of replay requests waiting for replay */
    bool                            replay_segments_opened;                        /**< Set to true after all initial segments given for replay have been opened */
    nuvo_cond_t                     replay_segments_opened_cond;                   /**< Signaled when initial segments given for replay have been opened */

    struct replay_log_reqs          replay_log_request_structs;                    /**< A list of free nuvo_log_requests to be used for replay */
    nuvo_mutex_t                    replay_log_request_structs_mutex;              /**< A mutex for protecting the list of free nuvo_log_requests */

    nuvo_mutex_t                    replay_callback_count_mutex;                   /**< A mutex protecting the callback count */
    nuvo_cond_t                     replay_callback_count_zero_cond;               /**< signaled when there are no callbacks running */
    uint32_t                        replay_callback_count;                         /**< The number of callback threads running */

    uint64_t                        acking_sequence_no;                            /**< The sequence number completion queue is waiting on for ack, otherwise 0 if not waiting */
    nuvo_cond_t                     acking_sequence_no_zero_cond;                  /** signaled when there are no outstanding acknowledgments */

    nuvo_cond_t                     completion_list_cond;
    bool                            ack_th_running;
    pthread_t                       ack_tid;

    struct nuvo_log_replay_request *replay_req;
};

/**
 * @brief Get the total length of the digest, including the footer block and the summary table.
 * @param segment The segment from which to get the digest length.
 * @return The length of the digest.
 */
inline uint32_t get_segment_digest_len(struct nuvo_segment *segment)
{
    NUVO_ASSERT(segment != NULL);
    return ((((segment->block_count * NUVO_SEGMENT_SUMMARY_ENTRY_SIZE) + (NUVO_BLOCK_SIZE - 1)) / NUVO_BLOCK_SIZE) + NUVO_SEGMENT_FOOTER_BLOCKS);
}

/**
 * @brief Gets the parcel relative block offset of the digest within the segment.
 * @param segment The segment from which to get the digest offset.
 * @return The block offset of the digest.
 */
inline uint32_t get_segment_digest_offset(struct nuvo_segment *segment)
{
    NUVO_ASSERT(segment != NULL);
    return ((segment->block_offset + segment->block_count) - get_segment_digest_len(segment));
}

/**
 * @brief Returns a segment relative block index given a parcel relative block offset in the segment.
 * @param segment A segment containing the given block offset.
 * @param block_offset A parcel relative block offset.
 * @return The segment relative block index.
 */
inline uint32_t segment_offset_to_index(struct nuvo_segment *segment, uint32_t block_offset)
{
    NUVO_ASSERT(segment != NULL);
    return (block_offset - segment->block_offset);
}

/**
 * @brief Returns a parcel relative block offset of the given segment relative block index offset.
 * @param segment A segment containing the given block index.
 * @param block_index A segment relative to block index.
 * @return The parcel relative block offset.
 */
inline uint32_t segment_index_to_offset(struct nuvo_segment *segment, uint32_t block_index)
{
    NUVO_ASSERT(segment != NULL);
    return (segment->block_offset + block_index);
}

#define NUVO_LOGGER_IN_REPLAY(logger)    ((logger)->state == NUVO_LOG_STATE_REPLAY)

inline bool nuvo_logger_is_running(struct nuvo_logger *logger)
{
    if (logger->state == NUVO_LOG_STATE_RUNNING)
    {
        return (true);
    }
    return (false);
}

nuvo_return_t nuvo_logger_fill_log_summary(Nuvo__LogSummary           *log_summary,
                                           struct nuvo_segment_digest *digest);

/* Logger functions */
nuvo_return_t nuvo_log_shutdown(struct nuvo_vol *vol);
nuvo_return_t nuvo_log_init(struct nuvo_vol *vol);
void nuvo_log_submit(struct nuvo_log_request *log_req);
void nuvo_log_ack_sno(struct nuvo_log_request *log_req);
void nuvo_log_replay(struct nuvo_log_replay_request *replay_req);
nuvo_return_t nuvo_log_sync_replay(struct nuvo_log_replay_request *replay_req);
uint64_t nuvo_log_freeze_map_updates(struct nuvo_vol *vol);
void nuvo_log_unfreeze_map_updates(struct nuvo_vol *vol);
void nuvo_log_get_open_segments(struct nuvo_vol *vol, uint64_t sequence_no, struct nuvo_segment *segments, uint32_t *segment_count);
void nuvo_process_segment_io_queue(struct nuvo_logger *logger);
void nuvo_log_close_segment(struct nuvo_vol *vol, struct nuvo_segment *segment, bool write_digest);
